#include "include/connection/connection.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"
#include "openssl/types.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include <errno.h>
#include <fcntl.h>
#include "ssl2.h"
#include "openssl/include/internal/ssl.h"
#include <unistd.h>
#include <stdbool.h>
#include <basetsd.h>
#include <sys/time.h>
#include "wireguard-nt-master/api/adapter.h"
#include "wireguard-nt-master/api/wireguard.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <ws2ipdef.h>
#include <bcrypt.h>
#include <winsock.h>
#include <fwpmu.h>

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif



static bool winsock_initialized = false;

static void init_winsock_once(void) {
#ifdef _WIN32
    if (!winsock_initialized) {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            log_error("WSAStartup failed");
            exit(EXIT_FAILURE);
        }
        winsock_initialized = true;
    }
#endif
}

void cleanup_winsock(void) {
#ifdef _WIN32
    if (winsock_initialized) {
        WSACleanup();
        winsock_initialized = false;
    }
#endif
}

static bool initialize_ssl_context(void) {
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        log_error("Failed to create SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // Добавляем установку глубины цепочки сертификатов:
    SSL_CTX_set_verify_depth(ssl_ctx, 4);

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, "ca-certificates.crt", NULL)) {
        log_error("Failed to load CA certificates: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return false;
    }

    return true;
}


// переподключение если сервер недоступен 

void handle_connection_loss(ConnectionState *state) {

}


bool set_socket_timeouts(int socket_fd, int send_timeout_sec, int recv_timeout_sec) {
    if (!_validis_socket(socket_fd)) {
        log_error("Invalid socket descriptor");
        return false;
    }

#ifdef _WIN32
    DWORD send_timeout = send_timeout_sec * 1000;
    DWORD recv_timeout = recv_timeout_sec * 1000;
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_timeout, sizeof(recv_timeout));
#else
    struct timeval send_timeout = {send_timeout_sec, 0};
    struct timeval recv_timeout = {recv_timeout_sec, 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
#endif

    log_info("Socket timeouts set: send=%d sec, recv=%d sec", send_timeout_sec, recv_timeout_sec);
    return true;
}

bool verify_certificate(SSL *ssl, const char *hostname) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        log_error("No certificate presented by the server");
        return false;
    }

    // Проверка имени хоста
    if (X509_check_host(cert, hostname, strlen(hostname), 0, NULL) != 1) {
        log_error("Certificate does not match hostname: %s", hostname);
        X509_free(cert);  // Теперь освобождаем память перед возвратом
        return false;
    }
    

    X509_free(cert);
    return true;
}

static inline bool is_fd_valid(int fd) {
    return fd >= 0;
}


// Преобразование имени хоста в IP-адрес
static bool resolve_hostname(const char *hostname, struct sockaddr_in *addr) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Поддержка IPv4 и IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        log_error("Failed to resolve hostname: %s", hostname);
        return false;
    }

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            memcpy(addr, ipv4, sizeof(struct sockaddr_in));
            break;
        } else if (p->ai_family == AF_INET6) {
            // Обработка IPv6 (добавьте код)
        }
    }

    freeaddrinfo(res);
    return true;
}



bool set_socket_timeouts(int socket_fd, int send_timeout_sec, int recv_timeout_sec) {
    if (!is_socket_valid(socket_fd)) {
        log_error("Invalid socket descriptor");
        return false;
    }

    struct timeval send_timeout = {send_timeout_sec, 0};
    struct timeval recv_timeout = {recv_timeout_sec, 0};

    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout)) < 0) {
        log_error("Failed to set send timeout");
        return false;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_timeout, sizeof(recv_timeout)) < 0) {
        log_error("Failed to set receive timeout");
        return false;
    }

    log_info("Socket timeouts set successfully: send=%d sec, recv=%d sec", send_timeout_sec, recv_timeout_sec);
    return true;
}


bool is_server_reachable(const char *server_ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        return false;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_error("Invalid address or address not supported");
        close(sockfd);
        return false;
    }

    int result = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sockfd);

    if (result < 0) {
        log_warning("Server %s:%d is unreachable", server_ip, port);
        return false;
    }

    log_info("Server %s:%d is reachable", server_ip, port);
    return true;
}

bool is_socket_valid(ConnectionState *state) {
    if (!state) {
        log_error("Invalid connection state");
        return false;
    }

    pthread_mutex_lock(&connection_mutex);
    bool valid = IS_SOCKET_VALID(state->socket_fd) && state->is_connected;
    pthread_mutex_unlock(&connection_mutex);
    
    return valid;
}


ssize_t receive_data(ConnectionState *state, void *buffer, size_t length) {
    pthread_mutex_lock(&connection_mutex);
    if (!is_socket_valid(state)) {
        log_error("Invalid socket descriptor");
        pthread_mutex_unlock(&connection_mutex);
        return -1;
    }

    ssize_t bytes_received = recv(state->socket_fd, buffer, length, 0);
    if (bytes_received < 0) {
        log_error("Receive failed: %s", strerror(errno));
        pthread_mutex_unlock(&connection_mutex);
        return -1;
    } else if (bytes_received == 0) {
        log_info("Connection closed by peer");
        state->is_connected = false;
    }

    pthread_mutex_unlock(&connection_mutex);
    return bytes_received;
}



// Переподключение при разрыве
bool reconnect(ConnectionState *state) {
    pthread_mutex_lock(&connection_mutex);

    if (!state || !state->server_ip) {
        log_error("Invalid connection state or server IP");
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    if (state->is_connected) {
        log_warning("Already connected, no need to reconnect");
        pthread_mutex_unlock(&connection_mutex);
        return true;
    }

    log_info("Reconnecting to %s:%d...", state->server_ip, state->port);
    close_connection(state->socket_fd); // Закрываем предыдущий сокет

    // Ждём перед повторной попыткой
    usleep(1000000); // 1 секунда

    bool success = initialize_connection(state, state->server_ip, state->port);
    pthread_mutex_unlock(&connection_mutex);
    return success;
}

static pthread_mutex_t shadowsocks_mutex = PTHREAD_MUTEX_INITIALIZER;

// Вспомогательная функция для очистки памяти
static void secure_clear_memory(void *ptr, size_t size) {
    if (ptr) {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}


// Функция для преобразования IP-адреса и порта в SOCKADDR_INET
static bool set_endpoint(SOCKADDR_INET *endpoint, const char *ip, uint16_t port) {
    memset(endpoint, 0, sizeof(*endpoint));

    // Преобразование IP-адреса
    if (inet_pton(AF_INET, ip, &endpoint->Ipv4.sin_addr) == 1) {
        endpoint->Ipv4.sin_family = AF_INET;
        endpoint->Ipv4.sin_port = htons(port);
        return true;
    } else if (inet_pton(AF_INET6, ip, &endpoint->Ipv6.sin6_addr) == 1) {
        endpoint->Ipv6.sin6_family = AF_INET6;
        endpoint->Ipv6.sin6_port = htons(port);
        return true;
    }

    return false; // Неверный формат IP-адреса
}
