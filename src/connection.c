#include "connection.h"
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
#include "ssl_lib.c"
#include <ssl.h>
#include <unistd.h>
#include <stdbool.h>
#include <basetsd.h>
#include <sys/time.h>
#include "obfuscation.h"
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

static void cleanup_winsock(void) {
#ifdef _WIN32
    WSACleanup();
#endif
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

// Пример для establish_tcp_tunnel:
int establish_tcp_tunnel(const char *server_ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        cleanup_winsock();
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close(sockfd);
        cleanup_winsock();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed");
        close(sockfd);
        cleanup_winsock();
        return -1;
    }

    log_info("TCP tunnel established successfully to %s:%d", server_ip, port);
    return sockfd;
}


#ifdef _WIN32
        static void init_winsock(void) {
            WSADATA wsa_data;
            int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            if (result != 0) {
                log_error("WSAStartup failed with error: %d", WSAGetLastError());
                exit(EXIT_FAILURE);
            }
        }
#endif


    

    
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

// Инициализация соединения
bool initialize_connection(ConnectionState *state, const char *server_ip, int port) {
    if (!state || !server_ip || port <= 0 || port > 65535) {
        log_error("Invalid connection state, server IP, or port");
        return false;
    }

    pthread_mutex_lock(&connection_mutex);
    init_winsock();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed: %s", strerror(errno));
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        if (!resolve_hostname(server_ip, &server_addr)) {
            log_error("Failed to resolve hostname: %s", server_ip);
            close(sockfd);
            pthread_mutex_unlock(&connection_mutex);
            return false;
        }
    }

    // Установка таймаутов
    struct timeval timeout = {5, 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&timeout, sizeof(timeout)) < 0) {
        log_warning("Failed to set receive timeout: %s", strerror(errno));
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&timeout, sizeof(timeout)) < 0) {
        log_warning("Failed to set send timeout: %s", strerror(errno));
    }

    // Лог перед попыткой соединения
    log_info("Attempting to connect to %s:%d", server_ip, port);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection to server failed: %s", strerror(errno));
        close(sockfd);
        pthread_mutex_unlock(&connection_mutex);
#ifdef _WIN32
        cleanup_winsock();
#endif
        return false;
    }

    // Копируем IP-адрес безопасно
    if (snprintf(state->server_ip, MAX_IP_LENGTH, "%s", server_ip) >= MAX_IP_LENGTH) {
        log_error("IP address exceeds buffer size");
        close(sockfd);
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    snprintf(state->server_ip, MAX_IP_LENGTH, "%s", server_ip);
    state->port = port;
    state->socket_fd = sockfd;
    state->is_connected = true;

    log_info("Connection established successfully to %s:%d", server_ip, port);
    pthread_mutex_unlock(&connection_mutex);
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


void close_connection(ConnectionState *state) {
    pthread_mutex_lock(&connection_mutex);

    if (state->socket_fd >= 0) {
#ifdef _WIN32
        closesocket(state->socket_fd);
#else
        close(state->socket_fd);
#endif
        log_info("Socket closed");
    }

    if (state->ssl_ctx) {
        SSL_CTX_free(state->ssl_ctx);
        state->ssl_ctx = NULL;
        log_info("SSL context cleaned up");
    }

    cleanup_winsock();
    state->is_connected = false;

    pthread_mutex_unlock(&connection_mutex);
}

void close_connection_state(ConnectionState *state) {
    if (!state) {
        log_error("Invalid connection state");
        return;
    }

    pthread_mutex_lock(&connection_mutex);

    // Закрытие сокета
    if (state->socket_fd >= 0) {
#ifdef _WIN32
        closesocket(state->socket_fd);
#else
        close(state->socket_fd);
#endif
        log_info("Socket closed successfully");
        state->socket_fd = -1; // Обнуление дескриптора сокета
    } else {
        log_warning("Socket descriptor is already invalid or closed");
    }

    // Очистка контекста шифрования (если используется)
    if (state->ssl_ctx) {
        SSL_CTX_free(state->ssl_ctx);
        state->ssl_ctx = NULL;
        log_info("SSL context cleaned up successfully");
    }

    // Сброс состояния соединения
    state->is_connected = false;
    memset(state->server_ip, 0, MAX_IP_LENGTH); // Очистка IP-адреса
    state->port = 0;

    // Очистка Winsock (только для Windows)
    cleanup_winsock();

    pthread_mutex_unlock(&connection_mutex);
}





bool initialize_ssl(EncryptionContext *ctx) {
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) {
        log_error("Failed to create SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // Запрещаем старые версии TLS
    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Проверка сертификатов
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, "ca-certificates.crt", NULL)) {
        log_error("Failed to load CA certificates");
        SSL_CTX_free(ctx->ssl_ctx);
        return false;
    }

    return true;
}

//
/* BASIC PROTOCOLS */
//

// TCP-туннелирование
bool initialize_tcp(ProtocolState *state, const char *server_ip, int port) {
    if (!state) return false;
    state->type = PROTOCOL_TCP;
    state->tcp_socket = establish_tcp_connection(server_ip, port);
    return state->tcp_socket >= 0;
}

// UDP-туннелирование
bool initialize_udp(ProtocolState *state, const char *server_ip, int port) {
    if (!state) return false;
    state->type = PROTOCOL_UDP;
    state->udp_socket = establish_udp_connection(server_ip, port);
    return state->udp_socket >= 0;
}

int establish_connection(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    init_winsock();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        cleanup_winsock();
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close(sockfd);
        cleanup_winsock();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed");
        close(sockfd);
        cleanup_winsock();
        return -1;
    }

    log_info("Connection established successfully");
    return sockfd;
}


// Установка UDP-соединения
int establish_udp_connection(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Инициализация Winsock на Windows
    init_winsock();

    // Создание UDP-сокета
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
#ifdef _WIN32
        log_error("Socket creation failed");
        cleanup_winsock();
#else
        perror("Socket creation failed");
#endif
        return -1;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Преобразование IP-адреса из текстового формата в сетевой
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close_connection(sockfd);
        cleanup_winsock();
        return -1;
    }

    log_info("UDP connection established successfully");
    return sockfd;
}

// Отправка данных через UDP
ssize_t send_udp_data(int socket_fd, const void *data, size_t length, const struct sockaddr_in *server_addr) {
    if (!is_socket_valid(socket_fd)) {
    log_error("Invalid socket descriptor");
    return -1;
    }
    ssize_t bytes_sent = sendto(socket_fd, data, length, 0, (const struct sockaddr *)server_addr, sizeof(*server_addr));
    if (bytes_sent < 0) {
#ifdef _WIN32
    log_error("Sendto failed");
#else
    perror("Sendto failed");
#endif
    return -1;
    }
    return bytes_sent;
}

// Получение данных через UDP
ssize_t receive_udp_data(int socket_fd, void *buffer, size_t length, struct sockaddr_in *client_addr) {
    if (!is_socket_valid(socket_fd)) {
        log_error("Invalid socket descriptor");
        return -1;

        if (!is_fd_valid(socket_fd)) {
            log_error("Invalid socket descriptor");
            return -1;
        }
        
    }

    socklen_t addr_len = sizeof(*client_addr);
    ssize_t bytes_received = recvfrom(socket_fd, buffer, length, 0, (struct sockaddr *)client_addr, &addr_len);
    if (bytes_received < 0) {
#ifdef _WIN32
        log_error("Recvfrom failed");
#else
        perror("Recvfrom failed");
#endif
        return -1;
    } else if (bytes_received == 0) {
        log_info("Connection closed by peer");
        return 0;
    }

    return bytes_received;
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

/* Proxy protocol */


int establish_https_proxy_tunnel(const char *proxy_ip, int proxy_port, const char *target_host, int target_port) {
    if (!proxy_ip || !target_host || proxy_port <= 0 || target_port <= 0) {
        log_error("Invalid proxy or target parameters");
        return -1;
    }

    // Установка TCP-соединения с прокси-сервером
    int sockfd = establish_tcp_tunnel(proxy_ip, proxy_port);
    if (sockfd < 0) {
        log_error("Failed to establish TCP tunnel to proxy");
        return -1;
    }

    // Формирование HTTP CONNECT запроса
    char request[512]; // Увеличен размер буфера для безопасности
    int ret = snprintf(request, sizeof(request), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
                       target_host, target_port, target_host, target_port);
    if (ret < 0 || ret >= sizeof(request)) {
        log_error("Failed to format CONNECT request");
        close_connection(sockfd);
        return -1;
    }

    // Отправка запроса на прокси
    ssize_t bytes_sent = send(sockfd, request, strlen(request), 0);
    if (bytes_sent < 0) {
        log_error("Failed to send CONNECT request to proxy");
        close_connection(sockfd);
        return -1;
    }

    // Чтение ответа от прокси
    #define RESPONSE_BUFFER_SIZE 1024
    char *response = malloc(RESPONSE_BUFFER_SIZE);
    if (!response) {
        log_error("Memory allocation failed");
        close_connection(sockfd);
        return -1;
    }

    ssize_t bytes_received = recv(sockfd, response, RESPONSE_BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        log_error("Failed to receive proxy response");
        free(response);
        close_connection(sockfd);
        return -1;
    }

    response[bytes_received] = '\0';
    if (strncmp(response, "HTTP/1.1 200", 12) != 0) { // Проверяем начало ответа
        log_error("Proxy connection failed: %s", response);
        free(response);
        close_connection(sockfd);
        return -1;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL handshake failed");
        close_connection(sockfd);
        return -1;
    }

    if (!verify_certificate(ssl, target_host)) {
        log_error("Certificate verification failed for %s", target_host);
        SSL_free(ssl);
        close_connection(sockfd);
        return -1;
    }



    free(response);
    log_info("HTTPS proxy tunnel established successfully");
    return sockfd;
}


void add_proxy(const char *ip, int port) {
    if (proxy_count < MAX_PROXIES) {
    strncpy(proxies[proxy_count].ip, ip, sizeof(proxies[proxy_count].ip) - 1);
    proxies[proxy_count].ip[sizeof(proxies[proxy_count].ip) - 1] = '\0';
    proxies[proxy_count].port = port;
    proxies[proxy_count].is_available = true;
    proxy_count++;
    }
}

int establish_connection_with_proxy(const char *proxy_ip, int proxy_port, const char *target_host, int target_port) {
    int sockfd = establish_https_proxy_tunnel(proxy_ip, proxy_port, target_host, target_port);
    if (sockfd < 0) {
        log_error("Failed to establish HTTPS proxy tunnel");
        return -1;
    }

    log_info("HTTPS proxy tunnel established successfully through %s:%d", proxy_ip, proxy_port);
    return sockfd;
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

// Инициализация Shadowsocks-соединения
bool initialize_shadowsocks(ShadowsocksState *state, const char *server_ip, int port, const char *password, const char *method) {
    pthread_mutex_lock(&shadowsocks_mutex);

    if (!state || !server_ip || !password || !method) {
        log_error("Invalid arguments for Shadowsocks initialization");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    // Очистка предыдущего состояния
    memset(state, 0, sizeof(ShadowsocksState));

    // Копирование параметров
    strncpy(state->server_ip, server_ip, sizeof(state->server_ip) - 1);
    state->server_port = port;
    strncpy(state->password, password, sizeof(state->password) - 1);
    strncpy(state->method, method, sizeof(state->method) - 1);

    // Создание сокета
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    // Настройка адреса сервера
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_error("Invalid server IP address: %s", server_ip);
        close(sockfd);
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    // Подключение к серверу
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to connect to Shadowsocks server");
        close(sockfd);
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    // Инициализация шифрования
    if (!initialize_encryption_with_password(method, password)) {
        log_error("Failed to initialize encryption for Shadowsocks");
        close(sockfd);
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    // Сохранение состояния
    state->socket_fd = sockfd;
    state->is_connected = true;

    log_info("Shadowsocks connection established successfully to %s:%d", server_ip, port);
    pthread_mutex_unlock(&shadowsocks_mutex);
    return true;
}

// Закрытие Shadowsocks-соединения
void close_shadowsocks(ShadowsocksState *state) {
    pthread_mutex_lock(&shadowsocks_mutex);

    if (!state) {
        log_warning("Invalid Shadowsocks state");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return;
    }

    if (state->socket_fd >= 0) {
#ifdef _WIN32
        closesocket(state->socket_fd);
#else
        close(state->socket_fd);
#endif
        log_info("Shadowsocks socket closed successfully");
        state->socket_fd = -1;
    }

    // Очистка пароля из памяти
    secure_clear_memory(state->password, sizeof(state->password));

    // Сброс состояния
    state->is_connected = false;
    memset(state->server_ip, 0, sizeof(state->server_ip));
    state->server_port = 0;

    pthread_mutex_unlock(&shadowsocks_mutex);
}

// Отправка данных через Shadowsocks
ssize_t send_data_shadowsocks(ShadowsocksState *state, const void *data, size_t length) {
    pthread_mutex_lock(&shadowsocks_mutex);

    if (!state || !state->is_connected || state->socket_fd < 0) {
        log_error("Invalid Shadowsocks state or socket");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    }

    // Шифрование данных
    size_t encrypted_len;
    unsigned char encrypted_buffer[4096];
    if (!encrypt_data(data, length, encrypted_buffer, &encrypted_len)) {
        log_error("Encryption failed for Shadowsocks data");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    }

    // Отправка зашифрованных данных
    ssize_t bytes_sent = send(state->socket_fd, encrypted_buffer, encrypted_len, 0);
    if (bytes_sent < 0) {
        log_error("Failed to send Shadowsocks data");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    }

    pthread_mutex_unlock(&shadowsocks_mutex);
    return bytes_sent;
}

// Получение данных через Shadowsocks
ssize_t receive_data_shadowsocks(ShadowsocksState *state, void *buffer, size_t length) {
    pthread_mutex_lock(&shadowsocks_mutex);

    if (!state || !state->is_connected || state->socket_fd < 0) {
        log_error("Invalid Shadowsocks state or socket");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    }

    // Получение зашифрованных данных
    ssize_t bytes_received = recv(state->socket_fd, buffer, length, 0);
    if (bytes_received < 0) {
        log_error("Failed to receive Shadowsocks data");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    } else if (bytes_received == 0) {
        log_info("Shadowsocks connection closed by peer");
        state->is_connected = false;
        pthread_mutex_unlock(&shadowsocks_mutex);
        return 0;
    }

    // Дешифрование данных
    size_t decrypted_len;
    if (!decrypt_data(buffer, bytes_received, buffer, &decrypted_len)) {
        log_error("Decryption failed for Shadowsocks data");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return -1;
    }

    pthread_mutex_unlock(&shadowsocks_mutex);
    return decrypted_len;
}

// Переподключение при разрыве
bool reconnect_shadowsocks(ShadowsocksState *state) {
    pthread_mutex_lock(&shadowsocks_mutex);

    if (!state || !state->is_connected) {
        log_warning("Already disconnected, no need to reconnect");
        pthread_mutex_unlock(&shadowsocks_mutex);
        return false;
    }

    log_info("Attempting to reconnect to Shadowsocks server at %s:%d", state->server_ip, state->server_port);

    // Закрытие текущего соединения
    close_shadowsocks(state);

    // Повторная инициализация
    bool success = initialize_shadowsocks(state, state->server_ip, state->server_port, state->password, state->method);
    if (success) {
        state->is_connected = true;
    }

    pthread_mutex_unlock(&shadowsocks_mutex);
    return success;
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

/*   wireGuard protocol logic  */ 



static pthread_mutex_t wg_mutex = PTHREAD_MUTEX_INITIALIZER;

// Генерация ключей WireGuard
static bool generate_wireguard_keys(char *private_key, char *public_key) {
    pthread_mutex_lock(&wg_mutex);
    uint8_t raw_private_key[32];
    uint8_t raw_public_key[32];

    // Генерация приватного ключа
    if (!RAND_bytes(raw_private_key, sizeof(raw_private_key))) {
        log_error("Failed to generate private key");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Генерация публичного ключа
    if (curve25519_generate_public(raw_public_key, raw_private_key) != 0) {
        log_error("Failed to generate public key");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Кодирование ключей в Base64
    if (!base64_encode(private_key, raw_private_key, sizeof(raw_private_key)) ||
        !base64_encode(public_key, raw_public_key, sizeof(raw_public_key))) {
        log_error("Base64 encoding failed");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    secure_clear_memory(raw_private_key, sizeof(raw_private_key));
    secure_clear_memory(raw_public_key, sizeof(raw_public_key));
    pthread_mutex_unlock(&wg_mutex);
    return true;
}

// Инициализация WireGuard на Windows
bool initialize_wireguard(WireGuardState *state, const char *server_endpoint, const char *private_key, const char *server_public_key) {
    pthread_mutex_lock(&wg_mutex);

    if (!state || !server_endpoint || !private_key || !server_public_key) {
        log_error("Invalid arguments for WireGuard initialization");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Сохраняем endpoint
    strncpy(state->endpoint, server_endpoint, sizeof(state->endpoint) - 1);
    state->endpoint[sizeof(state->endpoint) - 1] = '\0';

    // Генерация ключей (если не предоставлены)
    if (strlen(private_key) == 0) {
        char generated_private_key[64];
        char generated_public_key[64];
        if (!generate_wireguard_keys(generated_private_key, generated_public_key)) {
            pthread_mutex_unlock(&wg_mutex);
            return false;
        }
        strncpy(state->private_key, generated_private_key, sizeof(state->private_key));
        log_info("Generated new WireGuard key pair");
    } else {
        strncpy(state->private_key, private_key, sizeof(state->private_key));
    }

    // Декодирование публичного ключа сервера
    BYTE decoded_public_key[WIREGUARD_KEY_LENGTH];
    if (!base64_decode_key(server_public_key, decoded_public_key)) {
        log_error("Failed to decode server public key");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }
    memcpy(state->public_key, decoded_public_key, WIREGUARD_KEY_LENGTH);

#ifdef _WIN32
    // Создание адаптера
    state->adapter = WireGuardCreateAdapter(L"WireGuard-VPN", L"VPN Tunnel", NULL);
    if (!state->adapter) {
        log_error("Failed to create WireGuard adapter");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Настройка интерфейса
    WIREGUARD_INTERFACE wg_interface = {0};
    if (!base64_decode_key(state->private_key, wg_interface.PrivateKey)) {
        log_error("Invalid private key");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }
    wg_interface.ListenPort = 51820;

    if (WireGuardSetInterface(state->adapter, &wg_interface) != ERROR_SUCCESS) {
        log_error("Failed to configure WireGuard interface");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Добавление пира
    WIREGUARD_PEER peer = {0};
    memcpy(peer.PublicKey, decoded_public_key, WIREGUARD_KEY_LENGTH);
    peer.PersistentKeepalive = 25;

    // Парсим endpoint
    SOCKADDR_INET endpoint_addr;
    if (!parse_endpoint(server_endpoint, &endpoint_addr)) { // Используем server_endpoint
        log_error("Failed to parse endpoint");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }
    peer.Endpoint = endpoint_addr;

    if (WireGuardAddPeer(state->adapter, &peer) != ERROR_SUCCESS) {
        log_error("Failed to add WireGuard peer");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    WIREGUARD_ALLOWED_IP allowed_ips[2] = {0};
    allowed_ips[0].Address.V4.sin_family = AF_INET;
    inet_pton(AF_INET, "0.0.0.0", &allowed_ips[0].Address.V4.sin_addr);
    allowed_ips[0].Cidr = 0;

    allowed_ips[1].Address.V6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &allowed_ips[1].Address.V6.sin6_addr);
    allowed_ips[1].Cidr = 0;

    if (WireGuardSetAllowedIPs(state->adapter, peer.PublicKey, allowed_ips, 2) != ERROR_SUCCESS) {
        log_error("Failed to set allowed IPs");
        WireGuardRemovePeer(state->adapter, peer.PublicKey);
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }
#else
    // Unix-версия
    state->wg_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->wg_fd < 0) {
        log_error("Failed to create WireGuard socket");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    struct wg_device *device = calloc(1, sizeof(struct wg_device));
    if (!device) {
        log_error("Memory allocation failed");
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    if (wg_key_from_base64(device->private_key, state->private_key) != 0) {
        log_error("Invalid private key format");
        free(device);
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    struct wg_peer *peer = calloc(1, sizeof(struct wg_peer));
    if (!peer) {
        log_error("Memory allocation failed");
        free(device);
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    if (wg_key_from_base64(peer->public_key, state->public_key) != 0) {
        log_error("Invalid server public key");
        free(peer);
        free(device);
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Парсинг endpoint
    char *endpoint_copy = strdup(server_endpoint);
    char *ip = strtok(endpoint_copy, ":");
    char *port_str = strtok(NULL, ":");
    if (!ip || !port_str) {
        log_error("Invalid endpoint format");
        free(endpoint_copy);
        free(peer);
        free(device);
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    peer->endpoint.sin_family = AF_INET;
    peer->endpoint.sin_port = htons(atoi(port_str));
    inet_pton(AF_INET, ip, &peer->endpoint.sin_addr);

    device->peers = peer;
    device->peers_count = 1;

    if (ioctl(state->wg_fd, WG_IOCTL_SET_DEVICE, device) != 0) {
        log_error("Failed to set WireGuard device configuration");
        free(endpoint_copy);
        free(peer);
        free(device);
        close(state->wg_fd);
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    free(endpoint_copy);
    free(peer);
    free(device);
#endif

    state->is_connected = true;
    log_info("WireGuard initialized successfully");
    pthread_mutex_unlock(&wg_mutex);
    return true;
}

// Завершение WireGuard
void close_wireguard(WireGuardState *state) {
    pthread_mutex_lock(&wg_mutex);

    if (!state->is_connected) {
        log_warning("WireGuard is not connected");
        pthread_mutex_unlock(&wg_mutex);
        return;
    }

#ifdef _WIN32
    if (state->adapter) {
        WireGuardRemovePeer(state->adapter, state->public_key);
        WireGuardCloseAdapter(state->adapter);
        state->adapter = NULL;
    }
#else
    if (state->wg_fd >= 0) {
        close(state->wg_fd);
        state->wg_fd = -1;
    }
#endif

    secure_clear_memory(state->private_key, sizeof(state->private_key));
    secure_clear_memory(state->public_key, sizeof(state->public_key));
    state->is_connected = false;
    log_info("WireGuard connection closed");
    pthread_mutex_unlock(&wg_mutex);
}

// Переподключение
bool reconnect_wireguard(WireGuardState *state) {
    pthread_mutex_lock(&wg_mutex);

    if (!state->is_connected) {
        log_error("Cannot reconnect: WireGuard is not initialized");
        pthread_mutex_unlock(&wg_mutex);
        return false;
    }

    // Закрытие текущего соединения
    close_wireguard(state);

    // Повторная инициализация
    bool success = initialize_wireguard(state, state->endpoint, state->private_key, state->public_key);
    if (success) {
        log_info("Reconnected to WireGuard successfully");
    }

    pthread_mutex_unlock(&wg_mutex);
    return success;
}
