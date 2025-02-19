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

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

typedef struct {
    SSL_CTX *ssl_ctx;
} EncryptionContext;

typedef struct {
    int socket_fd;
    char server_ip[MAX_IP_LENGTH];
    int port;
    bool is_connected;
    SSL_CTX *ssl_ctx; // Добавляем поле для SSL контекста
} ConnectionState;




pthread_mutex_t connection_mutex;
WSADATA wsa_data;
static SSL_CTX *ssl_ctx = NULL;


#ifdef _WIN32
static void init_winsock(void) {
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        log_error("WSAStartup failed with error: %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
}
#endif

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
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        log_error("Failed to resolve hostname: %s", hostname);
        return false;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        memcpy(addr, ipv4, sizeof(struct sockaddr_in));
        break;
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
    char response[RESPONSE_BUFFER_SIZE];
    ssize_t bytes_received = recv(sockfd, response, RESPONSE_BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        log_error("Failed to receive response from proxy");
        close_connection(sockfd);
        return -1;
    }

    // Завершение строки и проверка ответа
    response[bytes_received] = '\0'; // Обязательно завершаем строку
    if (strstr(response, "200 Connection established") == NULL) {
        log_error("Proxy connection failed: %s", response);
        close_connection(sockfd);
        return -1;
    }

    log_info("HTTPS proxy tunnel established successfully through %s:%d", proxy_ip, proxy_port);
    return sockfd;
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






// Проверка состояния соединения
#define MAX_PROXIES 10

typedef struct {
    char ip[16];
    int port;
    bool is_available;
} Proxy;



static Proxy proxies[MAX_PROXIES];
static int proxy_count = 0;

void add_proxy(const char *ip, int port) {
    if (proxy_count < MAX_PROXIES) {
    strncpy(proxies[proxy_count].ip, ip, sizeof(proxies[proxy_count].ip) - 1);
    proxies[proxy_count].ip[sizeof(proxies[proxy_count].ip) - 1] = '\0';
    proxies[proxy_count].port = port;
    proxies[proxy_count].is_available = true;
    proxy_count++;
    }
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

    if (!state) {
        log_error("Invalid connection state");
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    if (state->is_connected) {
        log_warning("Already connected, no need to reconnect");
        pthread_mutex_unlock(&connection_mutex);
        return true;
    }

    log_info("Attempting to reconnect to %s:%d", state->server_ip, state->port);
    // Исправляем вызов: передаем сокет и обновляем состояние
    close_connection(state->socket_fd);
    state->is_connected = false;


    if (!state || !state->server_ip) {
        log_error("Invalid connection state or server IP");
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }
    bool success = initialize_connection(state, state->server_ip, state->port);
    if (success) {
        state->is_connected = true;
    }
    pthread_mutex_unlock(&connection_mutex);

    return success;
}
