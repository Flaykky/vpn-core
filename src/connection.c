#include "connection.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/types.h>
#include <openssl/evp.h>


#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
typedef SSIZE_T ssize_t;
#pragma comment(lib, "ws2_32.lib")

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>


static pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;


struct sockaddr_in server_addr;
memset(&server_addr, 0, sizeof(server_addr)); // Полная инициализация
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(port);

static void cleanup_winsock(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Установка TCP-туннеля
int establish_tcp_tunnel(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Инициализация Winsock на Windows
    init_winsock();

    // Создание сокета
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        cleanup_winsock();
        return -1;
    }

    // Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Преобразование IP-адреса из текстового формата в сетевой
if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    if (errno == EAFNOSUPPORT) {
        log_error("Invalid address family for IP address");
    } else {
        log_error("Invalid or unsupported IP address format");
    }
    close_connection(sockfd);
    cleanup_winsock();
    return -1;
}

    // Подключение к серверу
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed");
        close_connection(sockfd);
        cleanup_winsock();
        return -1;
    }

    log_info("TCP tunnel established successfully to %s:%d", server_ip, port);
    return sockfd;
}

// Инициализация Winsock на Windows
static void init_winsock(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        log_error("WSAStartup failed");
        exit(EXIT_FAILURE);
    }
#endif
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
    pthread_mutex_lock(&connection_mutex);

    if (!state) {
        log_error("Invalid connection state");
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    init_winsock();

    // Создание сокета
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
        cleanup_winsock();
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    // Настройка адреса сервера
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        if (!resolve_hostname(server_ip, &server_addr)) {
            log_error("Failed to resolve hostname: %s", server_ip);
            close(sockfd);
            cleanup_winsock();
            pthread_mutex_unlock(&connection_mutex);
            return false;
        }
    }

    // Подключение к серверу
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection to server failed");
        close(sockfd);
        cleanup_winsock();
        pthread_mutex_unlock(&connection_mutex);
        return false;
    }

    // Сохранение состояния соединения
    state->socket_fd = sockfd;
    snprintf(state->server_ip, MAX_IP_LENGTH, "%s", server_ip); // Безопасное копирование строки
    state->port = port;
    state->is_connected = true;

    log_info("Connection established successfully to %s:%d", server_ip, port);
    pthread_mutex_unlock(&connection_mutex);
    return true;
}

// Закрытие соединения
void close_connection(int socket_fd) {
    pthread_mutex_lock(&connection_mutex);
    if (socket_fd >= 0) {
#ifdef _WIN32
        closesocket(socket_fd);
#else
        close(socket_fd);
#endif
        cleanup_winsock();
        log_info("Connection closed successfully");
    } else {
        log_error("Invalid socket descriptor");
    }
    pthread_mutex_unlock(&connection_mutex);
}


int establish_https_proxy_tunnel(const char *proxy_ip, int proxy_port, const char *target_host, int target_port) {
    // ... [остальной код]

    // Чтение ответа от прокси
    char response[256];
    ssize_t bytes_received = recv(sockfd, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0) {
        log_error("Failed to receive response from proxy");
        close_connection(sockfd);
        cleanup_winsock();
        return -1;
    }
    response[bytes_received] = '\0'; // Обязательно завершаем строку

    // Проверка успешности подключения
    if (strstr(response, "200 Connection established") == NULL) {
        log_error("Proxy connection failed: %s", response);
        close_connection(sockfd);
        cleanup_winsock();
        return -1;
    }

    log_info("HTTPS proxy tunnel established successfully through %s:%d", proxy_ip, proxy_port);
    return sockfd;
}


static SSL_CTX *ssl_ctx = NULL;
SSL_CTX_set_verify_depth(ssl_ctx, 4); // Устанавливаем максимальную глубину цепочки сертификатов


bool initialize_ssl(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        log_error("Failed to create SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // Настройка проверки сертификатов
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, "ca-certificates.crt", NULL)) {
        log_error("Failed to load CA certificates: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
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
bool is_socket_valid(const ConnectionState *state) {
    return state && state->is_connected && state->socket_fd >= 0;
}

// Отправка данных через сокет
ssize_t send_data(ConnectionState *state, const void *data, size_t length) {
    pthread_mutex_lock(&connection_mutex);
    if (!is_socket_valid(state)) {
        log_error("Invalid socket descriptor");
        pthread_mutex_unlock(&connection_mutex);
        return -1;
    }

    ssize_t bytes_sent = send(state->socket_fd, data, length, 0);
    if (bytes_sent < 0) {
        log_error("Send failed: %s", strerror(errno));
        pthread_mutex_unlock(&connection_mutex);
        return -1;
    } else if (bytes_sent == 0) {
        log_warning("Connection closed by peer during send");
        state->is_connected = false;
    }

    pthread_mutex_unlock(&connection_mutex);
    return bytes_sent;
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


int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
if (result != 0) {
    log_error("WSAStartup failed with error: %d", WSAGetLastError());
    exit(EXIT_FAILURE);
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
    close_connection(state);
    bool success = initialize_connection(state, state->server_ip, state->port);

    pthread_mutex_unlock(&connection_mutex);
    return success;
}
