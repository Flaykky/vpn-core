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