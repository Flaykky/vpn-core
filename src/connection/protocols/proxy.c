#include "include/connection/connection.h"
#include "include/utils/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "include/utils/common.h"
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


