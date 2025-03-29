#include "include/DNS/dnsResolver.h"
#include "include/utils/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Стандартный DNS-порт
#define DNS_PORT 53

// Инициализация DNS-резолвера
bool dns_resolver_init(DnsResolver *resolver, DnsServerType type) {
    if (!resolver) return false;

    pthread_mutex_lock(&resolver->mutex);
    resolver->current = type;
    resolver->dns_servers[DNS_BLOCK_ADS] = "100.64.0.1";
    resolver->dns_servers[DNS_BLOCK_TRACKERS] = "100.64.0.2";
    resolver->dns_servers[DNS_BLOCK_ALL] = "100.64.0.3";
    pthread_mutex_unlock(&resolver->mutex);

    log_info("DNS resolver initialized with server type: %d", type);
    return true;
}

// Отправка DNS-запроса
static bool send_dns_query(const char *server, const char *domain, char *response, size_t response_len) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to create DNS socket");
        return false;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, server, &dest.sin_addr);

    // Формируем DNS-запрос (упрощенно)
    char query[256];
    snprintf(query, sizeof(query), "%c%c%s", 0x00, 0x01, domain); // Пример простого запроса

    if (sendto(sockfd, query, strlen(query), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        log_error("DNS query send failed");
        close(sockfd);
        return false;
    }

    ssize_t bytes_received = recvfrom(sockfd, response, response_len, 0, NULL, NULL);
    close(sockfd);

    return bytes_received > 0;
}

// Разрешение домена
bool dns_resolve(DnsResolver *resolver, const char *domain, char *ip_buffer, size_t ip_buffer_size) {
    pthread_mutex_lock(&resolver->mutex);

    const char *server = resolver->dns_servers[resolver->current];
    char response[512];
    
    if (!send_dns_query(server, domain, response, sizeof(response))) {
        pthread_mutex_unlock(&resolver->mutex);
        return false;
    }

    // Парсим ответ (упрощенно)
    strncpy(ip_buffer, response, ip_buffer_size);
    ip_buffer[ip_buffer_size - 1] = '\0';

    pthread_mutex_unlock(&resolver->mutex);
    return true;
}

// Очистка
void dns_resolver_cleanup(DnsResolver *resolver) {
    pthread_mutex_lock(&resolver->mutex);
    resolver->current = DNS_BLOCK_ADS; // Сброс на default
    pthread_mutex_unlock(&resolver->mutex);
    log_info("DNS resolver cleaned up");
}