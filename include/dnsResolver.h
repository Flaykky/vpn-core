#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdbool.h>
#include <stdint.h>

// Структура для хранения DNS-конфигурации
typedef struct {
    char *dns_server_ip;
    int dns_port;
    bool use_tls; // Для DNS-over-TLS
} DNSResolver;

// Инициализация DNS-резолвера
bool initialize_dns_resolver(DNSResolver *resolver, const char *dns_server);

// Отправка DNS-запроса
bool send_dns_query(DNSResolver *resolver, const char *domain, uint8_t *response, size_t *response_len);

// Очистка DNS-резолвера
void cleanup_dns_resolver(DNSResolver *resolver);

#endif // DNS_RESOLVER_H