#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdbool.h>
#include <stdint.h>

// Типы DNS-серверов
typedef enum {
    DNS_DEFAULT = 0,
    DNS_BLOCK_ADS = 100, // 100.64.0.1
    DNS_BLOCK_TRACKERS = 101, // 100.64.0.2
    DNS_BLOCK_BOTH = 102 // 100.64.0.3
} DnsServerType;

// Структура DNS-резолвера
typedef struct {
    char *dns_server_ip;
    uint16_t dns_port;
    pthread_mutex_t mutex;
} DNSResolver;

// Инициализация DNS-резолвера
bool dns_resolver_init(DNSResolver *resolver, DnsServerType type);

// Выполнение DNS-запроса
bool dns_resolve(DNSResolver *resolver, const char *domain, char *result, size_t result_size);

// Очистка ресурсов
void dns_resolver_cleanup(DNSResolver *resolver);

#endif // DNS_RESOLVER_H
