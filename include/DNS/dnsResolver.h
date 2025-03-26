#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdbool.h>
#include <stdint.h>

// Типы DNS-серверов
typedef enum {
    DNS_BLOCK_ADS = 0,      // 100.64.0.1
    DNS_BLOCK_TRACKERS,     // 100.64.0.2
    DNS_BLOCK_ALL           // 100.64.0.3
} DnsServerType;

// Структура для DNS-резолвера
typedef struct {
    char *dns_servers[3];   // Массив серверов
    DnsServerType current;  // Текущий сервер
    pthread_mutex_t mutex;  // Потокобезопасность
} DnsResolver;

// Инициализация DNS-резолвера
bool dns_resolver_init(DnsResolver *resolver, DnsServerType type);

// Разрешение домена в IP
bool dns_resolve(DnsResolver *resolver, const char *domain, char *ip_buffer, size_t ip_buffer_size);

// Деинициализация
void dns_resolver_cleanup(DnsResolver *resolver);

#endif // DNS_RESOLVER_H
