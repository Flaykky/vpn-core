#ifndef DNS_BLOCKS_H
#define DNS_BLOCKS_H

#include <stdbool.h>
#include "dnsResolver.h"

// Типы блокировок
typedef enum {
    BLOCK_NONE      = 0,
    BLOCK_ADS       = 1 << 0,
    BLOCK_TRACKERS  = 1 << 1
} BlockType;

// Структура для блокировщика
typedef struct {
    char **blocklist_ads;    // Список доменов рекламы
    size_t ads_count;        // Количество элементов в списке рекламы
    char **blocklist_trackers; // Список трекеров
    size_t trackers_count;   // Количество элементов в списке трекеров
    pthread_mutex_t mutex;   // Потокобезопасность
} DnsBlocker;

// Инициализация блокировщика
bool dns_blocks_init(DnsBlocker *blocker, BlockType type);

// Проверка домена на блокировку
bool dns_blocks_check_domain(DnsBlocker *blocker, const char *domain);

// Проверка IP на блокировку
bool dns_blocks_check_ip(DnsBlocker *blocker, const char *ip);

// Деинициализация
void dns_blocks_cleanup(DnsBlocker *blocker);

#endif // DNS_BLOCKS_H
