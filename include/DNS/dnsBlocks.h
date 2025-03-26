#ifndef DNS_BLOCKS_H
#define DNS_BLOCKS_H

#include <stdbool.h>
#include "dnsResolver.h"

// Типы блокировок
typedef enum {
    BLOCK_NONE = 0,
    BLOCK_ADS = 1,
    BLOCK_TRACKERS = 2,
    BLOCK_BOTH = 3
} BlockType;

// Настройка DNS-блокировок
bool dns_blocks_set(BlockType type);

// Восстановление оригинальных DNS-настроек
bool dns_blocks_reset();

#endif // DNS_BLOCKS_H
