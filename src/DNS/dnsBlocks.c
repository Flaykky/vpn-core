#include "include/DNS/dnsBlocks.h"
#include "include/DNS/dnsResolver.h"
#include "include/utils/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// Пример списков блокировки (замените на реальные)
static const char *default_ads[] = {"ads.example.com", "tracking.example.com"};
static const char *default_trackers[] = {"tracker1.com", "analytics.example.com"};

// Инициализация блокировщика
bool dns_blocks_init(DnsBlocker *blocker, BlockType type) {
    if (!blocker) return false;

    pthread_mutex_lock(&blocker->mutex);
    
    // Загрузка блок-листов из файлов (пример)
    if (type & BLOCK_ADS) {
        blocker->blocklist_ads = malloc(sizeof(default_ads));
        memcpy(blocker->blocklist_ads, default_ads, sizeof(default_ads));
        blocker->ads_count = sizeof(default_ads)/sizeof(default_ads[0]);
    }

    if (type & BLOCK_TRACKERS) {
        blocker->blocklist_trackers = malloc(sizeof(default_trackers));
        memcpy(blocker->blocklist_trackers, default_trackers, sizeof(default_trackers));
        blocker->trackers_count = sizeof(default_trackers)/sizeof(default_trackers[0]);
    }

    pthread_mutex_unlock(&blocker->mutex);
    log_info("DNS blocker initialized with type: %d", type);
    return true;
}

// Проверка домена
bool dns_blocks_check_domain(DnsBlocker *blocker, const char *domain) {
    pthread_mutex_lock(&blocker->mutex);

    if (blocker->blocklist_ads) {
        for (size_t i = 0; i < blocker->ads_count; i++) {
            if (strstr(domain, blocker->blocklist_ads[i])) {
                log_info("Blocked ad domain: %s", domain);
                pthread_mutex_unlock(&blocker->mutex);
                return true;
            }
        }
    }

    if (blocker->blocklist_trackers) {
        for (size_t i = 0; i < blocker->trackers_count; i++) {
            if (strstr(domain, blocker->blocklist_trackers[i])) {
                log_info("Blocked tracker domain: %s", domain);
                pthread_mutex_unlock(&blocker->mutex);
                return true;
            }
        }
    }

    pthread_mutex_unlock(&blocker->mutex);
    return false;
}

// Проверка IP
bool dns_blocks_check_ip(DnsBlocker *blocker, const char *ip) {
    pthread_mutex_lock(&blocker->mutex);
    
    // Пример проверки IP (можно интегрировать с базой заблокированных IP)
    if (strcmp(ip, "192.168.1.100") == 0) { // Заглушка
        log_info("Blocked malicious IP: %s", ip);
        pthread_mutex_unlock(&blocker->mutex);
        return true;
    }

    pthread_mutex_unlock(&blocker->mutex);
    return false;
}

// Очистка
void dns_blocks_cleanup(DnsBlocker *blocker) {
    pthread_mutex_lock(&blocker->mutex);
    
    free(blocker->blocklist_ads);
    free(blocker->blocklist_trackers);
    blocker->ads_count = 0;
    blocker->trackers_count = 0;
    
    pthread_mutex_unlock(&blocker->mutex);
    log_info("DNS blocker cleaned up");
}