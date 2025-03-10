#ifndef WIREGUARDWIN_H
#define WIREGUARDWIN_H


#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include "libs/wireguard-nt-master/api/wireguard.h"
#include "libs/wireguard-nt-master/api/adapter.h"
#endif

typedef struct {
    char private_key[64];   // Base64-приватный ключ
    char public_key[64];    // Base64-публичный ключ сервера
    char endpoint[128];     // Сервер в формате "IP:port"
    int mtu;                // MTU (по умолчанию 1420)
    bool is_connected;      // Состояние соединения
#ifdef _WIN32
    WIREGUARD_ADAPTER *adapter; // Адаптер для Windows
#else
    int wg_fd;              // Файловый дескриптор для Unix
#endif
} WireGuardState;

// Инициализация WireGuard
bool wg_initialize(WireGuardState *state, const char *server_endpoint, const char *private_key, const char *server_public_key);

// Завершение работы
void wg_teardown(WireGuardState *state);

// Переподключение
bool wg_reconnect(WireGuardState *state);

#endif  