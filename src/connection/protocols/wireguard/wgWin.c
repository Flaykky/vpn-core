#include "wireguard-nt-master/api/adapter.h"
#include "wireguard-nt-master/api/wireguard.h"
#include "logging.h"
#include <windows.h>
#include <winsock2.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "wgWin.h"
#include <ws2ipdef.h>

static pthread_mutex_t wg_win_mutex = PTHREAD_MUTEX_INITIALIZER;


WIREGUARD_ALLOWED_IP allowed_ips[2] = {0};


// Функция для безопасной очистки памяти
static void secure_clear(void *ptr, size_t size) {
    if (ptr) {
        SecureZeroMemory(ptr, size);
    }
}

// Генерация ключей (Windows)
static bool generate_keys_win(char *private_key, char *public_key) {
    BCRYPT_ALG_HANDLE alg_handle;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        log_error("Failed to open RNG provider: 0x%08x", status);
        return false;
    }

    // Генерация приватного ключа
    uint8_t raw_private_key[32];
    status = BCryptGenRandom(alg_handle, raw_private_key, sizeof(raw_private_key), 0);
    BCryptCloseAlgorithmProvider(alg_handle, 0);
    if (!NT_SUCCESS(status)) {
        log_error("Failed to generate private key: 0x%08x", status);
        return false;
    }

    // Конвертация в Base64
    if (!base64_encode(private_key, raw_private_key, sizeof(raw_private_key)) ||
        !base64_encode(public_key, raw_private_key, sizeof(raw_private_key))) {
        log_error("Base64 encoding failed");
        secure_clear(raw_private_key, sizeof(raw_private_key));
        return false;
    }

    secure_clear(raw_private_key, sizeof(raw_private_key));
    return true;
}

// Парсинг endpoint (IP:port)
static bool parse_endpoint_win(const char *endpoint, SOCKADDR_INET *addr) {
    char *copy = strdup(endpoint);
    char *ip = strtok(copy, ":");
    char *port_str = strtok(NULL, ":");
    if (!ip || !port_str) {
        log_error("Invalid endpoint format");
        free(copy);
        return false;
    }

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        log_error("Invalid port: %d", port);
        free(copy);
        return false;
    }

    addr->Ipv4.sin_family = AF_INET;
    addr->Ipv4.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr->Ipv4.sin_addr) != 1) {
        log_error("Invalid IP address: %s", ip);
        free(copy);
        return false;
    }

    free(copy);
    return true;
}

// Инициализация WireGuard на Windows
bool wg_initialize(WireGuardState *state, const char *server_endpoint, const char *private_key, const char *server_public_key) {
    pthread_mutex_lock(&wg_win_mutex);

    if (!state || !server_endpoint || !private_key || !server_public_key) {
        log_error("Invalid arguments for WireGuard initialization");
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    // Генерация ключей, если не предоставлены
    if (strlen(private_key) == 0) {
        if (!generate_keys_win(state->private_key, state->public_key)) {
            pthread_mutex_unlock(&wg_win_mutex);
            return false;
        }
        log_info("Generated new WireGuard key pair");
    } else {
        strncpy(state->private_key, private_key, sizeof(state->private_key));
    }

    strncpy(state->public_key, server_public_key, sizeof(state->public_key));
    strncpy(state->endpoint, server_endpoint, sizeof(state->endpoint));

    // Создание адаптера
    state->adapter = WireGuardCreateAdapter(L"WireGuard-NT", L"VPN Adapter", NULL);
    if (!state->adapter) {
        log_error("Failed to create WireGuard adapter");
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    // Настройка интерфейса
    WIREGUARD_INTERFACE wg_interface = {0};
    if (WireGuardKeyB64ToU8(state->private_key, wg_interface.PrivateKey) != ERROR_SUCCESS) {
        log_error("Invalid private key format");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }
    wg_interface.ListenPort = 51820; // Порт по умолчанию

    if (WireGuardSetInterface(state->adapter, &wg_interface) != ERROR_SUCCESS) {
        log_error("Failed to configure WireGuard interface");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    // Настройка пира
    WIREGUARD_PEER peer = {0};
    if (WireGuardKeyB64ToU8(server_public_key, peer.PublicKey) != ERROR_SUCCESS) {
        log_error("Invalid server public key");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    SOCKADDR_INET endpoint_addr;
    if (!parse_endpoint_win(server_endpoint, &endpoint_addr)) {
        log_error("Failed to parse endpoint");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }
    peer.Endpoint = endpoint_addr;
    peer.PersistentKeepalive = 25;

    // Добавление пира
    if (WireGuardAddPeer(state->adapter, &peer) != ERROR_SUCCESS) {
        log_error("Failed to add peer");
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    // Настройка AllowedIPs (0.0.0.0/0 и ::/0)
    WIREGUARD_ALLOWED_IP allowed_ips[2] = {0};
    allowed_ips[0].Address.V4.sin_family = AF_INET;
    allowed_ips[0].Cidr = 0; // 0.0.0.0/0
    allowed_ips[1].Address.V6.sin6_family = AF_INET6;
    allowed_ips[1].Cidr = 0; // ::/0

    if (WireGuardSetAllowedIPs(state->adapter, peer.PublicKey, allowed_ips, 2) != ERROR_SUCCESS) {
        log_error("Failed to set allowed IPs");
        WireGuardRemovePeer(state->adapter, peer.PublicKey);
        WireGuardCloseAdapter(state->adapter);
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    state->is_connected = true;
    log_info("WireGuard initialized successfully on Windows");
    pthread_mutex_unlock(&wg_win_mutex);
    return true;
}

// Завершение работы
void wg_teardown(WireGuardState *state) {
    pthread_mutex_lock(&wg_win_mutex);

    if (!state->is_connected) {
        pthread_mutex_unlock(&wg_win_mutex);
        return;
    }

    // Удаляем всех пиров
    WireGuardRemoveAllPeers(state->adapter);

    // Удаляем адаптер
    WireGuardCloseAdapter(state->adapter);
    state->adapter = NULL;

    // Очищаем ключи
    secure_clear(state->private_key, sizeof(state->private_key));
    secure_clear(state->public_key, sizeof(state->public_key));

    state->is_connected = false;
    log_info("WireGuard teardown completed on Windows");
    pthread_mutex_unlock(&wg_win_mutex);
}

// Переподключение
bool wg_reconnect(WireGuardState *state) {
    pthread_mutex_lock(&wg_win_mutex);

    if (!state->is_connected) {
        pthread_mutex_unlock(&wg_win_mutex);
        return false;
    }

    // Завершаем текущее соединение
    wg_teardown(state);

    // Повторная инициализация
    bool success = wg_initialize(state, state->endpoint, state->private_key, state->public_key);
    pthread_mutex_unlock(&wg_win_mutex);
    return success;
}