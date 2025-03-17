#ifndef WGLINUX_H
#define WGLINUX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_IFACE_NAME_MAX 16
#define WG_KEY_SIZE 32
#define WG_HANDSHAKE_MESSAGE_SIZE 96
#define WG_PACKET_MAX_SIZE 1500

typedef struct {
    int tun_fd;                        // Дескриптор TUN-интерфейса
    char if_name[WG_IFACE_NAME_MAX];     // Имя TUN-интерфейса
    uint8_t private_key[WG_KEY_SIZE];    // Приватный ключ
    uint8_t public_key[WG_KEY_SIZE];     // Публичный ключ
    // Здесь можно добавить поля для состояния рукопожатия, ключей сеанса, счетчиков и т.д.
} WGContext;

// Инициализация контекста Wireguard: создание TUN-интерфейса, генерация ключей и пр.
int wg_init(WGContext *ctx, const char *if_name);

// Запуск VPN-сервиса: выполнение рукопожатия и запуск основного цикла обработки пакетов.
int wg_start(WGContext *ctx);

// Остановка сервиса и освобождение ресурсов.
void wg_stop(WGContext *ctx);

// Отправка зашифрованного пакета через туннель Wireguard.
int wg_send_packet(WGContext *ctx, const void *packet, size_t length);

// Прием и дешифровка пакета из туннеля Wireguard.
int wg_receive_packet(WGContext *ctx, void *buffer, size_t buffer_length);

#ifdef __cplusplus
}
#endif

#endif // WGLINUX_H
