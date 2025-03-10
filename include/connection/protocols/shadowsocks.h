#ifndef SHADOWSOCKS_H
#define SHADOWSOCKS_H

#include <stdint.h>

typedef struct {
    char *server;         // Сервер Shadowsocks
    uint16_t server_port; // Порт сервера
    char *password;       // Пароль для аутентификации
    char *method;         // Метод шифрования
    char *local_addr;     // Локальный адрес для прослушивания
    uint16_t local_port;  // Локальный порт
} ShadowsocksConfig;

// Состояние соединения
typedef enum {
    SS_STOPPED,
    SS_RUNNING,
    SS_ERROR
} SSState;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Инициализация Shadowsocks контекста
 * @param config Конфигурация подключения
 * @return 0 при успехе, -1 при ошибке
 */
int ss_init(const ShadowsocksConfig *config);

/**
 * Запуск Shadowsocks клиента
 * @return 0 при успехе, -1 при ошибке
 */
int ss_start();

/**
 * Остановка клиента
 */
void ss_stop();

/**
 * Получение текущего состояния
 */
SSState ss_get_state();

/**
 * Очистка ресурсов
 */
void ss_cleanup();

#ifdef __cplusplus
}
#endif

#endif // SHADOWSOCKS_H