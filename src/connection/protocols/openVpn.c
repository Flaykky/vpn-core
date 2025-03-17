#include "openVPN.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libs/openvpn/include/openvpn-msg.h"
#include <openssl/evp.h> // Для шифрования пароля


// Кроссплатформенные определения
#ifdef _WIN32
    #include <windows.h>
    #define SLEEP(ms) Sleep(ms)
    #define STRDUP(str) _strdup(str)
#else
    #include <unistd.h>
    #define SLEEP(ms) usleep((ms) * 1000)
    #define STRDUP(str) strdup(str)
#endif

// Статические переменные для отслеживания состояния
static bool is_initialized = false;
static bool is_connected = false;

// Внутренняя структура для конфигурации
typedef struct {
    char* server;
    int port;
    char* username;
    char* password;
} InternalConfig;

// Глобальная переменная для хранения конфигурации
static InternalConfig* current_config = NULL;

// Вспомогательная функция для безопасного освобождения памяти
static void safe_free(char** ptr) {
    if (*ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}


// Установка конфигурации
bool openvpn_set_config(const OpenVPNConfig* config) {
    if (!config || !config->server || !config->username || !config->password) {
        fprintf(stderr, "Ошибка: некорректная конфигурация\n");
        return false;
    }

    // Очистка существующей конфигурации
    if (current_config) {
        safe_free(&current_config->server);
        safe_free(&current_config->username);
        safe_free(&current_config->password);
        free(current_config);
        current_config = NULL;
    }

    // Выделение памяти под новую конфигурацию
    current_config = (InternalConfig*)malloc(sizeof(InternalConfig));
    if (!current_config) {
        fprintf(stderr, "Ошибка: не удалось выделить память\n");
        return false;
    }

    // Инициализация полей
    current_config->server = NULL;
    current_config->username = NULL;
    current_config->password = NULL;
    current_config->port = 0;

    // Копирование данных
    current_config->server = STRDUP(config->server);
    current_config->port = config->port;
    current_config->username = STRDUP(config->username);
    current_config->password = STRDUP(config->password);

    // Проверка успешности копирования
    if (!current_config->server || !current_config->username || !current_config->password) {
        fprintf(stderr, "Ошибка: не удалось скопировать конфигурацию\n");
        safe_free(&current_config->server);
        safe_free(&current_config->username);
        safe_free(&current_config->password);
        free(current_config);
        current_config = NULL;
        return false;
    }

    printf("Конфигурация установлена: %s:%d, пользователь: %s\n",
           current_config->server, current_config->port, current_config->username);
    return true;
}


// Инициализация OpenVPN
bool openvpn_initialize(OpenVPNContext *ctx, const OpenVPNConfig *config) {
    pthread_mutex_lock(&ctx->mutex);

    if (!ctx || !config) {
        log_error("Invalid arguments for OpenVPN initialization");
        pthread_mutex_unlock(&ctx->mutex);
        return false;
    }

    // Копирование конфигурации
    ctx->config = malloc(sizeof(OpenVPNConfig));
    if (!ctx->config) {
        log_error("Memory allocation failed");
        pthread_mutex_unlock(&ctx->mutex);
        return false;
    }

    ctx->config->server = strdup(config->server);
    ctx->config->port = config->port;
    ctx->config->username = strdup(config->username);
    ctx->config->password = strdup(config->password);
    ctx->config->ca_cert = strdup(config->ca_cert);
    ctx->config->client_cert = strdup(config->client_cert);
    ctx->config->client_key = strdup(config->client_key);

    // Проверка обязательных параметров
    if (!ctx->config->server || !ctx->config->ca_cert || !ctx->config->client_cert) {
        log_error("Missing required OpenVPN parameters");
        pthread_mutex_unlock(&ctx->mutex);
        return false;
    }

    // Инициализация туннеля (пример)
    ctx->tunnel_handle = openvpn_create_tunnel(ctx->config);
    if (!ctx->tunnel_handle) {
        log_error("Failed to create OpenVPN tunnel");
        pthread_mutex_unlock(&ctx->mutex);
        return false;
    }

    ctx->is_connected = true;
    pthread_mutex_unlock(&ctx->mutex);
    log_info("OpenVPN initialized successfully");
    return true;
}

// Отключение от VPN
void openvpn_disconnect(void) {
    if (!is_connected) {
        printf("Нет активного подключения\n");
        return;
    }

    // Отключение (заглушка)
    printf("Отключение от VPN...\n");
    SLEEP(500); // Имитация задержки

    is_connected = false;
    printf("Отключение завершено\n");
}

// Очистка ресурсов
void openvpn_cleanup_library(void) {
    if (!is_initialized) {
        return;
    }

    if (is_connected) {
        openvpn_disconnect();
    }

    if (current_config) {
        safe_free(&current_config->server);
        safe_free(&current_config->username);
        safe_free(&current_config->password);
        free(current_config);
        current_config = NULL;
    }

    // Очистка (заглушка)
    printf("Очистка ресурсов библиотеки OpenVPN...\n");
    is_initialized = false;
}

// Проверка состояния подключения
bool openvpn_is_connected(void) {
    return is_connected;
}

// Получение информации о сервере
const char* openvpn_get_server(void) {
    return (current_config && current_config->server) ? current_config->server : NULL;
}

// Получение порта
int openvpn_get_port(void) {
    return (current_config) ? current_config->port : -1;
}

// Получение имени пользователя
const char* openvpn_get_username(void) {
    return (current_config && current_config->username) ? current_config->username : NULL;
}
