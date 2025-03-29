#ifndef OPENVPN_H
#define OPENVPN_H

#include <stdbool.h>
#include "logging.h"
#include <pthread.h> 

typedef struct {
    char *server;
    int port;
    char *username;
    char *password;
    char *ca_cert;      // Сертификат CA
    char *client_cert;  // Клиентский сертификат
    char *client_key;   // Приватный ключ клиента
} OpenVPNConfig;

typedef struct {
    bool is_connected;
    pthread_mutex_t mutex;
    OpenVPNConfig *config;
    // Дескриптор туннеля (зависит от библиотеки OpenVPN)
    void *tunnel_handle;
} OpenVPNContext;

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

bool openvpn_initialize(OpenVPNContext *ctx, const OpenVPNConfig *config);
void openvpn_cleanup(OpenVPNContext *ctx);
bool openvpn_reconnect(OpenVPNContext *ctx);

#endif  