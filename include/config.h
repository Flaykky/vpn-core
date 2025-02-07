#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include <stdbool.h>

typedef struct {
    char *server_ip;
    int port;
    bool use_udp; // Флаг для использования UDP
    int mtu;      // Размер MTU
    char *cert_path; // Путь к сертификатам
} Config;

// Функция для инициализации конфигурации
bool initialize_config(int argc, char *argv[]);

// Функция для получения серверного IP-адреса
const char* get_server_ip(void);

// Функция для получения порта сервера
int get_port(void);

#endif // CONFIG_H
