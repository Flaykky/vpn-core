#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

// Структура для хранения конфигурации
typedef struct {
    char *server_ip;
    int port;
    // Добавьте другие необходимые параметры конфигурации здесь
} Config;

// Функция для инициализации конфигурации
bool initialize_config(int argc, char *argv[]);

// Функция для получения серверного IP-адреса
const char* get_server_ip(void);

// Функция для получения порта сервера
int get_port(void);

#endif // CONFIG_H