#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

// Глобальная структура для хранения конфигурации
static Config config = {0};

// Функция для инициализации конфигурации
bool initialize_config(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    // Установка значений по умолчанию
    config.server_ip = strdup("127.0.0.1");
    config.port = 8080;

    while ((opt = getopt_long(argc, argv, "s:p:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                free(config.server_ip);
                config.server_ip = strdup(optarg);
                if (!is_valid_ip(config.server_ip)) {
                    fprintf(stderr, "Invalid server IP address: %s\n", optarg);
                    return false;
                }
                break;
            case 'p':
                config.port = atoi(optarg);
                if (config.port <= 0 || config.port > 65535) {
                    fprintf(stderr, "Invalid port number: %d\n", config.port);
                    return false;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-s server_ip] [-p port]\n", argv[0]);
                return false;
        }
    }

    log_info("Configuration initialized successfully");
    return true;
}


bool read_config_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open config file: %s", filename);
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        if (key && value) {
            if (strcmp(key, "server_ip") == 0) {
                free(config.server_ip);
                config.server_ip = strdup(value);
            } else if (strcmp(key, "port") == 0) {
                config.port = atoi(value);
            }
        }
    }

    fclose(file);
    log_info("Configuration loaded from file: %s", filename);
    return true;
}

typedef struct {
    char *server_ip;
    int port;
    bool use_udp; // Флаг для использования UDP
    int mtu;      // Размер MTU
    char *cert_path; // Путь к сертификатам
} Config;


// Функция для получения серверного IP-адреса
const char* get_server_ip(void) {
    return config.server_ip;
}

// Функция для получения порта сервера
int get_port(void) {
    return config.port;
}

// Вспомогательная функция для проверки корректности IP-адреса
bool is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

// Функция для очистки конфигурации при завершении программы
void cleanup_config(void) {
    if (config.server_ip) {
        free(config.server_ip);
        config.server_ip = NULL;
    }
    log_info("Configuration cleaned up successfully");
}
