#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <pthread.h>
#include <connection.h>


// Глобальная структура для хранения конфигурации
static Config config = {0};
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

// Функция для инициализации конфигурации
bool initialize_config(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"udp", no_argument, 0, 'u'}, // Новый флаг для UDP
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    // Установка значений по умолчанию
    pthread_mutex_lock(&config_mutex);
    config.server_ip = strdup("127.0.0.1");
    config.port = 8080;
    config.use_udp = false; // По умолчанию TCP
    pthread_mutex_unlock(&config_mutex);

    while ((opt = getopt_long(argc, argv, "s:p:u", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                pthread_mutex_lock(&config_mutex);
                free(config.server_ip);
                config.server_ip = strdup(optarg);
                if (!is_valid_ip(config.server_ip)) {
                    fprintf(stderr, "Invalid server IP address: %s\n", optarg);
                    pthread_mutex_unlock(&config_mutex);
                    return false;
                }
                pthread_mutex_unlock(&config_mutex);
                break;
            case 'p':
                pthread_mutex_lock(&config_mutex);
                config.port = atoi(optarg);
                if (config.port <= 0 || config.port > 65535) {
                    fprintf(stderr, "Invalid port number: %d\n", config.port);
                    pthread_mutex_unlock(&config_mutex);
                    return false;
                }
                pthread_mutex_unlock(&config_mutex);
                break;
            case 'u':
                pthread_mutex_lock(&config_mutex);
                config.use_udp = true;
                pthread_mutex_unlock(&config_mutex);
                break;
            default:
                fprintf(stderr, "Usage: %s [-s server_ip] [-p port] [--udp]\n", argv[0]);
                return false;
        }
    }

    log_info("Configuration initialized successfully");
    return true;
}

// Функция для получения серверного IP-адреса
const char* get_server_ip(void) {
    pthread_mutex_lock(&config_mutex);
    const char *ip = config.server_ip;
    pthread_mutex_unlock(&config_mutex);
    return ip;
}

// Функция для получения порта сервера
int get_port(void) {
    pthread_mutex_lock(&config_mutex);
    int port = config.port;
    pthread_mutex_unlock(&config_mutex);
    return port;
}

// Функция для проверки использования UDP
bool get_use_udp(void) {
    pthread_mutex_lock(&config_mutex);
    bool use_udp = config.use_udp;
    pthread_mutex_unlock(&config_mutex);
    return use_udp;
}

// Вспомогательная функция для проверки корректности IP-адреса
bool is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) {
        return true; // IPv4
    } else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1) {
        return true; // IPv6
    }
    return false;
}

// Функция для очистки конфигурации при завершении программы
void cleanup_config(void) {
    pthread_mutex_lock(&config_mutex);
    if (config.server_ip) {
        free(config.server_ip);
        config.server_ip = NULL;
    }
    pthread_mutex_unlock(&config_mutex);
    log_info("Configuration cleaned up successfully");
}
