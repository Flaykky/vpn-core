#include "config.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <pthread.h>
#include "cJSON.h"

#ifdef _WIN32
#include <winsock.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif


Config global_config = {0};
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

bool initialize_config(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"dpi", no_argument, 0, 'd'}, // Флаг -d для защиты DPI
        {"uot", no_argument, 0, 'u'}, // Флаг --uot для UDP-over-TCP
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "du", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                global_config.enable_dpi = true;
                break;
            case 'u':
                global_config.enable_udp_over_tcp = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [protocol] [server:port] [login:pass] [-d] [--uot]\n", argv[0]);
                return false;
        }
    }

    // Позиционные аргументы
    if (optind + 3 > argc) {
        fprintf(stderr, "Too few arguments. Usage: %s [protocol] [server:port] [login:pass] [-d] [--uot]\n", argv[0]);
        return false;
    }

    // Парсинг протокола
    global_config.protocol = strdup(argv[optind++]);
    if (!global_config.protocol) {
        log_error("Memory allocation failed");
        return false;
    }

    // Парсинг server:port
    char *server_port_str = argv[optind++];
    char *colon_pos = strchr(server_port_str, ':');
    if (!colon_pos) {
        log_error("Invalid server:port format");
        return false;
    }
    *colon_pos = '\0';
    global_config.server_ip = strdup(server_port_str);
    global_config.server_port = atoi(colon_pos + 1);
    *colon_pos = ':'; // Восстанавливаем строку

    // Парсинг login:pass
    char *auth_str = argv[optind++];
    char *auth_colon = strchr(auth_str, ':');
    if (!auth_colon) {
        log_error("Invalid login:pass format");
        return false;
    }
    *auth_colon = '\0';
    global_config.login = strdup(auth_str);
    global_config.password = strdup(auth_colon + 1);
    *auth_colon = ':'; // Восстанавливаем строку

    log_info("Config parsed: protocol=%s, server=%s:%d, login=%s, dpi=%d, uot=%d",
             global_config.protocol, global_config.server_ip, global_config.server_port,
             global_config.login, global_config.enable_dpi, global_config.enable_udp_over_tcp);
    return true;
}

bool initialize_config(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"udp", no_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    pthread_mutex_lock(&config_mutex);
    global_config.server_ip = strdup("127.0.0.1");
    global_config.server_port = 8080;
    global_config.use_udp = false;
    pthread_mutex_unlock(&config_mutex);

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "s:p:u", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                pthread_mutex_lock(&config_mutex);
                free(global_config.server_ip);
                global_config.server_ip = strdup(optarg);
                pthread_mutex_unlock(&config_mutex);
                break;
            case 'p':
                pthread_mutex_lock(&config_mutex);
                global_config.server_port = atoi(optarg);
                pthread_mutex_unlock(&config_mutex);
                break;
            case 'u':
                pthread_mutex_lock(&config_mutex);
                global_config.use_udp = true;
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

const char* get_server_ip(void) {
    pthread_mutex_lock(&config_mutex);
    const char *ip = global_config.server_ip;
    pthread_mutex_unlock(&config_mutex);
    return ip;
}

int get_port(void) {
    pthread_mutex_lock(&config_mutex);
    int port = global_config.server_port;
    pthread_mutex_unlock(&config_mutex);
    return port;
}

bool get_use_udp(void) {
    pthread_mutex_lock(&config_mutex);
    bool use_udp = global_config.use_udp;
    pthread_mutex_unlock(&config_mutex);
    return use_udp;
}

bool is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
#ifdef _WIN32
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
#else
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) {
        return true;
    } else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1) {
        return true;
    }
    return false;
#endif
}

void cleanup_config(void) {
    pthread_mutex_lock(&config_mutex);
    free(global_config.protocol);
    free(global_config.server_ip);
    free(global_config.login);
    free(global_config.password);
    free(global_config.country);
    free(global_config.city);
    memset(&global_config, 0, sizeof(Config));
    pthread_mutex_unlock(&config_mutex);
    log_info("Configuration cleaned up successfully");
}

