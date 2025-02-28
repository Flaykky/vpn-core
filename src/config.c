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

bool read_config_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open config file: %s", filename);
        return false;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *json_str = malloc(length + 1);
    if (!json_str) {
        log_error("Memory allocation failed");
        fclose(file);
        return false;
    }

    fread(json_str, 1, length, file);
    json_str[length] = '\0';
    fclose(file);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        log_error("Failed to parse JSON");
        return false;
    }

    cJSON *protocol = cJSON_GetObjectItemCaseSensitive(root, "protocol");
    cJSON *server_ip = cJSON_GetObjectItemCaseSensitive(root, "serverIp");
    cJSON *server_port = cJSON_GetObjectItemCaseSensitive(root, "serverPort");
    cJSON *login = cJSON_GetObjectItemCaseSensitive(root, "login");
    cJSON *password = cJSON_GetObjectItemCaseSensitive(root, "password");

    if (cJSON_IsString(protocol) && cJSON_IsString(server_ip) && cJSON_IsNumber(server_port)) {
        global_config.protocol = strdup(protocol->valuestring);
        global_config.server_ip = strdup(server_ip->valuestring);
        global_config.server_port = server_port->valueint;
        global_config.login = login ? strdup(login->valuestring) : NULL;
        global_config.password = password ? strdup(password->valuestring) : NULL;
    } else {
        log_error("Invalid config format");
        cJSON_Delete(root);
        return false;
    }

    cJSON_Delete(root);
    log_info("Configuration loaded from JSON file");
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
