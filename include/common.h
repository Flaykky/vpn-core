#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Макросы для логирования
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3

#ifdef DEBUG
    #define LOG_LEVEL LOG_LEVEL_INFO
#else
    #define LOG_LEVEL LOG_LEVEL_ERROR
#endif

#define log_message(level, fmt, ...) do { \
    if (level <= LOG_LEVEL) { \
        fprintf(stderr, "%s: " fmt "\n", get_current_time_str(), ##__VA_ARGS__); \
    } \
} while(0)

#define log_error(fmt, ...) log_message(LOG_LEVEL_ERROR, "ERROR: " fmt , ##__VA_ARGS__)
#define log_warning(fmt, ...) log_message(LOG_LEVEL_WARNING, "WARNING: " fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_message(LOG_LEVEL_INFO, "INFO: " fmt, ##__VA_ARGS__)

// Общие константы
#define BUFFER_SIZE 1024
#define MAX_IP_LENGTH 16

// Прототипы общих функций
char* get_current_time_str(void);

// Типы данных
typedef struct {
    char ip[MAX_IP_LENGTH];
    int port;
} ServerConfig;

#endif // COMMON_H
