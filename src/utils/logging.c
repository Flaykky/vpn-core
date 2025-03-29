#include "include/utils/logging.h"
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include "pthread.h"
#include <stdbool.h>
#include <string.h>
#include <errno.h>

// Глобальные переменные
static FILE *log_file = NULL;
static LogLevel min_log_level = LOG_LEVEL_NONE;
static bool log_to_console = false;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Цвета для консольного вывода
#define COLOR_RED     "\x1B[31m"
#define COLOR_YELLOW  "\x1B[33m"
#define COLOR_GREEN   "\x1B[32m"
#define COLOR_RESET   "\x1B[0m"

// Функция для получения цвета по уровню логирования
static const char* get_color(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return COLOR_RED;
        case LOG_LEVEL_WARNING: return COLOR_YELLOW;
        case LOG_LEVEL_INFO: return COLOR_GREEN;
        default: return "";
    }
}

// Внутренняя функция логирования
void log_message_internal(LogLevel level, const char *file, const char *func, int line, const char *format, ...) {
    if (level > min_log_level) return; // Фильтрация логов по уровню

    pthread_mutex_lock(&log_mutex);

    if (log_file == NULL && !log_to_console) {
        fprintf(stderr, "Logging not initialized\n");
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    // Получаем текущее время
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Формируем сообщение
    va_list args;
    va_start(args, format);

    // Логируем в файл
    if (log_file) {
        fprintf(log_file, "[%s] [%s:%d] [%s] ", timestamp, file, line, func);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file); // Принудительная запись на диск
    }

    // Логируем в консоль
    if (log_to_console) {
        const char *color = get_color(level);
        fprintf(stderr, "%s[%s] [%s:%d] [%s] ", color, timestamp, file, line, func);
        vfprintf(stderr, format, args);
        fprintf(stderr, "%s\n", COLOR_RESET);
    }

    va_end(args);

    pthread_mutex_unlock(&log_mutex);
}

// Инициализация системы логирования
void init_logging(const char *filename, LogLevel level, bool to_console) {
    if (filename != NULL) {
        log_file = fopen(filename, "a");
        if (log_file == NULL) {
            perror("Failed to open log file");
            return;
        }
    }
    min_log_level = level;
    log_to_console = to_console;
}

// Принудительная запись буфера логов на диск
void flush_logging() {
    if (log_file != NULL) {
        fflush(log_file);
    }
}

// Завершение работы системы логирования
void close_logging() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

// Ротация логов
bool rotate_logs(const char *filename, size_t max_size) {
    if (!filename || max_size == 0) {
        log_error("Invalid arguments for log rotation");
        return false;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open log file for rotation");
        return false;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fclose(file);

    if (file_size >= (long)max_size) {
        char new_filename[256];
        snprintf(new_filename, sizeof(new_filename), "%s.%ld", filename, time(NULL));

        if (rename(filename, new_filename) != 0) {
            log_error("Failed to rotate log file: %s", strerror(errno));
            return false;
        }

        log_info("Log file rotated successfully: %s -> %s", filename, new_filename);
    }

    return true;
}