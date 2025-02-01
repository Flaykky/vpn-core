#include "logging.h"
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

static FILE *log_file = NULL;
static LogLevel min_log_level = LOG_LEVEL_NONE;
static bool log_to_console = false;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Внутренняя функция логирования
void log_message_internal(LogLevel level, const char *file, const char *func, int line, const char *format, ...) {
    if (level > min_log_level) return; // Фильтрация логов по уровню

    pthread_mutex_lock(&log_mutex);

    if (log_file == NULL) {
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

    // Записываем в файл
    fprintf(log_file, "[%s] [%s:%d] [%s] ", timestamp, file, line, func);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");

    // Если включено логирование в консоль, выводим туда же
    if (log_to_console) {
        fprintf(stderr, "[%s] [%s:%d] [%s] ", timestamp, file, line, func);
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    }

    va_end(args);

    // Освобождаем мьютекс
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