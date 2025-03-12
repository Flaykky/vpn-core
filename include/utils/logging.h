#ifndef LOGGING_H_GUARD
#define LOGGING_H_GUARD

#include <stdbool.h>
#include <stdarg.h>

// Уровни логирования
typedef enum {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE
} LogLevel;

// Инициализация системы логирования
void init_logging(const char *filename, LogLevel level, bool log_to_console);

// Запись логов
void log_message_internal(LogLevel level, const char *file, const char *func, int line, const char *format, ...);

// Принудительная запись буфера логов на диск
void flush_logging(void);

// Завершение работы системы логирования
void close_logging(void);

// Макрос для записи логов
#define log_message(level, format, ...) \
    log_message_internal(level, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

#endif // LOGGING_H_GUARD 
