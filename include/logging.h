#ifndef _LOGGING_H_GUARD
#define _LOGGING_H_GUARD

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

// Замена для bool, если stdbool.h недоступен
#ifndef bool
#define bool char
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#include <pthread.h>

// Тип для уровней логирования
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

// Макрос для записи логов
#define log_message(level, format, ...) \
    log_message_internal(level, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

// Внутренняя функция логирования
void log_message_internal(LogLevel level, const char *file, const char *func, int line, const char *format, ...);

// Принудительная запись буфера логов на диск
void flush_logging();

// Завершение работы системы логирования
void close_logging();

#endif // _LOGGING_H_GUARD