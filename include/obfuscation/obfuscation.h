#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdbool.h>
#include <stdint.h>
#include "pthread.h"

// Методы обфускации
typedef enum {
    DAI_NOISE       = 1 << 0, // Сетевой шум
    DAI_PADDING     = 1 << 1, // Выравнивание пакетов
    DAI_MULTI_HOP   = 1 << 2, // Многократный переход
    DAI_TRAFFIC     = 1 << 3  // Повышенное потребление трафика
} DAITAMethod;

// Структура состояния
typedef struct {
    DAITAMethod methods;      // Битовая маска методов
    uint16_t noise_level;     // Уровень шума (0-100%)
    uint16_t padding_size;    // Размер выравнивания (например, 1500 байт)
    pthread_mutex_t mutex;    // Для потокобезопасности
} DpiBypassState;

// Инициализация
bool dpi_bypass_init(DpiBypassState *state, DAITAMethod methods, uint16_t noise_level, uint16_t padding_size);

// Применение обфускации
ssize_t dpi_bypass_apply(DpiBypassState *state, const unsigned char *input, size_t input_len, 
                        unsigned char *output, size_t output_size);

// Очистка
void dpi_bypass_cleanup(DpiBypassState *state);

#endif // OBFUSCATION_H