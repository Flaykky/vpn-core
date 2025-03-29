#ifndef NOISE_H
#define NOISE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/rand.h>

// Типы шума
typedef enum {
    NOISE_RANDOM_BYTES,       // Случайные байты
    NOISE_PSEUDO_PATTERN,     // Псевдослучайные паттерны
    NOISE_ENCRYPTED_DUMMY,    // Шифрованные фиктивные данные
    NOISE_HTTP_HEADERS        // Маскировка под HTTP-заголовки
} NoiseType;

// Параметры шума
typedef struct {
    NoiseType type;
    uint16_t noise_level;     // 0-100% шума
    size_t max_noise_size;    // Максимальный размер шума
    pthread_mutex_t mutex;    // Потокобезопасность
} NoiseConfig;

// Инициализация шума
bool noise_init(NoiseConfig *config, NoiseType type, uint16_t level, size_t max_size);

// Добавление шума в данные
ssize_t noise_apply(NoiseConfig *config, unsigned char *data, size_t *data_len, size_t max_buffer_size);

// Генерация фиктивного трафика
void noise_generate_dummy_traffic(int sock, size_t packet_size, uint32_t count);

#endif // NOISE_H