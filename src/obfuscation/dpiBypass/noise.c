#include "noise.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

// Глобальная конфигурация шума
static NoiseConfig global_noise_config = {0};

// Инициализация шума
bool noise_init(NoiseConfig *config, NoiseType type, uint16_t level, size_t max_size) {
    if (!config || level > 100 || max_size == 0) {
        log_error("Invalid noise parameters");
        return false;
    }

    pthread_mutex_lock(&config->mutex);
    config->type = type;
    config->noise_level = level;
    config->max_noise_size = max_size;
    pthread_mutex_unlock(&config->mutex);

    log_info("Noise initialized: type=%d, level=%d%%, max_size=%zu", type, level, max_size);
    return true;
}

// Добавление шума в данные
ssize_t noise_apply(NoiseConfig *config, unsigned char *data, size_t *data_len, size_t max_buffer_size) {
    pthread_mutex_lock(&config->mutex);

    if (!config || !data || !data_len || *data_len >= max_buffer_size) {
        pthread_mutex_unlock(&config->mutex);
        return -1;
    }

    size_t noise_size = (config->noise_level * (*data_len)) / 100;
    if (noise_size == 0) {
        pthread_mutex_unlock(&config->mutex);
        return *data_len;
    }

    // Проверка размера буфера
    if (*data_len + noise_size > max_buffer_size) {
        log_warning("Truncating noise to fit buffer");
        noise_size = max_buffer_size - *data_len;
    }

    switch (config->type) {
        case NOISE_RANDOM_BYTES:
            if (!RAND_bytes(data + *data_len, noise_size)) {
                log_error("Failed to generate random noise");
                pthread_mutex_unlock(&config->mutex);
                return -1;
            }
            break;

        case NOISE_PSEUDO_PATTERN: {
            // Генерация псевдослучайного паттерна (например, повторяющиеся байты)
            unsigned char pattern = (unsigned char)(rand() % 256);
            memset(data + *data_len, pattern, noise_size);
            break;
        }

        case NOISE_ENCRYPTED_DUMMY: {
            // Шифрование фиктивных данных
            unsigned char dummy[noise_size];
            RAND_bytes(dummy, noise_size);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            unsigned char key[32], iv[16];

            if (!RAND_bytes(key, 32) || !RAND_bytes(iv, 16)) {
                log_error("Failed to generate encryption keys for noise");
                EVP_CIPHER_CTX_free(ctx);
                pthread_mutex_unlock(&config->mutex);
                return -1;
            }

            int len;
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
                EVP_EncryptUpdate(ctx, data + *data_len, &len, dummy, noise_size) != 1) {
                log_error("Noise encryption failed");
                EVP_CIPHER_CTX_free(ctx);
                pthread_mutex_unlock(&config->mutex);
                return -1;
            }

            // Очистка ключей
            secure_clear_memory(key, 32);
            secure_clear_memory(iv, 16);
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        case NOISE_HTTP_HEADERS: {
            // Добавление HTTP-заголовков
            const char *headers = "GET / HTTP/1.1\r\n"
                                 "Host: cdn.example.com\r\n"
                                 "User-Agent: Mozilla/5.0\r\n";
            size_t headers_len = strlen(headers);
            if (*data_len + headers_len > max_buffer_size) {
                log_error("HTTP headers too large for buffer");
                pthread_mutex_unlock(&config->mutex);
                return -1;
            }

            memmove(data + headers_len, data, *data_len);
            memcpy(data, headers, headers_len);
            *data_len += headers_len;
            break;
        }

        default:
            log_error("Unknown noise type: %d", config->type);
            pthread_mutex_unlock(&config->mutex);
            return -1;
    }

    *data_len += noise_size;
    pthread_mutex_unlock(&config->mutex);
    return *data_len;
}

// Генерация фиктивного трафика
void noise_generate_dummy_traffic(int sock, size_t packet_size, uint32_t count) {
    pthread_mutex_lock(&global_noise_config.mutex);

    if (sock < 0 || packet_size == 0 || count == 0) {
        pthread_mutex_unlock(&global_noise_config.mutex);
        return;
    }

    unsigned char *dummy = malloc(packet_size);
    if (!dummy) {
        log_error("Memory allocation failed for dummy traffic");
        pthread_mutex_unlock(&global_noise_config.mutex);
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        RAND_bytes(dummy, packet_size);
        send(sock, dummy, packet_size, 0);
        usleep(rand() % 50000); // Случайные задержки между пакетами
    }

    free(dummy);
    pthread_mutex_unlock(&global_noise_config.mutex);
    log_info("Generated %u dummy packets of size %zu", count, packet_size);
}