#include "dpiBypass.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// Инициализация DPI Bypass
bool dpi_bypass_init(DpiBypassConfig *config, uint32_t methods, const char *fronting_domain) {
    pthread_mutex_lock(&config->mutex);

    if (!config) {
        log_error("Invalid DPI config");
        pthread_mutex_unlock(&config->mutex);
        return false;
    }

    config->methods = methods;
    config->fronting_domain = strdup(fronting_domain);
    config->ctx = EVP_CIPHER_CTX_new();
    if (!config->ctx) {
        log_error("Failed to create encryption context");
        pthread_mutex_unlock(&config->mutex);
        return false;
    }

    // Генерация ключа для шифрования шума
    unsigned char key[32];
    if (!RAND_bytes(key, sizeof(key))) {
        log_error("Failed to generate noise key");
        EVP_CIPHER_CTX_free(config->ctx);
        pthread_mutex_unlock(&config->mutex);
        return false;
    }

    // Инициализация AES-256-GCM
    if (EVP_EncryptInit_ex(config->ctx, EVP_aes_256_gcm(), NULL, key, NULL) != 1) {
        log_error("Failed to initialize AES-GCM");
        secure_clear_memory(key, sizeof(key));
        EVP_CIPHER_CTX_free(config->ctx);
        pthread_mutex_unlock(&config->mutex);
        return false;
    }

    secure_clear_memory(key, sizeof(key));
    pthread_mutex_unlock(&config->mutex);
    log_info("DPI Bypass initialized with methods: 0x%x", methods);
    return true;
}

// Применение обфускации
ssize_t dpi_bypass_apply(DpiBypassConfig *config, const unsigned char *input, size_t input_len, 
                        unsigned char *output, size_t output_size) {
    pthread_mutex_lock(&config->mutex);

    if (!config->ctx || input_len == 0 || output_size < input_len * 2) {
        log_error("Invalid parameters for DPI Bypass");
        pthread_mutex_unlock(&config->mutex);
        return -1;
    }

    size_t total_len = input_len;
    unsigned char *buffer = malloc(total_len * 2);
    memcpy(buffer, input, input_len);

    // 1. Добавление шума
    if (config->methods & DPI_ADD_NOISE) {
        add_noise(buffer, &total_len, config->noise_level);
    }

    // 2. Фрагментация пакетов
    if (config->methods & DPI_FRAGMENT_PACKETS) {
        unsigned char *fragments[4];
        size_t fragment_sizes[4];
        ssize_t fragmented_len = fragment_packet(buffer, total_len, fragments, fragment_sizes);
        if (fragmented_len > 0) {
            memcpy(output, fragments[0], fragment_sizes[0]);
            total_len = fragment_sizes[0];
        }
        free(fragments);
    }

    // 3. Имитация TLS
    if (config->methods & DPI_MIMIC_TLS) {
        unsigned char tls_header[128];
        size_t header_len = 0;
        if (generate_tls_header(tls_header, &header_len)) {
            memcpy(output, tls_header, header_len);
            memcpy(output + header_len, buffer, total_len);
            total_len += header_len;
        }
    }

    // 4. Domain Fronting
    if (config->methods & DPI_DOMAIN_FRONTING) {
        // Реализация через SNI-маскировку (например, Cloudflare)
        // Здесь может быть интеграция с SSL_CTX для подмены SNI
    }

    // 5. Случайные задержки
    if (config->methods & DPI_RANDOM_DELAYS) {
        apply_random_delay(config->min_delay, config->max_delay);
    }

    pthread_mutex_unlock(&config->mutex);
    return total_len;
}

// Генерация TLS-заголовка для маскировки
static bool generate_tls_header(unsigned char *buffer, size_t *len) {
    // Пример TLS Client Hello
    const unsigned char tls_hello[] = {
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
        // ... [полный заголовок TLS]
    };

    size_t header_size = sizeof(tls_hello);
    if (*len < header_size) {
        log_error("Buffer too small for TLS header");
        return false;
    }

    memcpy(buffer, tls_hello, header_size);
    *len = header_size;
    return true;
}

// Фрагментация пакетов
static ssize_t fragment_packet(const unsigned char *data, size_t data_len, 
                             unsigned char *fragments[], size_t fragment_sizes[]) {
    // Разбиваем пакет на 2-4 фрагмента случайного размера
    size_t num_fragments = 2 + (rand() % 3);
    size_t chunk_size = data_len / num_fragments;

    for (size_t i = 0; i < num_fragments; i++) {
        fragments[i] = malloc(chunk_size + 16);
        if (!fragments[i]) return -1;

        size_t offset = i * chunk_size;
        size_t size = (i == num_fragments - 1) ? data_len - offset : chunk_size;
        memcpy(fragments[i], data + offset, size);
        fragment_sizes[i] = size;

        // Добавляем случайные "хвосты"
        if (i % 2 == 0) {
            RAND_bytes(fragments[i] + size, 8);
            fragment_sizes[i] += 8;
        }
    }

    return num_fragments;
}

// Добавление шума
static void add_noise(unsigned char *data, size_t *len, uint16_t noise_level) {
    size_t noise_bytes = (*len * noise_level) / 100;
    if (noise_bytes == 0) return;

    unsigned char *noise = malloc(noise_bytes);
    RAND_bytes(noise, noise_bytes);

    // Вставляем шум в случайные позиции
    for (size_t i = 0; i < noise_bytes; i++) {
        size_t pos = rand() % (*len + i);
        memmove(data + pos + 1, data + pos, *len - pos);
        data[pos] = noise[i];
        (*len)++;
    }

    free(noise);
}

// Случайные задержки
static void apply_random_delay(uint16_t min_delay, uint16_t max_delay) {
    if (max_delay == 0) return;
    uint16_t delay = min_delay + (rand() % (max_delay - min_delay + 1));
    usleep(delay * 1000);
}

// Очистка ресурсов
void dpi_bypass_cleanup(DpiBypassConfig *config) {
    pthread_mutex_lock(&config->mutex);
    secure_clear_memory(config->fronting_domain, strlen(config->fronting_domain));
    free(config->fronting_domain);
    EVP_CIPHER_CTX_free(config->ctx);
    pthread_mutex_unlock(&config->mutex);
    log_info("DPI Bypass cleaned up");
}