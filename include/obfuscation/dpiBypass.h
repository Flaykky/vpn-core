#ifndef D_PIBYPASS_H
#define D_PIBYPASS_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <pthread.h>
// Список активных методов обхода DPI
typedef enum {
    // Существующие методы
    DPI_MIMIC_TLS         = 1 << 0,
    DPI_FRAGMENT_PACKETS  = 1 << 1,
    DPI_ADD_NOISE         = 1 << 2,
    DPI_RANDOM_DELAYS     = 1 << 3,
    DPI_DOMAIN_FRONTING   = 1 << 4,
    
    // Новые методы
    DPI_HTTP_MASQUERADE   = 1 << 5, // Маскировка под HTTP-трафик
    DPI_XOR_OBFUSCATION   = 1 << 6, // XOR-обфускация
    DPI_MTU_SPOOFING      = 1 << 7  // Изменение MTU
} DpiBypassMethod;

// Конфигурация обхода DPI
typedef struct {
    uint32_t methods;       // Битовая маска методов (DpiBypassMethod)
    uint16_t noise_level;   // Уровень шума (0-100%)
    uint16_t min_delay;     // Минимальная задержка (мс)
    uint16_t max_delay;     // Максимальная задержка (мс)
    char *fronting_domain;  // Домен для Domain Fronting
    EVP_CIPHER_CTX *ctx;    // Контекст шифрования
    pthread_mutex_t mutex;  // Мьютекс для потокобезопасности
} DpiBypassConfig;

// Инициализация DPI Bypass
bool dpi_bypass_init(DpiBypassConfig *config, uint32_t methods, const char *fronting_domain);

// Применение обфускации к данным
ssize_t dpi_bypass_apply(DpiBypassConfig *config, const unsigned char *input, size_t input_len, 
                        unsigned char *output, size_t output_size);

// Очистка ресурсов
void dpi_bypass_cleanup(DpiBypassConfig *config);

// Генерация TLS-заголовка для маскировки
static bool generate_tls_header(unsigned char *buffer, size_t *len);

// Фрагментация пакетов
static ssize_t fragment_packet(const unsigned char *data, size_t data_len, 
                             unsigned char *fragments[], size_t fragment_sizes[]);

// Добавление шума в данные
static void add_noise(unsigned char *data, size_t *len, uint16_t noise_level);

// Случайные задержки
static void apply_random_delay(uint16_t min_delay, uint16_t max_delay);

#endif // D_PIBYPASS_H
