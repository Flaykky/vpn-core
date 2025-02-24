#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

// Структура для хранения контекста шифрования
typedef struct {
    unsigned char key[32];
    unsigned char iv[16];
} EncryptionContext;

static EncryptionContext enc_ctx;

typedef struct {
    EC_KEY *ecdh_key; // Эфемерный ключ для ECDH
    unsigned char shared_secret[32]; // Общий секретный ключ
} PFSContext;

static PFSContext pfs_ctx;

static pthread_mutex_t encryption_mutex = PTHREAD_MUTEX_INITIALIZER;
static EVP_CIPHER_CTX *ctx = NULL;
static unsigned char key[32];
static unsigned char iv[16];

// ======== обьявление функций ======== 

bool initialize_encryption(void);

void cleanup_encryption(void);

bool encrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

bool decrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

bool get_encryption_key(uint8_t *key_out, size_t *key_len);

bool get_encryption_iv(uint8_t *iv_out, size_t *iv_len);

void secure_clear_memory(void *ptr, size_t size);

void cleanup_encryption_securely(void); // Полная очистка контекста шифрования и ключей с безопасным удалением данных

bool generate_unique_iv(unsigned char *iv_out, size_t iv_len); // Генерация уникального вектора инициализации (IV)

bool set_encryption_key(const uint8_t *new_key, size_t new_key_len); // Установка нового ключа шифрования

bool set_encryption_iv(const uint8_t *new_iv, size_t new_iv_len); // Установка нового вектора инициализации (IV)

bool rotate_encryption_keys(void); // Автоматическая ротация ключей шифрования

bool is_encryption_initialized(void); // Проверка состояния инициализации контекста шифрования

#endif // ENCRYPTION_H
