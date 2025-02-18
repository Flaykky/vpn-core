#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Структура для хранения контекста шифрования
typedef struct {
    uint8_t key[32]; // 256-битный ключ для AES-256
    uint8_t iv[16];  // 128-битный вектор инициализации (IV) для AES
} EncryptionContext;


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
