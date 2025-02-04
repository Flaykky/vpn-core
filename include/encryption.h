#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Типы данных для контекста шифрования
typedef struct {
    uint8_t key[32]; // 256-bit key for AES-256
    uint8_t iv[16];  // 128-bit IV for AES
} EncryptionContext;

// Инициализация контекста шифрования
bool initialize_encryption(void);

// Очистка контекста шифрования
void cleanup_encryption(void);

// Шифрование данных
bool encrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

// Дешифрование данных
bool decrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

// Получение текущего ключа шифрования
bool get_encryption_key(uint8_t *key_out, size_t *key_len);

// Получение текущего IV
bool get_encryption_iv(uint8_t *iv_out, size_t *iv_len);

// Установка нового ключа шифрования
bool set_encryption_key(const uint8_t *new_key, size_t new_key_len);

// Установка нового IV
bool set_encryption_iv(const uint8_t *new_iv, size_t new_iv_len);

// Автоматическая ротация ключей
bool rotate_encryption_keys(void);

// Проверка состояния контекста шифрования
bool is_encryption_initialized(void);

#endif // ENCRYPTION_H
