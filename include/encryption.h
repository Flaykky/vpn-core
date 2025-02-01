#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "common.h"

// Функция для инициализации контекста шифрования
bool initialize_encryption(void);

// Функция для очистки контекста шифрования
void cleanup_encryption(void);

// Функция для шифрования данных
void encrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

// Функция для дешифрования данных
void decrypt_data(const void *input, size_t input_len, void *output, size_t *output_len);

#endif // ENCRYPTION_H