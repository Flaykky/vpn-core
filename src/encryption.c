#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

static EVP_CIPHER_CTX *ctx = NULL;
static unsigned char key[32]; // 256-bit key for AES-256
static unsigned char iv[16];  // 128-bit IV for AES

// Инициализация контекста шифрования
bool initialize_encryption(void) {
    // Создание нового контекста шифрования
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create cipher context");
        return false;
    }

    // Генерация случайного ключа и IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        log_error("Failed to generate random bytes for encryption");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Инициализация контекста шифрования с алгоритмом AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        log_error("Failed to initialize encryption context");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    log_info("Encryption context initialized successfully");
    return true;
}

// Очистка контекста шифрования
void cleanup_encryption(void) {
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    log_info("Encryption context cleaned up successfully");
}

// Шифрование данных
void encrypt_data(const void *input, size_t input_len, void *output, size_t *output_len) {
    int len;
    *output_len = 0;

    if (!ctx) {
        log_error("Encryption context not initialized");
        return;
    }

    // Выполняем шифрование данных
    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Encryption update failed");
        return;
    }
    *output_len = len;

    // Завершаем шифрование
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        log_error("Encryption finalization failed");
        return;
    }
    *output_len += len;

    log_info("Data encrypted successfully");
}

// Дешифрование данных
void decrypt_data(const void *input, size_t input_len, void *output, size_t *output_len) {
    int len;
    *output_len = 0;

    if (!ctx) {
        log_error("Decryption context not initialized");
        return;
    }

    // Выполняем дешифрование данных
    if (EVP_DecryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Decryption update failed");
        return;
    }
    *output_len = len;

    // Завершаем дешифрование
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        log_error("Decryption finalization failed");
        return;
    }
    *output_len += len;

    log_info("Data decrypted successfully");
}

// Функция для получения текущего ключа шифрования
void get_encryption_key(unsigned char *key_out, size_t *key_len) {
    if (key_out && key_len) {
        memcpy(key_out, key, sizeof(key));
        *key_len = sizeof(key);
    }
}

// Функция для получения текущего IV
void get_encryption_iv(unsigned char *iv_out, size_t *iv_len) {
    if (iv_out && iv_len) {
        memcpy(iv_out, iv, sizeof(iv));
        *iv_len = sizeof(iv);
    }
}

// Функция для установки нового ключа шифрования
bool set_encryption_key(const unsigned char *new_key, size_t new_key_len) {
    if (new_key_len != sizeof(key)) {
        log_error("Invalid key length");
        return false;
    }

    memcpy(key, new_key, sizeof(key));

    // Перенастройка контекста шифрования с новым ключом
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        log_error("Failed to reinitialize encryption context with new key");
        return false;
    }

    log_info("Encryption key updated successfully");
    return true;
}

// Функция для установки нового IV
bool set_encryption_iv(const unsigned char *new_iv, size_t new_iv_len) {
    if (new_iv_len != sizeof(iv)) {
        log_error("Invalid IV length");
        return false;
    }

    memcpy(iv, new_iv, sizeof(iv));

    // Перенастройка контекста шифрования с новым IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        log_error("Failed to reinitialize encryption context with new IV");
        return false;
    }

    log_info("Encryption IV updated successfully");
    return true;
}