#include "encryption.h"
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


// Статические переменные для контекста шифрования
static EVP_CIPHER_CTX *ctx = NULL;
static unsigned char key[32]; // 256-bit key for AES-256
static unsigned char iv[16];  // 128-bit IV for AES
static pthread_mutex_t encryption_mutex = PTHREAD_MUTEX_INITIALIZER;

// Инициализация контекста шифрования
bool initialize_encryption(void) {
    pthread_mutex_lock(&encryption_mutex);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create cipher context");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Генерация случайного ключа и IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        log_error("Failed to generate random bytes for encryption");
        EVP_CIPHER_CTX_free(ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Инициализация контекста шифрования с алгоритмом AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        log_error("Failed to initialize encryption context");
        EVP_CIPHER_CTX_free(ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("Encryption context initialized successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

// Очистка контекста шифрования
void cleanup_encryption(void) {
    pthread_mutex_lock(&encryption_mutex);
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    log_info("Encryption context cleaned up successfully");
    pthread_mutex_unlock(&encryption_mutex);
}


void encrypt_data_with_gcm(const void *input, size_t input_len, void *output, size_t *output_len, unsigned char *tag) {
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    // Инициализация контекста
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        log_error("Failed to initialize encryption context");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Шифрование данных
    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Encryption update failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len = len;

    // Завершение шифрования
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        log_error("Encryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len += len;

    // Получение тега аутентификации
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        log_error("Failed to get GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
    log_info("Data encrypted successfully with GCM");
}



// Шифрование данных
bool encrypt_data(const void *input, size_t input_len, void *output, size_t *output_len) {
    pthread_mutex_lock(&encryption_mutex);

    if (!ctx) {
        log_error("Encryption context not initialized");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    int len;
    *output_len = 0;

    // Выполняем шифрование данных
    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Encryption update failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len = len;

    // Завершаем шифрование
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        log_error("Encryption finalization failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len += len;

    log_info("Data encrypted successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

// Дешифрование данных
bool decrypt_data(const void *input, size_t input_len, void *output, size_t *output_len) {
    pthread_mutex_lock(&encryption_mutex);

    if (!ctx) {
        log_error("Decryption context not initialized");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    int len;
    *output_len = 0;

    // Выполняем дешифрование данных
    if (EVP_DecryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Decryption update failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len = len;

    // Завершаем дешифрование
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        log_error("Decryption finalization failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len += len;

    log_info("Data decrypted successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

// Получение текущего ключа шифрования
bool get_encryption_key(unsigned char *key_out, size_t *key_len) {
    pthread_mutex_lock(&encryption_mutex);
    if (key_out && key_len) {
        memcpy(key_out, key, sizeof(key));
        *key_len = sizeof(key);
        pthread_mutex_unlock(&encryption_mutex);
        return true;
    }
    log_error("Invalid arguments for get_encryption_key");
    pthread_mutex_unlock(&encryption_mutex);
    return false;
}

// Получение текущего IV
bool get_encryption_iv(unsigned char *iv_out, size_t *iv_len) {
    pthread_mutex_lock(&encryption_mutex);
    if (iv_out && iv_len) {
        memcpy(iv_out, iv, sizeof(iv));
        *iv_len = sizeof(iv);
        pthread_mutex_unlock(&encryption_mutex);
        return true;
    }
    log_error("Invalid arguments for get_encryption_iv"); 
    pthread_mutex_unlock(&encryption_mutex);
    return false;
}
