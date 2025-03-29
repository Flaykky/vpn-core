#include "encryption.h"
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/ec.h>
#include <stdbool.h>

void secure_clear_memory(void *ptr, size_t size) {
    if (ptr) {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

void cleanup_encryption(void) {
    pthread_mutex_lock(&encryption_mutex);

    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    // Очистка эфемерных ключей
    if (pfs_ctx.ecdh_key) {
        EC_KEY_free(pfs_ctx.ecdh_key);
        pfs_ctx.ecdh_key = NULL;
    }
    memset(pfs_ctx.shared_secret, 0, sizeof(pfs_ctx.shared_secret));

    log_info("Encryption context and keys securely cleaned up");
    pthread_mutex_unlock(&encryption_mutex);
}

bool generate_unique_iv(unsigned char *iv_out, size_t iv_len) {
    if (!iv_out || iv_len != 16) {
        log_error("Invalid IV buffer or length");
        return false;
    }

    if (!RAND_bytes(iv_out, iv_len)) {
        log_error("Failed to generate unique IV");
        return false;
    }

    log_info("Unique IV generated successfully");
    return true;
}

bool initialize_pfs(void) {
    pthread_mutex_lock(&encryption_mutex);

    // Создаем ECDH-ключ на основе кривой prime256v1 (NIST P-256)
    pfs_ctx.ecdh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!pfs_ctx.ecdh_key) {
        log_error("Failed to create ECDH key");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Генерируем эфемерный ключ
    if (EC_KEY_generate_key(pfs_ctx.ecdh_key) != 1) {
        log_error("Failed to generate ECDH key");
        EC_KEY_free(pfs_ctx.ecdh_key);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("PFS context initialized successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

size_t get_public_key(unsigned char *public_key_out, size_t max_len) {
    pthread_mutex_lock(&encryption_mutex);

    const EC_POINT *pub_key = EC_KEY_get0_public_key(pfs_ctx.ecdh_key);
    const EC_GROUP *group = EC_KEY_get0_group(pfs_ctx.ecdh_key);

    size_t len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, public_key_out, max_len, NULL);
    if (len == 0) {
        log_error("Failed to export public key");
        pthread_mutex_unlock(&encryption_mutex);
        return 0;
    }

    pthread_mutex_unlock(&encryption_mutex);
    return len;
}

bool compute_shared_secret(const unsigned char *peer_public_key, size_t peer_public_key_len) {
    pthread_mutex_lock(&encryption_mutex);

    EC_POINT *peer_pub_key = EC_POINT_new(EC_KEY_get0_group(pfs_ctx.ecdh_key));
    if (!peer_pub_key) {
        log_error("Failed to allocate memory for peer's public key");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Преобразуем полученный открытый ключ в точку на кривой
    if (EC_POINT_oct2point(EC_KEY_get0_group(pfs_ctx.ecdh_key), peer_pub_key,
                           peer_public_key, peer_public_key_len, NULL) != 1) {
        log_error("Failed to convert peer's public key to EC point");
        EC_POINT_free(peer_pub_key);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Вычисляем общий секрет
    size_t secret_len = (size_t)ECDH_compute_key(pfs_ctx.shared_secret, sizeof(pfs_ctx.shared_secret),
                                                 peer_pub_key, pfs_ctx.ecdh_key, NULL);
    if (secret_len == 0) {
        log_error("Failed to compute shared secret");
        EC_POINT_free(peer_pub_key);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    EC_POINT_free(peer_pub_key);
    log_info("Shared secret computed successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

bool initialize_encryption(void) {
    pthread_mutex_lock(&encryption_mutex);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create cipher context");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Генерация эфемерного ECDH-ключа
    pfs_ctx.ecdh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!pfs_ctx.ecdh_key || EC_KEY_generate_key(pfs_ctx.ecdh_key) != 1) {
        log_error("Failed to generate ECDH key");
        EVP_CIPHER_CTX_free(ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("Encryption context initialized with PFS");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}


void cleanup_pfs(void) {
    pthread_mutex_lock(&encryption_mutex);

    if (pfs_ctx.ecdh_key) {
        EC_KEY_free(pfs_ctx.ecdh_key);
        pfs_ctx.ecdh_key = NULL;
    }

    memset(pfs_ctx.shared_secret, 0, sizeof(pfs_ctx.shared_secret)); // Очищаем общий секрет

    log_info("PFS context cleaned up successfully");
    pthread_mutex_unlock(&encryption_mutex);
}


bool generate_unique_iv(unsigned char *iv, size_t iv_len) {
    if (!RAND_bytes(iv, iv_len)) {
        log_error("Failed to generate unique IV");
        return false;
    }
    return true;
}

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
    memset(enc_ctx.key, 0, sizeof(enc_ctx.key)); // Очищаем ключ
    memset(enc_ctx.iv, 0, sizeof(enc_ctx.iv));   // Очищаем IV
    log_info("Encryption context cleaned up successfully");
    pthread_mutex_unlock(&encryption_mutex);
}


bool encrypt_data_with_gcm(const void *input, size_t input_len, void *output, size_t *output_len, unsigned char *tag) {
    pthread_mutex_lock(&encryption_mutex);

    if (!ctx) {
        log_error("Encryption context not initialized");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    unsigned char iv[16];
    if (!generate_unique_iv(iv, sizeof(iv))) {
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, pfs_ctx.shared_secret, iv) != 1) {
        log_error("Failed to initialize GCM encryption");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
        log_error("Encryption update failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len = len;

    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
        log_error("Encryption finalization failed");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        log_error("Failed to get GCM tag");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("Data encrypted with GCM and unique IV");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
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

// Вместо копирования ключей, используйте их только внутри
bool initialize_encryption_with_pfs(const unsigned char *peer_public_key, size_t peer_public_key_len) {
    pthread_mutex_lock(&encryption_mutex);

    // Вычисление общего секрета
    if (!compute_shared_secret(peer_public_key, peer_public_key_len)) {
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Инициализация контекста с общим секретом
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, pfs_ctx.shared_secret, NULL) != 1) {
        log_error("Failed to initialize encryption with PFS");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("Encryption initialized with PFS");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

bool verify_certificate(SSL *ssl, const char *hostname) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        log_error("No certificate presented");
        return false;
    }

    if (X509_check_host(cert, hostname, strlen(hostname), 0, NULL) != 1) {
        log_error("Certificate does not match hostname");
        X509_free(cert);
        return false;
    }

    X509_free(cert);
    return true;
}

bool encrypt_data_with_gcm(const void *input, size_t input_len, void *output, size_t *output_len, unsigned char *tag) {
    pthread_mutex_lock(&encryption_mutex);

    if (!ctx) {
        log_error("Encryption context not initialized");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    EVP_CIPHER_CTX *gcm_ctx = EVP_CIPHER_CTX_new();
    if (!gcm_ctx) {
        log_error("Failed to create GCM context");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    unsigned char iv[16];
    if (!generate_unique_iv(iv, sizeof(iv))) {
        EVP_CIPHER_CTX_free(gcm_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    if (EVP_EncryptInit_ex(gcm_ctx, EVP_aes_256_gcm(), NULL, pfs_ctx.shared_secret, iv) != 1) {
        log_error("Failed to initialize GCM encryption");
        EVP_CIPHER_CTX_free(gcm_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    int len;
    if (EVP_EncryptUpdate(gcm_ctx, output, &len, input, input_len) != 1) {
        log_error("Encryption update failed");
        EVP_CIPHER_CTX_free(gcm_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len = len;

    if (EVP_EncryptFinal_ex(gcm_ctx, output + len, &len) != 1) {
        log_error("Encryption finalization failed");
        EVP_CIPHER_CTX_free(gcm_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }
    *output_len += len;

    if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        log_error("Failed to get GCM tag");
        EVP_CIPHER_CTX_free(gcm_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    EVP_CIPHER_CTX_free(gcm_ctx);
    log_info("Data encrypted with GCM and ephemeral keys");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}


bool rotate_encryption_keys(void) {
    pthread_mutex_lock(&encryption_mutex);

    if (!RAND_bytes(pfs_ctx.shared_secret, sizeof(pfs_ctx.shared_secret))) {
        log_error("Failed to rotate keys");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, pfs_ctx.shared_secret, NULL) != 1) {
        log_error("Failed to reinitialize encryption context");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    log_info("Encryption keys rotated successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}