#include "uot.h"
#include "logging.h"
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <openssl/rand.h>
#include <pthread.h>

static pthread_mutex_t uot_mutex = PTHREAD_MUTEX_INITIALIZER;

// Инициализация обфускации
bool uot_initialize(UOTState *state, const unsigned char *shared_secret, size_t secret_len) {
    pthread_mutex_lock(&uot_mutex);

    if (!state || !shared_secret || secret_len != 32) {
        log_error("Invalid arguments for UOT initialization");
        pthread_mutex_unlock(&uot_mutex);
        return false;
    }

    // Инициализация контекстов шифрования
    state->encrypt_ctx = EVP_CIPHER_CTX_new();
    state->decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!state->encrypt_ctx || !state->decrypt_ctx) {
        log_error("Failed to create cipher contexts");
        EVP_CIPHER_CTX_free(state->encrypt_ctx);
        EVP_CIPHER_CTX_free(state->decrypt_ctx);
        pthread_mutex_unlock(&uot_mutex);
        return false;
    }

    // Генерация ключа и IV из общего секрета
    if (!HKDF(state->key, 32, EVP_sha256(), shared_secret, secret_len, NULL, 0, (unsigned char *)"UOT", 3)) {
        log_error("HKDF key derivation failed");
        goto cleanup;
    }

    if (!RAND_bytes(state->iv, 12)) {
        log_error("Failed to generate IV");
        goto cleanup;
    }

    // Инициализация AES-GCM
    if (EVP_EncryptInit_ex(state->encrypt_ctx, EVP_aes_256_gcm(), NULL, state->key, state->iv) != 1 ||
        EVP_DecryptInit_ex(state->decrypt_ctx, EVP_aes_256_gcm(), NULL, state->key, state->iv) != 1) {
        log_error("Failed to initialize AES-GCM");
        goto cleanup;
    }

    state->is_initialized = true;
    log_info("UOT initialized successfully");
    pthread_mutex_unlock(&uot_mutex);
    return true;

cleanup:
    EVP_CIPHER_CTX_free(state->encrypt_ctx);
    EVP_CIPHER_CTX_free(state->decrypt_ctx);
    pthread_mutex_unlock(&uot_mutex);
    return false;
}

// Деинициализация
void uot_cleanup(UOTState *state) {
    pthread_mutex_lock(&uot_mutex);

    if (!state) {
        pthread_mutex_unlock(&uot_mutex);
        return;
    }

    EVP_CIPHER_CTX_free(state->encrypt_ctx);
    EVP_CIPHER_CTX_free(state->decrypt_ctx);
    memset(state->key, 0, sizeof(state->key));
    memset(state->iv, 0, sizeof(state->iv));
    state->is_initialized = false;

    log_info("UOT cleaned up");
    pthread_mutex_unlock(&uot_mutex);
}

// Обфускация UDP -> TCP
ssize_t uot_obfuscate(const unsigned char *udp_data, size_t udp_len, unsigned char *tcp_buffer, size_t tcp_buffer_size) {
    pthread_mutex_lock(&uot_mutex);

    if (!udp_data || !tcp_buffer || tcp_buffer_size < 128) {
        log_error("Invalid buffer sizes for UOT");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    // 1. Сжатие данных
    uLongf compressed_len = tcp_buffer_size;
    if (compress2(tcp_buffer, &compressed_len, udp_data, udp_len, Z_BEST_COMPRESSION) != Z_OK) {
        log_error("Compression failed");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    // 2. Добавление случайного шума (10-50 байт)
    size_t noise_len = 10 + (rand() % 41);
    RAND_bytes(tcp_buffer + compressed_len, noise_len);
    compressed_len += noise_len;

    // 3. Шифрование AES-GCM
    int encrypted_len = 0;
    if (EVP_EncryptUpdate(state->encrypt_ctx, tcp_buffer, &encrypted_len, tcp_buffer, compressed_len) != 1) {
        log_error("Encryption failed");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    // 4. Добавление HTTP-заголовка для маскировки
    const char *http_header = "POST / HTTP/1.1\r\n"
                             "Host: cloudfront.net\r\n"
                             "Content-Type: application/octet-stream\r\n"
                             "Content-Length: %d\r\n\r\n";
    size_t header_len = snprintf((char *)tcp_buffer + encrypted_len, tcp_buffer_size - encrypted_len, http_header, encrypted_len);
    encrypted_len += header_len;

    pthread_mutex_unlock(&uot_mutex);
    return encrypted_len;
}

// Деобфускация TCP -> UDP
ssize_t uot_deobfuscate(const unsigned char *tcp_data, size_t tcp_len, unsigned char *udp_buffer, size_t udp_buffer_size) {
    pthread_mutex_lock(&uot_mutex);

    if (!tcp_data || !udp_buffer || tcp_len == 0) {
        log_error("Invalid input for deobfuscation");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    // 1. Удаление HTTP-заголовка
    const char *header_end = "\r\n\r\n";
    const unsigned char *payload_start = (const unsigned char *)strstr((const char *)tcp_data, header_end) + 4;
    size_t payload_len = tcp_len - (payload_start - tcp_data);

    // 2. Дешифрование AES-GCM
    int decrypted_len = 0;
    if (EVP_DecryptUpdate(state->decrypt_ctx, udp_buffer, &decrypted_len, payload_start, payload_len) != 1) {
        log_error("Decryption failed");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    // 3. Удаление шума (последние N байт)
    size_t noise_len = *(udp_buffer + decrypted_len - 1); // Предполагаем, что длина шума хранится в последнем байте
    decrypted_len -= noise_len + 1;

    // 4. Распаковка данных
    uLongf uncompressed_len = udp_buffer_size;
    if (uncompress(udp_buffer, &uncompressed_len, udp_buffer, decrypted_len) != Z_OK) {
        log_error("Decompression failed");
        pthread_mutex_unlock(&uot_mutex);
        return -1;
    }

    pthread_mutex_unlock(&uot_mutex);
    return uncompressed_len;
}

// Вспомогательная функция для генерации случайного шума
static void add_random_noise(unsigned char *data, size_t *len) {
    size_t noise_len = 10 + (rand() % 41);
    if (*len + noise_len > MAX_TCP_BUFFER) {
        noise_len = MAX_TCP_BUFFER - *len;
    }
    RAND_bytes(data + *len, noise_len);
    *len += noise_len;
}