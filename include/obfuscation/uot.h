#ifndef UOT_H
#define UOT_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

// Структура для состояния обфускации
typedef struct {
    EVP_CIPHER_CTX *encrypt_ctx; // Контекст шифрования
    EVP_CIPHER_CTX *decrypt_ctx; // Контекст дешифрования
    unsigned char key[32];       // Ключ AES-256-GCM
    unsigned char iv[12];        // IV для AES-GCM
    bool is_initialized;         // Флаг инициализации
} UOTState;

// Инициализация UOT
bool uot_initialize(UOTState *state, const unsigned char *shared_secret, size_t secret_len);

// Деинициализация UOT
void uot_cleanup(UOTState *state);

// Обфускация UDP-пакета в TCP
ssize_t uot_obfuscate(const unsigned char *udp_data, size_t udp_len, unsigned char *tcp_buffer, size_t tcp_buffer_size);

// Деобфускация TCP-пакета в UDP
ssize_t uot_deobfuscate(const unsigned char *tcp_data, size_t tcp_len, unsigned char *udp_buffer, size_t udp_buffer_size);

#endif // UOT_H
