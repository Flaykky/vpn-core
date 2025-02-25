#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdbool.h>
#include <stddef.h>


typedef struct {
    const char *name;
    bool (*initialize)(void);
    void (*cleanup)(void);
    ssize_t (*send_data)(int sock, const void *data, size_t length);
    ssize_t (*receive_data)(int sock, void *buffer, size_t length);
} Protocol;

static Protocol current_protocol;


// Максимальный размер случайного шума
#define MAX_NOISE_SIZE 64
#define MAX_OBFUSCATION_BUFFER 4096

// Структура для хранения состояния обфускации
typedef struct {
    bool is_initialized;
    EVP_CIPHER_CTX *encryption_ctx;
    unsigned char key[32]; // Ключ AES-256
    unsigned char iv[16];  // IV для AES
} ObfuscationState;

static ObfuscationState obfuscation_state = {false};

// Включение/выключение обфускации
void enable_obfuscation(bool enable);

// Включение/выключение шума
void enable_noise(bool enable);

// Установка диапазона случайных задержек
void set_random_delay_range(int min_ms, int max_ms);

// Инициализация системы обфускации
bool initialize_obfuscation(void);

// Очистка системы обфускации
void cleanup_obfuscation(void);

// Обфускация UDP-пакетов в TCP
ssize_t udp_over_tcp_obfuscate(int tcp_socket, const void *udp_data, size_t udp_len);

// Деобфускация TCP-пакетов обратно в UDP
ssize_t udp_over_tcp_deobfuscate(int tcp_socket, void *udp_data, size_t max_udp_len);

#endif // OBFUSCATION_H
