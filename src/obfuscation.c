#include "obfuscation.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>

#ifndef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#endif 
#define MAX_UDP_PACKET_SIZE 1400
#define NOISE_MIN_SIZE 16
#define NOISE_MAX_SIZE 128

typedef struct {
    uint16_t length; // Длина UDP-пакета
    char data[MAX_UDP_PACKET_SIZE]; // Данные UDP-пакета
} UDPPacket;

static bool obfuscation_enabled = false;
static bool noise_enabled = true;
static int min_delay_ms = 50; // Минимальная задержка (мс)
static int max_delay_ms = 200; // Максимальная задержка (мс)

// Функция для генерации случайного числа
static inline int get_random_int(int min, int max) {
    return min + rand() % (max - min + 1);
}

// Функция для добавления случайного шума к пакету
static void add_noise(char *buffer, size_t *buffer_len) {
    if (!noise_enabled || buffer == NULL || buffer_len == NULL) {
        return;
    }

    size_t noise_size = get_random_int(NOISE_MIN_SIZE, NOISE_MAX_SIZE);
    if (*buffer_len + noise_size > MAX_UDP_PACKET_SIZE) {
        noise_size = MAX_UDP_PACKET_SIZE - *buffer_len;
    }

    for (size_t i = 0; i < noise_size; i++) {
        buffer[*buffer_len + i] = (char)get_random_int(0, 255);
    }

    *buffer_len += noise_size;
    log_info("Added %zu bytes of noise to the packet", noise_size);
}

// Функция для добавления случайной задержки
static void add_random_delay(void) {
    int delay_ms = get_random_int(min_delay_ms, max_delay_ms);
    usleep(delay_ms * 1000); // Преобразование миллисекунд в микросекунды
    log_debug("Added random delay: %d ms", delay_ms);
}

// Обфускация UDP-пакетов в TCP
ssize_t udp_over_tcp_obfuscate(int tcp_socket, const void *udp_data, size_t udp_len) {
    if (!obfuscation_enabled || tcp_socket < 0 || udp_data == NULL || udp_len == 0) {
        log_error("Invalid parameters for obfuscation");
        return -1;
    }

    UDPPacket packet;
    memset(&packet, 0, sizeof(packet));

    // Копируем данные UDP в структуру пакета
    if (udp_len > MAX_UDP_PACKET_SIZE) {
        log_error("UDP packet too large for obfuscation");
        return -1;
    }

    packet.length = htons((uint16_t)udp_len);
    memcpy(packet.data, udp_data, udp_len);

    size_t total_len = sizeof(uint16_t) + udp_len;

    // Добавляем шум
    add_noise(packet.data, &total_len);

    // Добавляем случайную задержку
    add_random_delay();

    // Отправляем обфусцированный пакет через TCP
    ssize_t bytes_sent = send(tcp_socket, &packet, total_len, 0);
    if (bytes_sent < 0) {
        log_error("Failed to send obfuscated UDP packet over TCP");
        return -1;
    }

    log_info("Obfuscated UDP packet sent over TCP (%zd bytes)", bytes_sent);
    return bytes_sent;
}

// Деобфускация TCP-пакетов обратно в UDP
ssize_t udp_over_tcp_deobfuscate(int tcp_socket, void *udp_data, size_t max_udp_len) {
    if (!obfuscation_enabled || tcp_socket < 0 || udp_data == NULL || max_udp_len == 0) {
        log_error("Invalid parameters for deobfuscation");
        return -1;
    }

    UDPPacket packet;
    memset(&packet, 0, sizeof(packet));

    // Читаем заголовок пакета (длина UDP)
    ssize_t bytes_received = recv(tcp_socket, &packet, sizeof(uint16_t), 0);
    if (bytes_received != sizeof(uint16_t)) {
        log_error("Failed to receive packet header");
        return -1;
    }

    uint16_t udp_len = ntohs(packet.length);
    if (udp_len > max_udp_len) {
        log_error("Received UDP packet exceeds buffer size");
        return -1;
    }

    // Читаем данные UDP
    bytes_received = recv(tcp_socket, packet.data, udp_len, 0);
    if (bytes_received != udp_len) {
        log_error("Failed to receive full UDP packet");
        return -1;
    }

    // Копируем деобфусцированные данные в выходной буфер
    memcpy(udp_data, packet.data, udp_len);

    log_info("Deobfuscated UDP packet received (%zd bytes)", bytes_received);
    return udp_len;
}

// Включение/выключение обфускации
void enable_obfuscation(bool enable) {
    obfuscation_enabled = enable;
    log_info("Obfuscation %s", enable ? "enabled" : "disabled");
}

// Включение/выключение шума
void enable_noise(bool enable) {
    noise_enabled = enable;
    log_info("Noise %s", enable ? "enabled" : "disabled");
}

// Установка диапазона случайных задержек
void set_random_delay_range(int min_ms, int max_ms) {
    if (min_ms < 0 || max_ms < min_ms) {
        log_error("Invalid delay range");
        return;
    }

    min_delay_ms = min_ms;
    max_delay_ms = max_ms;
    log_info("Random delay range set to %d-%d ms", min_delay_ms, max_delay_ms);
}

// Инициализация системы обфускации
bool initialize_obfuscation(void) {
    srand((unsigned int)time(NULL)); // Инициализация генератора случайных чисел
    obfuscation_enabled = true;
    noise_enabled = true;
    min_delay_ms = 50;
    max_delay_ms = 200;

    log_info("Obfuscation system initialized successfully");
    return true;
}

// Очистка системы обфускации
void cleanup_obfuscation(void) {
    obfuscation_enabled = false;
    noise_enabled = false;
    log_info("Obfuscation system cleaned up successfully");
}