#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdbool.h>
#include <stddef.h>

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