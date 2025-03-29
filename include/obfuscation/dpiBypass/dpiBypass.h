#ifndef DPI_BYPASS_H
#define DPI_BYPASS_H

#include "../obfuscation.h"

// Сетевой шум
void add_random_noise(unsigned char *data, size_t *len, uint16_t noise_level);
bool generate_dummy_packets(int sock, uint16_t packet_size, uint16_t count);

// Выравнивание пакетов
bool apply_packet_padding(unsigned char *data, size_t *len, uint16_t target_size);

// Многократный переход
bool multi_hop_route(const char *intermediate_servers[], uint8_t num_servers);

// Увеличение трафика
void amplify_traffic(unsigned char *data, size_t *len);

#endif // DPI_BYPASS_H