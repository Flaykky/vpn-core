#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>


typedef struct {
    char *protocol; // "wireguard", "openvpn" и т.д.
    char *server_ip;
    int server_port;
    char *login;
    char *password;
    char *country; // Для геолокации
    char *city;
    bool use_udp; 
    bool enable_dpi;         // Флаг защиты от DPI (-d)
    bool enable_udp_over_tcp; // Флаг UDP-over-TCP (uot)
    char *wireguard_private_key; // Приватный ключ WireGuard
    char *wireguard_peer_public_key; // Публичный ключ сервера
    char *dns_server; 
    char *proxy_type; 
    char *wireguard_public_key;  // Публичный ключ сервера
} Config;


extern Config global_config;

extern Config global_config;

bool parse_json_config(const char *filename, Config *config);
void free_config(Config *config);

#endif // CONFIG_H
