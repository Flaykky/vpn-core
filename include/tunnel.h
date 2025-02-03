#ifndef TUNNEL_H
#define TUNNEL_H

#include "common.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>

#define IFNAMSIZ 16              // Максимальная длина имени интерфейса
#define INET6_ADDRSTRLEN 46      // Максимальная длина строки для IPv6-адреса


#else
#include <fcntl.h>
#include <net/if.h>          // Для IFNAMSIZ
#include <netinet/in.h>      // Для INET6_ADDRSTRLEN
#include <sys/ioctl.h>
#include <unistd.h>
#endif




// Типы данных для туннеля
typedef struct {
    int fd;                     // Файловый дескриптор туннеля
    char name[IFNAMSIZ];        // Имя интерфейса
    char ip_address[INET6_ADDRSTRLEN]; // IP-адрес
    char subnet_mask[INET6_ADDRSTRLEN]; // Маска подсети
    bool is_ipv6;               // Флаг для IPv6
} Tunnel;

// Инициализация туннеля
bool initialize_tunnel(Tunnel *tunnel, const char *ip_address, const char *subnet_mask, bool is_ipv6);

// Удаление туннеля
void teardown_tunnel(Tunnel *tunnel);

// Чтение данных из туннеля
ssize_t read_from_tunnel(Tunnel *tunnel, void *buffer, size_t length);

// Запись данных в туннель
ssize_t write_to_tunnel(Tunnel *tunnel, const void *buffer, size_t length);

// Проверка состояния туннеля
bool is_tunnel_valid(const Tunnel *tunnel);

// Переключение между IPv4 и IPv6
bool switch_tunnel_ip_version(Tunnel *tunnel, bool is_ipv6);

// Настройка MTU для туннеля
bool set_tunnel_mtu(Tunnel *tunnel, int mtu);

// Получение статистики туннеля
void get_tunnel_stats(Tunnel *tunnel, uint64_t *bytes_received, uint64_t *bytes_sent);

#endif // TUNNEL_H
