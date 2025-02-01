#ifndef TUNNEL_H
#define TUNNEL_H

#include "common.h"

// Кроссплатформенные объявления
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

// Функция для установки туннеля
bool setup_tunnel(int socket_fd);

// Функция для удаления туннеля
void teardown_tunnel(void);

// Функция для чтения данных из туннеля
ssize_t read_from_tunnel(void *buffer, size_t length);

// Функция для записи данных в туннель
ssize_t write_to_tunnel(const void *buffer, size_t length);

#endif // TUNNEL_H