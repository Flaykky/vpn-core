#ifndef CONNECTION_H
#define CONNECTION_H

#include "common.h"
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Тип для описания состояния соединения
typedef struct {
    int socket_fd;
    bool is_connected;
    char server_ip[MAX_IP_LENGTH];
    int port;
} ConnectionState;

// Инициализация соединения
bool initialize_connection(ConnectionState *state, const char *server_ip, int port);

// Закрытие соединения
void close_connection(ConnectionState *state);

// Проверка состояния соединения
bool is_socket_valid(const ConnectionState *state);

// Отправка данных через сокет
ssize_t send_data(ConnectionState *state, const void *data, size_t length);

// Получение данных через сокет
ssize_t receive_data(ConnectionState *state, void *buffer, size_t length);

int establish_tcp_tunnel(const char *server_ip, int port);


// Переподключение при разрыве
bool reconnect(ConnectionState *state);

#endif // CONNECTION_H
