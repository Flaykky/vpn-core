#ifndef TCP_H
#define TCP_H

#include <stdbool.h>
#include "connection/connection.h"

// под протоколом "tcp" имеется ввиду простое TCP туннелирование.

int establish_tcp_tunnel(const char *server_ip, int port); // установка простого TCP тоннеля

#ifdef _WIN32
static void init_winsock(void); // винсок для windows 
#endif 

bool initialize_tcp(ProtocolState *state, const char *server_ip, int port); // инициализация tcp 

void close_tcp(ProtocolState *state); // закрытие tcp 

#endif // TCP_H
