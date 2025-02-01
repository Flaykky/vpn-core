#ifndef CONNECTION_H
#define CONNECTION_H

#include "common.h"
#include <stdbool.h>

int establish_connection(const char *server_ip, int port);
void close_connection(int socket_fd);
bool is_socket_valid(int socket_fd);

#endif // CONNECTION_H