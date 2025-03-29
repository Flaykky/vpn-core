#ifndef UDP_H
#define UDP_H


#include <basetsd.h>
#include <sys/types.h> 

// под протоколом 'udp' имеется ввиду простое udp туннелирование 

int establish_udp_connection(const char *server_ip, int port); // установка udp соединения 

ssize_t send_udp_data(int socket_fd, const void *data, size_t length, const struct sockaddr_in *server_addr); // отправка через udp

ssize_t receive_udp_data(int socket_fd, void *buffer, size_t length, struct sockaddr_in *client_addr); // получение через udp

#endif // UDP_H