#include "include/connection/connection.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"
#include "openssl/types.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include <errno.h>
#include <fcntl.h>
#include "ssl2.h"
#include "ssl_lib.c"
#include <ssl.h>
#include <unistd.h>
#include <stdbool.h>
#include <basetsd.h>
#include <sys/time.h>
#include "wireguard-nt-master/api/adapter.h"
#include "wireguard-nt-master/api/wireguard.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <ws2ipdef.h>
#include <bcrypt.h>
#include <winsock.h>
#include <fwpmu.h>

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif




// Установка TCP-туннеля
int establish_tcp_tunnel(const char *server_ip, int port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (getaddrinfo(server_ip, NULL, &hints, &res) != 0) {
        log_error("Failed to resolve %s", server_ip);
        return -1;
    }

    int sockfd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        ipv4->sin_port = htons(port);

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);
    return sockfd;
}


#ifdef _WIN32
        static void init_winsock(void) {
            WSADATA wsa_data;
            int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            if (result != 0) {
                log_error("WSAStartup failed with error: %d", WSAGetLastError());
                exit(EXIT_FAILURE);
            }
        }
#endif


    
// Инициализация TCP-протокола
bool initialize_tcp(ProtocolState *state, const char *server_ip, int port) {
    if (!state || !server_ip || port <= 0) {
        log_error("Invalid arguments for TCP initialization");
        return false;
    }

    state->type = PROTOCOL_TCP;
    state->tcp_socket = establish_tcp_tunnel(server_ip, port);

    if (state->tcp_socket < 0) {
        log_error("Failed to establish TCP tunnel");
        return false;
    }

    log_info("TCP initialized successfully");
    return true;
}

// Закрытие TCP-соединения
void close_tcp(ProtocolState *state) {
    if (!state || state->type != PROTOCOL_TCP) return;

    close(state->tcp_socket);
    state->tcp_socket = -1;
    log_info("TCP connection closed");
}
