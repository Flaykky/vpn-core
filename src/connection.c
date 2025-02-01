#include <stdbool.h>
#include "connection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif


#ifdef _WIN32
    typedef SSIZE_T ssize_t;
#endif

// Initialize Winsock on Windows
static void init_winsock(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        log_error("WSAStartup failed");
        exit(EXIT_FAILURE);
    }
#endif
}

// Cleanup Winsock on Windows
static void cleanup_winsock(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Resolve hostname to IP address
static bool resolve_hostname(const char *hostname, struct sockaddr_in *addr) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return false;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        memcpy(addr, ipv4, sizeof(struct sockaddr_in));
        break;
    }

    freeaddrinfo(res);
    return true;
}

// Establish a connection with the server
int establish_connection(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Initialize Winsock on Windows
    init_winsock();

    // Create socket
#ifdef _WIN32
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (sockfd < 0) {
#ifdef _WIN32
        log_error("Socket creation failed");
        cleanup_winsock();
        return -1;
#else
        perror("Socket creation failed");
        return -1;
#endif
    }

    // Define server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert IP address from text to network format
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        if (!resolve_hostname(server_ip, &server_addr)) {
            log_error("Failed to resolve hostname");
            close_connection(sockfd);
            return -1;
        }
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
#ifdef _WIN32
        log_error("Connection failed");
        closesocket(sockfd);
        cleanup_winsock();
        return -1;
#else
        perror("Connection failed");
        close(sockfd);
        return -1;
#endif
    }

    log_info("Connection established successfully");
    return sockfd;
}

// Close a connection
void close_connection(int socket_fd) {
    if (is_socket_valid(socket_fd)) {
#ifdef _WIN32
        closesocket(socket_fd);
#else
        close(socket_fd);
#endif
        cleanup_winsock();  // Call only on Windows
        log_info("Connection closed successfully");
    } else {
        log_error("Invalid socket descriptor");
    }
}

// Check if the socket is valid
bool is_socket_valid(int socket_fd) {
    return socket_fd >= 0;
}

// Send data over the socket
ssize_t send_data(int socket_fd, const void *data, size_t length) {
    if (!is_socket_valid(socket_fd)) {
        log_error("Invalid socket descriptor");
        return -1;
    }

    ssize_t bytes_sent = send(socket_fd, data, length, 0);
    if (bytes_sent < 0) {
#ifdef _WIN32
        log_error("Send failed");
#else
        perror("Send failed");
#endif
        return -1;
    }

    return bytes_sent;
}

// Receive data over the socket
ssize_t receive_data(int socket_fd, void *buffer, size_t length) {
    if (!is_socket_valid(socket_fd)) {
        log_error("Invalid socket descriptor");
        return -1;
    }

    ssize_t bytes_received = recv(socket_fd, buffer, length, 0);
    if (bytes_received < 0) {
#ifdef _WIN32
        log_error("Receive failed");
#else
        perror("Receive failed");
#endif
        return -1;
    } else if (bytes_received == 0) {
        log_info("Connection closed by peer");
        return 0;
    }

    return bytes_received;
}