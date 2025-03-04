#ifndef CONNECTION_H
#define CONNECTION_H

#include "common.h"
#include <unistd.h>
#include <stdbool.h>
#include <basetsd.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "wireguard-nt-master/api/wireguard.h"
#include "wireguard-nt-master/api/adapter.h"
typedef SSIZE_T ssize_t;

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif


#define WG_KEY_LEN 32

typedef struct {
    char private_key[64];   // Приватный ключ в Base64
    char public_key[64];    // Публичный ключ сервера (Base64)
    char endpoint[128];     // Адрес сервера (IP:port)
    char interface_name[16]; // Имя интерфейса
    uint16_t listen_port;   // Порт для прослушивания (по умолчанию 51820)
    bool is_connected;      // Состояние соединения
#ifdef _WIN32
    WIREGUARD_ADAPTER *adapter; // Для Windows
#else
    int wg_fd;              // Для Unix
#endif
} WireGuardState;


bool wg_initialize(WireGuardState *state, const char *server_ip, uint16_t port, const char *private_key, const char *peer_pubkey);
void wg_cleanup(WireGuardState *state);
bool wg_connect(WireGuardState *state);
void wg_disconnect(WireGuardState *state);
ssize_t wg_send(WireGuardState *state, const void *data, size_t len);
ssize_t wg_receive(WireGuardState *state, void *buffer, size_t len);

typedef struct {
    SSL_CTX *ssl_ctx;
} EncryptionContext;

typedef struct {
    int socket_fd;
    char server_ip[MAX_IP_LENGTH];
    int port;
    bool is_connected;
    SSL_CTX *ssl_ctx; // Добавляем поле для SSL контекста
} ConnectionState;

#define MAX_PROXIES 10 // Проверка состояния соединения
#define SHADOWSOCKS_HEADER_SIZE 64 

typedef struct {
    char ip[16];
    int port;
    bool is_available;
} Proxy;

// Структура для состояния соединения Shadowsocks
typedef struct {
    int socket_fd;          // Дескриптор сокета
    char server_ip[64];     // IP-адрес сервера
    int server_port;        // Порт сервера
    char password[256];     // Пароль для шифрования
    char method[32];        // Метод шифрования
    bool is_connected;      // Флаг подключения
} ShadowsocksState;




static Proxy proxies[MAX_PROXIES];
static int proxy_count = 0;

pthread_mutex_t connection_mutex;
WSADATA wsa_data;
static SSL_CTX *ssl_ctx = NULL;


// Инициализация соединения
bool initialize_connection(ConnectionState *state, const char *server_ip, int port);

// Закрытие соединения
void close_connection(ConnectionState *state);

// Установка таймаутов для сокета
bool set_socket_timeouts(int socket_fd, int send_timeout_sec, int recv_timeout_sec);

// Проверка доступности сервера
bool is_server_reachable(const char *server_ip, int port);

// Проверка состояния соединения
bool is_socket_valid(const ConnectionState *state);

// Отправка данных через сокет
ssize_t send_data(ConnectionState *state, const void *data, size_t length);

// Получение данных через сокет
ssize_t receive_data(ConnectionState *state, void *buffer, size_t length);

int establish_tcp_tunnel(const char *server_ip, int port);

int establish_https_proxy_tunnel(const char *proxy_ip, int proxy_port, const char *target_host, int target_port);

// Переподключение при разрыве
bool reconnect(ConnectionState *state);

// Установка UDP-соединения
int establish_udp_connection(const char *server_ip, int port);

// Отправка данных через UDP
ssize_t send_udp_data(int socket_fd, const void *data, size_t length, const struct sockaddr_in *server_addr);

// Получение данных через UDP
ssize_t receive_udp_data(int socket_fd, void *buffer, size_t length, struct sockaddr_in *client_addr);


// Инициализация Shadowsocks-соединения
bool initialize_shadowsocks(ShadowsocksState *state, const char *server_ip, int port, const char *password, const char *method);

// Закрытие Shadowsocks-соединения
void close_shadowsocks(ShadowsocksState *state);

// Отправка данных через Shadowsocks
ssize_t send_data_shadowsocks(ShadowsocksState *state, const void *data, size_t length);

// Получение данных через Shadowsocks
ssize_t receive_data_shadowsocks(ShadowsocksState *state, void *buffer, size_t length);

// Переподключение при разрыве
bool reconnect_shadowsocks(ShadowsocksState *state);


// Инициализация WireGuard
bool initialize_wireguard(WireGuardState *state, const char *server_endpoint, const char *private_key, const char *server_public_key);

// Завершение WireGuard
void close_wireguard(WireGuardState *state);

// Переподключение
bool reconnect_wireguard(WireGuardState *state);

#endif // CONNECTION_H
