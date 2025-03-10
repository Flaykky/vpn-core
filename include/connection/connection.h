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
    char peer_public_key[64];
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


typedef enum {
    PROTOCOL_WIREGUARD,
    PROTOCOL_SHADOWSOCKS,
    PROTOCOL_TCP,
    PROTOCOL_UDP
} ProtocolType;

typedef struct {
    ProtocolType type;
    union {
        WireGuardState wg;
        ShadowsocksState ss;
        int tcp_socket;
        int udp_socket;
    };
} ProtocolState;



#endif // CONNECTION_H