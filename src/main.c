#include "common.h"
#include "connection.h"
#include "encryption.h"
#include "tunnel.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "killswitch.h"
#include "obfuscation.h"
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <basetsd.h>
#include <getopt.h>

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "wintun.lib")
#else
#endif


#include "connection.h"
#include "config.h"
#include <pthread.h>
#include <unistd.h>

static void print_help() {
    printf(
        "Usage: ./vpnCore [OPTIONS] PROTOCOL SERVER:PORT\n"
        "Protocols: wireguard, shadowsocks, tcp, udp\n"
        "Options:\n"
        "  -d, --dpi        Enable anti-DPI protection\n"
        "  -u, --uot        Enable UDP-over-TCP obfuscation\n"
        "  --proxy=TYPE     Proxy type (socks5/http/https)\n"
        "  --add-serv=FILE  Add server to configuration file\n"
    );
}

static void *monitor_thread(void *arg) {
    // Создаем временное состояние соединения
    ConnectionState temp_state = {0};
    temp_state.socket_fd = -1; // Инициализируем недействительным дескриптором
    strncpy(temp_state.server_ip, global_config.server_ip, MAX_IP_LENGTH);
    temp_state.port = global_config.server_port;

    while (!terminate_flag) {
        // Проверка состояния соединения
        bool connected = is_socket_valid(&temp_state);

        // Определение геолокации (если ещё не определено)
        if (!global_config.country || !global_config.city) {
            determine_server_location();
        }

        // Вывод статуса
        printf(
            "╭──────────────────────────────────────────────╮\n"
            "│  VPN Connection Status: %s [%s]        │\n"
            "│                                              │\n"
            "│  Location: %s, %s               │\n"
            "│  Protocol: %s                          │\n"
            "│                                              │\n"
            "│  Inbound:  %s:%d (UDP)                 │\n"
            "│  Outbound: %s                          │\n"
            "╰──────────────────────────────────────────────╯\n",
            connected ? "Connected" : "Disconnected",
            connected ? "✓" : "✗",
            global_config.country,
            global_config.city,
            global_config.protocol,
            global_config.server_ip,
            global_config.server_port,
            "1.1.1.2" // Пример outbound IP
        );

        sleep(5); // Обновление каждые 5 секунд
    }
    return NULL;
}

void process_data(int socket_fd, Tunnel *tunnel) {
    char buffer[1024];
    ssize_t bytes_read;

    // Чтение данных из туннеля
    bytes_read = read_from_tunnel(tunnel, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        // Обфускация и шифрование
        unsigned char obfuscated_data[2048];
        ssize_t obfuscated_len = obfuscate_udp_over_tcp(buffer, bytes_read, obfuscated_data, sizeof(obfuscated_data));
        if (obfuscated_len < 0) {
            log_error("Obfuscation failed");
            return;
        }

        // Отправка обфусцированных данных
        send_data(socket_fd, obfuscated_data, obfuscated_len);
    }

 }

bool read_config_file(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open config file: %s", filename);
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (key && value) {
            if (strcmp(key, "server_ip") == 0) {
                free(config->server_ip); // Освобождаем предыдущее значение
                config->server_ip = strdup(value);
            } else if (strcmp(key, "port") == 0) {
                config->server_port = atoi(value);
            }
        }
    }

    fclose(file);
    log_info("Configuration loaded from file: %s", filename);
    return true;
}

// Флаг для выхода из основного цикла
static volatile sig_atomic_t terminate_flag = 0;

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log_info("Shutdown signal received, terminating...");
        terminate_flag = true;
    }
}



void process_data(int socket_fd, Tunnel *tunnel) {
    char buffer[1024];
    ssize_t bytes_read;

    // Чтение данных из туннеля
    bytes_read = read_from_tunnel(tunnel, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        size_t encrypted_len;
        if (!encrypt_data(buffer, bytes_read, buffer, &encrypted_len)) {
            log_error("Encryption failed");
            return;
        }

        if (send_data(socket_fd, buffer, encrypted_len) < 0) {
            log_error("Failed to send encrypted data");
            return;
        }
    } else if (bytes_read == 0) {
        log_info("Tunnel closed by peer");
        terminate_flag = true;
    } else {
        log_error("Error reading from tunnel");
    }

    // Чтение данных из сокета
    bytes_read = receive_data(socket_fd, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        size_t decrypted_len;
        if (!decrypt_data(buffer, bytes_read, buffer, &decrypted_len)) {
            log_error("Decryption failed");
            return;
        }

        if (write_to_tunnel(tunnel, buffer, decrypted_len) < 0) {
            log_error("Failed to write decrypted data to tunnel");
            return;
        }
    } else if (bytes_read == 0) {
        log_info("Connection closed by peer");
        terminate_flag = true;
    } else {
        log_error("Error receiving from socket");
    }
}




// Основная функция
int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"proxy", required_argument, 0, 'x'},
        {"proxy-port", required_argument, 0, 'y'},
        {0, 0, 0, 0}
    };
    
    const char *mode = "tcp";
    const char *server_ip = "127.0.0.1";
    int server_port = 8080;
    const char *proxy_ip = NULL;
    int proxy_port = 0;

    int opt;



    log_info("VPN Core started with arguments:");
        for (int i = 0; i < argc; i++) {
        log_info("Arg %d: %s", i, argv[i]);
    }


    while ((opt = getopt_long(argc, argv, "m:s:p:x:y:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                mode = optarg;
                break;
            case 's':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'x':
                proxy_ip = optarg;
                break;
            case 'y':
                proxy_port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [--mode tcp|udp] [--server ip] [--port port] [--proxy ip] [--proxy-port port]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }
        // Инициализация системы логирования
    init_logging("vpn.log", LOG_LEVEL_INFO, true);

    // Обработка параметров командной строки


    Config global_config = {0}; // Глобальная структура для хранения конфигурации

    if (!read_config_file("config.json", &global_config)) {
        log_error("Failed to read config");
        return EXIT_FAILURE;
    }
        // Запуск мониторинга в отдельном потоке
        pthread_t monitor_tid;
        pthread_create(&monitor_tid, NULL, monitor_thread, NULL);
        pthread_detach(monitor_tid);
    
        // Инициализация соединения в зависимости от протокола
        if (strcmp(global_config.protocol, "wireguard") == 0) {
            // Инициализация WireGuard (добавьте ваш код)
            log_info("WireGuard initialized");
        } else {
            log_error("Unsupported protocol: %s", global_config.protocol);
            return EXIT_FAILURE;
        }

    log_info("Starting VPN core...");

    // Регистрация обработчика сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Инициализация конфигурации
    if (!initialize_config(argc, argv)) {
        log_error("Failed to initialize configuration.");
        return EXIT_FAILURE;
    }


    if (argc == 2 && strcmp(argv[1], "help") == 0) {
        print_help();
        return EXIT_SUCCESS;
    }

    // Создаем состояние Shadowsocks
    ShadowsocksState shadowsocks_state = {0};

    // Инициализация выбранного протокола
    if (strcmp(global_config.protocol, "Shadowsocks") == 0) {
        // Настройка Shadowsocks
        const char *default_method = "aes-256-cfb"; // Метод шифрования по умолчанию
        if (!initialize_shadowsocks(&shadowsocks_state, global_config.server_ip,
                                    global_config.server_port, global_config.password,
                                    default_method)) {
            log_error("Failed to initialize Shadowsocks");
            return EXIT_FAILURE;
        }
    } else if (strcmp(global_config.protocol, "WireGuard") == 0) {
        // Настройка WireGuard
        if (!initialize_wireguard(global_config.server_ip, global_config.server_port)) {
            log_error("Failed to initialize WireGuard");
            return EXIT_FAILURE;
        }
    } else {
        log_error("Unsupported protocol: %s", global_config.protocol);
        return EXIT_FAILURE;
    }

    // Включение защиты DPI
    if (global_config.enable_dpi) {
        enable_dpi_protection();
    }

    // Включение UDP-over-TCP
    if (global_config.enable_udp_over_tcp) {
        enable_udp_over_tcp_obfuscation();
    }

    // Установка соединения
    int socket_fd = establish_connection(server_ip, server_port);
    if (socket_fd < 0) {
        log_error("Failed to establish connection.");
        return EXIT_FAILURE;
    }

    // Инициализация шифрования
    if (!initialize_encryption()) {
        log_error("Failed to initialize encryption.");
        close_connection(socket_fd);
        return EXIT_FAILURE;
    }

    Tunnel tunnel;
    if (!setup_tunnel(&tunnel, socket_fd)) {
        log_error("Failed to set up tunnel.");
        return EXIT_FAILURE;
    }


    if (!initialize_pfs()) {
        log_error("Failed to initialize PFS");
        return EXIT_FAILURE;
    }

    // Получение открытого ключа
    unsigned char public_key[65];
    size_t public_key_len = get_public_key(public_key, sizeof(public_key));
    if (public_key_len == 0) {
        log_error("Failed to get public key");
        cleanup_pfs();
        return EXIT_FAILURE;
    }

    // Здесь должен быть код для обмена ключами с сервером
    // Например, отправка public_key и получение peer_public_key

    // Вычисление общего секрета
    unsigned char peer_public_key[65] = {0}; // Заполните реальными данными
    size_t peer_public_key_len = 65; // Пример
    if (!compute_shared_secret(peer_public_key, peer_public_key_len)) {
        log_error("Failed to compute shared secret");
        cleanup_pfs();
        return EXIT_FAILURE;
    }

    // Инициализация шифрования с PFS
    if (!initialize_encryption_with_pfs()) {
        log_error("Failed to initialize encryption with PFS");
        cleanup_pfs();
        return EXIT_FAILURE;
    }

    // Инициализация обфускации
    if (!initialize_obfuscation()) {
        log_error("Failed to initialize obfuscation");
        cleanup_encryption();
        cleanup_pfs();
        return EXIT_FAILURE;
    }

    log_info("VPN core is running...");

        // Основной цикл обработки данных
    #ifdef _WIN32
        while (!terminate_flag) {
            process_data(socket_fd, tun_fd); // Исправляем вызов функции
        }
    #else
        while (!terminate_flag) {
            process_data(socket_fd, tun_fd); // Исправляем вызов функции
        }
    #endif

        log_info("Shutting down VPN core...");

        Tunnel tunnel;
        if (!setup_tunnel(&tunnel, socket_fd)) {
        log_error("Failed to set up tunnel.");
        return EXIT_FAILURE;
    }

    #ifdef _WIN32
    while (!terminate_flag) {
        process_data(socket_fd, &tunnel); // Передаём tunnel
        // Проверка флага завершения
        if (should_terminate()) {
            break;
        }
    }
    #else
    while (!terminate_flag) {
        if (use_udp) {
            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(server_port);
            inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
            char buffer[1024];
            ssize_t bytes_received = receive_udp_data(socket_fd, buffer, sizeof(buffer), &server_addr);
            if (bytes_received > 0) {
                log_info("Received %zd bytes via UDP", bytes_received);
                write_to_tunnel(&tunnel, buffer, bytes_received);
            } else if (bytes_received == 0) {
                log_info("UDP connection closed by peer");
                terminate_flag = true;
            } else {
                log_error("Error receiving UDP data");
            }
        } else {
            process_data(socket_fd, &tunnel);
        }
    
        // Проверка флага завершения
        if (should_terminate()) {
            break;
        }
    }
    #endif



    // Проверка доступности сервера
    if (!is_server_reachable(server_ip, server_port)) {
        log_error("Server is unreachable");
        return EXIT_FAILURE;
    }

    bool use_udp = false; // Флаг для использования UDP

    // Установка соединения
    if (use_udp) {
        socket_fd = establish_udp_connection(server_ip, server_port);
    } else {
        socket_fd = establish_connection(server_ip, server_port);
    }


    bool use_udp = false; // Флаг для использования UDP

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            server_ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            server_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--udp") == 0) {
            use_udp = true; // Включаем UDP
        }
    }

    char random_ip[16];
    generate_random_ip(random_ip, sizeof(random_ip));
    setup_tunnel(socket_fd, random_ip, "255.255.255.0");

    // Установка соединения
    int socket_fd = -1;
    if (use_udp) {
        socket_fd = establish_udp_connection(server_ip, server_port);
    } else {
        socket_fd = establish_connection(server_ip, server_port);
    }

    if (socket_fd < 0) {
        log_error("Failed to establish connection.");
        return EXIT_FAILURE;
    }

    // Пример использования:
    if (!initialize_pfs()) {
        log_error("Failed to initialize PFS");
        return EXIT_FAILURE;
    }

    

    unsigned char public_key[65];
    size_t public_key_len = get_public_key(public_key, sizeof(public_key));
    if (public_key_len == 0) {
        log_error("Failed to get public key");
        return EXIT_FAILURE;
    }

    // отправка public_key другой стороне и получите её открытый ключ


    unsigned char peer_public_key[65]; // Define peer_public_key
    size_t peer_public_key_len = sizeof(peer_public_key); // Define peer_public_key_len

    // Assuming peer_public_key is filled with the actual public key data before this point

    if (!compute_shared_secret(peer_public_key, peer_public_key_len)) {
        log_error("Failed to compute shared secret");
        return EXIT_FAILURE;
    }

    if (!initialize_encryption_with_pfs()) {
        log_error("Failed to initialize encryption with PFS");
        return EXIT_FAILURE;
    }


    if (!initialize_obfuscation()) {
        log_error("Failed to initialize obfuscation");
        return EXIT_FAILURE;
    }
    
    // Обфускация данных
    unsigned char udp_data[] = "Hello, this is a test message!";
    unsigned char tcp_buffer[1024];
    ssize_t tcp_len = obfuscate_udp_over_tcp(udp_data, sizeof(udp_data), tcp_buffer, sizeof(tcp_buffer));
    if (tcp_len < 0) {
        log_error("Failed to obfuscate data");
        cleanup_obfuscation();
        return EXIT_FAILURE;
    }
    
    // Отправка данных через TCP
    send_data(socket_fd, tcp_buffer, tcp_len);
    
    // Получение данных через TCP
    unsigned char received_data[1024];
    ssize_t received_len = receive_data(socket_fd, received_data, sizeof(received_data));
    if (received_len < 0) {
        log_error("Failed to receive data");
        cleanup_obfuscation();
        return EXIT_FAILURE;
    }
    
    // Деобфускация данных
    unsigned char udp_buffer[1024];
    ssize_t udp_len = deobfuscate_udp_over_tcp(received_data, received_len, udp_buffer, sizeof(udp_buffer));
    if (udp_len < 0) {
        log_error("Failed to deobfuscate data");
        cleanup_obfuscation();
        return EXIT_FAILURE;
    }
    
    log_info("Deobfuscated data: %s", udp_buffer);
    
    


    
    // очистка ресурсов перед завершением ВПН
    teardown_tunnel(&tunnel);
    cleanup_encryption();
    cleanup_obfuscation();
    cleanup_pfs();
    close_connection(socket_fd);
    close_logging();

    log_info("VPN core terminated successfully."); // лог

    return EXIT_SUCCESS;
}
