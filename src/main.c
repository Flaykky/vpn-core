#include "common.h"
#include "connection.h"
#include "encryption.h"
#include "tunnel.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
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

bool read_config_file(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open config file: %s", filename);
        return false;
    }

    

    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        if (config->server_ip) {
            free(config->server_ip);
        }
        config->server_ip = strdup(value);
        
        if (key && value) {
            if (strcmp(key, "server_ip") == 0) {
                config->server_ip = strdup(value);
            } else if (strcmp(key, "port") == 0) {
                config->port = atoi(value);
            }

            
        }
    }




    fclose(file);
    log_info("Configuration loaded from file: %s", filename);
    return true;
}

// Флаг для выхода из основного цикла
static volatile sig_atomic_t terminate_flag = 0;

// Обработчик сигналов для graceful shutdown
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log_info("Shutdown signal received, terminating...");
        terminate_flag = true;
    }
}





void process_data(int socket_fd, Tunnel *tunnel) {
    char buffer[1024];
    ssize_t bytes_read;

    // Читаем данные из туннеля
    bytes_read = read_from_tunnel(tunnel, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        // Шифруем данные
        size_t encrypted_len;
        encrypt_data(buffer, bytes_read, buffer, &encrypted_len);
        // Отправляем зашифрованные данные через сокет
        send_data(socket_fd, buffer, encrypted_len);
    } else if (bytes_read == 0) {
        log_info("Tunnel closed by peer");
        terminate_flag = true;
    } else {
        log_error("Error reading from tunnel");
    }

    // Читаем данные из сокета
    bytes_read = receive_data(socket_fd, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        // Дешифруем данные
        size_t decrypted_len;
        decrypt_data(buffer, bytes_read, buffer, &decrypted_len);
        // Записываем дешифрованные данные в туннель
        write_to_tunnel(tunnel, buffer, decrypted_len);
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


    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            server_ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            server_port = atoi(argv[++i]);
        }
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

    // Настройка туннеля
    int tun_fd = -1; // Добавляем переменную для файлового дескриптора туннеля
    if (!setup_tunnel(socket_fd)) {
        log_error("Failed to set up tunnel.");
        cleanup_encryption();
        close_connection(socket_fd);
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
        process_data_windows(socket_fd);
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
                write_to_tunnel(buffer, bytes_received);
            } else if (bytes_received == 0) {
                log_info("UDP connection closed by peer");
                terminate_flag = true;
            } else {
                log_error("Error receiving UDP data");
            }
        } else {
            process_data(socket_fd, tun_fd);
        }

        // Проверка флага завершения
        if (should_terminate()) {
            break;
        }
    }
    #endif






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



    // Очистка ресурсов
    teardown_tunnel(&tunnel);
    cleanup_encryption();
    close_connection(socket_fd);

    // Завершение работы системы логирования
    close_logging();
    log_info("VPN core terminated successfully.");

    return EXIT_SUCCESS;
}
