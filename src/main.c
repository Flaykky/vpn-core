#include "common.h"
#include "connection.h"
#include "encryption.h"
#include "tunnel.h"
#include "config.h"
#include "logging.h"
#include "utils.h"

#include <signal.h>

#ifdef _WIN32
typedef SSIZE_T ssize_t;
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#pragma comment(lib, "wintun.lib")
#else
#endif

#include <sys/types.h> 
// Флаг для выхода из основного цикла
static volatile bool terminate_flag = false;

// Обработчик сигналов для graceful shutdown
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log_info("Shutdown signal received, terminating...");
        terminate_flag = true;
    }
}

// Функция для обработки входящих/исходящих данных
void process_data(int socket_fd, int tun_fd) {
    char buffer[1024];
    ssize_t bytes_read;

    // Читаем данные из туннеля
    bytes_read = read_from_tunnel(buffer, sizeof(buffer));
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
        write_to_tunnel(buffer, decrypted_len);
    } else if (bytes_read == 0) {
        log_info("Connection closed by peer");
        terminate_flag = true;
    } else {
        log_error("Error receiving from socket");
    }
}

int main(int argc, char *argv[]) {
    // Инициализация системы логирования
    init_logging("vpn.log", LOG_LEVEL_INFO, true);

    // Обработка параметров командной строки
    const char *server_ip = "127.0.0.1";
    int server_port = 8080;

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
        process_data_windows(socket_fd);

        // Проверка флага завершения
        if (should_terminate()) {
            break;
        }
    }
#else
    while (!terminate_flag) {
        process_data(socket_fd, tun_fd);

        // Проверка флага завершения
        if (should_terminate()) {
            break;
        }
    }
#endif

    
    log_info("Shutting down VPN core...");

    // Очистка ресурсов
    teardown_tunnel();
    cleanup_encryption();
    close_connection(socket_fd);

    // Завершение работы системы логирования
    close_logging();

    log_info("VPN core terminated successfully.");

    return EXIT_SUCCESS;
}