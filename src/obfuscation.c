#include "obfuscation.h"
#include "encryption.h"
#include "connection.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h> // Для сжатия данных
#include <openssl/rand.h> // Для генерации случайных чисел



// Максимальный размер случайного шума
#define MAX_NOISE_SIZE 64

// Структура для хранения состояния обфускации
typedef struct {
    bool is_initialized;
    EVP_CIPHER_CTX *encryption_ctx;
    unsigned char key[32]; // Ключ AES-256
    unsigned char iv[16];  // IV для AES
} ObfuscationState;

static ObfuscationState obfuscation_state = {false};



void add_dummy_traffic(int sock) {
    char buffer[MAX_NOISE_SIZE];
    while (true) {
        memset(buffer, rand() % 256, MAX_NOISE_SIZE);
        send(sock, buffer, MAX_NOISE_SIZE, 0);
        usleep(rand() % 50000); // Имитация случайных задержек
    }
}

// Обфускация через Meek
bool meek_initialize(void) {
    log_info("Initializing Meek protocol...");
    // Настройка Meek (например, HTTPS-запросы к легитимным серверам)
    return true;
}

void meek_cleanup(void) {
    log_info("Cleaning up Meek protocol...");
}

ssize_t meek_send_data(int sock, const void *data, size_t length) {
    // Имитация отправки данных через HTTPS
    return send(sock, data, length, 0);
}

ssize_t meek_receive_data(int sock, void *buffer, size_t length) {
    // Имитация получения данных через HTTPS
    return recv(sock, buffer, length, 0);
}

Protocol meek_protocol = {
    .name = "Meek",
    .initialize = meek_initialize,
    .cleanup = meek_cleanup,
    .send_data = meek_send_data,
    .receive_data = meek_receive_data
};

// Аналогично можно реализовать Obfs4, Shadowsocks и другие протоколы


bool switch_protocol(const char *protocol_name) {
    if (strcmp(protocol_name, "Meek") == 0) {
        current_protocol = meek_protocol;
    } else if (strcmp(protocol_name, "Obfs4") == 0) {
        // current_protocol = obfs4_protocol;
    } else if (strcmp(protocol_name, "Shadowsocks") == 0) {
        // current_protocol = shadowsocks_protocol;
    } else {
        log_error("Unknown protocol: %s", protocol_name);
        return false;
    }

    log_info("Switched to protocol: %s", protocol_name);
    return true;
}

void handle_block_detection(ConnectionState *state) {
    pthread_mutex_lock(&connection_mutex);

    if (!is_socket_valid(state)) {
        log_warning("Connection blocked, switching protocol...");
        static const char *protocols[] = {"Meek", "Obfs4", "Shadowsocks"};
        static int current_index = 0;

        // Попробуем следующий протокол
        current_index = (current_index + 1) % (sizeof(protocols) / sizeof(protocols[0]));
        if (!switch_protocol(protocols[current_index])) {
            log_error("Failed to switch protocol");
            pthread_mutex_unlock(&connection_mutex);
            return;
        }

        // Переподключение
        reconnect(state);
    }

    pthread_mutex_unlock(&connection_mutex);
}

// Функция для инициализации обфускации
bool initialize_obfuscation(void) {
    if (obfuscation_state.is_initialized) {
        log_warning("Obfuscation is already initialized");
        return true;
    }

    pthread_mutex_lock(&encryption_mutex);

    // Создание нового контекста шифрования
    obfuscation_state.encryption_ctx = EVP_CIPHER_CTX_new();
    if (!obfuscation_state.encryption_ctx) {
        log_error("Failed to create cipher context for obfuscation");
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Генерация случайного ключа и IV
    if (!RAND_bytes(obfuscation_state.key, sizeof(obfuscation_state.key)) ||
        !RAND_bytes(obfuscation_state.iv, sizeof(obfuscation_state.iv))) {
        log_error("Failed to generate random bytes for obfuscation");
        EVP_CIPHER_CTX_free(obfuscation_state.encryption_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    // Инициализация контекста шифрования с алгоритмом AES-256-GCM
    if (EVP_EncryptInit_ex(obfuscation_state.encryption_ctx, EVP_aes_256_gcm(), NULL,
                           obfuscation_state.key, obfuscation_state.iv) != 1) {
        log_error("Failed to initialize encryption context for obfuscation");
        EVP_CIPHER_CTX_free(obfuscation_state.encryption_ctx);
        pthread_mutex_unlock(&encryption_mutex);
        return false;
    }

    obfuscation_state.is_initialized = true;
    log_info("Obfuscation initialized successfully");
    pthread_mutex_unlock(&encryption_mutex);
    return true;
}

// Функция для очистки обфускации
void cleanup_obfuscation(void) {
    pthread_mutex_lock(&encryption_mutex);

    if (obfuscation_state.is_initialized) {
        if (obfuscation_state.encryption_ctx) {
            EVP_CIPHER_CTX_free(obfuscation_state.encryption_ctx);
            obfuscation_state.encryption_ctx = NULL;
        }

        // Очистка ключей и IV из памяти
        memset(obfuscation_state.key, 0, sizeof(obfuscation_state.key));
        memset(obfuscation_state.iv, 0, sizeof(obfuscation_state.iv));

        obfuscation_state.is_initialized = false;
        log_info("Obfuscation cleaned up successfully");
    }

    pthread_mutex_unlock(&encryption_mutex);
}

// Функция для добавления случайного шума
static void add_random_noise(unsigned char *buffer, size_t *length) {
    size_t noise_size = rand() % MAX_NOISE_SIZE; // Случайный размер шума
    if (noise_size > 0) {
        RAND_bytes(buffer + *length, noise_size); // Добавляем случайные байты
        *length += noise_size;
    }
}

// Функция для создания псевдозаголовка HTTP
static size_t create_http_header(unsigned char *buffer, size_t data_length) {
    const char *http_template = "POST /api/v1/data HTTP/1.1\r\n"
                                "Host: example.com\r\n"
                                "Content-Type: application/octet-stream\r\n"
                                "Content-Length: %zu\r\n\r\n";
    return snprintf((char *)buffer, 256, http_template, data_length);
}

// Функция для сжатия данных
static bool compress_data(const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
        log_error("Failed to initialize compression");
        return false;
    }

    strm.avail_in = input_len;
    strm.next_in = (unsigned char *)input;
    strm.avail_out = *output_len;
    strm.next_out = output;

    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&strm);
        log_error("Compression failed");
        return false;
    }

    *output_len = strm.total_out;
    deflateEnd(&strm);
    return true;
}

// Функция для распаковки данных
static bool decompress_data(const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (inflateInit(&strm) != Z_OK) {
        log_error("Failed to initialize decompression");
        return false;
    }

    strm.avail_in = input_len;
    strm.next_in = (unsigned char *)input;
    strm.avail_out = *output_len;
    strm.next_out = output;

    if (inflate(&strm, Z_FINISH) != Z_STREAM_END) {
        inflateEnd(&strm);
        log_error("Decompression failed");
        return false;
    }

    *output_len = strm.total_out;
    inflateEnd(&strm);
    return true;
}

// Функция для обфускации данных
ssize_t obfuscate_udp_over_tcp(const unsigned char *udp_data, size_t udp_len, unsigned char *tcp_buffer, size_t tcp_buffer_size) {
    if (!obfuscation_state.is_initialized) {
        log_error("Obfuscation is not initialized");
        return -1;
    }

    pthread_mutex_lock(&encryption_mutex);

    // Шаг 1: Сжатие данных
    size_t compressed_len = tcp_buffer_size;
    unsigned char compressed_data[tcp_buffer_size];
    if (!compress_data(udp_data, udp_len, compressed_data, &compressed_len)) {
        pthread_mutex_unlock(&encryption_mutex);
        return -1;
    }

    // Шаг 2: Добавление случайного шума
    size_t noisy_len = compressed_len + MAX_NOISE_SIZE;
    unsigned char noisy_data[noisy_len];
    memcpy(noisy_data, compressed_data, compressed_len);
    add_random_noise(noisy_data, &compressed_len);

    // Шаг 3: Шифрование данных
    size_t encrypted_len = tcp_buffer_size;
    if (!encrypt_data(noisy_data, compressed_len, tcp_buffer, &encrypted_len)) {
        pthread_mutex_unlock(&encryption_mutex);
        return -1;
    }

    // Шаг 4: Добавление HTTP-заголовка
    size_t header_len = create_http_header(tcp_buffer + encrypted_len, encrypted_len);
    memmove(tcp_buffer + header_len, tcp_buffer, encrypted_len);
    encrypted_len += header_len;

    pthread_mutex_unlock(&encryption_mutex);
    return encrypted_len;
}

// Функция для деобфускации данных
ssize_t deobfuscate_udp_over_tcp(const unsigned char *tcp_data, size_t tcp_len, unsigned char *udp_buffer, size_t udp_buffer_size) {
    if (!obfuscation_state.is_initialized) {
        log_error("Obfuscation is not initialized");
        return -1;
    }

    pthread_mutex_lock(&encryption_mutex);

    // Шаг 1: Удаление HTTP-заголовка
    const char *header_end = "\r\n\r\n";
    const char *header_pos = strstr((const char *)tcp_data, header_end);
    if (!header_pos) {
        log_error("Invalid TCP data format");
        pthread_mutex_unlock(&encryption_mutex);
        return -1;
    }

    size_t header_len = header_pos - (const char *)tcp_data + strlen(header_end);
    tcp_data += header_len;
    tcp_len -= header_len;

    // Шаг 2: Дешифрование данных
    size_t decrypted_len = udp_buffer_size;
    if (!decrypt_data(tcp_data, tcp_len, udp_buffer, &decrypted_len)) {
        pthread_mutex_unlock(&encryption_mutex);
        return -1;
    }

    // Шаг 3: Распаковка данных
    size_t decompressed_len = udp_buffer_size;
    if (!decompress_data(udp_buffer, decrypted_len, udp_buffer, &decompressed_len)) {
        pthread_mutex_unlock(&encryption_mutex);
        return -1;
    }

    pthread_mutex_unlock(&encryption_mutex);
    return decompressed_len;
}
