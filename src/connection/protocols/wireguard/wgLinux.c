// wireguard for Linux 

#include "include/connection/protocols/wireguard/wgLinux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>

// Создание TUN-интерфейса
static int create_tun_interface(const char *if_name) {
    struct ifreq ifr;
    int fd, err;
    
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (if_name && *if_name) {
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    }
    
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }
    
    return fd;
}

// Функция генерации пары ключей (placeholder; для продакшена использовать libsodium или аналог)
static int generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    // Здесь необходимо использовать криптографическую библиотеку для генерации ключей (например, Curve25519)
    for (int i = 0; i < WG_KEY_SIZE; i++) {
        private_key[i] = rand() % 256;
        public_key[i] = rand() % 256;
    }
    // TODO: Заменить на корректную реализацию генерации ключей
    return 0;
}

int wg_init(WGContext *ctx, const char *if_name) {
    if (!ctx || !if_name) {
        return -1;
    }
    
    memset(ctx, 0, sizeof(WGContext));
    strncpy(ctx->if_name, if_name, WG_IFACE_NAME_MAX - 1);
    
    ctx->tun_fd = create_tun_interface(ctx->if_name);
    if (ctx->tun_fd < 0) {
        fprintf(stderr, "Не удалось создать TUN-интерфейс\n");
        return -1;
    }
    
    // Генерация ключей
    if (generate_keypair(ctx->private_key, ctx->public_key) != 0) {
        fprintf(stderr, "Ошибка генерации ключей\n");
        close(ctx->tun_fd);
        return -1;
    }
    
    // Дополнительная инициализация состояния рукопожатия, таймеров, информации о пире и пр.
    // TODO: Инициализировать протокол рукопожатия (Noise) и другие необходимые структуры.
    
    return 0;
}

// Функция для выполнения рукопожатия (placeholder)
static int perform_handshake(WGContext *ctx) {
    // Реальная реализация должна выполнять обмен сообщениями рукопожатия с пировым узлом,
    // используя протокол Noise IK, шифруя и аутентифицируя сообщения.
    
    printf("Выполняется рукопожатие (placeholder)...\n");
    // TODO: Реализовать полный протокол рукопожатия
    return 0;
}

int wg_start(WGContext *ctx) {
    if (!ctx) return -1;
    
    // Выполнить рукопожатие для установления сеансовых ключей
    if (perform_handshake(ctx) != 0) {

        
        
    // Здесь должен располагаться основной цикл обработки пакетов:
    // например, использование select()/poll() для мультиплексирования между TUN-интерфейсом и UDP-сокетом.
    
    printf("Wireguard VPN-сервис запущен на интерфейсе %s\n", ctx->if_name);
    return 0;
}

void wg_stop(WGContext *ctx) {
    if (!ctx) return;
    
    if (ctx->tun_fd >= 0) {
        close(ctx->tun_fd);
        ctx->tun_fd = -1;
    }
    
    // Очистка состояния рукопожатия, сеансовых ключей и других ресурсов
    printf("Wireguard VPN-сервис остановлен\n");
}

// Placeholder для шифрования пакета
static int encrypt_packet(WGContext *ctx, const void *plaintext, size_t plaintext_len,
                          void *ciphertext, size_t *ciphertext_len) {
    // В реальной реализации необходимо использовать ChaCha20/Poly1305 для шифрования и аутентификации.
    if (plaintext_len > *ciphertext_len) return -1;
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len = plaintext_len;
    // TODO: Реализовать шифрование
    return 0;
}

// Placeholder для дешифрования пакета
static int decrypt_packet(WGContext *ctx, const void *ciphertext, size_t ciphertext_len,
                          void *plaintext, size_t *plaintext_len) {
    // В реальной реализации необходимо использовать ChaCha20/Poly1305 для дешифрования и проверки целостности.
    if (ciphertext_len > *plaintext_len) return -1;
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    // TODO: Реализовать дешифрование
    return 0;
}

int wg_send_packet(WGContext *ctx, const void *packet, size_t length) {
    if (!ctx || !packet || length == 0) return -1;
    
    uint8_t buffer[WG_PACKET_MAX_SIZE];
    size_t encrypted_len = sizeof(buffer);
    
    if (encrypt_packet(ctx, packet, length, buffer, &encrypted_len) != 0) {
        fprintf(stderr, "Ошибка шифрования пакета\n");
        return -1;
    }
    
    // В реальной реализации пакет отправляется по UDP-сокету,
    // здесь для упрощения мы записываем данные в TUN-интерфейс.
    ssize_t n = write(ctx->tun_fd, buffer, encrypted_len);
    if (n < 0) {
        perror("write");
        return -1;
    }
    
    return 0;
}

int wg_receive_packet(WGContext *ctx, void *buffer, size_t buffer_length) {
    if (!ctx || !buffer || buffer_length == 0) return -1;
    
    uint8_t encrypted[WG_PACKET_MAX_SIZE];
    ssize_t n = read(ctx->tun_fd, encrypted, sizeof(encrypted));
    if (n < 0) {
        perror("read");
        return -1;
    }
    
    size_t decrypted_len = buffer_length;
    if (decrypt_packet(ctx, encrypted, n, buffer, &decrypted_len) != 0) {
        fprintf(stderr, "Ошибка дешифрования пакета\n");
        return -1;
    }
    
    return (int)decrypted_len;
}
