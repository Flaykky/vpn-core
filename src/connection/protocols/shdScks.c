#include "shdScks.h"
#include "shadowsocks.h"  
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

/* Добавляем форвард-декларацию для shadowsocks_ctx_t, если она не была определена в shadowsocks.h */
#ifndef SHADOWSOCKS_CTX_T_DEFINED
typedef struct shadowsocks_ctx shadowsocks_ctx_t;
#define SHADOWSOCKS_CTX_T_DEFINED
#endif

/* Структура контекста для нашей обёртки.
 * Здесь мы храним указатель на внутренний контекст Shadowsocks,
 * который создаётся через API shadowsocks-libev.
 */
struct shdScks_context {
    shadowsocks_ctx_t *ss_ctx;
    /* Дополнительные параметры можно добавить сюда, например, логгер, настройки и т.д. */
};

/* Инициализация контекста Shadowsocks по файлу конфигурации.
 * Здесь предполагается, что shadowsocks-libev предоставляет функцию:
 * shadowsocks_ctx_new(const char *config_file) -> shadowsocks_ctx_t *
 */
bool shdScks_initialize(const char *config_file, shdScks_context_t **ctx) {
    if (!config_file || !ctx) {
        fprintf(stderr, "Invalid parameters to shdScks_initialize\n");
        return false;
    }
    *ctx = (shdScks_context_t *)malloc(sizeof(shdScks_context_t));
    if (!*ctx) {
        fprintf(stderr, "Memory allocation failed in shdScks_initialize\n");
        return false;
    }
    memset(*ctx, 0, sizeof(shdScks_context_t));
    
    (*ctx)->ss_ctx = shadowsocks_ctx_new(config_file);
    if (!(*ctx)->ss_ctx) {
        fprintf(stderr, "Failed to initialize shadowsocks context from config file: %s\n", config_file);
        free(*ctx);
        *ctx = NULL;
        return false;
    }
    return true;
}

/* Устанавливает соединение с Shadowsocks-сервером.
 * Предполагается, что shadowsocks-libev предоставляет функцию:
 * shadowsocks_connect(shadowsocks_ctx_t *ctx, const char *server, int port) -> int sockfd
 */
int shdScks_connect(shdScks_context_t *ctx, const char *server, int port) {
    if (!ctx || !server || port <= 0) {
        fprintf(stderr, "Invalid parameters to shdScks_connect\n");
        return -1;
    }
    int sockfd = shadowsocks_connect(ctx->ss_ctx, server, port);
    if (sockfd < 0) {
        fprintf(stderr, "shadowsocks_connect failed: %s\n", strerror(errno));
    }
    return sockfd;
}

/* Отправка данных через Shadowsocks-соединение.
 * Предполагается, что shadowsocks-libev предоставляет:
 * shadowsocks_send(shadowsocks_ctx_t *ctx, int sockfd, const void *data, size_t len) -> ssize_t
 */
ssize_t shdScks_send(shdScks_context_t *ctx, int sockfd, const void *data, size_t len) {
    if (!ctx || sockfd < 0 || !data) {
        fprintf(stderr, "Invalid parameters to shdScks_send\n");
        return -1;
    }
    ssize_t ret = shadowsocks_send(ctx->ss_ctx, sockfd, data, len);
    if (ret < 0) {
        fprintf(stderr, "shadowsocks_send error: %s\n", strerror(errno));
    }
    return ret;
}

/* Приём данных из Shadowsocks-соединения.
 * Предполагается, что shadowsocks-libev предоставляет:
 * shadowsocks_recv(shadowsocks_ctx_t *ctx, int sockfd, void *buf, size_t len) -> ssize_t
 */
ssize_t shdScks_recv(shdScks_context_t *ctx, int sockfd, void *buf, size_t len) {
    if (!ctx || sockfd < 0 || !buf) {
        fprintf(stderr, "Invalid parameters to shdScks_recv\n");
        return -1;
    }
    ssize_t ret = shadowsocks_recv(ctx->ss_ctx, sockfd, buf, len);
    if (ret < 0) {
        fprintf(stderr, "shadowsocks_recv error: %s\n", strerror(errno));
    }
    return ret;
}

/* Закрытие Shadowsocks-соединения.
 * Предполагается, что shadowsocks-libev предоставляет:
 * shadowsocks_close(shadowsocks_ctx_t *ctx, int sockfd)
 */
void shdScks_close(shdScks_context_t *ctx, int sockfd) {
    if (!ctx || sockfd < 0) {
        return;
    }
    shadowsocks_close(ctx->ss_ctx, sockfd);
}

/* Очистка и освобождение контекста Shadowsocks.
 * Предполагается, что shadowsocks-libev предоставляет:
 * shadowsocks_ctx_free(shadowsocks_ctx_t *ctx)
 */
void shdScks_cleanup(shdScks_context_t *ctx) {
    if (!ctx) {
        return;
    }
    shadowsocks_ctx_free(ctx->ss_ctx);
    free(ctx);
}
