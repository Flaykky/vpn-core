#include "shadowsocks.h"
#include "ssr_client.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// Платформозависимые заголовки
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Внутренний контекст
typedef struct {
    ssr_client_ctx *client;
    SSState state;
    uv_loop_t *loop;
    uv_thread_t thread;
} SSContext;

static SSContext ctx = {0};

// Функция очистки конфиденциальных данных
static void secure_cleanup(void *ptr, size_t size) {
    if (ptr && size > 0) {
        memset(ptr, 0, size);
#ifdef _WIN32
        SecureZeroMemory(ptr, size);
#else
        explicit_bzero(ptr, size);
#endif
    }
}

// Основной рабочий поток
static void worker_thread(void *arg) {
    SSContext *ctx = (SSContext*)arg;
    uv_run(ctx->loop, UV_RUN_DEFAULT);
}

// Обработчик сигналов
static void signal_handler(int sig) {
    ctx.state = SS_STOPPED;
    uv_stop(ctx.loop);
}

int ss_init(const ShadowsocksConfig *config) {
    if (!config || ctx.client) return -1;

    // Валидация параметров
    if (!config->server || !config->password || 
        !config->method || !config->local_addr) {
        return -1;
    }

    // Инициализация SSR клиента
    ssr_client_config client_cfg = {
        .remote_host = config->server,
        .remote_port = config->server_port,
        .local_addr = config->local_addr,
        .local_port = config->local_port,
        .password = config->password,
        .method = config->method,
        .timeout = 300,
        .fast_open = 0
    };

    ctx.client = ssr_client_init(&client_cfg);
    if (!ctx.client) return -1;

    // Инициализация UV loop
    ctx.loop = uv_default_loop();
    if (!ctx.loop) {
        ssr_client_free(ctx.client);
        return -1;
    }

    // Настройка обработки сигналов
#ifndef _WIN32
    struct sigaction sa = {
        .sa_handler = signal_handler,
        .sa_flags = 0
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif

    ctx.state = SS_STOPPED;
    return 0;
}

int ss_start() {
    if (!ctx.client || ctx.state == SS_RUNNING) return -1;

    // Запуск клиента
    if (ssr_client_start(ctx.client, ctx.loop) != 0) {
        return -1;
    }

    // Запуск рабочего потока
    if (uv_thread_create(&ctx.thread, worker_thread, &ctx) != 0) {
        return -1;
    }

    ctx.state = SS_RUNNING;
    return 0;
}

void ss_stop() {
    if (ctx.state != SS_RUNNING) return;
    
    // Остановка клиента
    ssr_client_stop(ctx.client);
    ctx.state = SS_STOPPED;
    
    // Ожидание завершения потока
    uv_thread_join(&ctx.thread);
}

SSState ss_get_state() {
    return ctx.state;
}

void ss_cleanup() {
    ss_stop();

    if (ctx.client) {
        ssr_client_free(ctx.client);
        ctx.client = NULL;
    }

    // Очистка конфиденциальных данных
    secure_cleanup(&ctx, sizeof(ctx));
}

// Платформозависимая реализация сна
#ifdef _WIN32
static void sleep_ms(int ms) {
    Sleep(ms);
}
#else
static void sleep_ms(int ms) {
    usleep(ms * 1000);
}
#endif