#include "include/obfuscation/obfuscation.h"
#include "include/obfuscation/dpiBypass/noise.h"
#include "include/obfuscation/dpiBypass/packet_padding.h"
#include "include/obfuscation/dpiBypass/traffic_obfuscation.h"
#include <pthread.h>
#include "include/utils/logging.h"

// Инициализация DPI Bypass
bool dpi_bypass_init(DpiBypassState *state, DAITAMethod methods, uint16_t noise_level, uint16_t padding_size) {
    pthread_mutex_lock(&state->mutex);

    if (!state) {
        log_error("Invalid state");
        pthread_mutex_unlock(&state->mutex);
        return false;
    }

    state->methods = methods;
    state->noise_level = noise_level;
    state->padding_size = padding_size;

    log_info("DPI Bypass initialized with methods: 0x%x", methods);
    pthread_mutex_unlock(&state->mutex);
    return true;
}

// Применение обфускации
ssize_t dpi_bypass_apply(DpiBypassState *state, const unsigned char *input, size_t input_len, 
                        unsigned char *output, size_t output_size) {
    pthread_mutex_lock(&state->mutex);

    if (!state || input_len == 0) {
        log_error("Invalid parameters for DPI Bypass");
        pthread_mutex_unlock(&state->mutex);
        return -1;
    }

    size_t current_len = input_len;
    memcpy(output, input, input_len);

    // 1. Добавление шума
    if (state->methods & DAI_NOISE) {
        add_random_noise(output, &current_len, state->noise_level);
    }

    // 2. Выравнивание пакетов
    if (state->methods & DAI_PADDING) {
        apply_packet_padding(output, &current_len, state->padding_size);
    }

    // 3. Многократный переход
    if (state->methods & DAI_MULTI_HOP) {
        // Пример промежуточных узлов
        const char *hops[] = {"192.168.1.100", "10.0.0.200"};
        multi_hop_route(hops, 2);
    }

    // 4. Увеличение трафика
    if (state->methods & DAI_TRAFFIC) {
        amplify_traffic(output, &current_len);
    }

    pthread_mutex_unlock(&state->mutex);
    return current_len;
}

// Очистка
void dpi_bypass_cleanup(DpiBypassState *state) {
    pthread_mutex_lock(&state->mutex);
    memset(state, 0, sizeof(DpiBypassState));
    pthread_mutex_unlock(&state->mutex);
    log_info("DPI Bypass cleaned up");
}