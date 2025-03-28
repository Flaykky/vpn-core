#include "include/obfuscation/dpiBypass/packet_padding.h"
#include <string.h>
#include "include/utils/logging.h"
#include <sys/types.h>
#include <basetsd.h>
#include <stdlib.h>
#include <stdint.h>



// Выравнивание до 1500 байт (MTU)
bool apply_packet_padding(unsigned char *data, size_t *len, uint16_t target_size) {
    if (*len >= target_size) return true;

    // Добавляем паддинг в конец пакета
    size_t padding_len = target_size - *len;
    unsigned char padding[padding_len];
    if (!RAND_bytes(padding, padding_len)) {
        log_error("Failed to generate padding");
        return false;
    }

    memcpy(data + *len, padding, padding_len);
    *len = target_size;
    log_info("Packet padded to %d bytes", target_size);
    return true;
}