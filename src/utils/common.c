#include "include/utils/common.h"
#include <time.h>
#include <rpcdce.h>
#include <stdbool.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <uuid/uuid.h> 
#endif

char* generate_uuid(void) {
    static char uuid_str[37];
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);
    return uuid_str;
}

bool is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void format_string(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, size, format, args);
    va_end(args);
}


// Функция для получения текущего времени в строковом формате
char* get_current_time_str(void) {
    static char buffer[80];
    time_t now = time(NULL);
    struct tm *tm_struct = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_struct);
    return buffer;
}