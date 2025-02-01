#include "common.h"
#include <time.h>

// Функция для получения текущего времени в строковом формате
char* get_current_time_str(void) {
    static char buffer[80];
    time_t now = time(NULL);
    struct tm *tm_struct = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_struct);
    return buffer;
}