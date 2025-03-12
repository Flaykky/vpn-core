#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include <stdbool.h>



// Функция для проверки строки на пустоту
bool is_string_empty(const char *str);

// Функция для проверки корректности IP-адреса
bool is_valid_ip(const char *ip);

// Функция для получения текущего времени в строковом формате
char* get_current_time_str(void);

// Функция для проверки наличия файла
bool file_exists(const char *filename);

// Функция для чтения всего содержимого файла в строку
char* read_file_contents(const char *filename, size_t *length);

#endif // UTILS_H
