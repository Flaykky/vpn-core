#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

// Проверка строки на пустоту
bool is_string_empty(const char *str) {
    return str == NULL || strlen(str) == 0;
}

// Обрезка пробелов в начале и конце строки
char* trim_whitespace(char *str) {
    if (str == NULL) return NULL;

    // Убираем пробелы в начале
    size_t start = 0;
    while (isspace((unsigned char)str[start])) {
        start++;
    }

    // Убираем пробелы в конце
    size_t len = strlen(str);
    size_t end = len;
    while (end > start && isspace((unsigned char)str[end - 1])) {
        end--;
    }

    // Создаем новую строку без пробелов
    if (start != 0 || end != len) {
        memmove(str, str + start, end - start);
        str[end - start] = '\0';
    }

    return str;
}

// Генерация случайной строки заданной длины
char* generate_random_string(size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char *random_str = malloc(length + 1);
    if (!random_str) return NULL;

    for (size_t i = 0; i < length; ++i) {
        random_str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    random_str[length] = '\0';

    return random_str;
}

// Преобразование строки в нижний регистр
void to_lowercase(char *str) {
    if (str == NULL) return;
    for (size_t i = 0; str[i] != '\0'; ++i) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

// Получение текущего времени в формате Unix timestamp
time_t get_current_timestamp(void) {
    return time(NULL);
}

// Форматирование времени в строку
char* format_time(time_t timestamp, char *buffer, size_t buffer_size) {
    struct tm *tm_info = localtime(&timestamp);
    if (strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        return NULL;
    }
    return buffer;
}

// Проверка наличия файла
bool file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// Чтение всего содержимого файла в строку
char* read_file_contents(const char *filename, size_t *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < 0) {
        perror("Failed to determine file size");
        fclose(file);
        return NULL;
    }
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Failed to allocate memory for file contents");
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("Failed to read file contents");
        free(buffer);
        fclose(file);
        return NULL;
    }

    buffer[file_size] = '\0';
    if (length) {
        *length = (size_t)file_size;
    }

    fclose(file);
    return buffer;
}