#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif


#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

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

#ifdef _WIN32
    // Используем CryptGenRandom для генерации случайных чисел на Windows
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        free(random_str);
        return NULL;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char random_byte;
        if (!CryptGenRandom(hProvider, 1, &random_byte)) {
            CryptReleaseContext(hProvider, 0);
            free(random_str);
            return NULL;
        }
        random_str[i] = charset[random_byte % (sizeof(charset) - 1)];
    }
    CryptReleaseContext(hProvider, 0);
#else
    // Используем /dev/urandom для генерации случайных чисел на Unix
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        free(random_str);
        return NULL;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char random_byte;
        if (fread(&random_byte, 1, 1, urandom) != 1) {
            fclose(urandom);
            free(random_str);
            return NULL;
        }
        random_str[i] = charset[random_byte % (sizeof(charset) - 1)];
    }
    fclose(urandom);
#endif

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
#ifdef _WIN32
    DWORD attrib = GetFileAttributes(filename);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
#endif
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

// Кроссплатформенная функция для создания директории
bool create_directory(const char *path) {
#ifdef _WIN32
    return CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(path, 0755) == 0 || errno == EEXIST;
#endif
}

// Кроссплатформенная функция для проверки прав доступа к файлу
bool check_file_permissions(const char *filename) {
#ifdef _WIN32
    HANDLE hFile = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(hFile);
    return true;
#else
    return access(filename, R_OK) == 0;
#endif
}
