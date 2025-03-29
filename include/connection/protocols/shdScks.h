#ifndef SHDSCKS_H
#define SHDSCKS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/types.h>
#include <stdbool.h>

/* Контекст обёртки для Shadowsocks. В нём хранится внутренний контекст,
 * созданный через shadowsocks-libev.
 */
typedef struct shdScks_context shdScks_context_t;

/* Инициализация контекста на основе конфигурационного файла.
 * config_file – путь к файлу конфигурации Shadowsocks (например, JSON или другой формат).
 * ctx – указатель на возвращаемый контекст.
 * Возвращает true при успехе, false при ошибке.
 */
bool shdScks_initialize(const char *config_file, shdScks_context_t **ctx);

/* Устанавливает соединение с сервером Shadowsocks.
 * ctx – инициализированный контекст.
 * server – IP-адрес или доменное имя сервера.
 * port – порт сервера.
 * Возвращает файловый дескриптор соединения или -1 при ошибке.
 */
int shdScks_connect(shdScks_context_t *ctx, const char *server, int port);

/* Отправка данных через установленное соединение.
 * ctx – контекст.
 * sockfd – файловый дескриптор соединения.
 * data – указатель на отправляемые данные.
 * len – длина данных.
 * Возвращает количество отправленных байт или -1 при ошибке.
 */
ssize_t shdScks_send(shdScks_context_t *ctx, int sockfd, const void *data, size_t len);

/* Приём данных из соединения.
 * ctx – контекст.
 * sockfd – файловый дескриптор соединения.
 * buf – буфер для приёма.
 * len – размер буфера.
 * Возвращает количество прочитанных байт или -1 при ошибке.
 */
ssize_t shdScks_recv(shdScks_context_t *ctx, int sockfd, void *buf, size_t len);

/* Закрытие соединения.
 * ctx – контекст.
 * sockfd – файловый дескриптор соединения.
 */
void shdScks_close(shdScks_context_t *ctx, int sockfd);

/* Очистка и освобождение контекста Shadowsocks.
 * ctx – контекст, который будет освобождён.
 */
void shdScks_cleanup(shdScks_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // SHDSCKS_H
