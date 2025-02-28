#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>


typedef struct {
    char *protocol;
    char *server_ip;
    int server_port;
    char *login;
    char *password;
    char *country; 
    char *city;
    bool use_udp; 
} Config;

extern Config global_config;

bool parse_json_config(const char *filename, Config *config);
void free_config(Config *config);

#endif // CONFIG_H
