#ifndef PROXY_H
#define PROXY_H


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int establish_https_proxy_tunnel(const char *proxy_ip, int proxy_port, const char *target_host, int target_port);

void add_proxy(const char *ip, int port);

int establish_connection_with_proxy(const char *proxy_ip, int proxy_port, const char *target_host, int target_port);

#endif 