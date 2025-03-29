#ifndef CMDINTERFACE_H
#define CMDINTERFACE_H

static void print_help();

static void *monitor_thread(void *arg);

void process_data(int socket_fd, Tunnel *tunnel);

bool read_config_file(const char *filename, Config *config);

int cmdInterface(int argc, char *argv[]);

#endif 