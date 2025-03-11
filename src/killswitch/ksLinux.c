// killswitch for linux

#include "ksLinux.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <regex.h>

// Валидация имени интерфейса
static bool is_valid_interface(const char* interface) {
    regex_t regex;
    int reti;
    const char* pattern = "^[a-zA-Z0-9_]+$";
    
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) return false;
    
    reti = regexec(&regex, interface, 0, NULL, 0);
    regfree(&regex);
    
    return reti == 0;
}

// Выполнение shell команды с проверкой
static int execute_command(const char* cmd) {
    int status = system(cmd);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

KillSwitch* ks_init(const char* vpn_interface) {
    if (!vpn_interface || !is_valid_interface(vpn_interface)) {
        return NULL;
    }
    
    KillSwitch* ks = malloc(sizeof(KillSwitch));
    if (!ks) return NULL;
    
    ks->vpn_interface = strdup(vpn_interface);
    if (!ks->vpn_interface) {
        free(ks);
        return NULL;
    }
    
    ks->enabled = false;
    return ks;
}

int ks_enable(KillSwitch* ks) {
    if (!ks || ks->enabled) return -1;
    
    const char* fmt;
    int rc;
    char cmd[256];
    
    // Блокировать весь исходящий трафик кроме VPN и локального
    const char* rules[] = {
        "iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment KILLSWITCH",
        "iptables -A OUTPUT -o %s -j ACCEPT -m comment --comment KILLSWITCH",
        "iptables -A OUTPUT -j DROP -m comment --comment KILLSWITCH",
        NULL
    };
    
    for (int i = 0; rules[i]; i++) {
        snprintf(cmd, sizeof(cmd), rules[i], ks->vpn_interface);
        if ((rc = execute_command(cmd)) != 0) {
            // Откат при ошибке
            while (--i >= 0) {
                snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT %d", i+1);
                execute_command(cmd);
            }
            return rc;
        }
    }
    
    ks->enabled = true;
    return 0;
}

int ks_disable(KillSwitch* ks) {
    if (!ks || !ks->enabled) return -1;
    
    char cmd[256];
    int rc = 0;
    
    // Удаление всех правил по комментарию
    const char* flush_cmd = "iptables-save | grep -v KILLSWITCH | iptables-restore";
    if ((rc = execute_command(flush_cmd)) != 0) {
        // Fallback: поочередное удаление
        for (int i = 0; i < 3; i++) {
            snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT 1");
            if (execute_command(cmd) != 0) break;
        }
    }
    
    ks->enabled = false;
    return rc;
}

void ks_destroy(KillSwitch* ks) {
    if (ks) {
        free(ks->vpn_interface);
        free(ks);
    }
}
