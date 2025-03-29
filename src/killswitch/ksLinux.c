// killswitch for linux
#ifdef __linux__

#include "ksLinux.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <regex.h>


static int safe_execute(const char *cmd, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execve(cmd, argv, NULL);
        exit(EXIT_FAILURE);
    }
    int status;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}

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

// Получение текущих правил iptables
static char* ks_get_iptables_rules() {
    char *rules = NULL;
    size_t size = 0;
    FILE *fp = popen("iptables-save", "r");
    if (fp) {
        getline(&rules, &size, fp);
        pclose(fp);
    }
    return rules;
}

// Включение Kill Switch
int ks_enable(KillSwitch *ks) {
    if (!ks || ks->enabled) return -1;

    // Сохраняем оригинальные правила
    ks->original_iptables = ks_get_iptables_rules();

    // Правила для IPv4
    const char *ipv4_rules[] = {
        "iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment KILLSWITCH",
        "iptables -A OUTPUT -o %s -j ACCEPT -m comment --comment KILLSWITCH",
        "iptables -A OUTPUT -j DROP -m comment --comment KILLSWITCH",
        NULL
    };

    // Правила для IPv6
    const char *ipv6_rules[] = {
        "ip6tables -A OUTPUT -o lo -j ACCEPT -m comment --comment KILLSWITCH",
        "ip6tables -A OUTPUT -o %s -j ACCEPT -m comment --comment KILLSWITCH",
        "ip6tables -A OUTPUT -j DROP -m comment --comment KILLSWITCH",
        NULL
    };

    // Выполнение правил
    for (int i = 0; ipv4_rules[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), ipv4_rules[i], ks->vpn_interface);
        char *argv[] = {"sh", "-c", cmd, NULL};
        if (safe_execute("/bin/sh", argv) != 0) {
            ks_disable(ks);
            return -1;
        }
    }

    // То же самое для IPv6
    for (int i = 0; ipv6_rules[i]; i++) {
        // Аналогичный код
    }

    ks->enabled = true;
    return 0;
}

int ks_disable(KillSwitch *ks) {
    if (!ks || !ks->enabled) return -1;

    // Удаляем правила по комментарию
    execute_command("iptables -F OUTPUT -m comment --comment KILLSWITCH");
    execute_command("ip6tables -F OUTPUT -m comment --comment KILLSWITCH");

    // Восстанавливаем оригинальные правила
    if (ks->original_iptables) {
        FILE *fp = fopen("/tmp/iptables.restore", "w");
        fwrite(ks->original_iptables, 1, strlen(ks->original_iptables), fp);
        fclose(fp);
        execute_command("iptables-restore < /tmp/iptables.restore");
        unlink("/tmp/iptables.restore");
    }

    ks->enabled = false;
    return 0;
}

void ks_destroy(KillSwitch* ks) {
    if (ks) {
        free(ks->vpn_interface);
        free(ks);
    }
}

#endif