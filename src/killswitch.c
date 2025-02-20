#include "killswitch.h"
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <fwpmu.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

static bool kill_switch_enabled = false;

// Включение Kill Switch
bool enable_kill_switch(void) {
    if (kill_switch_enabled) {
        log_warning("Kill switch is already enabled");
        return true;
    }

#ifdef _WIN32
    // Настройка Windows Firewall через netsh
    system("netsh advfirewall firewall add rule name=\"VPN Kill Switch\" dir=out action=block");
#else
    // Настройка iptables на Linux
    system("iptables -A OUTPUT -o eth0 -j DROP"); // Блокируем исходящий трафик
    system("iptables -A INPUT -i eth0 -j DROP");  // Блокируем входящий трафик
#endif

    kill_switch_enabled = true;
    log_info("Kill switch enabled");
    return true;
}

// Отключение Kill Switch
bool disable_kill_switch(void) {
    if (!kill_switch_enabled) {
        log_warning("Kill switch is already disabled");
        return true;
    }

#ifdef _WIN32
    system("netsh advfirewall firewall delete rule name=\"VPN Kill Switch\"");
#else
    system("iptables -D OUTPUT -o eth0 -j DROP");
    system("iptables -D INPUT -i eth0 -j DROP");
#endif

    kill_switch_enabled = false;
    log_info("Kill switch disabled");
    return true;
}