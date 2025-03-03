#include "killswitch.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#ifdef _WIN32

#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h> // Include this header for FWPM_LAYER_ALE_AUTH_CONNECT_V4
#include <objbase.h> // Для CoCreateGuid
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ole32.lib") // Для CoCreateGuid
#else
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif

static bool kill_switch_enabled = false;

#ifdef _WIN32
static HANDLE g_engine_handle = NULL;
static HANDLE engine_handle = NULL;
static GUID filter_key; // Храним ключ фильтра
static KillSwitchContext killswitch_ctx = {0};
static pthread_mutex_t killswitch_mutex = PTHREAD_MUTEX_INITIALIZER;

bool enable_kill_switch(void) {
    pthread_mutex_lock(&killswitch_mutex);

    if (killswitch_ctx.engine_handle) {
        log_warning("Kill switch already enabled");
        pthread_mutex_unlock(&killswitch_mutex);
        return true;
    }

    // Открываем движок WFP
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &killswitch_ctx.engine_handle);
    if (result != ERROR_SUCCESS) {
        log_error("FwpmEngineOpen0 failed: %lu", result);
        pthread_mutex_unlock(&killswitch_mutex);
        return false;
    }

    // Создаем правило для блокировки исходящего трафика
    FWPM_FILTER0 filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_EMPTY; // Приоритет правила

    // Добавляем правило
    result = FwpmFilterAdd0(killswitch_ctx.engine_handle, &filter, NULL, &killswitch_ctx.filter_id);
    if (result != ERROR_SUCCESS) {
        log_error("FwpmFilterAdd0 failed: %lu", result);
        FwpmEngineClose0(killswitch_ctx.engine_handle);
        pthread_mutex_unlock(&killswitch_mutex);
        return false;
    }

    log_info("Kill switch enabled via WFP");
    pthread_mutex_unlock(&killswitch_mutex);
    return true;
}

void disable_kill_switch(void) {
    pthread_mutex_lock(&killswitch_mutex);

    if (!killswitch_ctx.engine_handle) {
        log_warning("Kill switch not enabled");
        pthread_mutex_unlock(&killswitch_mutex);
        return;
    }

    // Удаляем правило по сохраненному ID
    if (FwpmFilterDeleteById0(killswitch_ctx.engine_handle, killswitch_ctx.filter_id) != ERROR_SUCCESS) {
        log_error("Failed to delete WFP filter");
    }

    // Закрываем движок WFP
    FwpmEngineClose0(killswitch_ctx.engine_handle);
    memset(&killswitch_ctx, 0, sizeof(KillSwitchContext));

    log_info("Kill switch disabled");
    pthread_mutex_unlock(&killswitch_mutex);
}
#else
// Для Linux: Используем iptables/ip6tables с безопасными вызовами

// Функция для выполнения команд через fork/exec (безопаснее system())
static bool exec_iptables(const char *table, const char *chain, const char *rule) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp(table, table, "-A", chain, rule, NULL);
        exit(EXIT_FAILURE);
    } else {
        waitpid(pid, NULL, 0);
        return WIFEXITED(pid) && WEXITSTATUS(pid) == 0;
    }
}

bool enable_kill_switch() {
    if (kill_switch_enabled) return true;

    // Сохраняем оригинальные правила
    system("iptables-save > /tmp/original_iptables.rules");
    system("ip6tables-save > /tmp/original_ip6tables.rules");

    // Блокируем весь трафик кроме туннеля
    const char *interface = get_primary_interface(); // Функция для определения основного интерфейса
    if (!interface) return false;

    bool success = true;
    success &= exec_iptables("iptables", "OUTPUT", "-o ! tun0 -j DROP");
    success &= exec_iptables("iptables", "INPUT", "-i ! tun0 -j DROP");
    success &= exec_iptables("ip6tables", "OUTPUT", "-o ! tun0 -j DROP");
    success &= exec_iptables("ip6tables", "INPUT", "-i ! tun0 -j DROP");

    if (!success) {
        log_error("Failed to set iptables rules");
        return false;
    }

    kill_switch_enabled = true;
    log_info("Kill Switch enabled with iptables/ip6tables");
    return true;
}

bool disable_kill_switch() {
    if (!kill_switch_enabled) return true;

    // Восстанавливаем оригинальные правила
    system("iptables-restore < /tmp/original_iptables.rules");
    system("ip6tables-restore < /tmp/original_ip6tables.rules");

    unlink("/tmp/original_iptables.rules");
    unlink("/tmp/original_ip6tables.rules");

    kill_switch_enabled = false;
    log_info("Kill Switch disabled");
    return true;
}

// Функция для определения основного сетевого интерфейса
static const char* get_primary_interface() {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return NULL;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            return strdup(ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
}
#endif
