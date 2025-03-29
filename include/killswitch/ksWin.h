#ifndef KSWIN_H
#define KSWIN_H

#include <windows.h>
#include <fwpmu.h>
#include <stdbool.h>

typedef struct {
    HANDLE engine_handle;
    UINT64 filter_id;
    wchar_t *interface_alias; // Имя интерфейса WireGuard
    bool is_enabled;
} KillSwitchWin;

// Инициализация Kill Switch
bool ks_win_init(KillSwitchWin *ks, const wchar_t *interface_alias);

// Включение блокировки
bool ks_win_enable(KillSwitchWin *ks);

// Отключение блокировки
bool ks_win_disable(KillSwitchWin *ks);

// Очистка ресурсов
void ks_win_cleanup(KillSwitchWin *ks);

#endif // KSWIN_H