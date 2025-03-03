#ifndef KILLSWITCH_H
#define KILLSWITCH_H

#include <stdbool.h>
#include <basetsd.h>



#ifdef _WIN32

#ifndef FWPM_LAYER_ALE_AUTH_CONNECT_V4
#define FWPM_LAYER_ALE_AUTH_CONNECT_V4 {0x59b4a28f, 0x7b5a, 0x4a5e, {0xb8, 0x4e, 0x9d, 0x7c, 0x7c, 0x8b, 0x0f, 0x4d}}
#endif

#ifndef FWPM_LAYER_OUTBOUND_TRANSPORT_V4
#define FWPM_LAYER_OUTBOUND_TRANSPORT_V4 {0x59b4a28f, 0x7b5a, 0x4a5e, {0xb8, 0x4e, 0x9d, 0x7c, 0x7c, 0x8b, 0x0f, 0x4d}}
#endif

#endif


typedef struct {
    HANDLE engine_handle;
    UINT64 filter_id; // Ключ правила
} KillSwitchContext;

// Функция для включения Kill Switch
bool enable_kill_switch(void);

// Функция для отключения Kill Switch
bool disable_kill_switch(void);

#endif // KILLSWITCH_H
