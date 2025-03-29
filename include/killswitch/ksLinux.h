#ifndef KSLINUX_H
#define KSLINUX_H

#include <stdbool.h>

typedef struct {
    char* vpn_interface;
    bool enabled;
} KillSwitch;

KillSwitch* ks_init(const char* vpn_interface);
int ks_enable(KillSwitch* ks);
int ks_disable(KillSwitch* ks);
void ks_destroy(KillSwitch* ks);

#endif // KSLINUX_H