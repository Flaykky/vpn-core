#include "common.h"
#include "connection.h"
#include "encryption.h"
#include "tunnel.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "kswin.h"
#include "kslinux.h"
#include "uot.h"
#include "dpiBypass.h"
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <basetsd.h>
#include <getopt.h>
#include "connection.h"
#include "config.h"
#include <pthread.h>
#include <unistd.h>
#include "wgLinux.h"
#include "wgWin.h"
#include "tcp.h"
#include "proxy.h"
#include "udp.h"
#include "shdScks.h"
#include "openvpn.h"
#include "dnsBlocks.h"
#include "dnsResolver.h"
#include "pfs.h"
#include "cmdinterface.h"
#include "main.h"
#ifdef _WIN32
#include <windows.h>
#else
#endif

int main() {
    int exitStatus = cmdinterface();
    return exitStatus;
}
