#include "include/utils/common.h"
#include "include/connection/connection.h"
#include "include/encryption/encryption.h"
#include "include/tunnel/tunnel.h"
#include "include/utils/config.h"
#include "include/utils/logging.h"
#include "include/utils/utils.h"
#include "include/killswitch/ksLinux.h"
#include "include/killswitch/kslinux.h"
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <basetsd.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include "include/connection/protocols/wireguard/wgLinux.h"
#include "include/connection/protocols/wireguard/wgWin.h"
#include "include/connection/protocols/tcp.h"
#include "include/connection/protocols/proxy.h"
#include "include/connection/protocols/udp.h"
#include "include/connection/protocols/shdScks.h"
#include "include/connection/protocols/openvpn.h"
#include "include/DNS/dnsBlocks.h"
#include "include/DNS/dnsResolver.h"
#include "include/encryption/pfs.h"
#include "include/interface/cmdinterface.h"
#include "include/main.h"
#include "libs/openssl/include/openssl/rand.h"
#include "libs/openssl/include/openssl/evp.h"
#include "libs/openssl/include/openssl/types.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef _WIN32
#include <windows.h>
#else
#endif

int main() {
    int exitStatus = cmdinterface();
    return exitStatus;
}



