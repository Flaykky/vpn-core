#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Определение ssize_t для Windows
#ifdef _WIN32
typedef SSIZE_T ssize_t;

#pragma comment(lib, "wintun.lib")
#else
#endif

#include <sys/types.h>


static int tun_fd = -1;

#ifdef _WIN32
// Windows-specific code for creating a virtual network interface using Wintun
static HANDLE wintun_handle = NULL;

bool setup_tunnel(int socket_fd, const char *ip_address, const char *subnet_mask) {
    if (!WintunIsAvailable()) {
        log_error("Wintun is not available on this system");
        return false;
    }


    

    // Create a new adapter
    const char *adapter_name = "VPN-Tunnel";
    const char *ip_address = "192.168.77.2";
    const char *subnet_mask = "255.255.255.0";

#ifdef _WIN32
    wintun_handle = WintunCreateAdapter(adapter_name, ip_address, subnet_mask);
#else
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &addr.sin_addr); // Используем переданный IP
    ifr.ifr_addr = *(struct sockaddr *)&addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, subnet_mask, &addr.sin_addr); // Используем переданную маску
    ifr.ifr_netmask = *(struct sockaddr *)&addr;
#endif

    if (!wintun_handle) {
        log_error("Failed to create Wintun adapter");
        return false;
    }

    // Start a session with the adapter
    tun_fd = WintunStartSession(wintun_handle, 1500); // MTU = 1500
    if (tun_fd == INVALID_HANDLE_VALUE) {
        log_error("Failed to start Wintun session");
        WintunDeleteAdapter(wintun_handle);
        return false;
    }

    log_info("Tunnel setup successfully on Windows");
    return true;
}

void teardown_tunnel(void) {
    if (wintun_handle) {
        if (!WintunStopSession(tun_fd)) {
            log_error("Failed to stop Wintun session");
        }
        if (!WintunDeleteAdapter(wintun_handle)) {
            log_error("Failed to delete Wintun adapter");
        }
        log_info("Tunnel torn down successfully on Windows");
    }
}
#else
// Unix-specific code for creating a TUN/TAP interface
bool setup_tunnel(int socket_fd) {
    struct ifreq ifr;
    char tun_name[IFNAMSIZ] = "tun0";

    // Open /dev/net/tun
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        perror("Opening /dev/net/tun failed");
        return false;
    }

    // Configure TUN device
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device without packet information
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);

    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        close(tun_fd);
        return false;
    }

    // Configure IP address and netmask
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        close(tun_fd);
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.77.2", &addr.sin_addr); // Example IP address
    addr.sin_port = 0;

    ifr.ifr_addr = *(struct sockaddr *)&addr;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR) failed");
        close(sockfd);
        close(tun_fd);
        return false;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &addr.sin_addr); // Example netmask
    addr.sin_port = 0;

    ifr.ifr_netmask = *(struct sockaddr *)&addr;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK) failed");
        close(sockfd);
        close(tun_fd);
        return false;
    }

    // Bring the interface up
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS) failed");
        close(sockfd);
        close(tun_fd);
        return false;
    }

    close(sockfd);
    log_info("Tunnel setup successfully on Unix");
    return true;
}

void teardown_tunnel(void) {
    if (tun_fd >= 0) {
        close(tun_fd);
        log_info("Tunnel torn down successfully on Unix");
    }
}
#endif

// Чтение данных из туннеля
ssize_t read_from_tunnel(void *buffer, size_t length) {
    if (tun_fd < 0) {
        log_error("Invalid tunnel file descriptor");
        return -1;
    }
    ssize_t bytes_read = read(tun_fd, buffer, length);
    if (bytes_read < 0) {
        perror("read from tunnel failed");
        return -1;
    }
    return bytes_read;
}

ssize_t write_to_tunnel(const void *buffer, size_t length) {
    if (tun_fd < 0) {
        log_error("Invalid tunnel file descriptor");
        return -1;
    }
    ssize_t bytes_written = write(tun_fd, buffer, length);
    if (bytes_written < 0) {
        perror("write to tunnel failed");
        return -1;
    }
    return bytes_written;
}

// Запись данных в туннель
ssize_t write_to_tunnel(const void *buffer, size_t length) {
    if (tun_fd < 0) {
        log_error("Invalid tunnel file descriptor");
        return -1;
    }

    ssize_t bytes_written = write(tun_fd, buffer, length);
    if (bytes_written < 0) {
        perror("write to tunnel failed");
        return -1;
    }

    return bytes_written;
}
