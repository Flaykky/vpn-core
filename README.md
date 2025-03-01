# Simple VPN Client in C

A minimal VPN-like client implementation for educational purposes.

## Features
- Basic TCP tunneling
- Connect with HTTPS proxies
- Cross-platform support (Windows/Linux)
- Basic UDP tunneling
- Shadowsocks protocol support
- PFS support
- WireGuard protocol support


## Requirements
- CMake 3.10+
- C compiler (GCC, Clang, MSVC)
- OpenSSL
- pthreads (for windows)
- getopt.h (for windows)
- WireGuard-nt


## Basic TCP tunneling
```bash
./vpnCore WireGuard 1.1.1.1:51820 login:pass -uot
```
output:
╭──────────────────────────────────────────────╮
│ VPN Connection Status: Connected [✓]         │
│                                               │
│ Location: Switzerland, Zurich                 │
│ Protocol: WireGuard                           │
│                                               │
│ server: 1.1.1.1:51820 (UDP)                   │
│ udp-over-tcp obfuscation  [✓]                │
╰──────────────────────────────────────────────╯


## Instructions
```bash
mkdir build
cd build
cmake ..
cmake --build .
```
