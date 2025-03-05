# Simple VPN Client in C

A minimal VPN-like client implementation for educational purposes.

## Features
- Basic TCP&UDP tunneling
- Connect with HTTPS proxies
- Cross-platform support (Windows/Linux)
- udp-over-tcp obfuscation
- Shadowsocks protocol support
- PFS support
- WireGuard protocol support
- smart defence against DPI (comming soon)

## Requirements
- CMake 3.10+
- C compiler (GCC, Clang, MSVC)
- OpenSSL
- pthreads (for windows)
- getopt.h (for windows)
- WireGuard-nt
- cJSON

## Basic WireGuard tunneling
```bash
./vpnCore WireGuard 1.1.1.1:51820 login:pass -uot
```



## Instructions
```bash
mkdir build
cd build
cmake ..
cmake --build .
```
