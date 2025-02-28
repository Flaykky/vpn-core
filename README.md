# Simple VPN Client in C

A minimal VPN-like client implementation for educational purposes.

## Features
- Basic TCP tunneling
- Connect with HTTPS proxies
- Cross-platform support (Windows/Linux)
- Basic UDP tunneling
- Shadowsocks protocol support
- PFS support
- WireGuard connection (comming soon)


## Requirements
- CMake 3.10+
- C compiler (GCC, Clang, MSVC)
- OpenSSL
- pthreads (for windows)
- getopt.h (for windows)



## Basic TCP tunneling
```bash
./vpnCore --server 192.168.1.100 --port 8080
```

## Instructions
```bash
mkdir build
cd build
cmake ..
cmake --build .
```
