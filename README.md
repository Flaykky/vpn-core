# Simple VPN Client in C

A minimal VPN-like client implementation for educational purposes.

## Features
- Connect to multiple servers/proxies from config file
- Basic TCP tunneling
- Cross-platform support (Windows/Linux)

## Build

### Requirements
- CMake 3.10+
- C compiler (GCC, Clang, MSVC)
- OpenSSL
- pthreads 
- getopt.h
### Instructions
```bash
mkdir build
cd build
cmake ..
cmake --build .


