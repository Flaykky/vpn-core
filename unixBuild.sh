#!/bin/bash

# this is builder for unix os (mac and linux)

# Компилятор
CC=gcc

# Флаги компиляции
CFLAGS="-Wall -O2 -Iinclude"

# Библиотеки
LIBS="-lssl -lcrypto"

# Исполняемый файл
TARGET="VPNCore"

# Исходные файлы
SRCS=(
    common.c
    config.c
    connection.c
    encryption.c
    logging.c
    main.c
    tunnel.c
    utils.c
)

# Объектные файлы
OBJS=("${SRCS[@]/%/.o}")

# Сборка
build() {
    echo "Compiling..."
    for src in "${SRCS[@]}"; do
        $CC $CFLAGS -c "$src" -o "${src%.c}.o"
        if [ $? -ne 0 ]; then
            echo "Compilation failed for $src"
            exit 1
        fi
    done

    echo "Linking..."
    $CC "${OBJS[@]}" -o "$TARGET" $LIBS
    if [ $? -eq 0 ]; then
        echo "Build successful: ./$TARGET"
    else
        echo "Linking failed"
        exit 1
    fi
}

# Очистка
clean() {
    echo "Cleaning up..."
    rm -f *.o "$TARGET"
    echo "Cleanup complete."
}

# Главная функция
main() {
    case "$1" in
        clean)
            clean
            ;;
        *)
            build
            ;;
    esac
}

main "$@"