#!/bin/bash

# Проверка зависимостей
if ! command -v gcc &> /dev/null; then
    echo "GCC не установлен. Устанавливаю..."
    sudo apt-get update
    sudo apt-get install -y build-essential
fi

# Установка библиотек
make deps-linux

# Сборка проекта
echo "building..."
make clean
make all

# Проверка успешности сборки
if [ $? -eq 0 ]; then
    echo "VPN Core собран успешно: ./vpnCore"
else
    echo "Сборка завершилась с ошибкой"
    exit 1
fi