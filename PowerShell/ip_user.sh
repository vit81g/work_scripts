#!/bin/bash

# Проверка наличия аргумента IP адреса
if [ $# -ne 1 ]; then
   echo "Usage: $0 <IP>"
   exit 1

fi

# IP адрес для проверки
target_ip=$1

# Выполнение команды who через SSH и получение активных сеансов
active_session=$(ssh adm-novivits@$target_ip who)

# Вывод активных сеансов
echo "Active session on $target_ip:"
echo "$active_session"
echo

# Выполнение finger для получения информации о пользователях
finger_output=$(ssh adm-novivits@$target_ip id)

# Вывод дополнительной информации о пользователях
echo "Additional information about users on $target_ip:"
echo "$finger_output"

# Сбор информации о последних активных пользователях на хосте (сервере)
last_users=$(ssh adm-novivits@$target_ip last)

# Вывод информации о последних активных пользователях
echo "Last users $target_ip:"
echo "$last_users"
