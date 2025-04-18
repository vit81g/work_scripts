#!/usr/bin/env python3

import subprocess
import sys
import ipaddress


def validate_ip_subnet(subnet, mask):
    """Проверка валидности подсети и маски"""
    try:
        ipaddress.ip_network(f"{subnet}/{mask}", strict=False)
        return True
    except ValueError as e:
        print(f"Ошибка: Неверный формат подсети или маски - {e}")
        return False


def run_amass(requests_per_ip, subnet, mask):
    """Запуск amass с указанными параметрами"""
    try:
        # Проверяем валидность входных данных
        if not validate_ip_subnet(subnet, mask):
            return

        # Формируем CIDR нотацию
        target = f"{subnet}/{mask}"

        # Команда для amass
        amass_cmd = [
            "amass",
            "enum",
            "-active",
            "-ip",
            f"-max-dns-queries={requests_per_ip}",
            "-cidr",
            target
        ]

        print(f"Запускаю сканирование подсети {target} с лимитом {requests_per_ip} запросов на IP...")

        # Запускаем процесс
        process = subprocess.run(
            amass_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Выводим результаты
        if process.stdout:
            print("\nРезультаты сканирования:")
            print(process.stdout)

        if process.stderr:
            print("\nОшибки:")
            print(process.stderr)

    except FileNotFoundError:
        print("Ошибка: amass не установлен или не найден в системе")
        print("Установите amass с помощью: go install github.com/OWASP/Amass/v3/...@master")
    except Exception as e:
        print(f"Произошла ошибка: {e}")


def main():
    # Проверяем количество аргументов
    if len(sys.argv) != 4:
        print("Использование: python script.py <requests_per_ip> <subnet> <mask>")
        print("Пример: python script.py 5 192.168.1.0 24")
        sys.exit(1)

    # Получаем аргументы
    try:
        requests_per_ip = int(sys.argv[1])
        subnet = sys.argv[2]
        mask = int(sys.argv[3])

        # Проверяем разумность значений
        if requests_per_ip <= 0:
            print("Ошибка: Количество запросов должно быть положительным числом")
            sys.exit(1)
        if mask < 0 or mask > 32:
            print("Ошибка: Маска подсети должна быть от 0 до 32")
            sys.exit(1)

        # Запускаем сканирование
        run_amass(requests_per_ip, subnet, mask)

    except ValueError:
        print("Ошибка: Неверный формат аргументов")
        print("requests_per_ip должен быть числом")
        print("mask должен быть числом от 0 до 32")
        sys.exit(1)


if __name__ == "__main__":
    main()