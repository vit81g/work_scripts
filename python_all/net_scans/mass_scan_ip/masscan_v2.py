import subprocess
import sys
import os


def run_masscan(rate, subnet, mask, ports):
    """
    Запускает masscan с заданными параметрами

    Args:
        rate (str): Количество запросов в секунду на IP
        subnet (str): Подсеть для сканирования (например, 185.97.164.0)
        mask (str): Маска подсети (например, 24)
        ports (str): Диапазон портов (например, 1-20 или пустой для всех)
    """
    try:
        # Проверяем доступность masscan
        check_cmd = ['masscan', '--version']
        try:
            version_check = subprocess.run(check_cmd, capture_output=True, text=True)
            if version_check.returncode == 0:
                print(f"Masscan версия: {version_check.stdout.strip()}")
            else:
                print(f"Предупреждение: не удалось проверить версию masscan: {version_check.stderr}")
        except FileNotFoundError:
            raise FileNotFoundError("masscan не найден в системе")

        # Формируем диапазон портов
        port_arg = '-p1-65535' if ports == '' else f'-p{ports}'

        # Формируем команду masscan
        masscan_cmd = [
            'masscan',
            f'{subnet}/{mask}',
            '--rate', rate,
            port_arg,
            '-oL', 'scan_results.txt'
        ]

        print(f"Запускаю сканирование с параметрами:")
        print(f"Подсеть: {subnet}/{mask}")
        print(f"Скорость: {rate} запросов/сек")
        print(f"Диапазон портов: {ports if ports else 'все порты (1-65535)'}")
        print(f"Полная команда: {' '.join(masscan_cmd)}")

        # Запускаем massscan
        result = subprocess.run(masscan_cmd, capture_output=True, text=True)

        # Подготовка отчета
        report_file = 'report_massscan.txt'
        with open(report_file, 'w') as report:
            report.write(f"Masscan отчет\n")
            report.write(f"Дата: {os.popen('date').read().strip()}\n")
            report.write(f"Подсеть: {subnet}/{mask}\n")
            report.write(f"Скорость сканирования: {rate} запросов/сек\n")
            report.write(f"Диапазон портов: {ports if ports else '1-65535'}\n")
            report.write("\n")

            if result.returncode == 0:
                report.write("Сканирование завершено успешно!\n")
                print("Сканирование завершено успешно!")
                print("Результаты сохранены в scan_results.txt и report_massscan.txt")

                if os.path.exists('scan_results.txt'):
                    with open('scan_results.txt', 'r') as f:
                        results = f.read()
                        report.write("Найденные открытые порты:\n")
                        report.write(results)
                        print("\nНайденные открытые порты:")
                        print(results)
            else:
                error_msg = f"Ошибка при сканировании: {result.stderr}\n"
                report.write(error_msg)
                print(error_msg)

    except FileNotFoundError:
        error_msg = "Ошибка: masscan не установлен. Установите его с помощью:\n" \
                    "sudo apt-get install masscan  # для Ubuntu/Debian\n" \
                    "sudo yum install masscan     # для CentOS/RHEL\n"
        print(error_msg)
        with open('report_massscan.txt', 'w') as report:
            report.write(error_msg)
    except Exception as e:
        error_msg = f"Произошла ошибка: {e}\n"
        print(error_msg)
        with open('report_massscan.txt', 'w') as report:
            report.write(error_msg)


def validate_args(args):
    """
    Проверяет корректность аргументов командной строки
    """
    if len(args) != 5:
        print("Использование: python script.py <rate> <subnet> <mask> <ports>")
        print("Пример: python script.py 10 185.97.164.0 24 1-20")
        print("Для всех портов: python script.py 10 185.97.164.0 24 -p-")
        return False

    rate, subnet, mask, ports = args[1], args[2], args[3], args[4]

    if not rate.isdigit() or int(rate) <= 0:
        print("Ошибка: rate должен быть положительным числом")
        return False

    if not all(part.isdigit() for part in subnet.split('.')) or len(subnet.split('.')) != 4:
        print("Ошибка: неверный формат подсети")
        return False

    if not mask.isdigit() or int(mask) < 0 or int(mask) > 32:
        print("Ошибка: маска должна быть числом от 0 до 32")
        return False

    if ports != '-p-':
        try:
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    print("Ошибка: порты должны быть в диапазоне 1-65535")
                    return False
            else:
                port = int(ports)
                if not (1 <= port <= 65535):
                    print("Ошибка: порт должен быть в диапазоне 1-65535")
                    return False
        except ValueError:
            print("Ошибка: неверный формат диапазона портов")
            return False

    return True


if __name__ == "__main__":
    if validate_args(sys.argv):
        rate = sys.argv[1]
        subnet = sys.argv[2]
        mask = sys.argv[3]
        ports = sys.argv[4]
        ports = '' if ports == '-p-' else ports
        run_masscan(rate, subnet, mask, ports)
    else:
        sys.exit(1)