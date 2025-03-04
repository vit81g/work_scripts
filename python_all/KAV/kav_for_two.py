import pandas as pd
import re
import argparse


def normalize_hostname(hostname):
    """
    Нормализует имя хоста: приводит к нижнему регистру и убирает доменную часть.
    :param hostname: строка с именем хоста (например, "HOST1.domain.local")
    :return: нормализованное имя хоста (например, "host1")
    """
    hostname = str(hostname).strip().lower()
    match = re.match(r'^[^\.\s]+', hostname)
    return match.group(0) if match else hostname


def process_kav_pk_excel(kav_pk_file):
    """
    Читает и нормализует данные из Excel-файла kav_pk.xlsx.
    :param kav_pk_file: путь к файлу kav_pk.xlsx
    :return: список нормализованных имен хостов
    """
    try:
        df = pd.read_excel(kav_pk_file)
        possible_columns = ['Host Name', 'Имя хоста', 'Hostname']
        host_column = None

        for col in possible_columns:
            if col in df.columns:
                host_column = col
                break

        if not host_column:
            raise ValueError("Не найден столбец с именами хостов в kav_pk.xlsx")

        hosts = [normalize_hostname(host) for host in df[host_column].dropna()]

        print(f"Обработано {len(hosts)} уникальных хостов из {kav_pk_file}")
        return hosts

    except FileNotFoundError:
        print(f"Ошибка: Файл {kav_pk_file} не найден")
        raise
    except Exception as e:
        print(f"Ошибка при обработке {kav_pk_file}: {str(e)}")
        raise


def find_missing_hosts(result_file, kav_pk_file, output_file):
    """
    Сравнивает хосты из result.txt с нормализованными хостами из kav_pk.xlsx,
    записывает отсутствующие в output_file.
    :param result_file: путь к файлу result.txt
    :param kav_pk_file: путь к файлу kav_pk.xlsx
    :param output_file: путь к выходному файлу missing_hosts.txt
    """
    kav_pk_hosts = process_kav_pk_excel(kav_pk_file)
    total_hosts = 0
    missing_hosts = []

    try:
        with open(result_file, 'r', encoding='utf-8') as result_f:
            for line in result_f:
                host = normalize_hostname(line)
                if not host:
                    continue

                total_hosts += 1
                if host not in kav_pk_hosts:
                    missing_hosts.append(host)

        with open(output_file, 'w', encoding='utf-8') as output_f:
            for host in sorted(missing_hosts):
                output_f.write(f"{host}\n")

        print(f"Обработано {total_hosts} хостов из {result_file}")
        print(f"Найдено {len(missing_hosts)} отсутствующих хостов")
        print(f"Результат сохранен в {output_file}")

        if missing_hosts:
            print("\nПервые 5 отсутствующих хостов:")
            for host in sorted(missing_hosts)[:5]:
                print(host)

    except FileNotFoundError:
        print(f"Ошибка: Файл {result_file} не найден")
    except Exception as e:
        print(f"Ошибка при обработке: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Сравнивает хосты из result.txt с kav_pk.xlsx и сохраняет отсутствующие в missing_hosts.txt")

    parser.add_argument("result_file", type=str, help="Путь к файлу result.txt")
    parser.add_argument("kav_pk_file", type=str, help="Путь к файлу kav_pk.xlsx")
    parser.add_argument("output_file", type=str, help="Путь к выходному файлу missing_hosts.txt")

    args = parser.parse_args()
    find_missing_hosts(args.result_file, args.kav_pk_file, args.output_file)