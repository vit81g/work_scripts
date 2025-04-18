import sys
import os
import re
from collections import Counter
import Evtx  # Импортируем библиотеку Evtx для работы с журналами событий Windows
from Evtx.Evtx import Evtx as EvtxFile  # Используем корректный импорт класса Evtx


def extract_sites_from_evtx(evtx_file):
    """
    Функция извлекает доменные имена из URL в файле журнала Windows (.evtx).
    Подсчитывает количество посещений каждого уникального сайта.
    """
    site_counter = Counter()  # Используем Counter для подсчета количества посещений сайтов
    pattern = re.compile(r'https?://(?:www\.)?([^/]+)')  # Регулярное выражение для поиска доменов

    try:
        with EvtxFile(evtx_file) as log:  # Открываем .evtx файл для чтения
            for record in log.records():  # Перебираем все записи в журнале
                text = record.xml()  # Получаем XML-представление записи
                matches = pattern.findall(text)  # Ищем домены в тексте
                for match in matches:
                    site_counter[match] += 1  # Увеличиваем счетчик для найденного домена
    except Exception as e:
        print(f"Ошибка при обработке файла {evtx_file}: {e}")  # Выводим сообщение об ошибке
        sys.exit(1)  # Завершаем выполнение скрипта при ошибке

    return site_counter  # Возвращаем словарь с подсчитанными доменами


def save_results(site_counter, output_file):
    """
    Функция сохраняет результаты анализа в текстовый файл.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:  # Открываем файл для записи
            for site, count in site_counter.most_common():  # Перебираем домены, сортируя по количеству
                f.write(f"{site}: {count}\n")  # Записываем данные в файл
    except Exception as e:
        print(f"Ошибка при записи в файл {output_file}: {e}")  # Выводим сообщение об ошибке
        sys.exit(1)  # Завершаем выполнение скрипта при ошибке


def main():
    """
    Главная функция: принимает аргумент командной строки, выполняет анализ журнала и сохраняет результаты.
    """
    if len(sys.argv) != 2:  # Проверяем, передан ли аргумент командной строки
        print("Usage: python3 script.py <evtx_file>")  # Выводим инструкцию по запуску
        sys.exit(1)  # Завершаем выполнение скрипта

    evtx_file = sys.argv[1]  # Получаем путь к файлу из аргументов командной строки
    if not os.path.isfile(evtx_file):  # Проверяем, существует ли указанный файл
        print("Error: File not found!")  # Выводим сообщение, если файл не найден
        sys.exit(1)  # Завершаем выполнение скрипта

    site_counter = extract_sites_from_evtx(evtx_file)  # Вызываем функцию для анализа файла
    output_file = f"{os.path.splitext(evtx_file)[0]}_sites.txt"  # Формируем имя выходного файла
    save_results(site_counter, output_file)  # Сохраняем результаты в файл
    print(f"Results saved to {output_file}")  # Выводим сообщение об успешном завершении


if __name__ == "__main__":
    main()  # Запускаем основную функцию, если скрипт запущен напрямую