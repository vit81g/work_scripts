import pandas as pd
import os
import sys
import re

def extract_hostnames(df):
    """Функция для нормализации и извлечения только имен хостов"""
    possible_columns = ['Имя хоста', 'Host Name', 'Hostname']  # Возможные названия колонок

    for col in possible_columns:
        if col in df.columns:
            # Удаляем доменную часть и IP, оставляя только имя хоста
            return df[col].dropna().astype(str).str.strip().apply(
                lambda x: re.match(r'^[^\.\s]+', x).group(0) if re.match(r'^[^\.\s]+', x) else x)

    raise ValueError("Не найдена колонка с именами хостов")

def normalize_file(input_file):
    # Загружаем данные
    df = pd.read_excel(input_file)

    hosts = extract_hostnames(df)

    # Генерируем имя выходного файла
    output_file = os.path.splitext(input_file)[0] + ".csv"

    # Сохраняем результат
    hosts.to_csv(output_file, index=False, header=False)
    print(f"Файл {output_file} сохранен. Количество уникальных хостов: {len(hosts)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python script.py <файл.xlsx>")
        sys.exit(1)

    input_file = sys.argv[1]
    normalize_file(input_file)