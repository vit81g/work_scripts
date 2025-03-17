import pandas as pd
import os
import sys


def process_exchange_logs(input_file):
    # Определяем разделитель по расширению файла
    sep = ',' if input_file.lower().endswith('.txt') or input_file.lower().endswith('.log') else ';'

    try:
        # Загружаем CSV или текстовый файл с обработкой ошибок
        df = pd.read_csv(input_file, encoding='utf-8', sep=sep, skiprows=4, on_bad_lines='skip')
    except Exception as e:
        print(f"Ошибка при обработке файла {input_file}: {e}")
        return None, None

    # Проверяем количество колонок
    expected_columns = 9
    if df.shape[1] != expected_columns:
        print(
            f"Файл {input_file} имеет некорректное количество колонок ({df.shape[1]} вместо {expected_columns}). Пропускаем.")
        return None, None

    # Переименуем колонки для удобства
    df.columns = [
        "date-time", "connector-id", "session-id", "sequence-number",
        "local-endpoint", "remote-endpoint", "event", "data", "context"
    ]

    # Фильтрация строк с "Default Frontend" в "connector-id" и "X-ANONYMOUSTLS" в "data"
    filtered_df = df[
        df["connector-id"].str.contains("Default Frontend", na=False) &
        df["data"].str.contains("X-ANONYMOUSTLS", na=False)
        ]

    # Удаление портов из IP-адресов
    df["remote-endpoint"] = df["remote-endpoint"].str.split(":").str[0]

    # Удаление дубликатов без использования множеств
    df_unique_ips = df.drop_duplicates(subset=["remote-endpoint"], keep="first")

    return filtered_df, df_unique_ips[["remote-endpoint"]]


def process_directory(directory):
    if not os.path.isdir(directory):
        print(f"Указанная папка не существует: {directory}")
        sys.exit(1)

    files = os.listdir(directory)
    print(f"Файлы в папке {directory}: {files}")

    valid_files = [f for f in files if f.lower().endswith(('.csv', '.txt', '.log'))]
    print(f"Найденные файлы для обработки: {valid_files}")

    if not valid_files:
        print("В папке нет подходящих файлов.")
        sys.exit(1)

    all_filtered_data = []
    all_unique_ips = pd.DataFrame(columns=["remote-endpoint"])

    for file in valid_files:
        input_file = os.path.join(directory, file)
        print(f"Обрабатываем файл: {file}")

        filtered_df, unique_ips_df = process_exchange_logs(input_file)

        if filtered_df is not None:
            all_filtered_data.append(filtered_df)

        if unique_ips_df is not None:
            all_unique_ips = pd.concat([all_unique_ips, unique_ips_df])

    # Сохранение всех отфильтрованных данных
    filtered_output = os.path.join(directory, "filtered_all_logs.csv")
    pd.concat(all_filtered_data).to_csv(filtered_output, index=False, encoding="utf-8")
    print(f"Файл со всеми отфильтрованными строками сохранён: {filtered_output}")

    # Удаление дубликатов IP среди всех обработанных файлов
    unique_ips_output = os.path.join(directory, "unique_ips_all_logs.csv")
    all_unique_ips.drop_duplicates(subset=["remote-endpoint"], keep="first").to_csv(unique_ips_output, index=False,
                                                                                    encoding="utf-8")
    print(f"Файл со всеми уникальными IP сохранён: {unique_ips_output}")

    # Вывод только IP-адресов в консоль
    print("\nСписок уникальных IP-адресов:")
    print(all_unique_ips["remote-endpoint"].drop_duplicates().to_string(index=False))


if __name__ == "__main__":
    directory = input("Введите путь к папке с файлами: ").strip()
    process_directory(directory)
