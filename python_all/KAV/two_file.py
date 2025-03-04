import pandas as pd
import argparse


def merge_csv_files(file1, file2, output_file):
    """
    Функция объединяет два CSV-файла, приводит все данные к нижнему регистру,
    удаляет дубликаты и сохраняет результат в новый CSV-файл.
    """
    # Читаем данные из CSV-файлов, указываем, что заголовков нет
    df1 = pd.read_csv(file1, header=None, names=["identifier"])
    df2 = pd.read_csv(file2, header=None, names=["identifier"])

    # Приводим все данные к нижнему регистру
    df1["identifier"] = df1["identifier"].str.lower()
    df2["identifier"] = df2["identifier"].str.lower()

    # Объединяем оба набора данных и удаляем дубликаты
    merged_df = pd.concat([df1, df2]).drop_duplicates().reset_index(drop=True)

    # Сохраняем результат в новый CSV-файл
    merged_df.to_csv(output_file, index=False, header=False)

    print(f"Файл успешно создан: {output_file}")


if __name__ == "__main__":
    # Создаём парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description="Объединяет два CSV-файла, приводя данные к нижнему регистру и удаляя дубликаты.")

    # Добавляем аргументы
    parser.add_argument("file1", type=str, help="Путь к первому CSV-файлу")
    parser.add_argument("file2", type=str, help="Путь ко второму CSV-файлу")
    parser.add_argument("output", type=str, help="Путь к выходному CSV-файлу")

    # Парсим аргументы
    args = parser.parse_args()

    # Запускаем функцию обработки
    merge_csv_files(args.file1, args.file2, args.output)
