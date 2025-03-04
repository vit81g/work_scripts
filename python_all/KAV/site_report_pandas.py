import os
import pandas as pd
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

def parse_evtx_to_dataframe(evtx_file_path):
    """
    Парсит .evtx файл и возвращает данные в виде DataFrame.
    """
    records = []

    # Открываем .evtx файл
    with Evtx(evtx_file_path) as evtx:
        for xml_record in evtx_file_xml_view(evtx):
            # Извлекаем данные из XML-записи
            record_data = {
                "EventRecordID": None,
                "TimeCreated": None,
                "EventID": None,
                "Level": None,
                "Channel": None,
                "Computer": None,
                "EventData": None
            }

            # Парсим XML для извлечения ключевых полей
            if "<EventRecordID>" in xml_record:
                record_data["EventRecordID"] = xml_record.split("<EventRecordID>")[1].split("</EventRecordID>")[0]
            if "<TimeCreated SystemTime=" in xml_record:
                record_data["TimeCreated"] = xml_record.split('<TimeCreated SystemTime="')[1].split('"')[0]
            if "<EventID" in xml_record:
                record_data["EventID"] = xml_record.split("<EventID>")[1].split("</EventID>")[0]
            if "<Level>" in xml_record:
                record_data["Level"] = xml_record.split("<Level>")[1].split("</Level>")[0]
            if "<Channel>" in xml_record:
                record_data["Channel"] = xml_record.split("<Channel>")[1].split("</Channel>")[0]
            if "<Computer>" in xml_record:
                record_data["Computer"] = xml_record.split("<Computer>")[1].split("</Computer>")[0]
            if "<EventData>" in xml_record:
                record_data["EventData"] = xml_record.split("<EventData>")[1].split("</EventData>")[0]

            records.append(record_data)

    # Создаем DataFrame из списка записей
    df = pd.DataFrame(records)
    return df


def main():
    # Путь к .evtx файлу
    evtx_file_path = ".\Kaspersky Event Log.evtx"

    # Проверяем существование файла
    if not os.path.exists(evtx_file_path):
        print(f"Файл {evtx_file_path} не найден.")
        return

    # Парсим .evtx файл
    df = parse_evtx_to_dataframe(evtx_file_path)

    # Выводим первые записи
    print(df.head())

    # Пример анализа: подсчет количества событий по EventID
    event_counts = df['EventID'].value_counts()
    print("Количество событий по EventID:")
    print(event_counts)

    # Сохраняем результаты в CSV
    output_csv = "parsed_logs.csv"
    df.to_csv(output_csv, index=False)
    print(f"Результаты сохранены в {output_csv}")


if __name__ == "__main__":
    main()