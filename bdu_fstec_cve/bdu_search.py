# export.xml
"""
Скрипт предназначен для обработки выгрузки БДУ ФСТЭК,
в формате xml. Необходимо ввести ID БДУ.
Файл export.xml должен находиться в директории запуска скрипта
"""

# импорт модуля для работы с xml
import xml.etree.ElementTree as ET
import sys

os_name = ''
ver_id = ''

# Вводная информация
print("\nРабочий файл выгрузки должен иметь расширение xml")
# ввод данных
bdu_id = input("\nВведите ID БДУ: ")
base_xml = sys.argv[1]

# указываем с каким файлом будем работать  (export.xml)
tree = ET.parse(base_xml)
# создание иерархии
root = tree.getroot()

# перебор иерархии
for elem in root:
    # поиск атрибута identifier
    for subelem in elem.findall('identifier'):
        # условие по заданному аргументу
        if subelem.text == str(bdu_id):
            for subelem in elem.findall('identifier'):
                # выводим найденное значение
                print(subelem.text)
            # в найденном значении ищем дополнительные значения аргументов
            # нужная нам информация храниться в vulnerable_software
            for subelem in elem.findall('vulnerable_software'):
                # перебор с поиском названия и версии ПО
                for soft in subelem.findall('soft'):
                    for os_name in soft.findall('name'):
                        pass
                    for ver_id in soft.findall('version'):
                        pass
                    # вывод информации
                    print(os_name.text, ' - ', ver_id.text)
print("\n")
print("****************************************")
print("Обработка данных произведена")
print("****************************************")