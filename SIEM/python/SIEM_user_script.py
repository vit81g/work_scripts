"""
Скрипт предназначен для обработки выгрузки из SIEM Ankey по событиям ОС Windows.
В итоговой файл будут записаны значения которые будут содержать логин и блок PowerShell скрипта.
Все три файла должны находиться в директории запуска скрипта
"""

from collections import Counter

# Вводная информация
print("Рабочий файл выгрузки должен иметь расширение csv")
print("Файл для вывода результатов должен быть создан\nи находиться в каталоге запуска скрипта")

"""
Ввод данных, названия файлов
"""
openFileWork = input("Введите файл выгрузки из МД: ")
openFileUser = input("Введите файл для записи результатов: ")

""" Работа с файлами """
# открытие  файла на чтение. r - чтение.
file1 = open(openFileWork, "r")
# открытие  файла на запись. w - запись.
file2 = open(openFileUser, "w")

# Построчное чтение данных из файлов
lines = file1.readlines()

list_all = []
dict_all = {}


def add_to_dict(dictionary, key, value):
    """
    Функция добавляет новую пару ключ-значение в словарь
    :param dictionary: исходный словарь
    :param key: ключ, который нужно добавить
    :param value: значение ключа
    :return: возвращает обновленный словарь
    """
    dictionary[key] = value
    return dictionary


def write_dict(dictionary, filename):
    """
    Функция записи словаря в файл, записывает ключ и значание, далее делает сброс на другую строку
    :param dictionary: исходный словарь
    :param filename: переменная со значением файла для записи
    :return: ничего, данные записываются в файл построчно
    """
    with open(filename, 'w') as file:
        for key, value in dictionary.items():
            file.write(f"{key}: {value}\n")


"""
Цикл обработки данных из файла
данные из рабочего файла csv и создает список пользователей по UserID и ScriptBlockText
Далее запускаем функцию write_dict
"""
# перебор данных в первом цикле - обработка рабочего файла
for line in lines:
    # создание списка из строки
    list1 = line.split('{')
    if len(list1) > 1:
        list_all.append(list1[2].split(',')[13])  # ""EventId""
        list_all.append(list1[3].split(',')[2])  # ""EventData""
        dict_all.update({list1[2].split(',')[13]: list1[3].split(',')[2]})

    else:
        continue


write_dict(dict_all, openFileUser)

""" Закрытие файлов """
file1.close()
file2.close()

# Сообщение о завершении работы
print("\n")
print("****************************************")
print("Обработка данных произведена")
print("****************************************")

