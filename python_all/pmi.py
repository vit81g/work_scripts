import os
import sys

""" исходные данные """
os.system('touch result.txt')
# os.system('touch compare.txt')
# python3 pmi.py <file_with_data>
openFileWork = sys.argv[1]
#openFileWork = 'com_pmi02.txt'

""" Работа с файлами """
# открытие  файла на чтение. r - чтение.
file1 = open(openFileWork, "r")
# открытие  файла на запись. w - чтение.
result = open('result.txt', 'w')
# Построчное чтение данных из файлов
lines = file1.readlines()

#catalog_files =
# обработка цикла выполняющего команды из списка данных
for i in lines:
    cmd = "getfacl -p " + i
    n = os.popen(cmd, 'r')
    for m in n:
        # запись успешного выполнения команды в файл
        result.write(m)

# закрытие файла
result.close()











