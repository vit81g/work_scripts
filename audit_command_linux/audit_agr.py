import subprocess
import os
import sys

def execute_commands(filename):
    """Считывает команды из файла, выполняет их и записывает результат в файл."""

    with open(filename, "r") as f:
        commands = f.readlines()

    output_filename = sys.argv[2]
    with open(output_filename, "w") as output_file:
        for command in commands:
            command = command.strip()  # Удаляем пробелы
            if command:  # Выполняем только непустые строки
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    output_file.write(f"Команда: {command}\nРезультат:\n{output.decode('utf-8')}\n\n")
                except subprocess.CalledProcessError as e:
                    output_file.write(f"Команда: {command}\nОшибка:\n{e.output.decode('utf-8')}\n\n")

    print(f"Результаты выполнения команд записаны в файл: {output_filename}")

# Пример использования
filename = sys.argv[1]  # Замените на имя вашего файла с командами
execute_commands(filename)
