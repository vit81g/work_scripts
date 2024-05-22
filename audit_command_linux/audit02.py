import subprocess
import os
import getpass

# Словарь для хранения паролей
passwords = {
    "auditvw": None,
    "auditctl": None
}

def execute_commands(filename):
    """Считывает команды из файла, выполняет их и записывает результат в файл.
    Включает ввод паролей для перехода в другую учетную запись."""

    with open(filename, "r") as f:
        commands = f.readlines()

    output_filename = "command_output.txt"
    with open(output_filename, "w") as output_file:
        for command in commands:
            command = command.strip()
            if command:
                # Проверяем, является ли команда переходом в другую учетную запись
                if command.startswith("sudo su - ") or command.startswith("su - "):
                    username = command.split(" ")[2]  # Извлекаем имя пользователя

                    # Проверяем, есть ли пароль в словаре
                    if passwords[username] is None:
                        passwords[username] = getpass.getpass(f"Введите пароль для {username}: ")
                    command = command + " -p " + passwords[username]  # Добавляем пароль к команде

                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    output_file.write(f"Команда: {command}\nРезультат:\n{output.decode('utf-8')}\n\n")
                except subprocess.CalledProcessError as e:
                    output_file.write(f"Команда: {command}\nОшибка:\n{e.output.decode('utf-8')}\n\n")

    print(f"Результаты выполнения команд записаны в файл: {output_filename}")

# Пример использования
filename = "commands.txt"  # Замените на имя вашего файла с командами
execute_commands(filename)
