import subprocess
import os

def get_password(username):
    """Запрашивает пароль для пользователя."""
    password = input(f"Введите пароль для {username}: ")
    return password

def execute_commands(commands_file, output_file, username, password):
    """
    Выполняет команды из файла и записывает результат в файл.
    """
    with open(commands_file, 'r') as f:
        commands = f.readlines()

    with open(output_file, 'w') as f:
        for command in commands:
            # Удаляем символ новой строки
            command = command.strip()
            # Заменяем "sudo su -" на "sudo su -l" для безопасного перехода
            command = command.replace("sudo su -", "sudo su -l")
            try:
                if command.startswith("sudo su -l"):
                    # Если команда для перехода в другую учетную запись
                    process = subprocess.run(
                        command.split(), 
                        capture_output=True, 
                        text=True,
                        input=password + '\n', # Передаем пароль
                        check=True,
                    )
                    f.write(f"\nКоманда: {command}\n")
                    f.write(f"Результат:\n{process.stdout}\n")
                else:
                    # Если команда не для перехода в другую учетную запись
                    process = subprocess.run(
                        command.split(), 
                        capture_output=True, 
                        text=True,
                        check=True,
                    )
                    f.write(f"\nКоманда: {command}\n")
                    f.write(f"Результат:\n{process.stdout}\n")
            except subprocess.CalledProcessError as e:
                f.write(f"\nКоманда: {command}\n")
                f.write(f"Ошибка:\n{e}\n")


if __name__ == "__main__":
    commands_file = 'commands.txt'  # Файл с командами
    output_file = 'output.txt'   # Файл для вывода результата
    
    # Получение паролей для пользователей
    auditctr_password = get_password('
