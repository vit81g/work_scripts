import subprocess
import os

def get_password(username):
    """Запрашивает пароль для пользователя."""
    password = input(f"Введите пароль для {username}: ")
    return password

def execute_commands(commands_file, output_file, usernames_and_passwords):
    """
    Выполняет команды из файла и записывает результат в файл.
    """
    with open(commands_file, 'r') as f:
        commands = f.readlines()

    with open(output_file, 'w') as f:
        current_user = None
        for command in commands:
            # Удаляем символ новой строки
            command = command.strip()
            
            # Проверяем, требуется ли переход в другую учетную запись
            if command.startswith("sudo su -l"):
                # Извлекаем имя пользователя из команды
                target_user = command.split()[2]
                if target_user in usernames_and_passwords:
                    # Переход в другую учетную запись
                    current_user = target_user
                    password = usernames_and_passwords[target_user]
                    try:
                        process = subprocess.run(
                            command.split(), 
                            capture_output=True, 
                            text=True,
                            input=password + '\n', # Передаем пароль
                            check=True,
                        )
                        f.write(f"\nКоманда: {command}\n")
                        f.write(f"Результат:\n{process.stdout}\n")
                    except subprocess.CalledProcessError as e:
                        f.write(f"\nКоманда: {command}\n")
                        f.write(f"Ошибка: Команда завершилась с кодом {e.returncode}\n")
                        f.write(f"Вывод ошибки:\n{e.stderr}\n")
                else:
                    f.write(f"\nКоманда: {command}\n")
                    f.write(f"Ошибка: Неизвестный пользователь: {target_user}\n")
            else:
                # Выполнение команды для текущего пользователя
                if current_user:
                    # Если текущий пользователь установлен
                    try:
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
                        f.write(f"Ошибка: Команда завершилась с кодом {e.returncode}\n")
                        f.write(f"Вывод ошибки:\n{e.stderr}\n")
                else:
                    # Если текущий пользователь не установлен (выполняется команда от root)
                    try:
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
                        f.write(f"Ошибка: Команда завершилась с кодом {e.returncode}\n")
                        f.write(f"Вывод ошибки:\n{e.stderr}\n")


if __name__ == "__main__":
    commands_file = 'commands.txt'  # Файл с командами
    output_file = 'output.txt'   # Файл для вывода результата
    
    # Получение паролей для пользователей
    auditctr_password = get_password('auditctr')
    usersec_password = get_password('usersec')
    usermngt_password = get_password('usermngt')
    userctr_password = get_password('userctr')
    useracc_password = get_password('useracc')
    
    usernames_and_passwords = {
        'auditctr': auditctr_password,
        'usersec': usersec_password,
        'usermngt': usermngt_password,
        'userctr': userctr_password,
        'useracc': useracc_password,
    }
    
    execute_commands(commands_file, output_file, usernames_and_passwords)
    print(f"Результаты выполнения команд записаны в файл: {output_file}")
