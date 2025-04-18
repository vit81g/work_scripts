import csv
import os
import subprocess
import socket
import requests

# Файл для сохранения результатов
CSV_FILE = "scan_results.csv"

# 🔹 Функция: запись в CSV
def write_to_csv(data):
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(data)

# 🔹 Функция: проверка порта через netcat
def check_netcat(ip, port):
    try:
        result = subprocess.run(["nc", "-zv", ip, str(port)], capture_output=True, text=True, timeout=3)
        return "Netcat: Open" if "succeeded" in result.stderr else "Netcat: Closed"
    except:
        return "Netcat: Error"

# 🔹 Функция: проверка HTTP(S) через requests
def check_http(ip, port):
    try:
        url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
        response = requests.get(url, timeout=3)
        return f"HTTP {response.status_code}" if response.status_code < 400 else f"HTTP Error {response.status_code}"
    except:
        return "HTTP: No Response"

# 🔹 Функция: проверка соединения через socket
def check_socket(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=3):
            return "Socket: Open"
    except:
        return "Socket: Closed"

# 🔹 Получаем диапазон IP и портов от пользователя
ip_range = input("Введите диапазон IP (например, 10.8.10.0/24): ").strip()
port_range = input("Введите диапазон портов (например, 20-1000): ").strip()

# 🔹 Запуск Nmap
print(f"\n[+] Сканируем {ip_range} на порты {port_range}...")
nmap_cmd = f"nmap -p {port_range} {ip_range} --open -oG -"
result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)

# 🔹 Обработка результатов Nmap
open_ports = []
for line in result.stdout.split("\n"):
    if "Ports:" in line:
        parts = line.split("\t")
        ip = parts[0].split(" ")[1]
        ports_data = parts[-1].split(":")[-1].strip()

        for port_info in ports_data.split(", "):
            port_details = port_info.split("/")
            if len(port_details) >= 2 and port_details[1] == "open":
                port = port_details[0]
                open_ports.append((ip, port))

# 🔹 Проверка найденных портов разными методами
print(f"\n[+] Найдено {len(open_ports)} открытых портов. Проверяем их...")

# Создаём заголовки в CSV
with open(CSV_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Port", "Nmap", "Netcat", "HTTP", "Socket"])

for ip, port in open_ports:
    netcat_status = check_netcat(ip, port)
    http_status = check_http(ip, port)
    socket_status = check_socket(ip, port)

    print(f"[+] {ip}:{port} - {netcat_status}, {http_status}, {socket_status}")

    # Записываем в CSV
    write_to_csv([ip, port, "Open", netcat_status, http_status, socket_status])

print(f"\n[✅] Сканирование завершено! Результаты сохранены в {CSV_FILE}")
