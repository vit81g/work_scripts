import os
import subprocess
import re

# 🔹 Настройки сканирования
TARGET_SUBNET = "10.8.10.0/24"  # Подсеть, которую сканируем
MASSCAN_RATE = "100000"  # Скорость сканирования (осторожно с высокой!)

# 🔹 1. Masscan: быстрый поиск открытых портов
print(f"[+] Запускаем Masscan для подсети {TARGET_SUBNET}...")
masscan_output = "masscan_results.txt"
masscan_cmd = f"sudo masscan {TARGET_SUBNET} -p1-65535 --rate={MASSCAN_RATE} -oL {masscan_output}"
os.system(masscan_cmd)

# 🔹 2. Извлекаем найденные порты
open_ports = set()
with open(masscan_output, "r") as f:
    for line in f:
        match = re.search(r"open tcp (\d+)", line)
        if match:
            open_ports.add(match.group(1))

if not open_ports:
    print("[-] Открытых портов не найдено.")
    exit()

ports_str = ",".join(open_ports)
print(f"[+] Найдены открытые порты: {ports_str}")

# 🔹 3. Nmap: сканирование сервисов и уязвимостей
nmap_output = "nmap_results.txt"
print("[+] Запускаем Nmap для анализа уязвимостей...")
nmap_cmd = f"sudo nmap -p {ports_str} -sV --script=vulners {TARGET_SUBNET} -oN {nmap_output}"
os.system(nmap_cmd)

# 🔹 4. Извлекаем CVE-коды из Nmap-отчёта
print("[+] Извлекаем CVE-коды для поиска эксплойтов...")
cve_list = set()
with open(nmap_output, "r") as f:
    for line in f:
        match = re.search(r"(CVE-\d{4}-\d+)", line)
        if match:
            cve_list.add(match.group(1))

if not cve_list:
    print("[-] Уязвимости (CVE) не найдены.")
    exit()

print(f"[+] Найдены уязвимости: {', '.join(cve_list)}")

# 🔹 5. Metasploit & Searchsploit: поиск эксплойтов для CVE
print("[+] Поиск доступных эксплойтов...")
for cve in cve_list:
    print(f"\n[+] Поиск эксплойтов для {cve}:")
    searchsploit_cmd = f"searchsploit --cve {cve}"
    subprocess.run(searchsploit_cmd, shell=True)

print("\n[✅] Анализ завершён! Смотри результаты в файлах masscan_results.txt и nmap_results.txt")

