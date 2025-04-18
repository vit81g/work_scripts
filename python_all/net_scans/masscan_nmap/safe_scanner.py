import os
import subprocess
import re
import time

# 🔹 Настройки
#TARGET_SUBNET = "10.8.10.0/24"  # Подсеть для сканирования
TARGET_SUBNET = "185.97.166.148"  # Подсеть для сканирования
MASSCAN_RATE = "5000"  # Скорость сканирования (не перегружай сеть!)
LOG_FILE = "patch_logs.txt"

def log_message(message):
    """Записываем логи"""
    print(message)
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# 🔹 1. Masscan: ищем открытые порты
log_message("[+] Запуск Masscan...")
masscan_output = "masscan_results.txt"
# --retries 3 --banners - более точная проверка портов и баннеров по умолчанию p1-65535
os.system(f"sudo masscan {TARGET_SUBNET} -p1-20 --rate={MASSCAN_RATE} --retries 5 --banners -oL {masscan_output}")

# 🔹 2. Извлекаем найденные порты
open_ports = set()
with open(masscan_output, "r") as f:
    for line in f:
        match = re.search(r"open tcp (\d+)", line)
        if match:
            open_ports.add(match.group(1))

if not open_ports:
    log_message("[-] Открытых портов не найдено. Выход.")
    exit()

ports_str = ",".join(open_ports)
log_message(f"[+] Найдены открытые порты: {ports_str}")

# 🔹 3. Nmap: анализ уязвимостей
log_message("[+] Запуск Nmap для поиска уязвимостей...")
nmap_output = "nmap_results.txt"
os.system(f"sudo nmap -p {ports_str} -sV --script=vulners {TARGET_SUBNET} -oN {nmap_output}")

# 🔹 4. Извлекаем CVE-коды
cve_list = set()
with open(nmap_output, "r") as f:
    for line in f:
        match = re.search(r"(CVE-\d{4}-\d+)", line)
        if match:
            cve_list.add(match.group(1))

if not cve_list:
    log_message("[-] Уязвимости (CVE) не найдены.")
    exit()

log_message(f"[+] Найдены уязвимости: {', '.join(cve_list)}")

# 🔹 5. Генерируем рекомендации
log_message("[+] Генерация отчёта по устранению уязвимостей...\n")

for cve in cve_list:
    log_message(f"[+] Проверяем {cve}...")

    # Используем searchsploit для поиска рекомендаций и патчей
    patch_check = subprocess.getoutput(f"searchsploit --cve {cve}")
    if "No Results" in patch_check:
        log_message(f"[-] Нет информации о патчах для {cve}. Проверьте вручную: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
        continue

    log_message(f"[+] Найдены возможные исправления:\n{patch_check}")

# 🔹 6. Финальный отчёт
log_message("\n[✅] Анализ завершён! См. patch_logs.txt для рекомендаций.")

