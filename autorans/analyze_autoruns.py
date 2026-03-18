#!/usr/bin/env python3
"""Анализ выгрузок автозагрузки Windows из папки work.

Скрипт рекурсивно обходит подпапки в каталоге ``work`` рядом с собой,
обрабатывает файлы ``.csv`` и ``.txt`` с выгрузками автозагрузок,
анализирует значения на предмет подозрительных путей и команд,
после чего формирует итоговый CSV-отчет ``autoruns_report.csv``.

Поддерживаемые типы источников определяются по имени родительской папки,
например: Scheduler, WMI, Winlogon, Image, Monitors и т.д.
"""

from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Tuple

# Имя итогового CSV-файла, который будет создан рядом со скриптом.
OUTPUT_FILE: str = "autoruns_report.csv"

# Регулярные выражения для каталогов, запуск из которых считаем подозрительным.
# Основная логика: TEMP, Public, Roaming и аналогичные user-writable директории
# часто используются для закрепления вредоносного ПО.
SUSPICIOUS_DIR_PATTERNS: List[Pattern[str]] = [
    re.compile(r"(?i)\\temp\\"),
    re.compile(r"(?i)\\users\\public\\"),
    re.compile(r"(?i)\\appdata\\local\\temp\\"),
    re.compile(r"(?i)\\appdata\\roaming\\"),
    re.compile(r"(?i)\\recycler\\"),
    re.compile(r"(?i)\\\$recycle\.bin\\"),
]

# Регулярные выражения для «нормальных» базовых путей.
# Если путь начинается с одного из них, запись по умолчанию считается штатной,
# если нет других признаков подозрительности.
NORMAL_BASE_DIR_PATTERNS: List[Pattern[str]] = [
    re.compile(r"(?i)^\"?c:\\windows\\"),
    re.compile(r"(?i)^\"?c:\\program files\\"),
    re.compile(r"(?i)^\"?c:\\program files \(x86\)\\"),
    re.compile(r"(?i)^\"?c:\\programdata\\microsoft\\windows defender\\platform\\"),
]

"""
# Набор LOLBIN/LOLBAS-утилит Windows, которые часто используются в атаках.
Сама по себе утилита не означает инцидент, но при подозрительных аргументах
запись помечается как suspicious.
"""
LOLBINS: set[str] = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "msiexec.exe",
}

# Известные штатные DLL для ветки Print Monitors.
# Если в значении Driver встречается одна из них без полного пути,
# такую запись считаем нормальной.
KNOWN_SAFE_MONITOR_DLLS: set[str] = {
    "localspl.dll",
    "tcpmon.dll",
    "usbmon.dll",
    "winspool.drv",
    "appmon.dll",
    "cnas0mok.dll",
    "fxst30.dll",
    "pjlmon.dll",
    "bjmon.dll",
}

# Эталонные безопасные значения для ключевых параметров Winlogon.
# Отклонения от них считаются подозрительными, так как часто используются
# для закрепления вредоносного ПО.
KNOWN_SAFE_WINLOGON: Dict[str, set[str]] = {
    "shell": {"explorer.exe"},
    "userinit": {"c:\\windows\\system32\\userinit.exe,"},
}

# Список колонок итогового CSV-отчета.
CSV_COLUMNS: List[str] = [
    "hostname",
    "source_type",
    "object_name",
    "value_name",
    "value_or_command",
    "status",
    "reason",
    "source_file",
]


def read_text_auto(path: Path) -> str:
    """Читает текстовый файл с автоподбором кодировки.

    Args: path: путь к входному текстовому или CSV-файлу.
    Returns: содержимое файла в виде строки.

    Notes: сначала пробуются наиболее вероятные кодировки выгрузок Windows,
        затем выполняется безопасное декодирование с заменой битых символов.
    """
    # Сырые байты файла; используем bytes, чтобы самим контролировать декодирование.
    raw: bytes = path.read_bytes()

    # Перечень кодировок в порядке вероятности для Windows-выгрузок.
    encodings_to_try: Tuple[str, ...] = ("utf-8-sig", "utf-16", "cp1251", "latin-1")

    for encoding_name in encodings_to_try:
        try:
            return raw.decode(encoding_name)
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace")



def clean_value(value: str) -> str:
    """Нормализует строковое значение.
    Args: value: исходное значение из CSV или текстовой выгрузки.
    Returns: строка без внешних пробелов и без обрамляющих двойных кавычек.
    """
    normalized_value: str = value.strip().strip('"').strip()
    return normalized_value



def extract_host_from_name(path: Path) -> str:
    """Извлекает имя хоста из имени файла.
    Args: path: путь к файлу выгрузки.
    Returns: имя хоста, полученное из stem файла.

    Notes: для некоторых форматов в имени файла может быть технический префикс, например Winlogon_HOSTNAME или Image_HOSTNAME.
    """
    # Имя файла без расширения.
    filename_stem: str = path.stem

    # Префиксы, которые нужно убрать, чтобы получить реальное имя хоста.
    removable_prefixes: Tuple[str, ...] = ("Winlogon_", "Image_")

    for prefix in removable_prefixes:
        if filename_stem.lower().startswith(prefix.lower()):
            return filename_stem[len(prefix):]

    return filename_stem



def extract_first_path(command: str) -> Optional[str]:
    """Пытается извлечь первый путь или исполняемый объект из команды.
    Args: command: командная строка или значение из записи автозагрузки.
    Returns: найденный путь/имя файла или None, если извлечь ничего не удалось.
    Notes: функция полезна для дальнейшей классификации записи: системный путь, user-writable путь, сетевой путь, DLL без полного пути и т.д.
    """
    if not command:
        return None

    # Командная строка без внешних пробелов.
    cmd: str = command.strip()

    # Поиск полного пути в кавычках: "C:\Path\file.exe".
    quoted_match: Optional[re.Match[str]] = re.search(r'"([A-Za-z]:\\[^\"]+)"', cmd)
    if quoted_match:
        return quoted_match.group(1)

    # Поиск полного пути к исполняемому файлу или скрипту с расширением.
    full_path_match: Optional[re.Match[str]] = re.search(
        r"([A-Za-z]:\\.*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js))(?=\s|,|$)",
        cmd,
        re.IGNORECASE,
    )
    if full_path_match:
        return full_path_match.group(1)

    # Более мягкий поиск пути вида C:\something\file.
    short_path_match: Optional[re.Match[str]] = re.search(
        r"([A-Za-z]:\\[^\s,]+(?:\.[A-Za-z0-9]{2,4})?)",
        cmd,
    )
    if short_path_match:
        return short_path_match.group(1)

    # Поиск UNC-пути вида \\server\share\file.exe.
    unc_match: Optional[re.Match[str]] = re.search(r"(\\\\[^\s]+)", cmd)
    if unc_match:
        return unc_match.group(1)

    # Поиск DLL без полного пути.
    dll_match: Optional[re.Match[str]] = re.search(r"(?i)\b([A-Za-z0-9._-]+\.dll)\b", cmd)
    if dll_match:
        return dll_match.group(1)

    # Поиск EXE без полного пути.
    exe_match: Optional[re.Match[str]] = re.search(r"(?i)\b([A-Za-z0-9._-]+\.exe)\b", cmd)
    if exe_match:
        return exe_match.group(1)

    return None



def is_in_normal_base(path_text: str) -> bool:
    """Проверяет, находится ли путь в штатной базовой директории.
    Args: path_text: нормализованный путь или команда для проверки.
    Returns: True, если путь попадает под один из паттернов безопасных базовых путей.
    """
    return any(pattern.search(path_text) for pattern in NORMAL_BASE_DIR_PATTERNS)



def check_command(command: str) -> Tuple[str, str]:
    """Оценивает строку команды/пути на предмет подозрительности.
    Args: command: значение автозагрузки, путь, команда службы или иной объект запуска.
    Returns:
        кортеж из двух строк:
        - статус: ``normal`` или ``suspicious``;
        - причина классификации.
    Heuristics:
        - сетевые пути считаются подозрительными;
        - TEMP / AppData / Public и иные нестандартные директории считаются подозрительными;
        - LOLBIN с подозрительными аргументами считаются подозрительными;
        - Windows / Program Files считаются нормальными базовыми путями.
    """
    if not command or not command.strip():
        return "normal", "empty value"

    # Команда после базовой нормализации.
    normalized_command: str = command.strip()

    # Строка в нижнем регистре для нечувствительных к регистру проверок.
    lowered_command: str = normalized_command.lower()

    # Первая найденная сущность: путь, exe, dll, UNC и т.д.
    first_path: Optional[str] = extract_first_path(normalized_command)

    # Основной кандидат для анализа. Если путь найден — анализируем его,
    # иначе используем всю исходную строку команды.
    candidate_text: str = first_path.lower() if first_path else lowered_command

    if candidate_text.startswith("\\\\"):
        return "suspicious", "network path in autostart"

    for suspicious_pattern in SUSPICIOUS_DIR_PATTERNS:
        if suspicious_pattern.search(candidate_text):
            return "suspicious", "launch from temp or nonstandard user-writable directory"

    # Имя файла без каталога; используется для проверки LOLBIN.
    base_name: str = os.path.basename(candidate_text.strip('"'))

    if base_name in LOLBINS and re.search(
        r"(?i)(-enc\b|frombase64string|http[s]?://|\\appdata\\|\\temp\\)",
        lowered_command,
    ):
        return "suspicious", "LOLBIN with suspicious arguments"

    if re.match(r"(?i)^[a-z]:\\", candidate_text):
        if is_in_normal_base(candidate_text):
            return "normal", "path under Windows or Program Files"
        if "\\users\\" in candidate_text or "\\programdata\\" in candidate_text:
            return "suspicious", "launch from nonstandard directory"
        return "suspicious", "launch from nonstandard directory"

    if base_name.endswith(".dll"):
        return "normal", "dll name without explicit path"

    return "normal", "no suspicious path markers found"



def parse_registry_dump(text: str) -> List[Dict[str, str]]:
    """Разбирает текстовую выгрузку ветки реестра в записи key/value.
    Args: text: текст содержимого файла выгрузки реестра.
    Returns:
        список словарей с полями:
        - key: имя текущего раздела реестра;
        - value_name: имя параметра;
        - value_data: значение параметра.
    Notes: ожидается формат, близкий к выводу ``reg query``.
    """
    # Итоговый список разобранных записей реестра.
    entries: List[Dict[str, str]] = []

    # Текущий раздел реестра, который встретился последним в тексте.
    current_key: Optional[str] = None

    for raw_line in text.splitlines():
        # Строка без служебного символа перевода каретки.
        line: str = raw_line.rstrip("\r")

        if not line.strip():
            continue

        # Удаляем BOM, если она попала в начало строки.
        cleaned_line: str = line.lstrip("\ufeff")

        if cleaned_line.startswith("HKEY_"):
            current_key = cleaned_line.strip()
            continue

        if current_key is None:
            continue

        # Разбор строки формата: <spaces>ValueName REG_SZ Data.
        value_match: Optional[re.Match[str]] = re.match(
            r"^\s{2,}(.+?)\s+REG_[A-Z0-9_]+\s+(.*)$",
            line,
        )
        if not value_match:
            continue

        entries.append(
            {
                "key": current_key,
                "value_name": value_match.group(1).strip(),
                "value_data": value_match.group(2).strip(),
            }
        )

    return entries



def analyze_winlogon(entry: Dict[str, str]) -> Tuple[str, str]:
    """Проверяет запись из ветки Winlogon.
    Args: entry: Словарь с полями key, value_name, value_data.
    Returns: кортеж ``(status, reason)``.
    Notes: для параметров Shell и Userinit используется отдельная строгая логика, так как это частый механизм закрепления вредоносного ПО.
    """
    value_name: str = entry["value_name"].strip().lower()
    value_data: str = entry["value_data"].strip().lower()

    if value_name == "shell" and clean_value(value_data) not in KNOWN_SAFE_WINLOGON["shell"]:
        return "suspicious", "Winlogon Shell differs from explorer.exe"

    if value_name == "userinit" and clean_value(value_data) not in KNOWN_SAFE_WINLOGON["userinit"]:
        return "suspicious", "Winlogon Userinit differs from default"

    return check_command(entry["value_data"])



def analyze_image(entry: Dict[str, str]) -> Tuple[str, str]:
    """Проверяет запись из ветки Image File Execution Options.
    Args: entry: Словарь с полями key, value_name, value_data.
    Returns: кортеж ``(status, reason)``.
    Notes: параметр Debugger в IFEO может использоваться для подмены запуска приложений и часто рассматривается как подозрительный.
    """
    if entry["value_name"].strip().lower() == "debugger" and entry["value_data"].strip():
        return "suspicious", "IFEO Debugger configured"

    return check_command(entry["value_data"])



def analyze_monitor(entry: Dict[str, str]) -> Tuple[str, str]:
    """Проверяет запись из ветки Print Monitors.
    Args: entry: словарь с полями key, value_name, value_data.
    Returns: кортеж ``(status, reason)``.
    """
    value_name: str = entry["value_name"].strip().lower()

    if value_name != "driver":
        return "normal", "non-driver monitor entry"

    # Имя DLL драйвера или полный путь к DLL.
    dll_name: str = clean_value(entry["value_data"]).lower()

    if dll_name and "\\" not in dll_name and dll_name in KNOWN_SAFE_MONITOR_DLLS:
        return "normal", "known monitor dll name"

    return check_command(entry["value_data"])



def analyze_wmi_row(row: Dict[str, str]) -> Tuple[str, str]:
    """Проверяет строку CSV-выгрузки WMI.
    Args: row: словарь одной строки CSV.
    Returns: кортеж ``(status, reason)``.
    Notes: в WMI-подписках особый интерес представляют Query и CommandLineTemplate.
    """
    # Основное текстовое поле для анализа команды или запроса.
    query_or_command: str = row.get("Query", "") or row.get("CommandLineTemplate", "") or ""

    status: str
    reason: str
    status, reason = check_command(query_or_command)

    if status == "normal" and re.search(
        r"(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)",
        query_or_command,
    ):
        return "suspicious", "WMI subscription references script or LOLBIN"

    return status, reason



def parse_csv_file(path: Path) -> Iterable[Dict[str, str]]:
    """Читает CSV-файл и возвращает строки как словари.
    Args: path: путь к CSV-файлу.
    Yields: словарь одной строки CSV, где ключи — имена колонок.
    Notes: разделитель определяется эвристически: ``;`` или ``,``.
    """
    # Текст CSV после декодирования файла.
    csv_text: str = read_text_auto(path)

    # Небольшой фрагмент файла для эвристического выбора разделителя.
    sample_text: str = csv_text[:2048]

    # Разделитель CSV. Если точек с запятой больше, выбираем ';'.
    delimiter: str = ";" if sample_text.count(";") > sample_text.count(",") else ","

    # DictReader автоматически строит словари по заголовкам CSV.
    reader: csv.DictReader = csv.DictReader(csv_text.splitlines(), delimiter=delimiter)

    for row in reader:
        # Нормализуем ключи и значения, пропуская пустые ключи.
        normalized_row: Dict[str, str] = {
            key.strip(): (value or "").strip()
            for key, value in row.items()
            if key is not None
        }
        yield normalized_row



def add_result(
    results: List[Dict[str, str]],
    hostname: str,
    source_type: str,
    object_name: str,
    value_name: str,
    value_or_command: str,
    status: str,
    reason: str,
    source_file: Path,
) -> None:
    """Добавляет одну строку результата в общий список отчета.
    Args:
        results: Общий накопитель результатов.
        hostname: Имя хоста, для которого найдена запись.
        source_type: Тип источника данных (WMI, Winlogon, Scheduler и т.д.).
        object_name: Имя объекта, службы, раздела или сущности.
        value_name: Имя параметра/колонки.
        value_or_command: Значение, команда или путь.
        status: Классификация записи (normal/suspicious).
        reason: Причина присвоения статуса.
        source_file: Исходный файл, из которого получена запись.
    """
    results.append(
        {
            "hostname": hostname,
            "source_type": source_type,
            "object_name": object_name,
            "value_name": value_name,
            "value_or_command": value_or_command,
            "status": status,
            "reason": reason,
            "source_file": str(source_file),
        }
    )



def process_scheduler(path: Path, results: List[Dict[str, str]]) -> None:
    """Обрабатывает CSV-выгрузку из папки Scheduler.
    Args:
        path: Путь к CSV-файлу.
        results: Общий список результатов.
    Notes: в предоставленном примере в этой папке встречались записи служб,
        поэтому анализируются поля Name и PathName/Command.
    """
    hostname: str = extract_host_from_name(path)

    for row in parse_csv_file(path):
        object_name: str = row.get("Name", "")
        value_or_command: str = row.get("PathName", "") or row.get("Command", "")
        status, reason = check_command(value_or_command)

        add_result(
            results,
            hostname,
            "Scheduler/Services",
            object_name,
            "PathName",
            value_or_command,
            status,
            reason,
            path,
        )



def process_wmi(path: Path, results: List[Dict[str, str]]) -> None:
    """Обрабатывает CSV-выгрузку WMI.
    Args:
        path: Путь к CSV-файлу.
        results: Общий список результатов.
    """
    hostname: str = extract_host_from_name(path)

    for row in parse_csv_file(path):
        object_name: str = row.get("Name", "") or row.get("__PATH", "")
        value_or_command: str = row.get("Query", "") or row.get("CommandLineTemplate", "")
        status, reason = analyze_wmi_row(row)

        add_result(
            results,
            hostname,
            "WMI",
            object_name,
            "Query/CommandLineTemplate",
            value_or_command,
            status,
            reason,
            path,
        )



def process_registry_text(path: Path, results: List[Dict[str, str]], source_type: str) -> None:
    """Обрабатывает текстовую выгрузку раздела реестра.
    Args:
        path: Путь к текстовому файлу.
        results: Общий список результатов.
        source_type: Тип источника по имени папки.
    """
    hostname: str = extract_host_from_name(path)
    text: str = read_text_auto(path)

    for entry in parse_registry_dump(text):
        key_name: str = entry["key"]
        value_name: str = entry["value_name"]
        value_data: str = entry["value_data"]

        if source_type == "Winlogon":
            status, reason = analyze_winlogon(entry)
        elif source_type == "Image":
            status, reason = analyze_image(entry)
        elif source_type == "Monitors":
            status, reason = analyze_monitor(entry)
        else:
            status, reason = check_command(value_data)

        add_result(
            results,
            hostname,
            source_type,
            key_name,
            value_name,
            value_data,
            status,
            reason,
            path,
        )



def detect_source_type(path: Path) -> str:
    """Определяет тип источника по имени родительской папки файла.
    Args: path: путь к файлу выгрузки.
    Returns: нормализованное имя типа источника.
    """
    # Сопоставление имен папок с нормализованными типами источников.
    folder_to_source_map: Dict[str, str] = {
        "scheduler": "Scheduler/Services",
        "wmi": "WMI",
        "winlogon": "Winlogon",
        "gpextensions": "GPExtensions",
        "shellexecutehooks": "ShellExecuteHooks",
        "shellserviceobjects": "ShellServiceObjects",
        "image": "Image",
        "monitors": "Monitors",
    }

    parent_folder_name: str = path.parent.name.lower()
    return folder_to_source_map.get(parent_folder_name, path.parent.name)



def process_file(path: Path, results: List[Dict[str, str]]) -> None:
    """Маршрутизирует обработку файла в нужный парсер.
    Args:
        path: Путь к файлу.
        results: Общий список результатов.
    """
    source_type: str = detect_source_type(path)
    suffix: str = path.suffix.lower()

    if suffix == ".csv":
        if source_type == "WMI":
            process_wmi(path, results)
        else:
            process_scheduler(path, results)
    elif suffix == ".txt":
        process_registry_text(path, results, source_type)



def find_target_root(base_dir: Path) -> Path:
    """Определяет корневую директорию с выгрузками.
    Args: base_dir: Базовая директория ``work``.
    Returns: либо сама ``work``, либо вложенная папка, если в ней уже лежат
        целевые подпапки с известными типами источников.
    Notes: это позволяет одинаково обрабатывать как распакованный архив,
        так и уже подготовленную структуру папок.
    """
    # Список непосредственных дочерних директорий внутри base_dir.
    child_directories: List[Path] = [item for item in base_dir.iterdir() if item.is_dir()]

    if len(child_directories) == 1:
        nested_dir: Path = child_directories[0]

        # Набор имен известных подпапок с выгрузками.
        known_source_folders: set[str] = {
            "scheduler",
            "wmi",
            "winlogon",
            "gpextensions",
            "shellexecutehooks",
            "shellserviceobjects",
            "image",
            "monitors",
        }

        nested_folder_names: List[str] = [
            item.name.lower() for item in nested_dir.iterdir() if item.is_dir()
        ]

        if any(folder_name in known_source_folders for folder_name in nested_folder_names):
            return nested_dir

    return base_dir



def main() -> int:
    """Точка входа скрипта.
    Returns:
        Код завершения процесса:
        - 0 при успешной обработке;
        - 1 если папка work не найдена.
    """
    # Абсолютный путь к каталогу, где расположен скрипт.
    script_dir: Path = Path(__file__).resolve().parent

    # Папка с входными данными. Должна лежать рядом со скриптом.
    work_dir: Path = script_dir / "work"

    if not work_dir.is_dir():
        print(f"[!] Folder not found: {work_dir}")
        return 1

    # Фактический корень данных после проверки вложенности.
    target_root: Path = find_target_root(work_dir)

    # Накопитель всех строк будущего отчета.
    results: List[Dict[str, str]] = []

    for file_path in sorted(target_root.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in {".csv", ".txt"}:
            process_file(file_path, results)

    # Путь к итоговому отчету.
    output_path: Path = script_dir / OUTPUT_FILE

    with output_path.open("w", newline="", encoding="utf-8-sig") as output_file_handle:
        writer: csv.DictWriter = csv.DictWriter(output_file_handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    # Количество записей, помеченных как suspicious.
    suspicious_count: int = sum(1 for item in results if item["status"] == "suspicious")

    print(f"[+] Processed entries: {len(results)}")
    print(f"[+] Suspicious entries: {suspicious_count}")
    print(f"[+] Report saved to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
