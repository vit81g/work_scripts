import sys
import os
import re
from collections import Counter
import Evtx  # Импорт библиотеки Evtx
from Evtx.Evtx import Evtx as EvtxFile  # Правильный вызов Evtx

def extract_sites_from_evtx(evtx_file):
    site_counter = Counter()
    pattern = re.compile(r'https?://(?:www\.)?([^/]+)')

    try:
        with EvtxFile(evtx_file) as log:  # Используем правильный вызов Evtx
            for record in log.records():
                text = record.xml()
                matches = pattern.findall(text)
                for match in matches:
                    site_counter[match] += 1
    except Exception as e:
        print(f"Ошибка при обработке файла {evtx_file}: {e}")
        sys.exit(1)

    return site_counter

def save_results(site_counter, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for site, count in site_counter.most_common():
                f.write(f"{site}: {count}\n")
    except Exception as e:
        print(f"Ошибка при записи в файл {output_file}: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <evtx_file>")
        sys.exit(1)

    evtx_file = sys.argv[1]
    if not os.path.isfile(evtx_file):
        print("Error: File not found!")
        sys.exit(1)

    site_counter = extract_sites_from_evtx(evtx_file)
    output_file = f"{os.path.splitext(evtx_file)[0]}_sites.txt"
    save_results(site_counter, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
