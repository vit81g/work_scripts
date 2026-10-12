# rkhunter audit (offline)

Python 3.9+, внешние зависимости отсутствуют.

1. Разместите `audit.py` и `rules.json` в корневом каталоге, а журналы rkhunter с расширением `.txt` или `.log` — в папке **`input/`**. Имя файла может быть произвольным.
2. Запустите: `python audit.py` (Windows) или `python3 audit.py` (Linux).
3. Результаты сохраняются в `reports/` рядом с `audit.py`: отчёт для каждого хоста, `00_summary.md`, `00_summary.txt`, `00_results.json`.

Для собственной папки можно использовать: `python audit.py --input C:\path\to\logs --output C:\path\to\reports`.

Дополнительные параметры: `--format md|txt|both`, `--rules /path/rules.json`.

## Семантика

WARNING = требуется проверка; FAIL = несоответствие доказано проверяемым правилом; NOT_CHECKED = нет данных. В базовом наборе нет правил, подтверждающих FAIL только по предупреждению rkhunter. Скрипт не выдает ложные PASS за отсутствие предупреждений.

CIS: https://www.cisecurity.org/cis-benchmarks. Получите эталон для своей версии ОС и профиля, проверьте права использования и привяжите подтвержденные идентификаторы требований. Для Astra Linux не следует автоматически применять профиль Ubuntu.

OWASP: https://owasp.org/projects/web-security-testing-guide/ — требует отдельного тестирования веб-приложений.

Изменять `rules.json` можно без правки Python. `mode`: `indicator` (есть совпадение — WARNING), `anomaly` (то же), `failed` (есть совпадение — FAIL), `not_checked` (данных нет). Регулярное выражение `regex` применяется к каждой строке исходного файла.

**Важно:** в `input/` помещайте только журналы rkhunter: все `.txt` и `.log` в этой папке будут прочитаны как входные отчёты.
