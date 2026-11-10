#!/usr/bin/env python3
"""Потоковый анализ экспорта Kaspersky KUMA TSV/CSV для события 4662.
Python 3.9+, без сторонних библиотек.
Пример: python parse_kuma_4662.py events.tsv --out results
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

TRUST_GUID = 'bf967ab8-0de6-11d0-a285-00aa003049e2'
KEYWORDS = (TRUST_GUID, 'trusteddomain', 'trustauthincoming')
FOCUS_ACCOUNTS = ('svc.csc-blitz', 'unfc-006898-pc$', 'tam-001271-lts$')
FOCUS_DCS = ('ulg-dc01', 'spb-dc01', 'spb-dc02')


def field(row, *names):
    for name in names:
        if row.get(name):
            return row[name].strip()
    return ''


def short_user(s):
    return (s or '').strip().lower().split('\\')[-1].split('@')[0]


def main():
    p = argparse.ArgumentParser(description='Анализ крупного экспорта событий KUMA')
    p.add_argument('input', type=Path, help='Путь к TSV или CSV')
    p.add_argument('--out', type=Path, default=Path('kuma_4662_result'))
    p.add_argument('--start', default='2026-11-10T15:20:00', help='Время начала МСК в формате YYYY-MM-DDTHH:MM:SS')
    p.add_argument('--end', default='2026-11-10T15:35:00', help='Время конца МСК в формате YYYY-MM-DDTHH:MM:SS')
    p.add_argument('--no-time-filter', action='store_true', help='Без фильтра времени')
    p.add_argument('--encoding', default='utf-8-sig', help='Кодировка файла; например cp1251')
    args = p.parse_args()
    if not args.input.is_file():
        p.error(f'Файл не найден: {args.input}')
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2147483647)

    counters = Counter()
    users = Counter()
    hosts = Counter()
    user_host = Counter()
    time_minutes = Counter()
    time_by_host = defaultdict(lambda: [None, None])
    files = {
        'focus_accounts': args.out / 'focus_accounts.tsv',
        'focus_dcs': args.out / 'focus_dcs.tsv',
        'trust_keywords': args.out / 'trust_keywords.tsv',
    }
    # Все выделенные строки сохраняются без потери исходных полей.
    try:
        with args.input.open('r', encoding=args.encoding, errors='replace', newline='') as inf:
            first = inf.readline()
            delim = '\t' if first.count('\t') >= first.count(',') else ','
            inf.seek(0)
            reader = csv.DictReader(inf, delimiter=delim)
            if not reader.fieldnames:
                raise ValueError('Не удалось прочитать заголовки')
            hdr = reader.fieldnames
            print('Колонки:', ', '.join(hdr))
            with (files['focus_accounts'].open('w', encoding='utf-8-sig', newline='') as fa,
                  files['focus_dcs'].open('w', encoding='utf-8-sig', newline='') as fd,
                  files['trust_keywords'].open('w', encoding='utf-8-sig', newline='') as fk):
                writers = {k: csv.DictWriter(f, fieldnames=hdr, delimiter='\t', extrasaction='ignore')
                           for k, f in (('focus_accounts', fa), ('focus_dcs', fd), ('trust_keywords', fk))}
                for w in writers.values():
                    w.writeheader()
                for row in reader:
                    counters['lines_seen'] += 1
                    if None in row:  # некорректное число колонок
                        counters['malformed_rows'] += 1
                        continue
                    eventid = field(row, 'DeviceEventClassID', 'EventID', 'EventId')
                    if eventid not in ('4662', 'Microsoft-Windows-Security-Auditing:4662'):
                        counters['other_event_ids'] += 1
                        continue
                    ts = field(row, 'Timestamp', 'DeviceReceiptTime', 'TimeCreated')
                    # ISO 8601 +03:00: сравнение первых 19 символов с локальным временем.
                    # Если TZ иная, не фильтруем молча: сохраняем диагностический счетчик.
                    if not args.no_time_filter:
                        if len(ts) < 19 or not ts[0:19].startswith('2026-'):
                            counters['unparseable_timestamp'] += 1
                            continue
                        if ts[19:] and not (ts.endswith('+03:00') or ts.endswith('+0300')):
                            counters['timezone_not_msk'] += 1
                            continue
                        if not (args.start <= ts[:19] <= args.end):
                            counters['out_of_time_window'] += 1
                            continue
                    counters['events_4662_in_window'] += 1
                    user = short_user(field(row, 'SourceUserName', 'SubjectUserName', 'DestinationUserName'))
                    dc = field(row, 'DestinationHostName', 'DeviceHostName', 'Computer', 'DeviceAssetName').lower()
                    users[user or '<empty>'] += 1
                    hosts[dc or '<empty>'] += 1
                    user_host[(user or '<empty>', dc or '<empty>')] += 1
                    time_minutes[ts[:16]] += 1
                    times = time_by_host[dc or '<empty>']
                    if times[0] is None or ts < times[0]: times[0] = ts
                    if times[1] is None or ts > times[1]: times[1] = ts
                    account_hit = any(x == user for x in FOCUS_ACCOUNTS)
                    dc_hit = any(dc == x or dc.startswith(x + '.') for x in FOCUS_DCS)
                    # Поиск во всех полях, в том числе в Raw/EventData если присутствуют.
                    text = '\n'.join(str(v) for v in row.values()).lower()
                    trust_hit = any(x in text for x in KEYWORDS)
                    if account_hit:
                        writers['focus_accounts'].writerow(row)
                        counters['focus_account_events'] += 1
                    if dc_hit:
                        writers['focus_dcs'].writerow(row)
                        counters['focus_dc_events'] += 1
                    if trust_hit:
                        writers['trust_keywords'].writerow(row)
                        counters['trust_keyword_events'] += 1
                    if counters['lines_seen'] % 200000 == 0:
                        print(f"Обработано строк: {counters['lines_seen']:,}", flush=True)
    except KeyboardInterrupt:
        print('Прервано пользователем', file=sys.stderr)
        return 130

    def write_count(name, cols, counter):
        path = args.out / name
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            w = csv.writer(f, delimiter='\t')
            w.writerow(cols)
            for key, count in counter.most_common():
                w.writerow([*(key if isinstance(key, tuple) else (key,)), count])
    write_count('top_users.tsv', ['UserName', 'Count'], users)
    write_count('top_dcs.tsv', ['DomainController', 'Count'], hosts)
    write_count('user_dc_pairs.tsv', ['UserName', 'DomainController', 'Count'], user_host)
    write_count('events_by_minute.tsv', ['Minute', 'Count'], time_minutes)
    report = {
        'input': str(args.input),
        'window_MSK': 'all' if args.no_time_filter else [args.start, args.end],
        'counters': dict(counters),
        'unique_users': len(users),
        'unique_domain_controllers': len(hosts),
        'top_users': users.most_common(20),
        'top_domain_controllers': hosts.most_common(20),
        'account_events_by_dc': [(u, h, n) for (u, h), n in user_host.most_common() if u in FOCUS_ACCOUNTS],
        'columns': hdr,
        'outputs': {k: str(v) for k, v in files.items()},
    }
    with (args.out / 'summary.json').open('w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print('\nРЕЗУЛЬТАТЫ')
    for k, v in counters.items(): print(f'{k}: {v:,}')
    print('Уникальных учетных записей:', len(users))
    print('Первые 10 учетных записей:', users.most_common(10))
    print('Сохранено в:', args.out.resolve())
    if 'ObjectName' not in hdr and 'Properties' not in hdr and not any('raw' in h.lower() for h in hdr):
        print('ВНИМАНИЕ: в выгрузке нет ObjectName/Properties/Raw. Идентифицировать объект AD по ней нельзя.')
    if counters['timezone_not_msk']:
        print('ВНИМАНИЕ: есть события с иной временной зоной. Уточните зону или используйте --no-time-filter.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
