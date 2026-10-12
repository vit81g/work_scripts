#!/usr/bin/env python3
"""Offline rkhunter evidence auditor. Python 3.9+, no dependencies."""
import argparse, collections, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATUS = re.compile(r'^\s*(.+?)\s{2,}\[\s*(OK|Warning|Bad|Found|Not found|Skipped|None found|Not installed|Not running)\s*\]\s*$', re.I)
HOST = re.compile(r'Running Rootkit Hunter version\s+(\S+)\s+on\s+(\S+)')
OS = re.compile(r"Found O/S name:\s*(.+)")
LOG_PREFIX = re.compile(r'^\[[0-9:]+\]\s*')


def parse(path):
    raw = path.read_text(encoding='utf-8', errors='replace')
    lines = raw.splitlines()
    host, os_name, version = path.stem.split('_rkhunter_')[0], 'не определена', '?'
    facts, warnings = [], []
    for n, line in enumerate(lines, 1):
        clean = LOG_PREFIX.sub('', line)
        m = HOST.search(clean)
        if m: version, host = m.groups()
        m = OS.search(clean)
        if m: os_name = m.group(1)
        m = STATUS.match(clean)
        if m: facts.append({'line':n, 'item':m.group(1).strip(), 'status':m.group(2).strip(), 'text':clean})
        if clean.startswith('Warning:'): warnings.append({'line':n, 'text':clean})
    return {'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'host':host,
            'os':os_name,'version':version,'lines':lines,'facts':facts,'warnings':warnings}


def evaluate(d, rule):
    if not re.search(rule.get('os_regex','.*'),d['os'],re.I):return None
    rx = re.compile(rule['regex'], re.I)
    matched = []
    for idx, line in enumerate(d['lines'],1):
        clean = LOG_PREFIX.sub('',line)
        if rx.search(clean):matched.append({'line':idx,'text':clean[:450]})
    if rule['mode']=='anomaly':status='WARNING' if matched else 'PASS'
    elif rule['mode']=='indicator':status='WARNING' if matched else 'NOT_CHECKED'
    elif rule['mode']=='failed':status='FAIL' if matched else 'NOT_CHECKED'
    else:status='NOT_CHECKED'
    if rule.get('mode')=='anomaly' and not matched and not d['facts']:status='NOT_CHECKED'
    if status=='PASS' and rule.get('no_match_not_proof',True):status='NOT_CHECKED'
    return {'id':rule['id'],'name':rule['name'],'status':status,'severity':rule['severity'],
            'evidence':matched[:25], 'evidence_total':len(matched),
            'recommendation':rule['recommendation'],'references':rule.get('references',[]),
            'check_commands':rule.get('check_commands',[])}


def generic(d, known):
    out=[]
    # Every warning is retained, including patterns not yet covered by the knowledge base.
    for w in d['warnings']:
        if w['line'] in known:continue
        out.append({'id':'RKH-UNCLASSIFIED','name':'Не классифицированное предупреждение rkhunter',
            'status':'WARNING','severity':'medium','evidence':[w],'evidence_total':1,
            'recommendation':'Проверить контекст предупреждения на хосте, сверить с пакетами/эталоном и задокументировать вывод.',
            'references':[{'name':'rkhunter validation','url':'https://sourceforge.net/p/rkhunter/wiki/validate/'}],
            'check_commands':[]})
    return out


def fmt_refs(refs):return ', '.join(f"[{x['name']}]({x['url']})" for x in refs) or '—'


def detail(r):
    out=[f"### {r['id']} — {r['name']}",f"**Результат:** {r['status']} | **Приоритет:** {r['severity']}",""]
    if r['evidence']:
        out += ['**Доказательства (номер строки в исходном файле):**','']
        out += [f"- Строка {e['line']}: `{e['text'].replace('`', chr(39))}`" for e in r['evidence']]
        if r['evidence_total']>len(r['evidence']):out += [f"- Дополнительно: {r['evidence_total']-len(r['evidence'])} совпадений"]
    else:out+=['Достаточных сведений в журнале нет.']
    out+=['',f"**Рекомендация:** {r['recommendation']}",'']
    if r['check_commands']:out+=['**Команды для ручной проверки на целевом хосте (не выполняются скриптом):**','','```bash',*r['check_commands'],'```','']
    out += [f"**Источники:** {fmt_refs(r['references'])}",'']
    return out


def main():
    p=argparse.ArgumentParser(description='Offline rkhunter review')
    p.add_argument('--input',type=Path,default=ROOT/'input', help='Папка с журналами, по умолчанию input рядом с audit.py')
    p.add_argument('--rules',type=Path,default=ROOT/'rules.json')
    p.add_argument('--output',type=Path,default=None)
    p.add_argument('--format',choices=['md','txt','both'],default='both')
    a=p.parse_args(); source=a.input.resolve(); output=(a.output or ROOT/'reports').resolve()
    if not source.is_dir(): raise SystemExit(f'Папка с отчетами не найдена: {source}. Создайте папку input рядом с audit.py.')
    output.mkdir(parents=True,exist_ok=True)
    rules=json.loads(a.rules.read_text(encoding='utf-8'))['rules']
    paths=sorted(x for x in source.iterdir() if x.is_file() and x.suffix.lower() in ('.txt','.log') and not x.stem.lower().endswith('_audit'))
    if not paths:raise SystemExit(f'В папке {source} не найдены отчеты .txt или .log')
    summary=['# Сводный анализ rkhunter','',f"Дата анализа (UTC): {datetime.now(timezone.utc).isoformat()}",'',
             '| Хост | ОС | Предупреждения rkhunter | WARNING | FAIL | NOT_CHECKED |','|---|---|---:|---:|---:|---:|']
    all_output=[]
    for path in paths:
        d=parse(path);result=[evaluate(d,r) for r in rules];result=[x for x in result if x]
        covered={e['line'] for x in result if x['status'] in ('FAIL','WARNING') for e in x['evidence']}
        result+=generic(d,covered)
        count=collections.Counter(x['status'] for x in result)
        txt=[f"# Аудит безопасности: {d['host']}",'',f"- Файл: `{d['file']}`",f"- SHA256: `{d['sha256']}`",
             f"- ОС (по журналу): {d['os']}",f"- rkhunter: {d['version']}",f"- Предупреждений `Warning:`: {len(d['warnings'])}",
             f"- WARNING: {count['WARNING']}; FAIL: {count['FAIL']}; NOT_CHECKED: {count['NOT_CHECKED']}; PASS: {count['PASS']}",'',
             '> WARNING — не доказательство компрометации. NOT_CHECKED — не подтверждено выполнение CIS/OWASP.','',
             '## Предупреждения и несоответствия','']
        for x in result:
            if x['status'] in ('WARNING','FAIL'):txt+=detail(x)
        txt+=['## Непроверенные требования и контрольные процедуры','']
        for x in result:
            if x['status']=='NOT_CHECKED':txt+=detail(x)
        text='\n'.join(txt)
        safe=re.sub(r'[^a-zA-Z0-9_.-]','_',path.stem)
        if a.format in ('md','both'):(output/f'{safe}_audit.md').write_text(text,encoding='utf-8')
        if a.format in ('txt','both'):(output/f'{safe}_audit.txt').write_text(text,encoding='utf-8')
        summary.append(f"| {d['host']} | {d['os']} | {len(d['warnings'])} | {count['WARNING']} | {count['FAIL']} | {count['NOT_CHECKED']} |")
        all_output.append({'host':d['host'],'os':d['os'],'warnings':len(d['warnings']), 'statuses':dict(count)})
    summary+=['','**Внимание:** значения WARNINGS/FAIL отражают правила этого анализатора, а не результат сертификационного CIS-аудита.',
              '', 'Для полного CIS Benchmark требуется отдельный сбор параметров ОС, а для web-приложений — проверки по OWASP WSTG.']
    s='\n'.join(summary)
    if a.format in ('md','both'):(output/'00_summary.md').write_text(s,encoding='utf-8')
    if a.format in ('txt','both'):(output/'00_summary.txt').write_text(s,encoding='utf-8')
    (output/'00_results.json').write_text(json.dumps(all_output,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'Обработано {len(paths)} файлов. Результаты: {output}')
if __name__=='__main__': main()
