"""Офлайн-анализ Lynis report.dat (key=value). Не исполняет команды на хостах."""
import collections, datetime, hashlib, json, re
from pathlib import Path


def load(path):
    items=collections.defaultdict(list)
    raw=path.read_text(encoding='utf-8',errors='replace')
    for n,line in enumerate(raw.splitlines(),1):
        if '=' not in line:continue
        key,value=line.split('=',1)
        items[key].append({'line':n,'value':value})
    host=(items.get('hostname',[{'value':path.name.split('_lynis_')[0]}])[-1]['value']).strip()
    date=items.get('report_datetime_start',[{'value':''}])[-1]['value']
    return {'file':path.name,'host':host,'date':date,'os':get(items,'os_fullname') or get(items,'os_name'),
            'version':get(items,'lynis_version'),'hash':hashlib.sha256(path.read_bytes()).hexdigest(), 'items':items}

def get(items,key):
    return items[key][-1]['value'] if items.get(key) else None

def suggestions(d, recommendations):
    out=[]
    for category in ('warning[]','suggestion[]'):
        for i in d['items'].get(category,[]):
            fields=i['value'].split('|')
            ident=fields[0]
            custom=recommendations.get(ident,{})
            out.append({'category':'WARNING' if category=='warning[]' else 'SUGGESTION',
              'id':ident,'message':fields[1] if len(fields)>1 else '',
              'detail':fields[2] if len(fields)>2 else '',
              'advice':fields[3] if len(fields)>3 else '',
              'recommendation':custom.get('recommendation','Проверить замечание Lynis, оценить применимость к роли сервера и устранить подтверждённое отклонение либо документировать исключение.'),
              'severity':custom.get('severity','high' if category=='warning[]' else 'medium'),
              'line':i['line']})
    return out

def sysctl(d):
    out={}
    for i in d['items'].get('details[]',[]):
        raw=i['value']
        if not raw.startswith('KRNL-6000|sysctl|'):continue
        attrs=dict(re.findall(r'(field|prefval|value|desc):([^;|]*)',raw))
        if attrs.get('field'):
            out[attrs['field']]={'value':attrs.get('value'),'preferred_lynis':attrs.get('prefval'),
                                  'line':i['line'],'desc':attrs.get('desc','')}
    return out

def ppk_checks(d,ppk_rules):
    observations=sysctl(d)
    out=[]
    for r in ppk_rules:
        key=r['key']; actual=None; line=None; status='NOT_CHECKED';note='В отчёте Lynis нет достаточного подтверждения фактического параметра.'
        if key.startswith('sysctl.'):
            entry=observations.get(key[7:])
            if entry:
                actual=entry['value'];line=entry['line']
                status='PASS' if str(actual)==str(r['expected']) else 'FAIL'
                note='Получено из details[]=KRNL-6000; для подтверждения требуется повторная проверка на узле.'
                if key.endswith('kernel.unprivileged_bpf_disabled') and actual=='2':
                    status='REVIEW';note='Значение 2 может означать более строгую блокировку, чем требуемое 1; требуется ручная оценка политики.'
        if key=='ssh.permitrootlogin':
            # Lynis can report sshd settings but a heuristic is not authoritative.
            note='Проверяйте effective sshd -T, включая Match/Include; рекомендации SSH-7408 не доказывают нужное значение.'
        out.append({**r,'status':status,'actual':actual,'line':line,'note':note})
    return out

def escape(s):return str(s if s is not None else '—').replace('|','\\|').replace('\n',' ')

def render(d,rec,checks):
    issues=suggestions(d,rec)
    counts=collections.Counter(x['category'] for x in issues)
    pc=collections.Counter(x['status'] for x in checks)
    lines=[f"# Дополнительный аудит Lynis: {d['host']}",'',f"- Источник: `{d['file']}`",f"- SHA256: `{d['hash']}`",f"- Дата исходного аудита: {d['date']}",f"- ОС: {d['os']}",f"- Lynis: {d['version']}",f"- Hardening Index: {get(d['items'],'hardening_index') or 'нет данных'} (метрика Lynis, не процент CIS)",f"- WARNING: {counts['WARNING']}; SUGGESTION: {counts['SUGGESTION']}",'',
    '> Предупреждение Lynis не является доказанной уязвимостью. Его оценки не подтверждают соответствие CIS/OWASP без отдельного профиля и проверки.','',
    '## Замечания Lynis — отдельный отчёт','','| Тип | Test ID | Замечание | Детали | Строка | Приоритет |','|---|---|---|---|---:|---|']
    for issue in issues:
        lines.append('| '+' | '.join(escape(x) for x in (issue['category'],issue['id'],issue['message'],issue['detail'],issue['line'],issue['severity']))+' |')
    lines+=['','## Корпоративные требования ГК ППК по данным Lynis','',
      'Не следует считать `NOT_CHECKED` нарушением. `REVIEW` — требуется ручная оценка альтернативного значения.','',
      '| Пункт | Требование ГК ППК | Ожидается | Факт Lynis | Соответствие ГК ППК | Строка | Риск изменения |',
      '|---|---|---|---|---|---:|---|']
    for c in checks:
        lines.append('| '+' | '.join(escape(x) for x in (c['section'],c['title'],c['expected'],c['actual'],c['status'],c['line'],c['risk']))+' |')
    lines +=['','## Требования ГК ППК: отклонения и уточнения','']
    for c in checks:
        if c['status'] not in ('FAIL','REVIEW'):continue
        lines+= [f"### {c['section']}: {c['title']}",'',f"- Статус: **{c['status']}**",f"- Ожидание: `{c['expected']}`; фактическое значение Lynis: `{c['actual']}`",f"- Доказательство: `{d['file']}`, строка {c['line']}",f"- Проверка: `{c['command']}`",f"- Риски применения: {c['risk']}",f"- Примечание: {c['note']}",'']
    lines+=['','## Рекомендации по замечаниям Lynis','']
    for idx,x in enumerate(issues,1):
        lines += [f"### {idx}. {x['category']} {x['id']}",'',f"**Наблюдение:** {x['message']}",f"**Детали Lynis:** {x['detail'] or '—'}",f"**Рекомендация Lynis:** {x['advice'] or '—'}",f"**Практическая рекомендация:** {x['recommendation']}",f"**Доказательство:** строка {x['line']} файла `{d['file']}`",'']
    lines+=['','## Сводка корпоративных проверок','',f"PASS: {pc['PASS']}; FAIL: {pc['FAIL']}; REVIEW: {pc['REVIEW']}; NOT_CHECKED: {pc['NOT_CHECKED']}",'',
    'Для полной проверки PAM, прав файлов и GRUB необходим отдельный сбор фактических параметров.','']
    return '\n'.join(lines),{'host':d['host'],'file':d['file'],'os':d['os'],'date':d['date'],
      'hardening_index':get(d['items'],'hardening_index'),'warnings':counts['WARNING'],
      'suggestions':counts['SUGGESTION'],'ppk':dict(pc), 'issues':issues,'ppk_checks':checks}

def run(paths,output,ppk_rules,recommendation_file):
    rec=json.loads(recommendation_file.read_text(encoding='utf-8'))['rules']
    data=[load(p) for p in paths]
    selected={}
    for d in data:
        old=selected.get(d['host'])
        if old is None or (d['date'],d['file'])>(old['date'],old['file']):selected[d['host']]=d
    results=[]
    for host,d in sorted(selected.items()):
        md,obj=render(d,rec,ppk_checks(d,ppk_rules))
        safe=re.sub(r'[^a-zA-Z0-9_.-]','_',host)
        (output/f'{safe}_lynis_audit.md').write_text(md,encoding='utf-8')
        (output/f'{safe}_lynis_audit.txt').write_text(md,encoding='utf-8')
        results.append(obj)
    summary=['# Сводка Lynis','',f'Исходных файлов: {len(data)}; уникальных хостов: {len(selected)}. Для дубликатов выбран последний отчёт по report_datetime_start.','',
             '| Хост | Дата Lynis | Hardening Index | WARNING | SUGGESTION | ГК ППК PASS | ГК ППК FAIL | REVIEW | NOT_CHECKED |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in results:
        pc=collections.Counter(r['ppk'])
        summary.append('| '+' | '.join(escape(v) for v in (r['host'],r['date'],r['hardening_index'],r['warnings'],r['suggestions'],pc['PASS'],pc['FAIL'],pc['REVIEW'],pc['NOT_CHECKED']))+' |')
    summary+=['','**Hardening Index не является процентом CIS Benchmark.**','']
    s='\n'.join(summary)
    for ext in ('md','txt'):(output/f'00_lynis_summary.{ext}').write_text(s,encoding='utf-8')
    (output/'00_lynis_results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    return results
