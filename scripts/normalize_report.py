#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Нормализация результатов всех сканеров в единый реестр находок и отчёт.

Читает сырые отчёты из каталога raw/ (любой файл может отсутствовать —
инструмент просто не был выбран детектором), план из plan.json и пишет:
  * findings.json  — единый реестр (машиночитаемый);
  * report.md      — отчёт для GitHub Job Summary / репозитория;
  * report.html    — автономный красивый отчёт (inline CSS, без сети).

Дедупликация — внутри каждой категории:
  * SAST:    один файл+строка+CWE от Semgrep и CodeQL = одна находка, источники оба;
  * Secrets: один файл+строка+детектор = одна находка (значения секретов в отчёт не попадают);
  * SCA:     один пакет+версия+CVE (с учётом алиасов GHSA) от OSV и Grype = одна находка.

Политика качества (gate): --fail-on critical|high|medium|none —
код возврата 1, если есть находки не ниже порога (по умолчанию отчёт не валит сборку).
"""
import argparse, html, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEV_RU = {'critical': 'Критический', 'high': 'Высокий', 'medium': 'Средний',
          'low': 'Низкий', 'info': 'Инфо'}

REMEDIATION = {
    'SAST': 'Исправить код в указанном месте; для инъекций — параметризованные запросы и '
            'валидация входных данных, для вывода — контекстное экранирование.',
    'Secrets': 'Отозвать и перевыпустить скомпрометированное значение, удалить его из кода и '
               'истории git, перенести секрет в хранилище секретов (CI secrets / Vault).',
    'SCA': 'Обновить пакет до исправленной версии (колонка «Исправлено в»); если обновления нет — '
           'оценить достижимость уязвимости и зафиксировать риск.',
}


def sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 'medium'
    return 'critical' if s >= 9 else 'high' if s >= 7 else 'medium' if s >= 4 else 'low'


def norm_sev(s, default='medium'):
    if s is None:
        return default
    s = str(s).lower()
    for k in SEV_ORDER:
        if s.startswith(k) or (k == 'info' and s in ('note', 'informational', 'negligible')):
            return k
    return {'error': 'high', 'warning': 'medium', 'critical': 'critical'}.get(s, default)


def cwe_of(text):
    m = re.search(r'CWE-(\d+)', str(text or ''), re.I)
    return f'CWE-{m.group(1)}' if m else ''


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return None


def first_existing(raw: Path, patterns):
    for pat in patterns:
        hits = sorted(raw.glob(pat))
        if hits:
            return hits[0]
    return None


# ---------------------------------------------------------------- парсеры
def parse_semgrep(path):
    data = load_json(path) or {}
    out = []
    for r in data.get('results', []):
        meta = r.get('extra', {}).get('metadata', {})
        out.append({
            'category': 'SAST', 'source': 'Semgrep',
            'rule': r.get('check_id', '').split('.')[-1],
            'title': (r.get('extra', {}).get('message') or r.get('check_id', ''))[:200],
            'severity': norm_sev(meta.get('impact') or r.get('extra', {}).get('severity')),
            'cwe': cwe_of(json.dumps(meta.get('cwe', ''))),
            'file': r.get('path', ''), 'line': (r.get('start') or {}).get('line', ''),
            'description': (r.get('extra', {}).get('message') or '')[:400],
        })
    return out


def parse_codeql(path):
    data = load_json(path) or {}
    out = []
    for run in data.get('runs', []):
        rules = {}
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            props = rule.get('properties', {})
            rules[rule['id']] = {
                'cwe': cwe_of(' '.join(props.get('tags', [])) + ' ' + rule.get('id', '')),
                'sev': sev_from_score(props.get('security-severity')) if props.get('security-severity') else None,
                'name': rule.get('shortDescription', {}).get('text') or rule.get('name', ''),
            }
        for res in run.get('results', []):
            rid = res.get('ruleId', '')
            meta = rules.get(rid, {})
            loc = (res.get('locations') or [{}])[0].get('physicalLocation', {})
            out.append({
                'category': 'SAST', 'source': 'CodeQL', 'rule': rid.split('/')[-1],
                'title': (meta.get('name') or res.get('message', {}).get('text', ''))[:200],
                'severity': meta.get('sev') or norm_sev(res.get('level'), 'medium'),
                'cwe': meta.get('cwe', ''),
                'file': loc.get('artifactLocation', {}).get('uri', ''),
                'line': loc.get('region', {}).get('startLine', ''),
                'description': res.get('message', {}).get('text', '')[:400],
            })
    return out


def parse_gitleaks(path):
    data = load_json(path) or []
    out = []
    for r in data if isinstance(data, list) else []:
        out.append({
            'category': 'Secrets', 'source': 'Gitleaks', 'rule': r.get('RuleID', ''),
            'title': r.get('Description') or f"Секрет: {r.get('RuleID', '')}",
            'severity': 'high', 'cwe': 'CWE-798',
            'file': r.get('File', ''), 'line': r.get('StartLine', ''),
            'description': 'Значение скрыто (redact); совпадение по отпечатку ' +
                           str(r.get('Fingerprint', ''))[:24],
        })
    return out


def parse_trufflehog(path):
    out = []
    try:
        lines = Path(path).read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return out
    for ln in lines:
        try:
            r = json.loads(ln)
        except Exception:
            continue
        git_meta = (((r.get('SourceMetadata') or {}).get('Data') or {}).get('Git') or {})
        fs_meta = (((r.get('SourceMetadata') or {}).get('Data') or {}).get('Filesystem') or {})
        out.append({
            'category': 'Secrets', 'source': 'TruffleHog',
            'rule': r.get('DetectorName') or r.get('RuleID', ''),
            'title': f"Секрет сервиса: {r.get('DetectorName') or r.get('RuleID', '')}",
            'severity': 'high', 'cwe': 'CWE-798',
            'file': git_meta.get('file') or fs_meta.get('file') or r.get('File', ''),
            'line': git_meta.get('line') or fs_meta.get('line') or r.get('Line', ''),
            'description': 'Значение в отчёт не включается (REDACTED)' +
                           (f"; коммит {str(git_meta.get('commit'))[:8]}" if git_meta.get('commit') else ''),
        })
    return out


def parse_osv(path):
    data = load_json(path) or {}
    out = []
    for res in data.get('results', []):
        src = res.get('source', {}).get('path', '')
        for pkg in res.get('packages', []):
            p = pkg.get('package', {})
            for v in pkg.get('vulnerabilities', []):
                sev = 'medium'
                for s in v.get('severity', []):
                    m = re.search(r'CVSS:[\d.]+/AV:[^/]*/AC:[^/]*/PR:[^/]*/UI:[^/]*/S:[^/]*/C:(\w)/I:(\w)/A:(\w)',
                                  s.get('score', ''))
                    sev = sev_from_score(_cvss_base(s.get('score', ''))) if s.get('score') else sev
                fixed = ''
                for aff in v.get('affected', []):
                    for rng in aff.get('ranges', []):
                        for ev in rng.get('events', []):
                            if ev.get('fixed'):
                                fixed = ev['fixed']
                out.append({
                    'category': 'SCA', 'source': 'OSV-Scanner',
                    'rule': v.get('id', ''), 'title': v.get('summary') or v.get('id', ''),
                    'severity': sev, 'cwe': cwe_of(json.dumps(v.get('database_specific', {}))),
                    'package': p.get('name', ''), 'version': p.get('version', ''),
                    'ecosystem': p.get('ecosystem', ''), 'fixed': fixed,
                    'file': src, 'line': '',
                    'description': (v.get('details') or '')[:300],
                    'aliases': v.get('aliases', []),
                })
    return out


def _cvss_base(vector):
    # грубая оценка base score по вектору CVSS (только для градации отчёта)
    impact = {'N': 0.0, 'L': 0.3, 'H': 0.6}
    c = re.search(r'/C:(\w)', vector)
    i = re.search(r'/I:(\w)', vector)
    a = re.search(r'/A:(\w)', vector)
    if not (c and i and a):
        return 5.0
    base = 10 * max(impact.get(c.group(1), 0.3), impact.get(i.group(1), 0.3), impact.get(a.group(1), 0.3))
    return min(10.0, base + 2.0)


def parse_grype(path):
    data = load_json(path) or {}
    out = []
    for m in data.get('matches', []):
        v = m.get('vulnerability', {})
        art = m.get('artifact', {})
        fixed = ''
        fix = v.get('fix', {})
        if fix.get('versions'):
            fixed = fix['versions'][0]
        related = m.get('relatedVulnerabilities') or [{}]
        out.append({
            'category': 'SCA', 'source': 'Grype', 'rule': v.get('id', ''),
            'title': (related[0].get('description') or related[0].get('id') or v.get('id', ''))[:200],
            'severity': norm_sev(v.get('severity'), 'medium'),
            'cwe': cwe_of(' '.join(v.get('cwe', []) if isinstance(v.get('cwe'), list) else [str(v.get('cwe', ''))])),
            'package': art.get('name', ''), 'version': art.get('version', ''),
            'ecosystem': art.get('type', ''), 'fixed': fixed,
            'file': (art.get('locations') or [{}])[0].get('path', ''), 'line': '',
            'description': (related[0].get('description') or '')[:300],
            'aliases': [r.get('id') for r in related if r.get('id')],
        })
    return out


def parse_sbom(path):
    data = load_json(path) or {}
    comps = data.get('components', [])
    stats = {'components': len(comps),
             'ecosystems': Counter()}
    names = []
    for c in comps:
        purl = c.get('purl', '')
        eco = purl[4:].split('/')[0] if purl.startswith('pkg:') else c.get('type', '')
        stats['ecosystems'][eco] += 1
        names.append(f"{c.get('name', '')}@{c.get('version', '')}")
    return {'stats': {'components': stats['components'],
                      'ecosystems': dict(stats['ecosystems'])},
            'sample': sorted(names)[:15]}


PARSERS = [
    ('Semgrep', 'SAST', ['semgrep/*.json', 'semgrep.json']),
    ('CodeQL', 'SAST', ['codeql/**/*.sarif', 'codeql/*.sarif']),
    ('Gitleaks', 'Secrets', ['gitleaks/results.json', 'gitleaks.json']),
    ('TruffleHog', 'Secrets', ['trufflehog/results.json', 'trufflehog/*.json', 'trufflehog.jsonl']),
    ('OSV-Scanner', 'SCA', ['osv/*.json', 'osv.json']),
    ('Grype', 'SCA', ['grype/*.json', 'grype.json']),
]
PARSE_FN = {'Semgrep': parse_semgrep, 'CodeQL': parse_codeql, 'Gitleaks': parse_gitleaks,
            'TruffleHog': parse_trufflehog, 'OSV-Scanner': parse_osv, 'Grype': parse_grype}


def dedup(findings):
    merged = {}
    for f in findings:
        if f['category'] == 'SAST':
            key = (f['category'], f.get('file', ''), str(f.get('line', '')),
                   f.get('cwe') or f['rule'])
        elif f['category'] == 'Secrets':
            key = (f['category'], f.get('file', ''), str(f.get('line', '')),
                   f['rule'].lower())
        else:
            ids = {f['rule']} | set(f.get('aliases') or [])
            cve = next((i for i in ids if str(i).startswith('CVE-')), f['rule'])
            key = (f['category'], f.get('package', ''), f.get('version', ''), cve)
            f['rule'] = cve
        if key in merged:
            m = merged[key]
            if f['source'] not in m['sources']:
                m['sources'].append(f['source'])
            if SEV_ORDER[f['severity']] < SEV_ORDER[m['severity']]:
                m['severity'] = f['severity']
            if not m.get('fixed') and f.get('fixed'):
                m['fixed'] = f['fixed']
            if len(f.get('description', '')) > len(m.get('description', '')):
                m['description'] = f['description']
        else:
            g = dict(f)
            g['sources'] = [f['source']]
            merged[key] = g
    out = sorted(merged.values(),
                 key=lambda x: (SEV_ORDER[x['severity']], x['category'],
                                x.get('file', ''), str(x.get('line', ''))))
    for i, f in enumerate(out, 1):
        f['id'] = f"F-{i:04d}"
    return out


# ---------------------------------------------------------------- отчёты
def plan_rows(plan):
    labels = {'semgrep': 'Semgrep', 'codeql': 'CodeQL', 'gitleaks': 'Gitleaks',
              'trufflehog': 'TruffleHog', 'cdxgen': 'cdxgen', 'syft': 'Syft',
              'osv-scanner': 'OSV-Scanner', 'grype': 'Grype'}
    rows = []
    for key, t in plan.get('tools', {}).items():
        rows.append((labels.get(key, key), t.get('category', ''),
                     'Запущен' if t.get('run') else 'Не выбран', t.get('reason', '')))
    return rows


def build_md(meta, plan, tool_runs, findings, sbom_info):
    sev = Counter(f['severity'] for f in findings)
    cat = Counter(f['category'] for f in findings)
    L = [f"# Отчёт проверки безопасности: {meta['project']}", '',
         f"**Дата:** {meta['generated_at']} · **Ветка/коммит:** {meta.get('ref', '—')} · "
         f"**Языки:** {', '.join(meta.get('languages', [])) or '—'}", '',
         '## Сводка', '',
         '| Категория | Находок | Критических | Высоких | Средних | Низких |',
         '|---|---:|---:|---:|---:|---:|']
    for c in ('SAST', 'Secrets', 'SCA'):
        sub = [f for f in findings if f['category'] == c]
        s = Counter(f['severity'] for f in sub)
        L.append(f"| {c} | {len(sub)} | {s['critical']} | {s['high']} | {s['medium']} | {s['low']} |")
    L.append(f"| **Итого** | **{len(findings)}** | **{sev['critical']}** | **{sev['high']}** | "
             f"**{sev['medium']}** | **{sev['low']}** |")
    L += ['', '## План проверки (выбранные инструменты)', '',
          '| Инструмент | Категория | Решение | Обоснование |', '|---|---|---|---|']
    for name, c, decision, reason in plan_rows(plan):
        L.append(f"| {name} | {c} | {decision} | {reason} |")
    L += ['', '## Выполнение', '', '| Инструмент | Категория | Статус | Находок (сырьё) |',
          '|---|---|---|---:|']
    for tr in tool_runs:
        L.append(f"| {tr['tool']} | {tr['category']} | {tr['status']} | {tr['raw_findings']} |")
    for sb in sbom_info:
        st = sb['sbom']['stats']
        L.append(f"| SBOM ({sb['tool']}) | SBOM | Готов | компонентов: {st['components']} "
                 f"({', '.join(f'{k}: {v}' for k, v in st['ecosystems'].items())}) |")
    L += ['', '## Находки', '']
    for c in ('Secrets', 'SAST', 'SCA'):
        sub = [f for f in findings if f['category'] == c]
        if not sub:
            continue
        L += [f'### {c} ({len(sub)})', '',
              '| ID | Уровень | Что найдено | Где | Источники | Исправление |',
              '|---|---|---|---|---|---|']
        for f in sub:
            where = f.get('file', '')
            if f.get('line'):
                where += f":{f['line']}"
            if f['category'] == 'SCA':
                where = f"{f.get('package', '')}@{f.get('version', '')}"
            L.append(f"| {f['id']} | {SEV_RU[f['severity']]} | {f['title'][:90]} | `{where}` | "
                     f"{', '.join(f['sources'])} | {f.get('fixed') or '—'} |")
        L.append('')
    L += ['## Что делать дальше', '',
          '1. **Secrets** — отозвать и перевыпустить значения, удалить из истории git.',
          '2. **SAST критического и высокого уровня** — исправить до слияния в основную ветку.',
          '3. **SCA** — обновить пакеты до версий из колонки «Исправление»; для недоступных '
          'обновлений зафиксировать оценку риска.',
          '4. Повторить проверку: пайплайн запускается на каждый pull request.']
    return '\n'.join(L) + '\n'


def build_html(meta, plan, tool_runs, findings, sbom_info):
    sev = Counter(f['severity'] for f in findings)
    cat = Counter(f['category'] for f in findings)
    esc = html.escape

    def badge(s):
        return f'<span class="sev {s}">{SEV_RU[s]}</span>'

    cards = ''.join(
        f'<div class="card"><div class="num">{sev[s]}</div><div class="lbl">{SEV_RU[s]}</div></div>'
        for s in ('critical', 'high', 'medium', 'low'))
    plan_tr = ''.join(
        f"<tr><td><b>{esc(n)}</b></td><td>{esc(c)}</td>"
        f"<td>{'<span class=ok>Запущен</span>' if d == 'Запущен' else '<span class=skip>Не выбран</span>'}</td>"
        f"<td>{esc(r)}</td></tr>" for n, c, d, r in plan_rows(plan))
    run_tr = ''.join(
        f"<tr><td>{esc(t['tool'])}</td><td>{esc(t['category'])}</td><td>{esc(t['status'])}</td>"
        f"<td class=r>{t['raw_findings']}</td></tr>" for t in tool_runs)
    for sb in sbom_info:
        st = sb['sbom']['stats']
        eco = ', '.join(f'{k}: {v}' for k, v in st['ecosystems'].items())
        run_tr += (f"<tr><td>SBOM ({esc(sb['tool'])})</td><td>SBOM</td><td>Готов</td>"
                   f"<td class=r>{st['components']} компонентов ({esc(eco)})</td></tr>")
    sections = ''
    for c, title in (('Secrets', 'Секреты в коде и истории'), ('SAST', 'Недостатки кода (SAST)'),
                     ('SCA', 'Уязвимые зависимости (SCA)')):
        sub = [f for f in findings if f['category'] == c]
        if not sub:
            sections += f'<h2>{title}</h2><p class="muted">Находок нет.</p>'
            continue
        rows_html = ''
        for f in sub:
            where = f.get('file', '')
            if f.get('line'):
                where += f":{f['line']}"
            if c == 'SCA':
                where = f"{f.get('package', '')}@{f.get('version', '')}"
            rows_html += (
                f"<tr data-sev='{f['severity']}' data-cat='{c}'><td>{f['id']}</td>"
                f"<td>{badge(f['severity'])}</td><td>{esc(f['title'][:140])}"
                f"<div class='muted'>{esc(f.get('cwe') or f['rule'])}</div></td>"
                f"<td><code>{esc(where)}</code></td><td>{esc(', '.join(f['sources']))}</td>"
                f"<td>{esc(f.get('fixed') or '—')}</td></tr>")
        sections += (f'<h2>{title} <span class="muted">({len(sub)})</span></h2>'
                     f'<table class="findings"><thead><tr><th>ID</th><th>Уровень</th><th>Что найдено</th>'
                     f'<th>Где</th><th>Источники</th><th>Исправлено в</th></tr></thead>'
                     f'<tbody>{rows_html}</tbody></table>'
                     f'<p class="muted">{esc(REMEDIATION[c])}</p>')
    langs = ', '.join(meta.get('languages', []))
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Отчёт проверки безопасности — {esc(meta['project'])}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f4f6fa;color:#1c2733}}
header{{background:linear-gradient(120deg,#0d2b52,#14509e);color:#fff;padding:28px 40px}}
header h1{{margin:0 0 6px;font-size:24px}} header p{{margin:2px 0;opacity:.85}}
main{{max-width:1180px;margin:0 auto;padding:24px 20px 60px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
.card{{background:#fff;border-radius:10px;padding:16px 22px;box-shadow:0 1px 4px rgba(13,43,82,.12);min-width:120px}}
.card .num{{font-size:30px;font-weight:700}} .card .lbl{{color:#5a6b7d}}
h2{{margin-top:34px;font-size:18px}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px rgba(13,43,82,.08)}}
th,td{{border:1px solid #dfe6ee;padding:7px 9px;font-size:13px;text-align:left;vertical-align:top}}
th{{background:#e8eef7}}
td.r{{text-align:right}}
.sev{{padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;white-space:nowrap}}
.critical{{background:#b00020}} .high{{background:#e65100}} .medium{{background:#c49000}}
.low{{background:#4e6e8e}} .info{{background:#78909c}}
.ok{{color:#1b7a43;font-weight:600}} .skip{{color:#8a97a5}}
.muted{{color:#5a6b7d;font-size:12px}}
code{{font-family:Consolas,monospace;font-size:12px}}
.controls{{margin:14px 0}} select{{padding:6px 10px;border-radius:6px;border:1px solid #b9c6d4}}
</style></head><body>
<header><h1>Отчёт проверки безопасности: {esc(meta['project'])}</h1>
<p>{esc(meta['generated_at'])} · {esc(meta.get('ref',''))} · Языки: {esc(langs)}</p>
<p>Всего находок после объединения источников: <b>{len(findings)}</b> ·
SAST: {cat['SAST']} · Secrets: {cat['Secrets']} · SCA: {cat['SCA']}</p></header>
<main>
<div class="cards">{cards}</div>
<h2>План проверки</h2>
<table><thead><tr><th>Инструмент</th><th>Категория</th><th>Решение</th><th>Обоснование</th></tr></thead>
<tbody>{plan_tr}</tbody></table>
<h2>Выполнение</h2>
<table><thead><tr><th>Инструмент</th><th>Категория</th><th>Статус</th><th>Находок</th></tr></thead>
<tbody>{run_tr}</tbody></table>
<div class="controls">Показывать уровень:
<select id="f"><option value="">все</option><option>critical</option><option>high</option>
<option>medium</option><option>low</option></select></div>
{sections}
<h2>Что делать дальше</h2>
<ol><li><b>Secrets</b> — отозвать и перевыпустить значения, удалить из истории git.</li>
<li><b>SAST критического и высокого уровня</b> — исправить до слияния в основную ветку.</li>
<li><b>SCA</b> — обновить пакеты до исправленных версий; для недоступных обновлений зафиксировать риск.</li></ol>
<p class="muted">Отчёт сформирован единым пайплайном: SAST (Semgrep, CodeQL), secret scanning
(Gitleaks, TruffleHog), SBOM (cdxgen, Syft), SCA (OSV-Scanner, Grype). Значения секретов в отчёт не включаются.</p>
</main>
<script>
document.getElementById('f').addEventListener('change', e => {{
  document.querySelectorAll('.findings tbody tr').forEach(tr =>
    tr.style.display = (!e.target.value || tr.dataset.sev === e.target.value) ? '' : 'none');
}});
</script></body></html>"""


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', required=True)
    ap.add_argument('--plan', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--project', default='target')
    ap.add_argument('--ref', default='')
    ap.add_argument('--fail-on', default='none', choices=['none', 'critical', 'high', 'medium'])
    ap.add_argument('--target', default='')
    args = ap.parse_args()

    raw, out = Path(args.raw), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plan = load_json(args.plan) or {}
    from datetime import datetime, timezone
    meta = {'project': args.project, 'ref': args.ref,
            'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            'languages': [l['name'] for l in plan.get('facts', {}).get('languages', [])]}

    findings, tool_runs = [], []
    selected = {k: v.get('run') for k, v in plan.get('tools', {}).items()}
    key_of = {'Semgrep': 'semgrep', 'CodeQL': 'codeql', 'Gitleaks': 'gitleaks',
              'TruffleHog': 'trufflehog', 'OSV-Scanner': 'osv-scanner', 'Grype': 'grype'}
    for tool, cat, patterns in PARSERS:
        planned = selected.get(key_of[tool], True)
        path = first_existing(raw, patterns) if raw.exists() else None
        if not planned:
            tool_runs.append({'tool': tool, 'category': cat, 'status': 'Не выбран по плану',
                              'raw_findings': 0})
            continue
        if tool == 'CodeQL' and raw.exists():
            parsed = []
            for sarif in sorted(set(raw.glob('codeql/**/*.sarif')) | set(raw.glob('codeql/*.sarif'))):
                parsed += parse_codeql(sarif)
            status = 'Выполнен' if parsed or list(raw.glob('codeql/**/*.sarif')) else 'Нет отчёта'
        elif path is not None:
            parsed = PARSE_FN[tool](path)
            status = 'Выполнен'
        else:
            parsed, status = [], 'Нет отчёта'
        findings += parsed
        tool_runs.append({'tool': tool, 'category': cat, 'status': status,
                          'raw_findings': len(parsed)})

    sbom_info = []
    for tool, patterns in (('cdxgen', ['sbom/cdxgen/*.cdx.json', 'sbom/cdxgen/*.json']),
                           ('syft', ['sbom/syft/*.cdx.json', 'sbom/syft/*.json'])):
        path = first_existing(raw, patterns) if raw.exists() else None
        if path is not None:
            sbom_info.append({'tool': tool, 'sbom': parse_sbom(path)})

    if args.target:
        pref = str(Path(args.target).resolve())
        for f in findings:
            if f.get('file', '').startswith(pref):
                f['file'] = f['file'][len(pref):].lstrip('/')
    uniq = dedup(findings)
    registry = {'meta': meta, 'plan': plan, 'tool_runs': tool_runs,
                'sbom': sbom_info, 'findings': uniq}
    (out / 'findings.json').write_text(json.dumps(registry, ensure_ascii=False, indent=2),
                                       encoding='utf-8')
    (out / 'report.md').write_text(build_md(meta, plan, tool_runs, uniq, sbom_info),
                                   encoding='utf-8')
    (out / 'report.html').write_text(build_html(meta, plan, tool_runs, uniq, sbom_info),
                                     encoding='utf-8')
    sev = Counter(f['severity'] for f in uniq)
    print(f"Итого находок: {len(uniq)} (critical {sev['critical']}, high {sev['high']}, "
          f"medium {sev['medium']}, low {sev['low']})")
    if args.fail_on != 'none':
        threshold = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f['severity']] <= threshold for f in uniq):
            print(f'GATE: есть находки уровня {args.fail_on} и выше', file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
