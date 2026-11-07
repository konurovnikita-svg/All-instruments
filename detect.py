#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Детектор проекта: определяет языки, экосистемы зависимостей и структуру
репозитория и на этом основании выбирает инструменты для пайплайна.

Результат — plan.json:
  * какие инструменты запускать (и почему);
  * какие — нет (и почему);
  * языки CodeQL для динамической матрицы GitHub Actions.

Использование:
    python3 detect.py --target ./target --out plan.json
В GitHub Actions дополнительно пишет outputs (steps.<id>.outputs.*),
если задан $GITHUB_OUTPUT.
"""
import argparse, json, os, subprocess, sys
from collections import Counter
from pathlib import Path


LANG_BY_EXT = {
    '.js': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.jsx': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.mjs': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.cjs': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.ts': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.tsx': ('javascript-typescript', 'javascript-typescript', 'JavaScript/TypeScript'),
    '.py': ('python', 'python', 'Python'),
    '.java': ('java-kotlin', 'java-kotlin', 'Java/Kotlin'),
    '.kt': ('java-kotlin', 'java-kotlin', 'Java/Kotlin'),
    '.kts': ('java-kotlin', 'java-kotlin', 'Java/Kotlin'),
    '.rb': ('ruby', 'ruby', 'Ruby'),
    '.erb': ('ruby', 'ruby', 'Ruby'),
    '.cs': ('csharp', 'csharp', 'C#'),
    '.go': ('go', 'go', 'Go'),
    '.php': ('php', None, 'PHP'),
    '.c': ('cpp', 'cpp', 'C/C++'),
    '.h': ('cpp', 'cpp', 'C/C++'),
    '.cpp': ('cpp', 'cpp', 'C/C++'),
    '.swift': ('swift', 'swift', 'Swift'),
    '.sh': ('shell', None, 'Shell'),
    '.tf': ('terraform', None, 'Terraform'),
}

# --- экосистемы зависимостей: манифест -> экосистема ---
MANIFESTS = {
    'package.json': 'npm', 'package-lock.json': 'npm', 'yarn.lock': 'npm',
    'pnpm-lock.yaml': 'npm',
    'requirements.txt': 'PyPI', 'requirements-dev.txt': 'PyPI',
    'Pipfile': 'PyPI', 'Pipfile.lock': 'PyPI', 'pyproject.toml': 'PyPI',
    'poetry.lock': 'PyPI', 'setup.py': 'PyPI',
    'pom.xml': 'Maven', 'build.gradle': 'Maven', 'build.gradle.kts': 'Maven',
    'Gemfile': 'RubyGems', 'Gemfile.lock': 'RubyGems',
    'go.mod': 'Go', 'go.sum': 'Go',
    'composer.json': 'Packagist', 'composer.lock': 'Packagist',
    'Cargo.toml': 'crates.io', 'Cargo.lock': 'crates.io',
}
LOCKFILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock',
             'poetry.lock', 'Gemfile.lock', 'go.sum', 'composer.lock', 'Cargo.lock'}


SEMGREP_PACKS = {
    'javascript-typescript': 'p/javascript',
    'python': 'p/python',
    'java-kotlin': 'p/java',
    'ruby': 'p/ruby',
    'csharp': 'p/csharp',
    'go': 'p/golang',
    'php': 'p/php',
    'terraform': 'p/terraform',
}

SKIP_DIRS = {'.git', 'node_modules', 'vendor', 'dist', 'build', 'target',
             '.venv', 'venv', '__pycache__', '.tox', 'site-packages'}


def scan(target: Path):
    ext_counter, manifests, lockfiles = Counter(), [], []
    dockerfile = compose = False
    file_total = 0
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            file_total += 1
            low = name.lower()
            if low in MANIFESTS:
                manifests.append(name)
                if low in LOCKFILES:
                    lockfiles.append(name)
            if low == 'dockerfile' or low.startswith('dockerfile.'):
                dockerfile = True
            if low.startswith('docker-compose'):
                compose = True
            ext = Path(name).suffix.lower()
            if ext in LANG_BY_EXT:
                ext_counter[LANG_BY_EXT[ext][0]] += 1
    languages = []
    codeql_languages = []
    for key, n in ext_counter.most_common():
        cq = next(v[1] for v in LANG_BY_EXT.values() if v[0] == key)
        display = next(v[2] for v in LANG_BY_EXT.values() if v[0] == key)
        languages.append({'key': key, 'name': display, 'files': n, 'codeql': cq})
        if cq and cq not in codeql_languages:
            codeql_languages.append(cq)
    ecosystems = sorted({MANIFESTS[m.lower()] for m in manifests})
    git = (target / '.git').exists()
    commits = 0
    if git:
        try:
            out = subprocess.run(['git', '-C', str(target), 'rev-list', '--count', 'HEAD'],
                                 capture_output=True, text=True, timeout=30)
            commits = int(out.stdout.strip() or 0)
        except Exception:
            commits = 0
    return {
        'files_total': file_total,
        'languages': languages,
        'codeql_languages': codeql_languages,
        'manifests': sorted(set(manifests)),
        'lockfiles': sorted(set(lockfiles)),
        'ecosystems': ecosystems,
        'has_dockerfile': dockerfile,
        'has_compose': compose,
        'git': {'present': git, 'commits': commits},
    }


def decide(f):
    """Правила выбора инструментов. Каждый инструмент — run + обоснование."""
    langs = f['languages']
    lang_keys = [l['key'] for l in langs]
    has_code = bool(langs)
    has_manifests = bool(f['manifests'])
    tools = {}

    # ---- SAST -------------------------------------------------------------
    packs = ['p/security-audit', 'p/secrets', 'p/owasp-top-ten']
    for k in lang_keys:
        if k in SEMGREP_PACKS and SEMGREP_PACKS[k] not in packs:
            packs.append(SEMGREP_PACKS[k])
    if f['has_dockerfile']:
        packs.append('p/docker')
    tools['semgrep'] = {
        'run': has_code, 'category': 'SAST',
        'reason': ('Обнаружен исходный код (%s); наборы правил: %s'
                   % (', '.join(l['name'] for l in langs), ', '.join(packs))) if has_code
                  else 'Исходный код поддерживаемых языков не обнаружен',
        'configs': packs if has_code else [],
    }
    cq = f['codeql_languages']
    tools['codeql'] = {
        'run': bool(cq), 'category': 'SAST',
        'reason': ('Языки с поддержкой анализа потока данных CodeQL: %s'
                   % ', '.join(cq)) if cq else
                  'Языки CodeQL в проекте не обнаружены (например, PHP CodeQL не поддерживает) — '
                  'SAST закрывает Semgrep',
        'languages': cq,
    }

    # ---- Secret scanning ---------------------------------------------------
    git_mode = f['git']['present'] and f['git']['commits'] > 0
    tools['gitleaks'] = {
        'run': True, 'category': 'Secrets',
        'mode': 'git' if git_mode else 'dir',
        'reason': 'Сканирование %s; детекторы по известным шаблонам ключей и generic-правилам'
                  % ('истории git (%d коммитов)' % f['git']['commits'] if git_mode
                     else 'рабочего дерева (история git недоступна)'),
    }
    tools['trufflehog'] = {
        'run': True, 'category': 'Secrets',
        'mode': 'git' if git_mode else 'filesystem',
        'reason': 'Второй, независимый набор детекторов сервисов (верификация отключена: '
                  'найденные значения не проверяются на стороне сервисов и не попадают в отчёт)',
    }

    # ---- SBOM ---------------------------------------------------------------
    tools['cdxgen'] = {
        'run': has_manifests, 'category': 'SBOM',
        'reason': ('Манифесты зависимостей: %s — SBOM строится из графа зависимостей исходного кода'
                   % ', '.join(f['manifests'])) if has_manifests
                  else 'Манифесты зависимостей не обнаружены — SBOM из исходного графа не построить',
    }
    tools['syft'] = {
        'run': True, 'category': 'SBOM',
        'reason': 'Инвентаризация файловой системы проекта целиком%s — покрывает пакеты ОС, '
                  'бинарные артефакты и зависимости вне манифестов'
                  % (', включая Docker-образ из Dockerfile' if f['has_dockerfile'] else ''),
    }

    # ---- SCA ----------------------------------------------------------------
    tools['osv-scanner'] = {
        'run': has_manifests, 'category': 'SCA',
        'reason': ('Экосистемы зависимостей: %s; сверка lock-файлов и манифестов с базой OSV'
                   % ', '.join(f['ecosystems'])) if has_manifests
                  else 'Зависимости по манифестам не заявлены — сверять с базой OSV нечего',
    }
    tools['grype'] = {
        'run': True, 'category': 'SCA',
        'reason': 'Анализ SBOM (Syft, при наличии — также cdxgen): уязвимости пакетов ОС и '
                  'зависимостей, не попавших в lock-файлы',
    }
    return tools


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--out', default='plan.json')
    args = ap.parse_args()
    target = Path(args.target).resolve()
    facts = scan(target)
    plan = {'target': str(target), 'facts': facts, 'tools': decide(facts)}
    Path(args.out).write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(plan, ensure_ascii=False, indent=2))

    gh_out = os.environ.get('GITHUB_OUTPUT')
    if gh_out:
        tools = plan['tools']
        with open(gh_out, 'a', encoding='utf-8') as fh:
            fh.write('plan<<EOF\n%s\nEOF\n' % json.dumps(plan, ensure_ascii=False))
            fh.write('codeql_matrix=%s\n' % json.dumps(
                [{'language': l} for l in tools['codeql']['languages']]))
            for name, t in tools.items():
                fh.write('%s=%s\n' % (name.replace('-', '_'), str(t['run']).lower()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
