# Security Pipeline

Единый конвейер проверки безопасности проекта: **сам определяет языки и структуру
репозитория, выбирает применимые инструменты и сводит все находки в один отчёт** —
не «вывод каждого сканера по отдельности», а единый реестр уязвимостей проекта.

| Блок | Инструменты | Что даёт |
|---|---|---|
| SAST | Semgrep, CodeQL | недостатки кода: инъекции, XSS, XXE, десериализация, крипто |
| Secret scanning | Gitleaks, TruffleHog | секреты в коде и истории git (значения в отчёт не попадают) |
| SBOM | cdxgen, Syft | состав ПО в формате CycloneDX: граф зависимостей + файловая система |
| SCA | OSV-Scanner, Grype | уязвимые зависимости: lock-файлы по базе OSV + анализ SBOM |

Пайплайн соответствует этапам Pre-build / Build / Test-time схемы безопасной
разработки (локальные проверки → CI/CD → перед развёртыванием); контур Post-deploy
(WAF/RASP) находится вне репозитория и этим пайплайном не покрывается.

## Как это работает

```
checkout проекта
      │
      ▼
┌────────────────┐   plan.json: языки, экосистемы, манифесты, Dockerfile,
│  detect.py     │   история git → решение по каждому инструменту
└───────┬────────┘   (что запускать, каким набором правил и почему)
        │
 ┌──────┼───────────┬──────────────┬─────────────┐
 ▼      ▼           ▼              ▼             │
Secrets SAST        SBOM           │             │
Gitleaks Semgrep    cdxgen ──┐     │             │
Truffle- CodeQL*    Syft ────┼──► SCA: OSV-Scanner (lock-файлы)
Hog     (матрица    │        └──► SCA: Grype (по SBOM)
        по языкам)  │                          │
 └──────┴───────────┴──────────────┬───────────┘
                                    ▼
                    normalize_report.py: дедупликация
                    Semgrep×CodeQL, Gitleaks×TruffleHog, OSV×Grype
                                    │
                  ┌─────────────────┼─────────────────┐
                  ▼                 ▼                 ▼
             report.html       report.md        findings.json
             (автономный,   (Job Summary,     (единый реестр,
              с фильтрами)    репозиторий)     машиночитаемый)
                                    │
                              quality gate (fail_on)
```
\* CodeQL запускается отдельной job на каждый поддерживаемый язык проекта
(динамическая матрица из plan.json).

## Логика выбора инструментов

| Условие (из detect.py) | Решение |
|---|---|
| Есть исходный код | Semgrep, наборы правил: `p/security-audit`, `p/secrets`, `p/owasp-top-ten` + языковые (`p/python`, `p/javascript`, `p/java`, …) + `p/docker` при Dockerfile |
| Язык поддерживается CodeQL (JS/TS, Python, Java/Kotlin, Ruby, C#, Go, C/C++, Swift) | CodeQL по этому языку; для PHP CodeQL не запускается — SAST закрывает Semgrep |
| Любой проект | Gitleaks + TruffleHog: два независимых набора детекторов; режим `git` при истории, иначе `dir`/`filesystem` |
| Есть манифесты зависимостей | cdxgen строит SBOM из графа; OSV-Scanner сверяет lock-файлы с базой OSV |
| Всегда | Syft инвентаризирует файловую систему (пакеты ОС, бинарники, зависимости вне манифестов); Grype анализирует SBOM |

Оба инструмента блока запускаются, когда применимы оба: Semgrep даёт широту и
скорость, CodeQL — анализ потока данных; Gitleaks силён в generic-шаблонах,
TruffleHog — в детекторах конкретных сервисов; OSV точен по lock-файлам экосистем,
Grype покрывает то, что в lock-файлы не попало. Пересечения убирает дедупликация:
одна уязвимость пакета от OSV и Grype — одна строка отчёта с двумя источниками.

## Запуск

### В GitHub Actions

Workflow: `.github/workflows/security-pipeline.yml`.

* **push / pull request** — проверяется репозиторий, где лежит workflow;
* **Actions → Security Pipeline → Run workflow** — можно указать любой
  `target_repository` (owner/repo), `target_ref` и порог quality gate.

Результаты: артефакт **security-report** (`report.html`, `report.md`,
`findings.json`, `plan.json`), сырые отчёты сканеров — артефакты `raw-*`,
сводка — прямо в Job Summary запуска.

### Локально

Требуется Python 3.10+ и установленные сканеры в PATH
(CodeQL — не менее 8 ГБ RAM; на CI-раннере это условие выполняется).

```bash
scripts/run_local.sh <путь-к-проекту | git-url> [каталог-результатов]
GATE=high scripts/run_local.sh ./my-project   # падать при высоких находках
```

## Единый отчёт

Каждая находка реестра: категория (SAST / Secrets / SCA), уровень
(critical / high / medium / low), CWE или CVE, файл и строка (или пакет и версия),
источники (какие инструменты подтвердили), исправленная версия для SCA и
рекомендация. Значения секретов в отчёт не включаются: Gitleaks работает с
`--redact`, вывод TruffleHog очищается до детектора, файла и коммита.

**Quality gate** (`fail_on`): `none` — только отчёт; `medium` / `high` /
`critical` — job завершается ошибкой, если есть находки не ниже порога.

## Проверка на проекте из стенда: DVNA

Для демонстрации взят один репозиторий из перечня уязвимых приложений —
[appsecco/dvna](https://github.com/appsecco/dvna) (Node.js/Express).
Детектор определил JavaScript/TypeScript и Shell, экосистему npm и Dockerfile,
поэтому запустились все четыре блока (семь инструментов локально; SARIF CodeQL
для этого проекта взят из прогона GitHub Actions — анализатору в локальной
песочнице с 2 ГБ RAM не хватает памяти, на раннере workflow он выполняется штатно).

Итог единого отчёта (`examples/dvna/`): **149 находок** после дедупликации —
SAST 39, SCA 110, секретов не найдено; критических 16, высоких 60.
OSV-Scanner и Grype подтвердили друг друга по 65 уязвимостям пакетов,
ещё 44 дал только OSV (транзитивные зависимости из lock-файла) — это и есть
эффект парного SCA. SBOM: cdxgen — 312 компонентов графа, Syft — 327 с учётом
файловой системы.

### Второй прогон: VAmPI (Python)

Тот же пайплайн без единой правки конфигурации запущен на
[erev0s/VAmPI](https://github.com/erev0s/VAmPI) (Python/Flask) — `examples/vampi/`:
детектор выбрал наборы `p/python`, CodeQL `python`, экосистему PyPI по
`requirements.txt`. Итог: **40 находок** — SAST 10 (включая ReDoS от CodeQL в
`api_views/users.py`), Secrets 1 (JWT в `openapi_specs/openapi3.yml`, Gitleaks;
захардкоженный `SECRET_KEY` в `config.py` дополнительно отметил Semgrep),
SCA 29 (OSV-Scanner и Grype пересекаются по 15, ещё 14 — только OSV).
SBOM: cdxgen — 30 компонентов, Syft — 13 (только файловая система без
установленных пакетов).

### Пример решения детектора: DVWA (PHP)

На PHP-проекте DVWA план выглядит иначе без ручных настроек: Semgrep получает
пакет `p/php`, а CodeQL выбирается только для JavaScript- и Python-файлов
проекта — PHP-часть статическим анализом закрывает Semgrep, потому что запросов
CodeQL для PHP не существует. Именно так пайплайн адаптируется к стеку:
инструмент не «запускается всегда», а назначается по языкам и структуре.

## Структура репозитория

```
.github/workflows/security-pipeline.yml   # конвейер GitHub Actions (7 job)
scripts/detect.py                          # анализ проекта → plan.json + outputs
scripts/normalize_report.py                # сырьё сканеров → единый отчёт
scripts/run_local.sh                       # локальное зеркало workflow
config/gitleaks.toml                       # правила Gitleaks и allowlist
examples/dvna/                             # демо-отчёт по DVNA (html/md/json)
```

## Соответствие заданию

| Требование | Реализация |
|---|---|
| SAST | Semgrep + CodeQL, выбор по языкам проекта |
| SCA | OSV-Scanner (lock-файлы) + Grype (по SBOM) |
| Secret scanning | Gitleaks + TruffleHog, история git, redact |
| Сборщик SBOM | cdxgen (граф зависимостей) + Syft (файловая система), CycloneDX |
| Каталог инструментов и матрица выбора | таблица «Логика выбора инструментов» + plan.json каждого запуска |
| Перечень уязвимых приложений | проекты стенда sast-check; для демонстрации — DVNA |
| Итог проверки проекта | единый отчёт: сводка, план, находки, рекомендации, quality gate |
