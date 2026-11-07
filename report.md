# Отчёт проверки безопасности: vampi

**Дата:** 2026-11-07 18:05 UTC · **Ветка/коммит:** f16052d · **Языки:** Python

## Сводка

| Категория | Находок | Критических | Высоких | Средних | Низких |
|---|---:|---:|---:|---:|---:|
| SAST | 10 | 0 | 4 | 5 | 1 |
| Secrets | 1 | 0 | 1 | 0 | 0 |
| SCA | 29 | 1 | 16 | 12 | 0 |
| **Итого** | **40** | **1** | **21** | **17** | **1** |

## План проверки (выбранные инструменты)

| Инструмент | Категория | Решение | Обоснование |
|---|---|---|---|
| Semgrep | SAST | Запущен | Обнаружен исходный код (Python); наборы правил: p/security-audit, p/secrets, p/owasp-top-ten, p/python, p/docker |
| CodeQL | SAST | Запущен | Языки с поддержкой анализа потока данных CodeQL: python |
| Gitleaks | Secrets | Запущен | Сканирование истории git (68 коммитов); детекторы по известным шаблонам ключей и generic-правилам |
| TruffleHog | Secrets | Запущен | Второй, независимый набор детекторов сервисов (верификация отключена: найденные значения не проверяются на стороне сервисов и не попадают в отчёт) |
| cdxgen | SBOM | Запущен | Манифесты зависимостей: requirements.txt — SBOM строится из графа зависимостей исходного кода |
| Syft | SBOM | Запущен | Инвентаризация файловой системы проекта целиком, включая Docker-образ из Dockerfile — покрывает пакеты ОС, бинарные артефакты и зависимости вне манифестов |
| OSV-Scanner | SCA | Запущен | Экосистемы зависимостей: PyPI; сверка lock-файлов и манифестов с базой OSV |
| Grype | SCA | Запущен | Анализ SBOM (Syft, при наличии — также cdxgen): уязвимости пакетов ОС и зависимостей, не попавших в lock-файлы |

## Выполнение

| Инструмент | Категория | Статус | Находок (сырьё) |
|---|---|---|---:|
| Semgrep | SAST | Выполнен | 7 |
| CodeQL | SAST | Выполнен | 3 |
| Gitleaks | Secrets | Выполнен | 1 |
| TruffleHog | Secrets | Выполнен | 0 |
| OSV-Scanner | SCA | Выполнен | 82 |
| Grype | SCA | Выполнен | 15 |
| SBOM (cdxgen) | SBOM | Готов | компонентов: 30 (pypi: 26, github: 4) |
| SBOM (syft) | SBOM | Готов | компонентов: 13 (pypi: 7, github: 4, file: 2) |

## Находки

### Secrets (1)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0022 | Высокий | Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and  | `openapi_specs/openapi3.yml:181` | Gitleaks | — |

### SAST (10)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0002 | Высокий | GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be s | `.github/workflows/docker-image.yml:16` | Semgrep | — |
| F-0003 | Высокий | GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be s | `.github/workflows/docker-image.yml:19` | Semgrep | — |
| F-0004 | Высокий | GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be s | `.github/workflows/docker-image.yml:22` | Semgrep | — |
| F-0005 | Высокий | GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be s | `.github/workflows/docker-image.yml:28` | Semgrep | — |
| F-0023 | Средний | By not specifying a USER, a program in the container may run as 'root'. This is a security | `Dockerfile:16` | Semgrep | — |
| F-0024 | Средний | By not specifying a USER, a program in the container may run as 'root'. This is a security | `Dockerfile:17` | Semgrep | — |
| F-0025 | Средний | This part of the regular expression may cause exponential backtracking on strings starting | `api_views/users.py:145` | CodeQL | — |
| F-0026 | Средний | This [regular expression](1) that depends on a [user-provided value](2) may run slow on st | `api_views/users.py:146` | CodeQL | — |
| F-0027 | Средний | This [regular expression](1) that depends on a [user-provided value](2) may run slow on st | `api_views/users.py:163` | CodeQL | — |
| F-0040 | Низкий | Hardcoded variable `SECRET_KEY` detected. Use environment variables or config files instea | `config.py:13` | Semgrep | — |

### SCA (29)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0001 | Критический | PyJWT: Asymmetric-PEM detection bypass: whitespace/line-ending-mutated public keys skip th | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0006 | Высокий | PYSEC-2025-183 | `pyjwt@2.6.0` | OSV-Scanner | — |
| F-0007 | Высокий | PYSEC-2026-120 | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.12.0 |
| F-0008 | Высокий | PYSEC-2026-179 | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.13.0 |
| F-0009 | Высокий | PyJWT: PyJWKClient follows redirects when fetching JWKS | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0010 | Высокий | PyJWT: ReDoS vulnerability when calling the `is_pem_format` function. | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0011 | Высокий | PyJWT: Public keys in DER form are accepted as HMAC secrets, bypassing the CVE-2022-29217  | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0012 | Высокий | PYSEC-2026-4183 | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.15.0 |
| F-0013 | Высокий | PyJWT: HS256/384/512 verify accepts empty HMAC key via oct JWK (PyJWK/PyJWKClient) enablin | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0014 | Высокий | PYSEC-2023-62 | `flask@2.2.2` | OSV-Scanner, Grype | 2.3.2 |
| F-0015 | Высокий | PYSEC-2018-28 | `requests@2.9.2` | OSV-Scanner | 2.20.0 |
| F-0016 | Высокий | PYSEC-2023-74 | `requests@2.9.2` | OSV-Scanner | 2.31.0 |
| F-0017 | Высокий | Requests vulnerable to .netrc credentials leak via malicious URLs | `requests@2.9.2` | OSV-Scanner | 2.32.4 |
| F-0018 | Высокий | Requests `Session` object does not verify requests after making first request with verify= | `requests@2.9.2` | OSV-Scanner | 2.32.0 |
| F-0019 | Высокий | PYSEC-2026-2275 | `requests@2.9.2` | OSV-Scanner | 2.33.0 |
| F-0020 | Высокий | PYSEC-2023-221 | `werkzeug@2.2.3` | OSV-Scanner | 3.0.1 |
| F-0021 | Высокий | Werkzeug debugger vulnerable to remote execution when interacting with attacker controlled | `werkzeug@2.2.3` | OSV-Scanner | 3.0.3 |
| F-0028 | Средний | PYSEC-2026-175 | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.13.0 |
| F-0029 | Средний | PYSEC-2026-177 | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.13.0 |
| F-0030 | Средний | PyJWT: PyJWKClient still amplifies unauthenticated JWKS fetches on unknown kid values (inc | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0031 | Средний | PyJWT: Unauthenticated RecursionError DoS in pre-verification payload parse (PyJWKClient.g | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.15.0 |
| F-0032 | Средний | PyJWT: Non-canonical signature segments enable raw-token revocation bypass | `pyjwt@2.6.0` | OSV-Scanner, Grype | 2.14.0 |
| F-0033 | Средний | PYSEC-2026-2151 | `flask@2.2.2` | OSV-Scanner, Grype | 3.1.3 |
| F-0034 | Средний |  Werkzeug safe_join() allows Windows special device names with compound extensions | `werkzeug@2.2.3` | OSV-Scanner | 3.1.5 |
| F-0035 | Средний | Werkzeug safe_join not safe on Windows | `werkzeug@2.2.3` | OSV-Scanner | 3.0.6 |
| F-0036 | Средний | Werkzeug safe_join() allows Windows special device names | `werkzeug@2.2.3` | OSV-Scanner | 3.1.4 |
| F-0037 | Средний | PYSEC-2026-2320 | `werkzeug@2.2.3` | OSV-Scanner | 3.1.6 |
| F-0038 | Средний | Werkzeug possible resource exhaustion when parsing file data in forms | `werkzeug@2.2.3` | OSV-Scanner | 3.0.6 |
| F-0039 | Средний | Werkzeug safe_join() allows Windows special device names | `werkzeug@2.2.3` | OSV-Scanner | 3.1.9 |

## Что делать дальше

1. **Secrets** — отозвать и перевыпустить значения, удалить из истории git.
2. **SAST критического и высокого уровня** — исправить до слияния в основную ветку.
3. **SCA** — обновить пакеты до версий из колонки «Исправление»; для недоступных обновлений зафиксировать оценку риска.
4. Повторить проверку: пайплайн запускается на каждый pull request.
