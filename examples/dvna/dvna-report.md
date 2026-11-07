# Отчёт проверки безопасности: dvna

**Дата:** 2026-11-07 19:04 UTC · **Ветка/коммит:** 37cf045cae9261457fcc429288d47c4fc1e1f793 · **Языки:** JavaScript/TypeScript, Shell

## Сводка

| Категория | Находок | Критических | Высоких | Средних | Низких |
|---|---:|---:|---:|---:|---:|
| SAST | 39 | 0 | 4 | 34 | 1 |
| Secrets | 0 | 0 | 0 | 0 | 0 |
| SCA | 66 | 16 | 27 | 21 | 2 |
| **Итого** | **105** | **16** | **31** | **55** | **3** |

## План проверки (выбранные инструменты)

| Инструмент | Категория | Решение | Обоснование |
|---|---|---|---|
| Semgrep | SAST | Запущен | Обнаружен исходный код (JavaScript/TypeScript, Shell); наборы правил: p/security-audit, p/secrets, p/owasp-top-ten, p/javascript, p/docker |
| CodeQL | SAST | Запущен | Языки с поддержкой анализа потока данных CodeQL: javascript-typescript |
| Gitleaks | Secrets | Запущен | Сканирование истории git (42 коммитов); детекторы по известным шаблонам ключей и generic-правилам |
| TruffleHog | Secrets | Запущен | Второй, независимый набор детекторов сервисов (верификация отключена: найденные значения не проверяются на стороне сервисов и не попадают в отчёт) |
| cdxgen | SBOM | Запущен | Манифесты зависимостей: package.json — SBOM строится из графа зависимостей исходного кода |
| Syft | SBOM | Запущен | Инвентаризация файловой системы проекта целиком, включая Docker-образ из Dockerfile — покрывает пакеты ОС, бинарные артефакты и зависимости вне манифестов |
| OSV-Scanner | SCA | Запущен | Экосистемы зависимостей: npm; сверка lock-файлов и манифестов с базой OSV |
| Grype | SCA | Запущен | Анализ SBOM (Syft, при наличии — также cdxgen): уязвимости пакетов ОС и зависимостей, не попавших в lock-файлы |

## Выполнение

| Инструмент | Категория | Статус | Находок (сырьё) |
|---|---|---|---:|
| Semgrep | SAST | Выполнен | 12 |
| CodeQL | SAST | Выполнен | 33 |
| Gitleaks | Secrets | Выполнен | 0 |
| TruffleHog | Secrets | Выполнен | 0 |
| OSV-Scanner | SCA | Нет отчёта | 0 |
| Grype | SCA | Выполнен | 66 |
| SBOM (cdxgen) | SBOM | Готов | компонентов: 317 (npm: 312, composer: 5) |
| SBOM (syft) | SBOM | Готов | компонентов: 333 (npm: 311, github: 11, composer: 5, file: 6) |

## Находки

### SAST (39)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0017 | Высокий | Detected a sequelize statement that is tainted by user-input. This could lead to SQL injec | `target/core/appHandler.js:11` | Semgrep | — |
| F-0018 | Высокий | The following function call serialize.unserialize accepts user controlled data which can r | `target/core/appHandler.js:218` | Semgrep | — |
| F-0019 | Высокий | The libxml library processes user-input with the `noent` attribute is set to `true` which  | `target/core/appHandler.js:235` | Semgrep | — |
| F-0020 | Высокий | A hard-coded credential was detected. It is not recommended to store credentials in source | `target/server.js:24` | Semgrep | — |
| F-0048 | Средний | This query string depends on a [user-provided value](1). | `core/appHandler.js:11` | CodeQL | — |
| F-0049 | Средний | Untrusted URL redirection depends on a [user-provided value](1). | `core/appHandler.js:188` | CodeQL | — |
| F-0050 | Средний | This code execution depends on a [user-provided value](1). | `core/appHandler.js:218` | CodeQL | — |
| F-0051 | Средний | XML parsing depends on a [user-provided value](1) without guarding against external entity | `core/appHandler.js:235` | CodeQL | — |
| F-0052 | Средний | This command line depends on a [user-provided value](1). | `core/appHandler.js:39` | CodeQL | — |
| F-0053 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:10` | CodeQL | — |
| F-0054 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:16` | CodeQL | — |
| F-0055 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:22` | CodeQL | — |
| F-0056 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:26` | CodeQL | — |
| F-0057 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:28` | CodeQL | — |
| F-0058 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:30` | CodeQL | — |
| F-0059 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:32` | CodeQL | — |
| F-0060 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:36` | CodeQL | — |
| F-0061 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:42` | CodeQL | — |
| F-0062 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:44` | CodeQL | — |
| F-0063 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:50` | CodeQL | — |
| F-0064 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:52` | CodeQL | — |
| F-0065 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:54` | CodeQL | — |
| F-0066 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:56` | CodeQL | — |
| F-0067 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:58` | CodeQL | — |
| F-0068 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:6` | CodeQL | — |
| F-0069 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:60` | CodeQL | — |
| F-0070 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:62` | CodeQL | — |
| F-0071 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:64` | CodeQL | — |
| F-0072 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:10` | CodeQL | — |
| F-0073 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:14` | CodeQL | — |
| F-0074 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:32` | CodeQL | — |
| F-0075 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:36` | CodeQL | — |
| F-0076 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:6` | CodeQL | — |
| F-0077 | Средний | Sensitive cookie sent without enforcing SSL encryption. | `server.js:23` | CodeQL | — |
| F-0078 | Средний | By not specifying a USER, a program in the container may run as 'root'. This is a security | `target/Dockerfile:13` | Semgrep | — |
| F-0079 | Средний | The application redirects to a URL specified by user-supplied input `req` that is not vali | `target/core/appHandler.js:188` | Semgrep | — |
| F-0080 | Средний | Cross-site scripting vulnerability due to [user-provided value](1). | `views/app/products.ejs:20` | CodeQL | — |
| F-0081 | Средний | Script loaded from content delivery network with no integrity check. | `views/common/head.ejs:11` | CodeQL | — |
| F-0103 | Низкий | Don’t use the default session cookie name Using the default session cookie name can open y | `target/server.js:23` | Semgrep | — |

### SCA (66)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0001 | Критический | An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data pa | `node-serialize@0.0.4` | Grype | — |
| F-0002 | Критический | The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side t | `ejs@2.7.4` | Grype | 3.1.7 |
| F-0003 | Критический | This affects the package express-fileupload before 1.1.8. If the parseNested option is ena | `express-fileupload@0.4.0` | Grype | 1.1.9 |
| F-0004 | Критический | Versions of the package mysql2 before 3.9.4 are vulnerable to Remote Code Execution (RCE)  | `mysql2@1.7.0` | Grype | 3.9.4 |
| F-0005 | Критический | math.js before 3.17.0 had an arbitrary code execution in the JavaScript engine. Creating a | `mathjs@3.10.1` | Grype | 3.17.0 |
| F-0006 | Критический | Use of Insufficiently Random Values vulnerability in form-data allows HTTP Parameter Pollu | `form-data@2.3.3` | Grype | 2.5.4 |
| F-0007 | Критический | math.js before 3.17.0 had an issue where private properties such as a constructor could be | `mathjs@3.10.1` | Grype | 3.17.0 |
| F-0008 | Критический | Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exist | `sequelize@4.44.4` | Grype | 6.19.1 |
| F-0009 | Критический | libxmljs is vulnerable to a type confusion vulnerability when parsing a specially crafted  | `libxmljs@0.19.10` | Grype | — |
| F-0010 | Критический | libxmljs is vulnerable to a type confusion vulnerability when parsing a specially crafted  | `libxmljs@0.19.10` | Grype | — |
| F-0011 | Критический | Versions of the package mysql2 before 3.9.7 are vulnerable to Arbitrary Code Injection due | `mysql2@1.7.0` | Grype | 3.9.7 |
| F-0012 | Критический | Due to improper artibute filtering in the sequalize js library, can a attacker peform SQL  | `sequelize@4.44.4` | Grype | 6.29.0 |
| F-0013 | Критический | Due to improper parameter filtering in the sequalize js library, can a attacker peform inj | `sequelize@4.44.4` | Grype | 6.28.1 |
| F-0014 | Критический | Sequelize is a Node.js ORM tool. Prior to 6.37.4, SQL injection is possible with strings o | `sequelize@4.44.4` | Grype | 6.37.4 |
| F-0015 | Критический | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.19, node-tar does | `tar@2.2.2` | Grype | 7.5.19 |
| F-0016 | Критический | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.19, node-tar does | `tar@6.2.1` | Grype | 7.5.19 |
| F-0021 | Высокий | The npm package "tar" (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a | `tar@2.2.2` | Grype | 3.2.2 |
| F-0022 | Высокий | The package mathjs before 7.5.1 are vulnerable to Prototype Pollution via the deepExtend f | `mathjs@3.10.1` | Grype | 7.5.1 |
| F-0023 | Высокий | This affects all versions of package dicer. A malicious attacker can send a modified form  | `dicer@0.2.5` | Grype | — |
| F-0024 | Высокий | Versions of the package mysql2 before 3.9.8 are vulnerable to Prototype Pollution due to i | `mysql2@1.7.0` | Grype | 3.9.8 |
| F-0025 | Высокий | typed-function before 0.10.6 had an arbitrary code execution in the JavaScript engine. Cre | `typed-function@0.10.5` | Grype | 0.10.6 |
| F-0026 | Высокий | An arbitrary file write vulnerability in Express-FileUpload v1.3.1 allows attackers to upl | `express-fileupload@0.4.0` | Grype | — |
| F-0027 | Высокий | The npm package "tar" (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbi | `tar@2.2.2` | Grype | 4.4.18 |
| F-0028 | Высокий | form-data is a library for creating readable multipart/form-data streams. In versions thro | `form-data@2.3.3` | Grype | 2.5.6 |
| F-0029 | Высокий | node-tar,a Tar for Node.js, contains a vulnerability in versions prior to 7.5.7 where the  | `tar@2.2.2` | Grype | 7.5.7 |
| F-0030 | Высокий | node-tar,a Tar for Node.js, contains a vulnerability in versions prior to 7.5.7 where the  | `tar@6.2.1` | Grype | 7.5.7 |
| F-0031 | Высокий | Versions of the package validator before 13.15.22 are vulnerable to Incomplete Filtering o | `validator@10.11.0` | Grype | 13.15.22 |
| F-0032 | Высокий | node-tar is a full-featured Tar for Node.js. Prior to version 7.5.10, tar can be tricked i | `tar@2.2.2` | Grype | 7.5.10 |
| F-0033 | Высокий | node-tar is a full-featured Tar for Node.js. Prior to version 7.5.10, tar can be tricked i | `tar@6.2.1` | Grype | 7.5.10 |
| F-0034 | Высокий | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.21, node-tar's fi | `tar@2.2.2` | Grype | 7.5.21 |
| F-0035 | Высокий | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.21, node-tar's fi | `tar@6.2.1` | Grype | 7.5.21 |
| F-0036 | Высокий | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.18, tar.replace a | `tar@2.2.2` | Grype | 7.5.18 |
| F-0037 | Высокий | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.18, tar.replace a | `tar@6.2.1` | Grype | 7.5.18 |
| F-0038 | Высокий | A vulnerability exists in the libxmljs 1.0.11 when parsing a specially crafted XML documen | `libxmljs@0.19.10` | Grype | — |
| F-0039 | Высокий | node-tar is a Tar for Node.js. The node-tar library (<= 7.5.2) fails to sanitize the linkp | `tar@2.2.2` | Grype | 7.5.3 |
| F-0040 | Высокий | node-tar is a Tar for Node.js. The node-tar library (<= 7.5.2) fails to sanitize the linkp | `tar@6.2.1` | Grype | 7.5.3 |
| F-0041 | Высокий | node-tar is a full-featured Tar for Node.js. When using default options in versions 7.5.7  | `tar@2.2.2` | Grype | 7.5.8 |
| F-0042 | Высокий | node-tar is a full-featured Tar for Node.js. When using default options in versions 7.5.7  | `tar@6.2.1` | Grype | 7.5.8 |
| F-0043 | Высокий | node-tar is a full-featured Tar for Node.js. Prior to version 7.5.11, tar (npm) can be tri | `tar@2.2.2` | Grype | 7.5.11 |
| F-0044 | Высокий | node-tar is a full-featured Tar for Node.js. Prior to version 7.5.11, tar (npm) can be tri | `tar@6.2.1` | Grype | 7.5.11 |
| F-0045 | Высокий | node-tar,a Tar for Node.js, has a race condition vulnerability in versions up to and inclu | `tar@2.2.2` | Grype | 7.5.4 |
| F-0046 | Высокий | node-tar,a Tar for Node.js, has a race condition vulnerability in versions up to and inclu | `tar@6.2.1` | Grype | 7.5.4 |
| F-0047 | Высокий | GHSA-3f6p-5ww8-9rcr | `mysql2@1.7.0` | Grype | 3.22.0 |
| F-0082 | Средний | Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution du | `tough-cookie@2.5.0` | Grype | 4.1.3 |
| F-0083 | Средний | validator.js is vulnerable to Inefficient Regular Expression Complexity | `validator@10.11.0` | Grype | 13.7.0 |
| F-0084 | Средний | Versions of the package mysql2 before 3.9.4 are vulnerable to Prototype Poisoning due to i | `mysql2@1.7.0` | Grype | 3.9.4 |
| F-0085 | Средний | This affects the package passport before 0.6.0. When a user logs in or logs out, the sessi | `passport@0.4.1` | Grype | 0.6.0 |
| F-0086 | Средний | node-tar is a Tar for Node.js. node-tar prior to version 6.2.1 has no limit on the number  | `tar@2.2.2` | Grype | 6.2.1 |
| F-0087 | Средний | Versions of the package mysql2 before 3.9.3 are vulnerable to Improper Input Validation th | `mysql2@1.7.0` | Grype | 3.9.3 |
| F-0088 | Средний | Data is truncated wrong when its length is greater than 255 bytes. | `bcrypt@1.0.3` | Grype | 5.0.0 |
| F-0089 | Средний | The Request package through 2.88.1 for Node.js allows a bypass of SSRF mitigations via an  | `request@2.88.2` | Grype | — |
| F-0090 | Средний | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.18, node-tar coer | `tar@2.2.2` | Grype | 7.5.18 |
| F-0091 | Средний | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.18, node-tar coer | `tar@6.2.1` | Grype | 7.5.18 |
| F-0092 | Средний | The ejs (aka Embedded JavaScript templates) package before 3.1.10 for Node.js lacks certai | `ejs@2.7.4` | Grype | 3.1.10 |
| F-0093 | Средний | Due to improper input filtering in the sequalize js library, can malicious queries lead to | `sequelize@4.44.4` | Grype | 6.28.1 |
| F-0094 | Средний | Improper Input Validation vulnerability in qs (parse modules) allows HTTP DoS.This issue a | `qs@6.5.5` | Grype | 6.14.1 |
| F-0095 | Средний | ### Summary



`qs.stringify` throws a `TypeError` when it serializes an object whose own  | `qs@6.5.5` | Grype | 6.16.0 |
| F-0096 | Средний | uuid is for the creation of RFC9562 (formerly RFC4122) UUIDs. Prior to 14.0.0, v3, v5, and | `uuid@3.4.0` | Grype | 11.1.1 |
| F-0097 | Средний | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.17, node-tar does | `tar@2.2.2` | Grype | 7.5.17 |
| F-0098 | Средний | node-tar is a tar archive manipulation library for Node.js. Prior to 7.5.17, node-tar does | `tar@6.2.1` | Grype | 7.5.17 |
| F-0099 | Средний | A URL validation bypass vulnerability exists in validator.js through version 13.15.15. The | `validator@10.11.0` | Grype | 13.15.20 |
| F-0100 | Средний | node-tar is a full-featured Tar for Node.js. Prior to 7.5.16, tar (node-tar) applies a PAX | `tar@2.2.2` | Grype | 7.5.16 |
| F-0101 | Средний | node-tar is a full-featured Tar for Node.js. Prior to 7.5.16, tar (node-tar) applies a PAX | `tar@6.2.1` | Grype | 7.5.16 |
| F-0102 | Средний | GHSA-rgwj-5xj2-c3m3 | `mysql2@1.7.0` | Grype | 3.23.1 |
| F-0104 | Низкий | cookie is a basic HTTP cookie parser and serializer for HTTP servers. The cookie name coul | `cookie@0.4.0` | Grype | 0.7.0 |
| F-0105 | Низкий | GHSA-q3w9-g74q-vp5f | `express-fileupload@0.4.0` | Grype | 1.1.6-alpha.6 |

## Что делать дальше

1. **Secrets** — отозвать и перевыпустить значения, удалить из истории git.
2. **SAST критического и высокого уровня** — исправить до слияния в основную ветку.
3. **SCA** — обновить пакеты до версий из колонки «Исправление»; для недоступных обновлений зафиксировать оценку риска.
4. Повторить проверку: пайплайн запускается на каждый pull request.
