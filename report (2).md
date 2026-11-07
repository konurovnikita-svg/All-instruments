# Отчёт проверки безопасности: dvna

**Дата:** 2026-11-07 18:01 UTC · **Ветка/коммит:** 9ba473a · **Языки:** JavaScript/TypeScript, Shell

## Сводка

| Категория | Находок | Критических | Высоких | Средних | Низких |
|---|---:|---:|---:|---:|---:|
| SAST | 39 | 0 | 4 | 34 | 1 |
| Secrets | 0 | 0 | 0 | 0 | 0 |
| SCA | 110 | 16 | 56 | 38 | 0 |
| **Итого** | **149** | **16** | **60** | **72** | **1** |

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
| OSV-Scanner | SCA | Выполнен | 109 |
| Grype | SCA | Выполнен | 66 |
| SBOM (cdxgen) | SBOM | Готов | компонентов: 312 (npm: 312) |
| SBOM (syft) | SBOM | Готов | компонентов: 327 (npm: 311, github: 11, file: 5) |

## Находки

### SAST (39)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0017 | Высокий | Detected a sequelize statement that is tainted by user-input. This could lead to SQL injec | `core/appHandler.js:11` | Semgrep | — |
| F-0018 | Высокий | The following function call serialize.unserialize accepts user controlled data which can r | `core/appHandler.js:218` | Semgrep | — |
| F-0019 | Высокий | The libxml library processes user-input with the `noent` attribute is set to `true` which  | `core/appHandler.js:235` | Semgrep | — |
| F-0020 | Высокий | A hard-coded credential was detected. It is not recommended to store credentials in source | `server.js:24` | Semgrep | — |
| F-0077 | Средний | By not specifying a USER, a program in the container may run as 'root'. This is a security | `Dockerfile:13` | Semgrep | — |
| F-0078 | Средний | This query string depends on a [user-provided value](1). | `core/appHandler.js:11` | CodeQL | — |
| F-0079 | Средний | The application redirects to a URL specified by user-supplied input `req` that is not vali | `core/appHandler.js:188` | Semgrep | — |
| F-0080 | Средний | Untrusted URL redirection depends on a [user-provided value](1). | `core/appHandler.js:188` | CodeQL | — |
| F-0081 | Средний | This code execution depends on a [user-provided value](1). | `core/appHandler.js:218` | CodeQL | — |
| F-0082 | Средний | XML parsing depends on a [user-provided value](1) without guarding against external entity | `core/appHandler.js:235` | CodeQL | — |
| F-0083 | Средний | This command line depends on a [user-provided value](1). | `core/appHandler.js:39` | CodeQL | — |
| F-0084 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:10` | CodeQL | — |
| F-0085 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:16` | CodeQL | — |
| F-0086 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:22` | CodeQL | — |
| F-0087 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:26` | CodeQL | — |
| F-0088 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:28` | CodeQL | — |
| F-0089 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:30` | CodeQL | — |
| F-0090 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:32` | CodeQL | — |
| F-0091 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:36` | CodeQL | — |
| F-0092 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:42` | CodeQL | — |
| F-0093 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:44` | CodeQL | — |
| F-0094 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:50` | CodeQL | — |
| F-0095 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:52` | CodeQL | — |
| F-0096 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:54` | CodeQL | — |
| F-0097 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:56` | CodeQL | — |
| F-0098 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:58` | CodeQL | — |
| F-0099 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:6` | CodeQL | — |
| F-0100 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:60` | CodeQL | — |
| F-0101 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:62` | CodeQL | — |
| F-0102 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/app.js:64` | CodeQL | — |
| F-0103 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:10` | CodeQL | — |
| F-0104 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:14` | CodeQL | — |
| F-0105 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:32` | CodeQL | — |
| F-0106 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:36` | CodeQL | — |
| F-0107 | Средний | This route handler performs [authorization](1), but is not rate-limited. | `routes/main.js:6` | CodeQL | — |
| F-0108 | Средний | Sensitive cookie sent without enforcing SSL encryption. | `server.js:23` | CodeQL | — |
| F-0109 | Средний | Cross-site scripting vulnerability due to [user-provided value](1). | `views/app/products.ejs:20` | CodeQL | — |
| F-0110 | Средний | Script loaded from content delivery network with no integrity check. | `views/common/head.ejs:11` | CodeQL | — |
| F-0149 | Низкий | Don’t use the default session cookie name Using the default session cookie name can open y | `server.js:23` | Semgrep | — |

### SCA (110)

| ID | Уровень | Что найдено | Где | Источники | Исправление |
|---|---|---|---|---|---|
| F-0001 | Критический | ejs template injection vulnerability | `ejs@2.7.4` | OSV-Scanner, Grype | 3.1.7 |
| F-0002 | Критический | Prototype Pollution in express-fileupload | `express-fileupload@0.4.0` | OSV-Scanner, Grype | 1.1.9 |
| F-0003 | Критический | form-data uses unsafe random function in form-data for choosing boundary | `form-data@2.3.3` | OSV-Scanner, Grype | 4.0.4 |
| F-0004 | Критический | libxmljs vulnerable to type confusion when parsing specially crafted XML | `libxmljs@0.19.10` | OSV-Scanner, Grype | — |
| F-0005 | Критический | libxmljs vulnerable to type confusion when parsing specially crafted XML  | `libxmljs@0.19.10` | OSV-Scanner, Grype | — |
| F-0006 | Критический | Arbitrary Code Execution in mathjs | `mathjs@3.10.1` | OSV-Scanner, Grype | 3.17.0 |
| F-0007 | Критический | Arbitrary Code Execution in mathjs | `mathjs@3.10.1` | OSV-Scanner, Grype | 3.17.0 |
| F-0008 | Критический | MySQL2 for Node Arbitrary Code Injection | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.9.7 |
| F-0009 | Критический | mysql2 Remote Code Execution (RCE) via the readCodeFor function | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.9.4 |
| F-0010 | Критический | Code Execution through IIFE in node-serialize | `node-serialize@0.0.4` | OSV-Scanner, Grype | — |
| F-0011 | Критический | Sequelize - Default support for “raw attributes” when using parentheses | `sequelize@4.44.4` | OSV-Scanner, Grype | 6.29.0 |
| F-0012 | Критический | Sequelize: SQL Injection (Oracle DB) | `sequelize@4.44.4` | OSV-Scanner, Grype | 6.37.4 |
| F-0013 | Критический | Unsafe fall-through in getWhereConditions | `sequelize@4.44.4` | OSV-Scanner, Grype | 7.0.0-alpha.20 |
| F-0014 | Критический | Sequelize vulnerable to SQL Injection via replacements | `sequelize@4.44.4` | OSV-Scanner, Grype | 6.19.1 |
| F-0015 | Критический | node-tar: Decompression/parse DoS via unlimited input | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.19 |
| F-0016 | Критический | node-tar: Decompression/parse DoS via unlimited input | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.19 |
| F-0021 | Высокий | CVE-2018-14404 | `@` | OSV-Scanner | — |
| F-0022 | Высокий | CVE-2018-14567 | `@` | OSV-Scanner | 2240fbf5912054af025fb6e01e26375100275e74 |
| F-0023 | Высокий | CVE-2018-9251 | `@` | OSV-Scanner | — |
| F-0024 | Высокий | CVE-2019-19956 | `@` | OSV-Scanner | 5a02583c7e683896d84878bd90641d8d9b0d0549 |
| F-0025 | Высокий | CVE-2021-3517 | `@` | OSV-Scanner | e1bcffea180d6cc0651757bb64284a763e0e2239 |
| F-0026 | Высокий | CVE-2021-3518 | `@` | OSV-Scanner | e1bcffea180d6cc0651757bb64284a763e0e2239 |
| F-0027 | Высокий | CVE-2021-3537 | `@` | OSV-Scanner | e1bcffea180d6cc0651757bb64284a763e0e2239 |
| F-0028 | Высокий | CVE-2021-3541 | `@` | OSV-Scanner | e1bcffea180d6cc0651757bb64284a763e0e2239 |
| F-0029 | Высокий | CVE-2022-23308 | `@` | OSV-Scanner | a075d256fd9ff15590b86d981b75a50ead124fca |
| F-0030 | Высокий | CVE-2022-40303 | `@` | OSV-Scanner | c846986356fc149915a74972bf198abc266bc2c0 |
| F-0031 | Высокий | CVE-2022-40304 | `@` | OSV-Scanner | 1b41ec4e9433b05bb0376be4725804c54ef1d80b |
| F-0032 | Высокий | CVE-2022-49043 | `@` | OSV-Scanner | 5a19e21605398cef6a8b1452477a8705cb41562b |
| F-0033 | Высокий | CVE-2023-28484 | `@` | OSV-Scanner | 223cb03a5d27b1b2393b266a8657443d046139d6 |
| F-0034 | Высокий | CVE-2023-29469 | `@` | OSV-Scanner | 223cb03a5d27b1b2393b266a8657443d046139d6 |
| F-0035 | Высокий | CVE-2024-25062 | `@` | OSV-Scanner | e189e9945317ad4c8603fa2300d11d11f5e2e335 |
| F-0036 | Высокий | CVE-2024-34459 | `@` | OSV-Scanner | 0b6d8130737125ba45981d54be7f15fe398ad2e0 |
| F-0037 | Высокий | CVE-2024-56171 | `@` | OSV-Scanner | 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 |
| F-0038 | Высокий | CVE-2025-24928 | `@` | OSV-Scanner | 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 |
| F-0039 | Высокий | Libxml2: integer overflow in xmlbuildqname() leads to stack buffer overflow in libxml2 | `@` | OSV-Scanner | 4c6b2c3096b1da0d0780fe0b4f147e837140468d |
| F-0040 | Высокий | Stack overflow in libxml2 | `@` | OSV-Scanner | 677a42645ef22b5a50741bad5facf9d8a8bc6d21 |
| F-0041 | Высокий | Libxml2: libxml2: denial of service via uncontrolled recursion in xml catalog processing | `@` | OSV-Scanner | 3d840e17858de03a09fba8b202e3a89267d5795a |
| F-0042 | Высокий | CVE-2026-86138 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0043 | Высокий | CVE-2026-86139 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0044 | Высокий | CVE-2026-86140 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0045 | Высокий | CVE-2026-86142 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0046 | Высокий | CVE-2026-86143 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0047 | Высокий | Integer Overflow or Wraparound and Use of a Broken or Risky Cryptographic Algorithm in bcr | `bcrypt@1.0.3` | OSV-Scanner, Grype | 5.0.0 |
| F-0048 | Высокий | Crash in HeaderParser in dicer | `dicer@0.2.5` | OSV-Scanner, Grype | — |
| F-0049 | Высокий | Express-FileUpload Arbitrary File Overwrite | `express-fileupload@0.4.0` | OSV-Scanner, Grype | — |
| F-0050 | Высокий | form-data: CRLF injection in form-data via unescaped multipart field names and filenames | `form-data@2.3.3` | OSV-Scanner, Grype | 4.0.6 |
| F-0051 | Высокий | libxmljs has segmentation fault, potentially leading to a denial-of-service (DoS) | `libxmljs@0.19.10` | OSV-Scanner, Grype | — |
| F-0052 | Высокий | Prototype Pollution in mathjs | `mathjs@3.10.1` | OSV-Scanner, Grype | 7.5.1 |
| F-0053 | Высокий | MySQL2: Auth Plugin Downgrade to mysql_clear_password Leaks Plaintext Credentials | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.22.0 |
| F-0054 | Высокий | mysql2 vulnerable to Prototype Pollution | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.9.8 |
| F-0055 | Высокий | MySQL2: Unbounded zlib inflate in compressed MySQL protocol handler allows decompression-b | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.23.1 |
| F-0056 | Высокий | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.7 |
| F-0057 | Высокий | Arbitrary File Creation/Overwrite due to insufficient absolute path sanitization | `tar@2.2.2` | OSV-Scanner, Grype | 6.1.1 |
| F-0058 | Высокий | Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization | `tar@2.2.2` | OSV-Scanner, Grype | 6.1.9 |
| F-0059 | Высокий | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Ext | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.8 |
| F-0060 | Высокий | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient  | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.3 |
| F-0061 | Высокий | node-tar: Negative tar entry size causes infinite loop in archive replace | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.18 |
| F-0062 | Высокий | node-tar Symlink Path Traversal via Drive-Relative Linkpath | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.11 |
| F-0063 | Высокий | Denial of service while parsing a tar file due to lack of folders count validation | `tar@2.2.2` | OSV-Scanner, Grype | 6.2.1 |
| F-0064 | Высокий | tar has Hardlink Path Traversal via Drive-Relative Linkpath | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.10 |
| F-0065 | Высокий | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow D | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.21 |
| F-0066 | Высокий | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.4 |
| F-0067 | Высокий | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.7 |
| F-0068 | Высокий | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Ext | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.8 |
| F-0069 | Высокий | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient  | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.3 |
| F-0070 | Высокий | node-tar: Negative tar entry size causes infinite loop in archive replace | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.18 |
| F-0071 | Высокий | node-tar Symlink Path Traversal via Drive-Relative Linkpath | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.11 |
| F-0072 | Высокий | tar has Hardlink Path Traversal via Drive-Relative Linkpath | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.10 |
| F-0073 | Высокий | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow D | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.21 |
| F-0074 | Высокий | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.4 |
| F-0075 | Высокий | Arbitrary JavaScript Execution in typed-function | `typed-function@0.10.5` | OSV-Scanner, Grype | 0.10.6 |
| F-0076 | Высокий | Validator is Vulnerable to Incomplete Filtering of One or More Instances of Special Elemen | `validator@10.11.0` | OSV-Scanner, Grype | 13.15.22 |
| F-0111 | Средний | uuid is for the creation of RFC9562 (formerly RFC4122) UUIDs. Prior to 14.0.0, v3, v5, and | `uuid@3.4.0` | Grype | 11.1.1 |
| F-0112 | Средний | CVE-2016-3709 | `@` | OSV-Scanner | e1bcffea180d6cc0651757bb64284a763e0e2239 |
| F-0113 | Средний | CVE-2021-47996 | `@` | OSV-Scanner | 9d69b44ed3357b8069856083d39ee418cd10109b |
| F-0114 | Средний | CVE-2022-29824 | `@` | OSV-Scanner | 6c283d83eccd940bcde15634ac8c7f100e3caefd |
| F-0115 | Средний | Nokogiri before 1.13.9 Multiple Vulnerabilities via libxml2 | `@` | OSV-Scanner | 897759cc25b57ebf2754897e910c86931dec7d39 |
| F-0116 | Средний | CVE-2023-45322 | `@` | OSV-Scanner | — |
| F-0117 | Средний | Nokogiri before 1.14.3 Null Pointer Dereference via libxml2 | `@` | OSV-Scanner | e8d2f4a829c50e6ad4ccd1625cd094e3a24acf36 |
| F-0118 | Средний | CVE-2025-27113 | `@` | OSV-Scanner | 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 |
| F-0119 | Средний | CVE-2025-32414 | `@` | OSV-Scanner | 0e145ae4881c2a05ae00128a3bd90d76d4dadc4b |
| F-0120 | Средний | CVE-2025-32415 | `@` | OSV-Scanner | 0e145ae4881c2a05ae00128a3bd90d76d4dadc4b |
| F-0121 | Средний | Libxml2: stack buffer overflow in xmllint interactive shell command handling | `@` | OSV-Scanner | 74f3154320df8950eceae4951975cc9dfc3a254d |
| F-0122 | Средний | libxml2 xmlcatalog xmlParseSGMLCatalog recursion | `@` | OSV-Scanner | 3d840e17858de03a09fba8b202e3a89267d5795a |
| F-0123 | Средний | Libxml2: unbounded relaxng include recursion leading to stack overflow | `@` | OSV-Scanner | 3d840e17858de03a09fba8b202e3a89267d5795a |
| F-0124 | Средний | Libxml2: libxml2: denial of service via crafted xml catalogs | `@` | OSV-Scanner | 3d840e17858de03a09fba8b202e3a89267d5795a |
| F-0125 | Средний | Stack-Based Buffer Overflow in libxml2 | `@` | OSV-Scanner | c2e233fc1b341685fc99621b2768b503f777a72e |
| F-0126 | Средний | CVE-2026-86137 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0127 | Средний | CVE-2026-86141 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0128 | Средний | CVE-2026-86144 | `@` | OSV-Scanner | 96498992efa48d52b0e8b83058bd88dbdaf153c1 |
| F-0129 | Средний | cookie accepts cookie name, path, and domain with out of bounds characters | `cookie@0.4.0` | OSV-Scanner, Grype | 0.7.0 |
| F-0130 | Средний | ejs lacks certain pollution protection | `ejs@2.7.4` | OSV-Scanner, Grype | 3.1.10 |
| F-0131 | Средний | Denial of Service in express-fileupload | `express-fileupload@0.4.0` | OSV-Scanner, Grype | 1.1.6-alpha.6 |
| F-0132 | Средний | mysql2 vulnerable to Prototype Poisoning | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.9.4 |
| F-0133 | Средний | mysql2 cache poisoning vulnerability | `mysql2@1.7.0` | OSV-Scanner, Grype | 3.9.3 |
| F-0134 | Средний | Passport vulnerable to session regeneration when a users logs in or out | `passport@0.4.1` | OSV-Scanner, Grype | 0.6.0 |
| F-0135 | Средний | qs: Denial of Service via Attacker Controlled isBuffer | `qs@6.5.5` | OSV-Scanner, Grype | 6.16.0 |
| F-0136 | Средний | qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion | `qs@6.5.5` | OSV-Scanner, Grype | 6.14.1 |
| F-0137 | Средний | Server-Side Request Forgery in Request | `request@2.88.2` | OSV-Scanner, Grype | 3.0.0 |
| F-0138 | Средний | Sequelize information disclosure vulnerability | `sequelize@4.44.4` | OSV-Scanner, Grype | 7.0.0-alpha.20 |
| F-0139 | Средний | node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.17 |
| F-0140 | Средний | node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causin | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.16 |
| F-0141 | Средний | node-tar: Process crash via PAX numeric path type confusion | `tar@2.2.2` | OSV-Scanner, Grype | 7.5.18 |
| F-0142 | Средний | node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.17 |
| F-0143 | Средний | node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causin | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.16 |
| F-0144 | Средний | node-tar: Process crash via PAX numeric path type confusion | `tar@6.2.1` | OSV-Scanner, Grype | 7.5.18 |
| F-0145 | Средний | tough-cookie Prototype Pollution vulnerability | `tough-cookie@2.5.0` | OSV-Scanner, Grype | 4.1.3 |
| F-0146 | Средний | uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided | `uuid@3.4.0` | OSV-Scanner | 13.0.1 |
| F-0147 | Средний | validator.js has a URL validation bypass vulnerability in its isURL function | `validator@10.11.0` | OSV-Scanner, Grype | 13.15.20 |
| F-0148 | Средний | Inefficient Regular Expression Complexity in validator.js | `validator@10.11.0` | OSV-Scanner, Grype | 13.7.0 |

## Что делать дальше

1. **Secrets** — отозвать и перевыпустить значения, удалить из истории git.
2. **SAST критического и высокого уровня** — исправить до слияния в основную ветку.
3. **SCA** — обновить пакеты до версий из колонки «Исправление»; для недоступных обновлений зафиксировать оценку риска.
4. Повторить проверку: пайплайн запускается на каждый pull request.
