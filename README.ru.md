# AmuleD v0.5.1

AmuleD — переносимый консольный ED2K/Kademlia-клиент на Python 3.12. Это независимая clean-room реализация открытых протоколов ED2K и Kademlia.

Текущий майлстоун включает полностью работающий **Kademlia-поиск (KAD) по ключевым словам в живой сети eMule** (200 реальных результатов по запросу «video» примерно за секунду), живую ED2K TCP-сессию с сервером и поиском, полный download-стек (очередь, part-файлы, верификация MD4), слой пирингового протокола, IP-фильтр и автоблокировку серверов, а также хранилище результатов поиска в DuckDB.

**Автор:** Soror L.'.L.'. &nbsp;|&nbsp; **Версия:** 0.5.1 &nbsp;|&nbsp; **Лицензия:** Apache 2.0

**Документация:** [English](README.md) · [Русский](README.ru.md)

**Репозитарий:** [GitHub - Methelina/AmuleD_v2_KAD-eD2k_Python](https://github.com/Methelina/AmuleD_v2_KAD-eD2k_Python.git)

---

## Для пользователей

### Что это такое

AmuleD — клиент для децентрализованного обмена файлами в p2p-сетях eD2K/Kademlia (сеть eMule). Архитектура сети не имеет центрального сервера-посредника: поиск файлов и обмен идут напрямую между узлами-участниками через распределённую хеш-таблицу (DHT), поэтому ни один узел не хранит полный каталог, а трафик и участники распределены по миллионам машин по всему миру.

Что вы можете делать прямо сейчас:

- **Расшарить свои папки** — AmuleD просканирует их, посчитает хеши и зарегистрирует файлы для сети (команды `share add` / `share scan`).
- **Найти файл в сети** по ключевому слову — через серверный поиск или по Kademlia (DHT) без серверов (команды `search server|auto` и движок `kad search`; поиск по «video» возвращает сотни реальных результатов).
- **Скачать найденное** — добавить файл в очередь по хешу, клиент сам запросит источники, будет докачивать частями с паузой/возобновлением и сверит MD4-хеш после завершения (команды `sources ed2k`, `download add|run|pause|resume|cancel`, прогресс-бар).
- **Работать безопасно** — IP-фильтр отсекает нежелательные адреса, ненадёжные серверы автоматически попадают в чёрный список (команды `ipfilter status|test`, `servers failures|forgive`).

Клиент полностью переносимый: ставится в свою папку одним скриптом, ничего не пишет в системные каталоги и не требует установленного Python.

### Текущий статус (честно)

Это ранний, но живой клиент: поиск (включая KAD) и приём источников работают против реальной сети eMule. Ещё в разработке: отдача файлов другим (upload), публикация ваших файлов в KAD-сети, входящие соединения. Следить за прогрессом можно в roadmap (секции помечены DONE/WIP/PLANNED).

### Требования

- Windows 10/11 для штатного PowerShell-установщика и лаунчера.
- Доступ в интернет при первой установке.
- Не требуется вручную установленный Python: установщик создаёт проект-локальное окружение Python 3.12.
- Достаточно места для виртуального окружения, кешей, базы состояния, временных файлов и будущих загрузок.

### Установка

Из каталога `AmuleD_v2` один раз запустите переносимый установщик:

```powershell
.\AmuleD_install.ps1
```

Установщик идемпотентен: разворачивает `uv`, Python 3.12, зависимости, рабочие каталоги и JSONC-конфигурацию по умолчанию внутри проекта. Системный Python не используется, существующая конфигурация не перезаписывается.

### Запуск

Штатный лаунчер:

```powershell
.\AmuleD_Run.ps1 -NoPause --help
.\AmuleD_Run.ps1 -NoPause status --json
.\AmuleD_Run.ps1 -NoPause config show --json
```

### Поиск

Поиск через ED2K-сервер:

```powershell
.\AmuleD_Run.ps1 -NoPause search server --server 176.123.5.89:4725 --query "video" --duration 30 --json
.\AmuleD_Run.ps1 -NoPause search auto --server 176.123.5.89:4725 --query "video" --json
```

Результаты поиска сохраняются в DuckDB и доступны позже:

```powershell
.\AmuleD_Run.ps1 -NoPause search results list --json
.\AmuleD_Run.ps1 -NoPause search results show <file_hash> --json
.\AmuleD_Run.ps1 -NoPause search results clear --json
```

KAD-поиск работает поверх движка Kademlia (бутстрап → созревание routing-таблицы → итеративный keyword-lookup). CLI kad-команд сейчас интегрируются; то же самое доступно через Python-API (`amuled_v2.core.kad.search.kad_keyword_search`) и `scripts\kad_warmup.py` / `scripts\kad_node_collector.py`, которые строят и кешируют таблицу KAD-узлов в `db\kad_nodes.json`.

### Источники и загрузки

```powershell
.\AmuleD_Run.ps1 -NoPause sources ed2k <file_hash> --server 176.123.5.89:4725 --save --json
.\AmuleD_Run.ps1 -NoPause download add <file_hash> <size_bytes> --name "имя файла" --json
.\AmuleD_Run.ps1 -NoPause download run --json
.\AmuleD_Run.ps1 -NoPause download list --json
.\AmuleD_Run.ps1 -NoPause download pause <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download resume <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download cancel <file_hash> --json
```

`download run` подключается к известным источникам, запрашивает части файла, собирает part-файл и сверяет MD4 по завершении. Прогресс-бары рисуются в stderr и отключаются в `--json`-режиме.

### Серверы и защита

```powershell
.\AmuleD_Run.ps1 -NoPause import servers --server-met assets\v1\server.met --static assets\v1\staticservers.dat --save --json
.\AmuleD_Run.ps1 -NoPause servers failures --json
.\AmuleD_Run.ps1 -NoPause servers forgive <ip> <port> --json
.\AmuleD_Run.ps1 -NoPause ipfilter status --json
.\AmuleD_Run.ps1 -NoPause ipfilter test <ip> --json
```

Серверы с повторными сбоями автоматически попадают в blacklist на cooldown; `servers forgive` снимает запись. Заблокированные серверы пропускаются командами серверного канала и `import servers --save`.

### Логи

Диагностика отделена от вывода команд: результаты — на stdout, тегированные сообщения — на stderr и в JSONL-файле:

```text
logs\amuled.jsonl
```

Пример консольной диагностики:

```text
2026-09-23 07:23:52 | INFO | [KAD] bootstrap done: live=63 pool=397
```

JSONL содержит стабильные поля: timestamp, level, tag, logger, message — логи можно разбивать по модулям для скриптов или будущего GUI.

---

## Для разработчиков и технического справочника

### Идентификация продукта

Публичные имя и версия:

```text
AmuleD v0.5.1
```

Стабильные технические имена:

| Параметр              | Значение        |
| --------------------- | --------------- |
| Публичное имя клиента | `AmuleD`        |
| Публичная версия      | `AmuleD v0.5.1` |
| Python-пакет          | `amuled_v2`     |
| Исполняемый файл CLI  | `amuled`        |
| Каталог проекта       | `AmuleD_v2`     |

Изменение публичной версии синхронно обновляет константы пакета, тесты, баннеры и документацию.

### Clean-room политика

AmuleD распространяется по Apache 2.0. GPL-деревья aMule/eMule можно изучать для выявления wire-фактов, констант, переходов состояний и наблюдаемого поведения, но GPL-код не копируется в реализацию. Знания о протоколе сначала фиксируются в clean-room документах, затем независимо реализуются на Python.

Основные документы:

- [`docs/AmuleD_v2_SPEC.md`](docs/AmuleD_v2_SPEC.md)
- [`docs/PROTOCOL_MATRIX.md`](docs/PROTOCOL_MATRIX.md)
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md)
- [`docs/roadmap.md`](docs/roadmap.md) (каждая секция помечена DONE/SOLVED/WIP/DEPRECATED/TODO)

### Реализованные технические слои

| Слой                                           | Статус                            | Расположение                                               |
| ---------------------------------------------- | --------------------------------- | ---------------------------------------------------------- |
| Переносимый установщик/лаунчер                 | Реализовано                       | `AmuleD_install.ps1`, `AmuleD_Run.ps1`                     |
| JSONC-конфигурация                             | Реализовано                       | `src/amuled_v2/config.py`, `jsonc.py`                      |
| Состояние DuckDB и миграции                    | Реализовано                       | `src/amuled_v2/state.py`                                   |
| Тегированное логирование                       | Реализовано                       | `src/amuled_v2/logging_setup.py`                           |
| MD4 / ED2K-хеширование                         | Реализовано                       | `src/amuled_v2/core/hashes`                                |
| SHA-1 / AICH                                   | Реализовано                       | `src/amuled_v2/core/hashes/aich.py`                        |
| Бинарный/теговый/пакетный кодек                | Реализовано                       | `src/amuled_v2/core/codec`                                 |
| Хранение списков серверов                      | Реализовано                       | `src/amuled_v2/core/ed2k/server_met.py`                    |
| Импорт метаданных share-файлов                 | Реализовано                       | `src/amuled_v2/core/sharing/shared_files.py`               |
| ED2K TCP login                                 | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| Модель каналов поиска                          | Реализовано                       | `src/amuled_v2/core/search_channels.py`                    |
| ED2K SERVER-поиск                              | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| ED2K GLOBAL-поиск                              | Реализовано                       | `src/amuled_v2/core/ed2k/`                                 |
| `OP_GETSOURCES`                                | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| Хранение результатов поиска                    | Реализовано                       | `src/amuled_v2/state.py`                                   |
| IP-фильтр + blacklist серверов                 | Реализовано                       | `src/amuled_v2/core/ipfilter.py`, `server_filter.py`       |
| Download-стек (очередь/parts/MD4)              | Реализовано                       | `src/amuled_v2/core/download/`, `src/amuled_v2/core/peer/` |
| KAD-кодек пакетов (kad2)                       | Проверено живой сетью             | `src/amuled_v2/core/kad/packets.py`                        |
| Парсер nodes.dat                               | Реализовано                       | `src/amuled_v2/core/kad/nodes_dat.py`                      |
| KAD-бутстрап (HELLO/PING/BOOT)                 | Проверено живой сетью             | `src/amuled_v2/core/kad/bootstrap.py`                      |
| KAD routing-таблица                            | Реализовано                       | `src/amuled_v2/core/kad/routing.py`                        |
| KAD UDP-обфускация (RC4)                       | Проверено живой сетью             | `src/amuled_v2/core/kad/obfuscation.py`                    |
| KAD keyword-поиск                              | **Живой: 200 результатов/запрос** | `src/amuled_v2/core/kad/search.py`                         |
| Стратегии выбора (xor/quality/vivaldi/kadabra) | Реализовано                       | `src/amuled_v2/core/kad/strategies.py`                     |
| KAD CLI-команды                                | В плане                           | `src/amuled_v2/cli.py`                                     |
| KAD-источники (`SEARCH_SOURCE_REQ`)            | В плане                           | `docs/roadmap.md` §11c                                     |
| Upload-движок                                  | В плане                           | `docs/roadmap.md`                                          |
| Входящий KAD-listener                          | В плане                           | `docs/roadmap.md`                                          |
| GeoIP / UPnP-NAT-PMP                           | В плане                           | `docs/roadmap.md`                                          |

### Заметки о KAD-движке

- ID узлов используют внутреннюю **LE-словную семантику eMule**: `CFileDataIO::ReadUInt128` — сырые 16 байт memcpy четырёх little-endian слов, а сравнение дистанций идёт по слову 0. `KadUInt128` в `src/amuled_v2/core/kad/packets.py` реализует это точно; байты на проводе не меняются.
- UDP-обфускация KAD следует `EncryptedDatagramSocket.cpp`: ключ = `MD5(NodeID пира || wire[1:3])`, RC4 без key-drop, magic `0x395F2EC1`, ключи receiver/sender после паддинга. Оба направления (decode/encode) реализованы и проверены живой сетью.
- Тёплый кеш узлов (`db/kad_nodes.json` + таблица DuckDB `kad_nodes`) общий для `scripts/kad_warmup.py` и `scripts/kad_node_collector.py` и привязан к персистентному `own_id` — узлы узнают клиент между рестартами.

### Структура проекта

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Идемпотентный переносимый установщик
├── AmuleD_Run.ps1             # Лаунчер CLI-команд
├── pyproject.toml             # Метаданные пакета и зависимости
├── requirements.txt           # Зафиксированные группы зависимостей
├── AGENTS.md                  # Правила разработки проекта
├── assets/v1/                 # Базовые ресурсы сети
├── config/                    # Пользовательская JSONC-конфигурация
├── db/                        # Состояние DuckDB, KAD-кеш узлов
├── logs/                      # JSONL-диагностика
├── tmp/                       # Временные файлы проекта
├── incoming/                  # Завершённые загрузки
├── temp/                      # Частичные загрузки
├── shared/                    # Хранилище по умолчанию
├── docs/                      # Спецификация, roadmap, матрица протокола
├── scripts/                   # Прогрев, сборщик узлов, диагностические скрипты
├── src/amuled_v2/             # Реализация на Python
│   └── core/kad/              # KAD-движок (packets, bootstrap, routing, search, obfuscation, strategies)
└── tests/                     # Юнит-, кодек-, state- и протокольные тесты
```

### Изоляция окружения

Все генерируемые данные остаются внутри `AmuleD_v2`:

```text
.venv\                 # Проектный Python 3.12
bin\uv.exe             # Проектный uv
bin\uv-python\         # Интерпретаторы uv
.cache\uv\             # Кеш uv
.cache\pip\            # Кеш pip
.cache\pycache\        # Кеш байткода
.cache\tmp\            # Временные файлы pytest/инструментов
config\ db\ logs\ tmp\ # Конфигурация, состояние, диагностика, scratch
```

Лаунчер использует только `.venv\Scripts\python.exe` и не выбирает и не изменяет системный Python. Все временные файлы, включая артефакты pytest, перенаправляются в проект (см. `tests/conftest.py`) — на системный диск ничего не пишется.

### Команды разработки

Все команды — из каталога `AmuleD_v2` проектным интерпретатором:

```powershell
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_live_ed2k.py
.\.venv\Scripts\python.exe -m amuled_v2 --help
.\.venv\Scripts\python.exe -m amuled_v2 status --json
```

Текущий статус offline-набора:

```text
184 passed, 2 skipped
```

### Тегированная диагностика

Весь диагностический вывод использует стабильный тег модуля: `APP`, `CLI`, `CONFIG`, `STATE`, `IMPORT`, `SERVER`, `KAD`, `ED2K`, `SEARCH`, `DOWNLOAD`, `UPLOAD`, `PEER`, `SHARE`, `HASH`, `CODEC`, `SECURITY`, `IPFILTER`, `NAT`, `DAEMON`, `INSTALL`, `RUNNER`, `TEST`.

Пример:

```python
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.search")
log.info("kad search done: results=%d, nodes=%d", results, nodes)
```

JSONL-записи фильтруются напрямую по полю `tag`.

### Базовые ресурсы

Репозиторий самодостаточен после клонирования. В комплекте публичные сетевые/бутстрап-данные:

- `assets/v1/server.met`
- `assets/v1/nodes.dat`
- `assets/v1/GeoIP.dat`
- `assets/v1/staticservers.dat`
- `assets/v1/ipfilter.dat`
- `assets/v1/ipfilter_static.dat`

Метаданные share-файлов, списки каталогов, сгенерированная конфигурация, состояние DuckDB, логи, KAD-кеш узлов и состояние частичных загрузок — приватные. Они игнорируются Git и генерируются локально через `share add`, скрипты прогрева или импортируются из ваших собственных legacy-файлов.

### Roadmap

Завершённые станции разработки:

- Сессия с ED2K-сервером, SERVER/AUTO/GLOBAL-поиск, хранение результатов - **DONE**
- Жизненный цикл источников (sources ed2k --save) - **DONE**
- Очередь загрузок, part-файлы, верификация MD4, пиринговый протокол - **DONE**
- IP-фильтр и blacklist серверов - **DONE**
- Движок Kademlia (бутстрап, routing, обфускация, keyword-поиск) - **DONE** (живой: 200 результатов/запрос)

Активные / следующие станции (WIP/PLANNED):

1. KAD-поиск источников (KADEMLIA2_SEARCH_SOURCE_REQ) и их хранение - **WIP**
2. Загрузки от KAD-источников end-to-end (верификация MD4) - **PLANNED**
3. KAD CLI-команды (kad bootstrap/search/status/sources) - **WIP**
4. Долгоживущая стабилизация сети (прогрев сессии, рост кеша узлов) - **WIP**
5. Upload-слоты и очереди - **PLANNED**
6. Входящий KAD-listener, firewall-проверки - **PLANNED**
7. GeoIP / UPnP-NAT-PMP - **PLANNED**

Заметки ранних сессий хранятся для контекста в docs/roadmap.md - каждая секция там помечена DONE/SOLVED/WIP/DEPRECATED/TODO; живое состояние - в секциях 11a-11c.

---

## Лицензия

Apache 2.0. См. [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — политика clean-room совместимости.
