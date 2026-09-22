# AmuleD v0.4.1

AmuleD — портативный консольный ED2K/Kademlia-клиент на Python 3.12. Это независимая clean-room реализация публичных протоколов ED2K и Kademlia, а не бинарная обёртка вокруг aMule/eMule и не прямой порт GPL-исходников.

Текущая веха уже даёт портативный runtime, конфигурацию JSONC, состояние DuckDB, хэши MD4/ED2K/SHA1/AICH, кодек ED2K-пакетов, persistence серверных списков, импорт данных шаринга, тегированную диагностику и живо проверенную ED2K TCP login-сессию. Поиск, discovery источников, скачивание, upload и Kademlia ещё не реализованы и входят в следующие протокольные вехи.

**Автор:** Soror L.'.L.'. &nbsp;|&nbsp; **Версия:** 0.4.1 &nbsp;|&nbsp; **Лицензия:** Apache 2.0

**Документация:** [Русский](README.ru.md) · [English](README.md)

---

## Для пользователя

### Текущий статус

AmuleD — ранняя клиентская основа. Сейчас уже доступны:

- полностью портативное окружение Python 3.12;
- конфигурация JSONC и runtime-состояние DuckDB;
- импорт bundled-ресурсов v1 в локальное состояние;
- импорт и persistence серверных списков, статических серверов, метаданных шаринга и общих каталогов;
- вычисление MD4, ED2K-хэшей по чанкам, SHA-1 и AICH-деревьев;
- кодирование и декодирование ED2K-пакетов, тегов, сжатых payload и login-сообщений;
- подключение к ED2K-серверу, отправка `OP_LOGINREQUEST`, разбор серверных сообщений, identity, status и `OP_IDCHANGE`;
- тегированный вывод в консоль и JSONL-лог.

Пока недоступны поиск, discovery источников, скачивание файлов, публикация в Kademlia, upload peer'ам и полноценная замена eMule/aMule. Эти этапы зафиксированы в roadmap.

### Системные требования

- Windows 10/11 для bundled PowerShell installer/runner.
- Интернет при первой установке.
- Отдельно ставить Python не нужно: установщик создаёт проектный Python 3.12.
- Свободное место для venv, кэшей, runtime-базы, временных файлов и будущих закачек.

### Установка

Из каталога `AmuleD_v2` один раз запустите portable-установщик:

```powershell
.\AmuleD_install.ps1
```

Установщик идемпотентен: он подготавливает `uv`, Python 3.12, зависимости, runtime-каталоги и JSONC-конфиг внутри проекта. Он не использует системный Python и не перезаписывает существующую конфигурацию.

### Запуск

Используйте portable-лаунчер:

```powershell
.\AmuleD_Run.ps1
```

Без аргументов он показывает CLI-справку. Типовые команды:

```powershell
.\AmuleD_Run.ps1 -NoPause init --json
.\AmuleD_Run.ps1 -NoPause status --json
.\AmuleD_Run.ps1 -NoPause config show --json
.\AmuleD_Run.ps1 -NoPause config set network.client_tcp_port 8089 --json
```

`status --json` показывает активный backend, путь базы, состояние ED2K/KAD и количество записей в таблицах.

### Импорт bundled-данных

Репозиторий самодостаточен: базовые ресурсы v1 находятся в `assets\v1`. Их нужно импортировать в проектную базу:

```powershell
.\AmuleD_Run.ps1 -NoPause import servers `
  --server-met assets\v1\server.met `
  --static assets\v1\staticservers.dat `
  --save --json

.\AmuleD_Run.ps1 -NoPause import shared `
  --shared-json assets\v1\shared_files.json `
  --shareddir assets\v1\shareddir.dat `
  --save --json
```

После импорта `status --json` покажет счётчики серверов, статических серверов, файлов и каталогов шаринга.

### Логи

Диагностика отделена от вывода команд. Результаты команд идут в stdout; тегированная диагностика — в stderr и дополнительно в JSONL-файл:

```text
logs\amuled.jsonl
```

Консольный формат выглядит так:

```text
2026-09-22 23:49:29 | INFO | [CLI] Status command completed
```

JSONL содержит стабильные поля времени, уровня, тега, logger и сообщения, поэтому поток удобно разбирать скриптом или раскладывать по отдельным окнам будущего GUI.

---

## Для разработчика и технический справочник

### Публичная идентичность

Зафиксированы публичное имя и версия:

```text
AmuleD v0.4.1
```

Технические имена отделены от публичных и стабильны:

| Элемент | Значение |
|---|---|
| Публичное имя клиента | `AmuleD` |
| Публичная строка версии | `AmuleD v0.4.1` |
| Python package | `amuled_v2` |
| CLI executable | `amuled` |
| Каталог проекта | `AmuleD_v2` |

При продвижении версии клиента обновляются package-константы, тесты, баннеры и документация.

### Clean-room политика

AmuleD планируется под Apache 2.0. GPL-исходники aMule/eMule можно изучать для выявления протокольных фактов, констант, переходов состояний и наблюдаемого поведения, но нельзя копировать GPL-код в реализацию. Сначала протокольное знание фиксируется в clean-room-документах, затем независимо реализуется на Python.

Основные документы:

- [`docs/AmuleD_v2_SPEC.md`](docs/AmuleD_v2_SPEC.md)
- [`docs/PROTOCOL_MATRIX.md`](docs/PROTOCOL_MATRIX.md)
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md)
- [`docs/roadmap.md`](docs/roadmap.md)

### Реализованные технические слои

| Слой | Статус | Расположение |
|---|---|---|
| Portable installer/runner | реализовано | `AmuleD_install.ps1`, `AmuleD_Run.ps1` |
| Конфигурация JSONC | реализовано | `src/amuled_v2/config.py`, `jsonc.py` |
| DuckDB state и миграции | реализовано | `src/amuled_v2/state.py` |
| Тегированное логирование | реализовано | `src/amuled_v2/logging_setup.py` |
| MD4 / ED2K hashing | реализовано | `src/amuled_v2/core/hashes` |
| SHA-1 / AICH hashing | реализовано | `src/amuled_v2/core/hashes/aich.py` |
| Binary/tag/packet codec | реализовано | `src/amuled_v2/core/codec` |
| Persistence серверных списков | реализовано | `src/amuled_v2/core/ed2k/server_met.py` |
| Импорт/хэширование метаданных шаринга | реализовано | `src/amuled_v2/core/sharing/shared_files.py` |
| ED2K TCP login | подтверждено на живом сервере | `src/amuled_v2/core/ed2k/server_client.py` |
| ED2K search / `OP_GETSOURCES` | в roadmap | `docs/roadmap.md`, M4 |
| Kademlia | в roadmap | `docs/roadmap.md`, M5 |
| Download engine | в roadmap | `docs/roadmap.md`, M8 |
| Upload engine | в roadmap | `docs/roadmap.md`, M9+ |
| Obfuscation / secure identification | в roadmap | `docs/roadmap.md`, M11 |

ED2K TCP wire framing выглядит так: байт протокола, little-endian `UInt32 packet_length`, байт opcode, затем payload. Поле длины включает opcode, поэтому `packet_length = payload_size + 1`. Живая проверка сервера подтвердила эту раскладку и расширенный eMule-compatible payload `OP_IDCHANGE`.

### Структура проекта

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Идемпотентный portable-установщик
├── AmuleD_Run.ps1             # Portable-лаунчер CLI-команд
├── pyproject.toml             # Метаданные пакета и зависимости
├── requirements.txt           # Группы зависимостей
├── AGENTS.md                  # Правила разработки проекта
├── assets/v1/                 # Bundled базовые ресурсы
├── config/                    # Пользовательский JSONC-конфиг
├── db/                        # DuckDB state и генерируемые файлы
├── logs/                      # JSONL-диагностика
├── tmp/                       # Проектные временные файлы
├── incoming/                  # Будущие завершённые закачки
├── temp/                      # Будущие частичные закачки
├── shared/                    # Каталог шаринга по умолчанию
├── docs/                      # Спецификация, roadmap, протокольная матрица
├── scripts/                   # Диагностика и live-проверки
├── src/amuled_v2/             # Python-реализация
└── tests/                     # Unit, codec, state и protocol тесты
```

### Портативная изоляция

Все генерируемые данные остаются внутри `AmuleD_v2`:

```text
.venv\                 # Проектный Python 3.12
bin\uv.exe             # Локальный uv
bin\uv-python\         # uv-managed интерпретаторы Python
.cache\uv\             # кэш uv
.cache\pip\            # кэш пакетов
.cache\pycache\        # bytecode-кэш
.cache\tmp\            # временные файлы
config\ db\ logs\      # конфигурация, состояние, диагностика
```

Runner использует только:

```text
.venv\Scripts\python.exe
```

Системный Python не выбирается и не модифицируется.

### Команды разработки

Команды выполняются из `AmuleD_v2` через проектный интерпретатор:

```powershell
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pytest -q tests
.\.venv\Scripts\python.exe -m amuled_v2 --help
.\.venv\Scripts\python.exe -m amuled_v2 status --json
```

Текущий статус полного набора тестов для v0.4.1:

```text
128 passed
```

### Тегированная диагностика

Каждое диагностическое сообщение имеет стабильный uppercase-тег. Стабильные теги:

`APP`, `CLI`, `CONFIG`, `STATE`, `IMPORT`, `SERVER`, `KAD`, `ED2K`, `SEARCH`, `DOWNLOAD`, `UPLOAD`, `PEER`, `SHARE`, `HASH`, `CODEC`, `SECURITY`, `IPFILTER`, `NAT`, `DAEMON`, `INSTALL`, `RUNNER`, `TEST`.

Python-код использует проектный logger:

```python
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.DOWNLOAD, "core.transfer.download")
log.debug("Block stored: file=%s, start=%d, length=%d", file_hash, start, length)
```

JSONL-записи можно фильтровать напрямую по полю `tag`.

### Bundled базовые ресурсы

После клонирования проект самодостаточен. В базовый дистрибутив входят:

- `assets/v1/server.met`
- `assets/v1/nodes.dat`
- `assets/v1/GeoIP.dat`
- `assets/v1/staticservers.dat`
- `assets/v1/ipfilter.dat`
- `assets/v1/ipfilter_static.dat`
- `assets/v1/shareddir.dat`
- `assets/v1/shared_files.json`

История пользователя, client credits, identity-файлы и состояние частичных закачек в публичный baseline не входят.

### Roadmap

Активный протокольный путь:

1. ED2K server search и `OP_GETSOURCES`.
2. Persistence источников и lifecycle источников.
3. Kademlia bootstrap и routing.
4. Unified search для ED2K/KAD.
5. Очередь закачек, part files, сборка блоков и resume.
6. Peer transfer, upload slots и очереди.
7. Security, obfuscation, IP filter, GeoIP, UPnP/NAT-PMP.
8. Длительная live-network стабилизация.

Критерии приёмки — в [`docs/roadmap.md`](docs/roadmap.md).

---

## Лицензия

Apache 2.0. Совместимость и clean-room ограничения описаны в [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md).
