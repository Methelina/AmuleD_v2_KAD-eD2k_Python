# AmuleD v0.6.0

AmuleD — переносимый консольный ED2K/Kademlia-клиент на Python 3.12. Это независимая clean-room реализация открытых протоколов ED2K и Kademlia.

Текущий майлстоун включает полностью работающий **движок Kademlia в живой сети eMule** — keyword-поиск (200 реальных результатов по запросу «video» примерно за секунду), поиск источников файлов (KADEMLIA2_SEARCH_SOURCE_REQ, сохранение в DuckDB) и **публикацию ваших файлов в KAD-индекс** (keyword- и source-записи, живо подтверждено: опубликованные AmuleD файлы находятся сетевым поиском, а сам AmuleD виден как источник), — живую ED2K TCP-сессию с сервером и поиском, полный download-стек (очередь, part-файлы, верификация MD4), слой пирингового протокола с **клиентским дозвоном через TCP-обфускацию** (современная сеть требует её; handshake живо подтверждён реальными пирами eMule), **входящий peer-listener с upload-движком**, **журнал клиентских кредитов** (учёт отданных/полученных байтов по userhash каждого клиента) и **единое ядро**, в одном процессе крутящее KAD-паука, listener, перепубликацию и состояние DuckDB под одним постоянным коннектом с IPC-каналом для CLI — драки за rw-лок БД между демонами и CLI больше нет. IP-фильтр, автоблокировка серверов, хранилище результатов поиска в DuckDB и интерактивное меню дополняют картину.

**Автор:** Soror L.'.L.'. &nbsp;|&nbsp; **Версия:** 0.6.0 &nbsp;|&nbsp; **Лицензия:** Apache 2.0

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

Это ранний, но живой клиент: поиск (включая KAD), приём источников, публикация ваших файлов в KAD и раздача файлов другим (serve-демон с upload-очередью) уже работают против реальной сети eMule, а исходящие пиринговые соединения используют обязательную TCP-обфускацию (проверено live end-to-end: AmuleD скачал реальный файл с реального eMule-клиента по обфусцированному каналу с совпавшим MD4; также установлена live DH-обфусцированная сессия с реальным ED2K-сервером). Ещё в разработке: приём обфусцированных входящих соединений (ожидает внешнего protocol review — сегодня отвечаем на plain-протокол), закачки напрямую из пула KAD-источников ядра, GeoIP, крипта SecureIdent/кредитов. Следить за прогрессом можно в roadmap (секции помечены DONE/WIP/PLANNED).

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

В проекте ровно два пусковика: установщик и единый рантайм. `AmuleD_Run.ps1` — диспетчер, всё делается из-под него:

```powershell
.\AmuleD_Run.ps1                      # интерактивное меню (Server / KAD / Share / Search / Downloads)
.\AmuleD_Run.ps1 serve                # ЯДРО: KAD-паук + listener + публикация + IPC для CLI (Ctrl+C — остановить)
.\AmuleD_Run.ps1 -NoPause --help      # CLI passthrough
.\AmuleD_Run.ps1 -NoPause status --json
.\AmuleD_Run.ps1 -NoPause daemon status   # статус ядра по IPC (порты, пул паука, аптайм)
.\AmuleD_Run.ps1 -NoPause daemon stop     # корректное завершение ядра
```

Ядро — единственный долгоживущий процесс. Оно держит KAD-сеть тёплой (постоянная HELLO/PING-матурация по кешу узлов, снапшот в `db\kad_status.json`), раздаёт файлы на эфемерном TCP-порту (рекламируемом в KAD source-записях), перепубликует ваши файлы каждые несколько часов и монопольно держит коннект DuckDB — CLI общается с ним по loopback-IPC (`db\kernel_status.json` несёт control-порт). Команды, работающие с базой напрямую (управление share, результаты поиска, загрузки), выполняются в окне `daemon stop` либо по мере перевода их на IPC-роутинг.

### Интерактивное меню

Без аргументов рантайм открывает интерактивное меню: нумерованные результаты поиска (выбор одного или нескольких — `1,3,5` или `2-5` — с добавлением в загрузки), статус KAD, управление share, загрузки с прогресс-барами, тесты IP-фильтра. Меню — тонкая оболочка над тем же CLI; каждое действие — одно нажатие вместо командной строки.

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

KAD-поиск работает поверх движка Kademlia (бутстрап → созревание routing-таблицы → итеративный keyword-lookup) со sliding-window-бюджетом: lookup продолжается, пока узлы отвечают, и завершается после тихого окна:

```powershell
.\AmuleD_Run.ps1 -NoPause kad search "video" --timeout 45 --json
.\AmuleD_Run.ps1 -NoPause search kad "video" --json   # тот же движок через модель каналов поиска
```

### KAD-источники

Поиск пиров, раздающих файл, напрямую через Kademlia, с сохранением в то же DuckDB-хранилище источников, которое потребляет загрузчик:

```powershell
.\AmuleD_Run.ps1 -NoPause kad sources <file_hash> --size <size_bytes> --timeout 45 --json
```

Каждый источник несёт eMule-тип (1 = high-ID, 3/5 = firewalled с buddy, 6 = direct callback), флаг dialable и KadID публикатора. Записи с reserved/multicast-адресами и невалидными портами отфильтровываются (правило `IsGoodIPPort`).

### Публикация ваших файлов в KAD

Регистрирует расшаренные файлы в распределённом KAD-индексе, чтобы их находили и качали другие клиенты:

```powershell
.\AmuleD_Run.ps1 -NoPause publish keywords --limit 5 --json   # keyword-записи (имена файлов -> KAD-индекс)
.\AmuleD_Run.ps1 -NoPause publish sources --limit 0 --json    # вы как источник для каждого файла
```

Publish-клиент выполняет тот же итеративный lookup ближайших узлов, что и eMule (`KADEMLIA2_PUBLISH_KEY_REQ`/`_SOURCE_REQ` → `PUBLISH_RES`, с `PUBLISH_RES_ACK`, если запрошен), принимает топ-респондеров и останавливается на eMule-лимитах store. Serve-демон (ниже) перепубликует автоматически каждые несколько часов — KAD-записи живут около суток. Проверено живой сетью: опубликованный AmuleD файл находится через `kad search` из сети, а `kad sources` возвращает сам AmuleD как dialable-источник.

### Раздача файлов другим (serve-демон)

`serve` запускает **ядро**: принимает eD2K client-to-client соединения, проводит handshake HELLO/HELLOANSWER, находит запрошенные хеши среди расшаренных файлов, ставит пиров в очередь (приоритеты, слоты, TTL, дедупликация) и отдаёт части файла с троттлингом на сессию. В том же процессе крутится KAD-паук (прогрев сети, созревание routing-таблицы, персист кеша узлов) и плановая KAD-перепубликация source-записей с фактическим TCP-портом:

```powershell
.\AmuleD_Run.ps1 serve                      # ядро: паук + listener + периодическая KAD-перепубликация
.\AmuleD_Run.ps1 serve --publish-limit 10   # ограничить файлов на проход публикации
.\AmuleD_Run.ps1 serve --no-publish         # ядро без перепубликации
.\AmuleD_Run.ps1 serve --no-spider          # ядро без встроенного паука
```

Ядро пишет `db\kernel_status.json` (pid, serve-порт, control-порт), соблюдает `serve.max_sessions` и корректно завершается по Ctrl+C или `amuled daemon stop`. Идентичность клиента (userhash, ник, TCP-порт) живёт в секции `identity` файла `config\amuled.jsonc` — один и тот же userhash работает и в HELLO-handshake, и в KAD-публикации источников, как у eMule (`GetClientHash = GetUserHash`); при первом запуске userhash генерируется и сохраняется. Пока ядро работает, коннект DuckDB монопольно его — поэтому `amuled credits list|get`, `daemon status` и `daemon stop` отвечают по IPC за миллисекунды, а остальные команды с базой выполняются в окне `daemon stop` (или по мере IPC-роутинга). Loopback-самотест: собственный загрузчик AmuleD забирает реальный файл у ядра, MD4 собранного совпадает; отданные байты начисляются в журнал кредитов (`client_credits`) в том же процессе.

### Клиентские кредиты

Каждый отданный/полученный байт учитывается на userhash удалённого клиента (модель кредитов eMule на уровне учёта; криптографическая проверка — отдельный внешний трек):

```powershell
.\AmuleD_Run.ps1 -NoPause credits list --limit 20 --json
.\AmuleD_Run.ps1 -NoPause credits get <user_hash> --json
```

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
AmuleD v0.6.0
```

Стабильные технические имена:

| Параметр              | Значение        |
| --------------------- | --------------- |
| Публичное имя клиента | `AmuleD`        |
| Публичная версия      | `AmuleD v0.6.0` |
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

Сортировка по статусу: **Проверено живой сетью** → **Реализовано** → **В плане**.

| Слой                                           | Статус                            | Расположение                                               |
| ---------------------------------------------- | --------------------------------- | ---------------------------------------------------------- |
| **Проверено живой сетью**                      |                                   |                                                            |
| KAD keyword-поиск                              | **Живой: 200 результатов/запрос** | `src/amuled_v2/core/kad/search.py`                         |
| KAD-поиск источников (`SEARCH_SOURCE_REQ`)     | **Живой: источники сохраняются**  | `src/amuled_v2/core/kad/source_search.py`                  |
| KAD-публикация (keyword/source-записи)         | **Проверено живой сетью**         | `src/amuled_v2/core/kad/publish.py`, `src/amuled_v2/cli.py` |
| KAD-кодек пакетов (kad2)                       | Проверено живой сетью             | `src/amuled_v2/core/kad/packets.py`                        |
| KAD-бутстрап (HELLO/PING/BOOT)                 | Проверено живой сетью             | `src/amuled_v2/core/kad/bootstrap.py`                      |
| KAD UDP-обфускация (RC4)                       | Проверено живой сетью             | `src/amuled_v2/core/kad/obfuscation.py`                    |
| KAD CLI-команды (`kad search/sources`)         | **Проверено живой сетью**         | `src/amuled_v2/cli.py`                                     |
| ED2K TCP login                                 | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| ED2K SERVER-поиск                              | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| `OP_GETSOURCES`                                | Проверено живой сетью             | `src/amuled_v2/core/ed2k/server_client.py`                 |
| Исходящая TCP-обфускация (BASIC, постоянные стримы) | **Проверено живой сетью**    | `src/amuled_v2/core/peer/obfuscation.py` (v0.3.0), `core/peer/client.py` |
| DH-обфусцированный handshake (server-mode)     | **Проверено живой сетью** (реальный ED2K-сервер) | `src/amuled_v2/core/peer/obfuscation.py`   |
| End-to-end обфусцированная закачка (реальный eMule-пир, MD4 сверен) | **Проверено живой сетью** | `src/amuled_v2/core/peer/client.py`, `core/download/runner.py` |
| Единое ядро (паук+listener+state, один процесс) | **Проверено живой сетью**        | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py`, `core/kad/spider.py` |
| **Реализовано**                                |                                   |                                                            |
| Переносимый установщик/лаунчер                 | Реализовано                       | `AmuleD_install.ps1`, `AmuleD_Run.ps1`                     |
| JSONC-конфигурация                             | Реализовано                       | `src/amuled_v2/config.py`, `jsonc.py`                      |
| Состояние DuckDB и миграции                    | Реализовано                       | `src/amuled_v2/state.py`                                   |
| Тегированное логирование                       | Реализовано                       | `src/amuled_v2/logging_setup.py`                           |
| MD4 / ED2K-хеширование                         | Реализовано                       | `src/amuled_v2/core/hashes`                                |
| SHA-1 / AICH                                   | Реализовано                       | `src/amuled_v2/core/hashes/aich.py`                        |
| Бинарный/теговый/пакетный кодек                | Реализовано                       | `src/amuled_v2/core/codec`                                 |
| Хранение списков серверов                      | Реализовано                       | `src/amuled_v2/core/ed2k/server_met.py`                    |
| Импорт метаданных share-файлов                 | Реализовано                       | `src/amuled_v2/core/sharing/shared_files.py`               |
| Модель каналов поиска                          | Реализовано                       | `src/amuled_v2/core/search_channels.py`                    |
| ED2K GLOBAL-поиск                              | Реализовано                       | `src/amuled_v2/core/ed2k/`                                 |
| Хранение результатов поиска                    | Реализовано                       | `src/amuled_v2/state.py`                                   |
| IP-фильтр + blacklist серверов                 | Реализовано                       | `src/amuled_v2/core/ipfilter.py`, `server_filter.py`       |
| Download-стек (очередь/parts/MD4)              | Реализовано                       | `src/amuled_v2/core/download/`, `src/amuled_v2/core/peer/` |
| Парсер nodes.dat                               | Реализовано                       | `src/amuled_v2/core/kad/nodes_dat.py`                      |
| KAD routing-таблица                            | Реализовано                       | `src/amuled_v2/core/kad/routing.py`                        |
| KAD-runtime (кеш → routing, bootstrap)         | Реализовано                       | `src/amuled_v2/core/kad/runtime.py`                        |
| Стратегии выбора (xor/quality/vivaldi/kadabra) | Реализовано                       | `src/amuled_v2/core/kad/strategies.py`                     |
| KAD-паук (прогрев сети)                        | Реализовано                       | `scripts/kad_spider.py`                                    |
| Идентичность клиента (userhash/ник/порт)       | Реализовано                       | `src/amuled_v2/core/identity.py`                           |
| Upload-движок (очередь/слоты/троттлинг, credits→priority) | Реализовано           | `src/amuled_v2/core/upload/`                               |
| Входящий peer-listener (plain)                 | Реализовано                       | `src/amuled_v2/core/peer/listener.py`                      |
| Serve-демон (раздача файлов)                   | Реализовано                       | `scripts/serve_daemon.py`                                  |
| Журнал клиентских кредитов (учёт по userhash)  | Реализовано                       | `src/amuled_v2/state.py` (миграция 7)                      |
| UPnP IGD + NAT-PMP маппинг портов              | Реализовано                       | `src/amuled_v2/core/nat/upnp.py`                           |
| known.met импорт/экспорт                       | Реализовано                       | `src/amuled_v2/core/sharing/known_met.py`, `cli.py`        |
| Интерактивное консольное меню                  | Реализовано                       | `scripts/amuled_menu.py`                                   |
| **В плане**                                    |                                   |                                                            |
| Приём обфусцированных входящих                 | В плане (внешняя сессия)          | `docs/roadmap.md`                                          |
| GeoIP                                          | В плане                           | `docs/roadmap.md`                                          |

### Заметки о KAD-движке

- ID узлов используют внутреннюю **LE-словную семантику eMule**: `CFileDataIO::ReadUInt128` — сырые 16 байт memcpy четырёх little-endian слов, а сравнение дистанций идёт по слову 0. `KadUInt128` в `src/amuled_v2/core/kad/packets.py` реализует это точно; байты на проводе не меняются.
- UDP-обфускация KAD следует `EncryptedDatagramSocket.cpp`: ключ = `MD5(NodeID пира || wire[1:3])`, RC4 без key-drop, magic `0x395F2EC1`, ключи receiver/sender после паддинга. Оба направления (decode/encode) реализованы и проверены живой сетью.
- Тёплый кеш узлов (`db/kad_nodes.json` + таблица DuckDB `kad_nodes`) общий для `scripts/kad_warmup.py` и `scripts/kad_node_collector.py` и привязан к персистентному `own_id` — узлы узнают клиент между рестартами.

### Структура проекта

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Идемпотентный переносимый установщик
├── AmuleD_Run.ps1             # Единый рантайм-диспетчер: меню / ядро(serve) / CLI
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
├── scripts/                   # Лаунчер ядра, интерактивное меню, прогрев и диагностические скрипты
├── src/amuled_v2/             # Реализация на Python
│   ├── core/kad/              # KAD-движок (packets, bootstrap, routing, search, publish, spider, obfuscation, strategies)
│   ├── core/peer/             # Пиринговый протокол (client, listener, codec, obfuscation)
│   ├── core/upload/           # Upload-движок (очередь, слоты, троттлинг отдачи)
│   ├── core/kernel.py         # Единое ядро: паук + listener + состояние + IPC
│   ├── core/kernel_control.py # IPC-сервер/клиент ядра (JSON lines)
│   └── core/identity.py       # Единая идентичность клиента (userhash/ник/порт)
└── tests/                     # Юнит-, кодек-, state-, kernel- и протокольные тесты
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
294 passed, 6 skipped
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
- KAD-поиск источников с сохранением в DuckDB - **DONE** (живой: источники из реальной сети)
- KAD CLI-команды (`kad search/sources`), паук-демон, интерактивное меню - **DONE**
- Клиентский дозвон через TCP-обфускацию - **DONE** (live: HELLOANSWER + полная закачка с реального eMuleAI, MD4 сверен)
- Live DH-сессия с реальным ED2K-сервером (server-mode) - **DONE** (magic сверён)
- KAD-публикация (keywords + sources) с петлёй перепубликации - **DONE** (живо подтверждено)
- Upload-движок, входящий listener, serve-демон, единая идентичность - **DONE** (loopback-самотест: MD4 сверен)
- Журнал клиентских кредитов по userhash (учёт upload/download, credits→priority) - **DONE**
- Единое ядро: паук + listener + состояние DuckDB в одном процессе, весь read-only CLI и меню по IPC - **DONE** (ноль конкуренции за лок, живо подтверждено)
- Паритет раздачи: periodic QUEUERANK, slot rotation, known.met импорт/экспорт, UPnP/NAT-PMP - **DONE**

Активные / следующие станции (WIP/PLANNED):

1. Закачки напрямую из пула KAD-источников ядра (infra готова, нужен live-прогон) - **WIP**
2. Приём обфусцированных входящих (внешний protocol review) - **WIP**
3. GeoIP (assets/v1/GeoIP.dat) - **PLANNED**
4. Каркас SecureIdent / крипта кредитов - **PLANNED** (крипта — внешняя сессия)
5. Source exchange как отвечающая сторона, AICH, disk-space checks - **PLANNED**

Заметки ранних сессий хранятся для контекста в docs/roadmap.md - каждая секция там помечена DONE/SOLVED/WIP/DEPRECATED/TODO; живое состояние - в секциях 11a-11f. Отдельный скрипт паука упразднён — паук живёт внутри ядра (`core/kad/spider.py`).

---

## Лицензия

Apache 2.0. См. [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — политика clean-room совместимости.
