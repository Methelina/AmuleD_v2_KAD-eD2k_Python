# AmuleD v0.6.0

AmuleD — переносимый консольный ED2K/Kademlia-клиент на Python 3.12. Это независимая clean-room реализация открытых протоколов ED2K и Kademlia, а не обёртка над бинарниками aMule/eMule и не порт GPL-исходников.

Текущий майлстоун — **полный по функциям стек интероперабельности с eMule, проверенный в живой сети**: работающий **движок Kademlia** (keyword-поиск — 200 реальных результатов за запрос, поиск источников файлов, публикация собственных файлов в KAD-индекс), живая ED2K-сессия с сервером, полный download-стек (очередь, part-файлы, верификация MD4, параллельная гонка источников по полосам файла, сальваж повреждённых частей с точностью до блоков AICH), пиринговый протокол с **TCP-обфускацией в обе стороны** (исходящий дозвон + входящий приём, BASIC и DH), **UDP-обфускация**, **SecureIdent (SUI) RSA-384** с персистентными ключами, **обмен источниками** (обе стороны), восстановление **AICH** (обе стороны), комплект NAT-траверсала (direct-UDP callback, KAD buddy-callback, **NAT-T rendezvous поверх uTP**, IPv6-rendezvous), выбор блоков **ICS** и гейт **A4AF/NNS**, upload-движок с credits→priority, журнал клиентских кредитов, GeoIP, UPnP/NAT-PMP, IP-фильтр и автоблокировка серверов — всё под **единым ядром** (KAD-паук + listener + перепубликация + состояние DuckDB + IPC-канал для CLI). Главный живой результат: **полная закачка multi-part файла 46,7 МБ (5 частей, 255 блоков) с реального eMuleAI 1.6.0, MD4 сверен**, со всем стеком ICS/A4AF, работающим по проводу.

**Автор:** Soror L.'.L.'. &nbsp;|&nbsp; **Версия:** 0.6.0 &nbsp;|&nbsp; **Лицензия:** Apache 2.0

**Документация:** [English](README.md) · [Русский](README.ru.md)

**Репозитарий:** [GitHub - Methelina/AmuleD_v2_KAD-eD2k_Python](https://github.com/Methelina/AmuleD_v2_KAD-eD2k_Python.git)

---

## Для пользователей

### Что это такое

AmuleD — клиент для децентрализованного обмена файлами в p2p-сетях eD2K/Kademlia (сеть eMule). Архитектура сети не имеет центрального сервера-посредника: поиск файлов и обмен идут напрямую между узлами-участниками через распределённую хеш-таблицу (DHT), поэтому ни один узел не хранит полный каталог, а трафик и участники распределены по миллионам машин по всему миру.

Что вы можете делать прямо сейчас:

- **Расшарить свои папки** — AmuleD просканирует их, посчитает хеши и зарегистрирует файлы для сети (`share add` / `share scan`); ядро будет автоматически перепубликовывать их в KAD.
- **Найти файл в сети** по ключевому слову — через серверный поиск или по Kademlia (DHT) без серверов (`search server|auto` и движок `kad search`; поиск по «video» возвращает сотни реальных результатов).
- **Скачать найденное** — добавить файл в очередь по хешу; клиент сам запросит источники (ED2K-сервер, KAD по типу источника, обмен источниками от пиров), погоняет несколько источников параллельно по непересекающимся полосам файла, докачивает после пауз и рестартов, сверяет MD4 каждой части и всего файла, а повреждённую часть перекачает с точностью до блоков по 180 КБ, используя AICH-данные восстановления (`sources ed2k`, `kad sources`, `download add|run|pause|resume|cancel`, прогресс-бар).
- **Раздавать файлы другим** — ядро принимает соединения клиентов eMule, ставит пиров в очередь, отдаёт части (со сжатием, где поддерживается), отвечает на запросы source-exchange и AICH и может работать как KAD serving-buddy.
- **Работать безопасно** — IP-фильтр отсекает нежелательные адреса, ненадёжные серверы автоматически попадают в чёрный список, а каждое пиринговое соединение может идти внутри совместимой с eMule обфускации с верификацией SecureIdent (`ipfilter status|test`, `servers failures|forgive`).

Клиент полностью переносимый: ставится в свою папку одним скриптом, ничего не пишет в системные каталоги и не требует установленного Python.

### Текущий статус (честно)

Это живой клиент с полным протокольным стеком. Проверено на реальной сети: KAD-поиск/источники/публикация, ED2K-сессии с сервером, обфусцированные end-to-end закачки с реальных eMule/eMuleAI-пиров (MD4 сверен), включая закачку 46,7 МБ multi-part выше, приём обфусцированных входящих (BASIC + DH accept), live DH с реальным ED2K-сервером и KAD UDP-обфускация против живых узлов. Весь интернет-конвейер — свежий KAD-поиск → сохранение источников (через IPC ядра) → параллельная закачка — работает end-to-end в ядре; на сегодняшней сети завершение произвольной интернет-закачки ограничено качеством записей об источниках (многие пиры firewalled с протухшими buddy-парами, часть high-ID пиров закрывает plain-дозвон по политике) — это те же данные, с которыми работает и штатный eMule. Совместимый с eMule UDP NAT-T rendezvous (holepunch + uTP) реализован и проверен на loopback; живой успех rendezvous требует свежих связных записей buddy. Известные остатки: специфичный для eMuleAI протокол «eServer Buddy» (опционально) и AICH-majority-trust от непроверенных пиров. Прогресс — в roadmap (секции помечены DONE/WIP/PLANNED).

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

Установщик идемпотентен: разворачивает `uv`, Python 3.12, зависимости, рабочие каталоги и JSONC-конфигурацию по умолчанию внутри проекта. Системный Python не используется, существующая конфигурация не перезаписывается. Конфигурация по умолчанию копируется из отслеживаемого очищенного прототипа `config\amuled.example.jsonc` (в `config\amuled.jsonc` при первом запуске; пустой `identity.user_hash` генерируется и сохраняется автоматически, `network.bind_ip` не задан — его нужно указывать только для привязки KAD/peer UDP-эгра к конкретному локальному NIC в обход VPN-туннеля).

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

Ядро — единственный долгоживущий процесс. Оно держит KAD-сеть тёплой (постоянная HELLO/PING-матурация с ротацией протухших контактов, снапшот в `db\kad_status.json`), раздаёт файлы на эфемерном TCP-порту (рекламируемом в KAD source-записях; UPnP/NAT-PMP-маппинг пробуется автоматически), перепубликует ваши файлы каждые несколько часов и монопольно держит коннект DuckDB — CLI общается с ним по loopback-IPC (`db\kernel_status.json` несёт control-порт): результаты поиска, источники (включая `sources.save`), загрузки, кредиты, списки share и статус ipfilter работают при живом ядре.

### Интерактивное меню

Без аргументов рантайм открывает интерактивное меню: нумерованные результаты поиска (выбор одного или нескольких — `1,3,5` или `2-5` — с добавлением в загрузки), статус KAD, управление share, загрузки с прогресс-барами, тесты IP-фильтра, GeoIP-запросы. Меню — тонкая оболочка над тем же CLI; каждое действие — одно нажатие вместо командной строки.

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

Каждый источник несёт eMule-тип (1 = high-ID прямой дозвон, 3/5 = firewalled за serving-buddy, 6 = firewalled direct-UDP callback), KAD UDP-порт, адрес buddy где применимо, IPv6-теги где опубликовано (`ip6`/`bi6`), флаг dialable и KadID публикатора. Записи с reserved/multicast-адресами и невалидными портами отфильтровываются (правило `IsGoodIPPort`). При живом ядре источники сохраняются через IPC ядра (`sources.save`), а не конкурирующей прямой записью в БД.

### Публикация ваших файлов в KAD

Регистрирует расшаренные файлы в распределённом KAD-индексе, чтобы их находили и качали другие клиенты:

```powershell
.\AmuleD_Run.ps1 -NoPause publish keywords --limit 5 --json   # keyword-записи (имена файлов -> KAD-индекс)
.\AmuleD_Run.ps1 -NoPause publish sources --limit 0 --json    # вы как источник для каждого файла
```

Publish-клиент выполняет тот же итеративный lookup ближайших узлов, что и eMule (`KADEMLIA2_PUBLISH_KEY_REQ`/`_SOURCE_REQ` → `PUBLISH_RES`, с `PUBLISH_RES_ACK`, если запрошен), принимает топ-респондеров и останавливается на eMule-лимитах store. Ядро перепубликует автоматически каждые несколько часов — KAD-записи живут около суток. Проверено живой сетью: опубликованный AmuleD файл находится через `kad search` из сети, а `kad sources` возвращает сам AmuleD как dialable-источник.

### Раздача файлов другим (serve-демон)

`serve` запускает **ядро**: принимает eD2K client-to-client соединения (plain и обфусцированные — BASIC и DH), проводит handshake HELLO/HELLOANSWER, опционально проводит двустороннюю SecureIdent-верификацию, находит запрошенные хеши среди расшаренных файлов, ставит пиров в очередь (приоритеты, слоты, TTL, дедупликация) и отдаёт части файла с троттлингом на сессию (включая сжатые суб-пакеты), а также отвечает пирам на source-exchange (`OP_REQUESTSOURCES2`) и AICH (`OP_AICHREQUEST`). Может также работать как KAD serving-buddy (`KADEMLIA_FINDSERVINGBUDDY_REQ` → ретранслированные callback'и):

```powershell
.\AmuleD_Run.ps1 serve                      # ядро: паук + listener + периодическая KAD-перепубликация
.\AmuleD_Run.ps1 serve --publish-limit 10   # ограничить файлов на проход публикации
.\AmuleD_Run.ps1 serve --no-publish         # ядро без перепубликации
.\AmuleD_Run.ps1 serve --no-spider          # ядро без встроенного паука
```

Ядро пишет `db\kernel_status.json` (pid, serve-порт, control-порт), соблюдает `serve.max_sessions` и корректно завершается по Ctrl+C или `amuled daemon stop`. Идентичность клиента (userhash, ник, TCP-порт) живёт в секции `identity` файла `config\amuled.jsonc` — один и тот же стабильный SO_EMULE-маркированный userhash работает и в HELLO-handshake, и в KAD-публикации, и в деривации ключей обфускации, и в журнале кредитов, как у eMule (`GetClientHash = GetUserHash`); при первом запуске userhash генерируется и сохраняется. Loopback-самотест: собственный загрузчик AmuleD забирает реальный файл у ядра, MD4 собранного совпадает; отданные байты начисляются в журнал кредитов (`client_credits`) в том же процессе.

### Загрузки

```powershell
.\AmuleD_Run.ps1 -NoPause sources ed2k <file_hash> --server 176.123.5.89:4725 --save --json
.\AmuleD_Run.ps1 -NoPause download add <file_hash> <size_bytes> --name "имя файла" --json
.\AmuleD_Run.ps1 -NoPause download run <file_hash> --max-peers 50 --queue-wait 240 --json
.\AmuleD_Run.ps1 -NoPause download list --json
.\AmuleD_Run.ps1 -NoPause download pause <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download resume <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download cancel <file_hash> --json
```

`download run` выполняется внутри ядра. Источники разрешаются по типу: high-ID пиры дозваниваются напрямую (сначала обфусцированно, с автоматическим plain-повтором, если пир молча игнорирует обфусцированный handshake — опубликованный в KAD userhash не всегда совпадает с реальным хешем идентичности пира); firewalled-источники вызываются обратно (KAD buddy-callback для типов 3/5, direct-UDP callback для типа 6, затем NAT-T rendezvous поверх uTP с пробитием NAT как fallback для двойного файрвола, включая IPv6 direct-punch для записей `ip6`). Гонящие пиры качают непересекающиеся полосы файла; мёртвые пиры отсекаются, а их полосы перераспределяются за до трёх раундов. После передачи сверяется MD4 каждой части с хешсетом пира; повреждённая часть выбрасывается и перекачается — с сужением до повреждённых блоков по 180 КБ, если есть доверенный AICH-мастер. Финальная сборка в `incoming\` происходит только при пустом списке пробелов и совпавшем полном MD4. Прогресс-бары рисуются в stderr и отключаются в `--json`-режиме.

### Клиентские кредиты

Каждый отданный/полученный байт учитывается на userhash удалённого клиента (модель кредитов eMule на уровне учёта; верифицированные SecureIdent-клиенты получают бонус подписи):

```powershell
.\AmuleD_Run.ps1 -NoPause credits list --limit 20 --json
.\AmuleD_Run.ps1 -NoPause credits get <user_hash> --json
```

### Серверы и защита

```powershell
.\AmuleD_Run.ps1 -NoPause import servers --server-met assets\v1\server.met --static assets\v1\staticservers.dat --save --json
.\AmuleD_Run.ps1 -NoPause servers failures --json
.\AmuleD_Run.ps1 -NoPause servers forgive <ip> <port> --json
.\AmuleD_Run.ps1 -NoPause ipfilter status --json
.\AmuleD_Run.ps1 -NoPause ipfilter test <ip> --json
```

Серверы с повторными сбоями автоматически попадают в blacklist на cooldown; `servers forgive` снимает запись. Заблокированные серверы пропускаются командами серверного канала и `import servers --save`.

### GeoIP

Запрос страны по IP (официальный формат MaxMind MMDB, с best-effort fallback на legacy `GeoIP.dat`):

```powershell
.\AmuleD_Run.ps1 -NoPause geoip lookup <ip> --json
```

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

Сортировка по статусу: **Проверено живой сетью** → **Реализовано** (offline/loopback) → **В плане**.

| Слой | Статус | Расположение |
| ---------------------------------------------- | --------------------------------- | ---------------------------------------------------------- |
| **Проверено живой сетью**                      |                                   |                                                            |
| KAD keyword-поиск | **Живой: 200 результатов/запрос** | `src/amuled_v2/core/kad/search.py` |
| KAD-поиск источников (`SEARCH_SOURCE_REQ`) | **Живой: источники сохраняются** | `src/amuled_v2/core/kad/source_search.py` |
| KAD-публикация (keyword/source-записи) | **Проверено живой сетью** | `src/amuled_v2/core/kad/publish.py`, `src/amuled_v2/cli.py` |
| KAD-кодек пакетов (kad2) | Проверено живой сетью | `src/amuled_v2/core/kad/packets.py` |
| KAD-бутстрап (HELLO/PING/BOOT) | Проверено живой сетью | `src/amuled_v2/core/kad/bootstrap.py` |
| KAD UDP-обфускация (RC4) | Проверено живой сетью | `src/amuled_v2/core/kad/obfuscation.py` |
| KAD CLI-команды (`kad search/sources`) | **Проверено живой сетью** | `src/amuled_v2/cli.py` |
| ED2K TCP login | Проверено живой сетью | `src/amuled_v2/core/ed2k/server_client.py` |
| ED2K SERVER-поиск | Проверено живой сетью | `src/amuled_v2/core/ed2k/server_client.py` |
| `OP_GETSOURCES` | Проверено живой сетью | `src/amuled_v2/core/ed2k/server_client.py` |
| Исходящая TCP-обфускация (BASIC, постоянные стримы) | **Проверено живой сетью** | `src/amuled_v2/core/peer/obfuscation.py`, `core/peer/client.py` |
| Приём входящей обфускации (BASIC + DH) | **Проверено живой сетью** | `src/amuled_v2/core/peer/listener.py` |
| DH-обфусцированный handshake (server-mode) | **Проверено живой сетью** (реальный ED2K-сервер) | `src/amuled_v2/core/peer/obfuscation.py` |
| End-to-end обфусцированная закачка (реальный eMuleAI-пир, MD4 сверен) | **Проверено живой сетью** (46,7 МБ, 5 частей, 255 блоков) | `src/amuled_v2/core/peer/client.py`, `core/download/runner.py` |
| Obf-дозвон-фолбэк + plain-повтор | **Проверено живой сетью** | `src/amuled_v2/core/download/runner.py` |
| Единое ядро (паук+listener+state+IPC, один процесс) | **Проверено живой сетью** | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py`, `core/kad/spider.py` |
| NIC-egress bind для KAD/peer UDP (`network.bind_ip`) | **Проверено живой сетью** | `src/amuled_v2/core/net/bind_ip.py` |
| **Реализовано** | | |
| Переносимый установщик/лаунчер | Реализовано | `AmuleD_install.ps1`, `AmuleD_Run.ps1` |
| JSONC-конфигурация (+ отслеживаемый очищенный прототип) | Реализовано | `src/amuled_v2/config.py`, `jsonc.py`, `config/amuled.example.jsonc` |
| Состояние DuckDB и миграции | Реализовано | `src/amuled_v2/state.py` |
| Тегированное логирование | Реализовано | `src/amuled_v2/logging_setup.py` |
| MD4 / ED2K-хеширование | Реализовано | `src/amuled_v2/core/hashes` |
| SHA-1 / AICH + recovery-данные | Реализовано | `src/amuled_v2/core/hashes/aich.py` |
| Бинарный/теговый/пакетный кодек | Реализовано | `src/amuled_v2/core/codec` |
| Хранение списков серверов | Реализовано | `src/amuled_v2/core/ed2k/server_met.py` |
| Импорт метаданных share-файлов | Реализовано | `src/amuled_v2/core/sharing/shared_files.py` |
| Модель каналов поиска | Реализовано | `src/amuled_v2/core/search_channels.py` |
| ED2K GLOBAL-поиск | Реализовано | `src/amuled_v2/core/ed2k/` |
| Хранение результатов поиска | Реализовано | `src/amuled_v2/state.py` |
| IP-фильтр + blacklist серверов | Реализовано | `src/amuled_v2/core/ipfilter.py`, `server_filter.py` |
| Download-стек (очередь/parts/полосы/раунды/MD4) | Реализовано | `src/amuled_v2/core/download/`, `src/amuled_v2/core/peer/` |
| Выбор блоков ICS (режимы RELEASE/SPREAD/SHARE) | Реализовано | `src/amuled_v2/core/download/ics.py` |
| Гейт A4AF / no-needed-parts | Реализовано | `src/amuled_v2/core/download/runner.py` |
| Сальваж повреждённых частей + AICH-сужение до блоков | Реализовано | `src/amuled_v2/core/download/runner.py`, `core/hashes/aich.py` |
| Парсер nodes.dat | Реализовано | `src/amuled_v2/core/kad/nodes_dat.py` |
| KAD routing-таблица | Реализовано | `src/amuled_v2/core/kad/routing.py` |
| KAD-runtime (кеш → routing, bootstrap) | Реализовано | `src/amuled_v2/core/kad/runtime.py` |
| Стратегии выбора (xor/quality/vivaldi/kadabra) | Реализовано | `src/amuled_v2/core/kad/strategies.py` |
| KAD-паук (в ядре, ротация узлов/эвикция по фейлам) | Реализовано | `src/amuled_v2/core/kad/spider.py` |
| Идентичность клиента (стабильный userhash/ник/порт) | Реализовано | `src/amuled_v2/core/identity.py` |
| Shield-compliance гвард (запрещённые строки/теги) | Реализовано | `src/amuled_v2/core/peer/shield_guard.py` |
| SecureIdent RSA-384 (ключи, подпись/проверка, провод) | Реализовано | `src/amuled_v2/core/security/secure_ident.py`, `core/peer/client.py`, `core/peer/listener.py` |
| Upload-движок (очередь/слоты/троттлинг, credits→priority) | Реализовано | `src/amuled_v2/core/upload/` |
| Входящий peer-listener (plain + обфусцированный) | Реализовано | `src/amuled_v2/core/peer/listener.py` |
| Обмен источниками (респондер v2/v4 + реквестер) | Реализовано | `src/amuled_v2/core/peer/codec.py`, `core/peer/listener.py`, `core/peer/client.py` |
| AICH-респондер + реквестер | Реализовано | `src/amuled_v2/core/hashes/aich.py`, `core/peer/listener.py`, `core/upload/engine.py` |
| Direct-UDP callback (KAD тип 6) | Реализовано | `src/amuled_v2/core/kad/direct_callback.py` |
| KAD buddy-callback (типы 3/5) + buddy serving/customer | Реализовано | `src/amuled_v2/core/kad/direct_callback.py`, `core/kad/buddy.py`, `core/kad/buddy_customer.py` |
| NAT-T rendezvous (holepunch, endpoint hint, CAPS) | Реализовано | `src/amuled_v2/core/natt/session.py`, `core/kad/direct_callback.py` |
| uTP NAT-T транспорт | Реализовано | `src/amuled_v2/core/natt/utp.py` |
| QUIC NAT-T транспорт (ALPN eMuleAI) | Реализовано (loopback) | `src/amuled_v2/core/natt/quic_transport.py` |
| IPv6 KAD-теги источников + IPv6 rendezvous | Реализовано | `src/amuled_v2/core/kad/source_search.py`, `core/natt/session.py` |
| UDP-обфускация датаграмм (лестница ключей ED2K/KAD) | Реализовано | `src/amuled_v2/core/peer/udp_obfuscation.py` |
| Журнал клиентских кредитов (учёт по userhash) | Реализовано | `src/amuled_v2/state.py` (миграция 7) |
| UPnP IGD + NAT-PMP маппинг | Реализовано | `src/amuled_v2/core/nat/upnp.py` |
| GeoIP (MaxMind MMDB + legacy fallback) | Реализовано | `src/amuled_v2/core/geoip.py` |
| known.met импорт/экспорт | Реализовано | `src/amuled_v2/core/sharing/known_met.py`, `cli.py` |
| IPC-канал управления ядром (search/sources/downloads/credits/...) | Реализовано | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py` |
| Интерактивное консольное меню | Реализовано | `scripts/amuled_menu.py` |
| **В плане** | | |
| eServer Buddy (специфичный для eMuleAI опциональный слой) | В плане (опционально) | `docs/roadmap.md` |
| AICH majority-trust от непроверенных пиров | В плане | `docs/roadmap.md` |

### Заметки о KAD-движке

- ID узлов используют внутреннюю **LE-словную семантику eMule**: `CFileDataIO::ReadUInt128` — сырые 16 байт memcpy четырёх little-endian слов, а сравнение дистанций идёт по слову 0. `KadUInt128` в `src/amuled_v2/core/kad/packets.py` реализует это точно; байты на проводе не меняются.
- UDP-обфускация KAD следует `EncryptedDatagramSocket.cpp`: кандидаты ключа — MD5 над (NodeID / userhash+IP+magic / receiver verify key) плюс random-key-part с провода, RC4 без key-drop, magic `0x395F2EC1`, ключи receiver/sender после паддинга. Оба направления реализованы и проверены живой сетью; формат байт-точен с eMuleAI (нигде в заголовке датаграммы endian-swap нет).
- Тёплый кеш узлов (`db/kad_nodes.json` + таблица DuckDB `kad_nodes`) привязан к персистентному `own_id` — узлы узнают клиент между рестартами; протухшие контакты вытесняются счётчиками фейлов и эвикцией.
- Записи источников хранят числовой eMule-тип KAD-источника (1/3/5/6 плюс `sx` для источников от обмена), per-source адреса buddy, KAD UDP-порты и IPv6-теги (`ip6`/`bi6`), так что загрузчик выбирает верный путь достижимости для каждого источника.

### Заметки о NAT-траверсале

- Firewalled-источники достигаются в eMule-порядке: buddy-callback (`KADEMLIA_CALLBACK_REQ` 0x52 serving-buddy источника), direct-UDP callback (`OP_DIRECTCALLBACKREQ` 0x95) для типа 6, затем NAT-T rendezvous (`OP_REASKCALLBACKUDP` 0x94) с пробитием NAT, endpoint-hint'ами и CAPS-обменом, рекламирующим uTP; далее uTP-поток передаётся пиринговой сессии. IPv6-цели используют вариант direct-punch (endpoint-hint'ы в eMule только IPv4).
- `network.bind_ip` прибивает KAD/peer UDP-эгра к физическому NIC, когда VPN-туннель владеет default route — иначе пиры видят туннельный адрес и все callback/rendezvous-пути умирают; loopback-назначения освобождены от привязки (NIC-прибитый сокет не может слать в 127.0.0.1).
- UPnP IGD и NAT-PMP маппинги создаются при старте ядра и снимаются при завершении; мульти-NIC SSDP-дискавери находит роутер даже когда туннель затеняет default route.

### Заметки о безопасности

- TCP-обфускация: BASIC (лестница ключей MD5 из userhash цели + per-connection key part, один постоянный RC4-стрим на направление) проверена live и как дозвон, и как приём; DH (768 бит, эфемерен на handshake — eMuleAI не хранит никакого персистентного ключевого материала обфускации) проверен live с реальным ED2K-сервером и во входящем приёме.
- Опубликованный в KAD userhash не всегда равен реальному хешу идентичности пира; поэтому при молчании на обфусцированный handshake дозвон автоматически повторяется plain (с логированием, по политике видимости фолбэков).
- SecureIdent: RSA-384 через PyCryptodome (`construct` + `pkcs1_15`/SHA1), `config\cryptkey.dat` в eMule-формате Base64-DER, подписи 48 байт над `[signer blob][challenge][IP-block]`; и клиент, и listener проходят обмен SECIDENTSTATE/PUBLICKEY/SIGNATURE и ведут множество верифицированных клиентов с eMule-бонусом.
- Shield-compliance гвард никогда не отправляет модстрок, никнеймов и HELLO/INFO-тегов, за которые anti-leech shield eMuleAI выдаёт hard-ban, и регенерирует вырожденные userhash'и.

### Структура проекта

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Идемпотентный переносимый установщик
├── AmuleD_Run.ps1             # Единый рантайм-диспетчер: меню / ядро(serve) / CLI
├── pyproject.toml             # Метаданные пакета и зависимости
├── requirements.txt           # Зафиксированные группы зависимостей
├── AGENTS.md                  # Правила разработки проекта
├── assets/v1/                 # Базовые ресурсы сети
├── config/                    # Пользовательская JSONC-конфигурация (+ отслеживаемый прототип amuled.example.jsonc)
├── db/                        # Состояние DuckDB, KAD-кеш узлов
├── logs/                      # JSONL-диагностика
├── tmp/                       # Временные файлы проекта
├── incoming/                  # Завершённые загрузки
├── temp/                      # Частичные загрузки
├── shared/                    # Хранилище по умолчанию
├── docs/                      # Спецификация, roadmap, матрица протокола
├── scripts/                   # Лаунчер ядра, интерактивное меню, диагностические скрипты
├── src/amuled_v2/             # Реализация на Python
│   ├── core/kad/              # KAD-движок (packets, bootstrap, routing, search, publish, spider, obfuscation, strategies, buddy, callbacks)
│   ├── core/peer/             # Пиринговый протокол (client, listener, codec, TCP/UDP-обфускация, shield-гвард)
│   ├── core/natt/             # NAT-T (UDP-сессия, uTP, QUIC-транспорты)
│   ├── core/nat/              # UPnP IGD + NAT-PMP
│   ├── core/net/              # Политика NIC-egress bind
│   ├── core/security/         # SecureIdent RSA-384
│   ├── core/download/         # Очередь загрузок, раннер, выбор ICS
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

Лаунчер использует только `.venv\Scripts\python.exe` и не выбирает и не изменяет системный Python. Все временные файлы, включая артефакты pytest, перенаправляются в проект (см. `tests/conftest.py`) — на системный диск ничего не пишется. `config\amuled.jsonc` (живой конфиг) и `config\cryptkey.dat` (приватный ключ SUI) персональны и никогда не коммитятся; отслеживаемый `config\amuled.example.jsonc` — очищенный прототип.

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
395 passed, 3 skipped
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

Метаданные share-файлов, списки каталогов, сгенерированный живой конфиг (`config\amuled.jsonc`), приватные ключи SUI, состояние DuckDB, логи, KAD-кеш узлов и состояние частичных загрузок — приватные. Они игнорируются Git и генерируются локально через `share add`, паука ядра или импортируются из ваших собственных legacy-файлов.

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
- Live DH-сессия с реальным ED2K-сервером (server-mode) - **DONE** (magic сверен)
- KAD-публикация (keywords + sources) с петлёй перепубликации - **DONE** (живо подтверждено)
- Upload-движок, входящий listener, serve-демон, единая идентичность - **DONE** (loopback-самотест: MD4 сверен)
- Журнал клиентских кредитов по userhash (учёт upload/download, credits→priority) - **DONE**
- Единое ядро: паук + listener + состояние DuckDB в одном процессе, весь read-only CLI и меню по IPC - **DONE** (ноль конкуренции за лок, живо подтверждено)
- Паритет раздачи: periodic QUEUERANK, slot rotation, known.met импорт/экспорт, UPnP/NAT-PMP - **DONE**
- Приём обфусцированных входящих (BASIC + DH) - **DONE** (loopback + live)
- GeoIP (MaxMind MMDB + legacy fallback) - **DONE**
- SecureIdent RSA-384: ядро + провод обеих сторон - **DONE** (loopback-взаимная верификация)
- Source exchange: респондер + реквестер - **DONE**
- AICH: респондер + реквестер + блочный сальваж - **DONE** (e2e, MD4 сверен)
- Ротация узлов паука (счётчики фейлов, эвикция, подпитка сидов) - **DONE**
- Callback-стек: direct-UDP (kad6), buddy-callback (kad3/5), per-source персист buddy - **DONE**
- NAT-T rendezvous: uTP-транспорт, holepunch, endpoint-hint'ы, CAPS-обмен; QUIC-транспорт (loopback) - **DONE**
- IPv6 KAD-теги источников + IPv6 rendezvous (direct-punch) - **DONE**
- KAD buddy serving + customer-сторона - **DONE** (loopback-тесты)
- Полосная разметка + перераспределение зависших полос по раундам - **DONE** (e2e, MD4 сверен)
- Сальваж повреждённых частей (part-MD4 punch + перекачка) - **DONE** (e2e с отравлением)
- ICS-выбор блоков + гейт A4AF/NNS - **DONE** (live в закачке 46,7 МБ с eMuleAI)
- UDP-обфускация датаграмм - **DONE**
- Стабильная HELLO-идентичность + shield-compliance гвард - **DONE** (бан «Userhash changed» eMuleAI обойден live)
- Приём данных на EMULE-протоколе (0xC5) в трансфере - **DONE** (live COMPRESSEDPART от eMuleAI)
- Один STARTUPLOADREQ на сессию (гвард aggressive-ban) - **DONE**
- faulthandler-watchdog ядра + зомби-чистка лаунчера - **DONE**
- NIC-egress bind (`network.bind_ip`) - **DONE** (live; безопасен для loopback через per-destination политику)
- Obf-дозвон-фолбэк + plain-повтор - **DONE** (live)
- IPC sources.save (сохранение KAD-источников через ядро) - **DONE** (live: saved=6)
- Прототип конфига в репозитории (`config\amuled.example.jsonc`) + сидирование установщиком - **DONE**
- Роадмап 8.4.6 crypto_key persistence - **CLOSED** (рекон оракула: eMuleAI не хранит персистентного ключевого материала обфускации; DH эфемерен на handshake)
- Вопрос endian-swap UDP - **CLOSED** (без swap; формат байт-точен eMuleAI, дивергенция aMule задокументирована)

Активные / следующие станции (WIP/PLANNED):

1. Живое завершение произвольных интернет-закачек — механика проверена live; упирается в качество записей об источниках (протухшие buddy-пары, require-crypt пиры), как у штатного eMule - **WIP (сетевое условие)**
2. Live NAT-T rendezvous против eMuleAI со свежими связными buddy-записями - **WIP (сетевое условие)**
3. eServer Buddy (специфичный для eMuleAI опциональный слой) - **PLANNED (опционально)**
4. AICH majority-trust от непроверенных пиров (правило 10 IP / 92%) - **PLANNED**

Заметки ранних сессий хранятся для контекста в docs/roadmap.md - каждая секция там помечена DONE/SOLVED/WIP/DEPRECATED/TODO; живое состояние - в секциях 11a-11q. Отдельный скрипт паука упразднён — паук живёт внутри ядра (`core/kad/spider.py`).

---

## Лицензия

Apache 2.0. См. [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — политика clean-room совместимости.
