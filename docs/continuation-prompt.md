# Continuation prompt — AmuleD v0.5.1 (K:\work\AmuleD_v2)

Updated: 2026-09-25 18:35
Session state: 8 (no-Claude track; P+S+C DONE; стадия U фаза 1 — DONE, фаза 2 TODO: паук внутрь ядра)

---

## Copy-paste prompt (start of a new session)

Ты продолжаешь разработку standalone-проекта AmuleD v0.5.1 в репозитарии K:\work\AmuleD_v2. Сначала прочитай AGENTS.md (K:\work\AmuleD_v2\AGENTS.md), актуальный roadmap: K:\work\AmuleD_v2\docs\roadmap.md (секции помечены [DONE]/[SOLVED]/[WIP]/[DEPRECATED]/[TODO]; живое состояние — секция 11e, сессия 7) и детальное состояние сессии: K:\work\AmuleD_v2\docs\continuation-prompt.md (этот файл).

Работай только с K-runtime: K:\work\AmuleD_v2\.venv\Scripts\python.exe и K:\work\AmuleD_v2\bin\uv.exe. O-runtime и legacy-репозитарий O:\Work\Coding\Paradise_Lost_KAD_SA не использовать (только чтение эталонов). Эталоны: eMuleAI 1.6.0 — НОВЫЙ ПЕРВИЧНЫЙ ОРАКУЛ: O:\Work\Coding\eMuleAI\srchybrid\ (репо https://github.com/eMuleAI/eMuleAI), eMule 0.50a — O:\Work\Coding\eMule_0.50a\srchybrid\. aMule (O:\Work\Coding\aMule-2.3.3) — только вторичная сверка. Установленный билд eMuleAI: K:\Software\eMuleAI_v1.6.0_x64\ (verbose-логи K:\Software\eMuleAI_v1.6.0_x64\logs\ — кодировка UTF-16 LE, читать через FileShare ReadWrite). Его конфиг: config\preferences.dat (userhash = первые 16 байт: 1415AF07…(redacted)), config\preferencesKad.dat (KadID на offset 6).

Git только безопасно: запрещены checkout/restore/reset/clean/rebase/merge/stash/amend/force-push без явного разрешения (restore по прямой просьбе — ок). Коммит после зелёных тестов и проверки на приватные пути; push — только спросив. Приватные файлы (AGENTS.md, docs\*.md, docs\recon\, config\amuled.jsonc, assets\v1\shared_files.json, assets\v1\shareddir.dat, db\, logs\, tmp\) не коммитить и не удалять. НИКОГДА не упоминать страну/локацию пользователя нигде (код, тексты, комментарии, логи) — это секрет.

ПРАВИЛА СУБАГЕНТОВ (критично): блочные кодовые задачи — через Task tool (тип general), 1 субагент = 1 атомарный файл. У субагентов отключён reasoning: полный контекст, точные API (сигнатуры читать из указанных файлов), абсолютные пути ВСЕХ файлов, реф-лист эталона в формате АБСОЛЮТНЫЙ ПУТЬ + НОМЕРА СТРОК. Явный путь питона K:\work\AmuleD_v2\.venv\Scripts\python.exe, запрет запускать python/pytest/git и ставить пакеты. Субагент ТОЛЬКО пишет файл(ы); компиляция, тесты, разбор ошибок — на тебе. ВСЕГДА лично перечитывай код за субагентами (полный git diff). НЕ пиши за субагента весь код — ссылки на эталон + констрейны. Большой таск — дроби.

ФОРМАТ КОМАНД (PowerShell, не bash):
$env:PYTHONPATH='K:\work\AmuleD_v2\src'; $env:AMULED_ROOT='K:\work\AmuleD_v2'; .\.venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_live_ed2k.py 2>&1 | Select-Object -Last 3
Компиляция: .\.venv\Scripts\python.exe -m compileall -q src tests scripts
Долгие прогоны — НЕ через bash-таймаут, а через background_process (иначе скрипт убивается вместе с таймаутом). KAD из скриптов: state=get_state(); state.connect(); con=state._require_duckdb() (DuckDB однописатель).
Wire-оракул: tshark K:\Software\WireShark\WiresharkPortable64\App\Wireshark\tshark.exe, интерфейс 6 = Ethernet 2 (LAN-интерфейс). ВЕСЬ исходящий трафик python-клиента идёт через отдельный туннельный интерфейс (tun0) — на iface 6 пробники НЕ ВИДНЫ, для них снимай интерфейс tun0.

Состояние (сессия 7): offline suite 195 passed, 2 skipped; compileall 0. KAD-поиск/источники LIVE (200 результатов «ubuntu»), паук-демон тёплый. Незакоммичено: codec.py (фикс HELLO — см. ниже), obfuscation.py v0.2.0 (basic client obfuscation). Изменён scripts\sanitize_log.py (проверить diff перед коммитом). Push копится — только по подтверждению.

ГЛАВНОЕ ЗА СЕССИЮ 7 (roadmap 11e — читать первым):
1. BASIC client TCP-obfuscation реализован (src\amuled_v2\core\peer\obfuscation.py v0.2.0) и LIVE-подтверждён: MorphXT-пир ответил HANDSHAKE OK 4 раза. Ключи/RC4/формат handshake ВЕРНЫ.
2. Протокольное доказательство: userhash цели для дозвона = sourceID из KAD source-ответа (Search.cpp:854 публикует GetClientHash=GetUserHash; DownloadQueue.cpp:4919-4921 SetUserHash(sourceID)). Наш source_search.py сохраняет его правильно.
3. FIX codec.py: HELLO был на 6 байт короче — хвост server_ip u32 + server_port u16 обязателен (SendHelloTypePacket, BaseClient.cpp:2212-2217). parse_hello тоже читает хвост.
4. FIX пробников: кадрирование было [proto][opcode][len], канон [proto][len=payload+1][opcode] (packets.cpp:32-36, GetHeader 182-187). «Эталон» loop_8089.pcapng оказался нашим же кривым пакетом — НЕ использовать.
5. ПЛЕЙМ-ПРОТОКОЛА В СЕТИ НЕТ: валидный plain HELLO → мгновенный FIN. Обфускация обязательна.
6. ОСТАВШИЙСЯ БЛОКЕР: после obf handshake OK + канонический HELLO(61 байт, 6 тегов vanilla-набор) → приёмник FIN <0.5 с, без HELLOANSWER. Исключено: ник, ранний EMULEINFO, константы типов тегов (совпадают с opcodes.h 0.50a), wire-формат тегов (Packets.cpp:444-518 = наш writer), userhash. Против MorphXT воспроизводится стабильно (tmp\probe_morph.py).
7. Инструмент ground truth: расшифровка живых дозвонов. keypart = открытые байты 1-5 handshake; RC4 send/recv ключи = MD5(target_userhash+34/203+keypart_LE), drop 1024. Userhash eMuleAI известен (см. выше) — расшифровывает входящие к нему. Блокер: поймать eMuleAI за дозвоном к IP, чей userhash знаем из KAD (tshark SYN-ловля + сверка с kad sources его текущего файла; файл виден в логе «SXSend: Local server source request; File=...»).
8. Event-driven pipeline (tmp\pipeline_dl.py): KAD source search в процессе + хук на parse_search_res_source_entries → мгновенный дозвон каждого источника + полный download ladder + MD4. Механика готова, ждать решения блокера. Долгие прогоны — только через background_process.
9. GETSOURCES через сервер работает: `amuled sources ed2k --server 176.123.5.89:4725 --hash H --size S` (в выдаче мусор 10.x/224+ — фильтровать). Серверные источники БЕЗ userhash → plain невозможен → для них нужен userhash из KAD или другой путь.

ЗАДАЧА №1 следующей сессии: снять блокер №6. Пути: (a) задать внешний LLM (промпт в чате сессии 7, репо https://github.com/eMuleAI/eMuleAI — файлы EncryptedStreamSocket.cpp, BaseClient.cpp, packets.cpp, ListenSocket.cpp CClientReqSocket::ProcessPacket) — что происходит между завершением basic handshake и HELLOANSWER, что может вызвать тихий мгновенный FIN; (b) перехват-расшифровка живого дозвона eMuleAI (см. №7) и байт-diff его HELLO с нашим; (c) после решения — подключить obfuscation к PeerClient + download runner, скачать файл ≤10 МБ end-to-end (MD4 сходится), коммит.

Дальше по стеку: KAD publish (PUBLISH_KEY/SOURCE_REQ), входящий peer-listener (стадия D), upload-движок (C), SecureIdent (E). Диск C: не трогать. Все диагностические сообщения — tagged logging (amuled_v2.logging_setup, LogTags). Автор во всех файлах только Soror L.'.L.'. Никаких AI/co-author упоминаний. Абсолютные пути в отчётах. Отвечай по-русски, кратко и по делу.

---

## Сессия 8 (no-Claude track): стадия P — KAD publish [DONE]

- Статус: publish.py отревьюлен vs Search.cpp:832-934/935-991, девиэйшены
  устранены, wire-баг count-байта тег-листа найден и исправлен
  (packets._build_tag_list считал count = len(байт); теперь count — явный
  параметр; publish builders возвращают (body, tag_count)).
- LIVE-acceptance зелёная: `publish keywords --limit 1` → 5 accepts/10;
  `search kad <полное имя тестового PDF из Incoming>` находит наш файл из
  сети (hash/size см. локально);
  `publish sources --limit 1` → 4 accepts; `kad sources <hash>` возвращает
  нас (source_id = наш own_id (redacted), type 1, dialable).
- CLI: `amuled publish keywords|sources [--limit N] [--tcp-port P]
  [--loop-interval H]` — петля перепубликации (~24ч ротация store).
- Публикация идёт под identity own_id (KadID = userhash для standalone);
  стадия S введёт LocalIdentity из конфига (Prefs GetClientHash = userhash).
- Грабли: DuckDB паук держит/блокирует db — CLI-publish ретраить до 10x8s;
  `--limit 0` = все файлы; поиск по полному имени файла (keyword hash =
  MD4 имени), слова-корни не найдут запись.
- Offline suite: 280 passed (+9 tests/test_publish.py); compileall 0.
- Незакоммичено: publish.py, packets.py (count-фикс), cli.py (publish),
  listener.py, upload/, test_publish.py и др. — коммит по подтверждению.

## Сессия 8 (no-Claude track): стадии P+S — DONE

### Стадия S — serve-демон (вторая половина сессии)

- `core/identity.py`: AppIdentity из конфига (`identity.user_hash/nick/
  tcp_port/client_id`); userhash генерируется и персистится при первом
  запуске. Один userhash на HELLO-handshake и KAD-публикацию
  (Prefs GetClientHash = GetUserHash).
- `scripts/serve_daemon.py` + `AmuleD_Run.ps1 serve` (guard, v2.1.0):
  ephemeral TCP, статус в `db/serve_status.json` (НЕ kad_status.json —
  паук его перезаписывает), max_sessions, throttle байт/с, graceful
  shutdown, периодическая KAD-перепубликация source-записей с фактическим
  портом (live: 4 accepts/проход). `--no-publish`, `--publish-limit`,
  `--once` (требует identity.tcp_port>0).
- LIVE self-test: наш PeerClient скачал у демона реальный файл из Incoming
  (5 916 774 байта, 33 блока, сжатие) — MD4 сошёлся.
- Грабли (пойманы живьём):
  - `PeerClient.transfer()` слал серверный OP_ACCEPTUPLOADREQ — движок
    рвал сессию после первого батча (комментарий оставлен в client.py);
  - COMPRESSEDPART приходит САБ-ПАКЕТАМИ (CreatePackedPackets: каждый чанк
    несёт BLOCK start + TOTAL compressed size) — клиент теперь копит чанки
    и декомпрессит целиком (codec: parse_compressed_part_chunk[_i64]);
  - REQUESTPARTS-паддинг (0,0) — легален (start==end допускается, ошибка
    только start>end) — поправлены валидаторы codec;
  - клиентский PeerInfo(version=) — несуществующее поле (emule_version);
  - DuckDB lock retry поднят до 20x1s (паук держит БД подолгу);
  - слоты upload-очереди текут при краше сессии (TTL 600с) — при отладке
    рестартить демона.
- Offline suite: 281 passed, 6 skipped; compileall 0.
- Незакоммичено: стадия S (identity/serve_daemon/AmuleD_Run/фиксы codec,
  client, listener, state, config) + README-обновление — коммит по
  подтверждению.

## Стадия C — DONE (итог сессии)

- Миграция 7 (`client_credits`, `seen_clients`) + credits-API в StateBackend
  (record/refund/get/list; DuckDB: в ON CONFLICT DO UPDATE — `now()`, НЕ
  CURRENT_TIMESTAMP).
- Учёт: listener traffic_recorder → uploaded (на transfer_complete и на
  transport-error: клиент рвёт соединение, получив всё); PeerClient.
  traffic_sink → DownloadRunner → CLI download run → downloaded;
  serve_daemon подключает recorder.
- SecureIdent-адаптер: core/security/ (sign/verify — заглушки, evaluate →
  unverified/bonus 1.0, `# WIP by external developer`).
- LIVE: loopback-раздача через демона, клиенту начислено
  uploaded=5 406 084 (файл 5.9 МБ, MD4 сверен).
- Фиксы по пути: transfer() считал раунды пакетами → дедлок с
  саб-пакетизацией; теперь байтовый учёт раунда. служебный регресс
  отступов в transfer-цикле пойман трассировкой dbg_flow.py.
- Offline suite: 288 passed, 6 skipped; compileall 0.
- Грабли: паук держит DuckDB подолгу — recorder/connect ретраит 20x1s;
  тесты на ledger — герметичные (in-memory recorder, уникальные userhash).

Следующая — стадия X (ротация узлов паука, upload status CLI,
MISCOPTIONS-сверка, GeoIP, UPnP).

## Быстрый старт (обязательный порядок)

0. **Паук-демон должен быть поднят ДО любой KAD-работы.** Холодная сеть = 0 результатов
   (главная грабля сессий 6-7). Проверка и запуск — только через AmuleD_Run.ps1 (доктрина
   проекта: ровно 2 пусковика — AmuleD_install.ps1 и AmuleD_Run.ps1, который диспетчер):
   ```powershell
   # статус паука: жив ли процесс и тёпла ли сеть
   Get-Content K:\work\AmuleD_v2\db\kad_status.json -Raw   # uptime_s растёт, pool_size > 300
   # запуск (guard от дублей встроен; если процесс уже жив — просто повторит статус)
   K:\work\AmuleD_v2\AmuleD_Run.ps1 spider
   ```
   Прогрев после холодного старта: ~5-10 мин до первых источников, полный — 20+ мин.
   Порт 4672 с фолбэком ephemeral; DuckDB паук открывает/закрывает на каждый save
   (CLI должен мочь писать одновременно — не держи соединение).
1. Тесты:
   ```powershell
   $env:PYTHONPATH='K:\work\AmuleD_v2\src'; $env:AMULED_ROOT='K:\work\AmuleD_v2'
   K:\work\AmuleD_v2\.venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_live_ed2k.py
   ```
2. Компиляция: `K:\work\AmuleD_v2\.venv\Scripts\python.exe -m compileall -q src tests scripts`
3. KAD-поиск/источники (после того как паук поднят):
   ```powershell
   .\.venv\Scripts\python.exe -m amuled_v2.cli search kad ubuntu --json
   .\.venv\Scripts\python.exe -m amuled_v2.cli kad sources <HASH> --json
   .\.venv\Scripts\python.exe -m amuled_v2.cli sources ed2k --server 176.123.5.89:4725 --hash <HASH> --size <SIZE> --save --json
   ```
   Фильтр источников: source_type in (1,4); выбрасывать ip 0.x/10.x/127.x/224+.
4. Дозвон/скачивание: `tmp\pipeline_dl.py` (event-driven: ищет источники и дозванивает
   в момент прихода). Запускать ТОЛЬКО через background_process (bash-таймаут убивает
   процесс вместе с недописанным логом), лог писать в файл и поллить.
5. Интерактив/CLI: `.\AmuleD_Run.ps1` (меню), `.\AmuleD_Run.ps1 <cli-команда>`.
6. `scripts\legacy\` — устаревшие скрипты (kad_warmup.py, kad_node_collector.py,
   live_ed2k_login.py, check_db.py), перекрыты пауком/CLI; НЕ использовать и не
   упоминать как актуальные. Актуальные: kad_spider.py, amuled_menu.py,
   sanitize_log.py, live_ed2k_search.py, kad_warmup_vivaldi.py (сайд-проект).

---

## Живые грабли сессии 7 (новое)

1. Пробники python идут через tun0 (VPN): tshark на iface 6 (Ethernet 2) их НЕ видит. Для своих пакетов снимай интерфейс tun0; eMuleAI-трафик виден на iface 6.
2. Старый KAD-источник умирает за минуты; TCP connect ≠ живой пир (NAT подделывает ACK). Event-driven pipeline обязателен: дозвон в момент прихода источника из UDP-ответа, не позже.
3. TCP-порт eMuleAI меняется при каждом запуске (был 8082, потом 27987); KAD UDP стабильно 8089. Слушающие порты: Get-NetTCPConnection -State Listen -OwningProcess <pid>.
4. eMuleAI перезапускается сам в случайные моменты — пробник может попасть в рестарт (тишина не является данными).
5. tmp\loop_8089.pcapng — НЕ эталон (наш собственный кривой пакет). Эталонных расшифрованных HELLO-байтов пока нет.
6. Логи eMuleAI: UTF-16 LE, файл занят — читать через [System.IO.File]::Open с FileShare ReadWrite. Полезные паттерны: «Sending OP_HELLO», «Received OP_HELLOANSWER», «SXSend: Local server source request», «myKadID=», «wrong magic value».
7. pytest-фикстуры: сбрасывать state_module._state = None; порты 4672/4673 bind запрещён Windows — ephemeral.
8. KAD-поиск по имени файла: слова с точками/дефисами («ubuntu-24.04») не находятся — ищи по корню («ubuntu») и фильтруй результаты по подстроке.

## Definition of done следующей сессии

- Блокер №6 снят (понятна и устранена причина мгновенного FIN после HELLO) — wire-diff с реальным клиентом или вердикт внешнего LLM, подтверждённый живым HELLOANSWER.
- `amuled download run` (или pipeline_dl.py) скачивает реальный файл ≤10 МБ с KAD-источника end-to-end, MD4 сходится.
- Obfuscation подключён к PeerClient (основной путь дозвона), offline suite зелёная, коммит.
