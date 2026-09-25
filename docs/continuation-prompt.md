# Continuation prompt — AmuleD (K:\work\AmuleD_v2)

Updated: 2026-09-26 01:15
Session state: 10 (no-Claude track; v0.6.0: релизная гигиена + audit_checklist + U фаза 3 IPC-роутинг — DONE, live-принято; suite 295 passed, 3 skipped; НЕЗАПУШЕНО: всё из сессии 10 + сессии 9)

---

## Праймер-промпт (скопировать новой сессии целиком; канонический текст — в чате сессии 9)

Ты продолжаешь разработку standalone-проекта AmuleD v0.5.1 в репозитарии K:\work\AmuleD_v2 — трек БЕЗ внешней LLM-сессии (обфускационный accept входящих / SecureIdent-крипта — BLOCKED-EXTERNAL; моки в коде помечены `# WIP by external developer` — не трогать и не «чинить»).

Прочитай по порядку:

K:\work\AmuleD_v2\AGENTS.md — среда, tagged logging, temp-политика, правила версии/имён.
K:\work\AmuleD_v2\docs\roadmap.md — канонический roadmap (секции 11a–11f, REAL-DATA VALIDATION).
Приложенный docs\roadmap.without_Claude.md — твой план: стадии P/S/C/U/X + Definition of done; работай строго по ним сверху вниз.
K:\work\AmuleD_v2\docs\continuation-prompt.md — живые грабли сети/Windows и этот праймер (актуальны и для этого трека).
Эталоны протокола (eMuleAI 1.6.0 — первичный оракул; читать ТОЛЬКО эти файлы, диск не сканировать):

O:\Work\Coding\eMuleAI\srchybrid\kademlia\kademlia\Search.cpp — STOREKEYWORD/STOREFILE StorePacket; SearchManager.cpp — ProcessPublishResult.
...\kademlia\kademlia\Kademlia.cpp — KadGetKeywordHash, Defines.h — SEARCHSTORE*_TOTAL.
...\kademlia\net\KademliaUDP.cpp, KademliaUDPListener.cpp — PUBLISH_RES (0x4B), ACK (0x4C), SendPublishSourcePacket.
...\kademlia\kademlia\Prefs.cpp — GetClientHash() = GetUserHash.
O:\Work\Coding\eMuleAI\srchybrid\UploadDiskIOThread.cpp — CreateStandardPackets/CreatePackedPackets; UploadClient.cpp, UploadQueue.cpp.
...\KnownFile.cpp, KnownFileList.cpp, FileIdentifier.cpp — known.met (готовый парсер: tmp\validate_known_met.py).
...\BaseClient.cpp, ListenSocket.cpp — HELLO/HELLOANSWER, ProcessPacket; EncryptedStreamSocket.cpp — только понимать WIP-точки, НЕ реализовывать.

Состояние: offline suite 294 passed, 6 skipped (запускать ТОЛЬКО при остановленном ядре), compileall 0. Стадии P (KAD publish), S (serve/identity/listener), C (credits + SecureIdent-каркас), U фазы 1–2 (единое ядро) — DONE и live-приняты. Архитектура (НЕ переписывать): `AmuleD_Run.ps1 serve` = единое ядро (`core/kernel.py::AmuleDKernel`) — один процесс, ОДИН постоянный DuckDB-коннект, внутри SpiderEngine (`core/kad/spider.py`), listener раздачи, KAD-перепубликация, IPC-сервер (`core/kernel_control.py`, JSON-lines 127.0.0.1, порт в db\kernel_status.json). CLI `credits list|get`, `daemon status|stop` — через IPC. СЛЕДСТВИЯ (by design): под живым ядром прямые DuckDB-команды CLI падают; `AmuleD_Run.ps1 spider` упразднён (паук внутри ядра). НЕЗАПУШЕНО: коммит 94373b1 (ядро) + README-правки.

Текущая задача (выбор из «Остаток до паритета eMuleAI» ниже):
1) Релизная гигиена: bump `__version__` 0.5.1 → 0.6.0 + docs\audit_checklist.md.
2) Фаза 3 стадии U: IPC-handlers (search.results, sources.get, download.list/add, servers.failures, ipfilter.status) + scripts\amuled_menu.py через IPC + deprecation-предупреждение для spider-режима в AmuleD_Run.ps1.
3) Далее по списку: загрузки end-to-end от KAD-источников; стадия X (MISCOPTIONS-сверка, upload status, GeoIP, UPnP/NAT-PMP); паритет раздачи (QUEUERANK-переодика, slot rotation, credits→priority, known.met import/export).

Среда: $env:PYTHONPATH='K:\work\AmuleD_v2\src'; $env:AMULED_ROOT='K:\work\AmuleD_v2'; только K:\work\AmuleD_v2\.venv\Scripts\python.exe (никакого activate); долгие прогоны — background_process; после прогонов убивать утечки python-процессов AmuleD; socket-операции в тестах — только под asyncio.wait_for (образец: tests\test_listener.py). Git — безопасно (без reset/amend/force-push без разрешения), коммит — только по явной команде, push — только спросив. Приватные файлы (docs*.md, config, assets\v1\shared_files.json, db, logs, tmp, userhash) не коммитить без санитизации. Никогда не упоминать локацию пользователя и имена/пути чужих файлов из known.met. Субагенты: 1 файл = 1 субагент, абсолютные пути, запрет запускать python/pytest/git и трогать файлы вне списка, отчёт START/END/DEVIATIONS; тесты пишет только оркестратор.

Отвечай по-русски, кратко, абсолютные пути в отчётах.

## Остаток до паритета eMuleAI — АКТУАЛЬНО после сессии 11 (cloud-трек ЗАКРЫТ)

**Блокер #6 (FIN после HELLO) СНЯТ live**: причина — RC4 send-стрим
пересоздавался для HELLO (v0.2.0); фикс клауда v0.3.0 (BasicObfuscationSession)
вживлён в PeerClient. Живые успехи: obf HELLOANSWER от eMuleAI, live DH
с реальным сервером 176.123.5.89:4725, end-to-end загрузка с реального
eMuleAI с MD4-верификацией (детали — roadmap.md секция 11h).

ОСТАЛОСЬ (порядок работ):

1. **download.run ядра с реальными KAD-источниками**: runner уже дозванивается
   по obf (target_userhash из KAD source_id) — прогнать полный цикл:
   kernel serve -> поиск -> источники с userhash -> download run -> MD4.
2. **GeoIP**: подключить assets/v1/GeoIP.dat к ipfilter/статистике.
3. **X-хвосты**: ротация узлов паука; source exchange как отвечающая
   сторона; AICH; disk-space checks.
4. **Коммит/пуш сессии 11** — по команде.

Только cloud-трек: обфускационный accept входящих (наш listener по-прежнему
plain-only; клиента это не касается — мы всегда дозваниваемся сами).

Definition of done (трек): kernel download.run принят live от KAD-источника;
GeoIP подключён; коммит запушен.

---

## Copy-paste prompt (start of a new session)

Ты продолжаешь разработку standalone-проекта AmuleD v0.6.0 в репозитарии K:\work\AmuleD_v2. Сначала прочитай AGENTS.md (K:\work\AmuleD_v2\AGENTS.md), актуальный roadmap: K:\work\AmuleD_v2\docs\roadmap.md (секции помечены [DONE]/[SOLVED]/[WIP]/[DEPRECATED]/[TODO]; живое состояние — секция 11g, сессия 10) и детальное состояние сессии: K:\work\AmuleD_v2\docs\continuation-prompt.md (этот файл).

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

ЗАДАЧА №1 (историческая, сессия 7) — снять блокер №6 — передана внешней cloud-сессии (см. docs/Cloud_Prompt_Help_Plz.md) и ИСКЛЮЧЕНА из этого трека. Этот трек продолжает работу из раздела «Остаток до паритета eMuleAI» выше.

Дальше по стеку: KAD publish (PUBLISH_KEY/SOURCE_REQ), входящий peer-listener (стадия D), upload-движок (C), SecureIdent (E). Диск C: не трогать. Все диагностические сообщения — tagged logging (amuled_v2.logging_setup, LogTags). Автор во всех файлах только Soror L.'.L.'. Никаких AI/co-author упоминаний. Абсолютные пути в отчётах. Отвечай по-русски, кратко и по делу.

---

## Сессия 10 (2026-09-26, no-Claude track): v0.6.0 — IPC + загрузки в ядре + стадия X + паритет [DONE]

Suite **303 passed, 3 skipped**; compileall 0. Live под ядром: read-only CLI
(664 результата search через IPC), download add/cancel, daemon status.

1. Версия 0.6.0 (init/pyproject/README/лаунчеры/тесты/AGENTS.md синк);
   docs/audit_checklist.md создан.
2. Фаза 3 U: 15+ kernel handlers; CLI-роутинг через `_kernel_control` с
   fallback на прямую БД; FIX readline-лимит IPC 64 KiB → 64 MiB
   (kernel_control.py; большие ответы рвались — пойман live).
3. Загрузки: runner v0.2.0 — параллельная гонка пиров; `download run`
   выполняется в ядре (владеет DuckDB), CLI поллит `download.status`;
   e2e-тест: ядро качает у своего listener, MD4 сверен.
4. X: честные MISCOPTIONS1/2 + EMULEINFO (codec.py/client.py, cap-
   константы: только compression/large files/unicode/kad2); `upload
   status` CLI; core/nat/upnp.py (SSDP+SOAP+NAT-PMP, map/unmap в ядре,
   `nat.enabled`).
5. Паритет раздачи: periodic QUEUERANK с удержанием соединения и промоцией
   (listener.py, `queue_rank_period`); slot rotation loop в ядре;
   credits→priority (queue.py v0.2.0, бонус = up/down, cap 10).
6. known.met: core/sharing/known_met.py — парсер сверен с реальным
   eMuleAI known.met (904/904) + writer; CLI `import known-met` /
   `export known-met`; tests/test_known_met.py.
7. Меню: kernel_status.json + `daemon status` по IPC; AmuleD_Run.ps1
   v2.1.1 — spider-режим DEPRECATED-предупреждение.
8. Грабли: статус-ключ очереди перетирал "ok" в download.add/lifecycle —
   вынесен в ключ "queue"; тестовые part-файлы и DB в тестах ядра —
   герметизация через monkeypatch DB_FILE/TEMP_DIR.

Незакоммичено: ВСЯ пачка сессий 9–10 (коммит/пуш — только по явной команде).

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

## Стадия U фаза 2 — ядро владеет DuckDB [КЛЮЧЕВОЕ ИЗМЕНЕНИЕ АРХИТЕКТУРЫ]

- `amuled serve` (AmuleD_Run.ps1 serve) = **единое ядро**: SpiderEngine
  (core/kad/spider.py, порт kad_spider) + listener + republish + IPC
  (core/kernel_control.py) в ОДНОМ процессе с ОДНИМ постоянным DuckDB-
  коннектом. `amuled daemon status|stop` — через IPC.
- **СЛЕДСТВИЕ (спроектированное)**: пока ядро работает, НИКАКИЙ другой
  процесс не откроет db/amuled.db (rw-лок). Старый `AmuleD_Run.ps1 spider`
  больше не запускать параллельно. CLI-команды с прямым DuckDB-доступом
  (share, search results, servers, download, publish, ipfilter) под живым
  ядром упадут — пользоваться после `amuled daemon stop` либо расширять
  IPC-роутинг (credits/daemon/share.list/share.count уже работают).
- kernel_status.json — источник правды (serve_port, control_port);
  serve_status.json больше не пишется.
- **pytest запускать при ОСТАНОВЛЕННОМ ядре** (ядро держит rw-лок — все
  DB-тесты падают иначе).
- LIVE: раздача 5 916 774 байт через ядро (MD4 сверен), кредит по IPC
  мгновенно, daemon status 0.56 c, lock-ретраев ноль. Suite 294 passed.
- Пуш стадии U НЕ делался — только по явной команде.

Следующая — стадия X; до неё: фаза 3 (IPC-роутинг остальных CLI-команд
или явно задокументированный stop-workflow).

## Быстрый старт (обязательный порядок)

0. **Ядро должно быть поднято ДО любой KAD-работы** (`K:\work\AmuleD_v2\AmuleD_Run.ps1 serve` — guard от дублей встроен; статус: `amuled daemon status`). Холодная сеть = 0 результатов. Прогрев после старта: ~5-10 мин до первых источников, полный — 20+ мин. Ядро держит DuckDB монопольно: CLI с прямой базой и pytest — только при остановленном ядре.
   ```powershell
   K:\work\AmuleD_v2\AmuleD_Run.ps1 serve            # ядро: паук + listener + publish + IPC
   .\.venv\Scripts\python.exe -m amuled_v2 daemon status --json
   ```
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
   live_ed2k_login.py, check_db.py, kad_spider.py — паук теперь внутри ядра,
   core/kad/spider.py), перекрыты ядром/CLI; НЕ использовать и не упоминать
   как актуальные. Актуальные: serve_daemon.py (лаунчер ядра), amuled_menu.py,
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
