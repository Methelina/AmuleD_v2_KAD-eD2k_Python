# AmuleD v0.6.0 — Roadmap WITHOUT external LLM (no-Claude track)

Автор: Soror L.'.L.'.
Обновлён: 2026-09-25
Назначение: план работ, полностью реализуемый локально, без ожидающей внешней
сессии (Соннет — обфускационный дозвон/DH, см. docs\Cloud_Prompt_Help_Plz.md).
Канонический roadmap проекта: docs\roadmap.md; текущее состояние сессии:
docs\continuation-prompt.md. Этот файл — рабочий план no-Claude трека.

[STATUS LEGEND] DONE | WIP | TODO | BLOCKED-EXTERNAL (зависит от внешней сессии)

## 0. Что уже готово (база трека) [DONE]

- KAD search/sources LIVE (200 результатов «ubuntu», 13 источников по хешу),
  паук-демон тёплый (kad_spider.py, pool >900).
- Upload-стек: core/upload/queue.py (приоритеты, ранги, слоты, TTL),
  core/upload/engine.py (UploadSession: REQUESTFILENAME / HASHSETREQUEST /
  REQUESTPARTS(_I64) → SENDINGPART/COMPRESSEDPART по семантике
  UploadDiskIOThread.cpp; саб-пакеты 13000/10240; семейство I64 по
  endpos > u32max), codec.py v0.2.0 (7 answer-builders).
- Incoming listener (стадия D): core/peer/listener.py — StreamTransport
  (plain 0xE3/0xC5 framing, idle timeouts), HELLO→HELLOANSWER, EMULEINFO,
  немедленные ответы на REQUESTFILENAME/HASHSETREQUEST, STARTUPLOADREQ →
  UploadQueue → accept через engine-hook (ACCEPTUPLOADREQ) / QUEUERANK.
  Все точки контакта с шифрованным транспортом помечены
  `# WIP by external developer`.
- REAL-DATA: реальная папка Incoming установленного eMuleAI
  (79 файлов) в DuckDB с путями; хеши 79/79 совпали с `known.met` реального
  eMuleAI (парсер known.met: [u8 0x0F][u32 count]; запись =
  [u32 date][hash16][u16 part_count][parts×16][u32 tagcount][tags]).
- Тесты: offline suite 266 passed (+5 listener, +71 upload), compileall 0.

## Стадия P — KAD publish [DONE]

- [x] core/kad/publish.py: KeywordPublisher / SourcePublisher /
      PublishReport; iterative closest-lookup, sliding-window, PUBLISH_RES
      → ACK (0x4C); builders в packets.py (0x43/0x44/0x4B/0x4C).
- [x] Оффлайн: компиляция + импорт.
- [x] Ревизия Девиэйшенов субагента (единая tried-map dist→контакт;
      FILESIZE в source-tags по Search.cpp:909-910).
- [x] FIX wire-баг: count-байт тег-листа писался дважды (len(bytes) в
      packets._build_tag_list + count в publish); count теперь явный
      параметр; тест test_publish_key_req_wire_layout — регрессия.
- [x] LIVE: publish keywords — 5 accepts/10; `search kad <полное имя>`
      находит наш файл из сети (hash/size тестового PDF см. локально).
- [x] LIVE: publish sources — 4 accepts; `kad sources <hash>` возвращает
      нас (source_id = наш own_id (redacted), type 1, dialable).
- [x] CLI: `amuled publish keywords|sources [--limit N] [--tcp-port P]
      [--loop-interval H]` (петля перепубликации, ~24ч ротация).
- [x] Тесты: tests/test_publish.py +9; offline suite 280 passed.

## Стадия S — Listener как боевой сервис [DONE]

- [x] LocalIdentity из конфига (`identity`-секция amuled.jsonc: userhash
      генерируется и персистится при первом запуске; nick/tcp_port) —
      единый источник с KAD-публикацией (user_hash = GetUserHash-модель),
      `src/amuled_v2/core/identity.py`.
- [x] `AmuleD_Run.ps1 serve` (v2.1.0: guard от дублей, tagged JSONL-лог),
      слушает ephemeral TCP, порт пишется в `db/serve_status.json`
      (девиэйшен: не kad_status.json — паук переписывает свой файл каждый
      цикл и затёр бы ключ).
- [x] Реклама TCP-порта в KAD publish: демон перепубликует source-записи
      с фактическим портом (старт + `serve.republish_hours`, по умолчанию
      6ч; live: 4 accepts за проход). `--no-publish`/`--publish-limit`.
- [x] Graceful shutdown (SIGINT/SIGTERM + KeyboardInterrupt-fallback),
      `serve.max_sessions` (reject сверх лимита), троттлинг байт/с из
      конфига (`serve.throttle_bytes_per_sec`), upload_slots.
- [x] Интеграционный self-test: наш PeerClient качает у нашего listener
      реальный файл из Incoming по loopback — MD4 сошёлся (5 916 774 байта,
      33 блока с компрессией). Offline: tests/test_serve_selftest.py.
- Фиксы по пути: PeerInfo(version=) → несуществующий kwarg; transfer()
  слал серверный OP_ACCEPTUPLOADREQ (движок рвал сессию — см. комментарий
  в client.py); REQUESTPARTS-паддинг (0,0) валидировался как ошибка;
  COMPRESSEDPART-саб-пакеты теперь пересобираются клиентом (chunk +
  total-size, CreatePackedPackets-семантика); DuckDB lock retry 20x1s.

## Стадия U — Единое ядро (объединение процессов) [ФАЗА 2 DONE]

Мотивация: паук/демон/CLI — отдельные процессы, дерущиеся за эксклюзивный
rw-лок DuckDB (у eMule всё в одном процессе — потоки с общими объектами).
Фаза 1 называлась «ядро» — честная формулировка: это был только IPC-каркас,
объединения ещё не было. Фаза 2 — настоящее объединение.

- [x] Фаза 1: IPC-каркас — KernelControlServer (JSON-lines, 127.0.0.1),
      kernel_status.json, control-клиент; CLI credits через IPC.
- [x] Фаза 2: НАСТОЯЩЕЕ объединение — core/kad/spider.py (SpiderEngine,
      порт kad_spider v0.2.0), ядро AmuleDKernel держит ОДИН постоянный
      DuckDB-коннект и крутит паук+listener+republish+IPC как задачи.
      serve_daemon.py — тонкий лаунчер. LIVE: раздача 5.9 МБ (MD4 сверен),
      кредит по IPC мгновенно, `daemon status` 0.56 c, lock-ретраев от
      ядра ноль. ВАЖНО: пока ядро работает, сторонние процессы (включая
      старый kad_spider и CLI-команды с прямым DuckDB-доступом) БД открыть
      не могут — это спроектированное следствие; CLI-команды постепенно
      переводятся на IPC-роутинг (credits, daemon — сделаны).
- [x] CLI `daemon status|stop` через IPC (start — через AmuleD_Run serve).
- [x] Тесты: test_kernel.py (roundtrip, снапшот, SpiderEngine-юниты,
      вертикальный срез «закачка → кредит по IPC»). Suite 294 passed.
- [x] Фаза 3 [DONE, сессия 10]: полный IPC-роутинг — search.results.*,
      sources.list, download.list/add/pause/resume/start/cancel/run/status,
      servers.failures, ipfilter.status, upload.status; меню работает под
      живым ядром; AmuleD_Run spider -> DEPRECATED-предупреждение (v2.1.1).
      FIX: readline-лимит IPC 64 KiB -> 64 MiB (большие ответы рвались).

## Стадия D2 — загрузки end-to-end [DONE (в ядре), live-приёмка — осталось]

- [x] DownloadRunner v0.2.0: параллельная гонка до max_peers пиров,
      первый полный результат побеждает, остальные отменяются.
- [x] `download run` ВНУТРИ ядра (владеет DuckDB); CLI стартует и поллит
      `download.status`; источники через IPC `sources.list`.
- [x] E2E-тест: ядро качает у собственного listener по loopback, MD4 сверен
      (tests/test_kernel.py::test_kernel_ipc_download_run_end_to_end).
- [ ] live: скачать реальный файл с реального чужого пира (клиентский
      obf-dial жив; inbound accept — BLOCKED-EXTERNAL).

## Стадия C — Credits/SecureIdent-каркас [DONE]

- [x] DuckDB-миграция 7: `client_credits` (user_hash PK, uploaded,
      downloaded, last_seen) + `seen_clients` (first/last_seen, hellos).
      Нюанс DuckDB: в ON CONFLICT DO UPDATE — `now()`, не CURRENT_TIMESTAMP.
- [x] API: record_traffic / refund_traffic (клампит в 0) / get_credits /
      list_credits / list_seen_clients / see_client в StateBackend.
- [x] Интеграция: upload — listener `traffic_recorder` начисляет
      stats.bytes_sent на transfer_complete И на transport-error (клиент
      рвёт соединение, получив всё); download — PeerClient.traffic_sink →
      DownloadRunner → CLI download run → record_traffic(downloaded).
      serve_daemon подключает recorder (открыл/записал/закрыл DuckDB).
- [x] SecureIdent-адаптер: core/security/secure_ident.py (SecureIdentState
      = CSecureIdentState, evaluate → unverified/bonus 1.0; sign/verify
      кидают SecureIdentError, `# WIP by external developer`).
- [x] LIVE: loopback-раздача через демона — начислено uploaded=5 406 084
      байт клиенту (5.9 МБ файл, 33 блока, MD4 сверен).
- [x] Тесты: tests/test_credits.py (миграция, ledger, clamp, порядок,
      SecureIdent-мок, listener-интеграция).
- Попутный фикс: PeerClient.transfer считал раунды пакетами (3/раунд) —
  дедлок с саб-пакетизацией движка; теперь байтовый учёт раунда
  (expected_bytes = сумма длин диапазонов).

## Стадия X — Прочее без внешних зависимостей [PARTLY — сессия 10]

- [ ] Ротация протухших узлов паука (11d хвост).
- [ ] Sources без userhash: дозвон только после KAD userhash-lookup.
- [x] `upload status` CLI (через kernel IPC, `upload.status`).
- [x] Сверка MISCOPTIONS1/2-битов HELLO + EMULEINFO с реально
      поддерживаемым: заявляем только compression/large files/unicode/
      kad2; AICH, source exchange, multipacket, extended requests,
      aux-UDP честно обнулены (codec.py cap-константы).
- [ ] GeoIP: подключить assets/v1/GeoIP.dat к ipfilter/статистике.
- [x] UPnP/NAT-PMP: core/nat/upnp.py (SSDP+SOAP AddPortMapping,
      NAT-PMP fallback), map при старте ядра / unmap при остановке,
      `nat.enabled` в конфиге.
- [ ] WEB-EDONKEY канал — опционально, по запросу.

## Заблокировано внешней сессией [BLOCKED-EXTERNAL]

- Server-side obfuscation accept в StreamTransport (→ боевой входящий
  канал от реальных пиров; все моки помечены `# WIP by external developer`).
- DH-вариант связи, SecureIdent-крипта.
- После разблокировки: live-приёмка — реальный eMuleAI качает реальный
  файл из Incoming через наш listener, MD4 у получателя сходится.

## Паритет раздачи [DONE, сессия 10]

- [x] Periodic QUEUERANK: клиент в очереди держит соединение, ранг
      обновляется по таймеру, при освобождении слота — промоция и
      ACCEPTUPLOADREQ по тому же соединению (listener.py).
- [x] Slot rotation по таймеру в ядре (expired slots -> release).
- [x] credits→priority в upload-очереди (бонус = uploaded/downloaded,
      cap 10; queue.py v0.2.0).
- [x] known.met import/export: core/sharing/known_met.py (парсер сверен
      с реальным eMuleAI known.met: 904/904) + CLI
      `import known-met` / `export known-met`.

## Definition of done трека (без внешней сессии)

1. P: наш файл находится KAD-поиском с чужих узлов; перепубликация работает. [DONE]
2. S: listener живёт как демон, порт опубликован, self-test loopback зелёный. [DONE]
3. C: credits пишутся при отдаче/получении; миграция 7 применена. [DONE]
4. U: единое ядро; весь read-only CLI и меню работают под живым ядром; загрузки end-to-end в ядре. [DONE]
5. X/паритет: upload status, честные MISCOPTIONS, UPnP/NAT-PMP, known.met import/export, periodic QUEUERANK, credits→priority. [DONE]
6. Полный offline suite зелёный (303 passed); worktree закоммичен по подтверждению
   пользователя; roadmap/continuation-prompt синхронизированы. [suite DONE; коммит — по команде]

ОСТАВШЕЕСЯ в этом треке (не блокер, а хвосты):
- live-приёмка скачивания с реального чужого пира;
- GeoIP-подключение;
- ротация узлов паука; sources без userhash.

Всё остальное — только cloud-трек: обфускационный accept входящих,
SecureIdent-крипта, UDP-обфускация/DH.

