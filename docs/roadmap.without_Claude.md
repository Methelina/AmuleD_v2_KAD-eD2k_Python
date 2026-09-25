# AmuleD v0.5.1 — Roadmap WITHOUT external LLM (no-Claude track)

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

## Стадия S — Listener как боевой сервис [TODO]

- [ ] LocalIdentity из конфига (userhash/ник/TCP-порт) — единый источник
      с KAD-идентичностью (Prefs.cpp GetClientHash = GetUserHash).
- [ ] `AmuleD_Run.ps1 serve` (диспетчер: guard от дублей, tagged JSONL-лог),
      слушает ephemeral TCP, порт пишется в kad_status.json.
- [ ] Реклама TCP-порта в KAD publish (type-1 source entries → наш порт).
- [ ] Graceful shutdown, ограничение числа одновременных сессий, throttle
      (байт/с) из конфига.
- [ ] Интеграционный self-test: наш PeerClient качает у нашего listener
      реальный файл из Incoming по loopback (внутренняя согласованность).

## Стадия C — Credits/SecureIdent-каркас (крипто — мок) [TODO]

- [ ] DuckDB-миграция 7: `client_credits` (user_hash PK, uploaded,
      downloaded, last_seen) + `seen_clients`.
- [ ] API: credit(view/add/refund) по user_hash; интеграция точек:
      upload queue enqueue (учёт отданных байтов), download (учёт
      полученных) — начисления уже работают без крипты.
- [ ] SecureIdent-интерфейс-адаптер с пометкой
      `# WIP by external developer` (подписи/проверка — внешний трек).

## Стадия X — Прочее без внешних зависимостей [TODO]

- [ ] Ротация протухших узлов паука (11d хвост).
- [ ] Sources без userhash: дозвон только после KAD userhash-lookup.
- [ ] `upload status` CLI (snapshot очереди через именованный канал/файл
      kad_status-стиля).
- [ ] Сверка MISCOPTIONS1/2-битов HELLO с реально поддерживаемым
      (source exchange, AICH-ответы) — не заявлять то, чего нет.
- [ ] GeoIP: подключить assets/v1/GeoIP.dat к ipfilter/статистике.
- [ ] UPnP/NAT-PMP (уменьшает lowid; без внешних зависимостей).
- [ ] WEB-EDONKEY канал — опционально, по запросу.

## Заблокировано внешней сессией [BLOCKED-EXTERNAL]

- Server-side obfuscation accept в StreamTransport (→ боевой входящий
  канал от реальных пиров; все моки помечены `# WIP by external developer`).
- DH-вариант связи, SecureIdent-крипта.
- После разблокировки: live-приёмка — реальный eMuleAI качает реальный
  файл из Incoming через наш listener, MD4 у получателя сходится.

## Definition of done трека (без внешней сессии)

1. P: наш файл находится KAD-поиском с чужих узлов; перепубликация работает. [DONE]
2. S: listener живёт как демон, порт опубликован, self-test loopback зелёный.
3. C: credits пишутся при отдаче/получении; миграция 7 применена.
4. Полный offline suite зелёный; worktree закоммичен по подтверждению
   пользователя; roadmap/continuation-prompt синхронизированы.

