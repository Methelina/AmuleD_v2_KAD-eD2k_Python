# AmuleD v0.5.1 — Operational Roadmap and Session Handoff
[STATUS LEGEND] DONE = выполнено, не трогать | SOLVED = проблема решена | WIP = в работе | DEPRECATED = устарело, читать только для контекста | TODO = сделать. Актуальное: 11c (SOLVED) и 11b. Секции 2-8, 12-13 — DEPRECATED (история сессий 1-4).

Дата обновления: 2026-09-23 (сессии 2–4: search persistence, GLOBAL UDP, AUTO, source lifecycle, peer protocol, download stack, ipfilter/blacklist). Актуальное состояние проекта — секции 11a–11c (11c: KAD search SOLVED — 200 результатов по «video» за 1 с); исторические секции 2–5 описывают состояние на момент сессии 1 и оставлены для контекста находок. Продолжение работы: [docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md). Этот файл является локальным рабочим roadmap'ом standalone-проекта AmuleD и не публикуется в Git.

## 1. Canonical workspace and runtime [DONE — навсегда актуальный канон]

Canonical repository root: [K:\work\AmuleD_v2](file:///K:/work/AmuleD_v2). Public repository: [Methelina/AmuleD_v2_KAD-eD2k_Python](https://github.com/Methelina/AmuleD_v2_KAD-eD2k_Python). Public branch: `main`; last sanitized public commit before pending work: `e600029a77c678b53b94bbbc6b08b16374d2d153`.

Current public product version: `AmuleD v0.5.1`. Technical package name remains `amuled_v2`; CLI remains `amuled`; project directory remains `AmuleD_v2`.

Only the standalone K runtime is active. Use only these executables and paths:

```powershell
K:\work\AmuleD_v2\.venv\Scripts\python.exe
K:\work\AmuleD_v2\bin\uv.exe
K:\work\AmuleD_v2\AmuleD_install.ps1
K:\work\AmuleD_v2\AmuleD_Run.ps1
```

Never use the legacy O wrapper Python or O virtual environment for K work. The O tree is a legacy research workspace and donor/source-study area, not the active client.

Primary project files:

- [README.md](file:///K:/work/AmuleD_v2/README.md)
- [README.ru.md](file:///K:/work/AmuleD_v2/README.ru.md)
- [pyproject.toml](file:///K:/work/AmuleD_v2/pyproject.toml)
- [AGENTS.md](file:///K:/work/AmuleD_v2/AGENTS.md)
- [AmuleD_install.ps1](file:///K:/work/AmuleD_v2/AmuleD_install.ps1)
- [AmuleD_Run.ps1](file:///K:/work/AmuleD_v2/AmuleD_Run.ps1)
- [src\amuled_v2](file:///K:/work/AmuleD_v2/src/amuled_v2)
- [tests](file:///K:/work/AmuleD_v2/tests)
- [scripts\live_ed2k_search.py](file:///K:/work/AmuleD_v2/scripts/live_ed2k_search.py)

## 2. Current state at handoff [DEPRECATED — сессия 1, актуальное в 11a-11c]

At handoff, `main` is synchronized with sanitized public commit `e600029`. There is a significant pending working set that implements the next protocol layer and must be reviewed, committed, and pushed.

Pending modified files:

- [AmuleD_install.ps1](file:///K:/work/AmuleD_v2/AmuleD_install.ps1) and [AmuleD_Run.ps1](file:///K:/work/AmuleD_v2/AmuleD_Run.ps1): public version synchronized to 0.5.1.
- [README.md](file:///K:/work/AmuleD_v2/README.md) and [README.ru.md](file:///K:/work/AmuleD_v2/README.ru.md): search-channel documentation updated.
- [pyproject.toml](file:///K:/work/AmuleD_v2/pyproject.toml): package version 0.5.1.
- [src\amuled_v2\__init__.py](file:///K:/work/AmuleD_v2/src/amuled_v2/__init__.py): public version 0.5.1.
- [src\amuled_v2\cli.py](file:///K:/work/AmuleD_v2/src/amuled_v2/cli.py): share commands, ED2K search/source commands, and explicit search channels.
- [src\amuled_v2\core\codec\packet.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/codec/packet.py): corrected packed-protocol restoration.
- [src\amuled_v2\core\ed2k\server_client.py](file:/K:/work/AmuleD_v2/src/amuled_v2/core/ed2k/server_client.py): live login, server search, source lookup, packed packets, more-results trailer.
- [src\amuled_v2\state.py](file:///K:/work/AmuleD_v2/src/amuled_v2/state.py): DuckDB schema migration 3 and `file_sources` persistence.
- [tests\test_codec.py](file:///K:/work/AmuleD_v2/tests/test_codec.py): packed packet expectation corrected.
- [tests\test_skeleton.py](file:///K:/work/AmuleD_v2/tests/test_skeleton.py): public version 0.5.1.

Pending new files:

- [src\amuled_v2\core\ed2k\links.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/ed2k/links.py): strict ED2K file-link parser/generator.
- [src\amuled_v2\core\search_channels.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/search_channels.py): eMule-compatible search-channel model.
- [scripts\live_ed2k_search.py](file:///K:/work/AmuleD_v2/scripts/live_ed2k_search.py): real-server search/source diagnostic.
- [tests\test_live_ed2k.py](file:///K:/work/AmuleD_v2/tests/test_live_ed2k.py): gated live integration tests.

Pending deletion:

- `tests/test_server_client.py` was removed from index and disk because it used a fake loopback ED2K server and synthetic payloads. By project policy, protocol integration must use the real server and real local ed2k links; fake protocol servers are no longer accepted for this area.

Validation at handoff:

- `python -m compileall -q src tests scripts`: exit code `0`.
- Offline suite, excluding live network tests: `126 passed, 2 skipped`.
- The previous full live stack run against the real server produced `3 passed in 87.62s`.
- The codec test that still expected packed `0xD4` to restore protocol `0xC5` was corrected to expect `0xE3`.

## 3. Confirmed protocol findings [DONE — вечные факты, читать, не переделывать]

These findings are confirmed by live ED2K traffic and/or reference source study.

### 3.1 ED2K TCP framing

Real wire layout is:

```text
protocol byte
UInt32 little-endian packet_length
opcode byte
payload
```

`packet_length = payload_size + 1`, because the length includes the opcode byte. This was validated against the working live server.

Reference sources:

- [aMule Client2Server TCP.h](file:///O:/Work/Coding/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h)
- [eMule opcodes.h](file:///O:/Work/Coding/eMule_0.50a/srchybrid/opcodes.h)
- [aMule ServerSocket.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/ServerSocket.cpp)
- [eMule ServerSocket.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/ServerSocket.cpp)

### 3.2 Packed packets

`OP_PACKEDPROT` is `0xD4`. Its payload is zlib-compressed, and the opcode remains in the header. After successful unpacking, an ED2K server packet restores protocol `0xE3`, not eMule extension protocol `0xC5`. KAD-packed `0xE5` restores KAD `0xE4`.

This was confirmed live when the real server sent packed `OP_SERVERMESSAGE`. The first implementation incorrectly restored `0xC5`; the fixed behavior restored `0xE3`, after which live search worked.

Relevant K implementation: [packet.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/codec/packet.py) and [server_client.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/ed2k/server_client.py).

### 3.3 Server login and lowid

Live login against `176.123.5.89:4725` succeeds. The server assigns a lowid and sends messages including the familiar lowid warning. Live observed IDs during development included `9382172`, `9475884`, `9477838`, and `9482508`; IDs change per connection and should not be treated as stable fixtures.

Server identity observed during live runs:

```text
server version 17.15 (lugdunum)
Welcome to eMule Sunrise!
```

Server stats observed on live runs: roughly 43k users and 19 million indexed files.

### 3.4 Search is cumulative

ED2K server search is not a synchronous request/response operation. It is a long-lived accumulation process. The client sends one `OP_SEARCHREQUEST` and must continue receiving packets over a real time window. In AmuleD v2, `Ed2kServerClient.search()` now uses a `duration` window, default 30 seconds, and accumulates batches.

The accumulation window must not be cancelled externally by tests or CLI wrappers. The client owns the window.

The real live phrase `canadian rabbit glasses` produced zero results, and the generic live query `video` also produced zero results on the SERVER channel during these runs. The request format matched reference behavior, so zero results is currently interpreted as server/network behavior or missing alternate channels, not as a malformed packet.

### 3.5 Search result trailer

After the result array, ED2K/eMule may append one byte:

```text
0x00 = no more results
0x01 = more results available
```

This was confirmed in eMule source and observed live. K implementation exposes `SearchResultResponse.more_results_available`.

Reference implementation: [eMule SearchList.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/SearchList.cpp), around `ProcessSearchAnswer`.

### 3.6 Source lookup silence

`OP_GETSOURCES` does not guarantee a reply when the server knows no sources. The client now normalizes idle timeout to an empty `FoundSources` response without closing the session. This behavior was validated live.

### 3.8 Real search acceptance, publish step, and server throttling [DONE + WIP: троттлинг Sunrise периодический]

Confirmed by live traffic on 2026-09-23:

- The SERVER channel returns a real batch for `video`: 153 deduplicated
  results in one OP_SEARCHRESULT packet (~16 KB payload), with the eMule
  more-results flag set. Results persist into DuckDB (`search_results`).
- **Server throttling (confirmed):** after a series of successful searches,
  the Sunrise server returns zero results for ANY query for an extended
  period, regardless of publish state. The identical request produced 153
  results three times early in the session and 0 afterwards. This is a
  per-IP query rate limit (lugdunum behavior), not a client bug. A live
  search test must be retried after a cooldown; do not treat throttling as a
  regression.
- Request body matches eMule 0.50a (`GetSearchPacket`, single-term search =
  `u8(1) + utf8 string`); verified byte-level against the reference.
- eMule 0.50a sends `OP_OFFERFILES` (shared list) right after login via
  `SharedFileList::SendListToServer`. AmuleD v2 now publishes its persisted
  shared-file list (up to 200 rows, packed 0xD4 like eMule) with the
  0xFBFBFBFB:0xFBFB complete-file marker after every successful login before
  searching.
- **GLOBAL UDP: Sunrise is silent on UDP search** (0 raw datagrams in a raw
  probe, REQ3/REQ2/REQ ladder). Works cleanly end-to-end but yields no
  results from this server. Live validation deferred by user decision.
- The bundled v1 `server.met` contains many dead/spy servers
  (155.x/226.x/236.x/239.x/246.x/251.x/252.x/254.x ranges). Sweeping the
  whole list is now opt-in (`search global --sweep`); default GLOBAL target
  is the single Sunrise server. IP-filter (`ipfilter.dat`) and dead-server
  blacklist (`ServerFilter`) are integrated into sweep selection.
- Windows consoles use legacy code pages; CLI JSON output reconfigures
  stdout/stderr to UTF-8 to survive real file names with non-cp1251
  characters.
- DuckDB is single-writer: killed CLI runs can leave `db/amuled.db` locked;
  `StateBackend.connect` now retries briefly instead of failing.

Reference sources:

- [eMule SearchResultsWnd.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/SearchResultsWnd.cpp), `GetSearchPacket` (line ~1008).
- [eMule SharedFileList.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/SharedFileList.cpp), `SendListToServer` / `CreateOfferedFilePacket` (lines ~840–1040).
- [eMule sockets.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/sockets.cpp), `ConnectionEstablished` post-login publish.

### 3.7 eMule search channels

The generic phrase “ED2K search” is insufficient. eMule has explicit channels:

- `auto`: resolve between server/global/KAD using reference eMule rules.
- `server`: search only the current connected ED2K server over TCP using `OP_SEARCHREQUEST`.
- `global`: search current server plus other known servers, with UDP request variants.
- `kad`: Kademlia keyword search.
- `web-edonkey`: external web eDonkey service.

AmuleD v2 now has an explicit model in [search_channels.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/search_channels.py). CLI exposes `search server`, `search auto`, `search global`, `search kad`, and `search web-edonkey`; old `search ed2k` remains only as a compatibility alias for `server`.

Only `server` is implemented and live-validated. `global`, `kad`, and `web-edonkey` return structured `not_implemented` status instead of silently falling back.

## 4. Legacy AmuleD v1 search stack [DEPRECATED — v1, только для контекста]

The legacy v1 wrapper did not contain a direct ED2K binary parser. Its live search flow used:

- [test_client.py](file:///O:/Work/Coding/Paradise_Lost_KAD_SA/test_client.py)
- [amule_cookie.txt](file:///O:/Work/Coding/Paradise_Lost_KAD_SA/amule_cookie.txt)
- HTTP access to local amuleweb at `http://127.0.0.1:4711`
- `requests`
- `BeautifulSoup`

V1 logged into the web UI, cleared state, submitted a real search, waited approximately 30 seconds, parsed real result tables, and selected real ed2k links for download. ED2K/KAD protocol handling remained inside `amuled.exe`; v1 itself was only a wrapper and HTML result parser.

The v1 lesson carried into K is: use real server, real links, and a real accumulation window. Do not replace network integration with fake servers or synthetic result payloads.

## 5. Immediate 2do: finish and publish pending work [DONE — сессии 2-4]

### 5.1 Review and commit pending integration [DONE]

The pending work is coherent and tested, but not committed.

Recommended commit title:

```text
Implement live ED2K search channels and source lookup
```

Before commit, verify:

1. `git status --short --branch --untracked-files=all`.
2. `git grep -n -I -E 'O:\\|O:/|file:///O:/|K:\\|K:/|Paradise_Lost_KAD_SA|AI_EveryNyan|EveryNyan' -- .` returns no tracked machine-specific references.
3. `git ls-files` does not contain `AGENTS.md`, `docs/roadmap.md`, `config/amuled.jsonc`, `assets/v1/shared_files.json`, or `assets/v1/shareddir.dat`.
4. No fake protocol integration test file remains.
5. Public version is consistently 0.5.1.

Do not commit local private files. They are intentionally ignored.

### 5.2 Push after verification [DONE частично, WIP: новые коммиты ждут подтверждения]

Push only the sanitized standalone K repository:

```powershell
git -C K:\work\AmuleD_v2 push origin main
```

Do not push from legacy O as part of K integration.

### 5.3 Run final test matrix [DONE — 184 passed, 2 skipped]

Use only K Python:

```powershell
$env:PYTHONPATH = 'K:\work\AmuleD_v2\src'
K:\work\AmuleD_v2\.venv\Scripts\python.exe -m compileall -q src tests scripts
K:\work\AmuleD_v2\.venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_live_ed2k.py
```

Then run gated live tests:

```powershell
$env:AMULED_LIVE_ED2K = '1'
$env:PYTHONPATH = 'K:\work\AmuleD_v2\src'
K:\work\AmuleD_v2\.venv\Scripts\python.exe -m pytest -q tests\test_live_ed2k.py -s
```

Live tests may require real network and should not be treated as deterministic unit tests.

## 6. Immediate 2do: complete search-channel integration [PARTLY DONE: SERVER/AUTO/ GLOBAL DONE; KAD SOLVED в 11c; WIP: sources через KAD]

### 6.1 SERVER channel polish [DONE]

Current implementation is live-validated, but these items remain:

1. Persist search batches into DuckDB, not only return them from CLI.
2. Add a `search_results` table with query, channel, hash, name, size, sources, complete_sources, first_seen, last_seen.
3. Add `search results list` CLI.
4. Preserve full result tags instead of discarding them in `to_dict()`.
5. Add robust decoding for all common file, size, source, complete-source, media, and codec tags.
6. Add integration-safe CLI tests using environment gates and real local metadata, never fake servers.
7. Ensure search sessions can be kept alive across multiple searches or intentionally closed after each search.

Relevant K files:

- [server_client.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/ed2k/server_client.py)
- [cli.py](file:///K:/work/AmuleD_v2/src/amuled_v2/cli.py)
- [state.py](file:///K:/work/AmuleD_v2/src/amuled_v2/state.py)

### 6.2 AUTO channel [DONE — но AUTO-канал переключается через Kad теперь приоритетно]

AUTO currently hardcodes `ed2k_connected=True, kad_connected=False` in CLI. This is only a temporary bridge.

Implement a connection-state manager so AUTO uses actual ED2K and KAD connection state. Match eMule rules:

- If both networks are connected, prefer KAD unless the current server is static or meets the historical trustworthy-size rules.
- If only ED2K is connected, choose SERVER.
- If only KAD is connected, choose KAD.
- If neither is connected, return a structured error.

Reference implementation: [eMule SearchResultsWnd.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/SearchResultsWnd.cpp), around `StartNewSearch`.

### 6.3 GLOBAL channel [DONE]

GLOBAL is not implemented. It is the next logical search milestone after SERVER polish.

Required work:

1. ED2K UDP socket layer.
2. Server list with TCP/UDP flags and failure counts.
3. Server capability detection:
   - large-file UDP support;
   - extended get-files support;
   - new tag support.
4. UDP request variants:
   - `OP_GLOBSEARCHREQ` = `0x98`;
   - `OP_GLOBSEARCHREQ2` = `0x92`;
   - `OP_GLOBSEARCHREQ3` = `0x90`.
5. Global response aggregation and deduplication across servers.
6. Server retry and dead-server handling.
7. Per-server result attribution.
8. Integration with the same unified search model as SERVER.

Reference sources:

- [eMule SearchResultsWnd.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/SearchResultsWnd.cpp), global UDP request loop around lines 245–331.
- [eMule opcodes.h](file:///O:/Work/Coding/eMule_0.50a/srchybrid/opcodes.h).
- [aMule SearchList.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/SearchList.cpp), global search packet creation around lines 375–391.

### 6.4 KAD channel [SOLVED — см. 11b/11c; WIP: sources через KAD, CLI kad-команды]

KAD search is not implemented. This is a separate major engine and must not be approximated with ED2K server search.

Required baseline:

1. Kademlia UDP protocol.
2. Bootstrap from bundled [nodes.dat](file:///K:/work/AmuleD_v2/assets/v1/nodes.dat).
3. Routing table and contact management.
4. Keyword publication and search.
5. Firewall/lowid state handling.
6. Kad2 packet codec.
7. Search-result normalization into the same model as SERVER/GLOBAL.

Reference sources:

- [aMule kademlia](file:///O:/Work/Coding/aMule-2.3.3/src/kademlia)
- [eMule KAD implementation](file:///O:/Work/Coding/eMule_0.50a/srchybrid/kademlia)
- [aMule KAD protocol headers](file:///O:/Work/Coding/aMule-2.3.3/src/include/protocol/kad2)

### 6.5 WEB-EDONKEY channel [TODO — не начат]

This channel is external and optional. Do not build it before GLOBAL/KAD unless the user specifically needs it. It requires:

1. Adapter isolation behind `SearchChannel.WEB_EDONKEY`.
2. External service endpoint configuration.
3. Rate limits and result normalization.
4. Explicit privacy and legal policy.

## 7. Immediate 2do: source lifecycle [DONE для ed2k-sources; TODO: kad-sources]

DuckDB schema migration 3 is implemented. Table `file_sources` persists returned source rows. Current fields include file hash, client ID, client port, source type, server IP/port, user hash, first/last seen.

Next work:

1. Update `last_seen` when the same source is seen again.
2. Add source expiry.
3. Add source quality scoring.
4. Track dead sources.
5. Distinguish server-provided, KAD-provided, and peer-exchanged sources.
6. Add `sources forget <hash>` and `sources prune`.
7. Add source count statistics to `status --json`.
8. Add integration-safe live tests using a real local ed2k link from [shared_files.json](file:///K:/work/AmuleD_v2/assets/v1/shared_files.json).

Relevant state implementation: [state.py](file:///K:/work/AmuleD_v2/src/amuled_v2/state.py).

## 8. Next major milestones [8.1-8.3 DONE; 8.4-8.5 TODO/WIP]

### 8.1 Unified search-result model [DONE]

Create a stable internal result object shared by SERVER, GLOBAL, and KAD:

- normalized ED2K hash;
- name;
- exact size;
- sources;
- complete sources;
- channel origin;
- server or KAD publisher;
- tags;
- first/last seen;
- spam/filter score;
- optional AICH metadata.

This should become the input model for future download queue additions.

### 8.2 Download queue [DONE — стек есть; TODO: скачивание с KAD-источников]

After unified results, implement:

1. Download queue state in DuckDB.
2. Native `.part` file format.
3. Chunk bitmap and gap list.
4. Source scheduling.
5. Block request pipeline.
6. Hashset request and verification.
7. AICH recovery data.
8. Final assembly into `incoming`.
9. Pause/resume/cancel.
10. Disk-space checks.

This is milestone M8 in the broader plan and should not start before source lifecycle is stable.

### 8.3 Peer protocol [DONE — eD2K handshake; TODO: KAD-источники в download]

Required after download queue:

1. Client hello.
2. File request.
3. Hashset request.
4. Queue rank.
5. Block request/response.
6. Compressed blocks.
7. Peer source exchange.
8. Dead source handling.
9. Upload slots and queues.
10. Bandwidth throttling.

### 8.4 Security [WIP — obfuscation/SecureIdent частично]

Implement only after stable transfer behavior:

1. TCP obfuscation.
2. UDP obfuscation.
3. DH handshake.
4. Secure identification.
5. Client credits.
6. Crypto key persistence.

Reference sources:

- [aMule EncryptedStreamSocket.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/EncryptedStreamSocket.cpp)
- [aMule EncryptedDatagramSocket.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/EncryptedDatagramSocket.cpp)
- [aMule RC4Encrypt.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/RC4Encrypt.cpp)
- [eMule ServerSocket.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/ServerSocket.cpp)

### 8.5 IP filter, GeoIP, UPnP/NAT-PMP [WIP — ipfilter/blacklist DONE, GeoIP/UPnP TODO]

After live transfer:

1. Parse bundled IP filters.
2. Apply filter levels to peers and servers.
3. Use bundled [GeoIP.dat](file:///K:/work/AmuleD_v2/assets/v1/GeoIP.dat).
4. Add NAT diagnostics.
5. Add UPnP/NAT-PMP port mapping.
6. Improve lowid diagnosis.

## 9. Test policy [DONE — действующая политика]

The project test policy changed after live integration:

1. Do not write fake ED2K/KAD protocol servers for integration tests.
2. Do not invent synthetic result packets for protocol integration tests.
3. Use the real server `176.123.5.89:4725` for live tests.
4. Use real links from local ignored metadata.
5. Offline unit tests are allowed only for pure utilities, parser math, codecs without wire session assumptions, configuration, and state layers.
6. Live tests must be explicitly gated by `AMULED_LIVE_ED2K=1`.
7. A live timeout can be a valid result when ED2K semantics say silence means no data; do not automatically classify it as a protocol failure.
8. **Only a real test counts.** A live search test is considered passed only when the channel returns a non-empty result set for the real query `video` against the real server. Zero results is a failure of the acceptance criterion, not a pass; investigate server-side causes (publish state, timing) instead of weakening the test.
9. Documented acceptance: successful search with real results on the `video` query, per channel (currently SERVER; GLOBAL/KAD when implemented).

Current policy-compliant live test file: [tests\test_live_ed2k.py](file:///K:/work/AmuleD_v2/tests/test_live_ed2k.py).

## 10. Privacy, Git, and local files [DONE — действующие правила]

Canonical K repository uses strict public/private separation.

Public files must not contain machine-specific paths, private shared metadata, roadmap, or agent instructions. The following local files exist or are expected to exist and are ignored:

- [AGENTS.md](file:///K:/work/AmuleD_v2/AGENTS.md)
- [docs\roadmap.md](file:///K:/work/AmuleD_v2/docs/roadmap.md)
- [docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md)
- [config\amuled.jsonc](file:///K:/work/AmuleD_v2/config/amuled.jsonc)
- [assets\v1\shared_files.json](file:///K:/work/AmuleD_v2/assets/v1/shared_files.json)
- [assets\v1\shareddir.dat](file:///K:/work/AmuleD_v2/assets/v1/shareddir.dat)
- [db\amuled.db](file:///K:/work/AmuleD_v2/db/amuled.db)
- logs and generated runtime files

Public bootstrap assets remain only:

- [server.met](file:///K:/work/AmuleD_v2/assets/v1/server.met)
- [nodes.dat](file:///K:/work/AmuleD_v2/assets/v1/nodes.dat)
- [GeoIP.dat](file:///K:/work/AmuleD_v2/assets/v1/GeoIP.dat)
- [staticservers.dat](file:///K:/work/AmuleD_v2/assets/v1/staticservers.dat)
- [ipfilter.dat](file:///K:/work/AmuleD_v2/assets/v1/ipfilter.dat)
- [ipfilter_static.dat](file:///K:/work/AmuleD_v2/assets/v1/ipfilter_static.dat)

The standalone repository history was already rewritten and force-pushed once to remove private files. The sanitized public commit was `e600029a77c678b53b94bbbc6b08b16374d2d153`. Old unreachable GitHub objects may remain cached internally, but they are no longer part of `main`. If stronger removal is required, the repository must be deleted/recreated or GitHub support contacted.

Legacy parent O remains a separate historical repository. Its current HEAD was cleaned in a local commit, but its older history was not rewritten. Do not treat O as the active project.

## 11. Open risks and unresolved tails [WIP — см. также 11a-11c]

1. **Pending integration commit (session 2):** search persistence, GLOBAL UDP layer, AUTO real state, source lifecycle, progress bars, ipfilter, and server blacklist are implemented; commit pending.
2. **Server throttling:** Sunrise rate-limits searches per IP; live search acceptance (non-empty `video` results) can only pass after a cooldown. Retry later; do not weaken the test.
3. **GLOBAL UDP live results:** layer works end-to-end; Sunrise answers nothing on UDP search. Validation deferred by user decision; other servers are a disabled fallback branch.
4. **Publish step:** packed OP_OFFERFILES implemented; live effect unclear because of throttling window. Re-validate after cooldown.
5. **KAD is absent.** Next major engine after ED2K stabilization.
6. **Source expiry defaults** (168h) are provisional; quality scoring and dead-source tracking are not implemented.
7. **Lowid remains unhandled beyond diagnostics.** No UPnP/NAT-PMP or firewall correction exists yet.
8. **Fake/spy servers in the bundled server.met:** sweeps are opt-in and filtered; consider refreshing server.met from a maintained list later.
9. **Machine-specific scrubbing must be repeated before every public commit.**
10. **Parent O history still contains legacy/private paths** and requires a separate decision if the parent repository itself is published.

## 11a. Session 3-4 state (2026-09-23) [DONE — история, актуальное в 11b/11c]

Implemented and committed:

1. **Full download stack foundation:** `core/download/` (partfile, queue,
   runner), DuckDB migration 5 (`downloads`), CLI `download
   add/run/list/pause/resume/cancel` with Unicode progress bars
   (`progressbar.py`, style `⣀⣄⣆⣇⣧⣷⣿`).
2. **Peer protocol codec:** `core/peer/codec.py` — C2CTCP opcodes, HELLO /
   HELLOANSWER, REQUESTFILENAME/REQFILENAMEANSWER, SETREQFILEID,
   HASHSETREQUEST/ANSWER, FILESTATUS, REQUESTPARTS(+I64),
   SENDINGPART(+I64), COMPRESSEDPART(+I64), QUEUERANK, END_OF_DOWNLOAD,
   STARTUPLOADREQ, ACCEPTUPLOADREQ. 15 offline round-trip tests.
3. **Peer session:** `core/peer/client.py` — asyncio session with HELLO +
   EMULEINFO (0xC5) handshake, upload-queue wait (QUEUERANK updates until
   ACCEPTUPLOADREQ), and the request-parts transfer loop (3 × 184320-byte
   blocks, compressed parts decompressed).
4. **Download runner:** `core/download/runner.py` — sources from
   `file_sources` (high-id only), sequential peer attempts, blocks into the
   queue, MD4-verified finalize into `incoming`.
5. **Server filtering:** `core/ipfilter.py` (eMule ipfilter.dat parser with
   zero-padded octets, CIDR, level threshold 127) and
   `core/server_filter.py` (in-session failure blacklist with cooldown),
   integrated into GLOBAL sweep selection; CLI `ipfilter status/test`.
6. **Persistent server blacklist:** DuckDB migration 6
   (`server_blacklist`), `record_server_failure/success`,
   `list_blacklisted_servers/list_server_failures`, CLI
   `servers failures/forgive`; TCP search records silent searches as soft
   failures (3 → 0.5 h cooldown). Offline suite: **181 passed, 2 skipped**.

Commits: `223916d` (peer stack + download queue + filtering),
`dc4d3e4` (persistent blacklist). Both await user push approval.

Subagent policy (user rule): block coding tasks go to Task subagents —
ONE atomic task per subagent, full context and constraints, absolute paths,
explicit K-runtime python; subagents write code only and never run
python/pytest/git; the orchestrator compiles, tests, and interprets.

Confirmed protocol findings:

- Sunrise is currently in an active throttle/deny phase for our IP: logins
  get dropped right after the lowid warning; earlier the same session it
  served 153 real `video` results three times. Wait out the cooldown before
  live acceptance runs.
- eMule block requests are 3 parts of up to EMBLOCKSIZE = 184320 bytes
  ([opcodes.h](file:///O:/Work/Coding/eMule_0.50a/srchybrid/opcodes.h)).
- EMULEINFO travels with protocol byte 0xC5, opcode 0x01/0x02; most peers
  expect it before answering file requests.
- Python 3.12 rejects zero-padded IPv4 octets; ipfilter parsing splits and
  normalizes octets manually.
- DuckDB INTERVAL arithmetic requires pytz (absent); compute cutoffs in
  Python with datetime/timedelta.

Next steps:

1. After server cooldown: live pipeline test — `sources ed2k --save` for a
   real link from `assets\v1\shared_files.json`
   (first item: `clip_vision_h.safetensors`, 1180000000 bytes,
   hash `0164BF6E1A3B44158E330320A403EA48`), then `download run <hash>`
   with MD4 verification into `incoming`.
2. Apply the persistent blacklist to TCP server choice and to
   `import servers` cleanup.
3. KAD remains the next major engine (user approval required).

Continuation prompt for the next session:
[docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md).



## 12. Handoff prompt for a new session [DEPRECATED — актуальный промпт в continuation-prompt.md]

Актуальный праймер-промпт для нового окна живёт в
[docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md)
(раздел «Copy-paste prompt») и синхронизируется в конце каждой сессии.
Блок ниже — устаревший промпт сессии 1, сохранён для истории.

```text
(устарел — см. docs/continuation-prompt.md)
```
## 13. Definition of done for next session [DEPRECATED — сессия 1; актуальное в continuation-prompt.md]

The next session is complete when all are true:

1. Pending integration tree is reviewed and committed.
2. Public repository `main` contains no private files or machine-specific paths.
3. Offline tests pass through `K:\work\AmuleD_v2\.venv\Scripts\python.exe`.
4. Gated live tests either pass or failures are reduced to explicit new protocol findings.
5. Search results persist in DuckDB.
6. CLI can list cached search results.
7. ROADMAP is updated with the new current state.
8. Any destructive Git operation was performed only with explicit user permission.

## 11b. KAD engine session findings (2026-09-23) [DONE — находки, читать]

Implemented (commits 7afbffb, 9d05d18, 710d9b9):
- core/kad/: packets (kad2 codec + opcodes), nodes_dat (v0-v2 parser),
  bootstrap (live UDP, 63 contacts/run), routing (K=10 zone tree),
  search (eMule-faithful iterative lookup), obfuscation (RC4 decode/encode),
  rtt / quality / vivaldi / strategies (pluggable seed ordering).
- scripts/kad_warmup.py: 20-min maturation with HELLO/PING cycles,
  node cache (db/kad_nodes.json + DuckDB table kad_nodes), full tagged JSONL.

Live-verified findings:
1. Wire oracle (tshark vs real eMule 0.50a, KAD UDP port 8089): our REQ/RES
   bytes are IDENTICAL to the real client; real eMule RES contacts are also
   ~target-agnostic (max prefix 5 bits over 14 responses). Non-convergence
   is network behavior, not our bug: convergence needs volume + time
   (thousands of queries over minutes), matching real eMule warm-up.
2. Kad2 UDP obfuscation fully implemented and live-verified: replies to
   HELLO decode with MD5(our NodeID || wire[1:3]) RC4 keys; per-node
   udp_key (sender verify key) harvested; encoder sends obfuscated REQs
   (accepted by nodes).
3. REQ sanity check: third field must be the RECEIVER's KadID (we fixed
   sending our own - nodes silently drop otherwise). Default contact
   count observed on real eMule: 0x0B (11, KADEMLIA_FIND_VALUE_MORE).
4. Strictly-closer filter (Search.cpp ProcessResponse) implemented; chain
   descends to ~15 bits then starves - node tables are shallow along
   arbitrary target paths (maxType=2 fresh-contact filter limits depth).
5. A/B test xor vs kadabra bandit ordering: mechanics work (weights
   differentiate rewarded nodes), but convergence ceiling unchanged (15
   bits) - bandit selects askers, cannot create closer contacts.

Open: keyword search returns 0 results until a lookup reaches the keyword
zone (~20-25 bits). Next candidates: (a) long-running background lookup
session (minutes, like real eMule), (b) wire-oracle diff on a full real
eMule keyword SEARCH_KEY_REQ flow, (c) parse tag payloads of HELLO_RES
versions for extra routing hints.
## 11d. Session 6: KAD sources LIVE + spider daemon + menu (2026-09-23) [DONE — актуальные хвосты в continuation-prompt.md]

Commits f4b9065, c01a9c5 (после f79492a). Состояние:
- **KAD file-source search LIVE:** core/kad/source_search.py (KADEMLIA2_SEARCH_SOURCE_REQ/RES, теги 0xF3-0xFF, network-order IP, IsGoodIPPort-валидация) — 13 источников по реальному хешу, 10 в DuckDB (source_type='kad'). Todo 1 закрыт.
- **CLI kad search/sources + search kad** поверх движка (runtime.py: load_kad_runtime/bootstrap_runtime). Todo 3 закрыт. Грабля сессии: nodes.dat-контакты в routing порождали 0-ответы closest-first — убраны из runtime (bootstrap-only).
- **Sliding-window** поиска: any-response refresh (иначе starvation на мёртвых узлах).
- **kad_spider.py + AmuleD_Demon_KAD-Spider.ps1:** постоянная тёплая сеть (1 UDP-сокет, HELLO/PING, bootstrap, JSON+DuckDB+kad_status.json с hot_stats, DuckDB close-per-save). Сеть без демона = холодная = 0 результатов.
- **amuled_menu.py + AmuleD_Menu.ps1:** интерактивное меню (v1-style: нумерованные результаты, мультивыбор 1,3,5/2-5) поверх CLI --json.
- Offline suite: 192 passed, 2 skipped.
- Открыто: todo 2 (пир рвёт соединение на файловом запросе — wire-сверка), ротация протухших узлов паука, входящий kad-listener.

## 11c. KAD SOLVED (2026-09-23, ~17:45) [SOLVED — история, старт сессии 6]
- ROOT CAUSE of non-convergence: CFileDataIO::ReadUInt128/WriteUInt128 are
  raw 16-byte memcpy of internal LE words (NOT SetValueBE). Node distance
  metric = LE-word order (word0 = LEint(wire[0:4]), most significant).
  Our BE-int metric misread every distance => contacts looked random.
- Fix: KadUInt128 internal = w0<<96|w1<<64|w2<<32|w3 with w_i = LEint(wire);
  wire format unchanged; keyword_target uses from_be_bytes (SetValueBE of
  MD4) per KadGetKeywordHash.
- LIVE RESULT: kad_keyword_search('video') = 200 real results (hash/name/
  size) in ~1 second on the warmed table. KAD search milestone DONE.
- Commit f79492a. Wire oracle pcap: tmp/emule_wire.pcapng, dump in
  tmp/wire_dump.txt (eMule KAD UDP port 8089, count=0x0B observed).

## 11e. Session 7 (2026-09-24): TCP-obfuscation client dial [WIP — один блокер остался]

Реализовано и проверено:
1. **BASIC client obfuscation** (src\amuled_v2\core\peer\obfuscation.py v0.2.0):
   derive_basic_keys / build_basic_client_request / parse_basic_client_response.
   Ключи MD5(target_userhash||34|203||keypart_LE), запрос [marker u8][keypart u32
   LE][RC4_send: MAGIC u32 LE|0x00|0x00|padlen|pad] (крипт с байта 5), drop 1024.
   Исправлены маркеры OP_PACKEDPROT=0xD4, OP_EMULEPROT=0xC5 (были 0xC0/0xED).
   Крипто-самотест зелёный (tmp\selftest_basic_obf.py).
2. **LIVE-доказательство handshake**: MorphXT (eMule 0.50a mod, 79.56.104.188:31687,
   userhash F2D85A45870E3593A8AB83EB8BA36F30) ответил HANDSHAKE OK 4 раза на наш
   дозвон. => ключи/RC4/формат handshake ВЕРНЫ. userhash цели = sourceID из
   KAD-источников (доказано: Search.cpp:854 публикует GetClientHash = GetUserHash
   (Prefs.cpp:84); DownloadQueue.cpp:4919-4921 ставит SetUserHash(sourceID)).
3. **HELLO codec fixed**: пропущенные 6 байт хвоста server_ip u32 + server_port u16
   (SendHelloTypePacket, BaseClient.cpp:2212-2217). Без них приёмник читает за
   концом буфера. _write_hello_body/parse_hello исправлены, тесты зелёные.
4. **Framing fix в пробниках**: было [proto][opcode][len] (наш собственный баг во
   всех tmp-пробниках — «байт-в-байт валидный» HELLO сессии 6 сверялся сам с
   собой; loop_8089.pcapng оказался НАШИМ же кривым пакетом, не эталоном).
   Канон: [proto][len u32 = payload+1][opcode] (packets.cpp:32-36, 182-187).
5. **Event-driven pipeline** (tmp\pipeline_dl.py): KAD source search в процессе,
   хук на parse_search_res_source_entries → каждый свежий источник мгновенно
   дозванивается, полный ladder (FILENAME/SETREQFILEID/HASHSET → FILESTATUS →
   REQUESTPARTS_I64 → SENDINGPART_I64/COMPRESSED) + MD4. Механика работает.
6. **GETSOURCES через сервер работает**: `sources ed2k --server 176.123.5.89:4725
   --hash H --size S` (4 источника; фильтровать 10.x/224+).

Факты сети:
- Plain-протокола в современной сети НЕТ (подтверждено живо): валидный plain
  HELLO → мгновенный FIN или 10 с тишины. Обфускация обязательна.
- KAD-источники умирают за минуты; TCP connect ≠ живой пир (NAT ACK-ает за
  приложение). 7/7 type-1 источников ubuntu-файлов молчат на handshake.
- Суточный круг источников: eMuleAI качает те же файлы успешно (uTP у него
  есть; TCP-порт меняется каждый запуск: 8082 → 27987).

ОСТАВШИЙСЯ БЛОКЕР (единственный, стадия B):
- После obf handshake OK + канонический HELLO → приёмник закрывает соединение
  (FIN без данных, <0.5 с). HELLOANSWER не приходит. Исключено: ник ("AmuleD"
  → "tester"), ранний EMULEINFO (шлём/не шлём — одинаково), константы типов
  тегов (совпадают с opcodes.h 0.50a: UINT16=0x08, UINT8=0x09, BLOB=0x07,
  BSOB=0x0A, UINT64=0x0B), wire-формат тегов (парсер Packets.cpp:444-518
  соответствует нашему writer 1:1), формат userhash.
- Путь к ground truth: расшифровать живой дозвон eMuleAI. keypart — открытым
  текстом (байты 1-5 handshake); ключи = MD5(target_userhash+34/203+keypart).
  Userhash eMuleAI извлечён: 1415AF07…(redacted)
  (config\preferences.dat offset 0; подтверждён preferencesKad.dat ↔ логом
  myKadID=99F088F0795D8B8613EEC8D4C8E36A25). Расшифровывает ВХОДЯЩИЕ дозвоны
  к eMuleAI. Блокер: поймать дозвон eMuleAI к IP, чей userhash знаем из KAD
  (сверка IP из tshark-SYN-ловли с kad sources его текущего файла).
- Состояние сюиты: 195 passed, 2 skipped; compileall 0. Незакоммичено:
  codec.py (хвост HELLO), obfuscation.py v0.2.0. Изменён scripts\sanitize_log.py
  (проверить diff). В worktree удалены docs\AmuleD_v2_SPEC.md и
  docs\PROTOCOL_MATRIX.md (D в git status) — не коммитить удаления без
  разрешения.

Следующие шаги (по порядку):
1. Спросить внешний LLM (промпт в чате сессии 7, репо https://github.com/eMuleAI/eMuleAI)
   о причине мгновенного FIN после HELLO при валидном handshake.
2. Поймать расшифровку: tshark iface 6 фильтр SYN от 192.0.2.10 → IP цели →
   kad sources файла, который eMuleAI качает (виден в transfers/логе SXSend) →
   userhash → decrypt → байт-diff его HELLO с нашим.
3. После решения: подключить obfuscation к PeerClient + download runner,
   скачать файл ≤10 МБ end-to-end (MD4), коммит.
