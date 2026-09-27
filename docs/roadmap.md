# AmuleD v0.5.1 — Operational Roadmap and Session Handoff
[STATUS LEGEND] DONE = completed, do not touch | SOLVED = problem solved | WIP = in progress | DEPRECATED = outdated, read only for context | TODO = to do. Current: 11c (SOLVED) and 11b. Sections 2-8, 12-13 — DEPRECATED (session 1-4 history).

Date updated: 2026-09-23 (sessions 2–4: search persistence, GLOBAL UDP, AUTO, source lifecycle, peer protocol, download stack, ipfilter/blacklist). Current project state — sections 11a–11c (11c: KAD search SOLVED — 200 results for "video" in 1s); historical sections 2–5 describe the state at session 1 and are kept for context of findings. Continuation of work: [docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md). This file is a local working roadmap of the standalone AmuleD project and is not published to Git.

## 1. Canonical workspace and runtime [DONE — forever canonical]

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

## 2. Current state at handoff [DEPRECATED — session 1, current in 11a-11c]

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

## 3. Confirmed protocol findings [DONE — eternal facts, read, do not redo]

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

### 3.8 Real search acceptance, publish step, and server throttling [DONE + WIP: Sunrise throttling periodic]

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

The generic phrase "ED2K search" is insufficient. eMule has explicit channels:

- `auto`: resolve between server/global/KAD using reference eMule rules.
- `server`: search only the current connected ED2K server over TCP using `OP_SEARCHREQUEST`.
- `global`: search current server plus other known servers, with UDP request variants.
- `kad`: Kademlia keyword search.
- `web-edonkey`: external web eDonkey service.

AmuleD v2 now has an explicit model in [search_channels.py](file:///K:/work/AmuleD_v2/src/amuled_v2/core/search_channels.py). CLI exposes `search server`, `search auto`, `search global`, `search kad`, and `search web-edonkey`; old `search ed2k` remains only as a compatibility alias for `server`.

Only `server` is implemented and live-validated. `global`, `kad`, and `web-edonkey` return structured `not_implemented` status instead of silently falling back.

## 4. Legacy AmuleD v1 search stack [DEPRECATED — v1, only for context]

The legacy v1 wrapper did not contain a direct ED2K binary parser. Its live search flow used:

- [test_client.py](file:///O:/Work/Coding/Paradise_Lost_KAD_SA/test_client.py)
- [amule_cookie.txt](file:///O:/Work/Coding/Paradise_Lost_KAD_SA/amule_cookie.txt)
- HTTP access to local amuleweb at `http://127.0.0.1:4711`
- `requests`
- `BeautifulSoup`

V1 logged into the web UI, cleared state, submitted a real search, waited approximately 30 seconds, parsed real result tables, and selected real ed2k links for download. ED2K/KAD protocol handling remained inside `amuled.exe`; v1 itself was only a wrapper and HTML result parser.

The v1 lesson carried into K is: use real server, real links, and a real accumulation window. Do not replace network integration with fake servers or synthetic result payloads.

## 5. Immediate 2do: finish and publish pending work [DONE — sessions 2-4]

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

### 5.2 Push after verification [DONE partly, WIP: new commits await confirmation]

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

## 6. Immediate 2do: complete search-channel integration [PARTLY DONE: SERVER/AUTO/ GLOBAL DONE; KAD SOLVED in 11c; WIP: sources via KAD]

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

### 6.2 AUTO channel [DONE — but the AUTO channel switches via Kad now preferentially]

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

### 6.4 KAD channel [SOLVED — see 11b/11c; WIP: sources via KAD, CLI kad-commands]

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

### 6.5 WEB-EDONKEY channel [TODO — not started]

This channel is external and optional. Do not build it before GLOBAL/KAD unless the user specifically needs it. It requires:

1. Adapter isolation behind `SearchChannel.WEB_EDONKEY`.
2. External service endpoint configuration.
3. Rate limits and result normalization.
4. Explicit privacy and legal policy.

## 7. Immediate 2do: source lifecycle [DONE for ed2k-sources; TODO: kad-sources]

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

## 8. Next major milestones [8.1-8.5 DONE]

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

### 8.2 Download queue [DONE — stack + launch in core; live receive from another peer — remaining]

After unified results, implement:

1. Download queue state in DuckDB. [DONE]
2. Native `.part` file format. [DONE]
3. Chunk bitmap and gap list. [DONE]
4. Source scheduling. [DONE — runner v0.2.0: parallel race to max_peers peers, first complete result wins]
5. Block request pipeline. [DONE]
6. Hashset request and verification. [DONE]
7. AICH recovery data. [TODO]
8. Final assembly into `incoming`. [DONE — finalize with MD4 verification]
9. Pause/resume/cancel. [DONE — via kernel IPC]
10. Disk-space checks. [TODO]

Session 10 (2026-09-26): `download run` runs INSIDE the core (owns DuckDB), CLI starts the task and polls `download.status` via IPC; sources — via `sources.list` IPC. E2E test: core downloads from its own listener, MD4 verified (tests/test_kernel.py).

This is milestone M8 in the broader plan and should not start before source lifecycle is stable.

### 8.3 Peer protocol [DONE — complete client and server stack; source exchange as a separate TODO feature]

Required after download queue:

1. Client hello. [DONE]
2. File request. [DONE]
3. Hashset request. [DONE]
4. Queue rank. [DONE — periodic QUEUERANK with connection retention, slot promotion (stage X, session 10)]
5. Block request/response. [DONE]
6. Compressed blocks. [DONE]
7. Peer source exchange. [DONE — responder v2/v4 (session 14); legacy gated]
8. Dead source handling. [PARTLY — low-id filter, prune/forget]
9. Upload slots and queues. [DONE — credits→priority, slot rotation, TTL]
10. Bandwidth throttling. [DONE]

### 8.4 Security [DONE — credits; obf-accept/obf-dial (session 11); SUI SecureIdent (sessions 13-14)]

Implement only after stable transfer behavior:

1. TCP obfuscation. [DONE — client dial LIVE (session 7/11); server accept (session 11)]
2. UDP obfuscation. [TODO — not on the live path]
3. DH handshake. [DONE — live with a real server (session 11)]
4. Secure identification. [DONE — RSA-384 core (session 13) + SUI wire (session 14)]
5. Client credits. [DONE — accounting both ways, credits→priority]
6. Crypto_key persistence. [TODO — external session]

Reference sources:

- [aMule EncryptedStreamSocket.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/EncryptedStreamSocket.cpp)
- [aMule EncryptedDatagramSocket.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/EncryptedDatagramSocket.cpp)
- [aMule RC4Encrypt.cpp](file:///O:/Work/Coding/aMule-2.3.3/src/RC4Encrypt.cpp)
- [eMule ServerSocket.cpp](file:///O:/Work/Coding/eMule_0.50a/srchybrid/ServerSocket.cpp)

### 8.5 IP filter, GeoIP, UPnP/NAT-PMP [PARTLY — ipfilter+UPnP/NAT-PMP DONE, GeoIP TODO]

After live transfer:

1. Parse bundled IP filters. [DONE]
2. Apply filter levels to peers and servers. [DONE]
3. Use bundled [GeoIP.dat](file:///K:/work/AmuleD_v2/assets/v1/GeoIP.dat). [TODO]
4. Add NAT diagnostics. [DONE — nat-result in core]
5. Add UPnP/NAT-PMP port mapping. [DONE — core/nat/upnp.py: SSDP+SOAP+NAT-PMP, map/unmap in core, session 10]
6. Improve lowid diagnosis. [PARTLY]

## 9. Test policy [DONE — active policy]

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

## 10. Privacy, Git, and local files [DONE — active rules]

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

## 11. Open risks and unresolved tails [WIP — see also 11a-11c]

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

## 11a. Session 3-4 state (2026-09-23) [DONE — history, current in 11b/11c]

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



## 12. Handoff prompt for a new session [DEPRECATED — active prompt in continuation-prompt.md]

The active template prompt for a new window lives in
[docs\continuation-prompt.md](file:///K:/work/AmuleD_v2/docs/continuation-prompt.md)
(section "Copy-paste prompt") and is synchronized at the end of every session.
The block below is the outdated session 1 prompt, saved for history.

```text
(outdated — see docs/continuation-prompt.md)
```
## 13. Definition of done for next session [DEPRECATED — session 1; active in continuation-prompt.md]

The next session is complete when all are true:

1. Pending integration tree is reviewed and committed.
2. Public repository `main` contains no private files or machine-specific paths.
3. Offline tests pass through `K:\work\AmuleD_v2\.venv\Scripts\python.exe`.
4. Gated live tests either pass or failures are reduced to explicit new protocol findings.
5. Search results persist in DuckDB.
6. CLI can list cached search results.
7. ROADMAP is updated with the new current state.
8. Any destructive Git operation was performed only with explicit user permission.

## 11b. KAD engine session findings (2026-09-23) [DONE — findings, read]

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
## 11d. Session 6: KAD sources LIVE + spider daemon + menu (2026-09-23) [DONE — current tails in continuation-prompt.md]

Commits f4b9065, c01a9c5 (after f79492a). State:
- **KAD file-source search LIVE:** core/kad/source_search.py (KADEMLIA2_SEARCH_SOURCE_REQ/RES, tags 0xF3-0xFF, network-order IP, IsGoodIPPort-validation) — 13 sources on a real hash, 10 in DuckDB (source_type='kad'). Todo 1 closed.
- **CLI kad search/sources + search kad** over the engine (runtime.py: load_kad_runtime/bootstrap_runtime). Todo 3 closed. Session pitfall: nodes.dat-contacts in routing produced 0-answers closest-first — removed from runtime (bootstrap-only).
- **Sliding-window** search: any-response refresh (otherwise starvation on dead nodes).
- **kad_spider.py + AmuleD_Demon_KAD-Spider.ps1:** continuous warm network (1 UDP-socket, HELLO/PING, bootstrap, JSON+DuckDB+kad_status.json with hot_stats, DuckDB close-per-save). Network without the daemon = cold = 0 results.
- **amuled_menu.py + AmuleD_Menu.ps1:** interactive menu (v1-style: numbered results, multi-select 1,3,5/2-5) over CLI --json.
- Offline suite: 192 passed, 2 skipped.
- Open: todo 2 (peer tears connection on file request — wire-check), rotation of stale spider nodes, incoming kad-listener.

## 11c. KAD SOLVED (2026-09-23, ~17:45) [SOLVED — history, start of session 6]
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

## 11f. Session 8 (2026-09-24): upload engine stage C [DONE — queue + upload engine; integration — stage D]

Decision made: obfuscation dial (blocker 11e) is not a blocker for the rest
of the stack — it was temporarily moved out (docs\Cloud_Prompt_Help_Plz.md),
wire-transport contact points were mocked; both sides are now REAL
(session 11: RC4-stream dial + inbound accept, blocker #6 closed).

Implemented (uncommitted):
- **core/upload/queue.py** — wait queue per eMuleAI UploadQueue.cpp rules:
  priority PR_LOW/NORMAL/HIGH → FIFO, 1-based rank, max_slots=4, slot TTL 600s,
  dedupe by (user_hash, requested_hash).
- **core/upload/engine.py** — UploadSession over injectable UploadTransport:
  REQUESTFILENAME→REQFILENAMEANSWER, HASHSETREQUEST→HASHSETANSWER (without chunk-hashes →
  END_OF_DOWNLOAD), REQUESTPARTS(_I64)→SENDINGPART/COMPRESSEDPART. Semantics
  verified against UploadDiskIOThread.cpp CreateStandardPackets/CreatePackedPackets:
  sub-packets ≤13000 bytes (10240 on remainder), I64 family selected by
  endpos > UINT32_MAX on sub-packet, COMPRESSEDPART carries BLOCK start + total
  comp size. UploadThrottle (bytes/s), BlockSource (PARTSIZE-chunks).
- **core/peer/codec.py v0.2.0** — builders of the response side: QUEUERANK,
  ACCEPTUPLOADREQ, END_OF_DOWNLOAD, SENDINGPART_I64, COMPRESSEDPART_I64,
  REQFILENAMEANSWER, FILESTATUS.
- All contact points with wire transport were marked
  `# WIP by external developer: encrypted transport (BASIC obfuscation / DH)`
  at the time; the marks are removed since session 11 (real obfuscation).
- Offline suite: **266 passed, 2 skipped** (+71 tests in tests/test_upload.py).

REAL-DATA VALIDATION (stage C/D, 2026-09-25):
- Registered a real shared Incoming folder of the installed
  eMuleAI (79 files, ~469 MB) via `share scan --json` — paths saved
  in DuckDB.
- Known issue: before scan all imported v1-rows had path=NULL.
- **Hash validation against a real client:** our ED2K-hashes 79/79 matched
  `config\known.met` eMuleAI (parser format: [u8 0x0F][u32 count]; record =
  [u32 date][hash16][u16 part_count][parts×16][u32 tagcount][tags]; tags:
  0x02-strings with u16-len name/value, 0x03 u32, 0x0B u64, 0x11..0x30 STRn
  of fixed length). Hashing byte-for-byte compatible with the real client.
- Listener-tests 5/5 (HELLO, full upload-flow, QUEUERANK on busy slots,
  END_OF_DOWNLOAD on unknown hash, EMULEINFO). Semantics fixed vs
  UploadDiskIOThread.cpp: SENDINGPART family per sub-packet (endpos > u32max),
  answers to REQUESTFILENAME/HASHSETREQUEST immediate, accept via engine hook.

Next steps: stage D (incoming peer-listener, routing STARTUPLOADREQ →
queue + UploadSession; transport = mock until external session verdict), KAD publish,
SecureIdent-framework (crypto — mock), rotation of stale spider nodes.

## 11e. Session 7 (2026-09-24): TCP-obfuscation client dial [WIP — passed to external session]

Implemented and verified:
1. **BASIC client obfuscation** (src\amuled_v2\core\peer\obfuscation.py v0.2.0):
   derive_basic_keys / build_basic_client_request / parse_basic_client_response.
   Keys MD5(target_userhash||34|203||keypart_LE), request [marker u8][keypart u32
   LE][RC4_send: MAGIC u32 LE|0x00|0x00|padlen|pad] (crypto from byte 5), drop 1024.
   Fixed markers OP_PACKEDPROT=0xD4, OP_EMULEPROT=0xC5 (were 0xC0/0xED).
   Crypto self-test green (tmp\selftest_basic_obf.py).
2. **LIVE handshake proof**: MorphXT (eMule 0.50a mod, 79.56.104.188:31687,
   userhash F2D85A45870E3593A8AB83EB8BA36F30) answered HANDSHAKE OK 4 times to our
   dial. => keys/RC4/format of handshake VERIFIED. target userhash = sourceID from
   KAD-sources (proved: Search.cpp:854 publishes GetClientHash = GetUserHash
   (Prefs.cpp:84); DownloadQueue.cpp:4919-4921 sets SetUserHash(sourceID)).
3. **HELLO codec fixed**: missing 6 bytes of tail server_ip u32 + server_port u16
   (SendHelloTypePacket, BaseClient.cpp:2212-2217). Without them the receiver reads
   past the end of the buffer. _write_hello_body/parse_hello fixed, tests green.
4. **Framing fix in probes**: was [proto][opcode][len] (our own bug in
   all tmp-probes — "byte-for-byte valid" HELLO of session 6 checked itself;
   loop_8089.pcapng turned out to be OUR OWN broken packet, not a reference).
   Canon: [proto][len u32 = payload+1][opcode] (packets.cpp:32-36, 182-187).
5. **Event-driven pipeline** (tmp\pipeline_dl.py): KAD source search in progress,
   hook on parse_search_res_source_entries → every fresh source dials instantly,
   full ladder (FILENAME/SETREQFILEID/HASHSET → FILESTATUS →
   REQUESTPARTS_I64 → SENDINGPART_I64/COMPRESSED) + MD4. Mechanics work.
6. **GETSOURCES via server works**: `sources ed2k --server 176.123.5.89:4725
   --hash H --size S` (4 sources; filter 10.x/224+).

Network facts:
- Plain-protocol in modern network does NOT exist (proved live): valid plain
  HELLO → instant FIN or 10s silence. Obfuscation is mandatory.
- KAD-sources die within minutes; TCP connect ≠ live peer (NAT ACKs at
  application layer). 7/7 type-1 sources of ubuntu-files silent on handshake.
- Daily source cycle: eMuleAI downloads same files successfully (it has uTP;
  TCP-port changes each run: 8082 → 27987).

REMAINING BLOCKER (the only one, stage B):
- After obf handshake OK + canonical HELLO → receiver closes connection
  (FIN without data, <0.5s). HELLOANSWER does not arrive. Ruled out: nickname ("AmuleD"
  → "tester"), early EMULEINFO (sent/not sent — same), tag type constants
  (match opcodes.h 0.50a: UINT16=0x08, UINT8=0x09, BLOB=0x07,
  BSOB=0x0A, UINT64=0x0B), wire-format of tags (parser Packets.cpp:444-518
  matches our writer 1:1), userhash format.
- Path to ground truth: decode live dial of eMuleAI. keypart — open text
  (bytes 1-5 of handshake); keys = MD5(target_userhash+34/203+keypart).
  eMuleAI userhash extracted: 1415AF07…(redacted)
  (config\preferences.dat offset 0; confirmed preferencesKad.dat ↔ log
  myKadID=99F088F0795D8B8613EEC8D4C8E36A25). Decodes INCOMING dials
  to eMuleAI. Blocker: catch eMuleAI's dial to IP whose userhash we know from KAD
  (match IP from tshark-SYN-catch with kad sources of its current file).
- Suite state: 195 passed, 2 skipped; compileall 0. Uncommitted:
  codec.py (HELLO tail), obfuscation.py v0.2.0. Changed scripts\sanitize_log.py
  (check diff). In worktree deleted docs\AmuleD_v2_SPEC.md and
  docs\PROTOCOL_MATRIX.md (D in git status) — do not commit deletions without
  permission.

Next steps (in order):
1. Ask external LLM (prompt in session 7 chat, repo https://github.com/eMuleAI/eMuleAI)
   about the reason for instant FIN after HELLO with valid handshake.
2. Catch the decode: tshark iface 6 filter SYN from our LAN-IP → target IP →
   kad sources of the file eMuleAI downloads (seen in transfers/log SXSend) →
   userhash → decrypt → byte-diff their HELLO from ours.
3. After solution: connect obfuscation to PeerClient + download runner,
   download a file ≤10 MB end-to-end (MD4), commit.

## 11g. Session 10 (2026-09-26): v0.6.0 — IPC-routing + downloads in core + stage X + upload parity [DONE]

Version: `AmuleD v0.6.0` (bump 0.5.1 -> 0.6.0; AGENTS.md synchronized).
Suite: **303 passed, 3 skipped**; compileall 0. Live-verified under live core:
all read-only CLI (664 results of search via IPC), download add/cancel,
`daemon status`.

Done:

1. **Stage U phase 3 — full IPC-routing**: 15+ handlers in
   core/kernel.py (search.results.*, sources.list, download.list/add/
   pause/resume/start/cancel/run/status, servers.failures, ipfilter.status,
   upload.status). All read-only CLI and menu work UNDER live core.
   FIX: IPC-client readline-limit 64 KiB -> 64 MiB (large answers were torn).
2. **Downloads end-to-end**: DownloadRunner v0.2.0 — parallel peer race
   (first complete result wins, others cancelled);
   `download run` runs INSIDE the core (it owns DuckDB), CLI
   polls progress. E2E test: core downloads from its own listener,
   MD4 verified.
3. **Stage X**: honest MISCOPTIONS1/2 + EMULEINFO (we claim only
   compression/large files/unicode/kad2 — no handlers AICH/source
   exchange/multipacket); `upload status` CLI; UPnP IGD + NAT-PMP
   (core/nat/upnp.py, map on core start / unmap on stop).
4. **Upload parity**: periodic QUEUERANK with connection retention and
   promotion over the same connection (eMule model); slot rotation on
   timer; credits->priority (bonus = uploaded/downloaded, cap 10).
5. **known.met**: core/sharing/known_met.py (parser matched to real
   eMuleAI known.met: 904/904 records) + CLI `import known-met` /
   `export known-met`. docs/audit_checklist.md created.
6. Menu: KAD status reads kernel_status.json + daemon status via IPC.
   AmuleD_Run.ps1: spider-mode marked DEPRECATED (v2.1.1).

Remainder (work order):
1. live-acceptance `download run` from a real external peer (client-side
   obf-dial alive from session 7; inbound accept landed in session 12).
2. GeoIP: connect assets/v1/GeoIP.dat to ipfilter/statistics.
3. Stage X tails: rotation of stale spider nodes; sources without userhash
   (dial after KAD userhash-lookup); source exchange as answering side; AICH; disk-space checks.
4. Commit/push of version 0.6.0 — on explicit user command.

## 11h. Session 11 (2026-09-26): BLOCKER #6 RESOLVED — live obfuscation, DH, download [DONE - LIVE]

Cloud answer integrated (docs/recon/From_Cloude/): obfuscation.py v0.3.0
(BasicObfuscationSession - one persistent RC4 stream per direction; the
v0.2.0 bug was HELLO encrypted on a RESTARTED stream) wired into PeerClient
(client.py v0.3.0: encrypt/decrypt at consumption, no plaintext fallback,
rx-leftover buffer consumed exactly once).

LIVE TESTS (not synthetic), all against real network nodes:

1. Obf HELLOANSWER from a real eMuleAI 1.6.0 (127.0.0.1:8089):
   negotiate -> HELLO on the extended send-stream (send_offset 18 -> 109)
   -> HELLOANSWER 0x4C on the extended recv-stream. SUCCESS.
2. Live DH-session with a real ED2K-server (176.123.5.89:4725):
   plaintext DH request [marker][g^a 96B][pad] -> g^B 96B -> RC4-keys from
   shared-secret -> decoded [magic 0x835E6FC4|methods|padlen] of the server.
   SUCCESS ("proper magic after DH-Agreement").
3. End-to-end download from a real eMuleAI: full ladder (HELLO ->
   filename/hashset -> STARTUPLOADREQ -> ACCEPTUPLOADREQ -> REQUESTPARTS ->
   SENDINGPART) -> 1237/1237 bytes -> MD4 verified (e4ba0be1...). SUCCESS.

Side-findings (live-debug):
- eMuleAI userhash in preferences.dat at offset 1, not 0 (leading byte);
  identified by markers h[5]=14, h[14]=111.
- HELLOANSWER fork written WITHOUT leading byte of hash length (codec.py
  tolerates both forms).
- HASHSETANSWER fork inverted: [hash 16][count u16] (codec.py
  tolerates).
- Need a STABLE marked-client hash: shield eMuleAI bans "Userhash
  changed" on hash change between dials and penalizes "Bad user hash"
  without SO_EMULE markers (PeerClient: local_userhash + markers).
- OP_OUTOFPARTREQS (0x57) immediately after slot grant = source has not
   prepared blocks yet; transfer retries up to 5 times with 3s pause.
- HELLO parity (cloud paragraph 7): old CTag tag format, order
   NAME,VERSION,UDPPORTS,MISO1,MISO2,EMULE_VER; CryptLayer
   Supports+Requests bits (0x180).

Suite: 315 passed, 3 skipped; compileall 0.

Remainder: sources with userhash from KAD into download.run core (runner already
passes target_userhash — check on a real KAD-source); GeoIP;
spider node rotation.

## 11i. Session 12 (2026-09-26): incoming obfuscation accept + GeoIP [DONE]

1. **Incoming obfuscated accept (stage X, closes the acceptor half of
    the former transport blocker)**: obfuscation.py — acceptor side (accept_basic_client /
    accept_dh_client / accept_obfuscated_client), mirror-key derivations
    (recv=34/send=203 from own userhash; DH: send=203/recv=34).
    listener.py v0.2.0: _expect_first_packet — 0xE3/0xC5/0xD4 -> plain,
    otherwise obf-accept; StreamTransport decodes in-place at consumption,
    decrypted leftovers consumed exactly once. WIP-mocks of incoming
    obfuscation in listener removed.
   Tests: BASIC-dial from our live-verified PeerClient to our
   listener with full download and MD4; DH-dial with manual key-derivation.
2. **GeoIP**: official maxminddb package (MMDB — eMuleAI format, parity);
   legacy GeoIP.dat left as best-effort fallback (walk requires
   cross-check with code table — marked honestly); CLI `amuled geoip lookup`.
3. Dependencies: + maxminddb>=2.6 (requirements.txt, pyproject.toml, uv).

Suite: 320 passed, 3 skipped; compileall 0.

Remainder: stable country-mapping of legacy dat (low priority — MMDB is primary); source exchange as answering side; AICH; SUI SecureIdent wire half; spider node rotation.


## 11j. Session 13 (2026-09-26): SUI SecureIdent — core DONE, wire half [WIP]

1. **SecureIdent RSA-384 (stage X, full SUI)**:
   - secure_ident.py v0.3.0: PyCryptodome RSA.construct (generate requires
     >=1024) + pkcs1_15/SHA1; cryptkey.dat = Base64 PKCS#1 DER (eMule
     format); signature 48 bytes, blob 58 (<80); signs [signer blob][challenge][IP-block v2?].
   - codec.py: SUI payloads (secident_state/publickey/signature) +
     miso1_secident_support.
   - client.py: opcodes 0x85/0x86/0x87 in C2CEMULE; constructor secure_ident
     (handshake integration — resume point in continuation-prompt).
   - listener.py: SUI branches (SECIDENTSTATE->PUBLICKEY+SIGNATURE,
     SIGNATURE->verify->mark_verified) — written, not yet verified.
   - Capabilities: miso1 SecIdent=3, EMULEINFO features=3.
2. Disk-space gate in queue.finalize.
3. Dependencies: maxminddb (session 12) — already in requirements/pyproject.

Suite: credits 8 passed (3 new SUI); compileall 0.

## 11k. Session 14 (2026-09-27): SUI wire + source exchange + spider rotation + AICH [DONE]

1. **SUI wire half closed (stage X)**: client.py handshake() —
   SECIDENTSTATE(2, rand) after EMULEINFO exchange when peer SUI
   (miso1_secident_support) and provider.has_keys; handshake loop answers
   SECIDENTSTATE (PUBLICKEY+SIGNATURE over their challenge) and verifies
   incoming SIGNATURE (peer_blob + challenge_out -> mark_verified); SUI
   grace window (3 s) after hello/info so the peer signature is not lost.
   Wire-test loopback: tests/test_sui_wire.py (mutual verification).
2. **Provider wired**: kernel.py — SecureIdentProvider(key_path =
   ROOT/config/cryptkey.dat), ensure_keys at kernel start, passed to
   IncomingPeerServer and DownloadRunner -> PeerClient.
3. **Source exchange responder**: codec.py — SXSource,
   parse_request_sources(2), build_answer_sources(2) (layout oracle
   KnownFile.cpp CreateSrcInfoPacket / ListenSocket.cpp:2285-2298: SX2 =
   [ver u8][options u16 LE][hash16]; entries [id][port][server ip/port]
   (+userhash v>=2, +connectOptions v>=4); v3 high-id id without htonl;
   cap 500; gate reqver>0 or SX1ver>1). listener.py — 0x81/0x82/0x83
   branches + source_provider plumbing (kernel: state file_sources rows
   with userhash). Capability bits enabled: miso1 SX=1, miso2 bit10,
   EMULEINFO 0x23=4. Tests: tests/test_source_exchange.py.
4. **Spider node rotation**: spider.py — per-node fails counter (cache
   roundtrip persisted), hello/ping timeout sweep (90 s -> fail), eviction
   at 3 fails, bootstrap seeds enter the pool each bootstrap_every cycle.
   Tests: tests/test_kad_spider.py.
5. **AICH responder**: aich.py — materialize_aich_tree +
   aich_part_recovery_data (SHAHashSet.cpp CreatePartRecoveryData layout:
   [count16][ident u16/hash 20]*n[u16 0]; 32-bit idents for large files);
   codec.py — AICHREQUEST/ANSWER payloads (0x9B/0x9C); listener.py —
   0x9B branch (gates: shared complete file, master match, part in
   range); cap_aich=1. Tests: tests/test_aich_wire.py (incl. client-side
   master reconstruction from recovery data).
6. Docs cleaned from the abolished external-session/blocked markings
   (epoch closed in session 11).

## 11l. Session 14b (2026-09-27 evening): callback stack + reachability [DONE]

1. **Direct-UDP-callback (KAD type 6) [DONE]**: direct_callback.py
   (OP_DIRECTCALLBACKREQ 0x95 client-UDP 0xC5), listener.expect_connection_from
   (inbound reservation by IP), PeerClient.adopt_connection (downloader role
   over an accepted socket), DownloadRunner kad6 flow. Loopback:
   tests/test_direct_callback.py (fake firewalled source dials back, MD4
   verified).
2. **Buddy-callback (KAD type 3/5) [DONE]**: KADEMLIA_CALLBACK_REQ 0x52 to
   the serving buddy [buddy KadID 16][file hash 16][tcp u16] (BaseClient.cpp:
   3258-3282, relay KademliaUDPListener.cpp:1813-1868, opcodes Opcodes.h:810/
   348); buddy_id persisted (migration 9 file_sources.buddy_id; FoundSource.
   buddy_id; kad CLI save); runner kad3/kad5 flow. Loopback test passed.
3. **Reachability [DONE, live]**: upnp.py v0.2.0 — SSDP discovery is
   multi-NIC (VPN tunnel owns the default route and shadowed the LAN IGD);
   live-mapped listener port via router 192.168.3.1 (NAT mapping ok).
4. **Server login parity [DONE]**: OP_LOGINREQUEST rewritten per oracle —
   OLD CTag tag form (compact form was ignored: 10 s drop), tag set
   ServerConnect.cpp:198-245, SRVCAP flags (Opcodes.h:725-734); identity
   userhash now SO_EMULE-marked (one-time upgrade persisted) instead of a
   fresh unmarked random hash per call.
5. **Source typing [DONE]**: numeric KAD source type persisted
   ("kad1"/"kad3"/...; migration 8/9 + FoundSource.kad_type/kad_udp_port/
   buddy_id); runner dials direct rows, sends callbacks for kad6/kad3/kad5;
   SX answers only direct rows.

Suite: 333 passed, 3 skipped; compileall 0. Remainder: live download.run
awaits clean network records (today's type-1 records FIN — stale/poisoned
userhash at the peer side); NAT-T (item 5) only for double-firewalled
corners. Commit+push on explicit user command.

## 11m. Session 14c (2026-09-27 night): NAT-T transports [DONE - transports]

1. **QUIC NAT-T transport (aioquic) [DONE]**: quic_transport.py —
   standard IETF QUIC (aioquic), ALPN "ed2k-ai-natt-quic-v1" (QuicNatConfig
   .h:12), downloader = QUIC client / source = server bootstrapped from the
   first Initial (pull_quic_header -> original_destination_connection_id);
   EAQN1 proof exchange as the first 37 stream bytes (QuicNatSocket.cpp:
   619-650); all datagrams wrapped OP_UDPRESERVEDPROT2 (0xB2) /
   OP_NATT_FRAME_QUIC (0x01). Proof/handshake verified over loopback
   (tests/test_natt_quic.py). Dependency: aioquic>=1.2 (requirements.txt +
   pyproject.toml).
2. **uTP NAT-T transport [DONE]**: utp.py — minimal BEP 29 uTP over
   asyncio (SYN/STATE/FIN, cumulative acks, reorder buffer, retransmit
   0.6 s x40, 20-byte header ">BBHIIIHH"); asyncio reader/writer adapters
   for PeerClient. tests/test_natt_utp.py.
3. **Rendezvous request [DONE]**: OP_REASKCALLBACKUDP (0x94) builder +
   sender (BaseClient.cpp:3147-3196 layout, RENDEZVOUS 0xA0, ENDPOINT_HINT
   0x20, UTP 0x80); CONNECT_OPT constants recorded (Opcodes.h:215-221).

Remainder (next session): rendezvous state machine wiring (holepunch burst
+ endpoint-hint handling + expectation table) to connect the transports to
DownloadRunner; QUIC/wire interop check against a live eMuleAI NAT-T
session; suite 335 passed / 3 skipped.

Suite: 331 passed, 3 skipped; compileall 0. Remainder: LIVE kernel
download.run from a real KAD source; commit+push on user command.

## 11n. Session 14d (2026-09-27): NAT-T rendezvous state machine [DONE]

1. **NAT-T UDP session layer [DONE]**: core/natt/session.py —
   NattUdpSession (asyncio DatagramProtocol) on a client-UDP socket:
   0xC5 demux of OP_HOLEPUNCH (0xA1, empty), OP_NATT_ENDPOINT_HINT (0xAA,
   56-byte layout per ClientUDPSocket.cpp:1301-1365) and 0xB2 frames
   (CAPS 0x02/CAPS_ACK 0x03 — magic 0x43514145, version 1, options byte,
   three 16-byte hashes, :480-521/:688-793; KEY 0xFF — 16-byte userhash,
   :397-407/:999-1006; UTP 0x00 / QUIC 0.01 payloads). Expectation table
   (30 s TTL, max 64, port-window fuzzy match, :141-293).
2. **Requester flow [DONE]**: rendezvous_connect() — OP_REASKCALLBACKUDP
   (rendezvous marker) SENT FROM THE SESSION SOCKET (buddy answers are
   addressed to the sender endpoint — a fresh socket never receives the
   hint/holepunch; caught in loopback debugging), endpoint-hint wait with
   3 retries, holepunch burst 12 + port sweep (:1957-2015), CAPS exchange
   3 + sweep (:523-550) advertising uTP only (0x80; QUIC 0x40 never
   advertised — ngtcp2 interop unproven), uTP connect + KEY frame.
3. **Source role [DONE]**: arm_source() — answers holepunch with CAPS and
   accepts inbound uTP SYNs (on_inbound_utp callback; mirrors
   :2021-2214), for loopback doubles and the future kernel wiring.
4. **uTP fixes [DONE]**: recv() eof/get race consumed two queue items per
   call and silently dropped a chunk (the HELLO packet was eaten and the
   source session parsed EMULEINFO as first packet — caught in loopback);
   accept() on_created callback registers the stream BEFORE the SYN-ack
   so post-connect DATA is not dropped by the demuxer.
5. **DownloadRunner wiring [DONE]**: kad3/kad5 rows — after the 12 s
   buddy-callback timeout (was 20 s) fall through to the rendezvous path
   (_connect_via_rendezvous: NattUdpSession -> uTP stream ->
   PeerClient.adopt_connection over the stream adapters; session kept
   alive via a closer callback); callback_identity may carry ext_ip.

Suite: 336 passed, 3 skipped; compileall 0. Remainder: LIVE interop check
against a real eMuleAI NAT-T session (eMuleAI logs: [NatTraversal] ...,
HOLEPUNCH: ...); commit+push on user command.

### 11n addendum (same session): live rendezvous probe [network-limited]

1. **Per-source buddy persistence [FIXED]**: FoundSource now carries
   buddy_ip/buddy_port (server_client.py 0.4.0); `kad sources` populates
   them (cli.py 0.6.1); save_found_sources writes per-row buddies for
   kad3/kad5 (state.py 0.6.1). Before: ALL rows of a save got the FIRST
   source's buddy — the second kad3 row dialed a foreign buddy.
2. **LIVE probe** (tmp\rendezvous_live.py, file 68D0E10D, two independent
   kad3 records + live buddies): buddy-callback 0x52 sent (no TCP callback,
   expected for double-firewalled), 12 s fallback fired, rendezvous 0x94
   sent FROM THE SESSION SOCKET to both buddies (79.112.136.166:65023,
   58.38.13.178:54188) — NO OP_HOLEPUNCH / OP_NATT_ENDPOINT_HINT came
   back within the 22 s hint window on either buddy (three runs).
3. Interpretation: our 0x94 chain is oracle-verified byte-for-byte
   (14c), so the silence is either (a) live buddies dead/behind NAT or
   not rendezvous-capable relays, or (b) a protocol variant difference —
   eMuleAI's own live log shows "Including REQUESTER endpoint ...
   transportHint=2 for ephemeral response", i.e. its transport-hint byte
   carries 0x02, not our 0x80, and it embeds the requester endpoint
   differently. NEXT: wire-diff our 0x94 against a captured eMuleAI
   rendezvous request (tshark on tun0) before the next live attempt.
4. kad1 direct dials: all FIN during BASIC handshake (stale/poisoned
   records — known condition, unchanged).

Suite: 336 passed, 3 skipped; compileall 0. Commit+push on user command.

### 11n addendum 2 (same session): AICH requester [DONE — core + audit]

1. **Client-side recovery consumer [DONE]**: hashes/aich.py 0.2.0 —
   aich_parse_recovery_data + aich_rebuild_master_from_part (the client
   mirror of CreatePartRecoveryData: part bytes + peer recovery blob
   must rebuild the claimed master; SHAHashSet.cpp ReadRecoveryData
   walk).
2. **PeerClient.request_aich [DONE]**: client.py 0.4.0 — OP_AICHREQUEST
   over the session, OP_AICHANSWER parsing; the responder's master gate
   (mismatch silently ignored) requires the requester to already know
   the master, so trust bootstrap = master computed from our own
   completed download first.  Loopback test: request + rebuild == master
   (tests/test_aich_wire.py).
3. **Runner AICH audit [DONE]**: runner.py 0.4.0 — after a complete
   transfer, cross-check with the peer (part-0 recovery must rebuild our
   master) and store the verified master (state.py migration 10,
   aich_masters; save/get API).  End-to-end verified: the rendezvous
   loopback test now asserts the master lands in aich_masters.
4. **Listener post-transfer drain [DONE]**: listener.py 0.3.0 — the
   session no longer dies on transfer_complete; it serves AICH requests
   until the downloader disconnects (eMule parity: the DOWNLOADER owns
   the connection lifetime).  Without this the runner audit raced the
   source's disconnect — caught by the new assertion.
5. **Trust bootstrap limitation (known)**: full corrupt-part salvage
   needs the untrusted-master flow (UntrustedHashReceived, 10 IPs/92%
   majority, SHAHashSet.cpp:178-182, 1320-1388) whose zero-master
   request gate lives in eMuleAI's packet dispatch (not in
   SHAHashSet.cpp — extract from UpDownClient.cpp/PartFile.cpp before
   implementing).  Current audit stores only our own MD4-verified
   masters — correct, but not yet a majority-trust set.

Suite: 337 passed, 3 skipped; compileall 0. Commit+push on user command.

### 11n addendum 3 (same session): SX requester [DONE]

1. **PeerClient.request_sources [DONE]**: client.py 0.5.0 — SX2
   (OP_REQUESTSOURCES2) when the peer advertises miso2 bit 10 (new codec
   helper miso2_source_exchange_v2; MISCOPTIONS2 is tag 0xFE — 0xFB is
   EMULE_VERSION) or SX1 nibble > 1; legacy OP_REQUESTSOURCES for
   SX1 == 1.  peer_tags now retained from the handshake.
2. **Answer collection [DONE]**: OP_ANSWERSOURCES(2) handled in the
   wait_upload_slot and transfer receive loops (EMULE-protocol packets
   were silently dropped there before); entries accumulate in
   client.collected_sources.
3. **Runner persistence [DONE]**: runner.py — request_sources fired
   after request_file; collected sources persisted into file_sources
   (source_type "sx", direct-dialable) in the attempt's finally block —
   sources survive even when the transfer itself fails.
4. Loopback test: PeerClient.request_sources vs the live SX responder —
   answer parsed and collected (tests/test_source_exchange.py).

Suite: 338 passed, 3 skipped; compileall 0. Commit+push on user command.

### 11n addendum 4 (same session): stripe scheduling [DONE]

1. **transfer(start_offset, end_offset) [DONE]**: client.py 0.6.0 — a
   racing peer downloads only its disjoint region; write offsets stay
   absolute.  Before: ALL racing peers downloaded identical bytes from
   offset 0 (verified live: two peers each pulled the same first 600 KB).
2. **Runner stripes [DONE]**: runner.py 0.5.0 — peer i gets
   [i*region, min(size, (i+1)*region)), region = ceil(size/peers).
   Queue gap list stays the completion source of truth.
3. **Buddy/direct-callback race [FIXED]**: the TCP wait now starts as a
   task BEFORE the callback request is sent — dial-backs arrive within
   milliseconds and previously fell through to normal sessions
   (listener.py 0.3.1: per-IP FIFO waiter queue; the single-future
   version made two same-IP racing peers share one reader —
   "readexactly() called while another coroutine is already waiting").
   Limitation (known): a stalled peer's stripe is not reassigned; the
   file stays incomplete until the next run() covers the gaps.
4. e2e: tests/test_download_stripe.py — two kad6 sources, disjoint
   stripes, full MD4-verified completion; both sources served ~equal
   halves (traffic_recorder counters).

Suite: 339 passed, 3 skipped; compileall 0. Commit+push on user command.

### 11n addendum 5 (same session): IPv6 NAT-T [DONE — transport]

1. **Dual-stack session [DONE]**: session.py 0.2.0 — start6() opens the
   IPv6 transport alongside the IPv4 one; _send routes by remote address
   family.
2. **Direct-punch rendezvous for IPv6 [DONE]**: the buddy endpoint hint
   is IPv4-only (ClientUDPSocket.cpp:1276 always writes a 4-byte
   address), so for an IPv6 target the hint is skipped and
   holepunch/CAPS/uTP go straight to the endpoint known from the KAD
   record — mirroring eMuleAI's observed live IPv6 rendezvous.
3. **Two environment traps [FIXED]**: (a) this CPython/Proactor build
   silently DROPS asyncio IPv6 datagram sendto (overlapped WSASendTo,
   WinError 10022) while plain non-blocking sockets work — v6 sends
   bypass asyncio through a raw socket; (b) Windows IPv6 addrs arrive
   as 4-tuples — the demux now normalizes to (host, port) or every
   lookup key misses.
4. Loopback test: test_natt_rendezvous.py::test_natt_rendezvous_ipv6_
   direct_punch — full rendezvous + uTP echo over ::1 with a
   hint-less buddy.
5. **Runner/data-source integration [BLOCKED]**: our KAD source parser
   only captures IPv4 tags; IPv6 source records need the eMuleAI KAD
   listener oracle (same missing file as the buddy item).

Suite: 340 passed, 3 skipped; compileall 0. Commit+push on user command.

### 11o. Serving as KAD buddy [DONE — serving side, loopback]

Oracle files located (the earlier "missing oracle" was a wrong path —
they live under kademlia\net\, not kademlia\kademlia\):
O:\Work\Coding\eMuleAI\srchybrid\kademlia\net\KademliaUDPListener.cpp and
O:\Work\Coding\eMule_0.50a\srchybrid\kademlia\net\KademliaUDPListener.cpp
(stock 0.50a names the same opcodes KADEMLIA_FINDBUDDY_*).  Recon:
tmp/recon/emuleai-buddy-udp.recon.md, emuleai-kad-ipv6-tags.recon.md.

1. **Serving-buddy UDP [DONE]**: core/kad/buddy.py 0.1.0 — 0x51 parsed
   ([ServedBuddyID-XOR 16][userhash 16][tcp u16][opts u8?]), answered
   with 0x5A ([XOR-ID echo][buddyHash][tcp u16][opts u8?]) when TCP-open
   and below capacity (gates :1690-1697); 0x52 relayed to the registered
   served client as OP_CALLBACK (0x99, 0xC5): [kadID-XOR][fileHash]
   [reqIP u32 LE][reqPort u16 LE] (:1850-1866; XOR-form fallback lookup
   mirrors :1112-1123).
2. **Buddy TCP registration [DONE]**: listener.py 0.3.1 — HELLO carrying
   CT_EMULE_SERVINGBUDDYID (0xBF, TAGTYPE_HASH 0x01, raw KadID;
   BaseClient.cpp:2005-2013) registers the client in the buddy registry
   and holds the channel open instead of the upload engine.
3. **Codec [DONE]**: codec.py 0.3.0 — hello extra_tags + TAGTYPE_HASH
   writing (bytes tag values).
4. **Wiring [DONE]**: spider.py 0.2.0 — 0x51/0x52 branches in the KAD
   receiver; kernel.py — buddy_registry.configure(tcp_port) at startup.
5. Loopback: tests/test_kad_buddy.py — payload roundtrips + TCP
   registration and OP_CALLBACK relay with XOR-form lookup.
6. **[TODO next]**: our own FIREWALLED-customer side (register with an
   external buddy: send 0x51, TCP-connect, HELLO with 0xBF tag, answer
   OP_CALLBACK by dialing the requester) and the buddy ping/pong
   (OP_BUDDYPING 0x9F payload oracle).  IPv6 KAD source tags
   (TAG_IPV6 "ip6" / TAG_SERVINGBUDDYIPV6 "bi6" — 32-char hex ASCII
   string tags per Search.cpp:917-922/1195-1202) now have their oracle:
   implement in source_search.py next.

Suite: 342 passed, 3 skipped; compileall 0. Commit+push on user command.

