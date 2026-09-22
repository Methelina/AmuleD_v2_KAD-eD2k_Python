# AmuleD_v2 Product & Technical Specification

**Version:** 0.1.0
**Status:** M0 deliverable (spec + clean-room protocol matrix)
**Author:** Soror L.'.L.'.
**Last updated:** 2026-09-22
**Controlling plan:** [docs/roadmap.md](../docs/roadmap.md)

This specification is the controlling product/technical document for AmuleD_v2. It is authoritative where it conflicts with any earlier prose. The [roadmap.md](../docs/roadmap.md) remains the stage gate; this spec fills the technical detail M0 requires and makes M0/M1 actionable for implementation.

## 1. Purpose

AmuleD_v2 is a fully native, pure-Python ED2K + Kademlia (Kad) P2P client. It replaces the existing v1 wrapper ([amuled_daemon.py](<parent-workspace>/amuled_daemon.py), [apply_amule_config.py](<parent-workspace>/apply_amule_config.py), [test_client.py](<parent-workspace>/test_client.py)) that merely shells out to `amuled.exe`/`amuleweb.exe` over ports 4711/4712. The v2 client implements the ED2K and Kad wire protocols directly in Python so that **no `amuled.exe`, `amule.exe`, `amuleweb.exe`, `amulecmd.exe`, `amulegui.exe`, or `.dll` is required at runtime.**

**Core protocol behavior reference** is aMule 2.3.3 source at [docs\src](<parent-workspace>/docs/src) (resolves to [<external-source-study>\aMule-2.3.3](<external-source-study>/aMule-2.3.3)), cross-checked against eMule 0.50 behavioral parity. Protocol facts are extracted from source study only; the Python implementation is written from the independent spec in this document and [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md), never by copying GPL code.

## 2. Non-goals

The following are explicitly out of scope for the initial v2 line and may be revisited only via roadmap change:

- **EC protocol (port 4712):** Not implemented. The existing [EC_Protocol.txt](<parent-workspace>/docs/EC_Protocol.txt) is retained as reference only. External connection to a running aMule is not supported.
- **Web UI / amuleweb HTTP (port 4711):** Not part of `core` networking. A future web UI may be added as an optional layer later; the internal control plane is CLI + daemon only.
- **GUI / wxWidgets parity:** No native GUI in scope. All user interaction is CLI-driven.
- **GUI file sharing through aMule's `shareddir.dat` live re-scan:** Only import-once conversion of [shareddir.dat](<parent-workspace>/amule-daemon-config/shareddir.dat) and [shared_files.json](<parent-workspace>/shared_files.json).
- **Mobile, cloud sync, web seeding, BitTorrent, Gnutella, or magnet DNS resolvers:** None of these.

## 3. Platform, runtime, and dependencies

| Property | Requirement |
|---|---|
| Minimum Python | 3.12 |
| Target OSs | Windows (authoring), Linux, macOS (product) |
| Package manager | `uv` with portable `.venv` inside [AmuleD_v2](..) |
| Source root | [AmuleD_v2/src/amuled_v2](../src/amuled_v2) |
| Runtime dirs | [config](../config), [db](../db), [logs](../logs), [tmp](../tmp), [incoming](../incoming), [shared](../shared) |
| Install scripts | Replace [AmuleD_install.ps1](../AmuleD_install.ps1) and [AmuleD_Run.ps1](../AmuleD_Run.ps1); drop the borrowed [requirements.txt](../requirements.txt) |

**Allowed dependencies** (all cross-platform): `duckdb` (runtime state + indexes), `aiohttp` (HTTP bootstrap, future web/API), `cryptography` or `pycryptodome` (security layer), `prompt_toolkit` (REPL), `rich` (CLI tables/output), a JSONC parser (configs), and a cross-platform UPnP/NAT-PMP library at the assigned M-stage.

**Portability rule:** the installer must be idempotent, create the venv only when missing, never overwrite user config, and never write outside [AmuleD_v2](..) except to externally configured Incoming/Temp/Shared paths.

## 4. Architecture

```
src/amuled_v2/
├── cli/          # one-shot CLI, REPL, JSON routing
├── daemon/        # background process lifecycle, OS signals
├── config/        # JSONC load + schema validation + defaults
├── logging_setup/ # structured logging
├── state/         # DuckDB schema + migrations + session state
├── core/
│   ├── hashes/    # MD4, ED2K, SHA1, AICH
│   ├── codec/     # little-endian binary IO, packet framing, tags, zlib
│   ├── ed2k/      # ED2K TCP/UDP client, server engine, C2C transfer
│   ├── kad/       # Kad DHT: routing, network, search, publish
│   ├── transfer/  # part files, gaps, block scheduling, queues
│   ├── search/    # unified KAD + ED2K search engine
│   ├── sharing/   # shared dirs, hashing queue, known-file index
│   ├── security/  # RC4 obfuscation, DH handshake, client credits
│   ├── ipfilter/  # ipfilter.dat / ipfilter_static.dat + URL updates
│   └── nat/       # UPnP, NAT-PMP, firewall diagnostics
└── tests/
```

- All network core is `asyncio`-based: ED2K TCP, ED2K UDP, Kad UDP, timers, reask, search, upload/download scheduling, and shutdown share one event loop.
- CLI and daemon share one internal service layer — **no duplicate protocol logic**.
- Clean-room boundary: `core.ed2k`, `core.kad`, `core.codec`, `core.hashes` implement protocol behavior derived **only** from the spec in this document and [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md). See [LICENSE_POLICY.md](../docs/LICENSE_POLICY.md) for the copying prohibition.

## 5. Configuration and state

- **Config:** JSONC in [config](../config). Default port `8089` for both TCP and UDP (old v1 default preserved). Legacy ports 4711 (web) and 4712 (EC) are reserved but unused.
- **Runtime state:** DuckDB in [db](../db) — queues, indexes, part bitmaps, statistics, client credits.
- **Temp/incoming:** [temp](../temp) for `.part` files; [incoming](../incoming) for completed files.
- **External paths:** Incoming/Temp/Shared may be overridden to absolute paths outside AmuleD_v2; this is the only sanctioned escape from portability.

### Asset import (M15)

| Asset | Source | Treatment |
|---|---|---|
| [shared_files.json](<parent-workspace>/shared_files.json) | project root | Native JSON; import-once seed of sharing list |
| [shareddir.dat](<parent-workspace>/amule-daemon-config/shareddir.dat) | text, CRLF paths | Import-once seed; not re-scanned |
| [server.met](<parent-workspace>/amule-daemon-config/server.met) | binary | Import-once server list; re-fetch from URL thereafter |
| [nodes.dat](<parent-workspace>/amule-daemon-config/nodes.dat) | binary | Bootstrap only; parse known-good contacts |
| [ipfilter.dat](<parent-workspace>/amule-daemon-config/ipfilter.dat) | text CIDR | Native; optional URL auto-update |
| [ipfilter_static.dat](<parent-workspace>/amule-daemon-config/ipfilter_static.dat) | text | Native; static overrides |
| [GeoIP.dat](<parent-workspace>/amule-daemon-config/GeoIP.dat) | binary | Read-only lookup; no writes back |
| [known.met](<parent-workspace>/amule-daemon-config/known.met), [known2_64.met](<parent-workspace>/amule-daemon-config/known2_64.met) | binary | Import-once only; not rewritten |
| [clients.met](<parent-workspace>/amule-daemon-config/clients.met) | binary | Import-once client credits; not rewritten |
| [preferences.dat](<parent-workspace>/amule-daemon-config/preferences.dat), [preferencesKad.dat](<parent-workspace>/amule-daemon-config/preferencesKad.dat) | binary | Native identity generation; import discouraged |
| [cryptkey.dat](<parent-workspace>/amule-daemon-config/cryptkey.dat) | PEM/RSA | Import-only reference; native keypair generated fresh |

**Hard rule:** no binary `.met`/`.dat` is ever written back by native code. Import is one-way into JSONC/DuckDB.

## 6. CLI modes

All commands produce human-readable output by default and JSON when `--json` is passed. Four invocation modes:

1. **One-shot:** `python -m amuled_v2 <command> [options]`
2. **REPL:** `python -m amuled_v2 repl` (prompt_toolkit-based, persistent session)
3. **Daemon:** `python -m amuled_v2 daemon start|stop|status|restart`
4. **JSON output:** `--json` flag on any command

### M13 command vocabulary (canonical list)

`status`, `connect`, `disconnect`, `server list`, `server add`, `server remove`, `search kad`, `search ed2k`, `search results`, `search clear`, `download add`, `download list`, `download pause`, `download resume`, `download cancel`, `download priority`, `share list`, `share add`, `share remove`, `share priority`, `kad status`, `kad bootstrap`, `stats`, `config show`, `config set`.

## 7. Networking roadmap (stage gates)

| Stage | Milestone | Network capability | Live network? |
|---|---|---|---|
| M0 | Spec + protocol matrix | None | No |
| M1 | Portable skeleton | None | No |
| M2 | Config, logging, DuckDB, CLI router | None | No |
| M3 | Hash + binary codec layer | None | No |
| M4 | ED2K server engine | ED2K TCP login, server search, source request | Loopback simulator first, then explicit live |
| M5 | Kad discovery + routing | Kad bootstrap, routing table, hello/ping/pong | Loopback first, then explicit live |
| M6 | Unified search + links | ED2K + Kad search, magnet/ED2K/TXT links | Live after M4/M5 stable |
| M7 | Sharing + hashing | dir scan, ED2K/AICH hashing, known-file index | No |
| M8 | Download engine | `.part` storage, chunk bitmap, gaps, resume | Loopback peers first |
| M9 | Peer transfer + queues | C2C hello, file/hashset request, queue rank, parts | Loopback first |
| M10 | Source exchange + limits | server/Kad sources, scoring, max connections, throttler | Loopback first |
| M11 | Security layer | TCP/UDP obfuscation, DH handshake, credits | Explicit live, opt-in |
| M12 | IP-filter, GeoIP, UPnP, NAT-PMP | ipfilter.dat, GeoIP lookup, port mapping, firewall tests | Explicit live |
| M13 | Full CLI surface | All commands above | Depends on prior stages |
| M14 | Daemon mode | Process lifecycle, PID control, graceful shutdown | No |
| M15 | Compatibility/import | One-way import of v1 assets | No |
| M16 | Live-network validation | Full real-world stabilization | Live, staged |

**Live-network validation priority (fixed order):** Kad bootstrap → Kad search → ED2K login → ED2K search → source discovery → partial download → resume → hashing → sharing → upload peer → obfuscation → long-run stability. Each step requires regression vectors and, where possible, hex captures of compatible clients. Live tests are **never** enabled until the preceding loopback stage is stable.

## 8. Compatibility targets

- **eMule 0.50** is the primary behavioral reference (confirmed stable by roadmap). Protocol facts are validated against eMule 0.50-compatible peers where live testing is permitted.
- **aMule 2.3.3 source** ([docs\src](<parent-workspace>/docs/src)) for opcodes, structures, constants, and observed behavior. Not copied.
- **Behavioral parity scope (long-term):** ED2K TCP/UDP, Kad, search, download, sharing, upload, queues, source exchange, IP-filter, NAT/firewall behavior, categories, limits, statistics, security layer. Simple categories; original-like limits/IP-filter.
- **Link formats:** ED2K file links, ED2K server links, magnet links, TXT lists of links.

## 9. Security

- TCP RC4 obfuscation (port 8089) and UDP obfuscation are architected from M11 but designed in from M0.
- DH key exchange + secure identification and client credits are implemented only as live-network necessity demands.
- No secrets are written to disk in plaintext. Config passwords (if any) use the same MD5 convention as v1 only when replicating aMule wire compatibility, and are stored outside the venv.
- IP-filter is honored before accepting connections from a peer.

## 10. Test strategy

- **Unit tests:** MD4/ED2K hashes, packet codec, tags, UInt128, routing buckets, part bitmaps, queue logic, IP-filter parser, link parser, storage migrations. Test vectors are derived from observed aMule/eMule behavior and published ED2K test vectors.
- **Protocol simulators:** fake ED2K server, fake ED2K peer, fake Kad node on loopback. These are the **only** way early stages are validated; no live network.
- **CLI smoke tests:** one-shot, REPL, JSON output, daemon lifecycle — no network.
- **Live-network tests:** enabled only after loopback stabilization, gated per stage above.

## 11. Acceptance criteria (M0 specific)

1. This spec, [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md), and [LICENSE_POLICY.md](../docs/LICENSE_POLICY.md) exist under [docs](../docs).
2. Protocol families (ED2K TCP/UDP, Kad) and sub-systems (packet/tag/hash layers, transfer, sharing, search, security, NAT, IP-filter) are mapped to independent Python modules with source-study references.
3. MVP scope vs. full-parity scope is explicitly bounded.
4. Clean-room constraints are stated and enforced.
5. Test strategy and live-network validation priorities are defined.
6. M1 is directly actionable from this spec (portable skeleton, uv, JSONC, DuckDB, CLI router).

---

**Task start time:** 2026-09-22T21:08:50+04:00
**Task completion time:** 2026-09-22T21:14:30+04:00
