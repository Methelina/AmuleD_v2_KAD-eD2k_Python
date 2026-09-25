# AmuleD v0.6.0

AmuleD is a portable, console-first ED2K/Kademlia client written in Python 3.12. It is an independent clean-room implementation of the public ED2K and Kademlia protocols, not a binary wrapper around aMule/eMule and not a GPL source port.

The current milestone provides a fully working **Kademlia (KAD) engine against the live eMule network** — keyword search (200 real results for a "video" query in about one second), file-source discovery (KADEMLIA2_SEARCH_SOURCE_REQ, sources persisted to DuckDB), and **publishing of your own shared files into the KAD index** (keyword and source entries, live-accepted: files published by AmuleD are found by network searches and AmuleD itself shows up as a source) — plus a live-validated ED2K TCP server session with search, a complete download stack (queue, part files, MD4 verification), a peer protocol layer with client-side **TCP obfuscation dialing** (the modern network requires it; the obfuscated handshake is live-verified against real eMule peers), an **incoming peer listener with an upload engine** and a **client credit ledger** (uploads/downloads attributed per userhash), and a **unified kernel process** that runs the KAD spider, the listener, the republication loop and the DuckDB state under one permanent connection with a CLI-facing IPC control channel — no more single-writer lock contention between daemons and the CLI. IP filter, server blacklisting, a DuckDB-backed result store, and an interactive console menu round out the stack.

**Author:** Soror L.'.L.'. &nbsp;|&nbsp; **Version:** 0.6.0 &nbsp;|&nbsp; **License:** Apache 2.0

**Documentation:** [English](README.md) · [Русский](README.ru.md)
**Repositary:** [GitHub - Methelina/AmuleD_v2_KAD-eD2k_Python](https://github.com/Methelina/AmuleD_v2_KAD-eD2k_Python.git)


---

## For users

### What it is

AmuleD is a client for decentralized file sharing in the eD2K/Kademlia p2p networks (the eMule network). The network architecture has no central intermediary server: file search and exchange happen directly between participating nodes through a distributed hash table (DHT), so no single node holds a full catalog, and traffic and participants are spread across millions of machines worldwide.

What you can do right now:

- **Share your folders** — AmuleD scans them, computes hashes, and registers the files for the network (`share add` / `share scan`).
- **Find files in the network** by keyword — through a server search or via Kademlia (DHT) without servers (`search server|auto` and the `kad search` engine; a "video" query returns hundreds of real results).
- **Download what you find** — add a file to the queue by its hash; the client requests sources on its own, downloads in parts with pause/resume, and verifies the MD4 hash after completion (`sources ed2k`, `download add|run|pause|resume|cancel`, progress bars).
- **Stay safe** — an IP filter cuts off unwanted addresses, and unreliable servers are blacklisted automatically (`ipfilter status|test`, `servers failures|forgive`).

The client is fully portable: it installs into its own folder with a single script, writes nothing to system directories, and does not require an installed Python.

### Current status (honestly)

This is an early but live client: search (including KAD), incoming sources, KAD publishing of your own files, and file sharing to others (serve daemon with an upload queue) already work against the real eMule network, and outgoing peer connections use the mandatory TCP obfuscation handshake (live-verified end to end: AmuleD downloaded a real file from a real eMule client over the obfuscated channel with a matching MD4; a live DH-obfuscated session with a real ED2K server was also established). Still in development: accepting obfuscated incoming connections (pending external protocol review — plain-protocol listeners are answered today), transfers sourced straight from the kernel's KAD source pool, GeoIP, and SecureIdent/credits crypto. Follow the progress in the roadmap (sections tagged DONE/WIP/PLANNED).

### Requirements

- Windows 10/11 for the bundled PowerShell installer and launcher.
- Internet access during first installation.
- No manually installed Python: the installer creates a project-local Python 3.12 environment.
- Enough free space for the virtual environment, caches, runtime database, temporary files, and future downloads.

### Install

From `AmuleD_v2`, run the portable installer once:

```powershell
.\AmuleD_install.ps1
```

The installer is idempotent. It provisions `uv`, Python 3.12, dependencies, runtime folders, and the default JSONC configuration inside the project. It does not use the system Python and does not overwrite an existing configuration.

### Run

The project has exactly two launchers: the installer and the single runtime. `AmuleD_Run.ps1` is a dispatcher — everything runs from under it:

```powershell
.\AmuleD_Run.ps1                      # interactive console menu (Server / KAD / Share / Search / Downloads)
.\AmuleD_Run.ps1 serve                # THE KERNEL: KAD spider + listener + publish + CLI IPC (Ctrl+C to stop)
.\AmuleD_Run.ps1 -NoPause --help      # CLI passthrough
.\AmuleD_Run.ps1 -NoPause status --json
.\AmuleD_Run.ps1 -NoPause daemon status   # kernel status over IPC (ports, spider pool, uptime)
.\AmuleD_Run.ps1 -NoPause daemon stop     # graceful kernel shutdown
```

The kernel is the single long-lived process. It keeps the Kademlia network warm (permanent HELLO/PING maturation over the cached node pool, status snapshot in `db\kad_status.json`), serves uploads on an ephemeral TCP port (advertised through KAD source entries), republishes your files every few hours, and owns the DuckDB connection exclusively — the CLI talks to it over loopback IPC (`db\kernel_status.json` carries the control port). Commands that need the database directly (share management, search-result persistence, downloads) run after `daemon stop`, or through the kernel once routed via IPC.

### Interactive menu

With no arguments the runtime opens an interactive menu: numbered search results (pick one or several — `1,3,5` or `2-5` — to add and download), KAD status, share management, downloads with progress bars, IP filter tests. The menu is a thin shell over the same CLI; every action is one keypress instead of a command line.

### Search

ED2K server-channel search:

```powershell
.\AmuleD_Run.ps1 -NoPause search server --server 176.123.5.89:4725 --query "video" --duration 30 --json
.\AmuleD_Run.ps1 -NoPause search auto --server 176.123.5.89:4725 --query "video" --json
```

Search results are persisted in DuckDB and can be listed later:

```powershell
.\AmuleD_Run.ps1 -NoPause search results list --json
.\AmuleD_Run.ps1 -NoPause search results show <file_hash> --json
.\AmuleD_Run.ps1 -NoPause search results clear --json
```

KAD search runs over the Kademlia engine (bootstrap → mature routing table → iterative keyword lookup) with a sliding-window budget: the lookup keeps going while nodes answer and stops after a quiet window:

```powershell
.\AmuleD_Run.ps1 -NoPause kad search "video" --timeout 45 --json
.\AmuleD_Run.ps1 -NoPause search kad "video" --json   # same engine via the search-channel model
```

### KAD file sources

Discover peers sharing a file directly through Kademlia and persist them into the same DuckDB source store the downloader consumes:

```powershell
.\AmuleD_Run.ps1 -NoPause kad sources <file_hash> --size <size_bytes> --timeout 45 --json
```

Each source carries its eMule source type (1 = high-ID, 3/5 = firewalled with buddy, 6 = direct callback), a dialability flag, and the publisher's KadID. Entries with reserved/multicast addresses or invalid ports are filtered out (`IsGoodIPPort` rule).

### Publish your files to KAD

Register your shared files in the KAD distributed index so other clients can find and download them:

```powershell
.\AmuleD_Run.ps1 -NoPause publish keywords --limit 5 --json   # keyword entries (file names -> KAD index)
.\AmuleD_Run.ps1 -NoPause publish sources --limit 0 --json    # yourself as a source for every shared file
```

The publish client performs the same iterative closest-node lookup as eMule (`KADEMLIA2_PUBLISH_KEY_REQ`/`_SOURCE_REQ` → `PUBLISH_RES`, with `PUBLISH_RES_ACK` when requested), accepts the top responders, and stops at eMule's store totals. The serve daemon (below) republishes automatically every few hours, because KAD store entries expire after about a day. Live-validated: a file published by AmuleD is found by `kad search` from the network, and `kad sources` returns AmuleD itself as a dialable source.

### Share files to others (serve daemon)

`serve` runs the kernel: it accepts eD2K client-to-client connections, performs the HELLO/HELLOANSWER handshake, resolves requested hashes against your shared files, queues peers (priority, slots, TTL, dedupe), and serves file parts with per-session throttling. The kernel also runs the KAD spider in-process (network warm-up, routing-table maturation, node cache persistence) and republishes KAD source entries with its actual bound TCP port on a schedule:

```powershell
.\AmuleD_Run.ps1 serve                      # kernel: spider + listener + hourly-repeated KAD republication
.\AmuleD_Run.ps1 serve --publish-limit 10   # cap files per republication pass
.\AmuleD_Run.ps1 serve --no-publish         # kernel without republication
.\AmuleD_Run.ps1 serve --no-spider          # kernel without the in-process spider
```

The kernel writes `db\kernel_status.json` (pid, serve port, control port), enforces `serve.max_sessions`, and shuts down gracefully on Ctrl+C or `amuled daemon stop`. The client identity (userhash, nickname, TCP port) lives in the `identity` section of `config\amuled.jsonc` — the same userhash backs the HELLO handshake and the KAD source publish, matching eMule's `GetClientHash = GetUserHash` model; a userhash is generated and persisted on first run. While the kernel runs it holds the DuckDB connection exclusively, so `amuled credits list|get`, `daemon status` and `daemon stop` answer over IPC in milliseconds, and other database-touching commands are meant for `daemon stop` windows (or future IPC routes). Loopback self-test: AmuleD's own downloader fetches a real shared file from the kernel and the reassembled MD4 matches; served bytes are credited to the remote client's ledger (`client_credits` table) in the same process.

### Client credits

Every served/received byte is attributed to the remote client's userhash (eMule's credit model at the accounting level; signature verification is a separate external track):

```powershell
.\AmuleD_Run.ps1 -NoPause credits list --limit 20 --json
.\AmuleD_Run.ps1 -NoPause credits get <user_hash> --json
```

### Sources and downloads

```powershell
.\AmuleD_Run.ps1 -NoPause sources ed2k <file_hash> --server 176.123.5.89:4725 --save --json
.\AmuleD_Run.ps1 -NoPause download add <file_hash> <size_bytes> --name "file name" --json
.\AmuleD_Run.ps1 -NoPause download run --json
.\AmuleD_Run.ps1 -NoPause download list --json
.\AmuleD_Run.ps1 -NoPause download pause <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download resume <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download cancel <file_hash> --json
```

`download run` connects to known sources, requests file parts, assembles the part file, and verifies the MD4 hash on completion. Progress bars render on stderr and are disabled in `--json` mode.

### Servers and protection

```powershell
.\AmuleD_Run.ps1 -NoPause import servers --server-met assets\v1\server.met --static assets\v1\staticservers.dat --save --json
.\AmuleD_Run.ps1 -NoPause servers failures --json
.\AmuleD_Run.ps1 -NoPause servers forgive <ip> <port> --json
.\AmuleD_Run.ps1 -NoPause ipfilter status --json
.\AmuleD_Run.ps1 -NoPause ipfilter test <ip> --json
```

Servers that fail repeatedly are blacklisted automatically for a cooldown; `servers forgive` clears the entry. Blacklisted servers are skipped by server-channel commands and `import servers --save`.

### Logs

Diagnostics are separate from command output. CLI results remain on stdout; tagged diagnostics go to stderr and are also written as JSONL to:

```text
logs\amuled.jsonl
```

Console diagnostics look like this:

```text
2026-09-23 07:23:52 | INFO | [KAD] bootstrap done: live=63 pool=397
```

The JSONL form contains stable fields for timestamp, level, tag, logger, and message, so logs can be split by module for scripts or future GUI windows.

---

## For developers and technical reference

### Product identity

The public name and version are:

```text
AmuleD v0.6.0
```

The stable technical names are intentionally separate:

| Item | Value |
|---|---|
| Public client name | `AmuleD` |
| Public version string | `AmuleD v0.6.0` |
| Python package | `amuled_v2` |
| CLI executable | `amuled` |
| Project directory | `AmuleD_v2` |

Public version changes must update the package constants, tests, banners, and documentation together.

### Clean-room policy

AmuleD is intended for Apache 2.0 distribution. GPL source trees from aMule or eMule may be studied to identify wire facts, constants, state transitions, and observable behavior, but GPL code must not be copied into this implementation. Protocol knowledge is first recorded in the clean-room documents and then implemented independently in Python.

Core policy documents:

- [`docs/AmuleD_v2_SPEC.md`](docs/AmuleD_v2_SPEC.md)
- [`docs/PROTOCOL_MATRIX.md`](docs/PROTOCOL_MATRIX.md)
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md)
- [`docs/roadmap.md`](docs/roadmap.md) (every section is tagged DONE/SOLVED/WIP/DEPRECATED/TODO)

### Implemented technical layers

| Layer | Status | Location |
|---|---|---|
| Portable installer/runner | Implemented | `AmuleD_install.ps1`, `AmuleD_Run.ps1` |
| JSONC configuration | Implemented | `src/amuled_v2/config.py`, `jsonc.py` |
| DuckDB state and migrations | Implemented | `src/amuled_v2/state.py` |
| Tagged logging | Implemented | `src/amuled_v2/logging_setup.py` |
| MD4 / ED2K hashing | Implemented | `src/amuled_v2/core/hashes` |
| SHA-1 / AICH hashing | Implemented | `src/amuled_v2/core/hashes/aich.py` |
| Binary/tag/packet codec | Implemented | `src/amuled_v2/core/codec` |
| Server-list persistence | Implemented | `src/amuled_v2/core/ed2k/server_met.py` |
| Shared metadata import/hashing | Implemented | `src/amuled_v2/core/sharing/shared_files.py` |
| ED2K TCP login | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| Search channel model | Implemented | `src/amuled_v2/core/search_channels.py` |
| ED2K SERVER search | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| ED2K GLOBAL search | Implemented | `src/amuled_v2/core/ed2k/` |
| `OP_GETSOURCES` | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| Result persistence | Implemented | `src/amuled_v2/state.py` |
| IP filter + server blacklist | Implemented | `src/amuled_v2/core/ipfilter.py`, `server_filter.py` |
| Download stack (queue/parts/MD4) | Implemented | `src/amuled_v2/core/download/`, `src/amuled_v2/core/peer/` |
| KAD packet codec (kad2) | Live-validated | `src/amuled_v2/core/kad/packets.py` |
| KAD nodes.dat parser | Implemented | `src/amuled_v2/core/kad/nodes_dat.py` |
| KAD bootstrap (HELLO/PING/BOOT) | Live-validated | `src/amuled_v2/core/kad/bootstrap.py` |
| KAD routing table | Implemented | `src/amuled_v2/core/kad/routing.py` |
| KAD UDP obfuscation (RC4) | Live-validated | `src/amuled_v2/core/kad/obfuscation.py` |
| KAD keyword search | **Live: 200 results/query** | `src/amuled_v2/core/kad/search.py` |
| KAD file-source search (`SEARCH_SOURCE_REQ`) | **Live: sources persisted** | `src/amuled_v2/core/kad/source_search.py` |
| KAD runtime (cache → routing, bootstrap) | Implemented | `src/amuled_v2/core/kad/runtime.py` |
| KAD CLI commands (`kad search/sources`) | **Live-validated** | `src/amuled_v2/cli.py` |
| KAD spider daemon (network warm-up) | Implemented | `scripts/kad_spider.py` |
| Interactive console menu | Implemented | `scripts/amuled_menu.py` |
| Selection strategies (xor/quality/vivaldi/kadabra) | Implemented | `src/amuled_v2/core/kad/strategies.py` |
| KAD publish (keyword/source entries) | **Live-validated** | `src/amuled_v2/core/kad/publish.py`, `src/amuled_v2/cli.py` |
| Client identity (userhash/nick/port) | Implemented | `src/amuled_v2/core/identity.py` |
| Upload engine (queue/slots/throttle) | Implemented | `src/amuled_v2/core/upload/` |
| Incoming peer listener (plain) | Implemented | `src/amuled_v2/core/peer/listener.py` |
| Serve daemon (share files) | Implemented | `scripts/serve_daemon.py` |
| Unified kernel (spider+listener+state, one process) | **Live-validated** | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py`, `core/kad/spider.py` |
| Client credits ledger (per-userhash accounting) | Implemented | `src/amuled_v2/state.py` (migration 7) |
| Outgoing TCP obfuscation (BASIC, persistent streams) | **Live-validated** | `src/amuled_v2/core/peer/obfuscation.py` (v0.3.0), `core/peer/client.py` |
| Server-mode DH obfuscated handshake | **Live-validated** (real ED2K server) | `src/amuled_v2/core/peer/obfuscation.py` |
| End-to-end obfuscated download (real eMule peer, MD4 verified) | **Live-validated** | `src/amuled_v2/core/peer/client.py`, `core/download/runner.py` |
| UPnP IGD + NAT-PMP mapping | Implemented | `src/amuled_v2/core/nat/upnp.py` |
| known.met import/export | Implemented | `src/amuled_v2/core/sharing/known_met.py`, `cli.py` |
| Incoming obfuscated accept | Planned (external) | `docs/roadmap.md` |
| GeoIP | Planned | `docs/roadmap.md` |

### KAD engine notes

- Node IDs use eMule's internal **LE-word semantics**: `CFileDataIO::ReadUInt128` is a raw 16-byte memcpy of four little-endian words, and distance ordering compares word 0 first. `KadUInt128` in `src/amuled_v2/core/kad/packets.py` implements this exactly; wire bytes are unchanged.
- KAD UDP obfuscation follows `EncryptedDatagramSocket.cpp`: key = `MD5(peer NodeID || wire[1:3])`, RC4 without key-drop, magic `0x395F2EC1`, and receiver/sender verify keys after the padding. Both directions (decode/encode) are implemented and live-verified.
- The warm node cache (`db/kad_nodes.json`, plus the DuckDB `kad_nodes` table) is shared between `scripts/kad_warmup.py` and `scripts/kad_node_collector.py` and keyed by a persistent `own_id`, so nodes recognize the client across restarts.

### Project layout

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Idempotent portable installer
├── AmuleD_Run.ps1             # Single runtime dispatcher: menu / kernel(serve) / CLI
├── pyproject.toml             # Package metadata and dependencies
├── requirements.txt           # Locked dependency groups
├── AGENTS.md                  # Project-local development rules
├── assets/v1/                 # Bundled baseline resources
├── config/                    # User JSONC configuration
├── db/                        # DuckDB state, KAD node cache, generated files
├── logs/                      # JSONL diagnostics
├── tmp/                       # Project temporary files
├── incoming/                  # Completed downloads
├── temp/                      # Partial downloads
├── shared/                    # Default shared storage
├── docs/                      # Specification, roadmap, protocol matrix
├── scripts/                   # Kernel launcher, interactive menu, warm-up and diagnostic scripts
├── src/amuled_v2/             # Python implementation
│   ├── core/kad/              # KAD engine (packets, bootstrap, routing, search, publish, spider, obfuscation, strategies)
│   ├── core/peer/             # Peer protocol (client, listener, codec, obfuscation)
│   ├── core/upload/           # Upload engine (queue, slots, throttled block transfer)
│   ├── core/kernel.py         # Unified kernel: spider + listener + state + IPC
│   ├── core/kernel_control.py # Kernel IPC control server/client (JSON lines)
│   └── core/identity.py       # Unified client identity (userhash/nick/port)
└── tests/                     # Unit, codec, state, kernel and protocol tests
```

### Runtime isolation

All generated data stays inside `AmuleD_v2`:

```text
.venv\                 # Project Python 3.12
bin\uv.exe             # Project-local uv
bin\uv-python\         # uv-managed Python interpreters
.cache\uv\             # uv cache
.cache\pip\            # package cache
.cache\pycache\        # bytecode cache
.cache\tmp\            # pytest/tool temporary files
config\ db\ logs\ tmp\ # configuration, state, diagnostics, scratch
```

The runner uses only `.venv\Scripts\python.exe` and never selects or mutates a system Python. All temporary files, including pytest artifacts, are redirected into the project (see `tests/conftest.py`) — nothing is written to the system drive.

### Development commands

Run all commands from `AmuleD_v2` using the project-local interpreter:

```powershell
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_live_ed2k.py
.\.venv\Scripts\python.exe -m amuled_v2 --help
.\.venv\Scripts\python.exe -m amuled_v2 status --json
```

Current full offline-suite status:

```text
294 passed, 6 skipped
```

### Tagged diagnostics

All diagnostic output uses a stable uppercase module tag. The stable tags are:

`APP`, `CLI`, `CONFIG`, `STATE`, `IMPORT`, `SERVER`, `KAD`, `ED2K`, `SEARCH`, `DOWNLOAD`, `UPLOAD`, `PEER`, `SHARE`, `HASH`, `CODEC`, `SECURITY`, `IPFILTER`, `NAT`, `DAEMON`, `INSTALL`, `RUNNER`, and `TEST`.

Python code uses the project logger:

```python
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.search")
log.info("kad search done: results=%d, nodes=%d", results, nodes)
```

JSONL records can be filtered directly by the `tag` field.

### Bundled baseline assets

The repository is self-contained after cloning. The bundled resources are public network/bootstrap data:

- `assets/v1/server.met`
- `assets/v1/nodes.dat`
- `assets/v1/GeoIP.dat`
- `assets/v1/staticservers.dat`
- `assets/v1/ipfilter.dat`
- `assets/v1/ipfilter_static.dat`

Shared-file metadata, shared-directory lists, generated configuration, DuckDB state, logs, KAD node caches, and partial-download state are private. They are ignored by Git and should be generated locally with `share add`, the warm-up scripts, or imported explicitly from your own legacy files when needed.

### Roadmap

Completed development stations:

- ED2K server session, SERVER/AUTO/GLOBAL search, result persistence - **DONE**
- Source lifecycle (sources ed2k --save) - **DONE**
- Download queue, part files, MD4 verification, peer transfer - **DONE**
- IP filter and server blacklist - **DONE**
- Kademlia engine (bootstrap, routing, obfuscation, keyword search) - **DONE** (live: 200 results/query)
- KAD file-source search with DuckDB persistence - **DONE** (live: sources from the real network)
- KAD CLI commands (`kad search/sources`), spider daemon, interactive menu - **DONE**
- Client-side TCP obfuscation dialing - **DONE** (handshake live-verified)
- KAD publish (keywords + sources) with republication loop - **DONE** (live-accepted)
- Upload engine, incoming listener, serve daemon, unified identity - **DONE** (loopback self-test: MD4-verified)
- Client credit ledger per userhash (upload/download accounting) - **DONE**
- Unified kernel: spider + listener + DuckDB state in one process, CLI over IPC - **DONE** (zero lock contention, live-validated)

Active / next stations (WIP/PLANNED):

1. Downloads fed from KAD sources end to end (MD4-verified) - **WIP**
2. Incoming obfuscated accept (external protocol review) - **WIP**
3. IPC routing for the remaining CLI commands (share/search/servers/download) - **PLANNED**
4. Credits / SecureIdent skeleton - **PLANNED** (crypto pending external session)
5. GeoIP / UPnP-NAT-PMP - **PLANNED**

Deprecated early-session notes are kept for context in docs/roadmap.md - every section there is tagged DONE/SOLVED/WIP/DEPRECATED/TODO; the live state is in sections 11a-11f. The standalone KAD spider script is superseded by the in-kernel spider (`core/kad/spider.py`).

---

## License

Apache 2.0. See [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) for the clean-room compatibility policy.
