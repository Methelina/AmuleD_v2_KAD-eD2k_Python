# AmuleD v0.5.1

AmuleD is a portable, console-first ED2K/Kademlia client written in Python 3.12. It is an independent clean-room implementation of the public ED2K and Kademlia protocols, not a binary wrapper around aMule/eMule and not a GPL source port.

The current milestone provides a fully working **Kademlia (KAD) engine against the live eMule network** — keyword search (200 real results for a "video" query in about one second) and file-source discovery (KADEMLIA2_SEARCH_SOURCE_REQ, sources persisted to DuckDB) — plus a live-validated ED2K TCP server session with search, a complete download stack (queue, part files, MD4 verification), a peer protocol layer, IP filter and server blacklisting, a searchable DuckDB-backed result store, a permanent KAD spider daemon that keeps the network warm, and an interactive console menu.

**Author:** Soror L.'.L.'. &nbsp;|&nbsp; **Version:** 0.5.1 &nbsp;|&nbsp; **License:** Apache 2.0

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

This is an early but live client: search (including KAD) and incoming sources already work against the real eMule network. Still in development: sharing files back to others (upload), publishing your own files into the KAD network, and incoming connections. Follow the progress in the roadmap (sections tagged DONE/WIP/PLANNED).

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
.\AmuleD_Run.ps1 spider               # KAD spider daemon: keeps the network warm (verbose, Ctrl+C to stop)
.\AmuleD_Run.ps1 -NoPause --help      # CLI passthrough
.\AmuleD_Run.ps1 -NoPause status --json
```

The KAD network only answers after warm-up. Keep the spider running in a console while you use search or sources; it continuously matures the routing table, refreshes the node cache (`db\kad_nodes.json`), and writes a live status snapshot to `db\kad_status.json` (including hot-connection statistics from the node database at the end of every cycle).

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
AmuleD v0.5.1
```

The stable technical names are intentionally separate:

| Item | Value |
|---|---|
| Public client name | `AmuleD` |
| Public version string | `AmuleD v0.5.1` |
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
| Upload engine | Planned | `docs/roadmap.md` |
| Incoming KAD listener | Planned | `docs/roadmap.md` |
| GeoIP / UPnP-NAT-PMP | Planned | `docs/roadmap.md` |

### KAD engine notes

- Node IDs use eMule's internal **LE-word semantics**: `CFileDataIO::ReadUInt128` is a raw 16-byte memcpy of four little-endian words, and distance ordering compares word 0 first. `KadUInt128` in `src/amuled_v2/core/kad/packets.py` implements this exactly; wire bytes are unchanged.
- KAD UDP obfuscation follows `EncryptedDatagramSocket.cpp`: key = `MD5(peer NodeID || wire[1:3])`, RC4 without key-drop, magic `0x395F2EC1`, and receiver/sender verify keys after the padding. Both directions (decode/encode) are implemented and live-verified.
- The warm node cache (`db/kad_nodes.json`, plus the DuckDB `kad_nodes` table) is shared between `scripts/kad_warmup.py` and `scripts/kad_node_collector.py` and keyed by a persistent `own_id`, so nodes recognize the client across restarts.

### Project layout

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Idempotent portable installer
├── AmuleD_Run.ps1             # Single runtime dispatcher: menu / spider / CLI
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
├── scripts/                   # KAD spider daemon, interactive menu, warm-up and diagnostic scripts
├── src/amuled_v2/             # Python implementation
│   └── core/kad/              # KAD engine (packets, bootstrap, routing, search, obfuscation, strategies)
└── tests/                     # Unit, codec, state, and protocol tests
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
192 passed, 2 skipped
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

Active / next stations (WIP/PLANNED):

1. Downloads fed from KAD sources end to end (MD4-verified) - **WIP** (peer handshake wire-verification in progress)
2. Spider daemon stale-node rotation and incoming KAD listener - **WIP**
3. Search tactics (quality/kadabra) as CLI flags - **PLANNED**
4. Upload slots and queues - **PLANNED**
5. GeoIP / UPnP-NAT-PMP - **PLANNED**

Deprecated early-session notes are kept for context in docs/roadmap.md - every section there is tagged DONE/SOLVED/WIP/DEPRECATED/TODO; the live state is in sections 11a-11d.

---

## License

Apache 2.0. See [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) for the clean-room compatibility policy.
