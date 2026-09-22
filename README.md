# AmuleD v0.5.1

AmuleD is a portable, console-first ED2K/Kademlia client written in Python 3.12. It is an independent clean-room implementation of the public ED2K and Kademlia protocols, not a binary wrapper around aMule/eMule and not a GPL source port.

The current milestone already provides the portable runtime, configuration and DuckDB state layers, MD4/ED2K/SHA1/AICH hashing, ED2K packet codec, server-list persistence, shared-file import, tagged diagnostics, and a live-validated ED2K TCP login session. Search, source exchange, download transfer, upload, and Kademlia networking are defined in the roadmap and are not yet available.

**Author:** Soror L.'.L.'. &nbsp;|&nbsp; **Version:** 0.4.1 &nbsp;|&nbsp; **License:** Apache 2.0

**Documentation:** [English](README.md) · [Русский](README.ru.md)

---

## For users

### Current status

AmuleD is an early client foundation. It can already:

- create a fully portable Python 3.12 environment;
- load portable JSONC configuration and DuckDB runtime state;
- import bundled v1 baseline resources into local state;
- import and persist server lists, static servers, shared-file metadata, and shared directories;
- compute MD4, ED2K chunk hashes, SHA-1, and AICH trees;
- encode and decode ED2K packets, tags, packed payloads, and login messages;
- connect to an ED2K server, send `OP_LOGINREQUEST`, and parse server messages, identity, status, and `OP_IDCHANGE`;
- produce tagged console and JSONL diagnostics.

It cannot yet search, discover sources, download files, publish to Kademlia, upload to peers, or replace a completed eMule/aMule client. Those stages are the next protocol milestones.

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

Use the portable launcher:

```powershell
.\AmuleD_Run.ps1
```

With no arguments it shows CLI help. Typical commands:

```powershell
.\AmuleD_Run.ps1 -NoPause init --json
.\AmuleD_Run.ps1 -NoPause status --json
.\AmuleD_Run.ps1 -NoPause config show --json
.\AmuleD_Run.ps1 -NoPause config set network.client_tcp_port 8089 --json
```

`status --json` reports the active backend, database path, ED2K/KAD switches, and current table counts.

### Add and scan shared files

New files can be registered, ED2K-hashed, and written directly to DuckDB from the CLI:

```powershell
.\AmuleD_Run.ps1 -NoPause share add D:\Media
.\AmuleD_Run.ps1 -NoPause share scan
.\AmuleD_Run.ps1 -NoPause share list --json
```

Interactive `share add` and `share scan` commands render a tqdm hashing progress bar on stderr. Progress is disabled automatically in `--json` mode, or explicitly with `--no-progress`.

`share add` registers the directory, scans it recursively, and saves the resulting file rows. `share scan` with no paths rescans every registered directory. A rescan also removes state rows for files that no longer exist or were moved out of the scanned tree, so stale rows do not remain.

Useful variants:

```powershell
.\AmuleD_Run.ps1 -NoPause share add D:\Music --priority high --json
.\AmuleD_Run.ps1 -NoPause share add D:\Downloads --no-recursive --json
.\AmuleD_Run.ps1 -NoPause share scan D:\Media --dry-run --json
.\AmuleD_Run.ps1 -NoPause share add D:\LargeLibrary --no-progress
.\AmuleD_Run.ps1 -NoPause share list --files-only --limit 100 --json
.\AmuleD_Run.ps1 -NoPause share remove file 00112233445566778899AABBCCDDEEFF --json
.\AmuleD_Run.ps1 -NoPause share remove dir D:\Media --json
```

`share remove dir` removes the registered directory and its scanned file rows by default. Add `--keep-files` to remove only the directory row. A file can be removed by its 32-hex ED2K hash.

### Search channels

Search commands mirror eMule's explicit channels. The implemented channel is `server`:

```powershell
.\AmuleD_Run.ps1 -NoPause search server `
  --server 176.123.5.89:4725 `
  --query "video" `
  --duration 30 `
  --json
```

The `server` channel logs in over TCP, sends `OP_SEARCHREQUEST`, and accumulates result batches for `--duration` seconds. ED2K search is asynchronous: zero early batches do not necessarily mean an invalid request.

AUTO uses the eMule channel-selection rules. With only ED2K connected it resolves to `server`:

```powershell
.\AmuleD_Run.ps1 -NoPause search auto --server 176.123.5.89:4725 --query "video" --json
```

Other eMule channels are explicit and currently report structured `not_implemented` status instead of silently falling back:

```powershell
.\AmuleD_Run.ps1 -NoPause search global --json
.\AmuleD_Run.ps1 -NoPause search kad --json
.\AmuleD_Run.ps1 -NoPause search web-edonkey --json
```

`global` requires the UDP server-list search layer. `kad` requires the Kademlia keyword-search engine. `web-edonkey` requires an external web-service adapter.

### Import bundled network resources

The repository bundles public network resources under `assets\v1`. Import them into the project-local DuckDB state:

```powershell
.\AmuleD_Run.ps1 -NoPause import servers `
  --server-met assets\v1\server.met `
  --static assets\v1\staticservers.dat `
  --save --json
```

After import, `status --json` should show the bundled server and static-server counts. Do not import shared-file metadata from another person's installation; register your own directories with `share add` so AmuleD hashes and stores only your files.

### Logs

Diagnostics are separate from command output. CLI results remain on stdout; tagged diagnostics go to stderr and are also written as JSONL to:

```text
logs\amuled.jsonl
```

Console diagnostics look like this:

```text
2026-09-22 23:49:29 | INFO | [CLI] Status command completed
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
- [`docs/roadmap.md`](docs/roadmap.md)

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
| ED2K GLOBAL search | Planned | UDP server-list search layer |
| KAD search | Planned | `docs/roadmap.md`, milestone M5 |
| `OP_GETSOURCES` | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| Kademlia transport | Planned | `docs/roadmap.md`, milestone M5 |
| Download engine | Planned | `docs/roadmap.md`, milestone M8 |
| Upload engine | Planned | `docs/roadmap.md`, milestone M9+ |
| Obfuscation / secure identification | Planned | `docs/roadmap.md`, milestone M11 |

The ED2K TCP wire framing is `protocol byte`, little-endian `UInt32 packet_length`, `opcode byte`, followed by payload. The length field includes the opcode byte, so `packet_length = payload_size + 1`. The live server validation confirmed this layout and the extended eMule-compatible `OP_IDCHANGE` payload.

### Project layout

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Idempotent portable installer
├── AmuleD_Run.ps1             # Portable launcher for CLI commands
├── pyproject.toml             # Package metadata and dependencies
├── requirements.txt           # Locked dependency groups
├── AGENTS.md                  # Project-local development rules
├── assets/v1/                 # Bundled baseline resources
├── config/                    # User JSONC configuration
├── db/                        # DuckDB state and generated files
├── logs/                      # JSONL diagnostics
├── tmp/                       # Project temporary files
├── incoming/                  # Future completed downloads
├── temp/                      # Future partial downloads
├── shared/                    # Default shared storage
├── docs/                      # Specification, roadmap, protocol matrix
├── scripts/                   # Diagnostic and live-validation scripts
├── src/amuled_v2/             # Python implementation
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
.cache\tmp\            # temporary files
config\ db\ logs\      # configuration, state, diagnostics
```

The runner uses only:

```text
.venv\Scripts\python.exe
```

It does not select or mutate a system Python.

### Development commands

Run all commands from `AmuleD_v2` using the project-local interpreter:

```powershell
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pytest -q tests
.\.venv\Scripts\python.exe -m amuled_v2 --help
.\.venv\Scripts\python.exe -m amuled_v2 status --json
```

Current full-suite status for v0.4.1:

```text
128 passed
```

### Tagged diagnostics

All diagnostic output uses a stable uppercase module tag. The stable tags are:

`APP`, `CLI`, `CONFIG`, `STATE`, `IMPORT`, `SERVER`, `KAD`, `ED2K`, `SEARCH`, `DOWNLOAD`, `UPLOAD`, `PEER`, `SHARE`, `HASH`, `CODEC`, `SECURITY`, `IPFILTER`, `NAT`, `DAEMON`, `INSTALL`, `RUNNER`, and `TEST`.

Python code uses the project logger:

```python
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.DOWNLOAD, "core.transfer.download")
log.debug("Block stored: file=%s, start=%d, length=%d", file_hash, start, length)
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

Shared-file metadata, shared-directory lists, generated configuration, DuckDB state, logs, and partial-download state are private. They are ignored by Git and should be generated locally with `share add` or imported explicitly from your own legacy files when needed.

### Roadmap

The active protocol path is:

1. ED2K GLOBAL UDP search across the server list.
2. Source persistence lifecycle.
3. Kademlia bootstrap, routing, and KAD keyword search.
4. Unified search-result model across SERVER, GLOBAL, and KAD.
5. Download queue, part files, block assembly, and resume.
6. Peer transfer, upload slots, and queues.
7. Security, obfuscation, IP filter, GeoIP, UPnP/NAT-PMP.
8. Long-run live-network stabilization.

See [`docs/roadmap.md`](docs/roadmap.md) for acceptance criteria.

---

## License

Apache 2.0. See [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) for the clean-room compatibility policy.
