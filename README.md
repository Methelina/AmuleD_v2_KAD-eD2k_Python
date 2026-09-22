# AmuleD v0.4.1

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

### Import bundled baseline data

The repository contains baseline v1 resources under `assets\v1`. Import them into the project-local DuckDB state:

```powershell
.\AmuleD_Run.ps1 -NoPause import servers `
  --server-met assets\v1\server.met `
  --static assets\v1\staticservers.dat `
  --save --json

.\AmuleD_Run.ps1 -NoPause import shared `
  --shared-json assets\v1\shared_files.json `
  --shareddir assets\v1\shareddir.dat `
  --save --json
```

After import, `status --json` should show the bundled server, static-server, shared-file, and shared-directory counts.

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
AmuleD v0.4.1
```

The stable technical names are intentionally separate:

| Item | Value |
|---|---|
| Public client name | `AmuleD` |
| Public version string | `AmuleD v0.4.1` |
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
| ED2K search / `OP_GETSOURCES` | Planned | `docs/roadmap.md`, milestone M4 |
| Kademlia | Planned | `docs/roadmap.md`, milestone M5 |
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

The repository is self-contained after cloning. The bundled resources are:

- `assets/v1/server.met`
- `assets/v1/nodes.dat`
- `assets/v1/GeoIP.dat`
- `assets/v1/staticservers.dat`
- `assets/v1/ipfilter.dat`
- `assets/v1/ipfilter_static.dat`
- `assets/v1/shareddir.dat`
- `assets/v1/shared_files.json`

User history, credits, identity files, and partial-download state are not included in the public baseline.

### Roadmap

The active protocol path is:

1. ED2K server search and `OP_GETSOURCES`.
2. Source persistence and source lifecycle.
3. Kademlia bootstrap and routing.
4. Unified ED2K/KAD search.
5. Download queue, part files, block assembly, and resume.
6. Peer transfer, upload slots, and queues.
7. Security, obfuscation, IP filter, GeoIP, UPnP/NAT-PMP.
8. Long-run live-network stabilization.

See [`docs/roadmap.md`](docs/roadmap.md) for acceptance criteria.

---

## License

Apache 2.0. See [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) for the clean-room compatibility policy.
