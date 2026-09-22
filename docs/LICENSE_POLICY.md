# AmuleD_v2 License Policy

**Version:** 0.1.0
**Status:** M0 deliverable
**Author:** Soror L.'.L.'.
**Last updated:** 2026-09-22
**Controlling plan:** [docs/roadmap.md](../docs/roadmap.md)
**Companion:** [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md) · [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md)

## 1. Target license

The AmuleD_v2 product is intended to ship under the **Apache License, Version 2.0** (the "Apache target"). The source study is performed against aMule 2.3.3 and eMule 0.50, whose code is distributed under the **GNU General Public License (GPL)**. GPL code **cannot** be copied into an Apache-licensed project. This policy defines the clean-room boundary that makes the Apache target achievable.

## 2. The clean-room rule (mandatory)

> **No file under [AmuleD_v2/src/amuled_v2](../src/amuled_v2) may be a derivative work of, or a direct copy of, any file from aMule 2.3.3 ([docs\src](<parent-workspace>/docs/src)) or eMule 0.50.** Transcription of protocol **facts** (opcode values, constant numeric values, packet field sizes, wire byte order) is permitted; transcription of **logic, structure, and organization** of GPL source is prohibited. The implementation must be an independent expression written from the spec in [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md) and [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md).

### What is allowed (facts, not code)

- Opcode numeric values and names (e.g. `LOGINREQUEST = 0x01`).
- Constant values (e.g. `PARTSIZE = 9728000`, `BLOCKSIZE = 184320`, `K = 10`, `ALPHA_QUERY = 3`).
- Protocol header byte values (e.g. `EDONKEY = 0xE3`, `EMULE = 0xC5`, `PACKED = 0xD4`, `KAD = 0xE4`, `KADEMLIAPACKED = 0xE5`).
- On-wire field layout (6-byte header: proto + UInt32 packet_length + opcode; packet_length = payload_size + 1), little-endian IO, tag type encodings.
- Observed behavioral parity from eMule 0.50 (timing, queue rank semantics, source limits).
- File format facts documented from aMule source (e.g. `known.met` header marker, `nodes.dat` version word, `server.met` header byte `0xE0`).
- Binary file header signatures verified via hex dump from the recon reports.

### What is prohibited

- Copying C++ function bodies, class hierarchies, or control flow into Python.
- Porting C++ member functions line-for-line (even with renames).
- Reusing aMule/eMule build system files, CMake modules, or test scaffolding.
- Including GPL boilerplate or copyright notices from aMule/eMule in AmuleD_v2 source files.

## 3. Permitted protocol facts (non-exhaustive, per PROTOCOL_MATRIX.md)

- **ED2K C2C TCP opcodes** and C2S TCP/UDP opcodes from [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h), [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h), [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) — used as wire facts only.
- **Kad v1/v2 opcodes** from [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kad2/Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Client2Client/TCP.h) — wire facts only.
- **Constants** from [ed2k/Constants.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Constants.h), [kad2/Constants.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Constants.h) — numeric facts only.
- **Packet framing** from [Packet.h/.cpp](<external-source-study>/aMule-2.3.3/src/Packet.h) — 6-byte header layout and zlib wrapping via `OP_PACKEDPROT = 0xD4`.
- **Tag system** from [Tag.h/.cpp](<external-source-study>/aMule-2.3.3/src/Tag.h), [TagTypes.h](<external-source-study>/aMule-2.3.3/src/include/tags/TagTypes.h) — type byte encodings only, re-implemented independently in `core.codec.tags`.
- **Hashes** from [aLinkCreator/md4.cpp](<external-source-study>/aMule-2.3.3/src/utils/aLinkCreator/src/md4.cpp), [ed2khash.cpp](<external-source-study>/aMule-2.3.3/src/utils/aLinkCreator/src/ed2khash.cpp), [SHA.h/.cpp](<external-source-study>/aMule-2.3.3/src/SHA.h), [SHAHashSet.h/.cpp](<external-source-study>/aMule-2.3.3/src/SHAHashSet.h) — algorithm descriptions (RFC 1320 for MD4, chunked ED2K, SHA-1, AICH tree) only; Python uses `hashlib` or independent re-implementations.
- **IP-filter format** from [IPFilter.cpp/.h](<external-source-study>/aMule-2.3.3/src/IPFilter.cpp), [IPFilterScanner.cpp](<external-source-study>/aMule-2.3.3/src/IPFilterScanner.cpp) — CIDR text line format only.

## 4. Implementation workflow (enforced per module)

1. Before writing any module in `src/amuled_v2/core/`, read the relevant **spec rows** in [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md) and the section in [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md).
2. Record the spec section reference in the module docstring — **never** the C++ filename as the source of implementation.
3. Write the module from the spec. If a detail is `TBD from source study`, stop, study the cited aMule source, and fill the spec row before implementing.
4. Review that no Python control flow mirrors a GPL file. Tests validate wire behavior (loopback simulators, then live parity), not code provenance.
5. Any change that copies a GPL file or a derived function body is rejected. This is a hard gate, not a style preference.

## 5. File header / licensing guidance

No AmuleD_v2 source file may carry a GPL copyright notice or GPL preamble. Each file header must state the Apache 2.0 license and a one-line clean-room attribution, for example:

```
# Copyright (c) 2026 Soror L.'.L.'..
# Licensed under the Apache License, Version 2.0.
#
# This module is a clean-room implementation of the ED2K/Kad wire protocol,
# written from the independent spec in docs/PROTOCOL_MATRIX.md.
# See LICENSE for details.
```

The full `LICENSE` file (Apache 2.0) must be added at the repo root at first tag, and `pyproject.toml` must declare `license = "Apache-2.0"`. License compliance is a build gate for M1.

## 6. Third-party dependencies

External libraries (`duckdb`, `aiohttp`, `cryptography`/`pycryptodome`, `prompt_toolkit`, `rich`, JSONC parser, UPnP/NAT-PMP library) are used under their own permissive or compatible licenses. The security layer (`core.security`) uses these libraries for RC4/DH but re-implements **no** GPL crypto code from aMule. If a needed library is itself GPL-incompatible with Apache 2.0, it must be replaced or isolated as a plugin before release.

## 7. What to do if direct GPL code is desired later

If a future decision is made to port C++ fragments directly from aMule/eMule (e.g. for a hard-to-spec performance path), the project license **must** be moved to a GPL-compatible side of the dual-license boundary before that code lands. Options, in order of preference:

1. Keep AmuleD_v2 Apache-licensed; **rewrite** the fragment from spec (continue as today).
2. Dual-license AmuleD_v2: Apache 2.0 + a GPL-compatible secondary license, and gate the GPL-derived code behind a build-time module that is only linked for GPL-compatible distributions.
3. Move AmuleD_v2 to **GPL-2.0-or-later** and accept the copyleft terms (relicensing decision requires the copyright holder to agree).

No GPL code may enter `src/amuled_v2/` until one of options 1/2/3 is documented and approved in [roadmap.md](../docs/roadmap.md). Option 1 remains the default and preferred path.

## 8. Acceptance / verification

- Every module docstring in `core/` cites a PROTOCOL_MATRIX.md spec row, not a C++ file.
- No file under `src/amuled_v2/` contains GPL copyright text or GPL preamble.
- `LICENSE` at repo root is Apache 2.0.
- This policy exists and is referenced by [PROTOCOL_MATRIX.md](../docs/PROTOCOL_MATRIX.md) and [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md).

---

**Task start time:** 2026-09-22T21:08:50+04:00
**Task completion time:** 2026-09-22T21:14:30+04:00
