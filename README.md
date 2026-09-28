# AmuleD v0.6.0

AmuleD is a portable, console-first ED2K/Kademlia client written in Python 3.12. It is an independent clean-room implementation of the public ED2K and Kademlia protocols, not a binary wrapper around aMule/eMule and not a GPL source port.

The current milestone is a **feature-complete eMule-interop client stack proven against the live network**: a working **Kademlia (KAD) engine** (keyword search with 200 real results per query, file-source discovery, publishing of your own files into the KAD index), a live-validated ED2K server session, a full download stack (queue, part files, MD4 verification, parallel peer racing with stripe scheduling, corrupt-part salvage with AICH narrowing), a peer protocol layer with **TCP obfuscation both ways** (outgoing dial + incoming accept, BASIC and DH), **UDP obfuscation**, **SecureIdent (SUI) RSA-384** with persisted keys, **source exchange** (both sides), **AICH** recovery (both sides), a NAT-traversal suite (direct-UDP callback, KAD buddy callback, **NAT-T rendezvous over uTP**, IPv6 rendezvous), **ICS block selection** and the **A4AF/NNS gate**, an upload engine with credits→priority, a client credit ledger, GeoIP, UPnP/NAT-PMP, IP filter and server blacklisting — all under a **unified kernel process** (KAD spider + listener + republication + DuckDB state + IPC control channel). The headline live result: a **complete multi-part download of 46.7 MB (5 parts, 255 blocks) from a real eMuleAI 1.6.0 client, MD4-verified**, with the full ICS/A4AF stack exercised on the wire.

**Author:** Soror L.'.L.'. &nbsp;|&nbsp; **Version:** 0.6.0 &nbsp;|&nbsp; **License:** Apache 2.0

**Documentation:** [English](README.md) · [Русский](README.ru.md)
**Repository:** [GitHub - Methelina/AmuleD_v2_KAD-eD2k_Python](https://github.com/Methelina/AmuleD_v2_KAD-eD2k_Python.git)


---

## For users

### What it is

AmuleD is a client for decentralized file sharing in the eD2K/Kademlia p2p networks (the eMule network). The network architecture has no central intermediary server: file search and exchange happen directly between participating nodes through a distributed hash table (DHT), so no single node holds a full catalog, and traffic and participants are spread across millions of machines worldwide.

What you can do right now:

- **Share your folders** — AmuleD scans them, computes hashes, and registers the files for the network (`share add` / `share scan`); the kernel republishes them to KAD automatically.
- **Find files in the network** by keyword — through a server search or via Kademlia (DHT) without servers (`search server|auto` and the `kad search` engine; a "video" query returns hundreds of real results).
- **Download what you find** — add a file to the queue by its hash; the client requests sources on its own (ED2K server, KAD by source type, peer source exchange), races several sources in parallel over disjoint file stripes, resumes after pauses and restarts, verifies every part and the final MD4, and salvages a corrupt part down to 180 KB blocks using AICH recovery data (`sources ed2k`, `kad sources`, `download add|run|pause|resume|cancel`, progress bars).
- **Serve files to others** — the kernel accepts eMule client connections, queues peers, serves parts (compressed where supported), answers source-exchange and AICH requests, and can act as a KAD serving buddy.
- **Stay safe** — an IP filter cuts off unwanted addresses, unreliable servers are blacklisted automatically, and every peer connection can run inside eMule-compatible obfuscation with SecureIdent verification (`ipfilter status|test`, `servers failures|forgive`).

The client is fully portable: it installs into its own folder with a single script, writes nothing to system directories, and does not require an installed Python.

### Current status (honestly)

This is a live client with a complete protocol stack. Verified against the real network: KAD search/sources/publish, ED2K server sessions, obfuscated end-to-end downloads from real eMule/eMuleAI peers (MD4-verified), including the 46.7 MB multi-part download above, obfuscated incoming connections (BASIC + DH accept), live DH with a real ED2K server, and KAD UDP obfuscation against live nodes. The full Internet pipeline — fresh KAD search → source persistence (through kernel IPC) → parallel download run — runs end-to-end in the kernel; on today's network, completion of an arbitrary Internet download is limited by source-record quality (many peers are firewalled with stale buddy pairs, and some high-ID peers close plain dials by policy), which is the same data-quality constraint a stock eMule operates under. A stock eMule-compatible UDP NAT-T rendezvous path (holepunch + uTP) is implemented and loopback-verified; live rendezvous success requires fresh, coherent buddy records. Known remaining tails: the eMuleAI-specific "eServer Buddy" protocol layer (optional), and AICH majority-trust bootstrap from untrusted peers. Follow the progress in the roadmap (sections tagged DONE/WIP/PLANNED).

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

The installer is idempotent. It provisions `uv`, Python 3.12, dependencies, runtime folders, and the default JSONC configuration inside the project. It does not use the system Python and does not overwrite an existing configuration. The default configuration is seeded from the tracked sanitized prototype `config\amuled.example.jsonc` (copied to `config\amuled.jsonc` on first run; a null `identity.user_hash` is generated and persisted automatically, and `network.bind_ip` stays unset unless you need to pin KAD/peer UDP egress to a specific local NIC to bypass a VPN tunnel default route).

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

The kernel is the single long-lived process. It keeps the Kademlia network warm (permanent HELLO/PING maturation with node-rotation of stale contacts, status snapshot in `db\kad_status.json`), serves uploads on an ephemeral TCP port (advertised through KAD source entries; UPnP/NAT-PMP mapping is attempted automatically), republishes your files every few hours, and owns the DuckDB connection exclusively — the CLI talks to it over loopback IPC (`db\kernel_status.json` carries the control port), so search results, sources (including `sources.save`), downloads, credits, share lists, and ipfilter status all work while the kernel is running.

### Interactive menu

With no arguments the runtime opens an interactive menu: numbered search results (pick one or several — `1,3,5` or `2-5` — to add and download), KAD status, share management, downloads with progress bars, IP filter tests, GeoIP lookups. The menu is a thin shell over the same CLI; every action is one keypress instead of a command line.

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

Each source carries its eMule source type (1 = high-ID direct dial, 3/5 = firewalled behind a serving buddy, 6 = firewalled direct-UDP callback), KAD UDP port, buddy address where applicable, IPv6 tags where published (`ip6`/`bi6`), a dialability flag, and the publisher's KadID. Entries with reserved/multicast addresses or invalid ports are filtered out (`IsGoodIPPort` rule). While the kernel runs, sources are saved through kernel IPC (`sources.save`), not by a competing direct DB write.

### Publish your files to KAD

Register your shared files in the KAD distributed index so other clients can find and download them:

```powershell
.\AmuleD_Run.ps1 -NoPause publish keywords --limit 5 --json   # keyword entries (file names -> KAD index)
.\AmuleD_Run.ps1 -NoPause publish sources --limit 0 --json    # yourself as a source for every shared file
```

The publish client performs the same iterative closest-node lookup as eMule (`KADEMLIA2_PUBLISH_KEY_REQ`/`_SOURCE_REQ` → `PUBLISH_RES`, with `PUBLISH_RES_ACK` when requested), accepts the top responders, and stops at eMule's store totals. The kernel republishes automatically every few hours, because KAD store entries expire after about a day. Live-validated: a file published by AmuleD is found by `kad search` from the network, and `kad sources` returns AmuleD itself as a dialable source.

### Share files to others (serve daemon)

`serve` runs the kernel: it accepts eD2K client-to-client connections (plain and obfuscated — BASIC and DH), performs the HELLO/HELLOANSWER handshake, optionally runs SecureIdent verification both ways, resolves requested hashes against your shared files, queues peers (priority, slots, TTL, dedupe), serves file parts with per-session throttling (compressed sub-packets included), and answers source-exchange (`OP_REQUESTSOURCES2`) and AICH (`OP_AICHREQUEST`) requests from peers. It can also serve as a KAD serving buddy (`KADEMLIA_FINDSERVINGBUDDY_REQ` → relayed callbacks):

```powershell
.\AmuleD_Run.ps1 serve                      # kernel: spider + listener + periodic KAD republication
.\AmuleD_Run.ps1 serve --publish-limit 10   # cap files per republication pass
.\AmuleD_Run.ps1 serve --no-publish         # kernel without republication
.\AmuleD_Run.ps1 serve --no-spider          # kernel without the in-process spider
```

The kernel writes `db\kernel_status.json` (pid, serve port, control port), enforces `serve.max_sessions`, and shuts down gracefully on Ctrl+C or `amuled daemon stop`. The client identity (userhash, nickname, TCP port) lives in the `identity` section of `config\amuled.jsonc` — the same stable, SO_EMULE-marked userhash backs the HELLO handshake, KAD publication, obfuscation key derivation and the credit ledger, matching eMule's `GetClientHash = GetUserHash` model; a userhash is generated and persisted on first run. Loopback self-test: AmuleD's own downloader fetches a real shared file from the kernel and the reassembled MD4 matches; served bytes are credited to the remote client's ledger (`client_credits` table) in the same process.

### Downloads

```powershell
.\AmuleD_Run.ps1 -NoPause sources ed2k <file_hash> --server 176.123.5.89:4725 --save --json
.\AmuleD_Run.ps1 -NoPause download add <file_hash> <size_bytes> --name "file name" --json
.\AmuleD_Run.ps1 -NoPause download run <file_hash> --max-peers 50 --queue-wait 240 --json
.\AmuleD_Run.ps1 -NoPause download list --json
.\AmuleD_Run.ps1 -NoPause download pause <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download resume <file_hash> --json
.\AmuleD_Run.ps1 -NoPause download cancel <file_hash> --json
```

`download run` executes inside the kernel. It resolves known sources by type: high-ID peers are dialed directly (obfuscated first, with an automatic plain retry when the peer silently ignores the obfuscated handshake — a KAD-published userhash does not always match the peer's real identity hash); firewalled sources are asked to call back (KAD buddy callback for types 3/5, direct-UDP callback for type 6, then NAT-T rendezvous over uTP with holepunching as the double-firewalled fallback, including IPv6 direct-punch for `ip6` records). Racing peers download disjoint file stripes; dead peers are pruned and their stripes reassigned over up to three rounds. After the transfer every part's MD4 is verified against the peer hashset; a corrupt part is punched out and refetched — narrowed to the corrupt 180 KB blocks when a trusted AICH master is available. Final assembly into `incoming\` happens only when the gap list is empty and the full MD4 verifies. Progress bars render on stderr and are disabled in `--json` mode.

### Client credits

Every served/received byte is attributed to the remote client's userhash (eMule's credit model at the accounting level; verified SecureIdent clients earn the signature bonus):

```powershell
.\AmuleD_Run.ps1 -NoPause credits list --limit 20 --json
.\AmuleD_Run.ps1 -NoPause credits get <user_hash> --json
```

### Servers and protection

```powershell
.\AmuleD_Run.ps1 -NoPause import servers --server-met assets\v1\server.met --static assets\v1\staticservers.dat --save --json
.\AmuleD_Run.ps1 -NoPause servers failures --json
.\AmuleD_Run.ps1 -NoPause servers forgive <ip> <port> --json
.\AmuleD_Run.ps1 -NoPause ipfilter status --json
.\AmuleD_Run.ps1 -NoPause ipfilter test <ip> --json
```

Servers that fail repeatedly are blacklisted automatically for a cooldown; `servers forgive` clears the entry. Blacklisted servers are skipped by server-channel commands and `import servers --save`.

### GeoIP

Country lookup by IP (official MaxMind MMDB format, with a best-effort legacy `GeoIP.dat` fallback):

```powershell
.\AmuleD_Run.ps1 -NoPause geoip lookup <ip> --json
```

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

Sorted by status: **Live-validated** (proven against the real eMule network) →
**Implemented** (tested offline, loopback-verified) → **Planned**.

| Layer | Status | Location |
|---|---|---|
| **Live-validated** | | |
| KAD keyword search | **Live: 200 results/query** | `src/amuled_v2/core/kad/search.py` |
| KAD file-source search (`SEARCH_SOURCE_REQ`) | **Live: sources persisted** | `src/amuled_v2/core/kad/source_search.py` |
| KAD publish (keyword/source entries) | **Live-validated** | `src/amuled_v2/core/kad/publish.py`, `src/amuled_v2/cli.py` |
| KAD packet codec (kad2) | Live-validated | `src/amuled_v2/core/kad/packets.py` |
| KAD bootstrap (HELLO/PING/BOOT) | Live-validated | `src/amuled_v2/core/kad/bootstrap.py` |
| KAD UDP obfuscation (RC4) | Live-validated | `src/amuled_v2/core/kad/obfuscation.py` |
| KAD CLI commands (`kad search/sources`) | **Live-validated** | `src/amuled_v2/cli.py` |
| ED2K TCP login | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| ED2K SERVER search | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| `OP_GETSOURCES` | Live-validated | `src/amuled_v2/core/ed2k/server_client.py` |
| Outgoing TCP obfuscation (BASIC, persistent streams) | **Live-validated** | `src/amuled_v2/core/peer/obfuscation.py`, `core/peer/client.py` |
| Incoming TCP obfuscation accept (BASIC + DH) | **Live-validated** | `src/amuled_v2/core/peer/listener.py` |
| Server-mode DH obfuscated handshake | **Live-validated** (real ED2K server) | `src/amuled_v2/core/peer/obfuscation.py` |
| End-to-end obfuscated download (real eMuleAI peer, MD4 verified) | **Live-validated** (46.7 MB, 5 parts, 255 blocks) | `src/amuled_v2/core/peer/client.py`, `core/download/runner.py` |
| Obfuscated-dial fallback + plain retry | **Live-validated** | `src/amuled_v2/core/download/runner.py` |
| Unified kernel (spider+listener+state+IPC, one process) | **Live-validated** | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py`, `core/kad/spider.py` |
| NIC-egress bind for KAD/peer UDP (`network.bind_ip`) | **Live-validated** | `src/amuled_v2/core/net/bind_ip.py` |
| **Implemented** | | |
| Portable installer/runner | Implemented | `AmuleD_install.ps1`, `AmuleD_Run.ps1` |
| JSONC configuration (+ tracked sanitized prototype) | Implemented | `src/amuled_v2/config.py`, `jsonc.py`, `config/amuled.example.jsonc` |
| DuckDB state and migrations | Implemented | `src/amuled_v2/state.py` |
| Tagged logging | Implemented | `src/amuled_v2/logging_setup.py` |
| MD4 / ED2K hashing | Implemented | `src/amuled_v2/core/hashes` |
| SHA-1 / AICH hashing + recovery data | Implemented | `src/amuled_v2/core/hashes/aich.py` |
| Binary/tag/packet codec | Implemented | `src/amuled_v2/core/codec` |
| Server-list persistence | Implemented | `src/amuled_v2/core/ed2k/server_met.py` |
| Shared metadata import/hashing | Implemented | `src/amuled_v2/core/sharing/shared_files.py` |
| Search channel model | Implemented | `src/amuled_v2/core/search_channels.py` |
| ED2K GLOBAL search | Implemented | `src/amuled_v2/core/ed2k/` |
| Result persistence | Implemented | `src/amuled_v2/state.py` |
| IP filter + server blacklist | Implemented | `src/amuled_v2/core/ipfilter.py`, `server_filter.py` |
| Download stack (queue/parts/stripes/rounds/MD4) | Implemented | `src/amuled_v2/core/download/`, `src/amuled_v2/core/peer/` |
| ICS block selection (RELEASE/SPREAD/SHARE modes) | Implemented | `src/amuled_v2/core/download/ics.py` |
| A4AF / no-needed-parts gate | Implemented | `src/amuled_v2/core/download/runner.py` |
| Corrupt-part salvage + AICH block narrowing | Implemented | `src/amuled_v2/core/download/runner.py`, `core/hashes/aich.py` |
| KAD nodes.dat parser | Implemented | `src/amuled_v2/core/kad/nodes_dat.py` |
| KAD routing table | Implemented | `src/amuled_v2/core/kad/routing.py` |
| KAD runtime (cache → routing, bootstrap) | Implemented | `src/amuled_v2/core/kad/runtime.py` |
| Selection strategies (xor/quality/vivaldi/kadabra) | Implemented | `src/amuled_v2/core/kad/strategies.py` |
| KAD spider (in-kernel, node rotation/fail-eviction) | Implemented | `src/amuled_v2/core/kad/spider.py` |
| Client identity (stable userhash/nick/port) | Implemented | `src/amuled_v2/core/identity.py` |
| Shield-compliance guard (banned strings/tags) | Implemented | `src/amuled_v2/core/peer/shield_guard.py` |
| SecureIdent RSA-384 (keys, sign/verify, wire) | Implemented | `src/amuled_v2/core/security/secure_ident.py`, `core/peer/client.py`, `core/peer/listener.py` |
| Upload engine (queue/slots/throttle, credits→priority) | Implemented | `src/amuled_v2/core/upload/` |
| Incoming peer listener (plain + obfuscated) | Implemented | `src/amuled_v2/core/peer/listener.py` |
| Source exchange (responder v2/v4 + requester) | Implemented | `src/amuled_v2/core/peer/codec.py`, `core/peer/listener.py`, `core/peer/client.py` |
| AICH responder + requester | Implemented | `src/amuled_v2/core/hashes/aich.py`, `core/peer/listener.py`, `core/upload/engine.py` |
| Direct-UDP callback (KAD type 6) | Implemented | `src/amuled_v2/core/kad/direct_callback.py` |
| KAD buddy callback (types 3/5) + buddy serving/customer | Implemented | `src/amuled_v2/core/kad/direct_callback.py`, `core/kad/buddy.py`, `core/kad/buddy_customer.py` |
| NAT-T rendezvous (holepunch, endpoint hint, CAPS) | Implemented | `src/amuled_v2/core/natt/session.py`, `core/kad/direct_callback.py` |
| uTP NAT-T transport | Implemented | `src/amuled_v2/core/natt/utp.py` |
| QUIC NAT-T transport (eMuleAI ALPN) | Implemented (loopback) | `src/amuled_v2/core/natt/quic_transport.py` |
| IPv6 KAD source tags + IPv6 rendezvous | Implemented | `src/amuled_v2/core/kad/source_search.py`, `core/natt/session.py` |
| UDP datagram obfuscation (ED2K/KAD key ladder) | Implemented | `src/amuled_v2/core/peer/udp_obfuscation.py` |
| Client credits ledger (per-userhash accounting) | Implemented | `src/amuled_v2/state.py` (migration 7) |
| UPnP IGD + NAT-PMP mapping | Implemented | `src/amuled_v2/core/nat/upnp.py` |
| GeoIP (MaxMind MMDB + legacy fallback) | Implemented | `src/amuled_v2/core/geoip.py` |
| known.met import/export | Implemented | `src/amuled_v2/core/sharing/known_met.py`, `cli.py` |
| Kernel IPC control channel (search/sources/downloads/credits/...) | Implemented | `src/amuled_v2/core/kernel.py`, `core/kernel_control.py` |
| Interactive console menu | Implemented | `scripts/amuled_menu.py` |
| **Planned** | | |
| eServer Buddy protocol (eMuleAI-specific optional layer) | Planned (optional) | `docs/roadmap.md` |
| AICH majority-trust bootstrap from untrusted peers | Planned | `docs/roadmap.md` |

### KAD engine notes

- Node IDs use eMule's internal **LE-word semantics**: `CFileDataIO::ReadUInt128` is a raw 16-byte memcpy of four little-endian words, and distance ordering compares word 0 first. `KadUInt128` in `src/amuled_v2/core/kad/packets.py` implements this exactly; wire bytes are unchanged.
- KAD UDP obfuscation follows `EncryptedDatagramSocket.cpp`: key candidates are MD5 over (NodeID / userhash+IP+magic / receiver verify key) plus the wire random-key-part, RC4 without key-drop, magic `0x395F2EC1`, receiver/sender verify keys after the padding. Both directions are implemented and live-verified; the wire format is byte-exact with eMuleAI (no endian swaps anywhere in the datagram header).
- The warm node cache (`db/kad_nodes.json`, plus the DuckDB `kad_nodes` table) is keyed by a persistent `own_id`, so nodes recognize the client across restarts; stale contacts are rotated out by fail counters and eviction.
- Source records keep the numeric eMule KAD source type (1/3/5/6, plus `sx` for peer-exchanged sources), per-source buddy addresses, KAD UDP ports, and IPv6 (`ip6`/`bi6`) tags, so the downloader can pick the right reachability path per source.

### NAT traversal notes

- Firewalled sources are reached in eMule order: buddy callback (`KADEMLIA_CALLBACK_REQ` 0x52 to the source's serving buddy), direct-UDP callback (`OP_DIRECTCALLBACKREQ` 0x95) for type 6, then NAT-T rendezvous (`OP_REASKCALLBACKUDP` 0x94) with holepunch bursts, endpoint hints and a CAPS exchange advertising uTP; the uTP stream is then adopted by the peer session. IPv6 targets use the direct-punch variant (endpoint hints are IPv4-only in eMule).
- `network.bind_ip` pins KAD/peer UDP egress to a physical NIC when a VPN tunnel owns the default route — otherwise peers see the tunnel address and every callback/rendezvous path dies; loopback destinations are exempt (a NIC-bound socket cannot send to 127.0.0.1).
- UPnP IGD and NAT-PMP mappings are created on kernel start and removed on shutdown; multi-NIC SSDP discovery finds the router even when a tunnel shadows the default route.

### Security notes

- TCP obfuscation: BASIC (MD5 key ladder from the target userhash + per-connection key part, one persistent RC4 stream per direction) is live-verified both as dialer and acceptor; DH (768-bit, ephemeral per handshake — eMuleAI keeps no persisted obfuscation key material) is live-verified with a real ED2K server and in incoming accept.
- A KAD-published userhash does not always equal the peer's real identity hash; the dial therefore falls back to plain automatically when the obfuscated handshake is silently ignored (logged, per the fallback-visibility policy).
- SecureIdent: RSA-384 via PyCryptodome (`construct` + `pkcs1_15`/SHA1), `config\cryptkey.dat` in the eMule Base64-DER format, 48-byte signatures over `[signer blob][challenge][IP-block]`; both client and listener perform the SECIDENTSTATE/PUBLICKEY/SIGNATURE exchange and keep a verified-clients set with the eMule bonus.
- The shield-compliance guard never sends modstrings, nicknames, or HELLO/INFO tags that eMuleAI's anti-leech shield hard-bans, and regenerates degenerate userhashes.

### Project layout

```text
AmuleD_v2/
├── AmuleD_install.ps1         # Idempotent portable installer
├── AmuleD_Run.ps1             # Single runtime dispatcher: menu / kernel(serve) / CLI
├── pyproject.toml             # Package metadata and dependencies
├── requirements.txt           # Locked dependency groups
├── AGENTS.md                  # Project-local development rules
├── assets/v1/                 # Bundled baseline resources
├── config/                    # User JSONC configuration (+ tracked amuled.example.jsonc prototype)
├── db/                        # DuckDB state, KAD node cache, generated files
├── logs/                      # JSONL diagnostics
├── tmp/                       # Project temporary files
├── incoming/                  # Completed downloads
├── temp/                      # Partial downloads
├── shared/                    # Default shared storage
├── docs/                      # Specification, roadmap, protocol matrix
├── scripts/                   # Kernel launcher, interactive menu, diagnostic scripts
├── src/amuled_v2/             # Python implementation
│   ├── core/kad/              # KAD engine (packets, bootstrap, routing, search, publish, spider, obfuscation, strategies, buddy, callbacks)
│   ├── core/peer/             # Peer protocol (client, listener, codec, TCP/UDP obfuscation, shield guard)
│   ├── core/natt/             # NAT-T (UDP session, uTP, QUIC transports)
│   ├── core/nat/              # UPnP IGD + NAT-PMP
│   ├── core/net/              # NIC-egress bind policy
│   ├── core/security/         # SecureIdent RSA-384
│   ├── core/download/         # Download queue, runner, ICS selection
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

The runner uses only `.venv\Scripts\python.exe` and never selects or mutates a system Python. All temporary files, including pytest artifacts, are redirected into the project (see `tests/conftest.py`) — nothing is written to the system drive. `config\amuled.jsonc` (live config) and `config\cryptkey.dat` (SUI private key) are personal and never committed; the tracked `config\amuled.example.jsonc` is the sanitized prototype.

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
395 passed, 3 skipped
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

Shared-file metadata, shared-directory lists, the generated live configuration (`config\amuled.jsonc`), SUI private keys, DuckDB state, logs, KAD node caches, and partial-download state are private. They are ignored by Git and should be generated locally with `share add`, the kernel's spider, or imported explicitly from your own legacy files when needed.

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
- Upload parity: periodic QUEUERANK, slot rotation, known.met import/export, UPnP/NAT-PMP - **DONE**
- Incoming obfuscated accept (BASIC + DH) - **DONE** (loopback + live)
- GeoIP (MaxMind MMDB + legacy fallback) - **DONE**
- SecureIdent RSA-384 core + wire both sides - **DONE** (loopback mutual verification)
- Source exchange responder + requester - **DONE**
- AICH responder + requester + block-level salvage - **DONE** (e2e MD4-verified)
- Spider node rotation (fail counters, eviction, seed refresh) - **DONE**
- Callback stack: direct-UDP (kad6), buddy callback (kad3/5), per-source buddy persistence - **DONE**
- NAT-T rendezvous: uTP transport, holepunch, endpoint hints, CAPS exchange; QUIC transport (loopback) - **DONE**
- IPv6 KAD source tags + IPv6 rendezvous (direct-punch) - **DONE**
- KAD buddy serving + customer side - **DONE** (loopback-tested)
- Stripe scheduling + stalled-stripe reassignment rounds - **DONE** (e2e MD4-verified)
- Corrupt-part salvage (part-MD4 punch + refetch) - **DONE** (e2e poison-test)
- ICS block selection + A4AF/NNS gate - **DONE** (live-proven in the 46.7 MB eMuleAI download)
- UDP datagram obfuscation - **DONE**
- Stable HELLO identity + shield-compliance guard - **DONE** (eMuleAI "Userhash changed" ban avoided live)
- EMULE-protocol data frames (0xC5) accepted in transfer - **DONE** (live eMuleAI COMPRESSEDPART)
- Single STARTUPLOADREQ per session (aggressive-ban guard) - **DONE**
- Kernel faulthandler watchdog + launcher zombie cleanup - **DONE**
- NIC-egress bind (`network.bind_ip`) - **DONE** (live; loopback-safe via per-destination bind policy)
- Obfuscated-dial fallback + plain retry - **DONE** (live-verified)
- IPC sources.save (KAD source persistence through the kernel) - **DONE** (live: saved=6)
- Config prototype in repo (`config\amuled.example.jsonc`) + installer seeding - **DONE**
- Roadmap 8.4.6 crypto_key persistence - **CLOSED** (oracle recon: eMuleAI keeps no persisted obfuscation key material; DH is ephemeral per handshake)
- UDP endian-swap decision - **CLOSED** (no swap; byte-exact eMuleAI wire format, aMule divergence documented)

Active / next stations (WIP/PLANNED):

1. Live completion of arbitrary Internet downloads — mechanics all live-verified; blocked by source-record quality (stale buddy pairs, require-crypt peers), the same constraint a stock eMule faces - **WIP (network condition)**
2. Live NAT-T rendezvous against eMuleAI with fresh coherent buddy records - **WIP (network condition)**
3. eServer Buddy protocol (eMuleAI-specific optional layer) - **PLANNED (optional)**
4. AICH majority-trust bootstrap from untrusted peers (10-IP/92% rule) - **PLANNED**

Deprecated early-session notes are kept for context in docs/roadmap.md - every section there is tagged DONE/SOLVED/WIP/DEPRECATED/TODO; the live state is in sections 11a-11q. The standalone KAD spider script is superseded by the in-kernel spider (`core/kad/spider.py`).

---

## License

Apache 2.0. See [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) for the clean-room compatibility policy.
