# AmuleD_v2 Protocol Matrix

**Version:** 0.1.0
**Status:** M0 deliverable
**Author:** Soror L.'.L.'.
**Last updated:** 2026-09-22
**Controlling plan:** [docs/roadmap.md](../docs/roadmap.md)
**Companion:** [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md) · [LICENSE_POLICY.md](../docs/LICENSE_POLICY.md)
**Source reference root:** [docs\src](<parent-workspace>/docs/src) → [<external-source-study>\aMule-2.3.3](<external-source-study>/aMule-2.3.3)
**Behavioral target:** eMule 0.50 compatibility

> **Clean-room rule (mandatory):** every opcode, structure, constant, and behavioral note below is extracted from aMule 2.3.3 / eMule 0.50 source study and then **re-written from an independent spec**. No Python line in `src/amuled_v2/core/` may be a copy of a GPL file. Where an exact protocol detail has not yet been pinned to source, it is marked `TBD from source study`.

## 1. Protocol family overview

| Family | Transport | Direction | Default port | Python layer | Source study |
|---|---|---|---|---|---|
| ED2K TCP (C2C) | TCP | client↔client | 8089 | `core.ed2k.tcp` | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) |
| ED2K UDP (C2C) | UDP | client↔client | 8089 | `core.ed2k.udp` | [Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/UDP.h) |
| ED2K TCP (C2S) | TCP | client→server | 8089 | `core.ed2k.server` | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) |
| ED2K UDP (C2S) | UDP | client→server | 8089 | `core.ed2k.server` | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) |
| Kad v1 UDP | UDP | DHT | 8089 | `core.kad.network` | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) |
| Kad v2 TCP | TCP | DHT | 8089 | `core.kad.network` | [kad2/Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Client2Client/TCP.h) |

**Protocol header byte constants** (from [Protocols.h](<external-source-study>/aMule-2.3.3/src/include/protocol/Protocols.h)): EDONKEY=`0xE3`, EMULE=`0xC5`, PACKED=`0xD4`, KAD=`0xE4`, KADEMLIAPACKED=`0xE5`. Used only as wire identifiers.

## 2. Packet / wire layer (maps to `core.codec` and `core.hashes`)

| Layer | Responsibility | Python module | Source study | Status |
|---|---|---|---|---|
| Binary IO, endianness | little-endian read/write UInt8/16/32/64, ReadString/WriteString | `core.codec` (binary, tags) | [MemFile.cpp](<external-source-study>/aMule-2.3.3/src/MemFile.cpp), [SafeFile.cpp](<external-source-study>/aMule-2.3.3/src/SafeFile.cpp) | TBD from source study |
| Packet framing | 6-byte header (proto + UInt32 packet_length + opcode; packet_length = payload_size + 1) | `core.codec.packet` | [Packet.h/.cpp](<external-source-study>/aMule-2.3.3/src/Packet.h), [Packet.cpp](<external-source-study>/aMule-2.3.3/src/Packet.cpp) | TBD from source study |
| Packed/zlib payload | OP_PACKEDPROT (`0xD4`) wraps zlib-compressed payloads | `core.codec.zlib_compat` | [Packet.cpp](<external-source-study>/aMule-2.3.3/src/Packet.cpp) (zlib compress/uncompress) | TBD from source study |
| Tag system | Tag type encoding, old vs new ED2K tag format, UTF-8 | `core.codec.tags` | [Tag.h/.cpp](<external-source-study>/aMule-2.3.3/src/Tag.h), [Tag.cpp](<external-source-study>/aMule-2.3.3/src/Tag.cpp), [TagTypes.h](<external-source-study>/aMule-2.3.3/src/include/tags/TagTypes.h), [ClientTags.h](<external-source-study>/aMule-2.3.3/src/include/tags/ClientTags.h), [FileTags.h](<external-source-study>/aMule-2.3.3/src/include/tags/FileTags.h), [ServerTags.h](<external-source-study>/aMule-2.3.3/src/include/tags/ServerTags.h) | TBD from source study |

## 3. Hash layer (maps to `core.hashes`)

| Hash | Python module | Source study | Status |
|---|---|---|---|
| MD4 | `core.hashes.md4` | [src/utils/aLinkCreator/src/md4.cpp](<external-source-study>/aMule-2.3.3/src/utils/aLinkCreator/src/md4.cpp), [MD4Hash.h](<external-source-study>/aMule-2.3.3/src/MD4Hash.h) | TBD from source study (16-byte, Init/Update/Final/Transform) |
| ED2K file hash | `core.hashes.ed2k` | [src/utils/aLinkCreator/src/ed2khash.cpp](<external-source-study>/aMule-2.3.3/src/utils/aLinkCreator/src/ed2khash.cpp), [MD4Hash.h](<external-source-study>/aMule-2.3.3/src/MD4Hash.h) | TBD from source study (180 KB block chunking) |
| SHA1 | `core.hashes.sha1` | [src/SHA.h/.cpp](<external-source-study>/aMule-2.3.3/src/SHA.h) | TBD from source study |
| AICH (SHA1 hashset tree) | `core.hashes.aich` | [SHAHashSet.h/.cpp](<external-source-study>/aMule-2.3.3/src/SHAHashSet.h), [ThreadTasks.cpp](<external-source-study>/aMule-2.3.3/src/ThreadTasks.cpp:281-395) | TBD from source study (known2.met, MINUNIQUEIPS_TOTRUST=10, MINPERCENTAGE_TOTRUST=92) |
| MD5 | `core.hashes.md5` (obf key derivation only) | [MD5Sum.h/.cpp](<external-source-study>/aMule-2.3.3/src/libs/common/MD5Sum.h) | TBD from source study |

## 4. ED2K opcodes matrix (maps to `core.ed2k`)

### 4.1 Client-to-Client (C2C) — TCP

| Opcode | Name | Source (aMule 2.3.3) | Python | Live-test priority |
|---|---|---|---|---|
| 0x01 | HELLO | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x46 | SENDINGPART | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x47 | REQUESTPARTS | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x50 | FILESTATUS | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x51/0x52 | HASHSET_REQUEST/ANSWER | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x54 | STARTUPLOAD | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x5C | QUEUERANK | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x92 | MULTIPACKET | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x40 | COMPRESSEDPART | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |
| 0x9B/0x9C | AICH_REQUEST/ANSWER | [Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/TCP.h) | `core.ed2k.tcp` | M9 |

### 4.2 Client-to-Client (C2C) — UDP

| Opcode | Name | Source (aMule 2.3.3) | Python | Live-test priority |
|---|---|---|---|---|
| 0x90 | REASKFILEPING | [Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/UDP.h) | `core.ed2k.udp` | M9 |
| 0x91 | REASKACK | [Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/UDP.h) | `core.ed2k.udp` | M9 |
| 0x94 | REASKCALLBACKUDP | [Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/UDP.h) | `core.ed2k.udp` | M9 |
| 0xFE | PORTTEST | [Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Client/UDP.h) | `core.ed2k.udp` | M12 |

### 4.3 Client-to-Server (C2S) — TCP

| Opcode | Name | Source (aMule 2.3.3) | Python | Live-test priority |
|---|---|---|---|---|
| 0x01 | LOGINREQUEST | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x15 | OFFERFILES | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x16 | SEARCHREQUEST | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x19 | GETSOURCES | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x33 | SEARCHRESULT | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x34 | SERVERSTATUS | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x42 | FOUNDSOURCES | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x35 | CALLBACKREQUESTED | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |
| 0x40 | IDCHANGE | [Client2Server/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/TCP.h) | `core.ed2k.server` | M4 |

### 4.4 Client-to-Server (C2S) — UDP

| Opcode | Name | Source (aMule 2.3.3) | Python | Live-test priority |
|---|---|---|---|---|
| 0x90 | GLOBSEARCHREQ3 | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x94 | GLOBGETSOURCES2 | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x96 | GLOBSERVSTATREQ | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x98 | GLOBSEARCHREQ | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x99 | GLOBSEARCHRES | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x9A | GLOBGETSOURCES | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0x9B | GLOBFINDSOURCES | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |
| 0xA0 | SERVER_LIST_REQ | [Client2Server/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Client2Server/UDP.h) | `core.ed2k.server` | M4 |

## 5. Kademlia opcodes matrix (maps to `core.kad`)

### 5.1 Kad v1 UDP

| Opcode | Name | Source (aMule 2.3.3) | Python | Live-test priority |
|---|---|---|---|---|
| 0x30 | SEARCH_REQ | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) | `core.kad.network` | M5/M6 |
| 0x38 | SEARCH_RES | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) | `core.kad.network` | M5/M6 |
| 0x40 | PUBLISH_REQ | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) | `core.kad.network` | M6/M7 |
| 0x48 | PUBLISH_RES | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) | `core.kad.network` | M6/M7 |
| 0x50 | FIREWALLED_REQ | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h), [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp) | `core.kad.network` | M12 |
| 0x51 | FINDBUDDY_REQ | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h) | `core.kad.network` | M12 |
| 0x52 | CALLBACK_REQ | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h) | `core.kad.network` | M12 |
| 0x58 | FIREWALLED_RES | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h) | `core.kad.network` | M12 |
| 0x59 | FIREWALLED_ACK_RES | [kad/Client2Client/UDP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad/Client2Client/UDP.h) | `core.kad.network` | M12 |

### 5.2 Kad constants

| Constant | Value | Source | Python |
|---|---|---|---|
| K | 10 | [kademlia/kademlia/Defines.h](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/Defines.h) | `core.kad.routing` |
| ALPHA_QUERY | 3 | [kademlia/kademlia/Defines.h](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/Defines.h) | `core.kad.routing` |
| KADEMLIA_VERSION | 0x08 | [include/protocol/kad2/Constants.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Constants.h) | `core.kad.protocol` (TBD from source study) |

### 5.3 Kad v2 TCP

| Opcode | Name | Source | Python |
|---|---|---|---|
| 0xA7 | FWCHECKUDPREQ | [kad2/Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Client2Client/TCP.h) | `core.kad.network` |
| 0xA8 | KAD_FWTCPCHECK_ACK | [kad2/Client2Client/TCP.h](<external-source-study>/aMule-2.3.3/src/include/protocol/kad2/Client2Client/TCP.h) | `core.kad.network` |

## 6. Kad core modules (maps to `core.kad`)

| Concern | Python module | Source study | Status |
|---|---|---|---|
| 128-bit IDs + XOR distance | `core.kad.uint128` | [kademlia/utils/UInt128.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/utils/UInt128.cpp) | TBD from source study |
| Routing zone + bins (buckets) | `core.kad.routing` | [kademlia/routing/RoutingZone.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/routing/RoutingZone.cpp), [RoutingBin.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/routing/RoutingBin.cpp) | TBD from source study |
| Contacts | `core.kad.routing` | [kademlia/routing/Contact.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/routing/Contact.cpp) | TBD from source study |
| UDP listener + opcodes | `core.kad.network` | [kademlia/net/KademliaUDPListener.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/KademliaUDPListener.cpp), [PacketTracking.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/net/PacketTracking.cpp) | TBD from source study |
| Firewall tester | `core.kad.fwcheck` | [kademlia/kademlia/UDPFirewallTester.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/UDPFirewallTester.cpp) | TBD from source study |
| Search engine | `core.kad.search` | [kademlia/kademlia/Search.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/Search.cpp), [SearchManager.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/SearchManager.cpp), [Indexed.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/Indexed.cpp) | TBD from source study |
| Preferences | `core.kad.prefs` | [kademlia/kademlia/Prefs.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/Prefs.cpp) | TBD from source study |
| Kad UDP key | `core.kad.crypto` | [kademlia/utils/KadUDPKey.h](<external-source-study>/aMule-2.3.3/src/kademlia/utils/KadUDPKey.h) | TBD from source study |

## 7. Transfer / sharing / search matrix

### 7.1 Transfer

| Concern | Python module | Source study | Status |
|---|---|---|---|
| Constants (PARTSIZE, BLOCKSIZE) | `core.ed2k.constants` | [ed2k/Constants.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Constants.h) (PARTSIZE=9728000, BLOCKSIZE=184320) | TBD from source study |
| Part files + gaps | `core.transfer.partfile` | [PartFile.cpp](<external-source-study>/aMule-2.3.3/src/PartFile.cpp), [GapList.cpp](<external-source-study>/aMule-2.3.3/src/GapList.cpp) | TBD from source study |
| Download queue | `core.transfer.download_queue` | [DownloadQueue.cpp](<external-source-study>/aMule-2.3.3/src/DownloadQueue.cpp) | TBD from source study |
| Upload queue | `core.transfer.upload_queue` | [UploadQueue.cpp](<external-source-study>/aMule-2.3.3/src/UploadQueue.cpp) | TBD from source study |
| Bandwidth throttler | `core.transfer.throttle` | [UploadBandwidthThrottler.cpp](<external-source-study>/aMule-2.3.3/src/UploadBandwidthThrottler.cpp) | TBD from source study |
| Dead source list | `core.transfer.dead_sources` | [DeadSourceList.cpp](<external-source-study>/aMule-2.3.3/src/DeadSourceList.cpp) | TBD from source study |
| Peer client | `core.transfer.client` | [updownclient.cpp](<external-source-study>/aMule-2.3.3/src/updownclient.cpp), [BaseClient.cpp](<external-source-study>/aMule-2.3.3/src/BaseClient.cpp) | TBD from source study |
| TCP socket | `core.ed2k.tcp` | [ClientTCPSocket.cpp](<external-source-study>/aMule-2.3.3/src/ClientTCPSocket.cpp) | TBD from source study |
| UDP socket | `core.ed2k.udp` | [ClientUDPSocket.cpp](<external-source-study>/aMule-2.3.3/src/ClientUDPSocket.cpp) | TBD from source study |

### 7.2 Source exchange

| Concern | Python module | Source study | Status |
|---|---|---|---|
| Source exchange v2 | `core.transfer.source_exchange` | [OtherStructs.h](<external-source-study>/aMule-2.3.3/src/OtherStructs.h), SOURCEEXCHANGE2_VERSION=4 in [Constants.h](<external-source-study>/aMule-2.3.3/src/include/protocol/ed2k/Constants.h) | TBD from source study |
| Requested_Block_Struct | `core.transfer.partfile` | [OtherStructs.h](<external-source-study>/aMule-2.3.3/src/OtherStructs.h) | TBD from source study |

### 7.3 Search

| Concern | Python module | Source study | Status |
|---|---|---|---|
| Unified search engine | `core.search` | [SearchList.cpp](<external-source-study>/aMule-2.3.3/src/SearchList.cpp) | TBD from source study |
| Search result model | `core.search` | [SearchFile.cpp](<external-source-study>/aMule-2.3.3/src/SearchFile.cpp) | TBD from source study |
| Search expression parser | `core.search.parser` | [Parser.cpp](<external-source-study>/aMule-2.3.3/src/Parser.cpp), [Scanner.cpp](<external-source-study>/aMule-2.3.3/src/Scanner.cpp) | TBD from source study |

### 7.4 Sharing

| Concern | Python module | Source study | Status |
|---|---|---|---|
| Shared file list | `core.sharing` | [SharedFileList.cpp](<external-source-study>/aMule-2.3.3/src/SharedFileList.cpp) | TBD from source study |
| Known file (index) | `core.sharing.known` | [KnownFile.cpp](<external-source-study>/aMule-2.3.3/src/KnownFile.cpp), [KnownFileList.cpp](<external-source-study>/aMule-2.3.3/src/KnownFileList.cpp) | TBD from source study |
| ED2K link parse/generate | `core.sharing.links` | [ED2KLink.cpp](<external-source-study>/aMule-2.3.3/src/ED2KLink.cpp) | TBD from source study |
| AICH pipeline | `core.sharing.aich` | [SHAHashSet.cpp](<external-source-study>/aMule-2.3.3/src/SHAHashSet.cpp) | TBD from source study |

## 8. Security matrix (maps to `core.security`)

| Concern | Python module | Source study | Status |
|---|---|---|---|
| TCP obfuscation (RC4 + DH) | `core.security.obfuscation` | [EncryptedStreamSocket.cpp](<external-source-study>/aMule-2.3.3/src/EncryptedStreamSocket.cpp), [RC4Encrypt.cpp](<external-source-study>/aMule-2.3.3/src/RC4Encrypt.cpp), [CryptoPP_Inc.h](<external-source-study>/aMule-2.3.3/src/CryptoPP_Inc.h) | TBD from source study |
| UDP obfuscation | `core.security.obfuscation` | [EncryptedDatagramSocket.cpp](<external-source-study>/aMule-2.3.3/src/EncryptedDatagramSocket.cpp) | TBD from source study |
| Client credits | `core.security.credits` | [ClientCredits.cpp](<external-source-study>/aMule-2.3.3/src/ClientCredits.cpp), [ClientCreditsList.cpp](<external-source-study>/aMule-2.3.3/src/ClientCreditsList.cpp) | TBD from source study |

## 9. NAT / firewall / IP-filter matrix

| Concern | Python module | Source study | Status |
|---|---|---|---|
| IP filter | `core.ipfilter` | [IPFilter.cpp](<external-source-study>/aMule-2.3.3/src/IPFilter.cpp), [IPFilterScanner.cpp](<external-source-study>/aMule-2.3.3/src/IPFilterScanner.cpp) | TBD from source study |
| UPnP | `core.nat.upnp` | n/a (external lib) | deferred to M12 library selection |
| NAT-PMP | `core.nat.natpmp` | n/a (external lib) | deferred to M12 library selection |
| Firewall diagnostics | `core.nat.fwcheck` | [UDPFirewallTester.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/kademlia/UDPFirewallTester.cpp) | TBD from source study |

## 10. Persistence / state mapping

| State artifact | Native store | Import source | Source study | Status |
|---|---|---|---|---|
| Config | JSONC in [config](../config) | [amule-config-template.json](<parent-workspace>/amule-config-template.json) | [apply_amule_config.py](<parent-workspace>/apply_amule_config.py) | TBD from source study |
| Queues / part bitmaps / stats | DuckDB in [db](../db) | — | [PartFile.cpp](<external-source-study>/aMule-2.3.3/src/PartFile.cpp) (format reference) | TBD from source study |
| Shared files | DuckDB + JSON sidecar | [shared_files.json](<parent-workspace>/shared_files.json) | [SharedFileList.cpp](<external-source-study>/aMule-2.3.3/src/SharedFileList.cpp) | TBD from source study |
| Server list | DuckDB | [server.met](<parent-workspace>/amule-daemon-config/server.met) | [ServerList.cpp](<external-source-study>/aMule-2.3.3/src/ServerList.cpp) | TBD from source study |
| Kad routing + contacts | DuckDB | [nodes.dat](<parent-workspace>/amule-daemon-config/nodes.dat) | [RoutingZone.cpp](<external-source-study>/aMule-2.3.3/src/kademlia/routing/RoutingZone.cpp) | TBD from source study |
| Client credits | DuckDB | [clients.met](<parent-workspace>/amule-daemon-config/clients.met) | [ClientCreditsList.cpp](<external-source-study>/aMule-2.3.3/src/ClientCreditsList.cpp) | TBD from source study |
| AICH hashset | DuckDB | [known2_64.met](<parent-workspace>/amule-daemon-config/known2_64.met) | [SHAHashSet.cpp](<external-source-study>/aMule-2.3.3/src/SHAHashSet.cpp) | TBD from source study |
| IP filter | native text | [ipfilter.dat](<parent-workspace>/amule-daemon-config/ipfilter.dat), [ipfilter_static.dat](<parent-workspace>/amule-daemon-config/ipfilter_static.dat) | [IPFilter.cpp](<external-source-study>/aMule-2.3.3/src/IPFilter.cpp) | TBD from source study |
| GeoIP | read-only | [GeoIP.dat](<parent-workspace>/amule-daemon-config/GeoIP.dat) | — | TBD from source study |

## 11. Clean-room boundary (enforced)

1. **Study phase:** read only — aMule 2.3.3 source at [docs\src](<parent-workspace>/docs/src) and eMule 0.50 behavioral observation. Record opcodes, structures, constants, and behavior into the spec rows above.
2. **Spec phase:** this document + [AmuleD_v2_SPEC.md](../docs/AmuleD_v2_SPEC.md) become the **only** authoritative input for Python implementation.
3. **Implement phase:** `src/amuled_v2/core/` implements from the spec above. **No file in `core/` may be a derivative of a GPL file.** All module docstrings record the spec section they implement, not the C++ file they came from.
4. **Prohibition:** direct copying of C++ → Python for any file under [<external-source-study>\aMule-2.3.3](<external-source-study>/aMule-2.3.3). Constants and opcode values may be transcribed because facts are not copyrightable; logic must be re-written.

## 12. Live-network validation priorities (fixed order, per roadmap M16)

Kad bootstrap → Kad search → ED2K login → ED2K search → source discovery → partial download → resume → hashing → sharing → upload peer → obfuscation → long-run stability. Each gate carries regression vectors and hex captures of compatible peers. Live tests are enabled only after the loopback simulator stage for that feature is green, and never for early M-stages.

---

**Task start time:** 2026-09-22T21:08:50+04:00
**Task completion time:** 2026-09-22T21:14:30+04:00
