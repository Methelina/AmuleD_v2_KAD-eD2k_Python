# Claude prompt — AmuleD eD2K/KAD client: obfuscated dial blocker

You are helping continue development of AmuleD, a from-scratch Python 3.12 reimplementation of an eMule-compatible file-sharing client (eD2K + Kademlia, protocol reference: eMule 0.50a and its fork eMuleAI).

## INPUTS YOU ARE GIVEN

1. **roadmap.md** — project operational roadmap. Section **"11e. Session 7"** is the CURRENT state: what is implemented and live-verified (KAD search/sources live, BASIC TCP-obfuscation handshake accepted by real peers, HELLO codec fixes), the single remaining blocker, and planned next steps. Earlier sections (3.x, 11b, 11d) hold confirmed wire-level protocol findings — treat them as authoritative measurements, do not contradict or re-derive them.
2. **continuation-prompt.md** — detailed handoff: exact fixes applied (HELLO 6-byte tail, probe framing), everything tested and ruled out, ground-truth decryption tooling (target userhash = KAD sourceID; keypart is plaintext in the handshake; RC4 keys = MD5(userhash+34/203+keypart), 1024-byte keystream drop), eMuleAI config facts, live-network behavior (plaintext protocol dead on today's network; KAD source entries churn within minutes; TCP SYN-ACK is not proof a peer application is alive), and the mandatory startup order (the KAD spider daemon must be running before any KAD work).
3. **The git repository** https://github.com/eMuleAI/eMuleAI — the primary protocol reference source. Key files for this task:
   - `srchybrid/EncryptedStreamSocket.cpp`
   - `srchybrid/BaseClient.cpp` (SendHelloPacket, SendHelloTypePacket, ProcessHelloTypePacket, Connect)
   - `srchybrid/packets.cpp` / `srchybrid/packets.h` (Header_Struct, CTag parser)
   - `srchybrid/ListenSocket.cpp` / `CClientReqSocket::ProcessPacket`
   - `srchybrid/opcodes.h`

## TASK CONTEXT (summary; the two files above expand it)

**What already works live:** KAD keyword search (200 real results), KAD file-source discovery (entries carry type/ip/tcp_port/source_id, where source_id IS the target client's userhash — proven against the reference: publish uses `CKademlia::GetPrefs()->GetClientHash()` which equals `GetUserHash()`, and the receiver stores it via `SetUserHash`).

**What we implemented:** the client side of the BASIC (non-DH) TCP obfuscation handshake, byte-for-byte per EncryptedStreamSocket.cpp ECS_PENDING path:

- keys: `send = MD5(target_userhash[16] || 0x22 || keypart_u32_LE)`, `recv = MD5(target_userhash || 0xCB || keypart_u32_LE)`, RC4 with first 1024 keystream bytes dropped;
- request: `[marker u8, not 0xE3/0xC5/0xD4][keypart u32 LE][RC4_send(MAGICVALUE_SYNC u32 LE)][RC4_send(0x00)][RC4_send(0x00)][RC4_send(padlen u8)][RC4_send(pad)]` — ciphertext starts at offset 5;
- response parsed as `RC4_recv(MAGIC u32 LE | method 0x00 | padlen u8 | pad)`.

**VERIFIED LIVE:** dialing a real peer (eMule 0.50a MorphXT 12.7) — our obfuscated handshake is accepted every time; the peer replies with a valid encrypted handshake response. So userhash sourcing, key derivation, and handshake framing are correct.

**THE BLOCKER:** as soon as the handshake completes we send one RC4-encrypted OP_HELLO and the peer closes the connection (graceful FIN, zero bytes back, no HELLOANSWER) in under 0.5 s — reproducibly.

### Our OP_HELLO bytes (validate against SendHelloPacket/SendHelloTypePacket)

```
[0xE3][len u32 LE = payload+1][opcode 0x01][0x10][userhash 16][client_id u32][tcp_port u16][tagcount u32=6]
```

tags in new format, each `[type u8 | 0x80][name_id u8][value]`:

- CT_NAME(0x01) STR6 "tester"
- CT_VERSION(0x11) UINT8 0x3C
- CT_EMULE_UDPPORTS(0xF9) UINT8 0
- CT_EMULE_MISCOPTIONS1(0xFA) UINT32 0x34104216
- CT_EMULEVERSION(0xFB) UINT16 0xC800
- CT_EMULE_MISCOPTIONS2(0xFE) UINT16 0x2439

then `[server_ip u32 = 0][server_port u16 = 0]`. Payload = 61 bytes.

Tag wire format matches CTag's parser (Packets.cpp:444-518): 0x80-flagged type byte + one-byte name id; STRn = fixed-length raw string; UINT8/16/32 LE. Type constants match opcodes.h exactly (UINT16=0x08, UINT8=0x09, BLOB=0x07, BSOB=0x0A, UINT64=0x0B, STR1..16=0x11..0x20).

### RULED OUT BY EXPERIMENT (do not re-suggest)

- nickname content;
- sending EMULEINFO before HELLOANSWER vs withholding it (identical instant FIN);
- packet framing (was `[proto][opcode][len]`, now canonical `[proto][len][opcode]`);
- missing server ip/port tail;
- userhash format;
- RC4 derivation (handshake success proves it);
- tag type constants; tag wire layout;
- wrong target userhash (would be a fast reject with a different fingerprint, and handshake acceptance already validates the shared secret direction).

## QUESTIONS (cite functions/files from the eMuleAI repo)

1. Enumerate EVERY condition between "basic obfuscation handshake completed (client side, ECS_PENDING -> ECS_NEGOTIATING/ENCRYPTING)" and "HELLOANSWER received" that causes a silent immediate disconnect with no data sent back: `CClientReqSocket::ProcessPacket`, ListenSocket paths, `clientlist->AddClient`, Shield/anti-leech modules, connection rate limits, IP/port consistency checks (our client_id is a constant, not our public IP — is that checked?), hello arriving in the same TCP segment as handshake data, minimum delay between handshake response and first application packet.
2. After `StartNegotiation(true)` finishes, is the HELLO encrypted with the SAME RC4 send-key stream continuing exactly where the handshake body's ciphertext ended — or is any keystream consumed/reset/padded between handshake and first packet (`SendNegotiatingData` details)?
3. Does eMuleAI (vs 0.50a) make a vanilla-style hello unacceptable — e.g. mandatory extra tags (CT_ESERVER_BUDDY_FLAGS, ET_INCOMPLETEPARTS, CT_MOD_MISCOPTIONS, CT_MOD_VERSION), changed hello order, NatTraversal/uTP wrapping on TCP, or hello-only-after-uTP assumptions?
4. Any known reason a MorphXT 12.7 receiver accepts the obfuscated handshake but instantly FINs on the first encrypted application packet — e.g. send/recv key direction swap on our side, double keystream drop, pad-length interpretation, or the receiver expecting the first packet within X ms?

**Most valuable answer:** the exact ordered byte/state timeline a real eMule client produces between TCP connect and HELLOANSWER in the BASIC-obfuscation dial case, plus every silent-disconnect condition in that window.
