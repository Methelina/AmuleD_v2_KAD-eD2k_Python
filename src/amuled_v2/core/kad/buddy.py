"""KAD serving-buddy registry and wire payloads (stage X, roadmap 11o).

Serving side of the eMuleAI buddy protocol (oracle:
kademlia/net/KademliaUDPListener.cpp:1681-1866, BaseClient.cpp:1853-2320;
recon: tmp/recon/emuleai-buddy-udp.recon.md):

- KADEMLIA_FINDSERVINGBUDDY_REQ (0x51) payload:
  [ServedBuddyID 16 LE][userhash 16 LE][tcp_port u16 LE][opts u8?]
  where ServedBuddyID = requester KadID XOR 0xFFFF...FF (eMule XOR
  convention; the RES echoes it and the requester XORs it back).
- RES (0x5A): [ServedBuddyID 16 LE][buddyHash 16 LE][tcp port u16 LE]
  [connectOpts u8?].
- KADEMLIA_CALLBACK_REQ (0x52): [uCheck 16 LE][fileHash 16 LE]
  [uTCP u16 LE][extIP u32 LE?]; relayed to the served client over its
  buddy TCP channel as OP_CALLBACK (0x99, protocol 0xC5):
  [uCheck 16][fileHash 16][requesterIP u32 LE][requesterPort u16 LE].

The registry maps served KadID -> the live TCP transport the client
registered on (its HELLO carries CT_EMULE_SERVINGBUDDYID = 0xBF with the
raw KadID, BaseClient.cpp:2005-2013).

src/amuled_v2/core/kad/buddy.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Wire payloads for 0x51/0x5A/0x52 and the OP_CALLBACK TCP relay.
  [+] BuddyRegistry: served-buddy table (KadID + XOR-form lookup),
      capacity gate, spider-side answer/relay helpers.
  [+] Loopback-verified: 0x51->0x5A builders, TCP registration via the
      CT_EMULE_SERVINGBUDDYID (0xBF) hello tag (codec: hello hash tags
      write as TAGTYPE_HASH 0x01), 0x52 -> OP_CALLBACK relay.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.buddy")

__all__ = [
    "BuddyRegistry",
    "buddy_registry",
    "KADEMLIA_FINDSERVINGBUDDY_REQ",
    "KADEMLIA_FINDSERVINGBUDDY_RES",
    "KADEMLIA_CALLBACK_REQ",
    "OP_CALLBACK",
    "OP_BUDDYPING",
    "parse_find_serving_buddy_req",
    "build_find_serving_buddy_res",
    "parse_callback_req",
    "build_op_callback_payload",
    "xor_mask",
]

KADEMLIA_FINDSERVINGBUDDY_REQ = 0x51
KADEMLIA_FINDSERVINGBUDDY_RES = 0x5A
KADEMLIA_CALLBACK_REQ = 0x52
OP_CALLBACK = 0x99
OP_BUDDYPING = 0x9F

_TAG_SERVINGBUDDYID = 0xBF
_EMULE_PROTOCOL = 0xC5

XOR_MASK = b"\xFF" * 16


def xor_mask(kad_id: bytes) -> bytes:
    """KadID XOR 0xFFFF...FF (the eMule buddy-ID wire form)."""
    return bytes(b ^ 0xFF for b in kad_id)


def parse_find_serving_buddy_req(
    payload: bytes,
) -> tuple[bytes, bytes, int, int | None]:
    """0x51 payload -> (served_buddy_id_xor, userhash, tcp_port, opts|None)."""
    if len(payload) < 34:
        raise ValueError(f"0x51 payload too short: {len(payload)}")
    served_id = bytes(payload[0:16])
    userhash = bytes(payload[16:32])
    (tcp_port,) = struct.unpack_from("<H", payload, 32)
    opts: int | None = None
    if len(payload) >= 35:
        opts = payload[34]
    return served_id, userhash, tcp_port, opts


def build_find_serving_buddy_res(
    served_buddy_id_xor: bytes,
    buddy_hash: bytes,
    buddy_tcp_port: int,
    connect_opts: int | None = None,
) -> bytes:
    """0x5A wire payload: echo the XOR-form ID, our client hash, our TCP
    port, optional connect-options byte."""
    out = bytes(served_buddy_id_xor) + bytes(buddy_hash)
    out += struct.pack("<H", buddy_tcp_port & 0xFFFF)
    if connect_opts is not None:
        out += bytes((connect_opts & 0xFF,))
    return out


def parse_callback_req(payload: bytes) -> tuple[bytes, bytes, int, int]:
    """0x52 payload -> (ucheck, file_hash, requester_tcp, ext_ip)."""
    if len(payload) < 34:
        raise ValueError(f"0x52 payload too short: {len(payload)}")
    ucheck = bytes(payload[0:16])
    file_hash = bytes(payload[16:32])
    (tcp_port,) = struct.unpack_from("<H", payload, 32)
    ext_ip = 0
    if len(payload) >= 38:
        (ext_ip,) = struct.unpack_from("<I", payload, 34)
    return ucheck, file_hash, tcp_port, ext_ip


def build_op_callback_payload(
    kad_id_xor: bytes,
    file_hash: bytes,
    requester_ip: str,
    requester_tcp_port: int,
) -> bytes:
    """OP_CALLBACK (0x99, protocol 0xC5) TCP payload the buddy relays to
    the served client: [kad_id 16][file_hash 16][ip u32 LE][port u16 LE]."""
    a, b, c, d = (int(x) for x in requester_ip.split("."))
    ip_le = struct.pack("<I", (a << 24) | (b << 16) | (c << 8) | d)
    return (
        bytes(kad_id_xor)
        + bytes(file_hash)
        + ip_le
        + struct.pack("<H", requester_tcp_port & 0xFFFF)
    )


class _ServedBuddy:
    __slots__ = ("kad_id", "kad_id_xor", "ip", "tcp_port", "writer",
                 "registered_at", "last_seen")

    def __init__(self, kad_id: bytes, ip: str, tcp_port: int, writer) -> None:
        self.kad_id = kad_id
        self.kad_id_xor = xor_mask(kad_id)
        self.ip = ip
        self.tcp_port = tcp_port
        self.writer = writer
        self.registered_at = time.monotonic()
        self.last_seen = self.registered_at


class BuddyRegistry:
    """Served-buddy table shared by the KAD spider (UDP answers) and the
    TCP listener (client registration + OP_CALLBACK relay)."""

    def __init__(self, max_served: int = 16) -> None:
        self._lock = threading.Lock()
        self._served: dict[bytes, _ServedBuddy] = {}
        self.max_served = max_served
        self.tcp_port = 0

    def configure(self, tcp_port: int, max_served: int = 16) -> None:
        with self._lock:
            self.tcp_port = tcp_port
            self.max_served = max_served

    def register(
        self, kad_id: bytes, ip: str, tcp_port: int, writer
    ) -> None:
        """A firewalled client registered via its HELLO
        (CT_EMULE_SERVINGBUDDYID tag) on the buddy TCP channel."""
        entry = _ServedBuddy(bytes(kad_id), ip, tcp_port, writer)
        with self._lock:
            self._served[entry.kad_id] = entry
            self._served[entry.kad_id_xor] = entry
        log.info(
            "KAD buddy registered: kad_id=%s, peer=%s:%d",
            kad_id.hex().upper(), ip, tcp_port,
        )

    def unregister_transport(self, writer) -> None:
        with self._lock:
            stale = [
                k
                for k, v in self._served.items()
                if v.writer is writer
            ]
            for k in stale:
                self._served.pop(k, None)
        if stale:
            log.info("KAD buddy unregistered: entries=%d", len(stale) // 2)

    def lookup(self, ucheck: bytes) -> _ServedBuddy | None:
        """Find a served client by KadID in either wire form (plain or
        XOR-masked — eMuleAI also falls back to the complement,
        ClientUDPSocket.cpp:1112-1123)."""
        with self._lock:
            return self._served.get(bytes(ucheck)) or self._served.get(
                xor_mask(bytes(ucheck))
            )

    def can_serve(self) -> bool:
        """Gate G1/G2 (KademliaUDPListener.cpp:1690-1697): we must be TCP
        open (nonzero port) and below capacity."""
        with self._lock:
            count = len({id(v) for v in self._served.values()})
        return self.tcp_port != 0 and count < self.max_served

    def relay_op_callback(
        self, ucheck: bytes, file_hash: bytes, requester_ip: str,
        requester_tcp_port: int,
    ) -> bool:
        """Relay a KADEMLIA_CALLBACK_REQ as an OP_CALLBACK TCP packet to
        the served client (KademliaUDPListener.cpp:1836-1866)."""
        entry = self.lookup(ucheck)
        if entry is None:
            return False
        payload = build_op_callback_payload(
            entry.kad_id_xor, file_hash, requester_ip, requester_tcp_port
        )
        wire = (
            bytes((_EMULE_PROTOCOL,))
            + struct.pack("<I", len(payload) + 1)
            + bytes((OP_CALLBACK,))
            + payload
        )
        try:
            entry.writer.write(wire)
        except Exception as exc:
            log.warning(
                "KAD buddy relay failed: kad_id=%s, error=%s",
                entry.kad_id.hex().upper(), exc,
            )
            return False
        log.info(
            "KAD buddy callback relayed: kad_id=%s, file=%s, "
            "requester=%s:%d",
            entry.kad_id.hex().upper(), file_hash.hex().upper(),
            requester_ip, requester_tcp_port,
        )
        return True


buddy_registry = BuddyRegistry()
