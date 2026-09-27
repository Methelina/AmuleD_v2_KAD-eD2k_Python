"""KAD direct-UDP-callback (firewalled source type 6).

eMule flow (BaseClient.cpp:2981-3003, ClientUDPSocket.cpp:2659-2691):
the requester sends OP_DIRECTCALLBACKREQ (0x95, protocol 0xC5) as a client
UDP packet straight to the source's KAD contact address (ip:kad_udp_port)
with payload [our tcp_port u16][our userhash 16][our connect_options u8];
the firewalled source then makes an OUTBOUND TCP connection to us, which
the download side accepts on our advertised port.

src/amuled_v2/core/kad/direct_callback.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Rendezvous payload wire-diff fixes (BaseClient.cpp:3147-3196):
      requester IP in network byte order (:3180 htonl), endpoint tail
      omitted when ip/port are zero (:3190), transport byte is the
      NATT_TRANSPORT_* enum (UTP=2 per live log), connect-options
      constant table for NATT_TRANSPORT_*.

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] OP_DIRECTCALLBACKREQ builder/parser + async UDP sender (stage X).
"""

from __future__ import annotations

import asyncio
import struct

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.kad.direct_callback")

__all__ = [
    "DIRECT_CALLBACK_OPCODE",
    "KAD_CALLBACK_REQ_OPCODE",
    "build_direct_callback_payload",
    "build_kad_callback_req_payload",
    "parse_direct_callback_payload",
    "parse_kad_callback_req_payload",
    "send_direct_callback_req",
    "send_kad_callback_req",
]

DIRECT_CALLBACK_OPCODE = 0x95  # Opcodes.h:450, protocol OP_EMULEPROT (0xC5)
KAD_CALLBACK_REQ_OPCODE = 0x52  # Opcodes.h:810, <TCPPORT (sender) [2]>
REASK_CALLBACK_UDP_OPCODE = 0x94  # Opcodes.h:449 (NAT-T rendezvous request)
RENDEZVOUS_MARKER = 0xA0  # Opcodes.h:705/704
CONNECT_OPT_NATT_ENDPOINT_HINT = 0x20  # Opcodes.h:219
CONNECT_OPT_NAT_TRAVERSAL_UTP = 0x80  # Opcodes.h:221
NATT_TRANSPORT_NONE = 0  # enum ENatTraversalTransport (live log: UTP=2)
NATT_TRANSPORT_QUIC = 1
NATT_TRANSPORT_UTP = 2
CLIENT_UDP_PROTOCOL = 0xC5


def build_direct_callback_payload(
    tcp_port: int, user_hash: bytes, connect_options: int = 3
) -> bytes:
    """[our tcp_port u16 LE][our userhash 16][connect_options u8] — 19 bytes
    (BaseClient.cpp:2989-2993)."""
    if len(user_hash) != 16:
        raise ValueError("user hash must be exactly 16 bytes")
    if not 0 <= tcp_port <= 0xFFFF:
        raise ValueError(f"tcp port out of UInt16 range: {tcp_port}")
    return (
        struct.pack("<H", tcp_port) + bytes(user_hash) + bytes((connect_options & 0xFF,))
    )


def parse_direct_callback_payload(payload: bytes) -> tuple[int, bytes, int]:
    """OP_DIRECTCALLBACKREQ payload -> (tcp_port, user_hash, connect_options)."""
    if len(payload) != 19:
        raise ValueError(
            f"malformed OP_DIRECTCALLBACKREQ: {len(payload)} bytes, expected 19"
        )
    port = struct.unpack_from("<H", payload, 0)[0]
    return port, payload[2:18], payload[18]


async def send_direct_callback_req(
    host: str,
    kad_udp_port: int,
    our_tcp_port: int,
    our_user_hash: bytes,
    connect_options: int = 3,
    *,
    attempts: int = 3,
    pause: float = 1.0,
) -> None:
    """Fire OP_DIRECTCALLBACKREQ at the source's KAD contact endpoint.

    Fire-and-forget by design: the source answers with a TCP connection,
    not with a UDP reply (ClientUDPSocket.cpp:2687 TryToConnect).
    """
    loop = asyncio.get_running_loop()
    payload = build_direct_callback_payload(our_tcp_port, our_user_hash, connect_options)
    wire = (
        bytes((CLIENT_UDP_PROTOCOL,))
        + struct.pack("<I", len(payload) + 1)
        + bytes((DIRECT_CALLBACK_OPCODE,))
        + payload
    )
    sock = socket_udp()
    try:
        for attempt in range(1, attempts + 1):
            await loop.sock_sendto(sock, wire, (host, kad_udp_port))
            log.info(
                "PEER direct-callback request sent: endpoint=%s:%d, "
                "attempt=%d, our_port=%d",
                host, kad_udp_port, attempt, our_tcp_port,
            )
            if attempt < attempts:
                await asyncio.sleep(pause)
    finally:
        sock.close()


def socket_udp():
    """Fresh non-blocking UDP socket for the callback request."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    return sock


# ---------------------------------------------------------------------------
# KAD serving-buddy callback (firewalled source type 3/5).
# BaseClient.cpp:3258-3282 (legacy KAD callback branch): the requester sends
# KADEMLIA_CALLBACK_REQ (0x52) to the TARGET's serving buddy
# (buddy_ip:buddy_udp_port, from the source entry tags) via the client UDP
# socket with payload [buddy KadID 16][file hash 16][our tcp port u16].
# The buddy relays a TCP OP_CALLBACK to the firewalled source
# (KademliaUDPListener.cpp:1850-1866), which then connects OUT to us.
# ---------------------------------------------------------------------------


def build_kad_callback_req_payload(
    buddy_id: bytes, file_hash: bytes, tcp_port: int
) -> bytes:
    """[buddy KadID 16][file hash 16][tcp port u16 LE] — 34 bytes
    (BaseClient.cpp:3259-3262)."""
    if len(buddy_id) != 16:
        raise ValueError("buddy id must be exactly 16 bytes")
    if len(file_hash) != 16:
        raise ValueError("file hash must be exactly 16 bytes")
    if not 0 <= tcp_port <= 0xFFFF:
        raise ValueError(f"tcp port out of UInt16 range: {tcp_port}")
    return bytes(buddy_id) + bytes(file_hash) + struct.pack("<H", tcp_port)


def parse_kad_callback_req_payload(payload: bytes) -> tuple[bytes, bytes, int]:
    """KADEMLIA_CALLBACK_REQ payload -> (buddy_id, file_hash, tcp_port)."""
    if len(payload) not in (34, 38):
        raise ValueError(
            f"malformed KADEMLIA_CALLBACK_REQ: {len(payload)} bytes, "
            "expected 34 or 38"
        )
    return payload[:16], payload[16:32], struct.unpack_from("<H", payload, 32)[0]


async def send_kad_callback_req(
    host: str,
    buddy_udp_port: int,
    buddy_id: bytes,
    file_hash: bytes,
    our_tcp_port: int,
    *,
    attempts: int = 3,
    pause: float = 1.0,
) -> None:
    """Fire KADEMLIA_CALLBACK_REQ at the source's serving buddy.

    Fire-and-forget: the firewalled source answers with a TCP connection
    (relayed via the buddy's OP_CALLBACK), not with a UDP reply.
    """
    loop = asyncio.get_running_loop()
    payload = build_kad_callback_req_payload(buddy_id, file_hash, our_tcp_port)
    wire = (
        bytes((CLIENT_UDP_PROTOCOL,))
        + struct.pack("<I", len(payload) + 1)
        + bytes((KAD_CALLBACK_REQ_OPCODE,))
        + payload
    )
    sock = socket_udp()
    try:
        for attempt in range(1, attempts + 1):
            await loop.sock_sendto(sock, wire, (host, buddy_udp_port))
            log.info(
                "PEER kad-callback request sent: buddy=%s:%d, attempt=%d, "
                "our_port=%d",
                host, buddy_udp_port, attempt, our_tcp_port,
            )
            if attempt < attempts:
                await asyncio.sleep(pause)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# NAT-T rendezvous (double-firewalled case; BaseClient.cpp:3091-3257).
# Requester -> TARGET's buddy via client UDP: OP_REASKCALLBACKUDP (0x94)
# [buddy KadID 16][null marker 16][OP_RENDEZVOUS 0xA0][our userhash 16]
# [connect options u8 | ENDPOINT_HINT][file hash 16][our ext ip u32]
# [our ext udp port u16][transport hint u8].  The buddy relays
# OP_REASKCALLBACKTCP to the firewalled source, kicks our NAT with
# OP_HOLEPUNCH and answers OP_NATT_ENDPOINT_HINT; both sides then open the
# NAT-T transport (uTP 0x80 / QUIC 0x40) over the punched endpoint.
# ---------------------------------------------------------------------------


def build_rendezvous_req_payload(
    buddy_id: bytes,
    our_user_hash: bytes,
    connect_options: int,
    file_hash: bytes,
    our_ext_ip: int,
    our_ext_udp_port: int,
    transport_hint: int,
) -> bytes:
    """BaseClient.cpp:3147-3196 payload layout (LE where applicable).

    The requester endpoint tail [ip u32][port u16][transport u8] is only
    appended when BOTH ip and port are nonzero (:3190) — and the IP goes
    out in NETWORK byte order (:3180 applies htonl before the LE
    WriteUInt32).  The transport byte is a NATT_TRANSPORT_* ENUM
    (NONE=0, QUIC=1, UTP=2 — live log shows transportHint=2 while pinned
    to uTP), NOT a CONNECT_OPT_* flag byte.
    """
    if len(buddy_id) != 16 or len(our_user_hash) != 16 or len(file_hash) != 16:
        raise ValueError("rendezvous payload needs three 16-byte ids")
    opts = (connect_options | CONNECT_OPT_NATT_ENDPOINT_HINT) & 0xFF
    payload = (
        bytes(buddy_id)
        + b"\x00" * 16
        + bytes((RENDEZVOUS_MARKER,))
        + bytes(our_user_hash)
        + bytes((opts,))
        + bytes(file_hash)
    )
    if our_ext_ip and our_ext_udp_port:
        payload += (
            struct.pack(">I", our_ext_ip & 0xFFFFFFFF)  # htonl, :3180
            + struct.pack("<H", our_ext_udp_port & 0xFFFF)
            + bytes((transport_hint & 0xFF,))
        )
    return payload


async def send_rendezvous_req(
    host: str,
    buddy_udp_port: int,
    buddy_id: bytes,
    our_user_hash: bytes,
    file_hash: bytes,
    our_ext_ip: int,
    our_ext_udp_port: int,
    *,
    connect_options: int = 3,
    transport_hint: int = 0,
    attempts: int = 3,
    pause: float = 1.0,
) -> None:
    """Fire OP_REASKCALLBACKUDP (rendezvous) at the target's buddy."""
    loop = asyncio.get_running_loop()
    payload = build_rendezvous_req_payload(
        buddy_id,
        our_user_hash,
        connect_options,
        file_hash,
        our_ext_ip,
        our_ext_udp_port,
        transport_hint,
    )
    wire = (
        bytes((CLIENT_UDP_PROTOCOL,))
        + struct.pack("<I", len(payload) + 1)
        + bytes((REASK_CALLBACK_UDP_OPCODE,))
        + payload
    )
    sock = socket_udp()
    try:
        for attempt in range(1, attempts + 1):
            await loop.sock_sendto(sock, wire, (host, buddy_udp_port))
            log.info(
                "PEER rendezvous request sent: buddy=%s:%d, attempt=%d",
                host, buddy_udp_port, attempt,
            )
            if attempt < attempts:
                await asyncio.sleep(pause)
    finally:
        sock.close()
