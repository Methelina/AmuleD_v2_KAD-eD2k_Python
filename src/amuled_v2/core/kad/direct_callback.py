"""KAD direct-UDP-callback (firewalled source type 6).

eMule flow (BaseClient.cpp:2981-3003, ClientUDPSocket.cpp:2659-2691):
the requester sends OP_DIRECTCALLBACKREQ (0x95, protocol 0xC5) as a client
UDP packet straight to the source's KAD contact address (ip:kad_udp_port)
with payload [our tcp_port u16][our userhash 16][our connect_options u8];
the firewalled source then makes an OUTBOUND TCP connection to us, which
the download side accepts on our advertised port.

src/amuled_v2/core/kad/direct_callback.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

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
