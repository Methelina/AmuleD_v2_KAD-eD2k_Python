"""NAT-T UDP session layer: 0xC5 demultiplex and rendezvous state machine.

Sits on a client-UDP socket (its own datagram endpoint or a shared one) and
demultiplexes the NAT-T opcodes (eMuleAI ClientUDPSocket.cpp):

  OP_HOLEPUNCH (0xA1, empty payload)          — NAT punch trigger
  OP_NATT_ENDPOINT_HINT (0xAA, 56 bytes)      — buddy-relayed endpoint
      [ver=1 u8][targetHash 16][servingBuddyID 16][fileHash 16]
      [targetIPv4 u32 LE][targetPort u16][targetOptions u8]
  OP_UDPRESERVEDPROT2 (0xB2) frames:
      UTP 0x00 / QUIC 0x01  — raw transport payloads
      CAPS 0x02 / CAPS_ACK 0x03
          [magic u32 LE = 0x43514145][version=1 u8][options u8]
          [senderHash 16][expectedHash 16][fileHash 16]
      KEY 0xFF — [sender userhash 16], registers the peer hash for the
          endpoint (ClientUDPSocket.cpp:397-407, 999-1006)

Requester flow (rendezvous, BaseClient.cpp:3091-3257): send
OP_REASKCALLBACKUDP with the rendezvous marker to the target's buddy,
consume OP_NATT_ENDPOINT_HINT, fire the holepunch burst (12 packets +
port-window sweep, ClientUDPSocket.cpp:1957-2015), run the CAPS exchange
(3 CAPS + sweep, 523-550) advertising uTP only (CONNECT_OPT 0x80; we
never advertise QUIC 0x40 — eMuleAI's ngtcp2 interop with our aioquic
is unproven on the wire), then bring up the uTP stream and hand its
reader/writer adapters to PeerClient.adopt_connection.

Source role (loopback tests / kernel): arm_source() answers holepunches
with CAPS and accepts inbound uTP SYNs, mirroring
ClientUDPSocket.cpp:2021-2214 (holepunch case) and 410-416 (UTP wrap).

src/amuled_v2/core/natt/session.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] IPv6 NAT-T (dual-stack): start6() opens the v6 transport;
      rendezvous_connect with an IPv6 target_addr takes the
      direct-punch variant (no endpoint hint — hints are IPv4-only,
      ClientUDPSocket.cpp:1276), punching/caps/uTP straight at the
      known endpoint, mirroring eMuleAI's live IPv6 rendezvous.
  [+] Windows Proactor workaround: asyncio IPv6 datagram sendto
      silently drops (overlapped WSASendTo, WinError 10022) — v6 sends
      go through a raw non-blocking socket (receive stays asyncio).
  [+] Demux normalizes Windows IPv6 4-tuple addrs to (host, port).

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] 0xC5 framing + payload builders/parsers for HOLEPUNCH,
      ENDPOINT_HINT and 0xB2 frames (CAPS/CAPS_ACK/KEY/UTP/QUIC).
  [+] NattUdpSession: expectation table (30 s TTL, port-window match),
      datagram demultiplexer, uTP stream registry.
  [+] Rendezvous requester driver: hint wait -> holepunch burst ->
      CAPS exchange -> uTP connect -> KEY frame.
  [+] Source role: arm_source() answering holepunch + CAPS, inbound
      uTP SYN accept.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import time

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.natt.session")

__all__ = [
    "NattUdpSession",
    "NattError",
    "CLIENT_UDP_PROTOCOL",
    "OP_HOLEPUNCH",
    "OP_NATT_ENDPOINT_HINT",
    "UDP_RESERVEDPROT2",
    "NATT_FRAME_UTP",
    "NATT_FRAME_QUIC",
    "NATT_FRAME_CAPS",
    "NATT_FRAME_CAPS_ACK",
    "NATT_FRAME_KEY",
    "CAPS_MAGIC",
    "CAPS_VERSION",
    "ENDPOINT_HINT_SIZE",
    "CONNECT_OPT_NAT_TRAVERSAL_UTP",
    "CONNECT_OPT_NAT_TRAVERSAL_QUIC",
    "build_client_udp_packet",
    "parse_client_udp_packet",
    "build_endpoint_hint_payload",
    "parse_endpoint_hint_payload",
    "build_caps_payload",
    "parse_caps_payload",
]

CLIENT_UDP_PROTOCOL = 0xC5
OP_HOLEPUNCH = 0xA1  # Opcodes.h:446
OP_NATT_ENDPOINT_HINT = 0xAA  # Opcodes.h:447
UDP_RESERVEDPROT2 = 0xB2  # Opcodes.h:207
NATT_FRAME_UTP = 0x00  # Opcodes.h:208
NATT_FRAME_QUIC = 0x01  # Opcodes.h:209
NATT_FRAME_CAPS = 0x02  # Opcodes.h:210
NATT_FRAME_CAPS_ACK = 0x03  # Opcodes.h:211
NATT_FRAME_KEY = 0xFF  # Opcodes.h:212

CAPS_MAGIC = 0x43514145  # ClientUDPSocket.cpp:494
CAPS_VERSION = 1
CAPS_MIN_SIZE = 4 + 1 + 1 + 16 + 16 + 16  # 50, ClientUDPSocket.cpp:690
ENDPOINT_HINT_SIZE = 1 + 16 + 16 + 16 + 4 + 2 + 1  # 56, :1305

CONNECT_OPT_NAT_TRAVERSAL_QUIC = 0x40  # Opcodes.h:220
CONNECT_OPT_NAT_TRAVERSAL_UTP = 0x80  # Opcodes.h:221

NAT_EXPECT_TTL = 30.0  # ClientUDPSocket.cpp:59 (30 s)
_MAX_EXPECTATIONS = 64  # ClientUDPSocket.cpp:188-189
_HOLEPUNCH_BURST = 12  # ClientUDPSocket.cpp:1959
_CAPS_BURST = 3  # ClientUDPSocket.cpp:531
_BURST_PAUSE = 0.05  # ClientUDPSocket.cpp:1965-1966


class NattError(Exception):
    pass


def _is_v6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 0xC5 framing: [protocol][len u32 LE incl. opcode][opcode][payload].
# ---------------------------------------------------------------------------


def build_client_udp_packet(opcode: int, payload: bytes = b"") -> bytes:
    return (
        bytes((CLIENT_UDP_PROTOCOL,))
        + struct.pack("<I", len(payload) + 1)
        + bytes((opcode,))
        + bytes(payload)
    )


def parse_client_udp_packet(data: bytes) -> tuple[int, bytes] | None:
    """Inbound client-UDP datagram -> (opcode, payload) or None."""
    if len(data) < 6 or data[0] != CLIENT_UDP_PROTOCOL:
        return None
    (length,) = struct.unpack_from("<I", data, 1)
    if length < 1 or len(data) < 5 + length:
        return None
    return data[5], data[6 : 5 + length]


def ip_to_u32(host: str) -> int:
    a, b, c, d = (int(part) for part in host.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def u32_to_ip(value: int) -> str:
    return f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


# ---------------------------------------------------------------------------
# OP_NATT_ENDPOINT_HINT payload (ClientUDPSocket.cpp:1301-1365).
# ---------------------------------------------------------------------------


def build_endpoint_hint_payload(
    target_hash: bytes,
    serving_buddy_id: bytes,
    file_hash: bytes,
    target_ip: int,
    target_port: int,
    target_options: int,
) -> bytes:
    return (
        bytes((1,))
        + bytes(target_hash)
        + bytes(serving_buddy_id)
        + bytes(file_hash)
        + struct.pack("<IH", target_ip & 0xFFFFFFFF, target_port & 0xFFFF)
        + bytes((target_options & 0xFF,))
    )


def parse_endpoint_hint_payload(payload: bytes) -> dict:
    if len(payload) != ENDPOINT_HINT_SIZE:
        raise NattError(
            f"endpoint hint size {len(payload)} != {ENDPOINT_HINT_SIZE}"
        )
    ver = payload[0]
    if ver != 1:
        raise NattError(f"endpoint hint version {ver} != 1")
    (target_ip, target_port) = struct.unpack_from("<IH", payload, 49)
    return {
        "version": ver,
        "target_hash": payload[1:17],
        "serving_buddy_id": payload[17:33],
        "file_hash": payload[33:49],
        "target_ip": u32_to_ip(target_ip),
        "target_port": target_port,
        "target_options": payload[55],
    }


# ---------------------------------------------------------------------------
# CAPS frame payload (ClientUDPSocket.cpp:480-521 build, 688-793 parse).
# ---------------------------------------------------------------------------


def build_caps_payload(
    options: int,
    sender_hash: bytes,
    expected_hash: bytes | None,
    file_hash: bytes | None,
) -> bytes:
    return (
        struct.pack("<IBB", CAPS_MAGIC, CAPS_VERSION, options & 0xFF)
        + bytes(sender_hash)
        + (bytes(expected_hash) if expected_hash else b"\x00" * 16)
        + (bytes(file_hash) if file_hash else b"\x00" * 16)
    )


def parse_caps_payload(payload: bytes) -> dict:
    if len(payload) < CAPS_MIN_SIZE:
        raise NattError(f"caps frame too short: {len(payload)}")
    magic, version, options = struct.unpack_from("<IBB", payload, 0)
    if magic != CAPS_MAGIC or version != CAPS_VERSION:
        raise NattError(f"caps magic/version mismatch: {magic:#x}/{version}")
    return {
        "options": options,
        "sender_hash": payload[6:22],
        "expected_hash": payload[22:38],
        "file_hash": payload[38:54],
    }


# ---------------------------------------------------------------------------
# Expectation table (ClientUDPSocket.cpp:141-293).
# ---------------------------------------------------------------------------


class _Expectation:
    __slots__ = ("ip", "port", "expires", "user_hash", "file_hash", "role",
                 "hint_future", "caps_future", "holepunch_evt")

    def __init__(self, ip: str, port: int, user_hash, file_hash, role) -> None:
        self.ip = ip
        self.port = port
        self.expires = time.monotonic() + NAT_EXPECT_TTL
        self.user_hash = user_hash
        self.file_hash = file_hash
        self.role = role  # "download" (requester) | "source" (firewalled)
        self.hint_future: asyncio.Future | None = None
        self.caps_future: asyncio.Future | None = None
        self.holepunch_evt = asyncio.Event()


# ---------------------------------------------------------------------------
# The session itself.
# ---------------------------------------------------------------------------


class NattUdpSession(asyncio.DatagramProtocol):
    """NAT-T demultiplexer + rendezvous driver on one client-UDP socket."""

    def __init__(
        self,
        user_hash: bytes,
        *,
        port_window: int = 0,
        on_inbound_utp=None,
    ) -> None:
        if len(user_hash) != 16:
            raise NattError("user hash must be exactly 16 bytes")
        self.user_hash = bytes(user_hash)
        self.port_window = port_window
        self.on_inbound_utp = on_inbound_utp
        self._transport: asyncio.DatagramTransport | None = None
        self._transport6: asyncio.DatagramTransport | None = None
        self._sock6: socket.socket | None = None
        self._expectations: list[_Expectation] = []
        self._utp_streams: dict[tuple, object] = {}  # (addr, conn_id) -> UtpStream
        self._quic_handlers: dict[tuple, object] = {}
        self._peer_hashes: dict[tuple, bytes] = {}
        self._peer_caps: dict[tuple, int] = {}
        self._source_armed: dict[bytes, dict] = {}  # file_hash -> info
        self._tasks: set[asyncio.Task] = set()

    # -- lifecycle ----------------------------------------------------------

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        loop = asyncio.get_running_loop()
        if host == "0.0.0.0":
            # Egress bind (live 2026-09-28): rendezvous punch packets must
            # leave through the physical NIC, not a VPN TUN default route -
            # the peer dials the source address of our UDP punch, and only
            # the home-NAT path has the UPnP-forwarded inbound port.
            from amuled_v2.core.net.bind_ip import resolve_bind_ip

            host = resolve_bind_ip() or host
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=(host, port)
        )
        bound = self._transport.get_extra_info("sockname")[1]
        log.info("NATT session bound: host=%s, port=%d", host, bound)
        return bound

    async def start6(self, host: str = "::", port: int = 0) -> int:
        """Open the additional IPv6 transport (dual-stack NAT-T; eMuleAI's
        live rendezvous runs over IPv6).  RECEIVE goes through asyncio;
        SEND bypasses it: this CPython/Proactor build silently drops
        IPv6 overlapped WSASendTo (WinError 10022), while a plain
        non-blocking socket works — so _send() uses _sock6 for v6."""
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock6.setblocking(False)
        sock6.bind((host, port))
        loop = asyncio.get_running_loop()
        self._transport6, _ = await loop.create_datagram_endpoint(
            lambda: self, sock=sock6
        )
        self._sock6 = sock6
        bound = self._transport6.get_extra_info("sockname")[1]
        log.info("NATT session bound (v6): host=%s, port=%d", host, bound)
        return bound

    def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        for stream in list(self._utp_streams.values()):
            if loop is not None:
                loop.create_task(stream.close())
        self._utp_streams.clear()
        for transport in (self._transport, self._transport6):
            if transport is not None:
                transport.close()
        self._transport = None
        self._transport6 = None
        if self._sock6 is not None:
            self._sock6.close()
            self._sock6 = None

    @property
    def bound_port(self) -> int:
        for transport in (self._transport, self._transport6):
            if transport is not None:
                return transport.get_extra_info("sockname")[1]
        return 0

    @property
    def bound_host(self) -> str:
        if self._transport is None:
            return "0.0.0.0"
        return self._transport.get_extra_info("sockname")[0]

    def _spawn(self, coro) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # -- outbound ------------------------------------------------------------

    def _send(self, data: bytes, addr) -> None:
        if _is_v6(addr[0]) and self._sock6 is not None:
            # IPv6 send bypasses asyncio (Proactor WSASendTo is broken on
            # this build); non-blocking UDP sendto never blocks for long.
            try:
                self._sock6.sendto(data, addr)
            except BlockingIOError:
                pass  # kernel buffer full — datagram dropped, as on wire
            return
        transport = self._transport_for(addr)
        if transport is not None:
            transport.sendto(data, addr)

    def _transport_for(self, addr) -> asyncio.DatagramTransport | None:
        """Pick the transport matching the remote address family."""
        try:
            v6 = ipaddress.ip_address(addr[0]).version == 6
        except (ValueError, TypeError, IndexError):
            v6 = False
        if v6:
            return self._transport6 or self._transport
        return self._transport or self._transport6

    def send_holepunch(self, addr) -> None:
        self._send(build_client_udp_packet(OP_HOLEPUNCH), addr)

    def send_caps(
        self,
        addr,
        *,
        options: int = CONNECT_OPT_NAT_TRAVERSAL_UTP,
        expected_hash: bytes | None = None,
        file_hash: bytes | None = None,
        ack: bool = False,
    ) -> None:
        payload = build_caps_payload(
            options, self.user_hash, expected_hash, file_hash
        )
        frame_op = NATT_FRAME_CAPS_ACK if ack else NATT_FRAME_CAPS
        self._send(
            build_client_udp_packet(UDP_RESERVEDPROT2, bytes((frame_op,)) + payload),
            addr,
        )

    def send_key(self, addr) -> None:
        self._send(
            build_client_udp_packet(
                UDP_RESERVEDPROT2, bytes((NATT_FRAME_KEY,)) + self.user_hash
            ),
            addr,
        )

    def send_endpoint_hint(
        self, addr, target_hash, serving_buddy_id, file_hash,
        target_ip: int, target_port: int, target_options: int,
    ) -> None:
        payload = build_endpoint_hint_payload(
            target_hash, serving_buddy_id, file_hash,
            target_ip, target_port, target_options,
        )
        self._send(build_client_udp_packet(OP_NATT_ENDPOINT_HINT, payload), addr)

    async def burst_holepunch(
        self, addr, *, count: int = 12, sweep: int = 0
    ) -> None:
        """Holepunch burst to the endpoint + port-window sweep
        (ClientUDPSocket.cpp:1957-2015)."""
        for i in range(count):
            self.send_holepunch(addr)
            if i == 5:
                await asyncio.sleep(_BURST_PAUSE)
        for offset in range(1, sweep + 1):
            for port in (addr[1] - offset, addr[1] + offset):
                if 0 < port <= 0xFFFF:
                    self.send_holepunch((addr[0], port))

    async def request_caps(
        self, addr, *, file_hash=None, expected_hash=None, sweep: int = 0
    ) -> None:
        """3 CAPS bursts + port-window sweep (ClientUDPSocket.cpp:523-550).
        We advertise uTP only; never the QUIC bit."""
        for _ in range(_CAPS_BURST):
            self.send_caps(
                addr, file_hash=file_hash, expected_hash=expected_hash
            )
        for offset in range(1, sweep + 1):
            for port in (addr[1] - offset, addr[1] + offset):
                if 0 < port <= 0xFFFF:
                    self.send_caps(
                        (addr[0], port),
                        file_hash=file_hash,
                        expected_hash=expected_hash,
                    )

    # -- expectations ---------------------------------------------------------

    def register_expectation(
        self, ip: str, port: int, *, user_hash=None, file_hash=None, role="download"
    ) -> _Expectation:
        self._prune_expectations()
        exp = _Expectation(ip, port, user_hash, file_hash, role)
        exp.hint_future = asyncio.get_running_loop().create_future()
        exp.caps_future = asyncio.get_running_loop().create_future()
        self._expectations.append(exp)
        if len(self._expectations) > _MAX_EXPECTATIONS:
            self._expectations.pop(0)
        return exp

    def _prune_expectations(self) -> None:
        now = time.monotonic()
        self._expectations = [e for e in self._expectations if e.expires > now]

    def match_expectation(self, ip: str, port: int) -> _Expectation | None:
        for exp in self._expectations:
            if exp.ip == ip and exp.port == port:
                return exp
        if self.port_window:
            for exp in self._expectations:
                if exp.ip == ip and abs(exp.port - port) <= self.port_window:
                    return exp
        return None

    def _match_hint(self, target_hash: bytes, file_hash: bytes) -> _Expectation | None:
        for exp in self._expectations:
            if exp.file_hash == file_hash and (
                exp.user_hash is None or exp.user_hash == target_hash
            ):
                return exp
        return None

    # -- demultiplexer ---------------------------------------------------------

    def datagram_received(self, data: bytes, addr) -> None:
        # Windows IPv6 reports 4-tuples ('::1', port, 0, 0); every lookup
        # key in this session uses (host, port) 2-tuples.
        addr = (addr[0], addr[1])
        parsed = parse_client_udp_packet(data)
        if parsed is None:
            return
        opcode, payload = parsed
        if opcode == OP_HOLEPUNCH:
            self._spawn(self._on_holepunch(addr))
        elif opcode == OP_NATT_ENDPOINT_HINT:
            self._on_endpoint_hint(payload, addr)
        elif opcode == UDP_RESERVEDPROT2:
            self._on_reserved_frame(payload, addr)

    async def _on_holepunch(self, addr) -> None:
        exp = self.match_expectation(addr[0], addr[1])
        if exp is None:
            # Source role: an armed source answers any punch for its file.
            armed = self._source_armed
            if armed:
                self.send_caps(addr, file_hash=next(iter(armed)))
            return
        exp.holepunch_evt.set()
        if exp.role == "source":
            self.send_caps(addr, file_hash=exp.file_hash)

    def _on_endpoint_hint(self, payload: bytes, addr) -> None:
        try:
            hint = parse_endpoint_hint_payload(payload)
        except NattError as exc:
            log.warning("NATT bad endpoint hint from %s: %s", addr, exc)
            return
        exp = self._match_hint(hint["target_hash"], hint["file_hash"])
        if exp is None or exp.hint_future is None or exp.hint_future.done():
            return
        exp.hint_future.set_result(hint)
        log.info(
            "NATT endpoint hint: target=%s:%d, options=0x%02X",
            hint["target_ip"], hint["target_port"], hint["target_options"],
        )

    def _on_reserved_frame(self, payload: bytes, addr) -> None:
        if len(payload) < 1:
            return
        frame_op, body = payload[0], payload[1:]
        if frame_op in (NATT_FRAME_CAPS, NATT_FRAME_CAPS_ACK):
            self._on_caps(body, addr, ack=frame_op == NATT_FRAME_CAPS_ACK)
        elif frame_op == NATT_FRAME_KEY:
            if len(body) >= 16:
                self._peer_hashes[addr] = body[:16]
        elif frame_op == NATT_FRAME_UTP:
            self._on_utp(body, addr)
        elif frame_op == NATT_FRAME_QUIC:
            handler = self._quic_handlers.get(addr)
            if handler is not None:
                handler.datagram_received(body, addr)

    def _on_caps(self, payload: bytes, addr, *, ack: bool) -> None:
        try:
            caps = parse_caps_payload(payload)
        except NattError as exc:
            log.warning("NATT bad CAPS from %s: %s", addr, exc)
            return
        expected = caps["expected_hash"]
        if expected != b"\x00" * 16 and expected != self.user_hash:
            return  # not addressed to us (ClientUDPSocket.cpp:710)
        self._peer_caps[addr] = caps["options"]
        exp = self.match_expectation(addr[0], addr[1])
        if exp is not None and exp.caps_future is not None and not exp.caps_future.done():
            exp.caps_future.set_result(caps["options"])
        if not ack:
            self.send_caps(
                addr,
                file_hash=caps["file_hash"]
                if caps["file_hash"] != b"\x00" * 16
                else None,
                expected_hash=caps["sender_hash"],
                ack=True,
            )

    def _on_utp(self, packet: bytes, addr) -> None:
        if len(packet) < 4:
            return
        (conn_id,) = struct.unpack_from(">H", packet, 2)
        stream = self._utp_streams.get((addr, conn_id))
        if stream is None:
            ptype = packet[0] >> 4
            if ptype == 4 and self.on_inbound_utp is not None:  # ST_SYN
                self._spawn(self._accept_utp(addr, packet))
            return
        stream._on_wire_packet(packet)

    async def _accept_utp(self, addr, syn_packet: bytes) -> None:
        from amuled_v2.core.natt.utp import UtpStream

        def _register(stream) -> None:
            self._utp_streams[(addr, stream.conn_id_recv)] = stream

        stream = await UtpStream.accept(
            self._utp_send_frame, addr, syn_packet, on_created=_register
        )
        self.send_key(addr)
        if self.on_inbound_utp is not None:
            self.on_inbound_utp(stream, addr)

    # -- uTP wiring -------------------------------------------------------------

    async def _utp_send_frame(self, packet: bytes, addr) -> None:
        """Wrap a raw uTP packet in a 0xB2/UTP frame (with a KEY frame
        ahead of the initiating SYN, ClientUDPSocket.cpp:397-407)."""
        if packet and packet[0] >> 4 == 4:  # ST_SYN
            self.send_key(addr)
        self._send(
            build_client_udp_packet(
                UDP_RESERVEDPROT2, bytes((NATT_FRAME_UTP,)) + packet
            ),
            addr,
        )

    def register_quic_handler(self, addr, handler) -> None:
        self._quic_handlers[addr] = handler

    # -- source role -------------------------------------------------------------

    def arm_source(self, file_hash: bytes, *, port: int = 0, ip: str = "") -> None:
        """Firewalled-source role: answer holepunches/CAPS for file_hash and
        accept inbound uTP SYNs (role-based holepunch handling mirrors
        ClientUDPSocket.cpp:2135-2195)."""
        self._source_armed[bytes(file_hash)] = {"ip": ip, "port": port}

    # -- rendezvous requester ------------------------------------------------------

    async def rendezvous_connect(
        self,
        *,
        buddy_host: str,
        buddy_port: int,
        buddy_id: bytes,
        target_user_hash: bytes,
        file_hash: bytes,
        our_ext_ip: int,
        our_ext_udp_port: int | None = None,
        connect_options: int = 3,
        hint_timeout: float = 20.0,
        caps_timeout: float = 10.0,
        sweep: int = 0,
        target_addr: tuple[str, int] | None = None,
    ):
        """Full requester flow; returns a connected UtpStream.

        1) holepunch pre-burst at the target's KAD endpoint, when known
           (BaseClient.cpp:3123-3143);
        2) OP_REASKCALLBACKUDP (rendezvous marker) to the buddy — sent
           with the eMuleAI transport-hint enum UTP=2 and uTP+crypt
           connect options (0x83 | hint 0x20 = 0xA3);
        3) wait OP_NATT_ENDPOINT_HINT (timeout hint_timeout);
        4) holepunch burst to the hinted endpoint;
        5) CAPS exchange (we advertise uTP only);
        6) uTP connect + KEY frame.

        IPv6 targets (direct-punch variant): the buddy's endpoint hint is
        IPv4-only (ClientUDPSocket.cpp:1276 writes a 4-byte address), so
        when the known target endpoint is IPv6 the hint is skipped and
        the holepunch/CAPS go straight to the known endpoint — mirroring
        eMuleAI's live IPv6 rendezvous.
        """
        from amuled_v2.core.kad.direct_callback import (
            NATT_TRANSPORT_UTP,
            REASK_CALLBACK_UDP_OPCODE,
            build_rendezvous_req_payload,
        )
        from amuled_v2.core.natt.utp import UtpStream

        if our_ext_udp_port is None:
            our_ext_udp_port = self.bound_port
        target_v6 = target_addr is not None and _is_v6(target_addr[0])
        if not target_v6:
            exp = self.register_expectation(
                buddy_host,
                buddy_port,
                user_hash=target_user_hash,
                file_hash=bytes(file_hash),
                role="download",
            )
        if target_addr is not None and target_addr[1]:
            await self.burst_holepunch(target_addr, count=6, sweep=sweep)
        # The rendezvous request MUST leave from this session socket: the
        # buddy's OP_HOLEPUNCH / OP_NATT_ENDPOINT_HINT answers are addressed
        # to the sender's endpoint (ClientUDPSocket.cpp:1282, 1290-1292).
        payload = build_rendezvous_req_payload(
            buddy_id,
            self.user_hash,
            connect_options | CONNECT_OPT_NAT_TRAVERSAL_UTP,
            bytes(file_hash),
            our_ext_ip,
            our_ext_udp_port,
            NATT_TRANSPORT_UTP,
        )
        self._send(
            build_client_udp_packet(REASK_CALLBACK_UDP_OPCODE, payload),
            (buddy_host, buddy_port),
        )
        log.info(
            "NATT rendezvous request sent: buddy=%s:%d, file=%s, direct=%s",
            buddy_host, buddy_port, bytes(file_hash).hex(), target_v6,
        )
        if target_v6:
            # Direct-punch variant: no endpoint hint exists for IPv6.
            hint = {
                "target_ip": target_addr[0],
                "target_port": target_addr[1],
                "target_options": CONNECT_OPT_NAT_TRAVERSAL_UTP,
            }
        else:
            # Retry while waiting for the hint (3 attempts, 1 s pause).
            for _ in range(2):
                try:
                    hint = await asyncio.wait_for(
                        asyncio.shield(exp.hint_future), 1.0
                    )
                    break
                except asyncio.TimeoutError:
                    self._send(
                        build_client_udp_packet(
                            REASK_CALLBACK_UDP_OPCODE, payload
                        ),
                        (buddy_host, buddy_port),
                    )
            else:
                hint = await asyncio.wait_for(exp.hint_future, hint_timeout)
        target = (hint["target_ip"], hint["target_port"])

        target_exp = self.register_expectation(
            target[0],
            target[1],
            user_hash=target_user_hash,
            file_hash=bytes(file_hash),
            role="download",
        )
        await self.burst_holepunch(target, sweep=sweep)
        await self.request_caps(
            target,
            file_hash=bytes(file_hash),
            expected_hash=target_user_hash,
            sweep=sweep,
        )
        peer_options = await asyncio.wait_for(
            target_exp.caps_future, caps_timeout
        )
        log.info(
            "NATT caps exchanged: peer=%s:%d, options=0x%02X",
            target[0], target[1], peer_options,
        )
        if not peer_options & CONNECT_OPT_NAT_TRAVERSAL_UTP:
            raise NattError(
                f"peer {target[0]}:{target[1]} does not offer uTP NAT-T "
                f"(options=0x{peer_options:02X})"
            )

        stream = UtpStream(self._utp_send_frame, target, initiator=True)
        self._utp_streams[(target, stream.conn_id_recv)] = stream
        await asyncio.wait_for(stream.connect(), caps_timeout)
        return stream
