"""Customer side of the KAD serving-buddy protocol (firewalled client).

The firewalled client asks a KAD node to act as its buddy over UDP
(KADEMLIA_FINDSERVINGBUDDY_REQ 0x51 / RES 0x5A), then TCP-connects to the
accepted buddy and registers with a plain eD2K HELLO whose tags carry
CT_EMULE_SERVINGBUDDYID / IP / UDP (BaseClient.cpp:1991-2013).  The buddy
relays KADEMLIA_CALLBACK_REQ as a TCP OP_CALLBACK (0x99, protocol 0xC5)
which the customer dials back.

Wire formats (oracle: tmp/recon/emuleai-buddy-udp.recon.md sections 4-6;
serving side: amuled_v2/core/kad/buddy.py):

- REQ 0x51 payload: [ServedBuddyID 16 = xor(own_kad_id)][userhash 16]
  [tcp_port u16 LE][connect_opts u8] — full UDP packet = bytes((0xE4,0x51))
  + payload (0xE4 = KAD UDP protocol prefix).
- RES 0x5A payload: [ServedBuddyID-XOR 16][buddyHash 16][buddyTCPport u16 LE]
  [connectOpts u8?].  Echo of xor(own_kad_id) proves the responder.
- Buddy TCP HELLO: protocol 0xE3 (EDONKEY), opcode 0x01 (OP_HELLO), framing
  [0xE3][len u32 LE = payload+1][0x01][payload]; payload tags carry
  CT_EMULE_SERVINGBUDDYID=0xBF (HASH, raw KadID), 0xFC (IP, u32 LE of buddy
  IPv4), 0xFD (UDP port, u32, 0 here — not known to the customer).
- Relay OP_CALLBACK (0x99, protocol 0xC5): [kad_id_xor 16][file_hash 16]
  [requester_ip u32 LE][requester_port u16 LE] (38 bytes); customer dials
  (requester_ip, requester_port).

src/amuled_v2/core/kad/buddy_customer.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.1.1 (Soror L'.L'.):
  [+] FIX _read_frame: the opcode is byte 6 of the frame (after the
      proto+len header), not hdr[4] (the len high byte) — HELLOANSWER
      detection and OP_CALLBACK parsing were off by one.
  [+] FIX OP_CALLBACK requester_port offset: 36, not 34 (port follows
      the full 4-byte IP field; 34 read the IP high bytes as the port).
  [+] FIX requester IP decode: inet_ntoa over big-endian serialization
      of the host-order integer ("127.0.0.1", not "1.0.0.127").

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Firewalled-side buddy protocol: 0x51 REQ builder, 0x5A RES parser,
    HELLO registration over TCP, OP_CALLBACK (0x99) relay consumer.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import types
from typing import Awaitable, Callable

from amuled_v2.core.codec.constants import EDONKEY, HASH16, UINT32
from amuled_v2.core.peer.codec import C2CTCP, build_hello_payload
from amuled_v2.logging_setup import LogTags, get_tagged_logger

from amuled_v2.core.kad.buddy import xor_mask

log = get_tagged_logger(LogTags.KAD, "core.kad.buddy_customer")

__all__ = [
    "KADEMLIA_FINDSERVINGBUDDY_REQ",
    "KADEMLIA_FINDSERVINGBUDDY_RES",
    "OP_CALLBACK",
    "_TAG_SERVINGBUDDYID",
    "_TAG_SERVINGBUDDYIP",
    "_TAG_SERVINGBUDDYUDP",
    "BuddyCustomer",
]

KADEMLIA_FINDSERVINGBUDDY_REQ = 0x51
KADEMLIA_FINDSERVINGBUDDY_RES = 0x5A
OP_CALLBACK = 0x99
_TAG_SERVINGBUDDYID = 0xBF
_TAG_SERVINGBUDDYIP = 0xFC
_TAG_SERVINGBUDDYUDP = 0xFD

# OP_CALLBACK rides the eMule protocol discriminator 0xC5 (recon section 6).
_KAD_CALLBACK_PROTOCOL = 0xC5


class BuddyCustomer:
    """Firewalled client side of the KAD buddy protocol.

    Builds the 0x51 UDP request, validates the 0x5A acceptance, performs the
    TCP HELLO registration, and consumes the OP_CALLBACK relay to dial back the
    original requester.
    """

    def __init__(
        self,
        own_kad_id: bytes,
        own_userhash: bytes,
        own_tcp_port: int,
        dial_back,
    ) -> None:
        """dial_back: async callable (ip: str, port: int) -> None, invoked when
        the buddy relays an OP_CALLBACK; it must open the TCP connection to the
        requester."""
        self.own_kad_id = bytes(own_kad_id)         # 16 bytes
        self.own_userhash = bytes(own_userhash)     # 16 bytes
        self.own_tcp_port = int(own_tcp_port)
        self.dial_back = dial_back
        self.buddy_ip: str | None = None            # set on accepted 0x5A
        self.buddy_tcp_port: int = 0
        self.buddy_hash: bytes | None = None

    # ---------------------------------------------------------------------------
    # UDP REQ/RES (tmp/recon/emuleai-buddy-udp.recon.md:4,5; buddy.py:62-119).
    # ---------------------------------------------------------------------------
    def build_find_serving_buddy_req(self) -> bytes:
        """Full UDP packet: bytes((0xE4, 0x51)) + payload with XOR-form ID,
        our userhash, our TCP port, connect_opts 0x83."""
        xor_id = xor_mask(self.own_kad_id)
        payload = (
            xor_id
            + self.own_userhash
            + struct.pack("<H", self.own_tcp_port & 0xFFFF)
            + bytes((0x83,))
        )
        return bytes((0xE4, KADEMLIA_FINDSERVINGBUDDY_REQ)) + payload

    def on_res(self, payload: bytes, buddy_ip: str) -> bool:
        """Parse a 0x5A RES (34 or 35 bytes).  Accept only when the echoed
        XOR-form matches xor_mask(self.own_kad_id).  On success store
        buddy_ip/buddy_tcp_port/buddy_hash and return True."""
        if len(payload) < 34:
            log.debug(
                "KAD 0x5A REJ: payload too short, len=%d, buddy=%s",
                len(payload), buddy_ip,
            )
            return False
        echoed_xor = bytes(payload[0:16])
        expected = xor_mask(self.own_kad_id)
        if echoed_xor != expected:
            log.warning(
                "KAD 0x5A identity mismatch: echoed=%s, expected=%s, buddy=%s",
                echoed_xor.hex().upper(),
                expected.hex().upper(),
                buddy_ip,
            )
            return False
        self.buddy_hash = bytes(payload[16:32])
        (self.buddy_tcp_port,) = struct.unpack_from("<H", payload, 32)
        self.buddy_ip = buddy_ip
        log.info(
            "KAD 0x5A accepted: buddy=%s:%d, hash=%s",
            buddy_ip, self.buddy_tcp_port,
            self.buddy_hash.hex().upper(),
        )
        return True

    # ---------------------------------------------------------------------------
    # HELLO extra-tags (recon section 6; BaseClient.cpp:1991-2013).
    # ---------------------------------------------------------------------------
    def _build_hello_extra_tags(self) -> tuple:
        """Three simple namespace tags (``name=None, name_id, type, value``)
        for the registration HELLO:

        - 0xBF SERVINGBUDDYID: HASH-type, raw 16-byte own KadID.
        - 0xFC SERVINGBUDDYIP: UINT32, buddy IPv4 host-order as uint32
          computed from buddy_ip octets ``(a<<24)|(b<<16)|(c<<8)|d``.
        - 0xFD SERVINGBUDDYUDP: UINT32, 0 — the customer does not know the
          buddy's UDP port at registration time.
        """
        ip_val = 0
        if self.buddy_ip is not None:
            octets = self.buddy_ip.split(".")
            if len(octets) == 4:
                a, b, c, d = (int(x) & 0xFF for x in octets)
                ip_val = (a << 24) | (b << 16) | (c << 8) | d
        return (
            types.SimpleNamespace(
                name=None, name_id=_TAG_SERVINGBUDDYID, type=HASH16,
                value=bytes(self.own_kad_id),
            ),
            types.SimpleNamespace(
                name=None, name_id=_TAG_SERVINGBUDDYIP, type=UINT32,
                value=ip_val,
            ),
            types.SimpleNamespace(
                name=None, name_id=_TAG_SERVINGBUDDYUDP, type=UINT32,
                value=0,
            ),
        )

    def _build_registration_hello(self) -> bytes:
        """Frame the registration HELLO:
        ``[0xE3][len u32 LE = payload+1][0x01][payload]``.

        ``build_hello_payload(user_hash=self.own_userhash, client_id=1,
        client_port=self.own_tcp_port, nickname='AmuleD',
        extra_tags=(...))`` produces the payload (codec.py:348).
        """
        payload = build_hello_payload(
            user_hash=self.own_userhash,
            client_id=1,
            client_port=self.own_tcp_port,
            nickname="AmuleD",
            extra_tags=self._build_hello_extra_tags(),
        )
        frame = bytes((EDONKEY,))
        frame += struct.pack("<I", len(payload) + 1)
        frame += bytes((C2CTCP.HELLO,))
        frame += payload
        return frame

    # ---------------------------------------------------------------------------
    # TCP run loop / OP_CALLBACK consumption (recon section 6: relay payload).
    # ---------------------------------------------------------------------------
    async def _read_frame(
        self,
        reader: asyncio.StreamReader,
        idle_timeout: float,
    ) -> bytes | None:
        """Read one eDonkey TCP frame: [protocol u8][len u32 LE][opcode u8][body].

        Returns ``opcode + body`` or ``None`` when the peer disconnects or
        the idle timeout elapses mid-frame.  NOTE: the opcode is the byte
        AFTER the 5-byte (proto+len) header and is included in ``len``.
        """
        try:
            hdr = await asyncio.wait_for(
                reader.readexactly(6), timeout=idle_timeout,
            )
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        (length,) = struct.unpack_from("<I", hdr, 1)
        opcode = hdr[5]
        if length <= 1:
            body = b""
        else:
            try:
                body = await asyncio.wait_for(
                    reader.readexactly(length - 1), timeout=idle_timeout,
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return None
        return bytes((opcode,)) + body

    async def run_registration(
        self,
        connect: Callable[
            [str, int],
            Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
        ],
        stop: asyncio.Event,
        idle_timeout: float = 300.0,
    ) -> None:
        """TCP-connect to (buddy_ip, buddy_tcp_port) via `connect`, send the
        registration HELLO (protocol 0xE3, opcode 0x01, framing
        [0xE3][len u32 LE = len(payload)+1][0x01][payload]; payload built with
        build_hello_payload(user_hash=self.own_userhash, client_id=1,
        client_port=self.own_tcp_port, nickname='AmuleD', extra_tags=(...)))
        where extra_tags are three simple namespace objects with attributes
        name=None, name_id (0xFC/0xFD/0xBF), type, value — 0xFC value = int
        LE-encodable IPv4 of the buddy as uint32 host-order (compute from
        buddy_ip octets (a<<24)|...), 0xFD value = int buddy UDP port is NOT
        known here — use 0 for it — and 0xBF value = self.own_kad_id bytes.
        Wait for the HELLOANSWER (opcode 0x4C), consume its payload for
        framing, then loop reading packets until `stop` is set, the peer
        disconnects, or idle_timeout elapses: on OP_CALLBACK (0x99,
        protocol 0xC5) parse the 38-byte payload and
        `await self.dial_back(requester_ip_str, requester_port)`.
        Any other opcode: ignore.  On exit: self.buddy_ip = None."""
        if self.buddy_ip is None or self.buddy_tcp_port == 0:
            log.warning(
                "KAD buddy registration skipped: no buddy assigned, "
                "buddy_ip=%s, buddy_tcp_port=%d",
                self.buddy_ip, self.buddy_tcp_port,
            )
            return
        try:
            reader, writer = await connect(self.buddy_ip, self.buddy_tcp_port)
        except OSError as exc:
            log.error(
                "KAD buddy TCP connect failed: buddy=%s:%d, error=%s",
                self.buddy_ip, self.buddy_tcp_port, exc,
            )
            self.buddy_ip = None
            return
        try:
            hello = self._build_registration_hello()
            writer.write(hello)
            await writer.drain()
            log.info(
                "KAD buddy HELLO sent: buddy=%s:%d, kad_id=%s, bytes=%d",
                self.buddy_ip, self.buddy_tcp_port,
                self.own_kad_id.hex().upper(), len(hello),
            )
            answer = await asyncio.wait_for(
                self._read_frame(reader, idle_timeout),
                timeout=idle_timeout,
            )
            if answer is None:
                log.warning("KAD buddy HELLOANSWER not received; peer closed")
                return
            if not answer or answer[0] != C2CTCP.HELLOANSWER:
                log.warning(
                    "KAD buddy unexpected HELLOANSWER opcode=%#04x",
                    answer[0] if answer else 0,
                )
                return
            log.debug(
                "KAD buddy HELLOANSWER consumed: %d bytes", len(answer),
            )
            await self._relay_loop(reader, stop, idle_timeout)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            self.buddy_ip = None
            log.debug("KAD buddy customer session ended")

    async def _relay_loop(
        self,
        reader: asyncio.StreamReader,
        stop: asyncio.Event,
        idle_timeout: float,
    ) -> None:
        """Consume OP_CALLBACK relays until ``stop``, idle timeout, or peer
        disconnect.  OP_CALLBACK payload layout (recon section 6,
        build_op_callback_payload in buddy.py:122):

        ``[kad_id_xor 16][file_hash 16][requester_ip u32 LE][requester_port
        u16 LE]`` — 38 bytes total; the requester IP is the host-order
        IPv4 serialized little-endian (buddy.py:131)."""
        while not stop.is_set():
            try:
                frame = await asyncio.wait_for(
                    self._read_frame(reader, idle_timeout),
                    timeout=idle_timeout,
                )
            except asyncio.TimeoutError:
                log.debug("KAD buddy idle timeout; exiting relay loop")
                return
            if frame is None:
                log.debug("KAD buddy peer disconnected; exiting relay loop")
                return
            opcode = frame[0]
            if opcode == OP_CALLBACK:
                body = frame[1:]
                # 38-byte payload: 16 (kad_id_xor) + 16 (file_hash) + 4 (ip) + 2 (port).
                if len(body) < 36:
                    log.warning(
                        "KAD OP_CALLBACK payload short: len=%d", len(body),
                    )
                    continue
                kad_id_xor = bytes(body[0:16])
                file_hash = bytes(body[16:32])
                (requester_ip,) = struct.unpack_from("<I", body, 32)
                (requester_port,) = struct.unpack_from("<H", body, 36)
                # IP was stored host-order by the buddy (buddy.py:131 packs
                # host-order octets into a LE uint32); the dotted quad is
                # the big-endian serialization of that integer.
                requester_ip_str = socket.inet_ntoa(
                    requester_ip.to_bytes(4, "big")
                )
                log.info(
                    "KAD OP_CALLBACK relayed: file=%s, requester=%s:%d",
                    file_hash.hex().upper(),
                    requester_ip_str, requester_port,
                )
                try:
                    await self.dial_back(requester_ip_str, requester_port)
                except Exception as exc:
                    log.error(
                        "KAD dial_back failed: requester=%s:%d, error=%s",
                        requester_ip_str, requester_port, exc,
                    )
            else:
                log.debug("KAD buddy relay ignored opcode=%#04x", opcode)
