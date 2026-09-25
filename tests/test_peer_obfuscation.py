"""Offline tests for BASIC client TCP obfuscation (keystream continuity).

The receiving peer is simulated by :class:`_ReferencePeer`, written from
eMuleAI ``EncryptedStreamSocket.cpp`` (``Receive`` ECS_UNKNOWN path and
``Negotiate`` ``ONS_BASIC_CLIENTA_*``) and ``EMSocket.cpp`` (protocol-byte
check in ``OnReceive``).  It uses its own pure-Python RC4, so it shares no
crypto code with the module under test.

tests/test_peer_obfuscation.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-26

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Reference receiver (handshake, header check, extra-bytes rule).
  [+] HELLO / HELLOANSWER round trip on continued streams.
  [+] Regression: HELLO on a re-created stream is rejected (FIN blocker).
  [+] Split / coalesced response, bad magic, state guards, asyncio loopback.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct

import pytest

from amuled_v2.core.codec import Packet, decode_packet, encode_packet
from amuled_v2.core.peer import (
    build_hello_answer_payload,
    build_hello_payload,
    parse_hello,
    parse_hello_answer,
)
from amuled_v2.core.peer.obfuscation import (
    BasicObfuscationSession,
    ObfuscationError,
    Rc4Stream,
    build_basic_client_request,
    negotiate_basic_client,
)


_PEER_HASH = bytes.fromhex("F2D85A45870E3593A8AB83EB8BA36F30")  # receiver userhash
_OUR_HASH = bytes(range(16))
_KEY_PART = 0x1234ABCD
_MAGIC = 0x835E6FC4
_VALID_PROTOCOLS = (0xE3, 0xC5, 0xD4)  # OP_EDONKEYPROT / OP_EMULEPROT / OP_PACKEDPROT
_OP_HELLO = 0x01
_OP_HELLOANSWER = 0x4C


class _PureRc4:
    """Textbook RC4 with eMule's 1024-byte drop (RC4CreateKey, bSkipDiscard=false)."""

    def __init__(self, key: bytes, drop: int = 1024) -> None:
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self._s, self._i, self._j = s, 0, 0
        self.crypt(bytes(drop))

    def crypt(self, data: bytes) -> bytes:
        s, i, j = self._s, self._i, self._j
        out = bytearray(len(data))
        for n, byte in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[n] = byte ^ s[(s[i] + s[j]) & 0xFF]
        self._i, self._j = i, j
        return bytes(out)


class _PeerDisconnect(Exception):
    """The reference peer would call OnError()/Disconnect() here."""


class _ReferencePeer:
    """Accepting side of a BASIC-obfuscated connection (eMule/eMuleAI logic)."""

    def __init__(self, own_hash: bytes, response_padding: bytes = b"") -> None:
        self._own_hash = own_hash
        self._response_padding = response_padding
        self._send: _PureRc4 | None = None
        self._recv: _PureRc4 | None = None

    def accept(self, first_read: bytes) -> bytes:
        """Process the first recv() of an incoming connection; return the response."""
        if first_read[0] in _VALID_PROTOCOLS:
            raise _PeerDisconnect("plain header on an obfuscated test")
        key_part = first_read[1:5]
        # ONS_BASIC_CLIENTA_RANDOMPART (EncryptedStreamSocket.cpp:533-551)
        material = bytearray(self._own_hash + b"\x00" + key_part)
        material[16] = 34
        self._recv = _PureRc4(hashlib.md5(material).digest())
        material[16] = 203
        self._send = _PureRc4(hashlib.md5(material).digest())
        # ONS_BASIC_CLIENTA_MAGICVALUE (:552-565)
        (magic,) = struct.unpack("<I", self._recv.crypt(first_read[5:9]))
        if magic != _MAGIC:
            raise _PeerDisconnect("wrong magic value (ERR_ENCRYPTION)")
        # ONS_BASIC_CLIENTA_METHODTAGSPADLEN / PADDING (:566-598)
        methods = self._recv.crypt(first_read[9:12])
        pad_len = methods[2]
        self._recv.crypt(first_read[12 : 12 + pad_len])
        if len(first_read) != 12 + pad_len:
            # Receive() ECS_UNKNOWN (:311-318): the response is already sent,
            # then "sent more data then expected while negotiating (1)".
            raise _PeerDisconnect("more data then expected while negotiating (1)")
        response = (
            struct.pack("<I", _MAGIC)
            + bytes((0x00, len(self._response_padding)))
            + self._response_padding
        )
        return self._send.crypt(response)

    def receive(self, data: bytes) -> bytes:
        """ECS_ENCRYPTING receive + CEMSocket::OnReceive protocol check."""
        assert self._recv is not None
        plain = self._recv.crypt(data)
        if plain[0] not in _VALID_PROTOCOLS:
            raise _PeerDisconnect(f"ERR_WRONGHEADER (first byte 0x{plain[0]:02X})")
        return plain

    def send(self, data: bytes) -> bytes:
        assert self._send is not None
        return self._send.crypt(data)


def _hello_frame() -> bytes:
    payload = build_hello_payload(
        user_hash=_OUR_HASH, client_id=0x01020304, client_port=4662, nickname="tester"
    )
    return encode_packet(Packet(protocol=0xE3, opcode=_OP_HELLO, payload=payload))


def _hello_answer_frame() -> bytes:
    payload = build_hello_answer_payload(
        user_hash=_PEER_HASH,
        client_id=0x05060708,
        client_port=31687,
        nickname="peer",
        server_ip=0,
        server_port=0,
    )
    return encode_packet(Packet(protocol=0xE3, opcode=_OP_HELLOANSWER, payload=payload))


def _handshake(
    padding: bytes = b"\xAA\xBB\xCC", response_padding: bytes = b"\x11" * 5
) -> tuple[BasicObfuscationSession, _ReferencePeer]:
    session = BasicObfuscationSession(_PEER_HASH, random_key_part=_KEY_PART, padding=padding)
    peer = _ReferencePeer(_PEER_HASH, response_padding=response_padding)
    response = peer.accept(session.build_request())
    assert session.feed_response(response) == b""
    assert session.is_established
    return session, peer


def test_pure_rc4_matches_module_stream() -> None:
    key = hashlib.md5(b"amuled").digest()
    data = bytes(range(256)) * 3
    assert _PureRc4(key).crypt(data) == Rc4Stream(key).crypt(data)


def test_request_layout_and_offsets() -> None:
    session = BasicObfuscationSession(
        _PEER_HASH, random_key_part=_KEY_PART, padding=b"\x00" * 9
    )
    request = session.build_request()
    assert request[0] not in _VALID_PROTOCOLS
    assert struct.unpack_from("<I", request, 1)[0] == _KEY_PART
    assert len(request) == 5 + 4 + 3 + 9
    assert session.send_offset == 7 + 9  # magic + 2 methods + padlen + pad


def test_hello_reaches_peer_on_continued_stream() -> None:
    session, peer = _handshake()
    frame = _hello_frame()
    plain = peer.receive(session.encrypt(frame))
    assert plain == frame
    packet, rest = decode_packet(plain)
    assert rest == b""
    assert (packet.protocol, packet.opcode) == (0xE3, _OP_HELLO)
    assert parse_hello(packet.payload).user_hash == _OUR_HASH


def test_hello_answer_decrypts_on_continued_recv_stream() -> None:
    session, peer = _handshake()
    peer.receive(session.encrypt(_hello_frame()))
    answer = _hello_answer_frame()
    packet, _ = decode_packet(session.decrypt(peer.send(answer)))
    assert packet.opcode == _OP_HELLOANSWER
    assert parse_hello_answer(packet.payload).user_hash == _PEER_HASH


def test_hello_on_recreated_stream_is_rejected() -> None:
    """Regression for the post-handshake FIN: re-dropping 1024 bytes for HELLO."""
    session, peer = _handshake()
    restarted = Rc4Stream(session.keys.send_key, drop=session.keys.send_pad_len)
    with pytest.raises(_PeerDisconnect, match="ERR_WRONGHEADER"):
        peer.receive(restarted.crypt(_hello_frame()))


def test_legacy_request_builder_still_accepted() -> None:
    request, keys, key_part = build_basic_client_request(
        _PEER_HASH, random_key_part=_KEY_PART, padding=b"\x01\x02"
    )
    assert key_part == _KEY_PART
    assert keys.send_pad_len == 1024
    _ReferencePeer(_PEER_HASH).accept(request)


def test_hello_pipelined_with_request_is_rejected() -> None:
    session = BasicObfuscationSession(_PEER_HASH, random_key_part=_KEY_PART, padding=b"")
    request = session.build_request()
    with pytest.raises(ObfuscationError):
        session.encrypt(_hello_frame())  # guard: not established yet
    with pytest.raises(_PeerDisconnect, match=r"\(1\)"):
        _ReferencePeer(_PEER_HASH).accept(request + b"\xE3" * 10)


def test_response_fed_byte_by_byte() -> None:
    session = BasicObfuscationSession(_PEER_HASH, random_key_part=_KEY_PART, padding=b"\x07")
    peer = _ReferencePeer(_PEER_HASH, response_padding=bytes(200))
    response = peer.accept(session.build_request())
    results = [session.feed_response(response[i : i + 1]) for i in range(len(response))]
    assert results[:-1] == [None] * (len(response) - 1)
    assert results[-1] == b""
    assert session.recv_offset == 6 + 200
    assert peer.receive(session.encrypt(_hello_frame())) == _hello_frame()


def test_response_with_trailing_payload_returns_leftover() -> None:
    session = BasicObfuscationSession(_PEER_HASH, random_key_part=_KEY_PART, padding=b"")
    peer = _ReferencePeer(_PEER_HASH, response_padding=b"\x22" * 3)
    response = peer.accept(session.build_request())
    answer = _hello_answer_frame()
    leftover = session.feed_response(response + peer.send(answer))
    assert leftover == answer
    assert session.decrypt(peer.send(answer)) == answer  # stream keeps going


def test_wrong_magic_fails_session() -> None:
    session = BasicObfuscationSession(_PEER_HASH, random_key_part=_KEY_PART)
    session.build_request()
    with pytest.raises(ObfuscationError, match="wrong magic"):
        session.feed_response(b"\x00" * 6)
    assert session.state == "failed"
    with pytest.raises(ObfuscationError):
        session.encrypt(b"x")


def test_build_request_only_once() -> None:
    session = BasicObfuscationSession(_PEER_HASH)
    session.build_request()
    with pytest.raises(ObfuscationError):
        session.build_request()


def test_negotiate_basic_client_over_loopback() -> None:
    async def scenario() -> tuple[bytes, bytes]:
        received: dict[str, bytes] = {}

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = _ReferencePeer(_PEER_HASH, response_padding=b"\x33" * 17)
            first = await reader.read(4096)
            writer.write(peer.accept(first))
            await writer.drain()
            frame = _hello_frame()
            data = await reader.readexactly(len(frame))
            received["hello"] = peer.receive(data)
            writer.write(peer.send(_hello_answer_frame()))
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            session, leftover = await negotiate_basic_client(
                reader, writer, _PEER_HASH, timeout=5.0
            )
            assert leftover == b""
            writer.write(session.encrypt(_hello_frame()))
            await writer.drain()
            answer = session.decrypt(await reader.readexactly(len(_hello_answer_frame())))
            writer.close()
            await writer.wait_closed()
        return received["hello"], answer

    hello, answer = asyncio.run(scenario())
    assert hello == _hello_frame()
    assert decode_packet(answer)[0].opcode == _OP_HELLOANSWER
