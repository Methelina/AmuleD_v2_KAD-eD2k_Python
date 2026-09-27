"""Offline loopback tests for the source-exchange responder (stage X).

Wire layout oracle: KnownFile.cpp CKnownFile::CreateSrcInfoPacket,
PartFile.cpp CPartFile::CreateSrcInfoPacket / AddClientSources,
ListenSocket.cpp ProcessExtPacket (OP_REQUESTSOURCES2 = version u8 +
options u16 + hash16; gate ``byRequestedVersion > 0 || SX1ver > 1``).

tests/test_source_exchange.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import struct

from amuled_v2.core.codec.constants import EDONKEY, EMULE
from amuled_v2.core.peer.client import C2CEMULE, build_emuleinfo_payload
from amuled_v2.core.peer.codec import (
    C2CTCP,
    SXSource,
    build_hello_payload,
    build_request_sources2_payload,
    parse_answer_sources2,
    parse_answer_sources,
)
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.upload.queue import UploadQueue

_LOCAL_HASH = bytes.fromhex("E" * 32)
_IO_TIMEOUT = 30.0

_FILE_HASH = bytes.fromhex("F" * 32)
_SOURCES = [
    SXSource(
        client_id=(80 << 24) | (1 << 16) | (2 << 8) | 3,  # 80.1.2.3
        port=4662,
        user_hash=bytes.fromhex("1" * 32),
    ),
    SXSource(
        client_id=(81 << 24) | (4 << 16) | (5 << 8) | 6,  # 81.4.5.6
        port=4711,
        user_hash=bytes.fromhex("2" * 32),
        connect_options=0x08,
    ),
]


class _EmptyResolver:
    def resolve(self, file_hash):
        return None


def _identity() -> LocalIdentity:
    return LocalIdentity(
        user_hash=_LOCAL_HASH,
        client_id=0x10203040,
        tcp_port=0,
        nickname="AmuleD-SX",
    )


def _run(coro) -> None:
    asyncio.run(coro)


async def _send(writer, opcode, payload, protocol=EDONKEY) -> None:
    writer.write(
        bytes([protocol]) + struct.pack("<I", len(payload) + 1)
        + bytes([opcode]) + payload
    )
    await writer.drain()


async def _recv(reader) -> tuple[int, int, bytes]:
    header = await asyncio.wait_for(reader.readexactly(6), _IO_TIMEOUT)
    (length,) = struct.unpack("<I", header[1:5])
    payload = (
        await asyncio.wait_for(reader.readexactly(length - 1), _IO_TIMEOUT)
        if length > 1 else b""
    )
    return header[0], header[5], payload


async def _handshake(reader, writer) -> None:
    await _send(
        writer, C2CTCP.HELLO,
        build_hello_payload(user_hash=bytes.fromhex("D" * 32),
                            client_id=0x0A0B0C0D, client_port=0,
                            nickname="sx-peer"),
    )
    protocol, opcode, _ = await _recv(reader)
    assert protocol == EDONKEY and opcode == C2CTCP.HELLOANSWER
    await _send(writer, C2CEMULE.EMULEINFO,
                build_emuleinfo_payload(), protocol=EMULE)
    protocol, opcode, _ = await _recv(reader)
    assert protocol == EMULE and opcode == C2CEMULE.EMULEINFOANSWER


def test_answer_sources2_wire_loopback(tmp_path) -> None:
    async def scenario() -> None:
        provided: list[bytes] = []

        def provider(file_hash: bytes):
            provided.append(file_hash)
            return list(_SOURCES)

        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
            source_provider=provider,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            try:
                await _handshake(reader, writer)
                await _send(
                    writer, C2CEMULE.REQUESTSOURCES2,
                    build_request_sources2_payload(4, 0, _FILE_HASH),
                    protocol=EMULE,
                )
                protocol, opcode, payload = await _recv(reader)
                assert protocol == EMULE
                assert opcode == C2CEMULE.ANSWERSOURCES2
                version, file_hash, entries = parse_answer_sources2(payload)
                assert version == 4
                assert file_hash == _FILE_HASH
                assert provided == [_FILE_HASH]
                assert len(entries) == 2
                first, second = entries
                assert first.client_id == _SOURCES[0].client_id
                assert first.port == 4662
                assert first.user_hash == bytes.fromhex("1" * 32)
                # SX2 v3+ high-id id travels in dotted byte order.
                assert struct.pack(">I", first.client_id) == struct.pack(
                    ">I", (80 << 24) | (1 << 16) | (2 << 8) | 3
                )
                assert second.connect_options == 0x08
            finally:
                writer.close()
        finally:
            await server.close()

    _run(scenario())


def test_legacy_request_gated_by_sx1_version(tmp_path) -> None:
    """Our own hello advertises SX1 version 1, so a legacy OP_REQUESTSOURCES
    must NOT be answered (gate: SX1ver > 1, ListenSocket.cpp:2289)."""

    async def scenario() -> None:
        calls: list[bytes] = []

        def provider(file_hash: bytes):
            calls.append(file_hash)
            return list(_SOURCES)

        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
            source_provider=provider,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            try:
                await _handshake(reader, writer)
                await _send(writer, C2CEMULE.REQUESTSOURCES, _FILE_HASH,
                            protocol=EMULE)
                # The listener must stay silent: waiting for the NEXT packet
                # times out rather than delivering an answer.
                with __import__("pytest").raises(asyncio.TimeoutError):
                    await asyncio.wait_for(_recv(reader), timeout=2.0)
                assert calls == []
            finally:
                writer.close()
        finally:
            await server.close()

    _run(scenario())


def test_answer_sources_codec_versions() -> None:
    from amuled_v2.core.peer.codec import build_answer_sources

    for version in (1, 2, 3, 4):
        payload = build_answer_sources(_FILE_HASH, list(_SOURCES), version)
        parsed_version, file_hash, entries = parse_answer_sources(
            payload, version
        )
        assert file_hash == _FILE_HASH
        assert len(entries) == 2
        assert entries[0].client_id == _SOURCES[0].client_id
        assert entries[0].port == _SOURCES[0].port
        if version >= 2:
            assert entries[0].user_hash == _SOURCES[0].user_hash
        else:
            assert entries[0].user_hash is None
        if version >= 4:
            assert entries[1].connect_options == 0x08


def test_request_sources_client_loopback(tmp_path) -> None:
    """PeerClient.request_sources against the live SX responder: the client
    sends OP_REQUESTSOURCES2 (peer miso2 bit 10 advertised by our own
    HELLOANSWER tags) and the ANSWERSOURCES2 entries land in
    client.collected_sources."""

    async def scenario() -> None:
        def provider(file_hash: bytes):
            return list(_SOURCES)

        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
            source_provider=provider,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            from amuled_v2.core.peer.client import PeerClient

            client = PeerClient.adopt_connection(
                reader,
                writer,
                local_userhash=bytes.fromhex("D" * 32),
                nickname="sx-client",
            )
            try:
                await client.handshake()
                assert client.peer_tags, "peer tags must be learned"
                await client.request_sources(_FILE_HASH)
                # Read the answer through the session receive path and
                # collect it exactly as the wait/transfer loops do.
                packet = await client._receive(timeout=5.0)
                assert packet is not None
                protocol, opcode, payload = packet
                assert client._collect_answer_sources(protocol, opcode, payload)
                first = client.collected_sources[0]
                assert first.client_id == _SOURCES[0].client_id
                assert first.port == 4662
                assert first.user_hash == bytes.fromhex("1" * 32)
            finally:
                await client.close()
        finally:
            await server.close()

    _run(scenario())
