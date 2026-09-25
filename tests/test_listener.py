"""Offline loopback tests for the incoming peer listener (stage D).

These tests verify INTERNAL consistency between the raw framed client side
and the upload engine over real TCP loopback (127.0.0.1, ephemeral ports).
They are NOT a live acceptance test against a real eMule client: the
encrypted transport is pending external work (see ``WIP by external
developer`` markers in core/peer/listener.py).

tests/test_listener.py
Author:      Soror L.'.L.'.
Updated:     2026-09-24
"""

from __future__ import annotations

import asyncio
import os
import struct

from amuled_v2.core.codec.constants import EDONKEY, EMULE
from amuled_v2.core.hashes.ed2k import ed2k_hash_file
from amuled_v2.core.peer.client import C2CEMULE, build_emuleinfo_payload
from amuled_v2.core.peer.codec import (
    C2CTCP,
    build_hello_payload,
    parse_filename_answer,
    parse_hello_answer,
    parse_queue_rank,
    parse_sending_part,
)
from amuled_v2.core.peer.listener import (
    IncomingPeerServer,
    LocalIdentity,
)
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.queue import UploadQueue

_LOCAL_HASH = bytes.fromhex("A" * 32)
_LOCAL_ID = 0x11223344
_NICK = "AmuleD"


class _FakeResolver:
    def __init__(self, mapping: dict[bytes, SharedFile]) -> None:
        self._mapping = mapping

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return self._mapping.get(file_hash)


def _make_shared_file(tmp_path, size: int = 200_000) -> SharedFile:
    path = tmp_path / "sample.bin"
    data = os.urandom(size)
    path.write_bytes(data)
    result = ed2k_hash_file(str(path))
    return SharedFile(
        file_hash=result.file_hash,
        name=path.name,
        size=result.file_size,
        path=str(path),
        hash_result=result,
    )


def _identity(port: int) -> LocalIdentity:
    return LocalIdentity(
        user_hash=_LOCAL_HASH,
        client_id=_LOCAL_ID,
        tcp_port=port,
        nickname=_NICK,
    )


_IO_TIMEOUT = 30.0


async def _send(
    writer: asyncio.StreamWriter,
    opcode: int,
    payload: bytes,
    protocol: int = EDONKEY,
) -> None:
    writer.write(
        bytes([protocol])
        + struct.pack("<I", len(payload) + 1)
        + bytes([opcode])
        + payload
    )
    await writer.drain()


async def _recv(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    # Every blocking read is bounded: a protocol mismatch must fail the
    # test, never hang it (a hung asyncio.run leaks the whole process).
    header = await asyncio.wait_for(reader.readexactly(6), _IO_TIMEOUT)
    assert header[0] in (EDONKEY, EMULE)
    (length,) = struct.unpack("<I", header[1:5])
    payload = (
        await asyncio.wait_for(reader.readexactly(length - 1), _IO_TIMEOUT)
        if length > 1
        else b""
    )
    return header[5], payload


def _run(coro) -> None:
    asyncio.run(coro)


async def _start_server(tmp_path, queue: UploadQueue, size: int = 200_000):
    shared = _make_shared_file(tmp_path, size)
    resolver = _FakeResolver({shared.file_hash: shared})
    server = IncomingPeerServer(
        identity=_identity(0),
        resolver=resolver,
        upload_queue=queue,
        host="127.0.0.1",
        port=0,
        idle_timeout=15.0,
    )
    await server.start()
    return server, shared


def test_hello_handshake(tmp_path) -> None:
    async def scenario() -> None:
        server, _ = await _start_server(tmp_path, UploadQueue())
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            await _send(
                writer,
                C2CTCP.HELLO,
                build_hello_payload(
                    user_hash=bytes.fromhex("B" * 32),
                    client_id=1,
                    client_port=4662,
                    nickname="peer",
                ),
            )
            opcode, payload = await _recv(reader)
            assert opcode == C2CTCP.HELLOANSWER
            answer = parse_hello_answer(payload)
            assert answer.user_hash == _LOCAL_HASH
            assert answer.nickname == _NICK
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        finally:
            await server.close()

    _run(scenario())


def test_full_upload_flow(tmp_path) -> None:
    async def scenario() -> None:
        server, shared = await _start_server(tmp_path, UploadQueue(max_slots=1))
        path_bytes = open(shared.path, "rb").read()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            peer_hash = bytes.fromhex("B" * 32)
            await _send(
                writer,
                C2CTCP.HELLO,
                build_hello_payload(
                    user_hash=peer_hash,
                    client_id=1,
                    client_port=4662,
                    nickname="peer",
                ),
            )
            await _recv(reader)  # HELLOANSWER

            # Pre-upload file requests (buffered by the listener, replayed
            # into the engine after the accept).
            await _send(
                writer,
                C2CTCP.REQUESTFILENAME,
                shared.file_hash,
            )
            await _send(writer, C2CTCP.HASHSETREQUEST, shared.file_hash)

            await _send(writer, C2CTCP.STARTUPLOADREQ, shared.file_hash)

            # File-name/hashset answers are sent immediately (before the
            # queue decision); the accept comes from the engine hook when
            # it processes the replayed STARTUPLOADREQ.
            opcode, payload = await _recv(reader)
            assert opcode == C2CTCP.REQFILENAMEANSWER
            name_answer = parse_filename_answer(payload)
            assert name_answer.file_hash == shared.file_hash
            assert name_answer.name == shared.name

            opcode, payload = await _recv(reader)
            assert opcode == C2CTCP.HASHSETANSWER

            opcode, _ = await _recv(reader)
            assert opcode == C2CTCP.ACCEPTUPLOADREQ

            ranges = [(0, 100_000), (150_000, 160_000)]
            await _send(
                writer,
                C2CTCP.REQUESTPARTS_I64,
                shared.file_hash
                + struct.pack("<3Q", ranges[0][0], ranges[1][0], 0)
                + struct.pack("<3Q", ranges[0][1], ranges[1][1], 0),
            )

            covered: dict[tuple[int, int], bytes] = {}
            expected_total = sum(end - start for start, end in ranges)
            received_total = 0
            while received_total < expected_total:
                opcode, payload = await _recv(reader)
                # Offsets are below 4 GiB, so per CreateStandardPackets
                # the plain SENDINGPART opcode is used, not I64.
                assert opcode == C2CTCP.SENDINGPART
                part = parse_sending_part(payload)
                assert part.file_hash == shared.file_hash
                window = (part.start, part.end)
                assert window not in covered
                covered[window] = part.data
                assert path_bytes[part.start:part.end] == part.data
                received_total += part.data_size

            for start, end in ranges:
                pieces = b"".join(
                    data
                    for (s, e), data in sorted(covered.items())
                    if s >= start and e <= end
                )
                assert pieces == path_bytes[start:end]

            await _send(writer, C2CTCP.END_OF_DOWNLOAD, shared.file_hash)
            eof = await asyncio.wait_for(reader.read(), _IO_TIMEOUT)
            assert eof == b""
        finally:
            await server.close()

    _run(scenario())


def test_queue_rank_when_busy(tmp_path) -> None:
    async def scenario() -> None:
        server, shared = await _start_server(tmp_path, UploadQueue(max_slots=1))
        try:
            peers = []
            for _ in range(2):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", server.bound_port
                )
                await _send(
                    writer,
                    C2CTCP.HELLO,
                    build_hello_payload(
                        user_hash=os.urandom(16),
                        client_id=1,
                        client_port=4662,
                        nickname="peer",
                    ),
                )
                await _recv(reader)
                peers.append((reader, writer))

            first_reader, first_writer = peers[0]
            second_reader, second_writer = peers[1]

            await _send(first_writer, C2CTCP.STARTUPLOADREQ, shared.file_hash)
            opcode, _ = await _recv(first_reader)
            assert opcode == C2CTCP.ACCEPTUPLOADREQ

            await _send(second_writer, C2CTCP.STARTUPLOADREQ, shared.file_hash)
            opcode, payload = await _recv(second_reader)
            assert opcode == C2CTCP.QUEUERANK
            assert parse_queue_rank(payload) == 1

            for _, writer in peers:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
        finally:
            await server.close()

    _run(scenario())


def test_unknown_hash_end_of_download(tmp_path) -> None:
    async def scenario() -> None:
        server, _ = await _start_server(tmp_path, UploadQueue())
        unknown = bytes.fromhex("C" * 32)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            await _send(
                writer,
                C2CTCP.HELLO,
                build_hello_payload(
                    user_hash=bytes.fromhex("B" * 32),
                    client_id=1,
                    client_port=4662,
                    nickname="peer",
                ),
            )
            await _recv(reader)
            await _send(writer, C2CTCP.STARTUPLOADREQ, unknown)
            opcode, payload = await _recv(reader)
            assert opcode == C2CTCP.END_OF_DOWNLOAD
            assert payload == unknown
        finally:
            await server.close()

    _run(scenario())


def test_emuleinfo_answered_and_session_alive(tmp_path) -> None:
    async def scenario() -> None:
        server, shared = await _start_server(tmp_path, UploadQueue())
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            await _send(
                writer,
                C2CTCP.HELLO,
                build_hello_payload(
                    user_hash=bytes.fromhex("B" * 32),
                    client_id=1,
                    client_port=4662,
                    nickname="peer",
                ),
            )
            await _recv(reader)

            await _send(
                writer,
                C2CEMULE.EMULEINFO,
                build_emuleinfo_payload(),
                protocol=EMULE,
            )
            opcode, _ = await _recv(reader)
            assert opcode == C2CEMULE.EMULEINFOANSWER

            # Session must still answer a file request afterwards.
            await _send(writer, C2CTCP.REQUESTFILENAME, shared.file_hash)
            await _send(writer, C2CTCP.STARTUPLOADREQ, shared.file_hash)
            # The file-name answer is immediate; the accept comes from
            # the engine hook on the replayed STARTUPLOADREQ.
            opcode, payload = await _recv(reader)
            assert opcode == C2CTCP.REQFILENAMEANSWER
            assert parse_filename_answer(payload).name == shared.name
            opcode, _ = await _recv(reader)
            assert opcode == C2CTCP.ACCEPTUPLOADREQ
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        finally:
            await server.close()

    _run(scenario())
