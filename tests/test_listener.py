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


async def _start_server(
    tmp_path,
    queue: UploadQueue,
    size: int = 200_000,
    queue_rank_period: float = 60.0,
):
    shared = _make_shared_file(tmp_path, size)
    resolver = _FakeResolver({shared.file_hash: shared})
    server = IncomingPeerServer(
        identity=_identity(0),
        resolver=resolver,
        upload_queue=queue,
        host="127.0.0.1",
        port=0,
        idle_timeout=15.0,
        queue_rank_period=queue_rank_period,
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

def test_queued_client_promoted_after_slot_frees(tmp_path) -> None:
    """Stage X parity: the queued client HOLDS its connection; when the
    slot holder leaves, the next rank refresh promotes it and the engine
    answers ACCEPTUPLOADREQ on the same connection."""

    async def scenario() -> None:
        server, shared = await _start_server(
            tmp_path, UploadQueue(max_slots=1), queue_rank_period=0.3
        )
        try:
            readers = []
            writers = []
            for i in range(2):
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
                        nickname=f"peer{i}",
                    ),
                )
                await _recv(reader)
                readers.append(reader)
                writers.append(writer)

            await _send(writers[0], C2CTCP.STARTUPLOADREQ, shared.file_hash)
            opcode, _ = await _recv(readers[0])
            assert opcode == C2CTCP.ACCEPTUPLOADREQ

            await _send(writers[1], C2CTCP.STARTUPLOADREQ, shared.file_hash)
            opcode, payload = await _recv(readers[1])
            assert opcode == C2CTCP.QUEUERANK
            assert parse_queue_rank(payload) == 1

            # Slot holder disconnects: its session ends, the slot is
            # released, and the queued client is promoted on the next
            # rank refresh -> ACCEPTUPLOADREQ on the same connection.
            writers[0].close()
            try:
                await writers[0].wait_closed()
            except OSError:
                pass

            opcode, _ = await asyncio.wait_for(
                _recv(readers[1]), timeout=10.0
            )
            assert opcode == C2CTCP.ACCEPTUPLOADREQ
        finally:
            await server.close()

    _run(scenario())

def _local_hash_bytes() -> bytes:
    """The listener identity userhash (tests/test_listener._LOCAL_HASH)."""
    import test_listener as t
    return bytes.fromhex(t._LOCAL_HASH) if isinstance(t._LOCAL_HASH, str) else bytes(t._LOCAL_HASH)


def test_obfuscated_client_downloads_from_listener(tmp_path) -> None:
    """Stage X acceptance: our live-verified PeerClient dials the listener
    with BASIC obfuscation; the acceptor completes the handshake and the
    client downloads the file with a matching MD4."""
    import hashlib

    from amuled_v2.core.peer.client import PeerClient
    from amuled_v2.core.hashes.ed2k import ed2k_hash_file
    from pathlib import Path

    shared = _make_shared_file(tmp_path, size=50_000)
    source_bytes = Path(shared.path).read_bytes()
    from Crypto.Hash import MD4

    expected_md4 = MD4.new(source_bytes).hexdigest()

    async def scenario() -> None:
        from amuled_v2.core.upload.queue import UploadQueue

        resolver = _FakeResolver({shared.file_hash: shared})
        server = IncomingPeerServer(
            identity=_identity(0),
            resolver=resolver,
            upload_queue=UploadQueue(max_slots=1),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
        )
        await server.start()
        try:
            blocks: dict[int, bytes] = {}
            client = PeerClient(
                "127.0.0.1",
                server.bound_port,
                connect_timeout=15.0,
                response_timeout=20.0,
                queue_wait_timeout=30.0,
                target_userhash=_local_hash_bytes(),
                local_userhash=bytes.fromhex("FEED" * 8),
            )
            async with client:
                await asyncio.wait_for(client.handshake(), timeout=30)
                await asyncio.wait_for(
                    client.request_file(shared.file_hash), timeout=30
                )
                await asyncio.wait_for(
                    client.wait_upload_slot(shared.file_hash), timeout=60
                )
                outcome = await asyncio.wait_for(
                    client.transfer(
                        shared.file_hash,
                        shared.size,
                        write_block=lambda s, d: blocks.__setitem__(s, d),
                    ),
                    timeout=120,
                )
            assert outcome.complete, outcome
            assembled = bytearray(shared.size)
            for start, data in blocks.items():
                assembled[start:start + len(data)] = data
            assert MD4.new(bytes(assembled)).hexdigest() == expected_md4
        finally:
            await server.close()

    _run(scenario())


def test_dh_client_accepted_by_listener(tmp_path) -> None:
    """Stage X: a server-role DH dial is accepted; the acceptor answers
    g^b and the post-handshake frames decrypt on the DH-derived keys."""
    import struct as _struct

    from amuled_v2.core.peer.obfuscation import (
        Rc4Stream,
        build_dh_request,
        compute_dh_public_key,
        generate_dh_private_key,
    )
    from amuled_v2.core.codec.binary import BinaryWriter

    async def scenario() -> None:
        shared = _make_shared_file(tmp_path, size=10_000)
        resolver = _FakeResolver({shared.file_hash: shared})
        server = IncomingPeerServer(
            identity=_identity(0),
            resolver=resolver,
            upload_queue=UploadQueue(max_slots=1),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
        )
        await server.start()
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            a = generate_dh_private_key()
            g_a = compute_dh_public_key(a)
            request = build_dh_request(g_a)
            import amuled_v2.core.peer.obfuscation as _obf

            _obf.log.debug(
                "DH dialer: request=%d, g_a_head=%s, marker=0x%02X",
                len(request), g_a[:8].hex(), request[0],
            )
            writer.write(request)
            await writer.drain()

            g_b = await asyncio.wait_for(reader.readexactly(96), 15.0)
            # DH shared secret: g_b^a mod p (big-endian, 96 bytes)
            from amuled_v2.core.peer.obfuscation import DIFFIE_HELLMAN_PRIME

            secret = pow(int.from_bytes(g_b, "big"), a, DIFFIE_HELLMAN_PRIME)
            secret_buf = secret.to_bytes(96, "big")
            import hashlib as _h

            recv_key = _h.md5(secret_buf + bytes((203,))).digest()
            send_key = _h.md5(secret_buf + bytes((34,))).digest()
            recv_stream = Rc4Stream(recv_key)
            send_stream = Rc4Stream(send_key)

            head = recv_stream.crypt(
                await asyncio.wait_for(reader.readexactly(6), 15.0)
            )
            _obf.log.debug(
                "DH dialer: recv_key=%s, head=%s",
                recv_key[:4].hex(), head.hex(),
            )
            magic = _struct.unpack("<I", head[:4])[0]
            assert magic == 0x835E6FC4, hex(magic)
            assert head[4] == 0x00  # ENM_OBFUSCATION selected
            pad_len = head[5]
            if pad_len:
                # Consume the pad THROUGH the recv stream so both sides'
                # keystreams stay aligned.
                recv_stream.crypt(
                    await asyncio.wait_for(reader.readexactly(pad_len), 15.0)
                )

            # Handshake accepted — send a plain-protocol HELLO through the
            # DH-encrypted stream and expect HELLOANSWER back.
            from amuled_v2.core.peer.codec import build_hello_payload

            hello = build_hello_payload(
                user_hash=bytes.fromhex("BEEF" * 8),
                client_id=1,
                client_port=4662,
                nickname="dh-probe",
            )
            w = BinaryWriter()
            w.write_bytes(
                bytes([EDONKEY])
                + _struct.pack("<I", len(hello) + 1)
                + bytes([C2CTCP.HELLO])
                + hello
            )
            writer.write(send_stream.crypt(w.to_bytes()))
            await writer.drain()
            header = recv_stream.crypt(
                await asyncio.wait_for(reader.readexactly(6), 15.0)
            )
            assert header[0] == EDONKEY
            (length,) = _struct.unpack("<I", header[1:5])
            payload = recv_stream.crypt(
                await asyncio.wait_for(reader.readexactly(length - 1), 15.0)
            )
            assert header[5] == C2CTCP.HELLOANSWER
            # Canonical HELLOANSWER: [hashlen u8 = 16][userhash 16]...
            assert payload[0] == 16
            assert payload[1:17] == _local_hash_bytes()
        finally:
            await server.close()
            if writer is not None:
                writer.close()

    _run(scenario())
