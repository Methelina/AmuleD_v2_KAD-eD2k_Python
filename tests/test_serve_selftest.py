"""Loopback self-test: our PeerClient downloads from our IncomingPeerServer.

Stage S integration check — internal consistency of the full client-to-client
ladder over real TCP loopback (127.0.0.1, ephemeral ports):

    PeerClient.connect -> handshake (HELLO/HELLOANSWER)
    -> request_file (REQUESTFILENAME/HASHSETREQUEST/STARTUPLOADREQ)
    -> wait_upload_slot (QUEUERANK / ACCEPTUPLOADREQ)
    -> transfer (REQUESTPARTS -> SENDINGPART/COMPRESSEDPART blocks)
    -> reassembled bytes hashed with MD4 must equal the ED2K file hash.

This is NOT a live acceptance test against a real eMule client: the
encrypted transport is pending external work (``WIP by external developer``
markers in core/peer/listener.py).  A real-file variant against the actual
Incoming folder can be run manually with AMULED_SELFTEST_REAL=1 and
AMULED_REAL_INCOMING pointing at a shared file.

tests/test_serve_selftest.py
Author:      Soror L.'.L.'.
Updated:     2026-09-25
"""

from __future__ import annotations

import asyncio
import os

import pytest
from Crypto.Hash import MD4

from amuled_v2.core.hashes.ed2k import ed2k_hash_file
from amuled_v2.core.peer.client import PeerClient, PeerSessionError
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.queue import UploadQueue

_LOCAL_HASH = bytes.fromhex("B" * 32)
_LOCAL_ID = 0x55667788
_NICK = "AmuleD-selftest"
_IO_TIMEOUT = 30.0


class _FakeResolver:
    def __init__(self, mapping: dict[bytes, SharedFile]) -> None:
        self._mapping = mapping

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return self._mapping.get(file_hash)


def _make_shared_file(tmp_path, size: int = 200_000) -> SharedFile:
    path = tmp_path / "selftest.bin"
    path.write_bytes(os.urandom(size))
    result = ed2k_hash_file(str(path))
    return SharedFile(
        file_hash=result.file_hash,
        name=path.name,
        size=result.file_size,
        path=str(path),
        hash_result=result,
    )


async def _selftest_scenario(tmp_path) -> None:
    shared = _make_shared_file(tmp_path)
    resolver = _FakeResolver({shared.file_hash: shared})
    server = IncomingPeerServer(
        identity=LocalIdentity(
            user_hash=_LOCAL_HASH,
            client_id=_LOCAL_ID,
            tcp_port=0,
            nickname=_NICK,
        ),
        resolver=resolver,
        upload_queue=UploadQueue(max_slots=2),
        host="127.0.0.1",
        port=0,
        idle_timeout=15.0,
        max_connections=4,
    )
    await server.start()
    try:
        blocks: dict[int, bytes] = {}
        progress: list[tuple[int, int, int]] = []

        client = PeerClient(
            "127.0.0.1",
            server.bound_port,
            local_client_id=0x01020304,
            local_port=0,
            nickname="AmuleD-dl",
            connect_timeout=_IO_TIMEOUT,
            response_timeout=_IO_TIMEOUT,
            queue_wait_timeout=_IO_TIMEOUT,
        )
        async with client:
            peer_info = await asyncio.wait_for(
                client.handshake(), timeout=_IO_TIMEOUT
            )
            assert peer_info is not None
            hashset = await asyncio.wait_for(
                client.request_file(shared.file_hash), timeout=_IO_TIMEOUT
            )
            assert hashset.file_hash == shared.file_hash
            await asyncio.wait_for(
                client.wait_upload_slot(shared.file_hash), timeout=_IO_TIMEOUT
            )
            outcome = await asyncio.wait_for(
                client.transfer(
                    shared.file_hash,
                    shared.size,
                    write_block=lambda start, data: blocks.__setitem__(
                        start, data
                    ),
                    progress_callback=lambda r, t, b: progress.append(
                        (r, t, b)
                    ),
                ),
                timeout=_IO_TIMEOUT,
                )

        assembled = bytearray()
        offset = 0
        while offset < shared.size:
            chunk = blocks.get(offset)
            assert chunk is not None, f"missing block at offset {offset}"
            assembled += chunk
            offset += len(chunk)
        assert len(assembled) == shared.size

        md4 = MD4.new()
        md4.update(bytes(assembled))
        assert md4.digest() == shared.file_hash, "reassembled MD4 mismatch"
        # The upload engine sub-packetizes ranges (<=13000/10240 bytes), so
        # the wire byte count may exceed the file size slightly; what matters
        # is completion and exact content.
        assert outcome.complete is True
        assert progress, "no progress callbacks fired"
    finally:
        await server.close()


def test_peerclient_downloads_from_own_listener(tmp_path) -> None:
    """Full loopback ladder: HELLO -> hashset -> slot -> parts -> MD4."""
    asyncio.run(_selftest_scenario(tmp_path))


@pytest.mark.skipif(
    os.environ.get("AMULED_SELFTEST_REAL") != "1",
    reason="real-file self-test requires AMULED_SELFTEST_REAL=1 and "
    "AMULED_REAL_INCOMING pointing at a shared file",
)
def test_peerclient_downloads_real_incoming_file(tmp_path) -> None:
    """Manual live variant against the real Incoming folder."""
    real_path = os.environ.get("AMULED_REAL_INCOMING")
    if not real_path or not os.path.isfile(real_path):
        pytest.skip("AMULED_REAL_INCOMING is not a readable file")

    result = ed2k_hash_file(real_path)
    shared = SharedFile(
        file_hash=result.file_hash,
        name=os.path.basename(real_path),
        size=result.file_size,
        path=real_path,
        hash_result=result,
    )
    mapping = {shared.file_hash: shared}

    async def scenario() -> None:
        resolver = _FakeResolver(mapping)
        server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=_LOCAL_ID,
                tcp_port=0,
                nickname=_NICK,
            ),
            resolver=resolver,
            upload_queue=UploadQueue(max_slots=2),
            host="127.0.0.1",
            port=0,
            idle_timeout=60.0,
        )
        await server.start()
        try:
            blocks: dict[int, bytes] = {}
            client = PeerClient(
                "127.0.0.1",
                server.bound_port,
                connect_timeout=_IO_TIMEOUT,
                response_timeout=_IO_TIMEOUT,
                queue_wait_timeout=_IO_TIMEOUT,
            )
            async with client:
                await asyncio.wait_for(
                    client.handshake(), timeout=_IO_TIMEOUT
                )
                await asyncio.wait_for(
                    client.request_file(shared.file_hash), timeout=_IO_TIMEOUT
                )
                await asyncio.wait_for(
                    client.wait_upload_slot(shared.file_hash),
                    timeout=_IO_TIMEOUT,
                )
                await asyncio.wait_for(
                    client.transfer(
                        shared.file_hash,
                        shared.size,
                        write_block=lambda s, d: blocks.__setitem__(s, d),
                    ),
                    timeout=600.0,
                )
            assembled = bytearray()
            offset = 0
            while offset < shared.size:
                chunk = blocks.get(offset)
                assert chunk is not None, f"missing block at {offset}"
                assembled += chunk
                offset += len(chunk)
            md4 = MD4.new()
            md4.update(bytes(assembled))
            assert md4.digest() == shared.file_hash
        finally:
            await server.close()

    asyncio.run(scenario())
