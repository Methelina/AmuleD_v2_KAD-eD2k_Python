"""Offline loopback test for the KAD type-6 direct-UDP-callback download.

Simulates a firewalled source: it holds a UDP socket, receives
OP_DIRECTCALLBACKREQ (0x95), TCP-connects BACK to the advertised port and
serves the file through the standard upload engine (IncomingPeerSession).
The download side runs the real DownloadRunner with a 'kad6' source row.

tests/test_direct_callback.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import os
import struct

from amuled_v2.core.download.queue import DownloadQueue
from amuled_v2.core.download.runner import DownloadRunner
from amuled_v2.core.hashes.ed2k import ed2k_hash_file
from amuled_v2.core.kad.direct_callback import parse_direct_callback_payload
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.sharing.shared_files import SharedFile

_LOCAL_HASH = bytes.fromhex("3" * 32)
_IO_TIMEOUT = 60.0


class _FakeFirewalledSource:
    """UDP endpoint that answers OP_DIRECTCALLBACKREQ by dialing back and
    serving the shared file with the real upload engine."""

    def __init__(self, shared: SharedFile) -> None:
        self.shared = shared
        self.udp_port = 0
        self._sock: asyncio.DatagramDatagramProtocol | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self.protocol: _SourceUDP | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.protocol = _SourceUDP(self)
        self._transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("127.0.0.1", 0)
        )
        self.udp_port = self._transport.get_extra_info("sockname")[1]

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()


class _SourceUDP(asyncio.DatagramProtocol):
    def __init__(self, owner: _FakeFirewalledSource) -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, addr) -> None:
        if data[0] != 0xC5 or data[5] not in (0x95, 0x52):
            return
        (length,) = struct.unpack_from("<I", data, 1)
        payload = data[6 : 5 + length]  # len field counts the opcode byte
        if data[5] == 0x95:
            tcp_port, user_hash, _opts = parse_direct_callback_payload(payload)
        else:
            from amuled_v2.core.kad.direct_callback import (
                parse_kad_callback_req_payload,
            )

            buddy_id, file_hash, tcp_port = parse_kad_callback_req_payload(
                payload
            )
        asyncio.get_running_loop().create_task(self._dial_back(addr[0], tcp_port))

    async def _dial_back(self, host: str, tcp_port: int) -> None:
        from amuled_v2.core.peer.listener import (
            IncomingPeerSession,
            StateSharedFileResolver,
        )

        reader, writer = await asyncio.open_connection(host, tcp_port)
        identity = LocalIdentity(
            user_hash=bytes.fromhex("5" * 32),
            client_id=1,
            tcp_port=self.owner.udp_port,
            nickname="fake-fw-source",
        )
        session = IncomingPeerSession(
            reader,
            writer,
            identity=identity,
            resolver=_StaticResolver(self.owner.shared),
            upload_queue=_PermissiveQueue(),
            idle_timeout=60.0,
        )
        try:
            await session.run()
        except Exception:
            pass
        finally:
            writer.close()


class _StaticResolver:
    def __init__(self, shared: SharedFile) -> None:
        self._shared = shared

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return self._shared if self._shared.file_hash == file_hash else None


class _PermissiveQueue:
    """Always-grant upload queue stub for the fake source."""

    def __init__(self) -> None:
        from amuled_v2.core.upload.queue import UploadQueue

        self._real = UploadQueue(max_slots=2)

    def __getattr__(self, item):
        return getattr(self._real, item)


def test_direct_callback_download_loopback(tmp_path) -> None:
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "cb_sample.bin"
        data = os.urandom(300_000)
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source = _FakeFirewalledSource(shared)
        await source.start()

        # Download side: our own listener receives the callback connection.
        listener = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-dl",
            ),
            resolver=_StaticResolver(None),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=30.0,
        )
        await listener.start()

        state = backend
        queue = DownloadQueue(
            state=state, temp_dir=tmp_path / "temp", incoming_dir=tmp_path / "inc"
        )
        queue.add(
            file_hash=shared.file_hash.hex(),
            name=shared.name,
            size=shared.size,
        )

        our_hash = bytes.fromhex("7" * 32)
        runner = DownloadRunner(
            queue,
            local_port=listener.bound_port,
            max_peers=2,
            plain_dial_ok=False,
            connection_source=listener.expect_connection_from,
            callback_identity={
                "tcp_port": listener.bound_port,
                "user_hash": our_hash,
            },
        )
        runner.source_provider = lambda h, limit: [
            {
                "client_id": 0x7F000001,  # 127.0.0.1
                "client_port": 12345,  # dummy; unused in callback flow
                "user_hash": "AA" * 16,
                "source_type": "kad6",
                "kad_udp_port": source.udp_port,
            }
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
        finally:
            await listener.close()
            await source.stop()

    asyncio.run(scenario())


def test_buddy_callback_download_loopback(tmp_path) -> None:
    """Type 3/5: KADEMLIA_CALLBACK_REQ (0x52) to the buddy; the firewalled
    source dials back and serves (BaseClient.cpp:3258-3282)."""
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "buddy_sample.bin"
        data = os.urandom(250_000)
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source = _FakeFirewalledSource(shared)
        await source.start()

        listener = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-dl",
            ),
            resolver=_StaticResolver(None),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=30.0,
        )
        await listener.start()

        queue = DownloadQueue(
            state=backend,
            temp_dir=tmp_path / "temp",
            incoming_dir=tmp_path / "inc",
        )
        queue.add(
            file_hash=shared.file_hash.hex(),
            name=shared.name,
            size=shared.size,
        )

        our_hash = bytes.fromhex("7" * 32)
        runner = DownloadRunner(
            queue,
            local_port=listener.bound_port,
            max_peers=2,
            plain_dial_ok=False,
            connection_source=listener.expect_connection_from,
            callback_identity={
                "tcp_port": listener.bound_port,
                "user_hash": our_hash,
            },
        )
        runner.source_provider = lambda h, limit: [
            {
                "client_id": 0x7F000001,
                "client_port": 12345,
                "user_hash": "AB" * 16,
                "source_type": "kad3",
                "kad_udp_port": source.udp_port,
                "buddy_id": "CD" * 16,
                # The fake buddy is the UDP endpoint itself; it relays by
                # dialing back directly in this loopback double.
                "buddy_ip": "127.0.0.1",
                "buddy_port": source.udp_port,
            }
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
        finally:
            await listener.close()
            await source.stop()

    asyncio.run(scenario())


class _StubState:
    """Minimal state double: stores the part file path for the queue."""

    def __init__(self, shared: SharedFile) -> None:
        self._shared = shared

    # DownloadQueue uses state only for bookkeeping in this test; the
    # part-file path comes from the queue itself.
    def __getattr__(self, item):
        raise AttributeError(item)
