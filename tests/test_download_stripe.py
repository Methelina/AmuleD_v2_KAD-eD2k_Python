"""Stripe-scheduling e2e test (stage X): two racing peers download
DISJOINT regions of one file; the queue's gap list completes the file and
MD4 verifies.  Before stripes both peers redundantly downloaded from
offset 0.

tests/test_download_stripe.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import os

from amuled_v2.core.download.queue import DownloadQueue
from amuled_v2.core.download.runner import DownloadRunner
from amuled_v2.core.hashes.ed2k import ed2k_hash_file
from amuled_v2.core.kad.direct_callback import parse_direct_callback_payload
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.sharing.shared_files import SharedFile

_LOCAL_HASH = bytes.fromhex("3" * 32)
_IO_TIMEOUT = 120.0


class _StaticResolver:
    def __init__(self, shared: SharedFile | None) -> None:
        self._shared = shared

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return (
            self._shared
            if self._shared and self._shared.file_hash == file_hash
            else None
        )


class _PermissiveQueue:
    def __init__(self) -> None:
        from amuled_v2.core.upload.queue import UploadQueue

        self._real = UploadQueue(max_slots=2)

    def __getattr__(self, item):
        return getattr(self._real, item)


class _SourceUDP(asyncio.DatagramProtocol):
    def __init__(self, owner: "_FakeSource") -> None:
        self.owner = owner

class _SourceUDP(asyncio.DatagramProtocol):
    def __init__(self, owner: "_FakeSource") -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, addr) -> None:
        if data[0] != 0xC5 or data[5] != 0x95:
            return
        if self.owner._conn_open:
            return  # one live callback session per source
        self.owner._conn_open = True
        (length,) = (int.from_bytes(data[1:5], "little"),)
        payload = data[6 : 5 + length]
        tcp_port, _user_hash, _opts = parse_direct_callback_payload(payload)
        asyncio.get_running_loop().create_task(
            self.owner._dial_back(addr[0], tcp_port)
        )


class _FakeSource:
    """Direct-callback double serving the shared file with the real
    upload engine; counts served bytes."""

    served_bytes = 0

    def __init__(self, shared: SharedFile) -> None:
        self.shared = shared
        self.udp_port = 0
        self.transport: asyncio.DatagramTransport | None = None
        self.protocol: _SourceUDP | None = None
        self._dialed = False
        self._conn_open = False
        self._served_box = [0]

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.protocol = _SourceUDP(self)
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("127.0.0.1", 0)
        )
        self.udp_port = self.transport.get_extra_info("sockname")[1]

    async def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()

    async def _dial_back(self, host: str, tcp_port: int) -> None:
        from amuled_v2.core.peer.listener import IncomingPeerSession

        def _recorder(_user_hash: str, n: int) -> None:
            self._served_box[0] += n

        reader, writer = await asyncio.open_connection(host, tcp_port)
        identity = LocalIdentity(
            user_hash=bytes.fromhex("5" * 32),
            client_id=1,
            tcp_port=self.udp_port,
            nickname="fake-stripe-source",
        )
        session = IncomingPeerSession(
            reader,
            writer,
            identity=identity,
            resolver=_StaticResolver(self.shared),
            upload_queue=_PermissiveQueue(),
            idle_timeout=60.0,
            traffic_recorder=_recorder,
        )
        try:
            await session.run()
        except Exception:
            pass
        finally:
            self._conn_open = False
            writer.close()


def test_stripe_download_two_peers(tmp_path) -> None:
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "stripe_sample.bin"
        data = os.urandom(1_200_000)  # several 180 KB blocks
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source_a = _FakeSource(shared)
        source_b = _FakeSource(shared)
        await source_a.start()
        await source_b.start()

        listener = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-stripe",
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
                "client_port": 1,
                "user_hash": "A1" * 16,
                "source_type": "kad6",
                "kad_udp_port": source_a.udp_port,
            },
            {
                "client_id": 0x7F000001,
                "client_port": 2,
                "user_hash": "A2" * 16,
                "source_type": "kad6",
                "kad_udp_port": source_b.udp_port,
            },
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
            # Both stripes were exercised: each peer served its region.
            assert source_a._served_box[0] > 0
            assert source_b._served_box[0] > 0
        finally:
            await listener.close()
            await source_a.stop()
            await source_b.stop()

    asyncio.run(scenario())


def test_stripe_reassignment_dead_peer(tmp_path) -> None:
    """Stalled-stripe reassignment: peer B is dead (immediate connect
    failure); round 2 must re-stripe the remaining hole onto peer A and
    still complete with MD4 verified."""
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "reassign_sample.bin"
        data = os.urandom(600_000)
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source_a = _FakeSource(shared)
        await source_a.start()

        listener = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-reassign",
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
            plain_dial_ok=True,
            connection_source=listener.expect_connection_from,
            callback_identity={
                "tcp_port": listener.bound_port,
                "user_hash": our_hash,
            },
        )
        runner.source_provider = lambda h, limit: [
            {
                "client_id": 0x7F000001,
                "client_port": 1,
                "user_hash": "A1" * 16,
                "source_type": "kad6",
                "kad_udp_port": source_a.udp_port,
            },
            {
                # Dead direct endpoint: nothing listens on this port.
                "client_id": 0x7F000001,
                "client_port": 2,
                "user_hash": None,
                "source_type": "ed2k",
            },
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
            # Peer A covered the dead peer's stripe in round 2: served
            # more than its own half of the file.
            assert source_a._served_box[0] >= shared.size
        finally:
            await listener.close()
            await source_a.stop()

    asyncio.run(scenario())


def test_corrupt_part_salvage(tmp_path) -> None:
    """Corrupt-part salvage: one block arrives corrupted; the part-MD4
    verification punches it as a gap and the next round refetches it —
    the file still completes MD4-verified."""
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "salvage_sample.bin"
        data = os.urandom(300_000)  # single part, 2 blocks
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source = _FakeSource(shared)
        await source.start()

        listener = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-salvage",
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

        # Corrupt exactly one byte of the FIRST written block (once).
        orig_record_block = queue.record_block
        poisoned = {"done": False}

        def poisoned_record_block(file_hash: str, start: int, data: bytes):
            if not poisoned["done"]:
                poisoned["done"] = True
                data = bytes([data[0] ^ 0xFF]) + data[1:]
            return orig_record_block(file_hash, start, data)

        queue.record_block = poisoned_record_block

        our_hash = bytes.fromhex("7" * 32)
        runner = DownloadRunner(
            queue,
            local_port=listener.bound_port,
            max_peers=1,
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
                "client_port": 1,
                "user_hash": "A1" * 16,
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
            # The corrupted round-1 write must have been refetched: the
            # source served the file content twice (round 1 + salvage).
            assert source._served_box[0] >= shared.size
        finally:
            await listener.close()
            await source.stop()

    asyncio.run(scenario())


def test_resolve_sources_self_record_filter() -> None:
    """Self-referential KAD records (our own userhash or our own local
    IPv6) must be dropped before the race."""
    from amuled_v2.core.download.runner import DownloadRunner

    our_hash = "7" * 32

    def provider(file_hash: str, limit: int):
        return [
            {
                # Self-record: our own userhash.
                "client_id": 0x7F000001,
                "client_port": 1,
                "user_hash": our_hash,
                "source_type": "kad3",
                "kad_udp_port": 1111,
                "ipv6": "::1",
            },
            {
                # Self-record by IPv6 only.
                "client_id": 0x7F000001,
                "client_port": 2,
                "user_hash": "A1" * 16,
                "source_type": "kad3",
                "kad_udp_port": 2222,
                "ipv6": "::1",
            },
            {
                # Good foreign record.
                "client_id": 0x7F000001,
                "client_port": 3,
                "user_hash": "CD" * 16,
                "source_type": "kad3",
                "kad_udp_port": 3333,
            },
        ]

    runner = DownloadRunner(
        queue=object(),  # provider path never touches the queue
        local_client_id=1,
        plain_dial_ok=True,
        source_provider=provider,
        callback_identity={
            "tcp_port": 4662,
            "user_hash": bytes.fromhex(our_hash),
        },
    )

    endpoints = runner.resolve_sources("6" * 32)
    assert len(endpoints) == 1
    assert endpoints[0]["port"] == 3
