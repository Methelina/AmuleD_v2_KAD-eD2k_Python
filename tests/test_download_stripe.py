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
        if self.owner._dialed:
            return  # one callback per source, like a real client
        self.owner._dialed = True
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
