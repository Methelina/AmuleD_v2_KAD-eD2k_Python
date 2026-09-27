"""Offline loopback test for the NAT-T rendezvous state machine.

Double-firewalled scenario (both sides behind "NAT" — simulated by
same-host UDP endpoints, per roadmap 11m): the download side asks the
target's serving buddy with OP_REASKCALLBACKUDP (rendezvous marker,
0xA0); the fake buddy punches BOTH sides with OP_HOLEPUNCH and relays
OP_NATT_ENDPOINT_HINT to the requester; the sides run the CAPS exchange
(uTP only) and bring up a uTP stream that carries a full eD2K session —
IncomingPeerSession (source role) vs PeerClient.adopt_connection
(downloader role).  The file is MD4-verified on finalize.

tests/test_natt_rendezvous.py
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
from amuled_v2.core.natt.session import (
    NattUdpSession,
    OP_NATT_ENDPOINT_HINT,
    build_client_udp_packet,
    parse_client_udp_packet,
)
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.sharing.shared_files import SharedFile

_LOCAL_HASH = bytes.fromhex("3" * 32)
_IO_TIMEOUT = 120.0


class _StaticResolver:
    def __init__(self, shared: SharedFile | None) -> None:
        self._shared = shared

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return self._shared if self._shared and self._shared.file_hash == file_hash else None


class _PermissiveQueue:
    def __init__(self) -> None:
        from amuled_v2.core.upload.queue import UploadQueue

        self._real = UploadQueue(max_slots=2)

    def __getattr__(self, item):
        return getattr(self._real, item)


class _FakeBuddy(asyncio.DatagramProtocol):
    """Serving buddy: ignores KADEMLIA_CALLBACK_REQ (0x52) so the runner's
    buddy-callback path times out; on the rendezvous-marked
    OP_REASKCALLBACKUDP (0x94) it punches both sides and relays
    OP_NATT_ENDPOINT_HINT to the requester (ClientUDPSocket.cpp:1258-1292)."""

    def __init__(self, source_addr, target_user_hash: bytes, buddy_id: bytes) -> None:
        self.source_addr = source_addr  # (host, port) of the firewalled source
        self.target_user_hash = target_user_hash
        self.buddy_id = buddy_id
        self.transport: asyncio.DatagramTransport | None = None

    def datagram_received(self, data: bytes, addr) -> None:
        parsed = parse_client_udp_packet(data)
        if parsed is None:
            return
        opcode, payload = parsed
        if opcode != 0x94 or len(payload) < 33 or payload[32] != 0xA0:
            return  # only the rendezvous-marked reask (0x52 falls through)
        file_hash = payload[50:66]
        holepunch = build_client_udp_packet(0xA1)
        # Punch both sides (ClientUDPSocket.cpp:1290-1292 + 1957-1984).
        self.transport.sendto(holepunch, addr)
        self.transport.sendto(holepunch, self.source_addr)
        # Relay the endpoint hint to the requester (1258-1286).
        hint = (
            bytes((1,))
            + self.target_user_hash
            + self.buddy_id
            + file_hash
            + struct.pack(
                "<IH",
                0x7F000001,  # 127.0.0.1 (loopback "NAT" endpoint)
                self.source_addr[1],
            )
            + bytes((0x80,))  # target options: uTP NAT-T only
        )
        self.transport.sendto(
            build_client_udp_packet(OP_NATT_ENDPOINT_HINT, hint), addr
        )


class _FakeRendezvousSource:
    """Firewalled source: NattUdpSession armed for the file; inbound uTP
    streams are served by the real upload engine (IncomingPeerSession)."""

    def __init__(self, shared: SharedFile, user_hash: bytes) -> None:
        self.shared = shared
        self.user_hash = user_hash
        self.session: NattUdpSession | None = None
        self.udp_port = 0

    async def start(self, host: str = "127.0.0.1") -> None:
        self.session = NattUdpSession(
            self.user_hash, on_inbound_utp=self._on_stream
        )
        if ":" in host:
            self.udp_port = await self.session.start6(host=host)
        else:
            self.udp_port = await self.session.start(host=host)
        self.session.arm_source(self.shared.file_hash)

    async def stop(self) -> None:
        if self.session is not None:
            self.session.close()

    def _on_stream(self, stream, addr) -> None:
        asyncio.get_running_loop().create_task(self._serve(stream))

    async def _serve(self, stream) -> None:
        from amuled_v2.core.peer.listener import IncomingPeerSession

        identity = LocalIdentity(
            user_hash=self.user_hash,
            client_id=1,
            tcp_port=self.udp_port,
            nickname="fake-rendezvous-source",
        )
        session = IncomingPeerSession(
            stream.reader(),
            stream.writer(),
            identity=identity,
            resolver=_StaticResolver(self.shared),
            upload_queue=_PermissiveQueue(),
            idle_timeout=60.0,
        )
        try:
            await session.run()
        except Exception:
            pass


def test_natt_rendezvous_download_loopback(tmp_path) -> None:
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "natt_sample.bin"
        data = os.urandom(280_000)
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source_user_hash = bytes.fromhex("AB" * 16)
        source = _FakeRendezvousSource(shared, source_user_hash)
        await source.start()

        loop = asyncio.get_running_loop()
        buddy = _FakeBuddy(
            ("127.0.0.1", source.udp_port),
            target_user_hash=source_user_hash,
            buddy_id=bytes.fromhex("CD" * 16),
        )
        buddy_transport, _ = await loop.create_datagram_endpoint(
            lambda: buddy, local_addr=("127.0.0.1", 0)
        )
        buddy.transport = buddy_transport
        buddy_port = buddy_transport.get_extra_info("sockname")[1]

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
                "client_id": 0x7F000001,  # 127.0.0.1
                "client_port": 12345,  # dummy; unused in callback flow
                "user_hash": source_user_hash.hex(),
                "source_type": "kad3",
                "kad_udp_port": source.udp_port,
                "buddy_id": "CD" * 16,
                "buddy_ip": "127.0.0.1",
                "buddy_port": buddy_port,
            }
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
            # AICH audit: the runner must have stored the recovery-verified
            # master hash for the completed file.
            stored = backend.get_aich_master(shared.file_hash.hex())
            assert stored is not None, "AICH master was not stored"
        finally:
            await listener.close()
            buddy_transport.close()
            await source.stop()

    asyncio.run(scenario())


def test_natt_rendezvous_ipv6_direct_punch() -> None:
    """IPv6 rendezvous (direct-punch variant): target endpoint known from
    the KAD record, buddy relays only the 0x94 (endpoint hints are
    IPv4-only), holepunch/CAPS/uTP go straight to the IPv6 endpoint."""
    import struct as _struct
    from amuled_v2.core.natt.session import NattUdpSession, build_client_udp_packet, parse_client_udp_packet

    SRC_HASH = bytes.fromhex("AB" * 16)
    BUDDY_ID = bytes.fromhex("CD" * 16)
    FILE_HASH = bytes.fromhex("EF" * 16)

    class Buddy6(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport = None

        def datagram_received(self, data, addr) -> None:
            parsed = parse_client_udp_packet(data)
            if not parsed:
                return
            op, payload = parsed
            if op != 0x94 or len(payload) < 33 or payload[32] != 0xA0:
                return  # the v6 buddy relays nothing else (no v4 hint)

    async def main() -> None:
        accepted = asyncio.get_running_loop().create_future()

        def on_stream(stream, addr) -> None:
            if not accepted.done():
                accepted.set_result(stream)

        src = NattUdpSession(SRC_HASH, on_inbound_utp=on_stream)
        src_port = await src.start6(host="::1")
        src.arm_source(FILE_HASH)

        buddy = Buddy6()
        loop = asyncio.get_running_loop()
        bt, _ = await loop.create_datagram_endpoint(
            lambda: buddy, local_addr=("::1", 0)
        )
        buddy.transport = bt
        bport = bt.get_extra_info("sockname")[1]

        req = NattUdpSession(bytes.fromhex("77" * 16))
        await req.start(host="127.0.0.1")
        await req.start6(host="::1")
        try:
            stream = await asyncio.wait_for(
                req.rendezvous_connect(
                    buddy_host="::1",
                    buddy_port=bport,
                    buddy_id=BUDDY_ID,
                    target_user_hash=SRC_HASH,
                    file_hash=FILE_HASH,
                    our_ext_ip=0,
                    our_ext_udp_port=req.bound_port,
                    target_addr=("::1", src_port),
                    hint_timeout=5.0,
                ),
                30.0,
            )
            upstream = await asyncio.wait_for(accepted, 10.0)
            await stream.send(b"v6-hello")
            data = await asyncio.wait_for(upstream.recv(), 10.0)
            assert data == b"v6-hello"
            await upstream.send(b"v6-ack")
            data2 = await asyncio.wait_for(stream.recv(), 10.0)
            assert data2 == b"v6-ack"
            await stream.close()
        finally:
            req.close()
            src.close()
            bt.close()

    asyncio.run(main())


def test_natt_rendezvous_runner_ipv6_direct_punch(tmp_path) -> None:
    """Runner-level IPv6 rendezvous: a kad3 row carrying ipv6 ("::1")
    must take the direct-punch variant (no endpoint hint) and complete
    the download over uTP with the MD4-verified file."""
    from amuled_v2 import state as state_module
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "natt_v6_sample.bin"
        data = os.urandom(280_000)
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )

        source_user_hash = bytes.fromhex("AB" * 16)
        source = _FakeRendezvousSource(shared, source_user_hash)
        await source.start(host="::1")

        loop = asyncio.get_running_loop()
        buddy = _FakeBuddy(
            ("::1", source.udp_port),
            target_user_hash=source_user_hash,
            buddy_id=bytes.fromhex("CD" * 16),
        )
        buddy_transport, _ = await loop.create_datagram_endpoint(
            lambda: buddy, local_addr=("127.0.0.1", 0)
        )
        buddy.transport = buddy_transport
        buddy_port = buddy_transport.get_extra_info("sockname")[1]

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
            # The loopback fake source legitimately sits on our own ::1 —
            # the production self-record filter must be off here.
            self_record_filter=False,
        )
        runner.source_provider = lambda h, limit: [
            {
                "client_id": 0x7F000001,
                "client_port": 12345,
                "user_hash": source_user_hash.hex(),
                "source_type": "kad3",
                "kad_udp_port": source.udp_port,
                "ipv6": "::1",
                "buddy_id": "CD" * 16,
                "buddy_ip": "127.0.0.1",
                "buddy_port": buddy_port,
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
            buddy_transport.close()
            await source.stop()

    asyncio.run(scenario())
