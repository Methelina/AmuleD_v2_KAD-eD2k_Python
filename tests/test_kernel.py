"""Stage U tests: kernel control, status snapshot, owned-state vertical slice.

Author: Soror L.'.L.'.
Updated: 2026-09-25
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from amuled_v2.core.kad.spider import (
    build_pool,
    is_routable_ipv4,
    prune_pool,
)
from amuled_v2.core.kernel import AmuleDKernel
from amuled_v2.core.kernel_control import (
    KernelControlServer,
    control_request,
    read_kernel_status,
)


def test_control_server_roundtrip_and_unknown_command() -> None:
    async def scenario() -> None:
        server = KernelControlServer(
            {
                "ping": lambda _req: {"pong": True},
                "echo.credits": lambda _req: {
                    "credits": [{"user_hash": "A" * 32}]
                },
            }
        )
        await server.start()
        try:
            first = await control_request(
                server.port, {"command": "ping"}, timeout=5.0
            )
            assert first == {"status": "ok", "pong": True}

            second = await control_request(
                server.port, {"command": "echo.credits"}, timeout=5.0
            )
            assert second["status"] == "ok"
            assert second["credits"][0]["user_hash"] == "A" * 32

            third = await control_request(
                server.port, {"command": "nope"}, timeout=5.0
            )
            assert third["status"] == "error"
            assert "nope" in third["reason"]
        finally:
            await server.close()

    asyncio.run(scenario())


def test_kernel_status_snapshot_roundtrip(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "amuled_v2.core.kernel_control.KERNEL_STATUS_PATH",
        tmp_path / "kernel_status.json",
    )
    from amuled_v2.core import kernel_control

    assert read_kernel_status() is None  # missing file

    kernel_control._write_json_atomic(
        kernel_control.KERNEL_STATUS_PATH,
        {"running": True, "pid": 1, "serve_port": 1234, "control_port": 5555},
    )
    status = read_kernel_status()
    assert status is not None
    assert status["control_port"] == 5555

    kernel_control._write_json_atomic(
        kernel_control.KERNEL_STATUS_PATH,
        {"running": False, "pid": 1, "control_port": 5555},
    )
    assert read_kernel_status() is None  # not running -> stale


# --- spider engine unit pieces --------------------------------------------------


def test_is_routable_ipv4() -> None:
    assert is_routable_ipv4("1.2.3.4")
    assert not is_routable_ipv4("0.1.2.3")
    assert not is_routable_ipv4("224.0.0.1")
    assert not is_routable_ipv4("255.255.255.255")
    assert not is_routable_ipv4("bogus")


def test_prune_pool_rotates_stale_and_overflow() -> None:
    import time as _time

    now = _time.time()
    nodes = {
        ("1.1.1.1", 1): {"last_seen": now - 99 * 86400, "hellos": 5},   # stale
        ("2.2.2.2", 2): {"last_seen": now, "hellos": 1},                # fresh
        ("3.3.3.3", 3): {"last_seen": now - 86400, "hellos": 0},        # fresh-ish
    }
    pruned = prune_pool(nodes)
    assert ("1.1.1.1", 1) not in nodes
    assert pruned == 1


def test_build_pool_merges_cache_entries(tmp_path) -> None:
    import json as _json

    db = tmp_path / "db"
    db.mkdir()
    cache_file = db / "kad_nodes.json"
    cache_file.write_text(
        _json.dumps(
            {
                "own_id": "0" * 32,
                "nodes": {"5.6.7.8:4672": {"kad_id": "ab", "hellos": 2}},
            }
        ),
        encoding="utf-8",
    )
    cache = _json.loads(cache_file.read_text(encoding="utf-8"))
    pool = build_pool(tmp_path, cache)
    assert ("5.6.7.8", 4672) in pool
    assert pool[("5.6.7.8", 4672)]["hellos"] == 2


# --- vertical slice: kernel process owns state, IPC serves credits --------------


def test_kernel_vertical_slice_upload_then_ipc_credits(tmp_path, monkeypatch) -> None:
    """Full in-process slice: kernel (no spider/publish) serves an upload,
    credits the client on its OWNED state, and answers credits.list over IPC
    with zero DuckDB lock contention (single connection, single process)."""
    from amuled_v2.core.hashes.ed2k import ed2k_hash_file
    from amuled_v2.core.peer.client import PeerClient
    from amuled_v2.core.sharing.shared_files import SharedFile
    from amuled_v2.state import get_state

    # Redirect the kernel status file into tmp so the test doesn't touch db/.
    monkeypatch.setattr(
        "amuled_v2.core.kernel.KERNEL_STATUS_PATH",
        tmp_path / "kernel_status.json",
    )
    monkeypatch.setenv("AMULED_ROOT", str(tmp_path))

    async def scenario() -> tuple[list, bytes]:
        path = tmp_path / "vslice.bin"
        path.write_bytes(os.urandom(60_000))
        result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=result.file_hash,
            name=path.name,
            size=result.file_size,
            path=str(path),
            hash_result=result,
        )

        class _Resolver:
            def __init__(self, state_backend) -> None:
                self._m = {shared.file_hash: shared}

            def resolve(self, file_hash: bytes) -> SharedFile | None:
                return self._m.get(file_hash)

        args = type(
            "Args", (), {
                "no_spider": True, "no_publish": True, "publish_limit": 0,
                "publish_timeout": 5.0, "once": False,
            },
        )()
        kernel = AmuleDKernel.__new__(AmuleDKernel)
        kernel.args = args
        kernel.state = get_state()
        kernel.state.connect()
        kernel.identity = type(
            "Id", (), {"user_hash": bytes.fromhex("D" * 32), "nickname": "k",
                       "tcp_port": 0,
                       "to_local_identity": lambda self, tcp_port=None: None},
        )()
        kernel.bind_host = "127.0.0.1"
        kernel.max_sessions = 8
        kernel.upload_slots = 2
        kernel.throttle_rate = 0
        kernel.republish_hours = 0.0
        kernel.publish_limit = 0
        kernel.stop = asyncio.Event()
        kernel.server = None
        kernel.control = None
        kernel.spider = None
        kernel.started_at = 0.0
        kernel.publish_box = {}
        kernel._tcp_port = 0
        # Replace the resolver with the fake one bound to the owned state.
        kernel.server = None

        from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
        from amuled_v2.core.upload.queue import UploadQueue

        kernel.server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=bytes.fromhex("D" * 32),
                client_id=1,
                tcp_port=0,
                nickname="kernel-vslice",
            ),
            resolver=_Resolver(kernel.state),
            upload_queue=UploadQueue(max_slots=2),
            host="127.0.0.1",
            port=0,
            idle_timeout=10.0,
            traffic_recorder=kernel._record_uploaded,
        )
        await kernel.server.start()
        kernel._tcp_port = kernel.server.bound_port
        kernel.control = KernelControlServer(kernel._handlers())
        await kernel.control.start()

        blocks: dict[int, bytes] = {}
        client = PeerClient(
            "127.0.0.1",
            kernel.server.bound_port,
            connect_timeout=15.0,
            response_timeout=15.0,
            queue_wait_timeout=15.0,
        )
        peer_uh = client.user_hash.hex().lower()
        async with client:
            await asyncio.wait_for(client.handshake(), timeout=15)
            await asyncio.wait_for(
                client.request_file(shared.file_hash), timeout=15
            )
            await asyncio.wait_for(
                client.wait_upload_slot(shared.file_hash), timeout=15
            )
            outcome = await asyncio.wait_for(
                client.transfer(
                    shared.file_hash,
                    shared.size,
                    write_block=lambda s, d: blocks.__setitem__(s, d),
                ),
                timeout=60,
            )
        assert outcome.complete

        # Credits answered over IPC, using the kernel-owned connection.
        response = await control_request(
            kernel.control.port,
            {"command": "credits.list"},
            timeout=15.0,
        )
        kernel.stop.set()
        await kernel.control.close()
        await kernel.server.close()
        kernel.state.close()
        return response.get("credits", []), peer_uh.encode()

    credits, peer_uh = asyncio.run(scenario())
    match = [c for c in credits if c["user_hash"] == peer_uh.decode()]
    assert match, f"client row missing from {len(credits)} rows"
    assert match[0]["uploaded"] >= 60_000
