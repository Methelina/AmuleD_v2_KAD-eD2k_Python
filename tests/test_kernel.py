"""Stage U tests: kernel control, status snapshot, owned-state vertical slice.

Author: Soror L.'.L.'.
Updated: 2026-09-25
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

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


# --- stage U phase 3: read-only/queue handlers over IPC -------------------------


def _make_kernel(tmp_path):
    """Bare AmuleDKernel with an owned connected state (no subsystems)."""
    from amuled_v2.state import get_state

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
        "Id", (), {"user_hash": bytes.fromhex("D" * 32)},
    )()
    kernel.started_at = 0.0
    kernel.publish_box = {}
    kernel.download_box = {}
    kernel._download_tasks = set()
    kernel.stop = asyncio.Event()
    kernel.spider = None
    kernel._tcp_port = 0
    return kernel


def test_kernel_ipc_phase3_handlers(tmp_path, monkeypatch) -> None:
    """search.results.*, sources.list, download.list/add, servers.failures,
    ipfilter.status all answer over IPC from the kernel-owned connection."""
    from amuled_v2.core.codec.tags import Ed2kTag
    from amuled_v2.core.ed2k.server_client import (
        FoundSource,
        FoundSources,
        SearchResult,
        SearchResultsBatch,
    )
    from amuled_v2.core.kernel_control import KernelControlServer, control_request

    # Hermetic db: fresh file, fresh singleton (canonical tests/state pattern).
    import amuled_v2.state as state_module

    monkeypatch.setattr(state_module, "DB_FILE", tmp_path / "state.db")
    monkeypatch.setattr(state_module, "_state", None)
    # Part files must land in tmp too (kernel.py imports these by value).
    import amuled_v2.core.kernel as kernel_module

    monkeypatch.setattr(kernel_module, "TEMP_DIR", tmp_path / "temp")
    monkeypatch.setattr(kernel_module, "INCOMING_DIR", tmp_path / "incoming")

    kernel = _make_kernel(tmp_path)
    state = kernel.state

    file_hash = ("ab" * 16)
    state.save_search_results_batch(
        SearchResultsBatch(
            query="ubuntu",
            channel="server",
            server_host="1.2.3.4",
            server_port=4711,
            results=(
                SearchResult(
                    file_hash=bytes.fromhex(file_hash),
                    client_id=0x01020304,
                    client_port=4662,
                    tags=(
                        Ed2kTag(name_id=0x01, type=2, value="ubuntu-24.04.iso"),
                        Ed2kTag(name_id=0x02, type=3, value=5_000_000),
                        Ed2kTag(name_id=0x15, type=3, value=3),
                    ),
                ),
            ),
        )
    )
    state.save_found_sources(
        FoundSources(
            file_hash=bytes.fromhex(file_hash),
            sources=(FoundSource(client_id=0x01020304, client_port=4661),),
        ),
        server_ip="1.2.3.4",
        server_port=4711,
    )
    state.record_server_failure("9.9.9.9", 4661, reason="test")

    async def scenario() -> None:
        control = KernelControlServer(kernel._handlers())
        await control.start()
        try:
            port = control.port

            listed = await control_request(
                port,
                {"command": "search.results.list", "query": "ubuntu"},
                timeout=15.0,
            )
            assert listed["status"] == "ok"
            assert listed["result_count"] == 1
            assert listed["results"][0]["hash"].lower() == file_hash

            shown = await control_request(
                port, {"command": "search.results.show", "hash": file_hash},
                timeout=15.0,
            )
            assert shown["tag_count"] == 3
            assert shown["status"] in ("ok", "not_found")

            sources = await control_request(
                port, {"command": "sources.list", "hash": file_hash},
                timeout=15.0,
            )
            assert sources["source_count"] == 1
            assert sources["sources"][0]["client_port"] == 4661

            added = await control_request(
                port,
                {
                    "command": "download.add",
                    "link": (
                        "ed2k://|file|ubuntu-24.04.iso|5000000|"
                        f"{file_hash}|/"
                    ),
                },
                timeout=15.0,
            )
            assert added["status"] == "ok", added
            assert added["hash"].lower() == file_hash
            assert added["queue"] == "queued"

            downloads = await control_request(
                port, {"command": "download.list"}, timeout=15.0,
            )
            assert downloads["download_count"] == 1
            assert downloads["downloads"][0]["hash"].lower() == file_hash

            paused = await control_request(
                port, {"command": "download.pause", "hash": file_hash},
                timeout=15.0,
            )
            assert paused["status"] == "ok"
            assert paused["queue"] == "paused"

            resumed = await control_request(
                port, {"command": "download.resume", "hash": file_hash},
                timeout=15.0,
            )
            assert resumed["status"] == "ok"
            assert resumed["queue"] == "downloading"

            cancelled = await control_request(
                port, {"command": "download.cancel", "hash": file_hash},
                timeout=15.0,
            )
            assert cancelled["status"] == "ok"
            # part file + its sidecar (PART_SIDECAR_SUFFIX)
            assert cancelled["files_removed"] == 2

            empty = await control_request(
                port, {"command": "download.list"}, timeout=15.0,
            )
            assert empty["download_count"] == 0

            missing = await control_request(
                port, {"command": "download.pause", "hash": "ee" * 16},
                timeout=15.0,
            )
            assert missing["status"] == "error"

            refused = await control_request(
                port,
                {
                    "command": "download.add",
                    "link": (
                        "ed2k://|file|preteen nude|10|"
                        + ("cd" * 16) + "|/"
                    ),
                },
                timeout=15.0,
            )
            # The kernel gate refuses CSAM-marked names regardless of client.
            assert refused["status"] == "error"

            servers = await control_request(
                port, {"command": "servers.failures"}, timeout=15.0,
            )
            assert servers["tracked_count"] == 1
            assert servers["tracked"][0]["ip"] == "9.9.9.9"

            ipfilter = await control_request(
                port, {"command": "ipfilter.status"}, timeout=15.0,
            )
            assert ipfilter["status"] == "ok"
            assert "range_count" in ipfilter
            assert "path" in ipfilter

            cleared = await control_request(
                port,
                {"command": "search.results.clear", "query": "ubuntu"},
                timeout=15.0,
            )
            assert cleared["removed"] == 1
        finally:
            await control.close()
            kernel.state.close()

    asyncio.run(scenario())


# --- stage X: NAT helpers --------------------------------------------------------


def test_nat_default_gateway_lookup() -> None:
    from amuled_v2.core.nat.upnp import _default_gateway

    gw = _default_gateway()
    if gw is not None:
        parts = gw.split(".")
        assert len(parts) == 4
        for p in parts:
            assert p.isdigit() and 0 <= int(p) <= 255


def test_nat_map_tcp_port_never_raises() -> None:
    from amuled_v2.core.nat.upnp import map_tcp_port

    async def scenario() -> None:
        result = await map_tcp_port(0)
        assert isinstance(result, dict)
        assert "ok" in result

    asyncio.run(asyncio.wait_for(scenario(), timeout=30))


def test_kernel_ipc_download_run_end_to_end(tmp_path, monkeypatch) -> None:
    """download.run over IPC: the kernel races peers against its own
    listener on loopback; download.status polls progress; the finalized
    file MD4-verifies against the source bytes."""
    from amuled_v2.core.ed2k.server_client import (
        FoundSource,
        FoundSources,
    )
    from amuled_v2.core.hashes.ed2k import ed2k_hash_file
    from amuled_v2.core.kernel_control import KernelControlServer, control_request
    from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
    from amuled_v2.core.sharing.shared_files import SharedFile
    from amuled_v2.core.upload.queue import UploadQueue

    import amuled_v2.state as state_module

    monkeypatch.setattr(state_module, "DB_FILE", tmp_path / "state.db")
    monkeypatch.setattr(state_module, "_state", None)
    import amuled_v2.core.kernel as kernel_module

    monkeypatch.setattr(kernel_module, "TEMP_DIR", tmp_path / "temp")
    monkeypatch.setattr(kernel_module, "INCOMING_DIR", tmp_path / "incoming")
    (tmp_path / "temp").mkdir()

    source_bytes = os.urandom(60_000)
    path = tmp_path / "dl_e2e.bin"
    path.write_bytes(source_bytes)
    hashed = ed2k_hash_file(str(path))
    file_hash = hashed.file_hash
    file_hash_hex = file_hash.hex()
    shared = SharedFile(
        file_hash=file_hash,
        name=path.name,
        size=hashed.file_size,
        path=str(path),
        hash_result=hashed,
    )

    class _Resolver:
        def __init__(self, shared: SharedFile) -> None:
            self._shared = shared

        def resolve(self, file_hash: bytes) -> SharedFile | None:
            if file_hash == self._shared.file_hash:
                return self._shared
            return None

    async def scenario() -> dict:
        from amuled_v2.state import get_state

        kernel = _make_kernel(tmp_path)
        # Loopback self-dial: our listener is plain-only (obf accept is
        # BLOCKED-EXTERNAL), so the runner must accept no-userhash rows.
        kernel.plain_dial_ok = True
        state = kernel.state
        kernel.server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=bytes.fromhex("D" * 32),
                client_id=1,
                tcp_port=0,
                nickname="kernel-dl-e2e",
            ),
            resolver=_Resolver(shared),
            upload_queue=UploadQueue(max_slots=2),
            host="127.0.0.1",
            port=0,
            idle_timeout=10.0,
            traffic_recorder=kernel._record_uploaded,
        )
        await kernel.server.start()
        serve_port = kernel.server.bound_port
        kernel._tcp_port = serve_port
        kernel.control = KernelControlServer(kernel._handlers())
        await kernel.control.start()
        port = kernel.control.port

        try:
            # Queue the download via IPC (creates the part file), then point
            # it at the kernel's own listener.
            added = await control_request(
                port,
                {
                    "command": "download.add",
                    "link": (
                        f"ed2k://|file|{path.name}|{hashed.file_size}|"
                        f"{file_hash_hex}|/"
                    ),
                },
                timeout=15.0,
            )
            assert added["status"] == "ok", added
            state.save_found_sources(
                FoundSources(
                    file_hash=file_hash,
                    sources=(
                        FoundSource(client_id=0x7F000001, client_port=serve_port),
                    ),
                ),
                server_ip="127.0.0.1",
                server_port=1,
            )

            started = await control_request(
                port,
                {"command": "download.run", "hash": file_hash_hex,
                 "max_peers": 2},
                timeout=15.0,
            )
            assert started["status"] == "ok", started
            assert started["started"] is True

            deadline = asyncio.get_event_loop().time() + 90.0
            status: dict = {}
            while asyncio.get_event_loop().time() < deadline:
                await asyncio.sleep(0.5)
                status = await control_request(
                    port, {"command": "download.status", "hash": file_hash_hex},
                    timeout=15.0,
                )
                if status.get("done"):
                    break
            assert status.get("done"), f"download did not finish: {status}"
            assert status.get("status") == "complete", status
            finalized = status.get("finalized") or {}
            assert finalized.get("verified") is True, finalized
            target = Path(finalized.get("target", ""))
            if target.exists():
                assert target.read_bytes() == source_bytes
            return status
        finally:
            kernel.stop.set()
            await kernel.control.close()
            await kernel.server.close()
            state.close()

    status = asyncio.run(scenario())
    assert status["status"] == "complete"
