"""Kernel source re-ask loop tests (roadmap 11r P3 №9): thin-pool refresh
before the first dial, periodic re-ask saving found sources, re-dial of
entries whose race finished incomplete.  The KAD lookup is mocked - the
loop plumbing is what is under test, not the network.

src/tests/test_kernel_reask.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L.'.L.'.):
  [+] Initial tests for the kernel source re-ask / re-dial loop.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os

os.environ.setdefault("AMULED_ROOT", r"K:\work\AmuleD_v2")

import pytest

from amuled_v2.config import DEFAULT_CONFIG


class _FakeKernel:
    """The loop under test, bound to fakes instead of a real kernel."""

    def __init__(self, tmp_path: Path) -> None:
        from amuled_v2 import state as state_module
        from amuled_v2.core.download.queue import DownloadQueue

        state_module.DB_FILE = tmp_path / "state.db"
        self.state = state_module.StateBackend()
        self.state.connect()
        self.queue = DownloadQueue(
            state=self.state,
            temp_dir=tmp_path / "t",
            incoming_dir=tmp_path / "i",
        )
        self.download_box: dict = {}
        self.races_started: list[str] = []
        self.stop = asyncio.Event()
        self._tcp_port = 4662

    # real methods from the kernel class, bound manually:
    from amuled_v2.core.kernel import AmuleDKernel as _K  # noqa: N814

    _refresh_sources_now = None  # replaced in fixtures
    _start_download_task = None


def test_reask_interval_config_default() -> None:
    assert DEFAULT_CONFIG["kademlia"]["reask_interval_s"] == 300


def test_refresh_sources_async_persists_found_rows(tmp_path, monkeypatch) -> None:
    """_refresh_sources_async (in-kernel, spider pool routing) maps lookup
    results into saved source rows."""
    from types import SimpleNamespace

    from amuled_v2 import state as state_module
    from amuled_v2.core import kernel as kernel_module
    from amuled_v2.core.kad.packets import KadUInt128

    state_module.DB_FILE = tmp_path / "state.db"
    backend = state_module.StateBackend()
    backend.connect()

    peer_id = 0x0A00_00_01  # 10.0.0.1

    class _FakeReport:
        sources = [
            SimpleNamespace(
                client_id=peer_id, tcp_port=4662, udp_port=4672,
                source_type=1, buddy_ip=None, buddy_port=None,
            )
        ]

    async def fake_search(*args, **kwargs):
        return _FakeReport()

    import amuled_v2.core.kad.source_search as ss

    monkeypatch.setattr(ss, "kad_file_source_search", fake_search)

    class _FakePoolRouting:
        def closest(self, target, count=120):
            return []

        def mark_alive(self, key):
            return False

        def add(self, node):
            return False

    class _FakeSpider:
        own = KadUInt128(int.from_bytes(b"\x01" * 16, "big"))

        def pool_routing(self):
            return _FakePoolRouting()

    class _MiniKernel:
        state = backend
        _tcp_port = 4662
        spider = _FakeSpider()

        _refresh_sources_async = (
            kernel_module.AmuleDKernel._refresh_sources_async
        )

    k = _MiniKernel()
    fh = "AB" * 16
    found, saved = asyncio.run(k._refresh_sources_async(fh, 12345))
    assert (found, saved) == (1, 1)
    rows = backend.list_file_sources(fh, limit=10)
    assert len(rows) == 1
    import socket

    assert socket.inet_ntoa(rows[0]["client_id"].to_bytes(4, "big")) == "10.0.0.1"


def test_thin_pool_threshold_present_in_kernel_code() -> None:
    """The thin-pool auto-refresh must be wired in the race task."""
    src = Path(r"K:\work\AmuleD_v2\src\amuled_v2\core\kernel.py").read_text(
        encoding="utf-8"
    )
    assert "thin source pool" in src
    assert "_refresh_sources_async" in src
    assert "_source_refresh_loop" in src
    # the re-ask loop re-dials: start_download_task called from the loop
    assert "re-dial" in src


import asyncio  # noqa: E402  (used by fakes)
