"""Offline tests for the eD2K server auto-connect session manager.

src/tests/test_server_session.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-29

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] ServerSessionManager hermetic tests: autoconnect gate, blacklist
      filtering, static-first priority ordering, failure accounting with
      start-position rotation, keepalive hold + snapshot, config fallback.
"""

from __future__ import annotations

import asyncio

from amuled_v2.core.ed2k.server_session import ServerSessionManager


class FakeState:
    def __init__(self, blacklisted: list[dict] | None = None):
        self.blacklisted = blacklisted or []
        self.failures: list[tuple[str, int, str]] = []
        self.successes: list[tuple[str, int]] = []

    def list_blacklisted_servers(self):
        return self.blacklisted

    def record_server_failure(self, ip, port, *, reason: str):
        self.failures.append((ip, port, reason))

    def record_server_success(self, ip, port):
        self.successes.append((ip, port))


class FakeClient:
    """Minimal Ed2kServerClient stand-in driven by scripted behavior."""

    def __init__(self, *, fail_connect: bool = False, fail_login: bool = False):
        self.fail_connect = fail_connect
        self.fail_login = fail_login
        self.logged_in = False
        self.is_connected = False
        self.pushes = 0
        self.closed = False

    async def connect(self):
        if self.fail_connect:
            raise OSError("simulated connect failure")
        self.is_connected = True

    async def login(self):
        if self.fail_login:
            raise OSError("simulated login failure")
        self.logged_in = True

    async def next_push(self, *, timeout: float) -> bool:
        self.pushes += 1
        if self.pushes <= 2:
            return False  # idle windows are normal
        raise OSError("simulated session loss")

    async def close(self):
        self.closed = True


class _Record:
    def __init__(self, ip: str, port: int, priority: int = 0):
        self.address = ip
        self.port = port
        self._priority = priority

    def priority(self) -> int:
        return self._priority


class _StaticRecord:
    """staticservers.dat shape: host field, priority as a plain int."""

    def __init__(self, ip: str, port: int, priority: int = 0):
        self.host = ip
        self.port = port
        self.priority = priority


def _make_manager(
    tmp_path,
    monkeypatch,
    *,
    servers_cfg: dict,
    state=None,
    static_records=None,
    met_records=None,
    factory_script=None,
):
    monkeypatch.setattr(
        "amuled_v2.core.ed2k.server_session.ServerSessionManager._load_static_records",
        lambda self, path: list(static_records or []),
    )
    monkeypatch.setattr(
        "amuled_v2.core.ed2k.server_session.ServerSessionManager._load_met_records",
        lambda self, path: list(met_records or []),
    )
    mgr = ServerSessionManager(
        state=state if state is not None else FakeState(),
        config_loader=lambda: {"servers": servers_cfg},
        tcp_port=9341,
        user_hash=b"\x11" * 16,
        nickname="AmuleD-test",
        client_factory=factory_script,
        root=tmp_path,
    )
    return mgr


def test_config_defaults_present() -> None:
    from amuled_v2.config import DEFAULT_CONFIG

    servers = DEFAULT_CONFIG["servers"]
    assert servers["autoconnect"] is True
    assert servers["retry_interval_s"] == 300
    assert servers["connect_timeout_s"] == 10
    assert servers["keepalive_timeout_s"] == 60


def test_candidates_static_first_priority_and_blacklist(tmp_path, monkeypatch) -> None:
    state = FakeState(
        blacklisted=[{"ip": "9.9.9.9", "port": 4711}]
    )
    mgr = _make_manager(
        tmp_path,
        monkeypatch,
        servers_cfg={"autoconnect": True},
        state=state,
        static_records=[_StaticRecord("1.1.1.1", 4662, priority=0)],
        met_records=[
            _Record("9.9.9.9", 4711, priority=10),   # blacklisted -> dropped
            _Record("2.2.2.2", 4711, priority=5),
            _Record("3.3.3.3", 4711, priority=9),
            _Record("1.1.1.1", 4662, priority=1),    # dup of static -> dropped
        ],
    )
    cands = mgr._build_candidates(
        {"server_met": "m.met", "static_servers": "s.dat"}
    )
    assert [(c[0], c[1]) for c in cands] == [
        ("1.1.1.1", 4662),
        ("3.3.3.3", 4711),
        ("2.2.2.2", 4711),
    ]
    assert cands[0][2] is True  # static first


def test_autoconnect_disabled_makes_no_attempts(tmp_path, monkeypatch) -> None:
    async def scenario():
        mgr = _make_manager(
            tmp_path,
            monkeypatch,
            servers_cfg={"autoconnect": False},
            static_records=[_Record("1.1.1.1", 4662)],
        )
        stop = asyncio.Event()
        task = asyncio.create_task(mgr.run(stop))
        await asyncio.sleep(0.2)
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        return mgr.snapshot()

    snap = asyncio.run(scenario())
    assert snap["autoconnect"] is False
    assert snap["attempts"] == 0
    assert snap["connected"] is False


def test_failures_recorded_and_rotation_advances(tmp_path, monkeypatch) -> None:
    state = FakeState()
    made: list[FakeClient] = []

    def factory(**kwargs):
        client = FakeClient(fail_connect=True)
        made.append(client)
        return client

    async def scenario():
        mgr = _make_manager(
            tmp_path,
            monkeypatch,
            servers_cfg={
                "autoconnect": True,
                "retry_interval_s": 0.05,
                "connect_timeout_s": 0.1,
            },
            state=state,
            met_records=[_Record("1.1.1.1", 4662), _Record("2.2.2.2", 4662)],
            factory_script=factory,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(mgr.run(stop))
        await asyncio.sleep(0.5)
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        return mgr.snapshot()

    snap = asyncio.run(scenario())
    assert snap["attempts"] >= 2
    assert len(state.failures) >= 2
    assert {f[0] for f in state.failures} == {"1.1.1.1", "2.2.2.2"}
    assert snap["connected"] is False
    assert snap["last_error"]


def test_success_holds_session_and_snapshots(tmp_path, monkeypatch) -> None:
    state = FakeState()
    made: list[FakeClient] = []

    def factory(**kwargs):
        client = FakeClient()
        made.append(client)
        return client

    async def scenario():
        mgr = _make_manager(
            tmp_path,
            monkeypatch,
            servers_cfg={
                "autoconnect": True,
                "retry_interval_s": 0.05,
                "connect_timeout_s": 0.1,
                "keepalive_timeout_s": 0.01,
            },
            state=state,
            static_records=[_Record("5.5.5.5", 4662)],
            factory_script=factory,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(mgr.run(stop))
        # Observe the first successful login, then stop while the session
        # is still held (before the scripted push-loss reconnects).
        for _ in range(200):
            await asyncio.sleep(0.01)
            snap = mgr.snapshot()
            if snap["logins"] >= 1:
                break
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        return mgr.snapshot()

    snap = asyncio.run(scenario())
    assert snap["logins"] >= 1
    assert snap["attempts"] >= 1
    assert state.successes and state.successes[0] == ("5.5.5.5", 4662)
    assert made[0].closed is True


def test_config_loader_error_falls_back_to_disabled(tmp_path, monkeypatch) -> None:
    async def scenario():
        mgr = ServerSessionManager(
            state=FakeState(),
            config_loader=lambda: (_ for _ in ()).throw(OSError("boom")),
            tcp_port=1,
            user_hash=b"\x11" * 16,
            nickname="t",
            root=tmp_path,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(mgr.run(stop))
        await asyncio.sleep(0.2)
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        return mgr.snapshot()

    snap = asyncio.run(scenario())
    assert snap["attempts"] == 0
    assert snap["connected"] is False
