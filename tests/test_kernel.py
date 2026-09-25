"""Stage U phase 1 tests: kernel control server and CLI routing pieces.

Author: Soror L.'.L.'.
Updated: 2026-09-25
"""

from __future__ import annotations

import asyncio
import json

from amuled_v2.core.kernel import (
    KERNEL_STATUS_PATH,
    KernelControlServer,
    control_request,
    read_kernel_status,
)


def test_control_server_roundtrip_and_unknown_command() -> None:
    async def scenario() -> None:
        server = KernelControlServer(
            {
                "ping": lambda: {"pong": True},
                "echo.credits": lambda: {"credits": [{"user_hash": "A" * 32}]},
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
        "amuled_v2.core.kernel.KERNEL_STATUS_PATH", tmp_path / "kernel_status.json"
    )
    from amuled_v2.core import kernel as kernel_module

    assert read_kernel_status() is None  # missing file

    kernel_module._write_json_atomic(
        kernel_module.KERNEL_STATUS_PATH,
        {"running": True, "pid": 1, "serve_port": 1234, "control_port": 5555},
    )
    status = read_kernel_status()
    assert status is not None
    assert status["control_port"] == 5555
    assert status["serve_port"] == 1234

    kernel_module._write_json_atomic(
        kernel_module.KERNEL_STATUS_PATH,
        {"running": False, "pid": 1, "control_port": 5555},
    )
    assert read_kernel_status() is None  # not running -> stale
