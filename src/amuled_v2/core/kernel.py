"""AmuleD unified kernel (stage U): one process owning state + listener + IPC.

Problem being solved: the spider daemon, the serve daemon and every CLI
invocation are separate OS processes fighting over the single-writer DuckDB
file lock (up to 20x1s retries each).  eMule solves this by running all
subsystems as threads of one process sharing in-memory objects; AmuleD moves
the same way.

Phase 1 (this file):
  - the kernel is the ONLY long-lived component for the listener side: it
    owns the identity, the incoming peer server, the KAD republication loop
    and a JSON-lines IPC control server on 127.0.0.1 (ephemeral port
    published in db/kernel_status.json);
  - CLI commands route read requests (status/credits/share) through IPC
    when the kernel is alive and fall back to direct DuckDB access
    otherwise;
  - DuckDB access stays open/close-per-operation until phase 2.

Phase 2 (planned):
  - the spider maturation cycle moves into the kernel and the kernel takes
    ONE permanent DuckDB connection; the spider script and per-process
    lock retries disappear.

src/amuled_v2/core/kernel.py
Version:     0.1.0
Author:      Soror L'.L'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added AmuleDKernel: listener + republish + IPC control server.
  [+] Added kernel_status.json snapshot (pid, serve port, control port).
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import time
from pathlib import Path
from typing import Any, Callable

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.DAEMON, "core.kernel")

ROOT = Path(__file__).resolve().parents[3]
KERNEL_STATUS_PATH = ROOT / "db" / "kernel_status.json"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    tmp.replace(path)


def read_kernel_status() -> dict[str, Any] | None:
    """Return the live kernel snapshot, or None when it is stale/dead."""
    try:
        status = json.loads(KERNEL_STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not status.get("running") or not status.get("control_port"):
        return None
    return status


async def control_request(
    port: int, request: dict[str, Any], *, timeout: float = 10.0
) -> dict[str, Any]:
    """One JSON-lines request/response against the kernel control server."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), timeout=timeout
    )
    try:
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            raise ConnectionError("kernel closed the control connection")
        return json.loads(line.decode("utf-8"))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass


def control_request_sync(
    port: int, request: dict[str, Any], *, timeout: float = 10.0
) -> dict[str, Any]:
    return asyncio.run(control_request(port, request, timeout=timeout))


class KernelControlServer:
    """JSON-lines request/response server for CLI commands (loopback only)."""

    def __init__(self, handlers: dict[str, Callable[[], dict[str, Any]]]) -> None:
        self._handlers = handlers
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client, "127.0.0.1", 0
        )
        info = self._server.sockets[0].getsockname()
        self.port = int(info[1])
        log.info("kernel control server listening: port=%d", self.port)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                try:
                    request = json.loads(line.decode("utf-8"))
                    name = str(request.get("command", ""))
                    handler = self._handlers.get(name)
                    if handler is None:
                        response = {
                            "status": "error",
                            "reason": f"unknown command: {name!r}",
                        }
                    else:
                        response = {"status": "ok", **handler()}
                except Exception as exc:
                    response = {"status": "error", "reason": repr(exc)}
                writer.write((json.dumps(response) + "\n").encode("utf-8"))
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass


def _state_traffic_recorder(
    user_hash_hex: str, uploaded: int
) -> None:
    """Stage C recorder: open, record, close (shared single-writer DB)."""
    from amuled_v2.state import get_state

    state = get_state()
    state.connect()
    try:
        state.record_traffic(user_hash_hex, uploaded=uploaded)
    finally:
        state.close()
