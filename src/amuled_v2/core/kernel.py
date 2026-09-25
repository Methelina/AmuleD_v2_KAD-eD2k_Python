"""AmuleD unified kernel (stage U): listener + spider + state in ONE process.

Phase 2 of the unification: the kernel owns ONE permanent DuckDB connection
and runs every subsystem as an asyncio task — the KAD spider maturation loop
(``core.kad.spider.SpiderEngine``), the incoming peer listener (uploads),
the KAD source republication loop and a JSON-lines IPC control server for
the CLI.  With the kernel running there are NO competing DB openers left:
the standalone spider script is not needed (and cannot open the locked db —
by design; run the kernel instead).

The CLI talks to the kernel over ``db/kernel_status.json`` → control port;
commands without a kernel fall back to direct DuckDB access (open/close).

src/amuled_v2/core/kernel.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-25

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] AmuleDKernel: owned StateBackend (permanent connection), SpiderEngine
      task, listener traffic recorder on the owned backend, republish loop,
      control handlers (status/spider.status/credits.*/share.list/stop).
  [+] run_kernel() lifecycle with graceful shutdown (state closed last).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any, Callable

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

ROOT = Path(__file__).resolve().parents[3]
configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled.jsonl",
)

from amuled_v2.config import load_config
from amuled_v2.core.identity import load_identity
from amuled_v2.core.kad.publish import SourcePublisher
from amuled_v2.core.kad.runtime import (
    bootstrap_runtime,
    load_kad_runtime,
    load_kadabra_state,
    save_kadabra_state,
)
from amuled_v2.core.kad.spider import SpiderEngine
from amuled_v2.core.kernel_control import (
    KERNEL_STATUS_PATH,
    KernelControlServer,
    _write_json_atomic,
)
from amuled_v2.core.peer.listener import (
    IncomingPeerServer,
    StateSharedFileResolver,
)
from amuled_v2.core.upload.engine import UploadThrottle
from amuled_v2.core.upload.queue import UploadQueue
from amuled_v2.state import get_state

log = get_tagged_logger(LogTags.DAEMON, "core.kernel")

STATUS_INTERVAL_S = 10.0


class AmuleDKernel:
    """One process: owned DuckDB connection + spider + listener + IPC."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        # THE permanent connection: nothing else in this process opens the
        # db, and no other process can while the kernel runs (by design).
        self.state = get_state()
        self.state.connect()
        self.identity = load_identity()
        cfg = load_config()
        serve_cfg = cfg.get("serve") or {}
        self.bind_host = str(serve_cfg.get("bind_host") or "0.0.0.0")
        self.max_sessions = int(serve_cfg.get("max_sessions") or 64)
        self.upload_slots = int(serve_cfg.get("upload_slots") or 4)
        self.throttle_rate = int(serve_cfg.get("throttle_bytes_per_sec") or 0)
        self.republish_hours = float(serve_cfg.get("republish_hours") or 0.0)
        self.publish_limit = int(serve_cfg.get("publish_limit") or 0)
        self.stop = asyncio.Event()
        self.server: IncomingPeerServer | None = None
        self.control: KernelControlServer | None = None
        self.spider: SpiderEngine | None = None
        self.started_at = time.time()
        self.publish_box: dict[str, Any] = {}

    # -- subsystem pieces ---------------------------------------------------

    def _record_uploaded(self, user_hash_hex: str, uploaded: int) -> None:
        try:
            self.state.record_traffic(user_hash_hex, uploaded=uploaded)
        except Exception as exc:
            log.debug("credit accounting skipped: error=%s", exc)

    async def _publish_sources_once(self) -> dict[str, Any]:
        """KAD source-publish pass advertising our bound TCP port."""
        from amuled_v2.core.kad.publish import PublishError

        rows = [
            r
            for r in self.state.list_shared_files(limit=100000)
            if r.get("path")
        ]
        limit = self.publish_limit if self.publish_limit > 0 else 100000
        rows = rows[:limit]
        if not rows:
            return {"status": "no_files", "published": 0, "accepts": 0}

        rt = load_kad_runtime()
        await bootstrap_runtime(rt, local_port=0)
        kadabra = load_kadabra_state()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 0))
        pub = SourcePublisher(
            own_id=rt.own_id,
            own_tcp_port=self._tcp_port,
            user_hash=self.identity.user_hash,
        )
        published = 0
        accepts = 0
        try:
            for row in rows:
                try:
                    report = await pub.publish_sources(
                        bytes.fromhex(row["hash"]),
                        [(0, self._tcp_port, None)],
                        socket=sock,
                        routing_table=rt.routing,
                        file_size=int(row["size"]),
                        timeout=self.args.publish_timeout,
                    )
                except PublishError as exc:
                    log.warning("republish: file=%s failed: %s", row["hash"], exc)
                    continue
                published += report.published
                accepts += len(report.accepts)
        finally:
            sock.close()
            save_kadabra_state(kadabra)
        result = {
            "status": "ok",
            "files": len(rows),
            "published": published,
            "accepts": accepts,
        }
        log.info(
            "republish: pass complete files=%d published=%d accepts=%d",
            len(rows), published, accepts,
        )
        return result

    async def _republish_loop(self) -> None:
        if self.republish_hours <= 0:
            return
        while not self.stop.is_set():
            try:
                self.publish_box.update(await self._publish_sources_once())
            except Exception as exc:
                log.error("republish: pass failed: %r", exc)
                self.publish_box.update({"status": "error", "reason": str(exc)})
            try:
                await asyncio.wait_for(
                    self.stop.wait(), timeout=self.republish_hours * 3600
                )
            except asyncio.TimeoutError:
                continue

    # -- control handlers ----------------------------------------------------

    def _handlers(self) -> dict[str, Callable[[dict], dict[str, Any]]]:
        def ctl_status(_req: dict) -> dict[str, Any]:
            spider = self.spider.status_snapshot() if self.spider else None
            return {
                "serve_port": self._tcp_port,
                "active_connections": (
                    self.server.active_connections if self.server else 0
                ),
                "uptime_s": int(time.time() - self.started_at),
                "republish": dict(self.publish_box) if self.publish_box else None,
                "spider": spider,
            }

        def ctl_credits_list(_req: dict) -> dict[str, Any]:
            return {"credits": self.state.list_credits(limit=100)}

        def ctl_credits_get(req: dict) -> dict[str, Any]:
            return {"credits": self.state.get_credits(str(req.get("user_hash", "")))}

        def ctl_share_list(req: dict) -> dict[str, Any]:
            limit = int(req.get("limit") or 100)
            return {"files": self.state.list_shared_files(limit=limit)}

        def ctl_share_count(_req: dict) -> dict[str, Any]:
            rows = self.state.list_shared_files(limit=100000)
            return {"count": len([r for r in rows if r.get("path")])}

        def ctl_stop(_req: dict) -> dict[str, Any]:
            self.stop.set()
            return {"stopping": True}

        return {
            "status": ctl_status,
            "spider.status": lambda req: {"spider": (
                self.spider.status_snapshot() if self.spider else None
            )},
            "credits.list": ctl_credits_list,
            "credits.get": ctl_credits_get,
            "share.list": ctl_share_list,
            "share.count": ctl_share_count,
            "stop": ctl_stop,
        }

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> int:
        identity = load_identity()
        tcp_port = identity.tcp_port
        queue = UploadQueue(max_slots=self.upload_slots)
        throttle = UploadThrottle(self.throttle_rate) if self.throttle_rate > 0 else None

        # Own the state BEFORE binding anything: with the permanent
        # connection taken, no other process can open the db mid-cycle.
        log.info(
            "kernel state owned: db=%s backend=%s",
            self.state.db_path, self.state.backend,
        )

        self.server = IncomingPeerServer(
            identity=identity.to_local_identity(),
            resolver=StateSharedFileResolver(lambda: self.state),
            upload_queue=queue,
            host=self.bind_host,
            port=tcp_port,
            throttle=throttle,
            max_connections=self.max_sessions,
            traffic_recorder=self._record_uploaded,
        )
        await self.server.start()
        self._tcp_port = self.server.bound_port
        # The HELLOANSWER must advertise the port that is actually listening.
        self.server._identity = identity.to_local_identity(tcp_port=self._tcp_port)

        if not self.args.no_spider:
            self.spider = SpiderEngine(
                ROOT,
                state_backend=self.state,
                verbose=False,
            )
            spider_task = asyncio.create_task(self.spider.run(self.stop))
        else:
            spider_task = asyncio.create_task(self.stop.wait())

        if not self.args.no_publish:
            republish_task = asyncio.create_task(self._republish_loop())
        else:
            republish_task = asyncio.create_task(self.stop.wait())

        self.control = KernelControlServer(self._handlers())
        await self.control.start()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop.set)
            except (NotImplementedError, RuntimeError):
                pass

        async def _status_loop() -> None:
            while not self.stop.is_set():
                try:
                    _write_json_atomic(
                        KERNEL_STATUS_PATH,
                        {
                            "running": True,
                            "pid": os.getpid(),
                            "serve_port": self._tcp_port,
                            "control_port": self.control.port,
                            "spider": bool(self.args.no_spider is False),
                        },
                    )
                except OSError as exc:
                    log.warning("kernel_status write failed: %s", exc)
                try:
                    await asyncio.wait_for(
                        self.stop.wait(), timeout=STATUS_INTERVAL_S
                    )
                except asyncio.TimeoutError:
                    continue

        status_task = asyncio.create_task(_status_loop())
        log.info(
            "kernel up: serve=%s:%d control=%d spider=%s republish_h=%s",
            self.bind_host, self._tcp_port, self.control.port,
            "off" if self.args.no_spider else "on",
            self.republish_hours or "once",
        )

        try:
            await self.stop.wait()
        except KeyboardInterrupt:
            log.info("kernel: KeyboardInterrupt, shutting down")
        finally:
            self.stop.set()
            for task in (status_task, spider_task, republish_task):
                task.cancel()
            await self.control.close()
            try:
                KERNEL_STATUS_PATH.unlink()
            except OSError:
                pass
            await self.server.close()
            for task in (status_task, spider_task, republish_task):
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            # State closes LAST: every subsystem above used it.
            try:
                self.state.close()
            except Exception:
                pass
            log.info("kernel stopped cleanly")
        return 0


def run_kernel(args: argparse.Namespace) -> int:
    """Entry point for the launcher; runs the kernel until stopped."""
    if getattr(args, "once", False):
        identity = load_identity()
        if identity.tcp_port <= 0:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "reason": "--once needs identity.tcp_port > 0 "
                        "(no listener is started, so there is no bound port "
                        "to advertise)",
                    },
                    ensure_ascii=False,
                )
            )
            return 2
        cfg = load_config()
        limit = int((cfg.get("serve") or {}).get("publish_limit") or 0)

        async def _once() -> dict[str, Any]:
            state = get_state()
            state.connect()
            try:
                kernel = AmuleDKernel.__new__(AmuleDKernel)
                kernel.args = args
                kernel.state = state
                kernel.identity = identity
                kernel.publish_limit = limit
                kernel.republish_hours = 0.0
                kernel.publish_box = {}
                kernel._tcp_port = identity.tcp_port
                kernel.started_at = time.time()
                return await kernel._publish_sources_once()
            finally:
                state.close()

        result = asyncio.run(_once())
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("status") == "ok" else 2

    try:
        return asyncio.run(AmuleDKernel(args).run())
    except KeyboardInterrupt:
        log.info("kernel interrupted")
        return 0


if __name__ == "__main__":
    sys.exit(run_kernel(argparse.Namespace(no_spider=False, no_publish=False,
                                        publish_limit=0, publish_timeout=25.0,
                                        once=False)))