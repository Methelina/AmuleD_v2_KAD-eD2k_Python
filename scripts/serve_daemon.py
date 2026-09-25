"""Incoming peer serve daemon (stage S): the listener as a background service.

Runs the incoming eD2K peer listener (``core.peer.listener``) as a permanent
service alongside the KAD spider:

  1. Loads the unified local identity (``core.identity``) — one userhash for
     both the HELLOANSWER handshake and KAD source publish (Prefs.cpp
     GetClientHash = GetUserHash).
  2. Binds an (optionally ephemeral) TCP port and serves upload sessions
     with a connection cap, per-session throttle and graceful shutdown.
  3. Writes a machine-readable status snapshot to ``db/serve_status.json``
      (pid, bound port, active connections) that other tools read
     while the daemon runs.  The KAD spider owns ``db/kad_status.json`` and
     rewrites it every cycle, so the serve port lives in its own file.
  4. Periodically republishes KAD source entries (STOREFILE, opcode 0x44)
     for the shared files, advertising the ACTUAL bound TCP port — remote
     clients can only dial us on a port that is really listening.

Usage (through the single runtime dispatcher, project doctrine):

    .\\AmuleD_Run.ps1 serve            # start daemon (Ctrl+C to stop)
    .\\AmuleD_Run.ps1 serve --once     # publish once, then exit

scripts/serve_daemon.py
Version:     0.1.0
Author:      Soror L'.L'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added serve daemon: IncomingPeerServer + identity from config +
      serve_status.json snapshot + periodic KAD source republication with
      the bound TCP port.
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
from typing import Any

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

ROOT = Path(__file__).resolve().parents[1]
configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled.jsonl",
)

from amuled_v2.config import load_config
from amuled_v2.core.identity import load_identity
from amuled_v2.core.kernel import (
    KERNEL_STATUS_PATH,
    KernelControlServer,
    _write_json_atomic,
)
from amuled_v2.core.kad.publish import SourcePublisher
from amuled_v2.core.kad.runtime import (
    bootstrap_runtime,
    load_kad_runtime,
    load_kadabra_state,
    save_kadabra_state,
)
from amuled_v2.core.peer.listener import (
    IncomingPeerServer,
    StateSharedFileResolver,
)
from amuled_v2.core.upload.engine import UploadThrottle
from amuled_v2.core.upload.queue import UploadQueue
from amuled_v2.state import get_state

log = get_tagged_logger(LogTags.DAEMON, "scripts.serve_daemon")

STATUS_PATH = ROOT / "db" / "serve_status.json"
STATUS_INTERVAL_S = 10.0


def _write_status(status: dict[str, Any]) -> None:
    tmp = STATUS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(STATUS_PATH)


async def _publish_sources_once(
    *,
    tcp_port: int,
    publish_limit: int,
    timeout: float,
    user_hash: bytes | None = None,
) -> dict[str, Any]:
    """One KAD source-publish pass advertising ``tcp_port`` for our files."""
    from amuled_v2.core.kad.publish import PublishError

    if user_hash is None:
        user_hash = load_identity().user_hash
    state = get_state()
    state.connect()
    try:
        limit = publish_limit if publish_limit > 0 else 100000
        rows = [
            r
            for r in state.list_shared_files(limit=100000)
            if r.get("path")
        ][:limit]
    finally:
        # Never hold the single-writer DuckDB longer than the listing:
        # the spider and CLI take turns on the same file.
        state.close()
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
        own_tcp_port=tcp_port,
        user_hash=user_hash,
    )
    published = 0
    accepts = 0
    try:
        for row in rows:
            file_hash = bytes.fromhex(row["hash"])
            try:
                report = await pub.publish_sources(
                    file_hash,
                    [(0, tcp_port, None)],
                    socket=sock,
                    routing_table=rt.routing,
                    file_size=int(row["size"]),
                    timeout=timeout,
                )
            except PublishError as exc:
                log.warning(
                    "republish: file=%s failed: %s", row["hash"], exc
                )
                continue
            published += report.published
            accepts += len(report.accepts)
    finally:
        sock.close()
        save_kadabra_state(kadabra)
    log.info(
        "republish: pass complete files=%d published=%d accepts=%d",
        len(rows),
        published,
        accepts,
    )
    return {
        "status": "ok",
        "files": len(rows),
        "published": published,
        "accepts": accepts,
    }


async def _republish_loop(
    stop: asyncio.Event,
    *,
    tcp_port: int,
    interval_hours: float,
    publish_limit: int,
    timeout: float,
    result_box: dict[str, Any],
) -> None:
    while not stop.is_set():
        try:
            result = await _publish_sources_once(
                tcp_port=tcp_port,
                publish_limit=publish_limit,
                timeout=timeout,
            )
            result_box.update(result)
        except Exception as exc:
            log.error("republish: pass failed: %r", exc)
            result_box.update({"status": "error", "reason": str(exc)})
        if interval_hours <= 0:
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_hours * 3600)
        except asyncio.TimeoutError:
            continue


async def _run(args: argparse.Namespace) -> int:
    cfg = load_config()
    serve_cfg = cfg.get("serve") or {}
    identity = load_identity()

    bind_host = str(serve_cfg.get("bind_host") or "0.0.0.0")
    max_sessions = int(serve_cfg.get("max_sessions") or 64)
    upload_slots = int(serve_cfg.get("upload_slots") or 4)
    throttle_rate = int(serve_cfg.get("throttle_bytes_per_sec") or 0)
    republish_hours = float(serve_cfg.get("republish_hours") or 0.0)
    publish_limit = int(serve_cfg.get("publish_limit") or 0)
    if args.publish_limit > 0:
        publish_limit = args.publish_limit
    if args.no_publish:
        republish_hours = -1.0  # disables the republish task

    resolver = StateSharedFileResolver(get_state)
    queue = UploadQueue(max_slots=upload_slots)
    throttle = UploadThrottle(throttle_rate) if throttle_rate > 0 else None

    def _record_uploaded(user_hash_hex: str, uploaded: int) -> None:
        """Stage C: attribute served bytes to the remote client's ledger.

        Opens/closes DuckDB per record (single-writer database shared with
        the spider), mirroring the StateSharedFileResolver pattern.
        """
        state = get_state()
        state.connect()
        try:
            state.record_traffic(user_hash_hex, uploaded=uploaded)
        finally:
            state.close()

    server = IncomingPeerServer(
        identity=identity.to_local_identity(),
        resolver=resolver,
        upload_queue=queue,
        host=bind_host,
        port=identity.tcp_port,
        throttle=throttle,
        max_connections=max_sessions,
        traffic_recorder=_record_uploaded,
    )
    await server.start()
    bound_port = server.bound_port
    # The HELLOANSWER must advertise the port that is actually listening.
    server._identity = identity.to_local_identity(tcp_port=bound_port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            # Windows fallback: KeyboardInterrupt in asyncio.run.
            pass

    # Kernel control server (stage U phase 1): CLI routes status/credits
    # queries here instead of fighting the spider for the DuckDB lock.
    def _ctl_status() -> dict[str, Any]:
        return {
            "port": bound_port,
            "active_connections": server.active_connections,
            "uptime_s": int(time.time() - started_at),
            "republish": dict(publish_box) if publish_box else None,
        }

    def _ctl_credits_list() -> dict[str, Any]:
        state = get_state()
        state.connect()
        try:
            return {"credits": state.list_credits(limit=100)}
        finally:
            state.close()

    control = KernelControlServer(
        {
            "status": _ctl_status,
            "credits.list": _ctl_credits_list,
        }
    )
    await control.start()

    started_at = time.time()
    publish_box: dict[str, Any] = {}

    if republish_hours >= 0:
        republish_task = asyncio.create_task(
            _republish_loop(
                stop,
                tcp_port=bound_port,
                interval_hours=republish_hours,
                publish_limit=publish_limit,
                timeout=args.publish_timeout,
                result_box=publish_box,
            )
        )
    else:
        republish_task = asyncio.create_task(stop.wait())

    async def _status_loop() -> None:
        while not stop.is_set():
            status = {
                "version": 2,
                "pid": os.getpid(),
                "running": True,
                "started_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%S", time.localtime(started_at)
                ),
                "uptime_s": int(time.time() - started_at),
                "host": bind_host,
                "port": bound_port,
                "control_port": control.port,
                "nick": identity.nickname,
                "max_sessions": max_sessions,
                "upload_slots": upload_slots,
                "throttle_bytes_per_sec": throttle_rate,
                "active_connections": server.active_connections,
                "last_publish": dict(publish_box) if publish_box else None,
            }
            try:
                _write_status(status)
                _write_json_atomic(
                    KERNEL_STATUS_PATH,
                    {
                        "running": True,
                        "pid": os.getpid(),
                        "serve_port": bound_port,
                        "control_port": control.port,
                    },
                )
            except OSError as exc:
                log.warning("status write failed: %s", exc)
            try:
                await asyncio.wait_for(stop.wait(), timeout=STATUS_INTERVAL_S)
            except asyncio.TimeoutError:
                continue

    status_task = asyncio.create_task(_status_loop())

    log.info(
        "serve daemon up: host=%s port=%d max_sessions=%d slots=%d "
        "throttle=%s republish_h=%s",
        bind_host,
        bound_port,
        max_sessions,
        upload_slots,
        throttle_rate or "none",
        republish_hours or "once",
    )

    try:
        await stop.wait()
    except KeyboardInterrupt:
        log.info("serve daemon: KeyboardInterrupt, shutting down")
    finally:
        stop.set()
        status_task.cancel()
        republish_task.cancel()
        await control.close()
        try:
            KERNEL_STATUS_PATH.unlink()
        except OSError:
            pass
        await server.close()
        final = {
            "version": 2,
            "pid": os.getpid(),
            "running": False,
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(started_at)
            ),
            "uptime_s": int(time.time() - started_at),
            "host": bind_host,
            "port": bound_port,
        }
        try:
            _write_status(final)
        except OSError:
            pass
        for task in (status_task, republish_task):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        log.info("serve daemon stopped cleanly")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AmuleD v0.5.1 incoming peer serve daemon (stage S)."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single KAD source-publish pass and exit (no listener).",
    )
    parser.add_argument(
        "--publish-timeout",
        type=float,
        default=25.0,
        help="Lookup window per file during the publish pass (seconds).",
    )
    parser.add_argument(
        "--publish-limit",
        type=int,
        default=0,
        help="Max shared files per publish pass (0 = config value).",
    )
    parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Disable the KAD source republication loop entirely.",
    )
    args = parser.parse_args()

    if args.once:
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
        result = asyncio.run(
            _publish_sources_once(
                tcp_port=identity.tcp_port,
                publish_limit=int(
                    (load_config().get("serve") or {}).get("publish_limit") or 0
                ),
                timeout=args.publish_timeout,
            )
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("status") == "ok" else 2

    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        log.info("serve daemon interrupted")
        return 0


if __name__ == "__main__":
    sys.exit(main())
