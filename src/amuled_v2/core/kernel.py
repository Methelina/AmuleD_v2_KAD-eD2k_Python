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
Version:     0.3.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] Stage U phase 3 control handlers: search.results.list/show/clear,
      sources.list, download.list/add, servers.failures, ipfilter.status —
      read-only CLI now works under a live kernel (no DuckDB lock fight).
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
from amuled_v2.paths import INCOMING_DIR, TEMP_DIR
from amuled_v2.state import get_state

log = get_tagged_logger(LogTags.DAEMON, "core.kernel")

STATUS_INTERVAL_S = 10.0

IPFILTER_PATH = ROOT / "assets" / "v1" / "ipfilter.dat"


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
        nat_cfg = cfg.get("nat") or {}
        self.nat_enabled = bool(nat_cfg.get("enabled", True))
        self.stop = asyncio.Event()
        self.server: IncomingPeerServer | None = None
        self.control: KernelControlServer | None = None
        self.spider: SpiderEngine | None = None
        self.upload_queue: UploadQueue | None = None
        self.nat_result: dict[str, Any] | None = None
        self.started_at = time.time()
        self.publish_box: dict[str, Any] = {}
        # In-kernel download runs (stage U phase 3 / downloads end-to-end):
        # the runner needs the owned DuckDB connection, so download.run is
        # executed HERE as an asyncio task; the CLI only starts and polls.
        self.download_box: dict[str, dict[str, Any]] = {}
        self._download_tasks: set[asyncio.Task] = set()

    # -- subsystem pieces ---------------------------------------------------

    def _record_uploaded(self, user_hash_hex: str, uploaded: int) -> None:
        try:
            self.state.record_traffic(user_hash_hex, uploaded=uploaded)
        except Exception as exc:
            log.debug("credit accounting skipped: error=%s", exc)

    def _record_downloaded(self, user_hash_hex: str, downloaded: int) -> None:
        try:
            self.state.record_traffic(user_hash_hex, downloaded=downloaded)
        except Exception as exc:
            log.debug("credit accounting skipped: error=%s", exc)

    def _credit_bonus(self, user_hash: str) -> float:
        """eMule credits -> upload queue priority (stage X).

        Bonus = uploaded/downloaded ratio seen from THIS client (what the
        client gave us vs took), capped at 10.0; clients unknown or with no
        history sit at 1.0. Refreshed on every queue recompute.
        """
        try:
            row = self.state.get_credits(user_hash)
        except Exception:
            return 1.0
        if not row:
            return 1.0
        up = float(row.get("uploaded") or 0)
        down = float(row.get("downloaded") or 0)
        if down <= 0:
            return 10.0 if up > 0 else 1.0
        return min(10.0, 1.0 + up / down)

    def _download_queue(self) -> Any:
        """DownloadQueue on the OWNED state connection (no re-open)."""
        from amuled_v2.core.download.queue import DownloadQueue

        return DownloadQueue(
            state=self.state, temp_dir=TEMP_DIR, incoming_dir=INCOMING_DIR
        )

    def _start_download_task(self, file_hash: str, max_peers: int) -> dict[str, Any]:
        """Launch an in-kernel download race; status lands in download_box."""
        if file_hash in self.download_box and not self.download_box[file_hash].get("done"):
            return {"started": False, "reason": "already running", "hash": file_hash}
        entry = self._download_queue().get(file_hash)
        if entry is None:
            return {"started": False, "reason": "download not found", "hash": file_hash}
        box: dict[str, Any] = {
            "done": False,
            "status": "running",
            "received": 0,
            "total": int(entry["size"]),
            "blocks": 0,
            "started_at": time.time(),
        }
        self.download_box[file_hash] = box

        async def _task() -> None:
            from amuled_v2.core.download.runner import DownloadRunner

            try:
                queue = self._download_queue()
                runner = DownloadRunner(
                    queue,
                    local_port=self._tcp_port,
                    max_peers=max_peers,
                    traffic_sink=self._record_downloaded,
                    plain_dial_ok=getattr(self, "plain_dial_ok", False),
                )

                def _progress(received: int, total: int, blocks: int) -> None:
                    box.update({"received": received, "total": total, "blocks": blocks})

                result = await runner.run(file_hash, progress_callback=_progress)
                box.update({"done": True, **result})
            except Exception as exc:
                log.warning("download task failed: hash=%s, error=%r", file_hash, exc)
                box.update({"done": True, "status": "error", "reason": repr(exc)})

        task = asyncio.create_task(_task(), name=f"dl-run-{file_hash[:8]}")
        self._download_tasks.add(task)
        task.add_done_callback(self._download_tasks.discard)
        log.info("download task started: hash=%s, max_peers=%d", file_hash, max_peers)
        return {"started": True, "hash": file_hash}

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

        # -- stage U phase 3: read-only/queue commands served from the owned
        #    connection so the CLI works while the kernel holds the db lock.

        def ctl_search_results_list(req: dict) -> dict[str, Any]:
            limit = int(req.get("limit") or 100)
            rows = self.state.list_search_results(
                query=req.get("query") or None,
                channel=req.get("channel") or None,
                hash_prefix=req.get("hash") or None,
                limit=limit,
            )
            return {"results": rows, "result_count": len(rows), "limit": limit}

        def ctl_search_results_show(req: dict) -> dict[str, Any]:
            file_hash = str(req.get("hash", "")).lower()
            tags = self.state.get_search_result_tags(file_hash)
            return {
                "status": "ok" if tags else "not_found",
                "hash": file_hash,
                "tags": tags,
                "tag_count": len(tags),
            }

        def ctl_search_results_clear(req: dict) -> dict[str, Any]:
            query = req.get("query") or None
            removed = self.state.clear_search_results(query=query)
            return {"removed": removed, "query": query}

        def ctl_sources_list(req: dict) -> dict[str, Any]:
            limit = int(req.get("limit") or 1000)
            file_hash = str(req.get("hash", "")).lower() or None
            rows = self.state.list_file_sources(file_hash, limit=limit)
            return {
                "file_hash": file_hash,
                "sources": rows,
                "source_count": len(rows),
                "limit": limit,
            }

        def ctl_download_list(req: dict) -> dict[str, Any]:
            entries = self._download_queue().list(limit=int(req.get("limit") or 100))
            return {"downloads": entries, "download_count": len(entries)}

        def ctl_download_lifecycle(req: dict, action: str) -> dict[str, Any]:
            queue = self._download_queue()
            if action == "pause":
                entry = queue.pause(str(req.get("hash", "")))
            elif action == "resume":
                entry = queue.resume(str(req.get("hash", "")))
            elif action == "start":
                entry = queue.start(str(req.get("hash", "")))
            else:
                raise ValueError(f"unknown lifecycle action: {action}")
            # entry["status"] is the QUEUE state; it must not override the
            # response status — it moves under the "queue" key (as in add).
            queue_status = entry.get("status")
            return {
                "status": "ok",
                "action": action,
                "queue": queue_status,
                **{k: v for k, v in entry.items() if k != "status"},
            }

        def ctl_download_cancel(req: dict) -> dict[str, Any]:
            summary = self._download_queue().cancel(
                str(req.get("hash", "")), keep_files=bool(req.get("keep_files"))
            )
            return {"status": "ok", **summary}

        def ctl_download_run(req: dict) -> dict[str, Any]:
            file_hash = str(req.get("hash", "")).lower()
            max_peers = int(req.get("max_peers") or 3)
            return self._start_download_task(file_hash, max_peers)

        def ctl_download_status(req: dict) -> dict[str, Any]:
            file_hash = str(req.get("hash", "")).lower()
            snapshot = self.download_box.get(file_hash)
            if snapshot is None:
                return {"status": "unknown", "hash": file_hash, "done": True}
            return {"hash": file_hash, **snapshot}

        def ctl_download_add(req: dict) -> dict[str, Any]:
            from amuled_v2.core.ed2k.links import parse_ed2k_file_link
            from amuled_v2.core.safety import ContentPolicyError, check_name_safe

            link = str(req.get("link", ""))
            parsed = parse_ed2k_file_link(link)
            # Content gate runs in the kernel too: an IPC client must not be
            # able to bypass the refusal that the CLI enforces locally.
            try:
                check_name_safe(parsed.name)
            except ContentPolicyError as exc:
                return {"status": "error", "action": "add", "reason": str(exc)}
            entry = self._download_queue().add(
                file_hash=parsed.file_hash.hex(),
                name=parsed.name,
                size=parsed.size,
            )
            # entry carries the QUEUE status ("queued"); the response status
            # stays "ok" — the queue state moves under the "queue" key.
            queue_status = entry.get("status")
            return {
                "status": "ok",
                "action": "add",
                "queue": queue_status,
                **{k: v for k, v in entry.items() if k != "status"},
            }

        def ctl_servers_failures(_req: dict) -> dict[str, Any]:
            blacklisted = self.state.list_blacklisted_servers()
            tracked = self.state.list_server_failures()
            return {
                "blacklisted": blacklisted,
                "tracked": tracked,
                "blacklisted_count": len(blacklisted),
                "tracked_count": len(tracked),
            }

        def ctl_ipfilter_status(_req: dict) -> dict[str, Any]:
            from amuled_v2.core.ipfilter import IpFilter, load_ipfilter_file

            try:
                ip_filter = load_ipfilter_file(IPFILTER_PATH)
            except FileNotFoundError:
                ip_filter = IpFilter()
            return {"path": str(IPFILTER_PATH), **ip_filter.statistics()}

        def ctl_upload_status(_req: dict) -> dict[str, Any]:
            if self.upload_queue is None:
                return {"snapshot": None, "reason": "listener not running"}
            return {"snapshot": self.upload_queue.snapshot()}

        return {
            "status": ctl_status,
            "spider.status": lambda req: {"spider": (
                self.spider.status_snapshot() if self.spider else None
            )},
            "credits.list": ctl_credits_list,
            "credits.get": ctl_credits_get,
            "share.list": ctl_share_list,
            "share.count": ctl_share_count,
            "search.results.list": ctl_search_results_list,
            "search.results.show": ctl_search_results_show,
            "search.results.clear": ctl_search_results_clear,
            "sources.list": ctl_sources_list,
            "download.list": ctl_download_list,
            "download.add": ctl_download_add,
            "download.pause": lambda req: ctl_download_lifecycle(req, "pause"),
            "download.resume": lambda req: ctl_download_lifecycle(req, "resume"),
            "download.start": lambda req: ctl_download_lifecycle(req, "start"),
            "download.cancel": ctl_download_cancel,
            "download.run": ctl_download_run,
            "download.status": ctl_download_status,
            "upload.status": ctl_upload_status,
            "servers.failures": ctl_servers_failures,
            "ipfilter.status": ctl_ipfilter_status,
            "stop": ctl_stop,
        }

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> int:
        identity = load_identity()
        tcp_port = identity.tcp_port
        queue = UploadQueue(
            max_slots=self.upload_slots, credit_bonus=self._credit_bonus
        )
        self.upload_queue = queue
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

        rotation_task: asyncio.Task | None = None
        if self.upload_queue is not None:

            async def _rotate() -> None:
                """Stage X upload parity: reclaim expired slots on a timer
                (rank/ttl bookkeeping continues while transfers run)."""
                while not self.stop.is_set():
                    try:
                        await asyncio.wait_for(
                            self.stop.wait(), timeout=30.0
                        )
                    except asyncio.TimeoutError:
                        pass
                    if self.stop.is_set() or self.upload_queue is None:
                        return
                    try:
                        expired = self.upload_queue.expired_slots()
                        for user_hash, file_hash in expired:
                            self.upload_queue.release_slot(user_hash, file_hash)
                        if expired:
                            log.info(
                                "UPLOAD slot rotation: reclaimed=%d",
                                len(expired),
                            )
                    except Exception as exc:
                        log.debug("slot rotation skipped: error=%s", exc)

            rotation_task = asyncio.create_task(_rotate(), name="slot-rotation")

        nat_task: asyncio.Task | None = None
        if self.nat_enabled:
            async def _nat() -> None:
                from amuled_v2.core.nat import map_tcp_port

                result = await map_tcp_port(self._tcp_port)
                self.nat_result = result
                if not result.get("ok"):
                    log.info(
                        "NAT mapping unavailable (lowid possible): detail=%s",
                        result,
                    )

            nat_task = asyncio.create_task(_nat(), name="nat-map")

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
            extra_tasks = tuple(
                t for t in (nat_task, rotation_task) if t is not None
            )
            for task in (status_task, spider_task, republish_task, *extra_tasks):
                task.cancel()
            if self.nat_result and self.nat_result.get("ok"):
                try:
                    from amuled_v2.core.nat import unmap_tcp_port

                    await asyncio.wait_for(
                        unmap_tcp_port(self._tcp_port), timeout=5.0
                    )
                except Exception as exc:
                    log.debug("NAT unmap skipped: error=%s", exc)
            await self.control.close()
            try:
                KERNEL_STATUS_PATH.unlink()
            except OSError:
                pass
            await self.server.close()
            for task in (status_task, spider_task, republish_task, *extra_tasks):
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