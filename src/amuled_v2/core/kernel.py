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
Version:     0.4.2
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.4.2 (Soror L.'.L'.):
  [+] eMule periodic source re-ask + re-dial (roadmap 11r P3 №9): a
      kernel loop (kademlia.reask_interval_s, default 300s) refreshes KAD
      sources for every queued/download entry via the ephemeral-runtime
      lookup (same path as the CLI, executor-driven) and re-launches a
      race for entries whose previous race finished incomplete.  A thin
      source pool (<3 rows) now also triggers an automatic KAD refresh
      BEFORE the first dial - the "run with zero sources" failure mode is
      gone without any manual source injection.

Patch Notes v0.4.1 (Soror L.'.L'.):
  [+] Config parity wiring (roadmap 11r): the listener receives
      network.max_conn_per_5s (connection rate limit) and the download
      queue receives download.sparse_part_files; both resolved from the
      live config with logged fallbacks to the documented defaults.
  [+] ipfilter auto-update loop: when ipfilter.auto_update and
      ipfilter.update_url are configured, the kernel refreshes the filter
      list every update_period_days (last-update stamp in
      db\\ipfilter_update.json; refresh failures keep the existing list,
      logged per the fallback policy).

Patch Notes v0.4.0 (Soror L.'.L'.):
  [+] Control command "sources.save": the CLI persists KAD-found sources
      through the kernel (the DB owner) instead of opening its own DuckDB
      connection and losing the write to the lock (live 2026-09-28:
      lookup found 14 sources, saved=0, the follow-up download run then
      failed with "no known sources").

Patch Notes v0.3.0 (Soror L.'.L'.):
  [+] Stage U phase 3 control handlers: search.results.list/show/clear,
      sources.list, download.list/add, servers.failures, ipfilter.status —
      read-only CLI now works under a live kernel (no DuckDB lock fight).
Patch Notes v0.2.0 (Soror L.'.L'.):
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
        # Stage X SecureIdent: one RSA-384 provider for the whole kernel
        # (listener challenges incoming peers; DownloadRunner challenges on
        # outgoing dials).  Key file: config/cryptkey.dat (eMule format).
        from amuled_v2.core.security.secure_ident import SecureIdentProvider

        self.secure_ident = SecureIdentProvider(key_path=ROOT / "config" / "cryptkey.dat")
        self.secure_ident.ensure_keys()
        self.started_at = time.time()
        self.publish_box: dict[str, Any] = {}
        # In-kernel download runs (stage U phase 3 / downloads end-to-end):
        # the runner needs the owned DuckDB connection, so download.run is
        # executed HERE as an asyncio task; the CLI only starts and polls.
        self.download_box: dict[str, dict[str, Any]] = {}
        self._download_tasks: set[asyncio.Task] = set()

    # -- subsystem pieces ---------------------------------------------------

    def _source_provider(self, file_hash: bytes) -> list:
        """SX answer rows: known dialable sources for the file (stage X).

        High-id rows with a userhash only — a source without a userhash
        cannot be dialed obfuscated on today's network, so advertising it
        would be noise (mirrors DownloadRunner.resolve_sources).
        """
        from amuled_v2.core.peer.codec import SXSource
        from amuled_v2.core.download.runner import _row_not_directly_dialable

        try:
            rows = self.state.list_file_sources(file_hash.hex(), limit=500)
        except Exception as exc:
            log.debug("SX source lookup failed: error=%s", exc)
            return []
        out = []
        for row in rows:
            if _row_not_directly_dialable(row):
                continue
            try:
                client_id = int(row["client_id"])
                user_hash = row.get("user_hash")
                out.append(
                    SXSource(
                        client_id=client_id,
                        port=int(row["client_port"]),
                        user_hash=bytes.fromhex(str(user_hash)) if user_hash else None,
                    )
                )
            except Exception as exc:
                log.debug("SX row skipped: error=%s", exc)
        return out

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

        # download.sparse_part_files (roadmap 11r): resolved per call so a
        # config edit is picked up without a kernel restart; on failure the
        # documented default (preallocate) applies via the empty dict.
        try:
            from amuled_v2.config import load_config

            _dl_cfg = (load_config().get("download") or {})
        except Exception as exc:
            log.warning(
                "kernel fallback: config load failed for download knobs, "
                "using defaults: error=%r",
                exc,
            )
            _dl_cfg = {}

        return DownloadQueue(
            state=self.state,
            temp_dir=TEMP_DIR,
            incoming_dir=INCOMING_DIR,
            sparse_part_files=bool(_dl_cfg.get("sparse_part_files")),
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
                # eMule auto-source-refresh (roadmap 11r P3 №9): a thin
                # source pool triggers an immediate KAD lookup BEFORE the
                # first dial - the "run with zero sources" failure dies here.
                try:
                    known = len(
                        self.state.list_file_sources(file_hash, limit=1000)
                    )
                except Exception as exc:
                    log.warning(
                        "kernel fallback: source count failed, skipping "
                        "thin-pool refresh: hash=%s, error=%r",
                        file_hash,
                        exc,
                    )
                    known = 99
                if known < 3:
                    log.info(
                        "DOWNLOAD thin source pool: hash=%s, known=%d - "
                        "refreshing from KAD before racing",
                        file_hash,
                        known,
                    )
                    try:
                        found, saved = await self._refresh_sources_async(
                            file_hash, int(entry["size"])
                        )
                        log.info(
                            "DOWNLOAD thin-pool refresh done: hash=%s, "
                            "found=%d, saved=%d",
                            file_hash,
                            found,
                            saved,
                        )
                    except Exception as exc:
                        log.warning(
                            "kernel fallback: thin-pool KAD refresh failed, "
                            "racing with the current pool: hash=%s, "
                            "error=%r",
                            file_hash,
                            exc,
                        )
                queue = self._download_queue()
                runner = DownloadRunner(
                    queue,
                    local_port=self._tcp_port,
                    max_peers=max_peers,
                    traffic_sink=self._record_downloaded,
                    plain_dial_ok=True,
                    secure_ident=getattr(self, "secure_ident", None),
                    connection_source=(
                        self.server.expect_connection_from
                        if self.server is not None
                        else None
                    ),
                    callback_identity=(
                        {
                            "tcp_port": self._tcp_port,
                            "user_hash": self.identity.user_hash,
                        }
                        if self.server is not None
                        else None
                    ),
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

    async def _refresh_sources_async(self, file_hash: str, size: int) -> tuple[int, int]:
        """One live KAD source lookup + persist.  Architecture invariant
        (AGENTS.md 2026-09-28): lookups run IN-KERNEL over the spider's
        mature pool routing - the ephemeral-runtime CLI path (bootstrap +
        41-contact tree) starved lookups and is no longer used here."""
        from amuled_v2.core.ed2k import FoundSource, FoundSources
        from amuled_v2.core.kad.source_search import kad_file_source_search

        if self.spider is None:
            raise RuntimeError("spider disabled - source refresh unavailable")
        report = await kad_file_source_search(
            bytes.fromhex(file_hash),
            file_size=size,
            routing=self.spider.pool_routing(),
            own_id=self.spider.own,
            own_tcp_port=self._tcp_port,
            timeout=30,
            max_sources=200,
            local_port=0,
        )
        record = FoundSources(
            file_hash=bytes.fromhex(file_hash),
            sources=tuple(
                FoundSource(
                    client_id=s.client_id,
                    client_port=s.tcp_port,
                    user_hash=None,
                    kad_type=s.source_type or None,
                    kad_udp_port=s.udp_port,
                    buddy_id=None,
                    buddy_ip=s.buddy_ip,
                    buddy_port=s.buddy_port,
                )
                for s in report.sources
            ),
        )
        saved = self.state.save_found_sources(
            record, server_ip="0.0.0.0", server_port=0, source_type="kad"
        )
        return len(report.sources), saved

    async def _source_refresh_loop(self) -> None:
        """eMule periodic source re-ask + re-dial (roadmap 11r P3 №9,
        eMule ReAskTime analog): every interval, refresh KAD sources for
        every queued/download entry and re-launch a race for entries whose
        previous race finished incomplete."""
        try:
            from amuled_v2.config import load_config

            interval = float(
                (load_config().get("kademlia") or {}).get("reask_interval_s")
                or 300
            )
        except Exception as exc:
            log.warning(
                "kernel fallback: config load failed for reask interval, "
                "using 300s: error=%r",
                exc,
            )
            interval = 300.0
        interval = max(60.0, interval)
        log.info("DOWNLOAD source re-ask loop: interval=%.0fs", interval)
        while not self.stop.is_set():
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            if self.stop.is_set():
                return
            queue = self._download_queue()
            try:
                entries = queue.list(limit=200)
            except Exception as exc:
                log.warning("kernel fallback: download list failed: error=%r", exc)
                continue
            for entry in entries:
                if self.stop.is_set():
                    return
                status = str(entry.get("status"))
                fhash = str(entry.get("file_hash"))
                if status not in ("queued", "downloading"):
                    continue
                try:
                    found, saved = await self._refresh_sources_async(
                        fhash, int(entry["size"])
                    )
                    log.info(
                        "DOWNLOAD source re-ask: hash=%s, found=%d, saved=%d",
                        fhash,
                        found,
                        saved,
                    )
                except Exception as exc:
                    log.warning(
                        "DOWNLOAD re-ask fallback: KAD lookup failed, "
                        "skipping this cycle: hash=%s, error=%r",
                        fhash,
                        exc,
                    )
                    continue
                box = self.download_box.get(fhash)
                if saved > 0 and (box is None or box.get("done")):
                    # Re-dial: the previous race finished incomplete; new
                    # sources (or simply time passed) warrant another pass.
                    log.info(
                        "DOWNLOAD re-dial: hash=%s (race idle, fresh "
                        "sources=%d)",
                        fhash,
                        saved,
                    )
                    self._start_download_task(fhash, 50)

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

        def ctl_sources_save(req: dict) -> dict[str, Any]:
            # The CLI cannot open DuckDB while the kernel owns it (single
            # writer) - source persistence MUST go through the owner.
            from amuled_v2.core.ed2k import FoundSource, FoundSources

            file_hash = bytes.fromhex(str(req["file_hash"]))
            srcs: list[FoundSource] = []
            for row in req.get("sources") or []:
                srcs.append(
                    FoundSource(
                        client_id=int(row["client_id"]),
                        client_port=int(row["client_port"]),
                        user_hash=(
                            bytes.fromhex(str(row["user_hash"]))
                            if row.get("user_hash")
                            else None
                        ),
                        kad_type=row.get("kad_type"),
                        kad_udp_port=row.get("kad_udp_port"),
                        buddy_id=(
                            bytes.fromhex(str(row["buddy_id"]))
                            if row.get("buddy_id")
                            else None
                        ),
                        buddy_ip=row.get("buddy_ip"),
                        buddy_port=row.get("buddy_port"),
                        ipv6=row.get("ipv6"),
                        buddy_ipv6=row.get("buddy_ipv6"),
                    )
                )
            record = FoundSources(file_hash=file_hash, sources=tuple(srcs))
            saved = self.state.save_found_sources(
                record,
                server_ip=str(req.get("server_ip") or "0.0.0.0"),
                server_port=int(req.get("server_port") or 0),
                source_type="kad",
            )
            return {"saved": saved, "received": len(srcs)}

        async def ctl_kad_search(req: dict) -> dict[str, Any]:
            """In-kernel keyword search over the spider's live pool (the
            ephemeral-runtime CLI path queries 6-9 stale contacts and often
            starves; the pool routing walks 1000+ maturing nodes)."""
            from amuled_v2.core.kad.search import kad_keyword_search

            if self.spider is None:
                return {"status": "error", "reason": "spider disabled"}
            query = str(req.get("query") or "").strip()
            timeout = float(req.get("timeout") or 45)
            if not query:
                return {"status": "error", "reason": "query is empty"}

            report = await kad_keyword_search(
                query,
                routing=self.spider.pool_routing(),
                own_id=self.spider.own,
                own_tcp_port=self._tcp_port,
                timeout=timeout,
            )
            return {
                "status": "ok",
                "query": query,
                "queried_nodes": report.queried_nodes,
                "responded_nodes": report.responded_nodes,
                "results": [
                    {
                        "hash": r.file_hash.hex().upper(),
                        "name": r.name,
                        "size": int(r.size),
                        "sources": int(r.sources),
                    }
                    for r in report.results
                ],
            }

        async def ctl_kad_sources(req: dict) -> dict[str, Any]:
            """In-kernel KAD source lookup over the spider's live pool;
            rows are persisted directly (the kernel owns the state)."""
            from amuled_v2.core.ed2k import FoundSource, FoundSources
            from amuled_v2.core.kad.source_search import kad_file_source_search

            if self.spider is None:
                return {"status": "error", "reason": "spider disabled"}
            file_hash = str(req.get("file_hash") or "").upper()
            if len(file_hash) != 32:
                return {"status": "error", "reason": "bad file hash"}
            size = int(req.get("size") or 0)
            timeout = float(req.get("timeout") or 40)

            report = await kad_file_source_search(
                bytes.fromhex(file_hash),
                file_size=size or None,
                routing=self.spider.pool_routing(),
                own_id=self.spider.own,
                own_tcp_port=self._tcp_port,
                timeout=timeout,
                max_sources=200,
                local_port=0,
            )
            record = FoundSources(
                file_hash=bytes.fromhex(file_hash),
                sources=tuple(
                    FoundSource(
                        client_id=s.client_id,
                        client_port=s.tcp_port,
                        user_hash=None,
                        kad_type=s.source_type or None,
                        kad_udp_port=s.udp_port,
                        buddy_id=None,
                        buddy_ip=s.buddy_ip,
                        buddy_port=s.buddy_port,
                    )
                    for s in report.sources
                ),
            )
            saved = self.state.save_found_sources(
                record, server_ip="0.0.0.0", server_port=0,
                source_type="kad",
            )
            return {
                "status": "ok",
                "hash": file_hash,
                "source_count": len(report.sources),
                "saved_sources": int(saved),
                "sources": [s.to_dict() for s in report.sources],
            }

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
            "sources.save": ctl_sources_save,
            "kad.search": ctl_kad_search,
            "kad.sources": ctl_kad_sources,
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

        # Config parity (roadmap 11r): connection rate limit and sparse part
        # files come from network.max_conn_per_5s / download.sparse_part_files;
        # a config problem degrades to the documented defaults (logged).
        try:
            from amuled_v2.config import load_config

            _cfg = load_config()
        except Exception as exc:
            log.warning(
                "kernel fallback: config load failed, using defaults for "
                "listener/queue knobs: error=%r",
                exc,
            )
            _cfg = {}
        _net_cfg = _cfg.get("network") or {}
        _dl_cfg = _cfg.get("download") or {}

        self.server = IncomingPeerServer(
            identity=identity.to_local_identity(),
            resolver=StateSharedFileResolver(lambda: self.state),
            upload_queue=queue,
            host=self.bind_host,
            port=tcp_port,
            throttle=throttle,
            max_connections=self.max_sessions,
            max_conn_per_5s=int(_net_cfg.get("max_conn_per_5s") or 0),
            traffic_recorder=self._record_uploaded,
            secure_ident=getattr(self, "secure_ident", None),
            source_provider=self._source_provider,
        )
        await self.server.start()
        self._tcp_port = self.server.bound_port
        # The HELLOANSWER must advertise the port that is actually listening.
        self.server._identity = identity.to_local_identity(tcp_port=self._tcp_port)
        # Serving-buddy registry: the KAD spider answers
        # KADEMLIA_FINDSERVINGBUDDY_REQ with this TCP port; the listener
        # registers served clients into the same table (stage X).
        from amuled_v2.core.kad.buddy import buddy_registry

        buddy_registry.configure(tcp_port=self._tcp_port)

        if not self.args.no_spider:
            self.spider = SpiderEngine(
                ROOT,
                state_backend=self.state,
                verbose=False,
                # Serving-buddy customer (stage X): our own userhash lets
                # the spider register with an external buddy once accepted.
                buddy_tcp_port=self._tcp_port,
                buddy_userhash=bytes(self.identity.user_hash),
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

        # eMule periodic source re-ask + re-dial (roadmap 11r P3 №9).
        reask_task = asyncio.create_task(
            self._source_refresh_loop(), name="source-reask"
        )

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

        # Config parity (roadmap 11r): periodic ipfilter refresh from
        # ipfilter.update_url when ipfilter.auto_update is on (eMule
        # AutoIPFilterUpdate analog). The last-update stamp lives in
        # db\ipfilter_update.json so restarts do not re-download early.
        ipfilter_task: asyncio.Task | None = None

        async def _ipfilter_autoupdate() -> None:
            import json as _json
            from datetime import datetime, timedelta
            from pathlib import Path

            from amuled_v2.core.ipfilter import update_ipfilter_from_url

            try:
                from amuled_v2.config import load_config

                cfg_ip = (load_config().get("ipfilter") or {})
            except Exception as exc:
                log.warning(
                    "kernel fallback: config load failed, ipfilter "
                    "auto-update disabled: error=%r",
                    exc,
                )
                return
            url = cfg_ip.get("update_url")
            if not (cfg_ip.get("auto_update") and url):
                return
            period_days = float(cfg_ip.get("update_period_days") or 7)
            stamp_path = Path(ROOT) / "db" / "ipfilter_update.json"
            dest = Path(ROOT) / str(
                cfg_ip.get("ipfilter_dat") or "assets/v1/ipfilter.dat"
            )

            def _due() -> bool:
                try:
                    stamp = _json.loads(stamp_path.read_text(encoding="utf-8"))
                    last = datetime.fromisoformat(stamp["last_update"])
                    return datetime.now() - last >= timedelta(days=period_days)
                except Exception:
                    return True  # missing/corrupt stamp -> refresh now

            while not self.stop.is_set():
                if _due():
                    try:
                        loop = asyncio.get_running_loop()
                        stats = await loop.run_in_executor(
                            None, update_ipfilter_from_url, url, str(dest), 60.0
                        )
                        stamp_path.parent.mkdir(parents=True, exist_ok=True)
                        _write_json_atomic(
                            stamp_path,
                            {
                                "last_update": datetime.now().isoformat(),
                                "url": url,
                                "bytes": stats.get("bytes"),
                            },
                        )
                        log.info(
                            "IPFILTER auto-update: url=%s, bytes=%s",
                            url,
                            stats.get("bytes"),
                        )
                    except Exception as exc:
                        log.warning(
                            "ipfilter auto-update fallback: refresh failed, "
                            "keeping the existing list: error=%r",
                            exc,
                        )
                try:
                    await asyncio.wait_for(
                        self.stop.wait(), timeout=3600.0
                    )
                except asyncio.TimeoutError:
                    pass

        ipfilter_task = asyncio.create_task(
            _ipfilter_autoupdate(), name="ipfilter-autoupdate"
        )

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
                t
                for t in (nat_task, rotation_task, ipfilter_task, reask_task)
                if t is not None
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