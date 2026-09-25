"""Download runner wiring the queue to peer-to-peer transfers.

Coordinates sequential peer attempts for a queued file: resolves known
ED2K sources from state, opens a ``PeerClient`` against each endpoint,
and drives the handshake / hashset / upload-slot / transfer pipeline.
A single peer is tried at a time; progress is forwarded to the queue's
part file via ``record_block`` and completion is finalized only when a
peer delivers the whole file.

src/amuled_v2/core/download/runner.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Parallel peer attempts (race semantics): up to max_peers peers run
      concurrently; the first peer delivering a complete file wins and the
      losers are cancelled.  Part-file writes stay sequential on the event
      loop, so sparse block writes from several peers are safe.
  [+] Optional source_provider: sources may come from the kernel over IPC
      instead of the runner's own state connection.

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added DownloadRunner coordinating sequential peer download attempts.
  [+] Added source resolution converting high-id client rows to endpoints.
  [+] Added single-file run() and bulk run_all() entry points.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Callable

from amuled_v2.logging_setup import LogTags, get_tagged_logger

if TYPE_CHECKING:
    from amuled_v2.core.download.queue import DownloadQueue
    from amuled_v2.core.peer.client import DownloadOutcome

log = get_tagged_logger(LogTags.DOWNLOAD, "core.download.runner")

__all__ = [
    "DownloadRunner",
    "DownloadRunnerError",
]

_HIGH_ID_THRESHOLD = 16_000_000


class DownloadRunnerError(RuntimeError):
    """Raised for download runner lifecycle errors."""


def _client_id_to_ip(client_id: int) -> str:
    packed = struct.pack(">I", client_id & 0xFFFFFFFF)
    a, b, c, d = packed
    return f"{a}.{b}.{c}.{d}"


class DownloadRunner:
    """Sequential peer-driven download runner over a ``DownloadQueue``."""

    def __init__(
        self,
        queue: "DownloadQueue",
        *,
        local_client_id: int = 0,
        local_port: int = 8089,
        nickname: str = "AmuleD",
        max_peers: int = 3,
        peer_connect_timeout: float = 8.0,
        peer_response_timeout: float = 20.0,
        queue_wait_timeout: float = 60.0,
        traffic_sink: "Callable[[str, int], None] | None" = None,
        source_provider: "Callable[[str, int], list[dict]] | None" = None,
        plain_dial_ok: bool = False,
    ) -> None:
        self.queue = queue
        self.local_client_id = local_client_id
        self.local_port = local_port
        self.nickname = nickname
        self.max_peers = max_peers
        self.peer_connect_timeout = peer_connect_timeout
        self.peer_response_timeout = peer_response_timeout
        self.queue_wait_timeout = queue_wait_timeout
        # Stage C credit accounting: forwarded to every PeerClient; called
        # with (peer_user_hash_hex, downloaded_bytes) per finished transfer.
        self.traffic_sink = traffic_sink
        # Stage U: when the kernel owns the db, sources arrive over IPC via
        # this provider instead of a direct state query.
        self.source_provider = source_provider
        # Plain dial for rows WITHOUT a KAD userhash.  On the real network
        # plain is dead (instant FIN) so the default is False; loopback
        # self-tests against our own plain-only listener set it True.
        self.plain_dial_ok = plain_dial_ok

    def resolve_sources(
        self, file_hash: str, *, limit: int = 20
    ) -> list[tuple[str, int, bytes | None]]:
        """High-id endpoints for a hash: (ip, port, user_hash | None).

        The user_hash (KAD source_id) enables the BASIC-obfuscated dial;
        rows without it cannot be dialed safely (plain is dead), so they
        are skipped for the attempt list.
        """
        if self.source_provider is not None:
            rows = self.source_provider(file_hash, limit)
        else:
            rows = self.queue.state.list_file_sources(file_hash, limit=limit)
        seen: set[tuple[str, int]] = set()
        endpoints: list[tuple[str, int, bytes | None]] = []
        skipped = 0
        for row in rows:
            client_id = row["client_id"]
            if client_id < _HIGH_ID_THRESHOLD:
                skipped += 1
                continue
            raw_hash = row.get("user_hash")
            user_hash: bytes | None = None
            if raw_hash:
                try:
                    user_hash = bytes.fromhex(str(raw_hash))
                except ValueError:
                    user_hash = None
            if user_hash is None:
                if not self.plain_dial_ok:
                    skipped += 1
                    continue
            endpoint = (_client_id_to_ip(client_id), row["client_port"])
            if endpoint in seen:
                continue
            seen.add(endpoint)
            endpoints.append((endpoint[0], endpoint[1], user_hash))
        if skipped:
            log.debug(
                "DOWNLOAD skipped undialable sources: hash=%s, skipped=%d",
                file_hash,
                skipped,
            )
        return endpoints

    async def _attempt_peer(
        self,
        endpoint: tuple[str, int, bytes | None],
        file_hash: str,
        size: int,
        file_hash_bytes: bytes,
        progress_callback: Callable[[int, int, int], None] | None,
    ) -> dict:
        """Drive one peer through the full download ladder; return an
        outcome dict (never raises — failures become outcome dicts)."""
        host, port, user_hash = endpoint
        outcome: "DownloadOutcome | None" = None
        client = None
        try:
            from amuled_v2.core.peer.client import PeerClient

            client = PeerClient(
                host,
                port,
                local_client_id=self.local_client_id,
                local_port=self.local_port,
                nickname=self.nickname,
                connect_timeout=self.peer_connect_timeout,
                response_timeout=self.peer_response_timeout,
                queue_wait_timeout=self.queue_wait_timeout,
                traffic_sink=self.traffic_sink,
                target_userhash=user_hash,
            )
            await client.connect()
            await client.handshake()
            await client.request_file(file_hash_bytes)
            await client.wait_upload_slot(file_hash_bytes)
            outcome = await client.transfer(
                file_hash_bytes,
                size,
                write_block=lambda start, data: self.queue.record_block(
                    file_hash, start, data
                ),
                progress_callback=progress_callback,
            )
            return outcome.to_dict()
        except Exception as exc:
            log.warning(
                "DOWNLOAD peer attempt failed: endpoint=%s:%d, error=%s",
                host, port, exc,
            )
            if outcome is not None:
                return outcome.to_dict()
            return {
                "file_hash": file_hash,
                "bytes_received": 0,
                "blocks_received": 0,
                "complete": False,
                "elapsed": 0.0,
                "detail": f"peer error: {exc}",
            }
        finally:
            if client is not None:
                await client.close()

    async def run(
        self,
        file_hash: str,
        *,
        verify: bool = True,
        progress_callback: Callable[[int, int, int], None] | None = None,
    ) -> dict:
        entry = self.queue.get(file_hash)
        if entry is None:
            from amuled_v2.core.download.queue import DownloadQueueError

            raise DownloadQueueError(f"download not found: {file_hash}")
        if entry["status"] == "complete":
            return {"status": "already_complete", **entry}

        sources = self.resolve_sources(file_hash)
        if not sources:
            from amuled_v2.core.download.queue import DownloadQueueError

            raise DownloadQueueError(
                f"no known sources for hash {file_hash}; run a sources lookup first"
            )

        file_hash_bytes = bytes.fromhex(str(entry["hash"]))
        size = int(entry["size"])
        endpoints = sources[: self.max_peers]
        log.info(
            "DOWNLOAD race start: hash=%s, peers=%d",
            file_hash, len(endpoints),
        )

        tasks = {
            asyncio.create_task(
                self._attempt_peer(
                    endpoint, file_hash, size, file_hash_bytes, progress_callback
                ),
                name=f"dl-peer-{endpoint[0]}:{endpoint[1]}",
            ): endpoint
            for endpoint in endpoints
        }
        attempts: list[dict] = []
        pending = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    attempts.append(task.result())
                refreshed = self.queue.get(file_hash)
                if refreshed is not None and refreshed["status"] == "complete":
                    # First winner takes the file; the losing peers are
                    # cancelled mid-transfer.
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    finalized = self.queue.finalize(file_hash, verify=verify)
                    winner = next(
                        (a for a in attempts if a.get("complete")),
                        attempts[-1] if attempts else {},
                    )
                    log.info(
                        "DOWNLOAD race won: hash=%s, attempts=%d", file_hash,
                        len(attempts),
                    )
                    return {
                        "status": "complete",
                        "outcome": winner,
                        "finalized": finalized,
                    }
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "status": "incomplete",
            "hash": file_hash,
            "outcomes": attempts,
        }

    async def run_all(
        self,
        *,
        verify: bool = True,
        progress_callback: Callable[[int, int, int], None] | None = None,
    ) -> list[dict]:
        results: list[dict] = []
        for entry in self.queue.list(limit=100):
            if entry["status"] not in ("queued", "downloading"):
                continue
            result = await self.run(
                str(entry["hash"]),
                verify=verify,
                progress_callback=progress_callback,
            )
            results.append(result)
        return results
