"""Download runner wiring the queue to peer-to-peer transfers.

Coordinates sequential peer attempts for a queued file: resolves known
ED2K sources from state, opens a ``PeerClient`` against each endpoint,
and drives the handshake / hashset / upload-slot / transfer pipeline.
A single peer is tried at a time; progress is forwarded to the queue's
part file via ``record_block`` and completion is finalized only when a
peer delivers the whole file.

src/amuled_v2/core/download/runner.py
Version:     0.1.0
Author:      Soror L'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added DownloadRunner coordinating sequential peer download attempts.
  [+] Added source resolution converting high-id client rows to endpoints.
  [+] Added single-file run() and bulk run_all() entry points.
"""

from __future__ import annotations

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

    def resolve_sources(self, file_hash: str, *, limit: int = 20) -> list[tuple[str, int]]:
        rows = self.queue.state.list_file_sources(file_hash, limit=limit)
        seen: set[tuple[str, int]] = set()
        endpoints: list[tuple[str, int]] = []
        skipped = 0
        for row in rows:
            client_id = row["client_id"]
            if client_id < _HIGH_ID_THRESHOLD:
                skipped += 1
                continue
            endpoint = (_client_id_to_ip(client_id), row["client_port"])
            if endpoint in seen:
                continue
            seen.add(endpoint)
            endpoints.append(endpoint)
        if skipped:
            log.debug(
                "DOWNLOAD skipped low-id sources: hash=%s, skipped=%d",
                file_hash,
                skipped,
            )
        return endpoints

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
        attempts: list[dict] = []
        for endpoint in sources[: self.max_peers]:
            host, port = endpoint
            outcome: "DownloadOutcome | None" = None
            client = None
            try:
                from amuled_v2.core.peer.client import (
                    PeerCodecError,
                    PeerClient,
                    PeerSessionError,
                )

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
                )
                await client.connect()
                await client.handshake()
                await client.request_file(file_hash_bytes)
                await client.wait_upload_slot(file_hash_bytes)
                outcome = await client.transfer(
                    file_hash_bytes,
                    int(entry["size"]),
                    write_block=lambda start, data: self.queue.record_block(
                        file_hash, start, data
                    ),
                    progress_callback=progress_callback,
                )
                attempts.append(outcome.to_dict())
            except (PeerSessionError, PeerCodecError, OSError) as exc:
                from amuled_v2.core.download.queue import DownloadQueueError

                if isinstance(exc, DownloadQueueError):
                    log.warning(
                        "DOWNLOAD source lookup failed: endpoint=%s:%d, error=%s",
                        host,
                        port,
                        exc,
                    )
                else:
                    log.warning(
                        "DOWNLOAD peer attempt failed: endpoint=%s:%d, error=%s",
                        host,
                        port,
                        exc,
                    )
                if outcome is not None:
                    attempts.append(outcome.to_dict())
                else:
                    attempts.append(
                        {
                            "file_hash": file_hash,
                            "bytes_received": 0,
                            "blocks_received": 0,
                            "complete": False,
                            "elapsed": 0.0,
                            "detail": f"peer error: {exc}",
                        }
                    )
            finally:
                if client is not None:
                    await client.close()

            refreshed = self.queue.get(file_hash)
            if refreshed is not None and refreshed["status"] == "complete":
                finalized = self.queue.finalize(file_hash, verify=verify)
                outcome_dict = attempts[-1] if attempts else {}
                return {
                    "status": "complete",
                    "outcome": outcome_dict,
                    "finalized": finalized,
                }

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
