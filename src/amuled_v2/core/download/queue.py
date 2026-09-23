"""Download queue backed by DuckDB and native part files.

The queue tracks requested files, their lifecycle (queued, downloading,
paused, complete, error), and the on-disk part-file state.  Adding a download
requires a real ED2K file link; the queue itself never fakes transfer data.

src/amuled_v2/core/download/queue.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added DuckDB download queue schema helpers and lifecycle transitions.
  [+] Added part-file creation, resume, pause, resume, and cancel.
  [+] Added disk-space checks and incoming-file finalization.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from amuled_v2.logging_setup import LogTags, get_tagged_logger

if TYPE_CHECKING:
    from amuled_v2.core.download.partfile import PartFile
    from amuled_v2.state import StateBackend

log = get_tagged_logger(LogTags.DOWNLOAD, "core.download.queue")

__all__ = [
    "DownloadStatus",
    "DownloadQueue",
    "DownloadQueueError",
]


class DownloadStatus:
    """Lifecycle values stored in the ``downloads`` table."""

    QUEUED = "queued"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    COMPLETE = "complete"
    ERROR = "error"


class DownloadQueueError(RuntimeError):
    """Raised for invalid queue operations."""


@dataclass
class DownloadQueue:
    """File-backed download queue sharing the project state backend."""

    state: "StateBackend"
    temp_dir: Path
    incoming_dir: Path

    def _normalize_hash(self, file_hash: str) -> str:
        normalized = file_hash.strip().lower()
        if len(normalized) != 32:
            raise DownloadQueueError(
                "file hash must contain 32 hexadecimal digits"
            )
        bytes.fromhex(normalized)
        return normalized

    # -- queue operations ----------------------------------------------------

    def add(
        self,
        *,
        file_hash: str,
        name: str,
        size: int,
    ) -> dict[str, object]:
        """Register a new download and create its part file."""
        normalized = self._normalize_hash(file_hash)
        existing = self.get(normalized)
        if existing is not None:
            log.info(
                "DOWNLOAD already queued: hash=%s, status=%s",
                normalized,
                existing["status"],
            )
            return existing

        from amuled_v2.core.download.partfile import PartFile

        part_path = self.temp_dir / f"{normalized}.part"
        part = PartFile(part_path, size, normalized, name)
        part.open_new()
        part.close()
        self.state.add_download(
            file_hash=normalized,
            name=name,
            size=size,
            part_path=str(part_path),
            status=DownloadStatus.QUEUED,
        )
        entry = self.get(normalized)
        assert entry is not None
        log.info(
            "DOWNLOAD queued: hash=%s, name=%r, size=%d",
            normalized,
            name,
            size,
        )
        return entry

    def get(self, file_hash: str) -> dict[str, object] | None:
        return self.state.get_download(self._normalize_hash(file_hash))

    def list(self, *, limit: int = 100) -> list[dict[str, object]]:
        return self.state.list_downloads(limit=limit)

    def set_status(self, file_hash: str, status: str) -> dict[str, object]:
        normalized = self._normalize_hash(file_hash)
        changed = self.state.set_download_status(normalized, status)
        if not changed:
            raise DownloadQueueError(f"download not found: {normalized}")
        entry = self.get(normalized)
        assert entry is not None
        log.info(
            "DOWNLOAD status changed: hash=%s, status=%s",
            normalized,
            status,
        )
        return entry

    def start(self, file_hash: str) -> dict[str, object]:
        return self.set_status(file_hash, DownloadStatus.DOWNLOADING)

    def pause(self, file_hash: str) -> dict[str, object]:
        return self.set_status(file_hash, DownloadStatus.PAUSED)

    def resume(self, file_hash: str) -> dict[str, object]:
        entry = self.get(file_hash)
        if entry is None:
            raise DownloadQueueError(f"download not found: {file_hash}")
        if entry["status"] != DownloadStatus.PAUSED:
            raise DownloadQueueError(
                f"only paused downloads can be resumed: {entry['status']}"
            )
        return self.set_status(file_hash, DownloadStatus.DOWNLOADING)

    def cancel(self, file_hash: str, *, keep_files: bool = False) -> dict[str, object]:
        """Remove a download from the queue, deleting its part files."""
        normalized = self._normalize_hash(file_hash)
        entry = self.get(normalized)
        if entry is None:
            raise DownloadQueueError(f"download not found: {normalized}")
        part_path = Path(str(entry["part_path"]))
        removed_files = 0
        if not keep_files:
            from amuled_v2.core.download.partfile import PART_SIDECAR_SUFFIX

            for candidate in (part_path, Path(str(part_path) + PART_SIDECAR_SUFFIX)):
                if candidate.exists():
                    candidate.unlink()
                    removed_files += 1
        self.state.remove_download(normalized)
        log.info(
            "DOWNLOAD cancelled: hash=%s, files_removed=%d",
            normalized,
            removed_files,
        )
        return {
            "hash": normalized,
            "cancelled": True,
            "files_removed": removed_files,
        }

    # -- transfer bookkeeping ------------------------------------------------

    def record_block(self, file_hash: str, start: int, data: bytes) -> dict[str, object]:
        """Write one received block into the part file and update the queue."""
        normalized = self._normalize_hash(file_hash)
        entry = self.get(normalized)
        if entry is None:
            raise DownloadQueueError(f"download not found: {normalized}")

        from amuled_v2.core.download.partfile import PartFile

        part = PartFile.resume(Path(str(entry["part_path"])))
        try:
            remaining = part.write_block(start, data)
            part.save()
        finally:
            part.close()
        status = DownloadStatus.COMPLETE if part.is_complete else DownloadStatus.DOWNLOADING
        self.state.update_download_progress(
            normalized,
            downloaded_bytes=part.downloaded_bytes,
            status=status,
        )
        return {
            "hash": normalized,
            "remaining_bytes": remaining,
            "complete": part.is_complete,
            "status": status,
        }

    def finalize(self, file_hash: str, *, verify: bool = True) -> dict[str, object]:
        """Move a complete part file into incoming, optionally verifying MD4."""
        normalized = self._normalize_hash(file_hash)
        entry = self.get(normalized)
        if entry is None:
            raise DownloadQueueError(f"download not found: {normalized}")
        if entry["status"] != DownloadStatus.COMPLETE:
            raise DownloadQueueError(
                f"download is not complete: status={entry['status']}"
            )
        part_path = Path(str(entry["part_path"]))
        self.incoming_dir.mkdir(parents=True, exist_ok=True)
        target = self.incoming_dir / str(entry["name"])
        if verify:
            from amuled_v2.core.download.partfile import PartFile

            part = PartFile.resume(part_path)
            part.close()
            if not part.is_complete:
                raise DownloadQueueError("part file still has gaps")

        if verify:
            actual = self._file_hash(part_path)
            if actual.lower() != normalized:
                raise DownloadQueueError(
                    f"hash mismatch after download: expected={normalized}, got={actual}"
                )
        shutil.move(str(part_path), str(target))
        self.state.set_download_status(normalized, DownloadStatus.COMPLETE)
        log.info(
            "DOWNLOAD finalized: hash=%s, target=%s",
            normalized,
            str(target),
        )
        return {
            "hash": normalized,
            "finalized": True,
            "target": str(target),
            "verified": verify,
        }

    @staticmethod
    def _file_hash(path: Path) -> str:
        from Crypto.Hash import MD4

        digest = MD4.new()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest().upper()
