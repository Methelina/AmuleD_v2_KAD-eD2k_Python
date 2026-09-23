"""Native .part file format with gap tracking and chunk bitmaps.

Implements the eMule-compatible incomplete-download file layout:

- the data file is preallocated to the full final size;
- a gap list (ordered, non-overlapping ``[start, end)`` intervals) records
  the missing byte ranges;
- the file is divided into 9,728,400-byte (9.28 MiB) chunks, the ED2K hash
  granularity, and a bitmap tracks which chunks contain no gaps;
- a ``.amuled.json`` sidecar persists the gap list, the chunk bitmap, and the
  expected hash so a resumed client can continue exactly where it stopped.

src/amuled_v2/core/download/partfile.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added preallocated part files with persisted gap lists.
  [+] Added ED2K chunk bitmap computation and completion detection.
  [+] Added block write, sidecar save/load, and disk-space checks.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.DOWNLOAD, "core.download.partfile")

__all__ = [
    "PartFile",
    "PartFileError",
    "PART_SIDECAR_SUFFIX",
    "ED2K_CHUNK_SIZE",
    "check_free_space",
]


PART_SIDECAR_SUFFIX = ".amuled.json"
ED2K_CHUNK_SIZE = 9_728_400


class PartFileError(RuntimeError):
    """Raised when a part file cannot be created, written, or resumed."""


@dataclass
class Gap:
    start: int
    end: int  # exclusive

    @property
    def length(self) -> int:
        return self.end - self.start


def check_free_space(directory: Path, required_bytes: int) -> bool:
    """True when *directory* has at least *required_bytes* free."""
    usage = shutil.disk_usage(str(directory))
    return usage.free >= required_bytes


def _normalize_gaps(gaps: list[Gap], total_size: int) -> list[Gap]:
    """Sort, clip, and merge gaps into a canonical non-overlapping list."""
    clipped: list[tuple[int, int]] = []
    for gap in gaps:
        start = max(0, min(gap.start, total_size))
        end = max(0, min(gap.end, total_size))
        if end > start:
            clipped.append((start, end))
    clipped.sort()
    merged: list[Gap] = []
    for start, end in clipped:
        if merged and start <= merged[-1].end:
            merged[-1].end = max(merged[-1].end, end)
        else:
            merged.append(Gap(start, end))
    return merged


class PartFile:
    """One incomplete download on disk with its metadata sidecar."""

    def __init__(self, path: str | Path, total_size: int, file_hash: str, name: str) -> None:
        if total_size <= 0:
            raise PartFileError(f"download size must be positive: {total_size}")
        self.path = Path(path)
        self.total_size = total_size
        self.file_hash = file_hash.upper()
        self.name = name
        self.gaps: list[Gap] = [Gap(0, total_size)]
        self._handle = None

    # -- lifecycle -----------------------------------------------------------

    def open_new(self) -> None:
        """Create and preallocate the data file, then persist the sidecar."""
        if self.path.exists() and self.path.stat().st_size == self.total_size:
            log.info(
                "DOWNLOAD part file exists: path=%s, size=%d",
                str(self.path),
                self.total_size,
            )
        else:
            directory = self.path.parent
            directory.mkdir(parents=True, exist_ok=True)
            if not check_free_space(directory, self.total_size):
                raise PartFileError(
                    f"insufficient disk space for {self.total_size} bytes "
                    f"in {directory}"
                )
            with open(self.path, "wb") as handle:
                handle.truncate(self.total_size)
            log.info(
                "DOWNLOAD part file created: path=%s, size=%d",
                str(self.path),
                self.total_size,
            )
        self._open_handle()
        self.save()

    @classmethod
    def resume(cls, path: str | Path) -> "PartFile":
        """Load an existing part file from its sidecar."""
        sidecar = cls._sidecar_path(Path(path))
        if not sidecar.exists():
            raise PartFileError(f"part sidecar is missing: {sidecar}")
        with open(sidecar, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        part = cls(path, int(data["total_size"]), str(data["file_hash"]), str(data["name"]))
        part.gaps = _normalize_gaps(
            [Gap(int(g["start"]), int(g["end"])) for g in data.get("gaps", [])],
            part.total_size,
        )
        part._open_handle()
        return part

    @staticmethod
    def _sidecar_path(path: Path) -> Path:
        return path.with_name(path.name + PART_SIDECAR_SUFFIX)

    def _open_handle(self) -> None:
        if self._handle is None:
            self._handle = open(self.path, "r+b")

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    # -- writes --------------------------------------------------------------

    def write_block(self, start: int, data: bytes) -> int:
        """Write one received block and return the remaining gap bytes."""
        if start < 0 or start + len(data) > self.total_size:
            raise PartFileError(
                f"block outside file bounds: start={start}, bytes={len(data)}"
            )
        self._open_handle()
        self._handle.seek(start)
        self._handle.write(data)
        self._apply_gap_fill(start, start + len(data))
        return self.remaining_bytes

    def _apply_gap_fill(self, start: int, end: int) -> None:
        updated: list[Gap] = []
        for gap in self.gaps:
            if end <= gap.start or start >= gap.end:
                updated.append(gap)
                continue
            if start > gap.start:
                updated.append(Gap(gap.start, start))
            if end < gap.end:
                updated.append(Gap(end, gap.end))
        self.gaps = _normalize_gaps(updated, self.total_size)

    # -- status --------------------------------------------------------------

    @property
    def remaining_bytes(self) -> int:
        return sum(gap.length for gap in self.gaps)

    @property
    def downloaded_bytes(self) -> int:
        return self.total_size - self.remaining_bytes

    @property
    def is_complete(self) -> bool:
        return not self.gaps

    @property
    def chunk_count(self) -> int:
        chunks, remainder = divmod(self.total_size, ED2K_CHUNK_SIZE)
        return chunks + (1 if remainder else 0)

    def chunk_bitmap(self) -> list[bool]:
        """Per-chunk True when the chunk contains no gaps."""
        bitmap: list[bool] = []
        for index in range(self.chunk_count):
            chunk_start = index * ED2K_CHUNK_SIZE
            chunk_end = min(chunk_start + ED2K_CHUNK_SIZE, self.total_size)
            complete = not any(
                gap.start < chunk_end and gap.end > chunk_start for gap in self.gaps
            )
            bitmap.append(complete)
        return bitmap

    def first_usable_gap(self, max_length: int) -> Gap | None:
        """Return the first gap (clipped to *max_length*) available to request."""
        for gap in self.gaps:
            end = min(gap.end, gap.start + max_length)
            if end > gap.start:
                return Gap(gap.start, end)
        return None

    # -- persistence ---------------------------------------------------------

    def save(self) -> None:
        sidecar = self._sidecar_path(self.path)
        payload = {
            "file_hash": self.file_hash,
            "name": self.name,
            "total_size": self.total_size,
            "gaps": [
                {"start": gap.start, "end": gap.end} for gap in self.gaps
            ],
            "chunk_bitmap": self.chunk_bitmap(),
        }
        with open(sidecar, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def status(self) -> dict[str, object]:
        return {
            "hash": self.file_hash,
            "name": self.name,
            "path": str(self.path),
            "total_size": self.total_size,
            "downloaded_bytes": self.downloaded_bytes,
            "remaining_bytes": self.remaining_bytes,
            "complete": self.is_complete,
            "chunks_total": self.chunk_count,
            "chunks_done": sum(self.chunk_bitmap()),
            "gaps": len(self.gaps),
        }
