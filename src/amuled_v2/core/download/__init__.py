"""Download subsystem: part files and the DuckDB-backed download queue.

src/amuled_v2/core/download/__init__.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package exports for part files and the download queue.
"""

from .partfile import (
    ED2K_CHUNK_SIZE,
    PART_SIDECAR_SUFFIX,
    Gap,
    PartFile,
    PartFileError,
    check_free_space,
)
from .queue import (
    DownloadQueue,
    DownloadQueueError,
    DownloadStatus,
)
from .runner import (
    DownloadRunner,
    DownloadRunnerError,
)

__all__ = [
    "ED2K_CHUNK_SIZE",
    "PART_SIDECAR_SUFFIX",
    "Gap",
    "PartFile",
    "PartFileError",
    "check_free_space",
    "DownloadQueue",
    "DownloadQueueError",
    "DownloadStatus",
    "DownloadRunner",
    "DownloadRunnerError",
]
