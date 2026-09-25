"""Upload subsystem: in-memory waiting queue and slot management.

Mirrors the core scheduling rules from eMuleAI's ``UploadQueue.cpp``: waiting
clients are ordered by file priority (PR_LOW < PR_NORMAL < PR_HIGH) then by
enqueue time, and a bounded number of active upload slots are granted to the
highest-ranking waiter.

src/amuled_v2/core/upload/__init__.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-24

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added upload-queue package exports and tagged UPLOAD diagnostics.
  [+] Added engine exports (UploadSession, BlockSource, UploadThrottle,
      UploadTransport, UploadSessionStats, UploadEngineError).
"""
from __future__ import annotations

from .engine import (
    BlockSource,
    UploadEngineError,
    UploadSession,
    UploadSessionStats,
    UploadThrottle,
    UploadTransport,
)
from .queue import (
    UploadClient,
    UploadPriority,
    UploadQueue,
    UploadQueueError,
)

__all__ = [
    "BlockSource",
    "UploadClient",
    "UploadEngineError",
    "UploadPriority",
    "UploadQueue",
    "UploadQueueError",
    "UploadSession",
    "UploadSessionStats",
    "UploadThrottle",
    "UploadTransport",
]
