"""In-memory upload waiting queue and slot management.

Implements the core scheduling rules from eMuleAI's UploadQueue.cpp:

* Waiting clients are ordered by file priority (PR_LOW < PR_NORMAL < PR_HIGH)
  then by enqueue time, giving each an ascending 1-based ``rank``.
* A bounded number of active upload slots (``max_slots``) is granted to the
  highest-ranking waiters; each granted slot carries a ``granted_at``
  timestamp and a TTL (``slot_ttl``) after which it is considered expired.
* Deduplication is keyed on ``(user_hash, requested_hash)`` so a client
  requesting the same file while already queued or holding a slot returns
  its current rank instead of being re-enqueued.

src/amuled_v2/core/upload/queue.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-24

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added UploadPriority with eMule PR_LOW/PR_NORMAL/PR_HIGH mapping.
  [+] Added frozen UploadClient dataclass with hash validation and to_dict.
  [+] Added UploadQueue with enqueue/dequeue, grant/release, rank, TTL, and
      snapshot operations following eMuleAI UploadQueue.cpp ordering rules.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.UPLOAD, "core.upload.queue")

__all__ = [
    "UploadClient",
    "UploadPriority",
    "UploadQueue",
    "UploadQueueError",
]

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


class UploadQueueError(RuntimeError):
    """Raised for invalid upload queue operations."""


class UploadPriority:
    """eMule PR_LOW/PR_NORMAL/PR_HIGH file-priority values.

    Mapping mirrors eMuleAI UploadQueue.cpp rules: lower numeric value
    means lower rank in the waiting queue (PR_LOW < PR_NORMAL < PR_HIGH).
    """

    LOW = 0
    NORMAL = 1
    HIGH = 2


@dataclass(frozen=True)
class UploadClient:
    """A waiting or granted upload client (eMule CUpDownClient in the waiting queue)."""

    user_hash: str
    client_id: int
    client_port: int
    nickname: str
    requested_hash: str
    file_priority: int = 1
    enqueued_at: float = field(default_factory=time.monotonic)
    rank: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "user_hash": self.user_hash,
            "client_id": self.client_id,
            "client_port": self.client_port,
            "nickname": self.nickname,
            "requested_hash": self.requested_hash,
            "file_priority": self.file_priority,
            "enqueued_at": self.enqueued_at,
            "rank": self.rank,
        }


class UploadQueue:
    """In-memory upload queue following eMuleAI UploadQueue.cpp ordering.

    eMule default allows a small number of simultaneous upload slots
    (MIN_UP_CLIENTS_ALLOWED=2, practical floor 3-4 per UploadQueue.cpp
    AcceptNewClient/ForceNewClient); the full-queue threshold caps active
    clients at MAX_UP_CLIENTS_ALLOWED=100.  A granted slot is held for at
    most ``slot_ttl`` seconds (eMule session time/limit rules grant a bounded
    window before the uploader reclaims the slot).  Default TTL of 600s
    (10 min) covers the typical slot lifetime before re-queuing.
    """

    def __init__(self, max_slots: int = 4, slot_ttl: float = 600.0) -> None:
        self.max_slots = max_slots
        self.slot_ttl = slot_ttl
        self._waiting: dict[tuple[str, str], UploadClient] = {}
        self._slots: dict[tuple[str, str], float] = {}

    @staticmethod
    def _normalize_hash(file_hash: str) -> str:
        normalized = file_hash.strip().lower()
        if not _HEX32.fullmatch(normalized):
            raise UploadQueueError(
                "file hash must contain exactly 32 hexadecimal digits"
            )
        return normalized

    def _recompute(self) -> None:
        ordered = sorted(
            self._waiting.values(),
            key=lambda c: (-c.file_priority, c.enqueued_at),
        )
        for index, client in enumerate(ordered, start=1):
            object.__setattr__(client, "rank", index)

    def enqueue(
        self,
        user_hash: str,
        client_id: int,
        client_port: int,
        nickname: str,
        requested_hash: str,
        file_priority: int = 1,
    ) -> int:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        key = (normalized_user, normalized_file)

        if key in self._waiting or key in self._slots:
            self._recompute()
            client = self._waiting.get(key)
            if client is not None:
                log.info(
                    "UPLOAD client already waiting: user_hash=%s, requested_hash=%s, rank=%d",
                    normalized_user,
                    normalized_file,
                    client.rank,
                )
                return client.rank
            log.info(
                "UPLOAD client already granted slot: user_hash=%s, requested_hash=%s",
                normalized_user,
                normalized_file,
            )
            self._recompute()
            holder = self._waiting.get(key)
            return holder.rank if holder is not None else 0

        client = UploadClient(
            user_hash=normalized_user,
            client_id=client_id,
            client_port=client_port,
            nickname=nickname,
            requested_hash=normalized_file,
            file_priority=file_priority,
            enqueued_at=time.monotonic(),
            rank=0,
        )
        self._waiting[key] = client
        self._recompute()
        log.info(
            "UPLOAD client enqueued: user_hash=%s, requested_hash=%s, priority=%d, rank=%d",
            normalized_user,
            normalized_file,
            file_priority,
            client.rank,
        )
        return client.rank

    def rank_of(self, user_hash: str, requested_hash: str) -> int | None:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        client = self._waiting.get((normalized_user, normalized_file))
        if client is None:
            return None
        return client.rank

    def next_for_slot(self) -> UploadClient | None:
        if len(self._slots) >= self.max_slots:
            return None
        if not self._waiting:
            return None
        ordered = sorted(
            self._waiting.values(),
            key=lambda c: (-c.file_priority, c.enqueued_at),
        )
        return ordered[0]

    def grant_slot(self, user_hash: str, requested_hash: str) -> None:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        key = (normalized_user, normalized_file)
        if key in self._slots:
            raise UploadQueueError(
                f"slot already granted: user_hash={normalized_user}, requested_hash={normalized_file}"
            )
        if len(self._slots) >= self.max_slots:
            raise UploadQueueError(
                f"no free upload slots: active={len(self._slots)}, max={self.max_slots}"
            )
        candidate = self.next_for_slot()
        if candidate is None or candidate.user_hash != normalized_user or candidate.requested_hash != normalized_file:
            raise UploadQueueError(
                f"client is not at head of queue or no free slot: user_hash={normalized_user}, requested_hash={normalized_file}"
            )
        self._slots[key] = time.monotonic()
        self._waiting.pop(key, None)
        self._recompute()
        log.info(
            "UPLOAD slot granted: user_hash=%s, requested_hash=%s, active_slots=%d",
            normalized_user,
            normalized_file,
            len(self._slots),
        )

    def release_slot(self, user_hash: str, requested_hash: str) -> bool:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        key = (normalized_user, normalized_file)
        if key not in self._slots:
            return False
        del self._slots[key]
        log.info(
            "UPLOAD slot released: user_hash=%s, requested_hash=%s, active_slots=%d",
            normalized_user,
            normalized_file,
            len(self._slots),
        )
        return True

    def is_active(self, user_hash: str, requested_hash: str) -> bool:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        return (normalized_user, normalized_file) in self._slots

    def expired_slots(self) -> list[tuple[str, str]]:
        now = time.monotonic()
        expired: list[tuple[str, str]] = []
        for key, granted_at in self._slots.items():
            if now - granted_at >= self.slot_ttl:
                expired.append(key)
        return expired

    def cancel(self, user_hash: str, requested_hash: str) -> bool:
        normalized_user = self._normalize_hash(user_hash)
        normalized_file = self._normalize_hash(requested_hash)
        key = (normalized_user, normalized_file)
        removed_waiting = self._waiting.pop(key, None) is not None
        removed_slot = key in self._slots
        if removed_slot:
            del self._slots[key]
        if removed_waiting or removed_slot:
            self._recompute()
            log.info(
                "UPLOAD client cancelled: user_hash=%s, requested_hash=%s",
                normalized_user,
                normalized_file,
            )
            return True
        return False

    def waiting(self) -> list[UploadClient]:
        return sorted(
            self._waiting.values(),
            key=lambda c: (-c.file_priority, c.enqueued_at),
        )

    def snapshot(self) -> dict[str, object]:
        queued = self.waiting()
        return {
            "max_slots": self.max_slots,
            "active_slots": len(self._slots),
            "waiting": len(queued),
            "queue": [client.to_dict() for client in queued],
        }
