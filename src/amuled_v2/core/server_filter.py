"""Server reliability tracking: dead/fake server detection and blacklisting.

The eD2K network is full of dead or spy servers that accept requests and stay
silent.  This module tracks per-server failure counts and applies a blacklist
cooldown, matching the reference client's dead-server retry policy.

src/amuled_v2/core/server_filter.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added failure counting with blacklist cooldown per server.
  [+] Added IP-filter integration for server selection.
  [+] Added allowed-server resolution over a candidate list.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from amuled_v2.core.ipfilter import IpFilter
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.IPFILTER, "core.server_filter")

__all__ = [
    "ServerFilter",
    "ServerVerdict",
    "DEFAULT_BLACKLIST_THRESHOLD",
    "DEFAULT_BLACKLIST_COOLDOWN_SECONDS",
]


DEFAULT_BLACKLIST_THRESHOLD = 3
DEFAULT_BLACKLIST_COOLDOWN_SECONDS = 30 * 60


@dataclass(frozen=True)
class ServerVerdict:
    """Selection outcome for one candidate server."""

    host: str
    port: int
    allowed: bool
    reason: str


@dataclass
class _ServerRecord:
    failures: int = 0
    blacklisted_until: float = 0.0
    successes: int = 0
    last_error: str = ""
    history: list[float] = field(default_factory=list)


class ServerFilter:
    """In-memory dead-server tracker combined with the IP filter."""

    def __init__(
        self,
        ip_filter: IpFilter | None = None,
        *,
        failure_threshold: int = DEFAULT_BLACKLIST_THRESHOLD,
        cooldown_seconds: float = DEFAULT_BLACKLIST_COOLDOWN_SECONDS,
        filter_level: int = 127,
    ) -> None:
        self.ip_filter = ip_filter
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.filter_level = filter_level
        self._records: dict[tuple[str, int], _ServerRecord] = {}

    def _record(self, host: str, port: int) -> _ServerRecord:
        return self._records.setdefault((host, port), _ServerRecord())

    def report_failure(self, host: str, port: int, reason: str = "timeout") -> bool:
        """Record one failure; returns True when the server got blacklisted."""
        record = self._record(host, port)
        record.failures += 1
        record.last_error = reason
        record.history.append(time.time())
        if record.failures >= self.failure_threshold:
            record.blacklisted_until = time.time() + self.cooldown_seconds
            log.warning(
                "SERVER blacklisted: host=%s, port=%d, failures=%d, "
                "cooldown_s=%.0f, reason=%s",
                host,
                port,
                record.failures,
                self.cooldown_seconds,
                reason,
            )
            return True
        return False

    def report_success(self, host: str, port: int) -> None:
        """Record one success; clears failure history."""
        record = self._record(host, port)
        record.failures = 0
        record.successes += 1
        record.blacklisted_until = 0.0
        record.last_error = ""

    def is_blacklisted(self, host: str, port: int) -> bool:
        record = self._records.get((host, port))
        if record is None:
            return False
        if record.blacklisted_until and time.time() >= record.blacklisted_until:
            record.blacklisted_until = 0.0
            record.failures = 0
            return False
        return record.blacklisted_until > 0.0

    def evaluate(self, host: str, port: int) -> ServerVerdict:
        """Apply IP filter and blacklist checks to one candidate."""
        if self.ip_filter is not None and self.ip_filter.is_filtered(
            host, level_threshold=self.filter_level
        ):
            matched = self.ip_filter.match(host)
            level = matched.level if matched else 0
            log.info(
                "SERVER rejected by ipfilter: host=%s, port=%d, level=%d",
                host,
                port,
                level,
            )
            return ServerVerdict(host, port, False, f"ipfilter level {level}")
        if self.is_blacklisted(host, port):
            return ServerVerdict(host, port, False, "blacklisted (dead server)")
        return ServerVerdict(host, port, True, "ok")

    def select_servers(
        self,
        candidates: list[tuple[str, int]],
    ) -> list[ServerVerdict]:
        """Evaluate a candidate list, keeping order, allowed first."""
        verdicts = [self.evaluate(host, port) for host, port in candidates]
        allowed = [v for v in verdicts if v.allowed]
        rejected = [v for v in verdicts if not v.allowed]
        return allowed + rejected

    def statistics(self) -> dict[str, object]:
        now = time.time()
        blacklisted = sum(
            1
            for record in self._records.values()
            if record.blacklisted_until > now
        )
        return {
            "tracked_servers": len(self._records),
            "blacklisted_servers": blacklisted,
            "failure_threshold": self.failure_threshold,
            "cooldown_seconds": self.cooldown_seconds,
            "ipfilter_ranges": len(self.ip_filter) if self.ip_filter else 0,
        }
