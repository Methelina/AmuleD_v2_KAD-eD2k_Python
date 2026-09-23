"""Node quality scoring for KAD peer prioritisation.

src/amuled_v2/core/kad/quality.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added activity/RTT/recency quality score and ranking helper.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, List, Tuple

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.quality")

__all__ = ["NodeStats", "quality_score", "rank"]


@dataclass
class NodeStats:
    """Aggregated per-node activity/latency state."""

    hellos: int = 0
    pings: int = 0
    rtt_ewma: float = 0.0
    last_seen: float = 0.0
    fails: int = 0
    positioned: bool = False


def quality_score(stats: NodeStats, now: float | None = None) -> float:
    """Combined node quality in ``[0.0, 1.0]`` (higher = better)."""
    now = time.time() if now is None else now
    activity = min(1.0, (stats.hellos + stats.pings) / 10.0)
    rtt_score = 0.0
    if stats.rtt_ewma > 0:
        rtt_score = max(0.0, 1.0 - stats.rtt_ewma / 1000.0)
    idle = now - stats.last_seen if stats.last_seen > 0 else 9999.0
    recency = max(0.0, 1.0 - idle / 3600.0)
    score = activity * 0.4 + rtt_score * 0.4 + recency * 0.2
    score -= min(0.5, stats.fails * 0.05)
    return max(0.0, min(1.0, score))


def rank(items: List[Tuple[Any, NodeStats]]) -> List[Tuple[Any, NodeStats]]:
    """Stable sort by quality score descending."""

    def _key(item: Tuple[Any, NodeStats]) -> float:
        return -quality_score(item[1])

    return sorted(items, key=_key)
