"""Pluggable node-selection strategies for KAD lookups and warm-up.

Switchable without code changes via env ``AMULED_KAD_SEED_STRATEGY``:
``xor`` (default, current behaviour), ``quality``, ``vivaldi``.

src/amuled_v2/core/kad/strategies.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added xor/quality/vivaldi ordering strategy registry.
"""

from __future__ import annotations

import math
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from amuled_v2.core.kad.quality import NodeStats, quality_score
from amuled_v2.core.kad.rtt import RttTracker
from amuled_v2.core.kad.vivaldi import LocalVivaldi
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.strategies")

__all__ = ["STRATEGIES", "get_strategy", "active_strategy_name"]

StatsLookup = Callable[[Any], NodeStats]


def _order_xor(
    candidates: List[Any],
    stats_lookup: StatsLookup,
    rtt: Optional[RttTracker] = None,
    vivaldi: Optional[LocalVivaldi] = None,
) -> List[Any]:
    """Identity ordering — the default XOR-first behaviour."""
    return list(candidates)


def _order_quality(
    candidates: List[Any],
    stats_lookup: StatsLookup,
    rtt: Optional[RttTracker] = None,
    vivaldi: Optional[LocalVivaldi] = None,
) -> List[Any]:
    """Quality-score DESC ordering (activity + RTT + recency)."""

    def _key(item: Any) -> float:
        return -quality_score(stats_lookup(item))

    return sorted(candidates, key=_key)


def _order_vivaldi(
    candidates: List[Any],
    stats_lookup: StatsLookup,
    rtt: Optional[RttTracker] = None,
    vivaldi: Optional[LocalVivaldi] = None,
) -> List[Any]:
    """Predicted-RTT ASC ordering (unknown -> infinity, stable)."""
    if vivaldi is None:
        return list(candidates)

    def _key(item: Any) -> float:
        return vivaldi.predict(stats_lookup_key(item))

    def stats_lookup_key(item: Any) -> Tuple[str, int]:
        stats = stats_lookup(item)
        # candidates are (ip, udp_port)-keyed or expose .key; fall back
        stats_key = getattr(item, "key", None)
        if isinstance(stats_key, tuple):
            return stats_key
        return ("", 0)

    return sorted(candidates, key=_key)


STRATEGIES: Dict[str, Callable[..., List[Any]]] = {
    "xor": _order_xor,
    "quality": _order_quality,
    "vivaldi": _order_vivaldi,
}


def get_strategy(name: str) -> Callable[..., List[Any]]:
    strategy = STRATEGIES.get((name or "xor").lower())
    if strategy is None:
        log.warning("unknown strategy selected: name=%s, using xor", name)
        return _order_xor
    if (name or "xor").lower() != "xor":
        log.info("node-selection strategy active: name=%s", name)
    return strategy


def active_strategy_name() -> str:
    return (os.environ.get("AMULED_KAD_SEED_STRATEGY", "xor") or "xor").lower()


class KadabraState:
    """Multi-armed bandit weights per node (Kadabra, arXiv 2210.12858).

    Reward rule used by the search loop: 1.0 when a response contained a
    strictly-closer contact, 2.0 for a SEARCH_RES, 0.2 for any response.
    Weights decay multiplicatively so stale nodes fade out.
    """

    ETA = 0.3
    DECAY = 0.9
    BASE = 1.0

    def __init__(self) -> None:
        self.weights: Dict[Tuple[str, int], float] = {}

    def reward(self, key: Tuple[str, int], value: float) -> None:
        weight = self.weights.get(key, self.BASE)
        weight *= math.exp(self.ETA * value)
        self.weights[key] = min(weight, 50.0)

    def decay(self, factor: float | None = None) -> None:
        f = self.DECAY if factor is None else factor
        for key in list(self.weights):
            self.weights[key] *= f

    def weight(self, key: Tuple[str, int]) -> float:
        return self.weights.get(key, self.BASE)

    def export(self) -> Dict[str, float]:
        return {"%s:%d" % k: v for k, v in self.weights.items()}

    def load(self, data: Dict[str, float]) -> None:
        for text, value in (data or {}).items():
            ip, _, port = text.rpartition(":")
            try:
                self.weights[(ip, int(port))] = float(value)
            except ValueError:
                continue


def _order_kadabra(
    candidates: List[Any],
    stats_lookup: StatsLookup,
    rtt: Optional[RttTracker] = None,
    vivaldi: Optional[LocalVivaldi] = None,
    state: Optional[KadabraState] = None,
) -> List[Any]:
    """Bandit-weight DESC ordering (Kadabra)."""
    if state is None:
        return list(candidates)
    return sorted(candidates, key=lambda item: -state.weight(_as_key(item)))


def _as_key(item: Any) -> Tuple[str, int]:
    key = getattr(item, "key", None)
    if isinstance(key, tuple):
        return key
    return ("", 0)


STRATEGIES["kadabra"] = _order_kadabra
