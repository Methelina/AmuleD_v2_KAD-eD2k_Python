"""Per-node RTT tracking with EWMA smoothing for the KAD engine.

src/amuled_v2/core/kad/rtt.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added EWMA RTT tracker with JSON export/load.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.rtt")

__all__ = ["RttSample", "RttTracker"]

_EWMA_ALPHA = 0.3
_MAX_SAMPLES = 100


@dataclass
class RttSample:
    """One measured RTT sample."""

    rtt_ms: float
    timestamp: float = field(default_factory=time.time)


class RttTracker:
    """Per-node EWMA RTT store keyed by ``(ip, udp_port)``."""

    def __init__(self, alpha: float = _EWMA_ALPHA) -> None:
        self._alpha = alpha
        self._ewma: Dict[Tuple[str, int], float] = {}
        self._samples: Dict[Tuple[str, int], List[RttSample]] = {}

    def update(self, key: Tuple[str, int], rtt_ms: float) -> float:
        if not math.isfinite(rtt_ms) or rtt_ms <= 0 or rtt_ms >= 300000:
            log.debug(
                "rtt sample rejected: key=%s:%d value=%s", key[0], key[1], rtt_ms
            )
            return self._ewma.get(key, 0.0)
        sample = RttSample(rtt_ms)
        history = self._samples.setdefault(key, [])
        history.append(sample)
        if len(history) > _MAX_SAMPLES:
            del history[: len(history) - _MAX_SAMPLES]
        previous = self._ewma.get(key, rtt_ms)
        value = previous * (1.0 - self._alpha) + rtt_ms * self._alpha
        self._ewma[key] = value
        return value

    def ewma(self, key: Tuple[str, int]) -> float:
        return self._ewma.get(key, 0.0)

    def samples(self, key: Tuple[str, int]) -> int:
        return len(self._samples.get(key, ()))

    def keys(self) -> List[Tuple[str, int]]:
        return list(self._ewma)

    def reset(self) -> None:
        self._ewma.clear()
        self._samples.clear()

    def export(self) -> Dict[str, Dict[str, float]]:
        return {
            "%s:%d" % key: {"ewma": value, "count": self.samples(key)}
            for key, value in self._ewma.items()
        }

    def load(self, data: Dict[str, Dict[str, float]]) -> None:
        for text, rec in (data or {}).items():
            ip, _, port = text.rpartition(":")
            try:
                key = (ip, int(port))
                value = float(rec["ewma"])
            except (KeyError, ValueError):
                continue
            self._ewma[key] = value
            self._samples[key] = [RttSample(value)]
        log.info("rtt tracker loaded: entries=%d", len(self._ewma))
