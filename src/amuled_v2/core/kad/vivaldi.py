"""Local Vivaldi network coordinates for the KAD engine (no wire exchange).

Vanilla kad2 HELLO carries no coordinate field, so remote positions are
unavailable; this module keeps only our own position, moved by measured
RTT magnitudes (PONG timing).  Useful as a low-RTT-first tie-breaker, not
as a distributed coordinate system.

src/amuled_v2/core/kad/vivaldi.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added local Vivaldi position port with JSON persistence.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.vivaldi")

__all__ = ["VivaldiPosition", "LocalVivaldi"]

VIVALDI_CC = 0.25
VIVALDI_CE = 0.5
VIVALDI_ERROR_MIN = 0.1
VIVALDI_INITIAL_ERROR = 10.0
VIVALDI_CONVERGE_EVERY = 5


@dataclass
class VivaldiPosition:
    """3D network coordinate for RTT estimation."""

    x: float = 0.0
    y: float = 0.0
    h: float = 0.0
    error: float = VIVALDI_INITIAL_ERROR
    _update_count: int = field(default=0, repr=False)

    def is_valid(self) -> bool:
        return (
            math.isfinite(self.x)
            and math.isfinite(self.y)
            and math.isfinite(self.h)
            and abs(self.x) <= 30000
            and abs(self.y) <= 30000
        )

    def at_origin(self) -> bool:
        return self.x == 0.0 and self.y == 0.0

    def measure(self) -> float:
        return math.sqrt(self.x * self.x + self.y * self.y) + abs(self.h)

    def distance_to(self, other: "VivaldiPosition") -> float:
        dx = self.x - other.x
        dy = self.y - other.y
        return math.sqrt(dx * dx + dy * dy) + abs(self.h + other.h)

    def update(self, rtt_ms: float, remote: "VivaldiPosition") -> None:
        """Update position based on a measured RTT."""
        if not math.isfinite(rtt_ms) or rtt_ms <= 0 or rtt_ms > 300000:
            return
        if not remote.is_valid() or self.error + remote.error == 0:
            return

        weight = self.error / (remote.error + self.error)
        predicted = self.distance_to(remote)
        residual = rtt_ms - predicted
        sample_error = abs(residual) / rtt_ms
        new_error = (
            sample_error * VIVALDI_CE * weight
            + self.error * (1.0 - VIVALDI_CE * weight)
        )
        scale = VIVALDI_CC * weight * residual

        target_x = remote.x + random.uniform(-0.1, 0.1)
        target_y = remote.y + random.uniform(-0.1, 0.1)
        dx = self.x - target_x
        dy = self.y - target_y
        dist = math.sqrt(dx * dx + dy * dy)
        if dist > 0:
            new_x = self.x + (dx / dist) * scale
            new_y = self.y + (dy / dist) * scale
        else:
            angle = random.uniform(0, 2 * math.pi)
            new_x = self.x + math.cos(angle) * scale
            new_y = self.y + math.sin(angle) * scale

        candidate = VivaldiPosition(new_x, new_y, self.h, new_error)
        if candidate.is_valid() and math.isfinite(new_error):
            self.x = new_x
            self.y = new_y
            self.error = max(new_error, VIVALDI_ERROR_MIN)
        else:
            self.x = self.y = self.h = 0.0
            self.error = VIVALDI_INITIAL_ERROR

        if not remote.at_origin():
            self._update_count += 1
        if self._update_count > VIVALDI_CONVERGE_EVERY:
            self._update_count = 0
            self.update(10.0, VivaldiPosition(0, 0, 0, 50.0))

    def to_list(self) -> list[float]:
        return [self.x, self.y, self.h, self.error]

    def from_list(self, values: list[float]) -> None:
        if len(values) >= 3:
            self.x = float(values[0])
            self.y = float(values[1])
            self.h = float(values[2])
        if len(values) >= 4:
            self.error = float(values[3])


class LocalVivaldi:
    """Our own coordinate, moved by measured RTT magnitudes."""

    def __init__(self) -> None:
        self.position = VivaldiPosition()
        self._updates = 0

    def update(self, key: Tuple[str, int], rtt_ms: float) -> None:
        self.position.update(rtt_ms, VivaldiPosition())
        self._updates += 1
        if self._updates % 25 == 0:
            log.info(
                "vivaldi local position: coord=%s updates=%d",
                self.position.to_list(),
                self._updates,
            )

    def predict(self, key: Tuple[str, int]) -> float:
        """Predicted RTT magnitude toward a node (no remote coordinate)."""
        return self.position.measure()

    def export(self) -> list[float]:
        return self.position.to_list()

    def load(self, data: Any) -> None:
        if isinstance(data, (list, tuple)) and data:
            self.position.from_list(list(data))
