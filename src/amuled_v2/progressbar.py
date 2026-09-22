"""Unicode progress bars for long-running CLI operations.

Renders smooth Unicode bars for search accumulation windows, UDP server
sweeps, and other multi-second processes.  The default block style is the
project standard ``⣀⣄⣆⣇⣧⣷⣿``.

src/amuled_v2/progressbar.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added smooth Unicode bar renderer with the project block style.
  [+] Added the full original style registry for CLI reuse.
"""

from __future__ import annotations

from typing import Sequence

__all__ = ["BAR_STYLE", "bar_styles", "render_progress", "fraction"]


BAR_STYLE = "⣀⣄⣆⣇⣧⣷⣿"

bar_styles: Sequence[str] = (
    "▁▂▃▄▅▆▇█",
    "⣀⣄⣤⣦⣶⣷⣿",
    BAR_STYLE,
    "○◔◐◕⬤",
    "□◱◧▣■",
    "□◱▨▩■",
    "□▨▩■",
    "□◱▥▦■",
    "░▒▓█",
    "░█",
    "⬜⬛",
    "▱▰",
    "▭◼",
    "▯▮",
    "◯⬤",
    "⚪⚫",
    "▏▎▍▌▋▊▉█",
)


def fraction(minimum: float, maximum: float, current: float) -> float:
    """Return the 0..1 progress ratio, clamped and division-safe."""
    if maximum <= minimum:
        return 0.0
    ratio = (current - minimum) / (maximum - minimum)
    return min(1.0, max(0.0, ratio))


def render_progress(
    minimum: float,
    maximum: float,
    current: float,
    width: int,
    *,
    style: str = BAR_STYLE,
    before: str = "⎹",
    after: str = "⎸",
) -> str:
    """Render a smooth Unicode bar of *width* characters."""
    if width <= 0:
        return before + after
    ratio = fraction(minimum, maximum, current)
    q_max = len(style) * width
    q_current = int(ratio * q_max)
    cells: list[str] = []
    for index in range(1, width + 1):
        cell_end = index * len(style)
        if cell_end <= q_current:
            cells.append(style[-1])
        elif cell_end - q_current < len(style):
            cells.append(style[q_current - cell_end])
        else:
            cells.append(style[0])
    return before + "".join(cells) + after
