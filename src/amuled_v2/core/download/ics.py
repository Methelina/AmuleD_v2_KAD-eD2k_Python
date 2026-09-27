"""Intelligent Chunk Selection (ICS) block-request algorithm for AmuleD.

Pure, dependency-light port of eMule's ICS dispatch (PartFile.cpp) to AmuleD.
No asyncio, no I/O, only stdlib + project logging. All gap/requested/block
ranges are INCLUSIVE (start, end) byte ranges, matching eMule's gaplist
semantics and the project's queue.gap_ranges convention.

Oracle: eMuleAI PartFile.cpp — GetNextRequestedBlockICS (7367-7521),
GetNextEmptyBlockInPart (2777-2851), ShrinkToAvoidAlreadyRequested
(2698-2741), IsAlreadyRequested (2674-2696), CalcDownloadingParts (7340-7358).

src/amuled_v2/core/download/ics.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Port of ICS block-request algorithm from eMuleAI PartFile.cpp.
  [+] Constants: PART_SIZE, EMBLOCK_SIZE, CM_* modes and thresholds.
  [+] part_count / part_bounds: eMule GetED2KPartCount and per-part bounds.
  [+] is_already_requested / shrink_to_avoid / next_block_in_part:
      PartFile.cpp:2674-2851 duplicate-prevention and block derivation.
  [+] ics_mode: ICS mode selection (RELEASE/SPREAD/SHARE) per PartFile.cpp:7382-7396.
  [+] choose_part: GetNextRequestedBlockICS (PartFile.cpp:7367-7521) per-candidate
      preference packing per recon section 3.
  [+] select_blocks: top-level multi-block emission loop per PartFile.cpp:7496-7514.
"""

from __future__ import annotations

import math
import random
from typing import Iterable, Mapping, Sequence

from ...logging_setup import LogTags, get_tagged_logger

# ---------------------------------------------------------------------------
# Constants (recon section 7: PartFile.cpp:7369-7374).
# PARTSIZE = 9728000; EMBLOCKSIZE = 184320.
# ---------------------------------------------------------------------------
PART_SIZE = 9_728_000
EMBLOCK_SIZE = 184_320

# ICS chunk-selection modes (PartFile.cpp:7369-7374).
CM_RELEASE_MODE = 1
CM_SPREAD_MODE = 2
CM_SHARE_MODE = 3

# ICS thresholds.
CM_SPREAD_MINSRC = 10
CM_SHARE_MINSRC = 25
CM_MAX_SRC_CHUNK = 3

# Module-level RNG for tie-breaking (PartFile.cpp:7451-7483 randomisation).
_rng = random.Random()

# Debug logger (tagged); diagnostics only, no user-facing prints.
_log = get_tagged_logger(LogTags.DOWNLOAD, "core.download.ics")

__all__ = [
    "PART_SIZE",
    "EMBLOCK_SIZE",
    "CM_RELEASE_MODE",
    "CM_SPREAD_MODE",
    "CM_SHARE_MODE",
    "CM_SPREAD_MINSRC",
    "CM_SHARE_MINSRC",
    "CM_MAX_SRC_CHUNK",
    "part_count",
    "part_bounds",
    "is_already_requested",
    "shrink_to_avoid",
    "next_block_in_part",
    "ics_mode",
    "choose_part",
    "select_blocks",
]


def part_count(total_size: int) -> int:
    """eMule GetED2KPartCount: max(1, ceil(total_size / PART_SIZE))."""
    if total_size <= 0:
        return 1
    return max(1, math.ceil(total_size / PART_SIZE))


def part_bounds(part: int, total_size: int) -> tuple[int, int]:
    """Inclusive [partStart, partEnd]; partEnd = min(partStart+PART_SIZE, total_size) - 1."""
    part_start = part * PART_SIZE
    part_end = min(part_start + PART_SIZE, total_size) - 1
    return part_start, part_end


# ---------------------------------------------------------------------------
# Duplicate prevention (PartFile.cpp:2674-2741).
# requested ranges are INCLUSIVE (start, end) byte ranges.
# ---------------------------------------------------------------------------


def is_already_requested(start: int, end: int, requested: Iterable[tuple[int, int]]) -> bool:
    """Any overlap with requested (start, end) inclusive ranges.

    PartFile.cpp:2674-2696 IsAlreadyRequested: true if the requested block
    overlaps any entry in requestedblocks_list.
    """
    for r_start, r_end in requested:
        if start <= r_end and r_start <= end:
            return True
    return False


def shrink_to_avoid(start: int, end: int, requested: Iterable[tuple[int, int]]) -> tuple[int, int] | None:
    """Trim (start, end) inclusive against each requested range until no overlap.

    PartFile.cpp:2698-2741 ShrinkToAvoidAlreadyRequested: for each requested
    range, if it fully covers [start, end] the block is void (return None);
    otherwise clip start up or end down. Returns the trimmed inclusive range,
    or None if nothing valid remains.
    """
    cur_start, cur_end = start, end
    # Materialise once because we may iterate and re-iterate in the worst case.
    ranges = list(requested)
    if not ranges:
        if cur_end < cur_start:
            return None
        return cur_start, cur_end
    # Iterate to fixpoint: clipping against one range may expose overlap with
    # another.  A bounded loop is safe because ranges are finite and disjoint
    # requests only ever shrink the interval.
    changed = True
    guard = 0
    while changed and guard < len(ranges) + 1:
        changed = False
        guard += 1
        for r_start, r_end in ranges:
            if cur_end < cur_start:
                return None
            if r_start <= cur_start and r_end >= cur_end:
                # Fully covered.
                return None
            if cur_start >= r_start and cur_start <= r_end:
                cur_start = r_end + 1
                changed = True
            elif cur_end >= r_start and cur_end <= r_end:
                cur_end = r_start - 1
                changed = True
    if cur_end < cur_start:
        return None
    return cur_start, cur_end


def next_block_in_part(
    part: int,
    total_size: int,
    gaps: Iterable[tuple[int, int]],
    requested: Iterable[tuple[int, int]],
) -> tuple[int, int] | None:
    """GetNextEmptyBlockInPart (PartFile.cpp:2777-2851).

    gaps: iterable of INCLUSIVE (start, end) byte ranges that are NOT yet
    downloaded.  Find the first gap overlapping [partStart, partEnd]; clamp to
    the part and to one EMBLOCK boundary, then shrink against `requested`.
    Returns the inclusive block range or None if nothing remains.
    """
    part_start, part_end = part_bounds(part, total_size)
    req_list = list(requested)
    for g_start, g_end in gaps:
        if g_end < part_start or g_start > part_end:
            continue
        # Walk EMBLOCK windows forward through this gap: the first window
        # may already be fully covered by outstanding requests (the gap
        # only clears when the data arrives, not when it is requested).
        start = max(g_start, part_start)
        gap_limit = min(g_end, part_end)
        while start <= gap_limit:
            block_end = (
                part_start
                + ((start - part_start) // EMBLOCK_SIZE + 1) * EMBLOCK_SIZE
                - 1
            )
            end = min(gap_limit, block_end)
            shrunk = shrink_to_avoid(start, end, req_list)
            if shrunk is not None:
                return shrunk
            start = end + 1
    return None


# ---------------------------------------------------------------------------
# ICS mode selection (PartFile.cpp:7382-7396).
# ---------------------------------------------------------------------------


def ics_mode(frequencies: Sequence[int], gap_parts: Iterable[int]) -> int:
    """min_src = min over parts listed in gap_parts of frequencies[p].

    PartFile.cpp:7392-7396: min_src <= CM_SPREAD_MINSRC -> RELEASE;
    min_src <= CM_SHARE_MINSRC -> SPREAD; default SHARE.
    If no gap parts or empty frequencies -> SHARE.
    """
    gap_parts_list = list(gap_parts)
    if not gap_parts_list or not frequencies:
        return CM_SHARE_MODE
    min_src = None
    for p in gap_parts_list:
        if 0 <= p < len(frequencies):
            f = frequencies[p]
            if min_src is None or f < min_src:
                min_src = f
    if min_src is None:
        return CM_SHARE_MODE
    if min_src <= CM_SPREAD_MINSRC:
        return CM_RELEASE_MODE
    if min_src <= CM_SHARE_MINSRC:
        return CM_SPREAD_MODE
    return CM_SHARE_MODE


# ---------------------------------------------------------------------------
# Per-candidate preference packing (PartFile.cpp:7431-7449, recon section 3).
# ---------------------------------------------------------------------------


def _c_pref(
    mode: int,
    p: int,
    size2transfer: int,
    parts_downloading: int,
    gap_size: int,
) -> int:
    """Compute the c_pref priority for candidate part p per ICS mode.

    Faithful to PartFile.cpp:7431-7446 (recon section 3).  Simplifications:
      - incomplete_src / complete_src: eMule tracks per-part partial/complete
        source counts (m_SrcIncPartFrequency / m_SrcPartFrequency) separately
        (PartFile.cpp:3644-3647); we do not, so both are 0 (documented).
      - first_last_mod: eMule tracks part modification/ask ordering
        (PartFile.cpp:7453-7455); we do not, so it is 0 (documented).
    """
    # size2transfer_shifted = min(0xFFFF, (size2transfer + PARTSIZE*pd/CM_MAX_SRC_CHUNK) >> 8)
    combined = size2transfer + (PART_SIZE * parts_downloading) // CM_MAX_SRC_CHUNK
    size2transfer_shifted = min(0xFFFF, combined >> 8)
    # first_last_mod is not tracked; use 0.
    first_last_mod = 0
    # incomplete_src / complete_src not tracked; use 0.
    incomplete_src = 0
    complete_src = 0

    if mode == CM_RELEASE_MODE:
        # size2transfer | (incomplete_src << 16) | (complete_src << 24)
        pref = size2transfer | (incomplete_src << 16) | (complete_src << 24)
    elif mode == CM_SPREAD_MODE:
        # first_last_mod | (incomplete_src << 2) | (complete_src << 8) | (size2transfer << 16)
        pref = (
            first_last_mod
            | (incomplete_src << 2)
            | (complete_src << 8)
            | (size2transfer_shifted << 16)
        )
    else:  # CM_SHARE_MODE
        # first_last_mod | (size2transfer << 16)
        pref = first_last_mod | (size2transfer_shifted << 16)

    # Over-assignment penalty (PartFile.cpp:7448-7449):
    # if downloading sources on this part >= ceil(gap_size * 3 / PART_SIZE) -> set 0xFF000000.
    if gap_size > 0:
        threshold = math.ceil(gap_size * 3 / PART_SIZE)
        if parts_downloading >= threshold:
            pref |= 0xFF000000
    return pref


def choose_part(
    available: frozenset[int],
    frequencies: Sequence[int],
    gap_parts: Iterable[int],
    gap_sizes: Mapping[int, int],
    downloading_counts: Mapping[int, int],
    last_part: int | None,
    total_size: int,
) -> int | None:
    """GetNextRequestedBlockICS (PartFile.cpp:7367-7521), faithful port.

    - candidates = parts p where p in available AND p has a gap (in gap_parts /
      gap_sizes).
    - mode = ics_mode(frequencies, gap_parts).
    - per candidate c_pref packing per recon section 3 EXACTLY.
    - sticky chunk (PartFile.cpp:7490-7494): if last_part is a candidate, it
      wins outright (inserted at head with pref 0).
    - else pick minimal c_pref; ties broken by random module-level instance
      (random.choice among tied candidates) per PartFile.cpp:7451-7483.
    """
    gap_parts_list = list(gap_parts)
    gap_parts_set = set(gap_parts_list)
    if not gap_parts_list:
        return None

    candidates: list[tuple[int, int]] = []
    for p in gap_parts_list:
        if p not in available:
            continue
        gap_size = gap_sizes.get(p, 0)
        if gap_size <= 0:
            continue
        size2transfer = PART_SIZE - gap_size
        parts_downloading = downloading_counts.get(p, 0)
        mode = ics_mode(frequencies, gap_parts_set)
        pref = _c_pref(mode, p, size2transfer, parts_downloading, gap_size)
        candidates.append((p, pref))

    if not candidates:
        return None

    # Sticky chunk (PartFile.cpp:7490-7494): last requested chunk wins outright.
    if last_part is not None:
        for p, pref in candidates:
            if p == last_part:
                _log.debug(
                    "sticky chunk selected: part=%d pref=%d", p, pref
                )
                return p

    # Pick minimal c_pref (lowest = highest priority); ties randomised.
    min_pref = min(c[1] for c in candidates)
    tied = [p for p, pref in candidates if pref == min_pref]
    chosen = _rng.choice(tied)
    _log.debug(
        "choose_part: chosen=%d min_pref=%d candidates=%d", chosen, min_pref, len(candidates)
    )
    return chosen


# ---------------------------------------------------------------------------
# Top-level multi-block emission (PartFile.cpp:7496-7514).
# ---------------------------------------------------------------------------


def select_blocks(
    total_size: int,
    gaps: Sequence[tuple[int, int]],
    available: frozenset[int],
    frequencies: Sequence[int],
    downloading_counts: Mapping[int, int],
    last_part: int | None,
    requested: Iterable[tuple[int, int]],
    max_blocks: int = 3,
) -> tuple[list[tuple[int, int]], int | None]:
    """Top-level ICS block selection loop.

    Splits gaps into per-part gap_sizes; loops: choose_part -> next_block_in_part
    (feeding `requested`); each issued block extends the requested registry so
    subsequent blocks do not duplicate within the same call.  Sticky: subsequent
    iterations pass the chosen part as last_part (PartFile.cpp:7496-7514).
    Stops at max_blocks or no candidates.

    Returns (list of inclusive (start, end) ranges, last chosen part or None).
    """
    n_parts = part_count(total_size)
    last = last_part
    issued: list[tuple[int, int]] = []
    req: list[tuple[int, int]] = list(requested)

    # Pre-compute per-part gap sizes and gap_parts set.
    gap_parts: list[int] = []
    gap_sizes: dict[int, int] = {}
    for p in range(n_parts):
        p_start, p_end = part_bounds(p, total_size)
        if p_end < p_start:
            continue
        part_gap = 0
        for g_start, g_end in gaps:
            ov_start = max(g_start, p_start)
            ov_end = min(g_end, p_end)
            if ov_end >= ov_start:
                part_gap += ov_end - ov_start + 1
        if part_gap > 0:
            gap_parts.append(p)
            gap_sizes[p] = part_gap

    for _ in range(max_blocks):
        chosen = choose_part(
            available,
            frequencies,
            gap_parts,
            gap_sizes,
            downloading_counts,
            last,
            total_size,
        )
        if chosen is None:
            break

        block = next_block_in_part(chosen, total_size, gaps, req)
        if block is None:
            # Chosen part has no remaining block; mark exhausted for this call.
            gap_sizes.pop(chosen, None)
            if chosen in gap_parts:
                gap_parts.remove(chosen)
            last = chosen
            continue

        issued.append(block)
        req.append(block)
        last = chosen

    if issued:
        return issued, last
    return [], None
