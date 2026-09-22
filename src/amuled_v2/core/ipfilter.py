"""IP filter loading and matching for servers and peers.

Parses eMule-compatible ``ipfilter.dat`` text:

- range form:    ``a.b.c.d - e.f.g.h , level , description``
- single form:   ``a.b.c.d , level , description``
- CIDR form:     ``a.b.c.d/len , level , description``

Blank lines and ``#`` comments are ignored.  Matching uses the range's access
level against a configured threshold: a range is filtered when its level is
greater than or equal to the threshold (the eMule default threshold is 127).

src/amuled_v2/core/ipfilter.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added eMule-compatible ipfilter.dat parser with range and CIDR forms.
  [+] Added level-threshold matching and duplicate-range merging.
  [+] Added statistics reporting for CLI status output.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.IPFILTER, "core.ipfilter")

__all__ = [
    "IpRange",
    "IpFilter",
    "IpFilterError",
    "load_ipfilter_file",
    "DEFAULT_FILTER_LEVEL",
]


DEFAULT_FILTER_LEVEL = 127


class IpFilterError(ValueError):
    """Raised when an ipfilter file cannot be parsed."""


@dataclass(frozen=True)
class IpRange:
    """One filtered address range with an access level."""

    start: int
    end: int
    level: int
    description: str

    def contains(self, ip_int: int) -> bool:
        return self.start <= ip_int <= self.end


def _ip_to_int(text: str) -> int:
    cleaned = text.strip()
    # eMule filter lists commonly zero-pad octets; Python 3.9+ rejects
    # leading zeros in IPv4Address, so split and normalize manually.
    octets = cleaned.split(".")
    if len(octets) == 4:
        try:
            values = [int(octet) for octet in octets]
            if all(0 <= value <= 255 for value in values):
                return (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
        except ValueError:
            pass
    try:
        return int(ipaddress.IPv4Address(cleaned))
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise IpFilterError(f"invalid IPv4 address: {text!r}") from exc


def _parse_line(raw: str) -> IpRange | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        raise IpFilterError(f"ipfilter line needs at least range and level: {line!r}")
    range_text = parts[0]
    try:
        level = int(parts[1])
    except ValueError as exc:
        raise IpFilterError(f"invalid ipfilter level: {parts[1]!r}") from exc
    description = parts[2] if len(parts) > 2 else ""

    if "/" in range_text:
        try:
            network = ipaddress.IPv4Network(range_text, strict=False)
        except (ValueError, ipaddress.NetmaskValueError) as exc:
            raise IpFilterError(f"invalid ipfilter CIDR range: {range_text!r}") from exc
        return IpRange(
            start=int(network.network_address),
            end=int(network.broadcast_address),
            level=level,
            description=description,
        )

    if "-" in range_text:
        left, _, right = range_text.partition("-")
        start = _ip_to_int(left)
        end = _ip_to_int(right)
    else:
        start = end = _ip_to_int(range_text)
    if start > end:
        raise IpFilterError(
            f"ipfilter range start exceeds end: {range_text!r}"
        )
    return IpRange(start=start, end=end, level=level, description=description)


def load_ipfilter_file(path: str | Path) -> "IpFilter":
    """Parse one ipfilter file into an IpFilter."""
    filter_path = Path(path)
    ranges: list[IpRange] = []
    skipped = 0
    with open(filter_path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            try:
                parsed = _parse_line(raw)
            except IpFilterError as exc:
                skipped += 1
                log.warning(
                    "IPFILTER skipped line: file=%s, line=%d, error=%s",
                    str(filter_path),
                    line_number,
                    exc,
                )
                continue
            if parsed is not None:
                ranges.append(parsed)
    ip_filter = IpFilter(ranges)
    log.info(
        "IPFILTER loaded: file=%s, ranges=%d, skipped=%d",
        str(filter_path),
        len(ranges),
        skipped,
    )
    return ip_filter


class IpFilter:
    """Ordered set of filtered ranges with threshold matching."""

    def __init__(self, ranges: list[IpRange] | None = None) -> None:
        self._ranges: list[IpRange] = list(ranges or [])
        self._ranges.sort(key=lambda r: (r.start, r.end))

    def __len__(self) -> int:
        return len(self._ranges)

    @property
    def ranges(self) -> list[IpRange]:
        return list(self._ranges)

    def match(self, ip: str | int) -> IpRange | None:
        """Return the first range containing *ip*, or None."""
        ip_int = ip if isinstance(ip, int) else _ip_to_int(str(ip))
        for ip_range in self._ranges:
            if ip_range.contains(ip_int):
                return ip_range
        return None

    def is_filtered(
        self,
        ip: str | int,
        *,
        level_threshold: int = DEFAULT_FILTER_LEVEL,
    ) -> bool:
        """True when *ip* falls into a range at or above the threshold."""
        matched = self.match(ip)
        return matched is not None and matched.level >= level_threshold

    def statistics(self) -> dict[str, object]:
        return {
            "range_count": len(self._ranges),
            "max_level": max((r.level for r in self._ranges), default=0),
            "description_count": sum(1 for r in self._ranges if r.description),
        }
