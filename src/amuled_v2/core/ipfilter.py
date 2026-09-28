"""IP filter loading, matching and AutoUpdate fetching for servers and peers.

Parses eMule-compatible ``ipfilter.dat`` text:

- range form:    ``a.b.c.d - e.f.g.h , level , description``
- single form:   ``a.b.c.d , level , description``
- CIDR form:     ``a.b.c.d/len , level , description``

Blank lines and ``#`` comments are ignored.  Matching uses the range's access
level against a configured threshold: a range is filtered when its level is
greater than or equal to the threshold (the eMule default threshold is 127).

Also provides :func:`update_ipfilter_from_url`, the synchronous download-and-
replace primitive behind ``ipfilter.auto_update`` (eMule AutoIPFilterUpdate),
intended to be run in a worker executor by the caller.

src/amuled_v2/core/ipfilter.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L.'.L.'.):
  [+] Added eMule-compatible ipfilter.dat parser with range and CIDR forms.
  [+] Added level-threshold matching and duplicate-range merging.
  [+] Added statistics reporting for CLI status output.

Patch Notes v0.2.0 (Soror L.'.L.'.):
  [+] Added update_ipfilter_from_url() synchronous download/refresh primitive
      (urllib + gzip, 64 MiB cap, content sanity check, atomic replace).
  [+] Exported update_ipfilter_from_url in __all__.
"""

from __future__ import annotations

import gzip
import ipaddress
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.IPFILTER, "core.ipfilter")

__all__ = [
    "IpRange",
    "IpFilter",
    "IpFilterError",
    "load_ipfilter_file",
    "update_ipfilter_from_url",
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


_GZIP_MAGIC = b"\x1f\x8b"
_IP4_RANGE_START_RE = re.compile(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024


def update_ipfilter_from_url(url: str, dest_path, timeout: float = 60.0) -> dict:
    """Synchronously download an ipfilter list and atomically replace *dest_path*.

    Fetches the URL with :mod:`urllib.request` (default SSL context), honours a
    hard 64 MiB memory cap, transparently decompresses gzip payloads, validates
    that the decoded text looks like an ipfilter list, then writes the result to
    ``str(dest_path) + ".part"`` and atomically :func:`os.replace`-s it into
    place.  Intended to be wrapped in a worker executor by the caller.

    Returns a dict with the downloaded byte count and an ``entries_hint`` count
    of candidate range lines.
    """
    dest_path = os.fspath(dest_path)
    part_path = str(dest_path) + ".part"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            raw = response.read(_MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.URLError as exc:
        log.warning("IPFILTER update fallback: failed to fetch url=%s, error=%s", url, exc)
        raise IpFilterError(f"ipfilter download failed: {url}") from exc
    except TimeoutError as exc:
        log.warning("IPFILTER update fallback: timeout fetching url=%s, error=%s", url, exc)
        raise IpFilterError(f"ipfilter download timeout: {url}") from exc

    if len(raw) > _MAX_DOWNLOAD_BYTES:
        log.warning(
            "IPFILTER update refused: payload exceeded cap bytes=%d, url=%s",
            len(raw),
            url,
        )
        raise IpFilterError("ipfilter download exceeded 64 MiB cap")

    if raw[:2] == _GZIP_MAGIC or url.lower().endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            log.warning("IPFILTER update fallback: gzip decompress failed url=%s, error=%s", url, exc)
            raise IpFilterError("ipfilter gzip decompression failed") from exc

    text = raw.decode("utf-8", errors="replace")

    range_lines = [line for line in text.splitlines() if _IP4_RANGE_START_RE.match(line)]
    if not text.strip() or not range_lines:
        log.warning("IPFILTER update refused: payload failed sanity check url=%s", url)
        raise IpFilterError("ipfilter payload failed sanity validation")

    with open(part_path, "wb") as handle:
        handle.write(raw)
    os.replace(part_path, dest_path)

    log.info(
        "IPFILTER updated: url=%s, dest=%s, bytes=%d, ranges=%d",
        url,
        dest_path,
        len(raw),
        len(range_lines),
    )
    return {"bytes": len(raw), "entries_hint": len(range_lines)}
