"""Explicit ED2K/Kademlia search channel model.

eMule-compatible clients have several search transports.  They are not
interchangeable: server and global both use ED2K server infrastructure, KAD
uses Kademlia keyword routing, and web-eDonkey uses an external HTTP service.
This module makes the selected channel explicit instead of hiding it behind a
generic ``search`` command.

src/amuled_v2/core/search_channels.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added eMule-compatible search channel enum and resolver.
  [+] Added capability-aware AUTO selection matching the reference behavior.
  [+] Added explicit implementation status for each channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "SearchChannel",
    "ChannelStatus",
    "ResolvedSearchChannel",
    "parse_search_channel",
    "resolve_auto_search_channel",
]


class SearchChannel(str, Enum):
    """eMule-compatible search channels."""

    AUTO = "auto"
    SERVER = "server"
    GLOBAL = "global"
    KAD = "kad"
    WEB_EDONKEY = "web-edonkey"


class ChannelStatus(str, Enum):
    """Implementation status in AmuleD v2."""

    IMPLEMENTED = "implemented"
    PLANNED = "planned"
    NOT_IMPLEMENTED = "not-implemented"


@dataclass(frozen=True)
class ResolvedSearchChannel:
    """Concrete channel chosen for one search request."""

    channel: SearchChannel
    status: ChannelStatus
    reason: str


def parse_search_channel(value: str) -> SearchChannel:
    """Parse a user-facing channel name."""
    try:
        return SearchChannel(value.strip().lower())
    except ValueError as exc:
        valid = ", ".join(item.value for item in SearchChannel)
        raise ValueError(f"invalid search channel {value!r}; expected one of: {valid}") from exc


def resolve_auto_search_channel(
    *,
    ed2k_connected: bool,
    kad_connected: bool,
    server_is_static: bool = False,
    server_users: int = 0,
    server_files: int = 0,
    server_count: int = 0,
) -> ResolvedSearchChannel:
    """Resolve AUTO using the reference eMule preference rules.

    eMule prefers KAD when both networks are connected, unless the connected
    server is static or appears trustworthy by the historical size thresholds.
    AmuleD currently implements only the ED2K TCP server channel, so AUTO can
    resolve to KAD only as an explicit planned channel, never pretending to run
    a KAD search.
    """
    if ed2k_connected and (
        server_is_static
        or (
            server_users > 40_000
            and server_files > 5_000_000
            and server_users < 5_000_000
            and 0 < server_count < 40
        )
    ):
        return ResolvedSearchChannel(
            SearchChannel.SERVER,
            ChannelStatus.IMPLEMENTED,
            "AUTO selected the ED2K server channel by reference eMule rules",
        )
    if kad_connected:
        return ResolvedSearchChannel(
            SearchChannel.KAD,
            ChannelStatus.PLANNED,
            "AUTO selected KAD by reference rules; the KAD search engine is not implemented yet",
        )
    if ed2k_connected:
        return ResolvedSearchChannel(
            SearchChannel.SERVER,
            ChannelStatus.IMPLEMENTED,
            "AUTO selected ED2K server because KAD is not connected",
        )
    raise ValueError("AUTO search requires a connected ED2K server or KAD")
