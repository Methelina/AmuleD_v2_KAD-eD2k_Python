"""Parse eMule/aMule nodes.dat bootstrap files into KadNodeInfo records.

src/amuled_v2/core/kad/nodes_dat.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added nodes.dat v0-v2 bootstrap contact parser.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.nodes_dat")

__all__ = ["KadNodeInfo", "NodesDatError", "load_nodes_dat"]


class NodesDatError(ValueError):
    """Raised when a nodes.dat file cannot be parsed."""


@dataclass(frozen=True)
class KadNodeInfo:
    """One parsed Kad bootstrap contact."""

    kad_id: bytes
    ip: str
    udp_port: int
    tcp_port: int
    contact_version: int = 0
    verified: bool = False
    udp_key: int = 0

    def __post_init__(self) -> None:
        if len(self.kad_id) != 16:
            raise ValueError(f"kad_id must be 16 bytes, got {len(self.kad_id)}")

    @property
    def key(self) -> tuple[str, int]:
        return self.ip, self.udp_port


def load_nodes_dat(path: str | Path) -> list[KadNodeInfo]:
    """Load and parse *path* as a ``nodes.dat`` bootstrap file."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        log.error(f"Cannot read nodes.dat: {path} ({exc})")
        raise NodesDatError(f"cannot read nodes.dat: {exc}") from exc

    return _parse_nodes_dat(data)


def _parse_nodes_dat(data: bytes) -> list[KadNodeInfo]:
    """Parse the in-memory byte image of a ``nodes.dat`` file."""
    offset = 0
    try:
        num_contacts_hint = struct.unpack_from("<I", data, offset)[0]
        offset += 4
    except struct.error as exc:
        raise NodesDatError(f"truncated nodes.dat header: {exc}") from exc

    total = len(data)
    if num_contacts_hint == 0:
        if total - offset >= 4:
            file_version = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if file_version in (1, 2, 3):
                if total - offset < 4:
                    raise NodesDatError("truncated nodes.dat after version")
                real_count = struct.unpack_from("<I", data, offset)[0]
                offset += 4
            else:
                raise NodesDatError("unsupported nodes.dat version")
        else:
            file_version = 0
            real_count = 0
    else:
        real_count = num_contacts_hint
        file_version = 0

    remaining = total - offset
    record_size = 25 if file_version < 2 else 34
    if real_count * record_size > remaining:
        raise NodesDatError(
            f"nodes.dat truncated: need {real_count * record_size} bytes "
            f"for {real_count} contacts, have {remaining}"
        )

    contacts: list[KadNodeInfo] = []
    skipped = 0
    for _ in range(real_count):
        kad_id = data[offset:offset + 16]
        offset += 16

        raw_ip_int = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        udp_port = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        tcp_port = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        if file_version >= 1:
            contact_version = data[offset]
            offset += 1
        else:
            _legacy_type = data[offset]
            offset += 1
            contact_version = 0
            if offset >= total:
                raise NodesDatError("truncated nodes.dat in legacy record")

        udp_key = 0
        verified = False
        if file_version >= 2:
            udp_key = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
            verified_flag = data[offset]
            offset += 1
            verified = bool(verified_flag)

        try:
            ip_str = str(ipaddress.IPv4Address(raw_ip_int))
        except (ValueError, ipaddress.AddressValueError):
            skipped += 1
            continue

        if udp_port == 0:
            skipped += 1
            continue

        contacts.append(
            KadNodeInfo(
                kad_id=kad_id,
                ip=ip_str,
                udp_port=udp_port,
                tcp_port=tcp_port,
                contact_version=contact_version,
                verified=verified,
                udp_key=udp_key,
            )
        )

    log.debug(
        "nodes.dat parsed: contacts=%d, skipped=%d, version=%d",
        len(contacts),
        skipped,
        file_version,
    )
    return contacts
