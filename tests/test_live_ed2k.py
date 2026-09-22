"""Live ED2K integration tests using a real server and real shared links.

These tests intentionally contain no fake loopback servers and no synthetic
result payloads.  They are disabled unless explicitly enabled with:

    AMULED_LIVE_ED2K=1

They default to the user's working ED2K server and use a real file selected
from the local, ignored AmuleD v1 metadata file.  Override the defaults with:

    AMULED_LIVE_SERVER=host:port
    AMULED_LIVE_QUERY=search text
    AMULED_LIVE_ED2K_LINK=ed2k://|file|...|

tests/test_live_ed2k.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added real-server login, search, and source integration tests.
  [+] Selected test targets from real local AmuleD v1 ed2k metadata.
  [+] Enforced a 30-second live search polling interval, matching the v1 UX.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import pytest

from amuled_v2.core.ed2k import (
    Ed2kServerClient,
    LoginRequest,
    parse_ed2k_file_link,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REAL_SHARED_JSON = _PROJECT_ROOT / "assets" / "v1" / "shared_files.json"
_DEFAULT_SERVER = "176.123.5.89:4725"
_LIVE_ENABLED = os.environ.get("AMULED_LIVE_ED2K", "").strip() == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="live ED2K tests require AMULED_LIVE_ED2K=1 and a real network",
)


@dataclass(frozen=True)
class RealEd2kTarget:
    name: str
    size: int
    file_hash: bytes
    link: str


def _server_endpoint() -> tuple[str, int]:
    value = os.environ.get("AMULED_LIVE_SERVER", _DEFAULT_SERVER).strip()
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError(f"invalid live server endpoint: {value}")
    return host, int(port_text)


def _parse_display_size(value: object) -> int:
    match = re.match(
        r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?i?b?)\s*$",
        str(value or ""),
        re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"invalid real shared-file size: {value!r}")
    number, unit = match.groups()
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1_000,
        "kb": 1_000,
        "m": 1_000_000,
        "mb": 1_000_000,
        "g": 1_000_000_000,
        "gb": 1_000_000_000,
        "t": 1_000_000_000_000,
        "tb": 1_000_000_000_000,
        "ki": 1_024,
        "kib": 1_024,
        "mi": 1_024**2,
        "mib": 1_024**2,
        "gi": 1_024**3,
        "gib": 1_024**3,
        "ti": 1_024**4,
        "tib": 1_024**4,
    }
    return int(float(number) * multipliers[unit.lower()])


def _real_target() -> RealEd2kTarget:
    override = os.environ.get("AMULED_LIVE_ED2K_LINK", "").strip()
    if override:
        parsed = parse_ed2k_file_link(override)
        return RealEd2kTarget(
            name=parsed.name,
            size=parsed.size,
            file_hash=parsed.file_hash,
            link=override,
        )

    if not _REAL_SHARED_JSON.exists():
        pytest.skip("real local shared_files.json is unavailable")
    payload = json.loads(_REAL_SHARED_JSON.read_text(encoding="utf-8-sig"))
    for item in payload:
        try:
            size = _parse_display_size(item.get("size"))
        except ValueError:
            continue
        if size <= 0:
            continue
        name = str(item.get("name") or "").strip()
        hash_text = str(item.get("hash") or "").strip()
        if len(hash_text) != 32:
            continue
        try:
            file_hash = bytes.fromhex(hash_text)
        except ValueError:
            continue
        link = f"ed2k://|file|{name.replace('|', '%7C')}|{size}|{hash_text.upper()}|/"
        return RealEd2kTarget(
            name=name,
            size=size,
            file_hash=file_hash,
            link=link,
        )
    pytest.skip("no usable real ed2k target found in local shared metadata")


def _query() -> str:
    return os.environ.get("AMULED_LIVE_QUERY", _real_target().name)


def _client() -> Ed2kServerClient:
    host, port = _server_endpoint()
    return Ed2kServerClient(
        host,
        port,
        LoginRequest.create(nickname="AmuleD_v2", client_port=8089),
        connect_timeout=12.0,
        response_timeout=30.0,
    )


@pytest.mark.asyncio
async def test_live_ed2k_server_login() -> None:
    client = _client()
    try:
        await client.connect()
        result = await client.login()
        assert client.logged_in is True
        assert result.client_id > 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_live_ed2k_search_real_query() -> None:
    query = _query()
    client = _client()
    try:
        await client.connect()
        await client.login()
        # ED2K search is cumulative over time; let the client own its 30s
        # result-accumulation window instead of cancelling it externally.
        results = await client.search(query)
        assert isinstance(results, (list, tuple))
        for result in results:
            assert len(result.file_hash) == 16
            assert result.name
            assert result.size > 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_live_ed2k_sources_for_real_link() -> None:
    target = _real_target()
    client = _client()
    try:
        await client.connect()
        await client.login()
        # The client response timeout normalizes no-reply to an empty source
        # response.  Do not wrap it in another timeout that cancels the task
        # before that protocol-specific normalization can run.
        found = await client.get_sources(target.file_hash, target.size)
        assert found.file_hash == target.file_hash
        assert isinstance(found.sources, tuple)
    finally:
        await client.close()
