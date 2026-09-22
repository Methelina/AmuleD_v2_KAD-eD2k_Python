#!/usr/bin/env python3
"""Live ED2K search/source diagnostic against a real ED2K server.

This script intentionally performs no fake-server test.  It connects to a real
ED2K server, logs in, executes a real query, and optionally requests sources
for a real ``ed2k://`` link.  Defaults use the local, ignored AmuleD v1 shared
metadata when available.

scripts/live_ed2k_search.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added real global search and real link source lookup.
  [+] Added optional DuckDB persistence for returned sources.
  [*] Uses only the standalone K client protocol stack.

Patch Notes v0.1.1 (Soror L.'.L'.):
  [+] Added --file to test alternative live server lists without replacing the
      bundled baseline automatically.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial bounded live-server login validation for M4.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from amuled_v2.core.ed2k import (
    Ed2kLinkError,
    Ed2kServerClient,
    LoginRequest,
    parse_ed2k_file_link,
)
from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

log = get_tagged_logger(LogTags.SERVER, "scripts.live_ed2k_search")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REAL_SHARED_JSON = _PROJECT_ROOT / "assets" / "v1" / "shared_files.json"
_REAL_SHAREDDIR = _PROJECT_ROOT / "assets" / "v1" / "shareddir.dat"
_DEFAULT_SERVER = "176.123.5.89:4725"


def _load_real_target(path: str | None) -> tuple[str, int, bytes, str] | None:
    """Return one real name/size/hash/link from local v1 metadata."""
    if path:
        parsed = parse_ed2k_file_link(path)
        return parsed.name, parsed.size, parsed.file_hash, path
    if not _REAL_SHARED_JSON.exists():
        return None
    payload = json.loads(_REAL_SHARED_JSON.read_text(encoding="utf-8-sig"))
    for item in payload:
        try:
            size = int(str(item.get("size_display_bytes", "") or 0))
        except ValueError:
            continue
        name = str(item.get("name") or "").strip()
        hash_text = str(item.get("hash") or "").strip()
        if size <= 0 or len(name) == 0 or len(hash_text) != 32:
            continue
        try:
            file_hash = bytes.fromhex(hash_text)
        except ValueError:
            continue
        link = f"ed2k://|file|{name.replace('|', '%7C')}|{size}|{file_hash.hex().upper()}|/"
        return name, size, file_hash, link
    return None


async def run(args: argparse.Namespace) -> int:
    from amuled_v2.core.ed2k import Ed2kServerClient

    host, separator, port_text = args.server.rpartition(":")
    if not separator or not host:
        raise ValueError(f"invalid server endpoint: {args.server}")
    port = int(port_text)

    target = _load_real_target(args.link)
    query = args.query or (target[0] if target else None)
    if not query:
        raise ValueError("a real search query is required when no real link is available")

    client = Ed2kServerClient(
        host,
        port,
        LoginRequest.create(nickname="AmuleD_v2", client_port=args.client_port),
        connect_timeout=args.timeout,
        response_timeout=args.timeout,
    )
    try:
        await client.connect()
        login_result = await client.login()
        log.info(
            f"LIVE LOGIN OK: endpoint={args.server}, client_id={login_result.client_id}, "
            f"low_id={login_result.low_id}"
        )

        results = await client.search(query)
        result_payload = {
            "server": args.server,
            "login": {
                "client_id": login_result.client_id,
                "low_id": login_result.low_id,
            },
            "query": query,
            "results": [result.to_dict() for result in results],
            "result_count": len(results),
        }

        if args.link or target:
            link_name, link_size, link_hash, _ = target  # type: ignore[misc]
            found = await client.get_sources(link_hash, link_size)
            saved_sources = 0
            if args.save:
                from amuled_v2.state import get_state

                state = get_state()
                state.connect()
                saved_sources = state.save_found_sources(
                    found,
                    server_ip=host,
                    server_port=port,
                )
            result_payload["source_lookup"] = {
                **found.to_dict(),
                "saved_sources": saved_sources,
            }

        if args.json:
            print(json.dumps(result_payload, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(f"Server       : {args.server}")
            print(f"Client ID    : {login_result.client_id} ({'low' if login_result.low_id else 'high'})")
            print(f"Query        : {query}")
            print(f"Results      : {len(results)}")
            for result in results:
                print(f"  {result.hash_hex} {result.size} {result.name}")
            if "source_lookup" in result_payload:
                lookup = result_payload["source_lookup"]
                print(f"Source target: {lookup['hash']}")
                print(f"Sources      : {lookup['source_count']} (saved {lookup['saved_sources']})")
                for source in lookup["sources"]:
                    address = source["address"] or "lowid"
                    print(f"  {address}:{source['client_port']}")
        return 0
    finally:
        await client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Live ED2K search/source diagnostic.")
    parser.add_argument(
        "--server",
        default=os.environ.get("AMULED_LIVE_SERVER", _DEFAULT_SERVER),
        help=f"Real ED2K server endpoint (default: {_DEFAULT_SERVER}).",
    )
    parser.add_argument(
        "--query",
        help="Real search query; defaults to the selected real file name.",
    )
    parser.add_argument(
        "--link",
        help="Real ed2k://|file|... link; defaults to a local v1 metadata target.",
    )
    parser.add_argument(
        "--client-port",
        type=int,
        default=8089,
        help="Client TCP port announced during login.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connect/response timeout in seconds.",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Persist returned sources to project-local DuckDB state.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    configure_logging("INFO", log_file="logs/live-ed2k-search.jsonl")
    try:
        return asyncio.run(run(args))
    except (Ed2kLinkError, OSError, ValueError) as exc:
        log.error(f"LIVE ED2K TEST FAILED: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
