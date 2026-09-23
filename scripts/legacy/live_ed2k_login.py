"""Live ED2K server login smoke test using bundled baseline server list.

This is a manual diagnostic script, not part of pytest.  It connects to the
first reachable servers and performs login only: no search, source request,
offer, or download traffic is emitted.

scripts/live_ed2k_login.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.1 (Soror L.'.L'.):
  [+] Added --file to test alternative live server lists without replacing the
      bundled baseline automatically.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added bounded live-server login validation for M4.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from amuled_v2.core.ed2k import (
    Ed2kServerClient,
    LoginRequest,
    ServerSessionError,
    load_server_met,
)
from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

log = get_tagged_logger(LogTags.SERVER, "scripts.live_ed2k_login")


async def try_server(
    host: str,
    port: int,
    timeout: float,
) -> bool:
    login = LoginRequest.create(
        nickname="AmuleD_v2",
        client_id=0,
        client_port=8089,
        enable_security=True,
    )
    client = Ed2kServerClient(
        host,
        port,
        login,
        connect_timeout=timeout,
        response_timeout=timeout,
    )
    try:
        await client.connect()
        result = await client.login()
        log.info(
            f"LIVE LOGIN OK: endpoint={host}:{port}, client_id={result.client_id}, "
            f"low_id={result.low_id}, server={result.identity.name() if result.identity else ''!r}"
        )
        return True
    except (ServerSessionError, OSError, asyncio.TimeoutError) as exc:
        log.warning(f"LIVE LOGIN FAILED: endpoint={host}:{port}, error={type(exc).__name__}: {exc}")
        return False
    finally:
        await client.close()


async def run(limit: int, timeout: float, path: Path) -> int:
    servers = load_server_met(path)
    log.info(f"LIVE LOGIN START: servers={len(servers)}, limit={limit}, timeout={timeout}")

    successes = 0
    attempts = 0
    for server in servers:
        if attempts >= limit:
            break
        attempts += 1
        ok = await try_server(server.address, server.port, timeout)
        if ok:
            successes += 1

    log.info(f"LIVE LOGIN FINISH: attempts={attempts}, successes={successes}")
    return 0 if successes else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Live ED2K server login smoke test.")
    parser.add_argument("--limit", type=int, default=5, help="Maximum servers to try.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-server timeout in seconds.")
    parser.add_argument(
        "--file",
        default="assets/v1/server.met",
        help="server.met path to test; defaults to the bundled baseline list.",
    )
    args = parser.parse_args()

    configure_logging("DEBUG", log_file="logs/live-ed2k-login.jsonl")
    return asyncio.run(run(args.limit, args.timeout, Path(args.file)))


if __name__ == "__main__":
    sys.exit(main())
