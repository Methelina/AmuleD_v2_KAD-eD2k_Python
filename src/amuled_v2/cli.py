"""Command-line interface for AmuleD_v2.

Provides an argparse-based English CLI with optional ``--json`` output.
Commands:
  - ``status``              — show backend, db path, table counts, version.
  - ``config show``         — print current JSONC config.
  - ``config set <key> <v>``— set a dotted config key (type-inferred).
  - ``init``                — ensure runtime dirs and default config exist.
  - ``import servers/shared`` — import compatible v1 resources into state.
  - ``share add/scan/list/remove`` — hash files and maintain DuckDB state.
  - ``search server/auto`` — ED2K server search with explicit channel model.
  - ``search global/kad/web-edonkey`` — planned channels with explicit status.
  - ``sources ed2k/list`` — request and list ED2K file sources.
  - ``daemon start/stop``   — M2 stubs returning not_implemented.

Dependencies (duckdb, rich) are optional at runtime; ``--help`` works without
them installed.  Network protocol sessions are not started by share commands.

src/amuled_v2/cli.py
Version:     0.6.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.6.0 (Soror L.'.L'.):
  [+] Search results persist in DuckDB with full tag sets.
  [+] Added `search results list/show/clear` for cached results.
  [+] Implemented the GLOBAL channel as a real UDP server-list search.
  [+] AUTO now resolves from the real ED2K connection state.
  [+] Added `sources forget` and `sources prune` lifecycle commands.
  [+] Added source statistics to `status --json`.

Patch Notes v0.5.1 (Soror L.'.L'.):
  [+] Added explicit eMule-compatible search channel model.
  [+] Split SERVER, AUTO, GLOBAL, KAD, and WEB-EDONKEY CLI channels.
  [*] Replaced generic `search ed2k` semantics with a compatibility alias.

Patch Notes v0.5.0 (Soror L.'.L'.):
  [+] Added `search ed2k` and `sources ed2k/list` commands.
  [+] Added optional persistence for ED2K sources returned by servers.

Patch Notes v0.4.3 (Soror L.'.L'.):
  [+] Added `share add`, `share scan`, `share list`, and `share remove`.
  [+] New and rescanned files are written directly to DuckDB.
  [*] Directory rescans remove stale rows for missing or moved files.

Patch Notes v0.4.2 (Soror L.'.L'.):
  [+] Unified public display name to `AmuleD v0.4.1` across CLI and status.

Patch Notes v0.3.2 (Soror L.'.L'.):
  [+] Added tagged CLI command lifecycle diagnostics and error reporting.
  [*] Logging now initializes from the configured console level and JSONL file.

Patch Notes v0.3.0 (Soror L.'.L'.):
  [+] Added one-shot v1 import commands for server lists and shared metadata.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] argparse CLI with --json, status, config show/set, init, daemon.
  [+] Lazy imports so --help works without optional deps.
  [+] status and config work without network.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from amuled_v2 import __app_name__, __version__, __version_string__
from amuled_v2.config import config_set, config_show, load_config
from amuled_v2.daemon import start_daemon, stop_daemon
from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger
from amuled_v2.core.search_channels import (
    ChannelStatus,
    SearchChannel,
    parse_search_channel,
    resolve_auto_search_channel,
)
from amuled_v2.core.connection_state import get_connection_state
from amuled_v2.core.ipfilter import IpFilter, load_ipfilter_file
from amuled_v2.core.server_filter import ServerFilter

_IPFILTER_PATH = Path(__file__).resolve().parents[2] / "assets" / "v1" / "ipfilter.dat"


def _load_ipfilter() -> IpFilter:
    try:
        return load_ipfilter_file(_IPFILTER_PATH)
    except FileNotFoundError:
        log.warning(f"IPFILTER file missing: path={_IPFILTER_PATH}")
        return IpFilter()

log = get_tagged_logger(LogTags.CLI, "cli")
from amuled_v2.state import get_state


# ------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------

def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))


def _print_text(header: str, lines: list[str]) -> None:
    print(header)
    for line in lines:
        print(f"  {line}")


def _progress_line(text: str) -> None:
    """Render one in-place progress line when the console supports it."""
    if sys.stdout.isatty():
        sys.stdout.write("\r\033[K" + text)
        sys.stdout.flush()


def _progress_done() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\n")
        sys.stdout.flush()


def _render_search_progress(
    elapsed: float,
    duration: float,
    result_count: int,
    label: str,
) -> None:
    from amuled_v2.progressbar import render_progress

    bar = render_progress(0.0, duration, elapsed, 30)
    _progress_line(f"{bar} {label} {elapsed:5.1f}s/{duration:.0f}s results={result_count}")


# ------------------------------------------------------------------
# Command handlers
# ------------------------------------------------------------------

def _cmd_status(args: argparse.Namespace) -> int:
    log.debug(f"Command started: name=status, json={args.json}")
    cfg = load_config(save_if_missing=True)
    st = get_state()
    st.connect()
    status = st.get_status()
    result: dict = {
        "app": __app_name__,
        "version": __version__,
        "backend": status["backend"],
        "db_path": status["db_path"],
        "tables": status["tables"],
        "network": {
            "client_tcp_port": cfg["network"]["client_tcp_port"],
            "client_udp_port": cfg["network"]["client_udp_port"],
            "enable_ed2k": cfg["network"]["enable_ed2k"],
            "enable_kad": cfg["network"]["enable_kad"],
        },
    }
    connections = get_connection_state()
    result["connections"] = {
        "ed2k_connected": connections.snapshot.ed2k_connected,
        "kad_connected": connections.snapshot.kad_connected,
        "server": (
            f"{connections.snapshot.server_host}:{connections.snapshot.server_port}"
            if connections.snapshot.ed2k_connected
            else None
        ),
    }
    try:
        result["source_stats"] = st.get_source_statistics()
    except Exception as exc:
        log.warning(f"Source statistics unavailable: error={exc}")
        result["source_stats"] = None
    if args.json:
        _print_json(result)
    else:
        source_stats = result.get("source_stats")
        connections_info = result["connections"]
        _print_text(f"{__version_string__} Status", [
            f"version    : {result['version']}",
            f"backend    : {result['backend']}",
            f"db_path    : {result['db_path']}",
            f"tables     : {result['tables']}",
            f"tcp_port   : {result['network']['client_tcp_port']}",
            f"udp_port   : {result['network']['client_udp_port']}",
            f"ed2k       : {result['network']['enable_ed2k']}",
            f"kad        : {result['network']['enable_kad']}",
            f"ed2k_conn  : {connections_info['ed2k_connected']}",
            f"kad_conn   : {connections_info['kad_connected']}",
            f"sources    : "
            f"{source_stats['total_sources'] if source_stats else 'n/a'} "
            f"({source_stats['distinct_files'] if source_stats else '-'} files)",
        ])
    log.info("Status command completed")
    return 0


def _cmd_config_show(args: argparse.Namespace) -> int:
    return config_show(json_output=args.json)


def _cmd_config_set(args: argparse.Namespace) -> int:
    return config_set(args.key, args.value, json_output=args.json)


def _cmd_init(args: argparse.Namespace) -> int:
    from amuled_v2.paths import ensure_runtime_dirs

    log.debug(f"Command started: name=init, json={args.json}")
    created = ensure_runtime_dirs()
    load_config(save_if_missing=True)
    st = get_state()
    st.connect()
    status = st.get_status()
    result: dict = {
        "status": "ok",
        "dirs_created": [str(p) for p in created] if created else [],
        "backend": status["backend"],
        "db_path": status["db_path"],
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Init", [
            f"status       : {result['status']}",
            f"dirs_created : {result['dirs_created']}",
            f"backend      : {result['backend']}",
            f"db_path      : {result['db_path']}",
        ])
    log.info("Init command completed")
    return 0


def _cmd_daemon_start(args: argparse.Namespace) -> int:
    log.debug(f"Command started: name=daemon-start, json={args.json}")
    code, info = start_daemon()
    result = info.to_dict()
    if args.json:
        _print_json(result)
    else:
        _print_text("Daemon", [
            f"status   : {result['status']}",
            f"message  : {result['message']}",
        ])
    return code


def _cmd_daemon_stop(args: argparse.Namespace) -> int:
    log.debug(f"Command started: name=daemon-stop, json={args.json}")
    code, info = stop_daemon()
    result = info.to_dict()
    if args.json:
        _print_json(result)
    else:
        _print_text("Daemon", [
            f"status   : {result['status']}",
            f"message  : {result['message']}",
        ])
    return code


# ------------------------------------------------------------------
# Share command handlers
# ------------------------------------------------------------------

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _share_priority(raw: str) -> int:
    value = raw.lower()
    if value == "low":
        return 0
    if value == "normal":
        return 1
    if value == "high":
        return 2
    raise ValueError(f"invalid priority: {raw}")


def _scan_and_save(
    paths: list[str | Path],
    *,
    recursive: bool,
    priority: int,
    save: bool,
    progress: bool = False,
) -> dict:
    """Scan paths, reconcile their DB rows, and return an aggregate summary."""
    from amuled_v2.core.sharing import scan_shared_directory
    from amuled_v2.state import get_state

    state = get_state()
    state.connect()

    if not paths:
        paths = state.list_shared_directories()
        if not paths:
            raise ValueError("no paths supplied and no shared directories are registered")

    scans: list[dict] = []
    total_saved = 0
    total_removed = 0
    total_files = 0
    for raw_path in paths:
        root = Path(raw_path).expanduser().resolve()
        log.debug(
            f"Share scan started: path={root}, recursive={recursive}, save={save}"
        )
        files = scan_shared_directory(
            root,
            recursive=recursive,
            progress=progress,
        )
        for file_record in files:
            file_record.priority = priority

        if save:
            summary = state.replace_shared_directory_scan(root, files)
            saved = summary["saved_files"]
            removed = summary["removed_files"]
        else:
            saved = len(files)
            removed = 0
        total_saved += saved
        total_removed += removed
        total_files += len(files)
        scans.append(
            {
                "directory": str(root),
                "files_found": len(files),
                "files_saved": saved,
                "stale_files_removed": removed,
                "saved": save,
            }
        )
        log.info(
            f"Share scan completed: path={root}, files={len(files)}, "
            f"saved={saved}, removed={removed}"
        )

    return {
        "status": "ok",
        "saved": save,
        "directories_scanned": len(scans),
        "files_found": total_files,
        "files_saved": total_saved,
        "stale_files_removed": total_removed,
        "scans": scans,
    }


def _print_share_scan(result: dict, json_output: bool) -> None:
    if json_output:
        _print_json(result)
        return
    _print_text("Share scan", [
        f"status        : {result['status']}",
        f"saved         : {result['saved']}",
        f"directories   : {result['directories_scanned']}",
        f"files_found   : {result['files_found']}",
        f"files_saved   : {result['files_saved']}",
        f"stale_removed : {result['stale_files_removed']}",
    ])
    for scan in result["scans"]:
        print(f"  {scan['directory']}: found={scan['files_found']}, saved={scan['files_saved']}, removed={scan['stale_files_removed']}")


def _cmd_share_add(args: argparse.Namespace) -> int:
    log.debug(
        f"Command started: name=share-add, path={args.path}, "
        f"recursive={not args.no_recursive}, priority={args.priority}, "
        f"progress={not args.no_progress and not args.json}"
    )
    result = _scan_and_save(
        [args.path],
        recursive=not args.no_recursive,
        priority=_share_priority(args.priority),
        save=not args.dry_run,
        progress=not args.no_progress and not args.json,
    )
    result["action"] = "add"
    result["progress"] = not args.no_progress and not args.json
    _print_share_scan(result, args.json)
    return 0


def _cmd_share_scan(args: argparse.Namespace) -> int:
    log.debug(
        f"Command started: name=share-scan, paths={args.paths}, "
        f"recursive={not args.no_recursive}, priority={args.priority}, "
        f"progress={not args.no_progress and not args.json}"
    )
    result = _scan_and_save(
        args.paths,
        recursive=not args.no_recursive,
        priority=_share_priority(args.priority),
        save=not args.dry_run,
        progress=not args.no_progress and not args.json,
    )
    result["action"] = "scan"
    result["progress"] = not args.no_progress and not args.json
    _print_share_scan(result, args.json)
    return 0


def _cmd_share_list(args: argparse.Namespace) -> int:
    from amuled_v2.state import get_state

    log.debug(
        f"Command started: name=share-list, limit={args.limit}, "
        f"files_only={args.files_only}, dirs_only={args.dirs_only}"
    )
    state = get_state()
    state.connect()
    directories = [] if args.files_only else state.list_shared_directories()
    files = [] if args.dirs_only else state.list_shared_files(limit=args.limit)
    result = {
        "status": "ok",
        "directories": directories,
        "files": files,
        "directory_count": len(directories),
        "file_count": len(files),
        "limited": args.limit,
    }
    if args.json:
        _print_json(result)
        return 0

    lines = [
        f"status          : ok",
        f"directories     : {len(directories)}",
        f"files shown     : {len(files)}",
    ]
    for directory in directories:
        lines.append(f"  DIR  {directory}")
    for item in files:
        lines.append(
            f"  FILE {item['hash']} {item['size']} {item['name']}"
        )
    _print_text("Shared files", lines)
    return 0


def _cmd_share_remove(args: argparse.Namespace) -> int:
    from amuled_v2.state import get_state

    state = get_state()
    state.connect()

    if args.remove_action == "file":
        target = args.hash.strip()
        log.debug(
            f"Command started: name=share-remove-file, hash={target}"
        )
        prior = state.get_shared_file(target)
        removed = state.remove_shared_file(target)
        result = {
            "status": "ok" if removed else "not_found",
            "kind": "file",
            "hash": target.lower(),
            "removed": removed,
            "name": prior.get("name") if prior else None,
        }
        exit_code = 0 if removed else 1
    else:
        target = str(Path(args.path).expanduser().resolve())
        log.debug(
            f"Command started: name=share-remove-dir, path={target}, "
            f"keep_files={args.keep_files}"
        )
        result = state.remove_shared_directory(
            target,
            remove_files=not args.keep_files,
        )
        result.update(
            {
                "status": "ok" if result["directory_removed"] else "not_found",
                "kind": "directory",
                "removed": result["directory_removed"],
            }
        )
        exit_code = 0 if result["directory_removed"] else 1

    if args.json:
        _print_json(result)
    else:
        _print_text("Share remove", [
            f"status      : {result['status']}",
            f"kind        : {result['kind']}",
            f"target      : {target}",
            f"removed     : {result['removed']}",
            f"file_rows   : {result.get('removed_files', True)}",
        ])
    log.info(
        f"Share remove completed: action={args.remove_action}, "
        f"target={target}, status={result['status']}"
    )
    return exit_code


# ------------------------------------------------------------------
# ED2K search and source command handlers
# ------------------------------------------------------------------

def _parse_server_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError(f"invalid server endpoint, expected host:port: {value!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid server port in endpoint: {value!r}") from exc
    if not 0 <= port <= 0xFFFF:
        raise ValueError(f"server port out of range in endpoint: {value!r}")
    return host, port


_DEFAULT_GLOBAL_SERVER = "176.123.5.89"
_DEFAULT_GLOBAL_PORT = 4725


def _ed2k_login_request() -> "LoginRequest":
    from amuled_v2.core.ed2k import LoginRequest

    cfg = load_config(save_if_missing=True)
    return LoginRequest.create(
        nickname=cfg.get("app", {}).get("name", "AmuleD"),
        client_id=0,
        client_port=int(cfg.get("network", {}).get("client_tcp_port", 8089)),
        enable_security=True,
    )


def _print_search_results(result: dict, json_output: bool) -> None:
    if json_output:
        _print_json(result)
        return
    lines = [
        f"status     : {result['status']}",
        f"channel    : {result['channel']}",
        f"server     : {result['server']}",
        f"query      : {result['query']}",
        f"results    : {len(result['results'])}",
    ]
    for item in result["results"]:
        lines.append(
            f"  {item['hash']} {item['size']} src={item['sources']} {item['name']}"
        )
    _print_text("ED2K search", lines)


async def _run_ed2k_search(args: argparse.Namespace) -> dict:
    from amuled_v2.core.ed2k import Ed2kServerClient, SearchResultsBatch

    host, port = _parse_server_endpoint(args.server)
    login = _ed2k_login_request()
    client = Ed2kServerClient(
        host,
        port,
        login,
        connect_timeout=args.timeout,
        response_timeout=args.timeout,
    )
    connections = get_connection_state()
    results = []
    more_results = False
    resolved_channel = getattr(args, "channel", SearchChannel.SERVER.value)
    published = 0
    try:
        await client.connect()
        await client.login()
        connections.update_from_server_client(client)
        published = await _publish_shared_files_to(client)

        if resolved_channel == SearchChannel.AUTO.value:
            snapshot = connections.snapshot
            resolved = resolve_auto_search_channel(
                ed2k_connected=snapshot.ed2k_connected,
                kad_connected=snapshot.kad_connected,
                server_is_static=snapshot.server_is_static,
                server_users=snapshot.server_users,
                server_files=snapshot.server_files,
                server_count=snapshot.server_count,
            )
            resolved_channel = resolved.channel.value

        raw = await client.search(
            args.query,
            duration=args.duration,
            progress_callback=(
                (lambda e, d, n: _render_search_progress(e, d, n, f"server {args.server}"))
                if not args.json
                else None
            ),
        )
        results = list(raw)
        more_results = bool(getattr(client, "last_search_more", False))
    finally:
        await client.close()
        connections.set_ed2k_connected(False)
        if not args.json:
            _progress_done()

    batch = SearchResultsBatch(
        query=args.query,
        channel=resolved_channel,
        server_host=host,
        server_port=port,
        results=tuple(results),
        more_results_available=more_results,
    )

    saved = 0
    if not getattr(args, "no_save", False):
        state = get_state()
        state.connect()
        saved = state.save_search_results_batch(batch)

    return {
        "status": "ok",
        "channel": resolved_channel,
        "server": args.server,
        "query": args.query,
        "session_id": batch.session_id,
        "published_files": published,
        "results": [item.to_dict() for item in results],
        "result_count": len(results),
        "saved_results": saved,
    }


async def _publish_shared_files_to(client) -> int:
    """Publish the persisted shared-file list to the connected server."""
    state = get_state()
    state.connect()
    rows = state.list_shared_files(limit=200)
    files: list[tuple[bytes, str, int]] = []
    for row in rows:
        try:
            files.append((bytes.fromhex(row["hash"]), row["name"], int(row["size"])))
        except (ValueError, TypeError):
            continue
    try:
        return await client.publish_shared_files(files)
    except Exception as exc:
        log.warning(f"Shared file publish failed: error={exc}")
        return 0


def _cmd_search_ed2k(args: argparse.Namespace) -> int:
    log.debug(
        f"Command started: name=search-server, server={args.server}, "
        f"query={args.query!r}, timeout={args.timeout}, duration={args.duration}"
    )
    result = asyncio.run(_run_ed2k_search(args))
    _print_search_results(result, args.json)
    log.info(f"ED2K server search CLI completed: results={result['result_count']}")
    return 0


def _cmd_search_auto(args: argparse.Namespace) -> int:
    log.debug(
        f"Command started: name=search-auto, server={args.server}, "
        f"query={args.query!r}, timeout={args.timeout}, duration={args.duration}"
    )
    args.channel = SearchChannel.AUTO.value
    return _cmd_search_ed2k(args)


def _load_global_servers(explicit: str | None, *, sweep: bool = False) -> list:
    import ipaddress

    from amuled_v2.core.ed2k import GlobalServerEndpoint

    # Default policy: work with the single Sunrise server where the client
    # publishes resources.  Sweeping the whole persisted list is opt-in and
    # exists only as a disabled-by-default fallback branch.
    if explicit:
        host, port = _parse_server_endpoint(explicit)
        return [GlobalServerEndpoint(host=host, port=port)]
    if not sweep:
        return [GlobalServerEndpoint(host=_DEFAULT_GLOBAL_SERVER, port=_DEFAULT_GLOBAL_PORT)]

    endpoints: list[GlobalServerEndpoint] = []
    seen: set[tuple[str, int]] = set()
    state = get_state()
    state.connect()
    server_filter = ServerFilter(ip_filter=_load_ipfilter())
    for row in state.list_servers():
        host = str(ipaddress.IPv4Address(row["ip"]))
        key = (host, row["port"])
        if key not in seen:
            seen.add(key)
            verdict = server_filter.evaluate(host, row["port"])
            if not verdict.allowed:
                log.info(
                    "GLOBAL candidate filtered: host=%s, port=%d, reason=%s",
                    host,
                    row["port"],
                    verdict.reason,
                )
                continue
            endpoints.append(GlobalServerEndpoint(host=host, port=row["port"]))
    return endpoints


def _cmd_search_global(args: argparse.Namespace) -> int:
    from amuled_v2.core.ed2k import GlobalUdpSearch, SearchResultsBatch
    from amuled_v2.progressbar import render_progress

    log.debug(
        f"Command started: name=search-global, server={args.server}, "
        f"query={args.query!r}, timeout={args.timeout}"
    )
    try:
        endpoints = _load_global_servers(args.server, sweep=args.sweep)
    except Exception as exc:
        log.error(f"GLOBAL server list load failed: error={exc}")
        raise
    if not endpoints:
        result = {
            "status": "no_servers",
            "channel": SearchChannel.GLOBAL.value,
            "reason": (
                "no servers known; run `import servers --save` or pass --server"
            ),
        }
        if args.json:
            _print_json(result)
        else:
            _print_text("Search channel unavailable", [
                f"status  : {result['status']}",
                f"channel : {result['channel']}",
                f"reason  : {result['reason']}",
            ])
        return 2

    if len(endpoints) > args.max_servers:
        log.warning(
            "GLOBAL server list truncated to live sweep limit: "
            "total=%d, kept=%d",
            len(endpoints),
            args.max_servers,
        )
        endpoints = endpoints[: args.max_servers]

    show_progress = not args.json and sys.stdout.isatty()
    search = GlobalUdpSearch(
        endpoints,
        response_window=args.timeout,
        dead_server_retries=args.dead_retries,
        progress_callback=(
            (lambda done, total, results: (
                _progress_line(
                    f"{render_progress(0, max(total, 1), done, 30)} GLOBAL "
                    f"servers={done}/{total} results={results}"
                )
            ))
            if show_progress
            else None
        ),
    )
    aggregate = asyncio.run(search.search(args.query))
    if show_progress:
        _progress_done()

    saved = 0
    session_id = None
    if aggregate.results or not getattr(args, "no_save", False):
        first = endpoints[0]
        batch = SearchResultsBatch(
            query=args.query,
            channel=SearchChannel.GLOBAL.value,
            server_host=first.host,
            server_port=first.port,
            results=aggregate.results,
            more_results_available=False,
        )
        session_id = batch.session_id
        if not getattr(args, "no_save", False):
            state = get_state()
            state.connect()
            saved = state.save_search_results_batch(batch)

    result = {
        "status": "ok",
        "channel": SearchChannel.GLOBAL.value,
        "query": args.query,
        "servers_queried": len(endpoints),
        "per_server": aggregate.per_server,
        "dead_servers": list(aggregate.dead_servers),
        "session_id": session_id,
        "results": [item.to_dict() for item in aggregate.results],
        "result_count": aggregate.result_count,
        "saved_results": saved,
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            f"status     : {result['status']}",
            f"channel    : {result['channel']}",
            f"query      : {result['query']}",
            f"servers    : {result['servers_queried']}",
            f"results    : {result['result_count']} "
            f"(saved={result['saved_results']})",
        ]
        for server, count in aggregate.per_server.items():
            lines.append(f"  {server}: {count}")
        for server in aggregate.dead_servers:
            lines.append(f"  DEAD {server}")
        for item in result["results"]:
            lines.append(
                f"  {item['hash']} {item['size']} src={item['sources']} {item['name']}"
            )
        _print_text("ED2K global search", lines)
    log.info(
        f"ED2K global search CLI completed: results={aggregate.result_count}, "
        f"saved={saved}"
    )
    return 0


def _cmd_search_results_list(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    rows = state.list_search_results(
        query=args.query,
        channel=args.channel,
        hash_prefix=args.hash,
        limit=args.limit,
    )
    result = {
        "status": "ok",
        "results": rows,
        "result_count": len(rows),
        "limit": args.limit,
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            "status  : ok",
            f"results : {len(rows)}",
        ]
        for row in rows:
            lines.append(
                f"  {row['hash']} {row['size']} src={row['sources']} "
                f"[{row['channel']}|{row['query']}] {row['name']}"
            )
        _print_text("Cached search results", lines)
    log.info(f"Search result list completed: count={len(rows)}")
    return 0


def _cmd_search_results_show(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    tags = state.get_search_result_tags(args.hash)
    result = {
        "status": "ok" if tags else "not_found",
        "hash": args.hash.lower(),
        "tags": tags,
        "tag_count": len(tags),
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            f"status : {result['status']}",
            f"hash   : {result['hash']}",
            f"tags   : {result['tag_count']}",
        ]
        for tag in tags:
            lines.append(
                f"  name={tag.get('name')} name_id={tag.get('name_id')} "
                f"type={tag.get('type')} value={tag.get('value')!r}"
            )
        _print_text("Search result tags", lines)
    log.info(f"Search result show completed: hash={args.hash.lower()}, tags={len(tags)}")
    return 0


def _cmd_search_results_clear(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    removed = state.clear_search_results(query=args.query)
    result = {
        "status": "ok",
        "removed": removed,
        "query": args.query,
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Search results cleared", [
            f"status  : ok",
            f"query   : {args.query or '(all)'}",
            f"removed : {removed}",
        ])
    log.info(f"Search results clear completed: removed={removed}")
    return 0


def _cmd_search_not_implemented(args: argparse.Namespace) -> int:
    channel = parse_search_channel(args.channel_name)
    result = {
        "status": "not_implemented",
        "channel": channel.value,
        "implementation_status": (
            ChannelStatus.PLANNED.value
            if channel == SearchChannel.KAD
            else ChannelStatus.NOT_IMPLEMENTED.value
        ),
        "reason": {
            SearchChannel.KAD.value: "KAD requires the Kademlia keyword search engine",
            SearchChannel.WEB_EDONKEY.value: "WEB-EDONKEY requires an external web-service adapter",
        }[channel.value],
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Search channel unavailable", [
            f"status  : {result['status']}",
            f"channel : {result['channel']}",
            f"state   : {result['implementation_status']}",
            f"reason  : {result['reason']}",
        ])
    return 2


async def _run_ed2k_sources(args: argparse.Namespace) -> dict:
    from amuled_v2.core.ed2k import Ed2kServerClient

    host, port = _parse_server_endpoint(args.server)
    file_hash = bytes.fromhex(args.hash)
    login = _ed2k_login_request()
    client = Ed2kServerClient(
        host,
        port,
        login,
        connect_timeout=args.timeout,
        response_timeout=args.timeout,
    )
    saved_sources = 0
    try:
        await client.connect()
        await client.login()
        found = await client.get_sources(file_hash, args.size)
        if args.save:
            state = get_state()
            state.connect()
            saved_sources = state.save_found_sources(
                found,
                server_ip=client.host,
                server_port=client.port,
            )
    finally:
        await client.close()
    result = found.to_dict()
    result.update(
        {
            "status": "ok",
            "server": args.server,
            "saved_sources": saved_sources,
        }
    )
    return result


def _cmd_sources_ed2k(args: argparse.Namespace) -> int:
    log.debug(
        f"Command started: name=sources-ed2k, server={args.server}, "
        f"hash={args.hash}, size={args.size}, save={args.save}"
    )
    result = asyncio.run(_run_ed2k_sources(args))
    if args.json:
        _print_json(result)
    else:
        lines = [
            f"status      : {result['status']}",
            f"server      : {result['server']}",
            f"hash        : {result['hash']}",
            f"sources     : {result['source_count']}",
            f"saved       : {result['saved_sources']}",
        ]
        for source in result["sources"]:
            address = source["address"] or "lowid"
            lines.append(
                f"  {address}:{source['client_port']} id={source['client_id']}"
            )
        _print_text("ED2K sources", lines)
    log.info(
        f"ED2K sources CLI completed: hash={result['hash']}, "
        f"sources={result['source_count']}, saved={result['saved_sources']}"
    )
    return 0


def _cmd_ipfilter_status(args: argparse.Namespace) -> int:
    ip_filter = _load_ipfilter()
    stats = ip_filter.statistics()
    result = {"status": "ok", "path": str(_IPFILTER_PATH), **stats}
    if args.json:
        _print_json(result)
    else:
        _print_text("IP filter", [
            f"status   : ok",
            f"path     : {result['path']}",
            f"ranges   : {stats['range_count']}",
            f"max_level: {stats['max_level']}",
        ])
    log.info(f"IP filter status completed: ranges={stats['range_count']}")
    return 0


def _cmd_ipfilter_test(args: argparse.Namespace) -> int:
    ip_filter = _load_ipfilter()
    matched = ip_filter.match(args.ip)
    filtered = ip_filter.is_filtered(args.ip)
    result = {
        "status": "ok",
        "ip": args.ip,
        "filtered": filtered,
        "range": (
            None
            if matched is None
            else {
                "start": str(ipaddress.IPv4Address(matched.start)),
                "end": str(ipaddress.IPv4Address(matched.end)),
                "level": matched.level,
                "description": matched.description,
            }
        ),
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            f"status   : ok",
            f"ip       : {args.ip}",
            f"filtered : {filtered}",
        ]
        if matched is not None:
            lines.append(
                f"range    : {result['range']['start']} - "
                f"{result['range']['end']} level={matched.level} "
                f"{matched.description}"
            )
        _print_text("IP filter test", lines)
    log.info(f"IP filter test completed: ip={args.ip}, filtered={filtered}")
    return 0


def _cmd_sources_forget(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    removed = state.forget_file_sources(args.hash)
    result = {
        "status": "ok",
        "hash": args.hash.lower(),
        "removed": removed,
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Sources forgotten", [
            f"status  : ok",
            f"hash    : {args.hash.lower()}",
            f"removed : {removed}",
        ])
    log.info(f"Sources forget completed: hash={args.hash.lower()}, removed={removed}")
    return 0


def _cmd_sources_prune(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    summary = state.prune_file_sources(
        max_age_hours=args.max_age_hours,
        dead_only=args.dead_only,
        dry_run=args.dry_run,
    )
    result = {"status": "ok", **summary}
    if args.json:
        _print_json(result)
    else:
        _print_text("Sources prune", [
            f"status         : ok",
            f"matched        : {summary['matched']}",
            f"pruned         : {summary['pruned']}",
            f"max_age_hours  : {summary['max_age_hours']}",
            f"dead_only      : {summary['dead_only']}",
            f"dry_run        : {summary['dry_run']}",
        ])
    log.info(
        f"Sources prune completed: matched={summary['matched']}, "
        f"pruned={summary['pruned']}, dry_run={summary['dry_run']}"
    )
    return 0


def _cmd_sources_list(args: argparse.Namespace) -> int:
    state = get_state()
    state.connect()
    rows = state.list_file_sources(args.hash, limit=args.limit)
    result = {
        "status": "ok",
        "file_hash": args.hash.lower() if args.hash else None,
        "sources": rows,
        "source_count": len(rows),
        "limit": args.limit,
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            "status  : ok",
            f"sources : {len(rows)}",
        ]
        for row in rows:
            lines.append(
                f"  {row['hash']} {row['client_id']}:{row['client_port']} "
                f"via {row['server_ip']}:{row['server_port']} [{row['source_type']}]"
            )
        _print_text("File sources", lines)
    log.info(f"File source list completed: count={len(rows)}")
    return 0


def _download_queue():
    from amuled_v2.core.download import DownloadQueue
    from amuled_v2.paths import INCOMING_DIR, TEMP_DIR

    state = get_state()
    state.connect()
    return DownloadQueue(
        state=state,
        temp_dir=TEMP_DIR,
        incoming_dir=INCOMING_DIR,
    )


def _cmd_download_add(args: argparse.Namespace) -> int:
    from amuled_v2.core.ed2k import parse_ed2k_file_link

    log.debug(f"Command started: name=download-add, link={args.link!r}")
    parsed = parse_ed2k_file_link(args.link)
    queue = _download_queue()
    entry = queue.add(
        file_hash=parsed.file_hash.hex(),
        name=parsed.name,
        size=parsed.size,
    )
    result = {"status": "ok", "action": "add", **entry}
    if args.json:
        _print_json(result)
    else:
        _print_text("Download added", [
            f"status : ok",
            f"hash   : {entry['hash']}",
            f"name   : {entry['name']}",
            f"size   : {entry['size']}",
            f"queue  : {entry['status']}",
        ])
    log.info(f"Download add completed: hash={entry['hash']}")
    return 0


def _cmd_download_run(args: argparse.Namespace) -> int:
    from amuled_v2.core.download import DownloadRunner

    log.debug(
        f"Command started: name=download-run, hash={args.hash}, "
        f"max_peers={args.max_peers}, verify={not args.no_verify}"
    )
    queue = _download_queue()
    runner = DownloadRunner(
        queue,
        local_port=int(load_config(save_if_missing=True).get("network", {}).get("client_tcp_port", 8089)),
        max_peers=args.max_peers,
        queue_wait_timeout=args.queue_wait,
    )

    def _progress(received: int, total: int, blocks: int) -> None:
        from amuled_v2.progressbar import render_progress

        _progress_line(
            f"{render_progress(0, total, received, 30)} download "
            f"{received}/{total} bytes, blocks={blocks}"
        )

    result = asyncio.run(
        runner.run(
            args.hash,
            verify=not args.no_verify,
            progress_callback=None if args.json else _progress,
        )
    )
    _progress_done()
    result = {"status": result.get("status", "ok"), **result}
    if args.json:
        _print_json(result)
    else:
        lines = [f"status : {result['status']}"]
        outcome = result.get("outcome")
        if isinstance(outcome, dict):
            lines.append(
                f"peer   : received={outcome.get('bytes_received')}, "
                f"blocks={outcome.get('blocks_received')}, "
                f"detail={outcome.get('detail')}"
            )
        finalized = result.get("finalized")
        if isinstance(finalized, dict):
            lines.append(f"target : {finalized.get('target')}")
        _print_text("Download run", lines)
    log.info(f"Download run completed: hash={args.hash}, status={result['status']}")
    return 0 if result["status"] in ("complete", "already_complete") else 1


def _cmd_download_list(args: argparse.Namespace) -> int:
    queue = _download_queue()
    entries = queue.list(limit=args.limit)
    result = {
        "status": "ok",
        "downloads": entries,
        "download_count": len(entries),
    }
    if args.json:
        _print_json(result)
    else:
        lines = [
            "status    : ok",
            f"downloads : {len(entries)}",
        ]
        for entry in entries:
            lines.append(
                f"  {entry['hash']} [{entry['status']}] "
                f"{entry['downloaded']}/{entry['size']} {entry['name']}"
            )
        _print_text("Download queue", lines)
    log.info(f"Download list completed: count={len(entries)}")
    return 0


def _download_lifecycle(args: argparse.Namespace, action: str) -> int:
    queue = _download_queue()
    if action == "pause":
        entry = queue.pause(args.hash)
    elif action == "resume":
        entry = queue.resume(args.hash)
    elif action == "start":
        entry = queue.start(args.hash)
    else:
        raise ValueError(f"unknown lifecycle action: {action}")
    result = {"status": "ok", "action": action, **entry}
    if args.json:
        _print_json(result)
    else:
        _print_text(f"Download {action}", [
            f"status : ok",
            f"hash   : {entry['hash']}",
            f"name   : {entry['name']}",
            f"queue  : {entry['status']}",
        ])
    log.info(f"Download {action} completed: hash={entry['hash']}")
    return 0


def _cmd_download_pause(args: argparse.Namespace) -> int:
    return _download_lifecycle(args, "pause")


def _cmd_download_resume(args: argparse.Namespace) -> int:
    return _download_lifecycle(args, "resume")


def _cmd_download_cancel(args: argparse.Namespace) -> int:
    queue = _download_queue()
    summary = queue.cancel(args.hash, keep_files=args.keep_files)
    result = {"status": "ok", **summary}
    if args.json:
        _print_json(result)
    else:
        _print_text("Download cancelled", [
            f"status        : ok",
            f"hash          : {summary['hash']}",
            f"files_removed : {summary['files_removed']}",
        ])
    log.info(f"Download cancel completed: hash={summary['hash']}")
    return 0


# ------------------------------------------------------------------
# Import command handlers
# ------------------------------------------------------------------

def _cmd_import_servers(args: argparse.Namespace) -> int:
    from amuled_v2.core.ed2k import load_server_met, load_static_servers

    log.debug(
        f"Command started: name=import-servers, save={args.save}, "
        f"server_met={args.server_met}, static={args.static}"
    )
    records = load_server_met(args.server_met)
    static = load_static_servers(args.static) if args.static else []
    saved_servers = 0
    saved_static = 0
    if args.save:
        from amuled_v2.state import get_state

        state = get_state()
        state.connect()
        saved_servers = state.save_servers(records)
        saved_static = state.save_static_servers(static)
    result = {
        "status": "ok",
        "servers": len(records),
        "static_servers": len(static),
        "saved_servers": saved_servers,
        "saved_static_servers": saved_static,
        "server_met": str(args.server_met),
        "staticservers_dat": str(args.static) if args.static else None,
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Import servers", [
            f"status          : {result['status']}",
            f"servers         : {result['servers']}",
            f"static_servers  : {result['static_servers']}",
            f"server_met      : {result['server_met']}",
            f"static_list     : {result['staticservers_dat']}",
        ])
    log.info(f"Server import completed: servers={len(records)}, static={len(static)}")
    return 0


def _cmd_import_shared(args: argparse.Namespace) -> int:
    from amuled_v2.core.sharing import (
        load_shareddir_dat,
        load_shared_files_json,
    )

    log.debug(
        f"Command started: name=import-shared, save={args.save}, "
        f"shared_json={args.shared_json}, shareddir={args.shareddir}"
    )
    files = load_shared_files_json(args.shared_json)
    directories = load_shareddir_dat(args.shareddir) if args.shareddir else []
    saved_files = 0
    saved_dirs = 0
    if args.save:
        from amuled_v2.state import get_state

        state = get_state()
        state.connect()
        saved_files = state.save_shared_files(files)
        saved_dirs = state.save_shared_directories(str(path) for path in directories)
    result = {
        "status": "ok",
        "shared_files": len(files),
        "shared_directories": len(directories),
        "saved_shared_files": saved_files,
        "saved_shared_directories": saved_dirs,
        "shared_files_json": str(args.shared_json),
        "shareddir_dat": str(args.shareddir) if args.shareddir else None,
    }
    if args.json:
        _print_json(result)
    else:
        _print_text("Import shared metadata", [
            f"status             : {result['status']}",
            f"shared_files       : {result['shared_files']}",
            f"shared_directories : {result['shared_directories']}",
            f"shared_json        : {result['shared_files_json']}",
            f"shared_dirs        : {result['shareddir_dat']}",
        ])
    log.info(f"Shared import completed: files={len(files)}, directories={len(directories)}")
    return 0


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def _make_parents() -> argparse.ArgumentParser:
    """Parent parser carrying --json for both top-level and subcommand use."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit machine-readable JSON output.",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    parents = [_make_parents()]

    parser = argparse.ArgumentParser(
        prog="amuled",
        description=f"{__version_string__} — pure Python ED2K/Kademlia client.",
        parents=parents,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version_string__,
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # --- status ---
    p_status = sub.add_parser("status", help="Show client status.", parents=parents)
    p_status.set_defaults(func=_cmd_status)

    # --- config ---
    p_config = sub.add_parser("config", help="Manage configuration.", parents=parents)
    cfg_sub = p_config.add_subparsers(dest="config_command", metavar="<action>")
    p_cfg_show = cfg_sub.add_parser("show", help="Show current config.", parents=parents)
    p_cfg_show.set_defaults(func=_cmd_config_show)
    p_cfg_set = cfg_sub.add_parser("set", help="Set a dotted config key.", parents=parents)
    p_cfg_set.add_argument("key", help="Dotted key, e.g. network.client_tcp_port")
    p_cfg_set.add_argument("value", help="Value (bool/int/float/str inferred).")
    p_cfg_set.set_defaults(func=_cmd_config_set)

    # --- init ---
    p_init = sub.add_parser("init", help="Initialize runtime dirs and config.", parents=parents)
    p_init.set_defaults(func=_cmd_init)

    # --- import ---
    p_import = sub.add_parser("import", help="Import compatible v1 resources.", parents=parents)
    import_sub = p_import.add_subparsers(dest="import_command", metavar="<resource>")

    p_import_servers = import_sub.add_parser(
        "servers",
        help="Import server.met and optional staticservers.dat.",
        parents=parents,
    )
    p_import_servers.add_argument(
        "--server-met",
        required=True,
        help="Path to the source server.met file.",
    )
    p_import_servers.add_argument(
        "--static",
        help="Optional path to staticservers.dat.",
    )
    p_import_servers.add_argument(
        "--save",
        action="store_true",
        help="Persist imported records to the project DuckDB state.",
    )
    p_import_servers.set_defaults(func=_cmd_import_servers)

    p_import_shared = import_sub.add_parser(
        "shared",
        help="Import v1 shared_files.json and optional shareddir.dat.",
        parents=parents,
    )
    p_import_shared.add_argument(
        "--shared-json",
        required=True,
        help="Path to the source shared_files.json file.",
    )
    p_import_shared.add_argument(
        "--shareddir",
        help="Optional path to shareddir.dat.",
    )
    p_import_shared.add_argument(
        "--save",
        action="store_true",
        help="Persist imported metadata to the project DuckDB state.",
    )
    p_import_shared.set_defaults(func=_cmd_import_shared)

    # --- share ---
    p_share = sub.add_parser(
        "share",
        help="Scan, list, and manage shared files in DuckDB.",
        parents=parents,
    )
    share_sub = p_share.add_subparsers(dest="share_command", metavar="<action>")

    p_share_add = share_sub.add_parser(
        "add",
        help="Register a directory, hash its files, and save them to state.",
        parents=parents,
    )
    p_share_add.add_argument("path", help="Directory to register and scan.")
    p_share_add.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not descend into subdirectories.",
    )
    p_share_add.add_argument(
        "--priority",
        choices=("low", "normal", "high"),
        default="normal",
        help="Priority assigned to files from this scan.",
    )
    p_share_add.add_argument(
        "--dry-run",
        action="store_true",
        help="Hash files without changing DuckDB state.",
    )
    p_share_add.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the tqdm hashing progress bar.",
    )
    p_share_add.set_defaults(func=_cmd_share_add)

    p_share_scan = share_sub.add_parser(
        "scan",
        help="Rescan registered directories or explicit paths.",
        parents=parents,
    )
    p_share_scan.add_argument(
        "paths",
        nargs="*",
        help="Paths to scan; omit to rescan all registered directories.",
    )
    p_share_scan.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not descend into subdirectories.",
    )
    p_share_scan.add_argument(
        "--priority",
        choices=("low", "normal", "high"),
        default="normal",
        help="Priority assigned to files from this scan.",
    )
    p_share_scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Hash files without changing DuckDB state.",
    )
    p_share_scan.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the tqdm hashing progress bar.",
    )
    p_share_scan.set_defaults(func=_cmd_share_scan)

    p_share_list = share_sub.add_parser(
        "list",
        help="List registered directories and shared files.",
        parents=parents,
    )
    p_share_list.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum number of files to show (default: 1000).",
    )
    p_share_list.add_argument(
        "--files-only",
        action="store_true",
        help="Omit registered directories.",
    )
    p_share_list.add_argument(
        "--dirs-only",
        action="store_true",
        help="Omit shared files.",
    )
    p_share_list.set_defaults(func=_cmd_share_list)

    p_share_remove = share_sub.add_parser(
        "remove",
        help="Remove one file by ED2K hash or one directory by path.",
        parents=parents,
    )
    remove_sub = p_share_remove.add_subparsers(
        dest="remove_action",
        metavar="<kind>",
        required=True,
    )

    p_remove_file = remove_sub.add_parser(
        "file",
        help="Remove one file row by its 32-hex ED2K hash.",
        parents=parents,
    )
    p_remove_file.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_remove_file.set_defaults(func=_cmd_share_remove)

    p_remove_dir = remove_sub.add_parser(
        "dir",
        help="Remove a registered directory and its scanned file rows.",
        parents=parents,
    )
    p_remove_dir.add_argument("path", help="Registered shared directory path.")
    p_remove_dir.add_argument(
        "--keep-files",
        action="store_true",
        help="Keep the directory's file rows in state.",
    )
    p_remove_dir.set_defaults(func=_cmd_share_remove)

    # --- search ---
    p_search = sub.add_parser(
        "search",
        help="Run searches through explicit eMule-compatible channels.",
        parents=parents,
    )
    search_sub = p_search.add_subparsers(dest="search_command", metavar="<channel>")

    def add_server_search_parser(name: str, help_text: str):
        parser = search_sub.add_parser(name, help=help_text, parents=parents)
        parser.add_argument(
            "--server",
            required=True,
            help="ED2K server endpoint as host:port.",
        )
        parser.add_argument(
            "--query",
            required=True,
            help="Search query.",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=20.0,
            help="Connect timeout in seconds.",
        )
        parser.add_argument(
            "--duration",
            type=float,
            default=30.0,
            help="Search result accumulation window in seconds.",
        )
        parser.add_argument(
            "--no-save",
            action="store_true",
            help="Do not persist results into DuckDB.",
        )
        return parser

    p_search_server = add_server_search_parser(
        "server",
        "Search the connected ED2K server over TCP.",
    )
    p_search_server.set_defaults(
        channel=SearchChannel.SERVER.value,
        func=_cmd_search_ed2k,
    )

    p_search_auto = add_server_search_parser(
        "auto",
        "Resolve AUTO from the real connection state using eMule rules.",
    )
    p_search_auto.set_defaults(func=_cmd_search_auto)

    p_search_global = search_sub.add_parser(
        "global",
        help="GLOBAL channel: UDP search across the known server list.",
        parents=parents,
    )
    p_search_global.add_argument(
        "--server",
        help=(
            "Explicit endpoint; defaults to the Sunrise server "
            f"({_DEFAULT_GLOBAL_SERVER}:{_DEFAULT_GLOBAL_PORT})."
        ),
    )
    p_search_global.add_argument(
        "--sweep",
        action="store_true",
        help=(
            "Sweep the whole persisted server list instead of the default "
            "Sunrise server (fallback branch; disabled by default)."
        ),
    )
    p_search_global.add_argument(
        "--query",
        required=True,
        help="Search query.",
    )
    p_search_global.add_argument(
        "--timeout",
        type=float,
        default=6.0,
        help="Per-server UDP response window in seconds.",
    )
    p_search_global.add_argument(
        "--dead-retries",
        type=int,
        default=2,
        help="Silent searches before a server is skipped for the session.",
    )
    p_search_global.add_argument(
        "--max-servers",
        type=int,
        default=25,
        help="Cap on servers swept in one run (dead/spy server protection).",
    )
    p_search_global.add_argument(
        "--no-save",
        action="store_true",
        help="Do not persist results into DuckDB.",
    )
    p_search_global.set_defaults(func=_cmd_search_global)

    p_search_kad = search_sub.add_parser(
        "kad",
        help="Kademlia channel (planned keyword search engine).",
        parents=parents,
    )
    p_search_kad.add_argument("--query", help="Search query (unused while planned).")
    p_search_kad.set_defaults(
        channel_name=SearchChannel.KAD.value,
        func=_cmd_search_not_implemented,
    )

    p_search_web = search_sub.add_parser(
        "web-edonkey",
        help="External web-eDonkey channel (not implemented).",
        parents=parents,
    )
    p_search_web.add_argument("--query", help="Search query (unused while not implemented).")
    p_search_web.set_defaults(
        channel_name=SearchChannel.WEB_EDONKEY.value,
        func=_cmd_search_not_implemented,
    )

    # Deprecated compatibility alias for the former generic network command.
    p_search_ed2k = add_server_search_parser(
        "ed2k",
        "Compatibility alias for the SERVER channel.",
    )
    p_search_ed2k.set_defaults(
        channel=SearchChannel.SERVER.value,
        func=_cmd_search_ed2k,
    )

    # --- search results ---
    p_results = search_sub.add_parser(
        "results",
        help="List, inspect, or clear persisted search results.",
        parents=parents,
    )
    results_sub = p_results.add_subparsers(dest="results_command", metavar="<action>")

    p_results_list = results_sub.add_parser(
        "list",
        help="List cached search results.",
        parents=parents,
    )
    p_results_list.add_argument("--query", help="Filter by original query.")
    p_results_list.add_argument(
        "--channel",
        help="Filter by channel (server, global, ...).",
    )
    p_results_list.add_argument(
        "--hash",
        help="Filter by file-hash hexadecimal prefix.",
    )
    p_results_list.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum rows to return.",
    )
    p_results_list.set_defaults(func=_cmd_search_results_list)

    p_results_show = results_sub.add_parser(
        "show",
        help="Show the full stored tag set for one result hash.",
        parents=parents,
    )
    p_results_show.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_results_show.set_defaults(func=_cmd_search_results_show)

    p_results_clear = results_sub.add_parser(
        "clear",
        help="Clear cached search results.",
        parents=parents,
    )
    p_results_clear.add_argument(
        "--query",
        help="Clear only rows from this query; omit for all results.",
    )
    p_results_clear.set_defaults(func=_cmd_search_results_clear)

    # --- sources ---
    p_sources = sub.add_parser(
        "sources",
        help="Request or list ED2K file sources.",
        parents=parents,
    )
    sources_sub = p_sources.add_subparsers(dest="sources_command", metavar="<action>")

    p_sources_ed2k = sources_sub.add_parser(
        "ed2k",
        help="Request sources for one ED2K file from a server.",
        parents=parents,
    )
    p_sources_ed2k.add_argument(
        "--server",
        required=True,
        help="ED2K server endpoint as host:port.",
    )
    p_sources_ed2k.add_argument(
        "--hash",
        required=True,
        help="ED2K file hash, 32 hexadecimal digits.",
    )
    p_sources_ed2k.add_argument(
        "--size",
        required=True,
        type=int,
        help="Complete file size in bytes.",
    )
    p_sources_ed2k.add_argument(
        "--save",
        action="store_true",
        help="Persist returned sources to DuckDB.",
    )
    p_sources_ed2k.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="Connect and response timeout in seconds.",
    )
    p_sources_ed2k.set_defaults(func=_cmd_sources_ed2k)

    p_sources_list = sources_sub.add_parser(
        "list",
        help="List persisted ED2K file sources.",
        parents=parents,
    )
    p_sources_list.add_argument(
        "--hash",
        help="Optional ED2K file hash filter.",
    )
    p_sources_list.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum rows to return.",
    )
    p_sources_list.set_defaults(func=_cmd_sources_list)

    p_sources_forget = sources_sub.add_parser(
        "forget",
        help="Delete all persisted sources for one ED2K hash.",
        parents=parents,
    )
    p_sources_forget.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_sources_forget.set_defaults(func=_cmd_sources_forget)

    p_sources_prune = sources_sub.add_parser(
        "prune",
        help="Delete expired or dead source rows.",
        parents=parents,
    )
    p_sources_prune.add_argument(
        "--max-age-hours",
        type=float,
        default=24 * 7,
        help="Remove rows not seen within this many hours (default: 168).",
    )
    p_sources_prune.add_argument(
        "--dead-only",
        action="store_true",
        help="Only remove low-id rows that expired.",
    )
    p_sources_prune.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be pruned without deleting.",
    )
    p_sources_prune.set_defaults(func=_cmd_sources_prune)

    # --- download ---
    p_download = sub.add_parser(
        "download",
        help="Manage the download queue.",
        parents=parents,
    )
    download_sub = p_download.add_subparsers(dest="download_command", metavar="<action>")

    p_download_add = download_sub.add_parser(
        "add",
        help="Queue a download from a real ed2k:// file link.",
        parents=parents,
    )
    p_download_add.add_argument("link", help="ed2k://|file|... link.")
    p_download_add.set_defaults(func=_cmd_download_add)

    p_download_run = download_sub.add_parser(
        "run",
        help="Download one queued file from its known sources.",
        parents=parents,
    )
    p_download_run.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_download_run.add_argument(
        "--max-peers",
        type=int,
        default=3,
        help="Maximum sequential peers to try.",
    )
    p_download_run.add_argument(
        "--queue-wait",
        type=float,
        default=60.0,
        help="Upload-slot wait per peer in seconds.",
    )
    p_download_run.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the MD4 verification on finalize.",
    )
    p_download_run.set_defaults(func=_cmd_download_run)

    p_download_list = download_sub.add_parser(
        "list",
        help="List queued downloads.",
        parents=parents,
    )
    p_download_list.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum rows to return.",
    )
    p_download_list.set_defaults(func=_cmd_download_list)

    p_download_pause = download_sub.add_parser(
        "pause",
        help="Pause one download.",
        parents=parents,
    )
    p_download_pause.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_download_pause.set_defaults(func=_cmd_download_pause)

    p_download_resume = download_sub.add_parser(
        "resume",
        help="Resume one paused download.",
        parents=parents,
    )
    p_download_resume.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_download_resume.set_defaults(func=_cmd_download_resume)

    p_download_cancel = download_sub.add_parser(
        "cancel",
        help="Remove a download and its part files.",
        parents=parents,
    )
    p_download_cancel.add_argument("hash", help="ED2K file hash (32 hexadecimal digits).")
    p_download_cancel.add_argument(
        "--keep-files",
        action="store_true",
        help="Keep the .part files on disk.",
    )
    p_download_cancel.set_defaults(func=_cmd_download_cancel)

    # --- ipfilter ---
    p_ipfilter = sub.add_parser(
        "ipfilter",
        help="Inspect the IP filter used for servers and peers.",
        parents=parents,
    )
    ipfilter_sub = p_ipfilter.add_subparsers(dest="ipfilter_command", metavar="<action>")

    p_ipfilter_status = ipfilter_sub.add_parser(
        "status",
        help="Show loaded ipfilter statistics.",
        parents=parents,
    )
    p_ipfilter_status.set_defaults(func=_cmd_ipfilter_status)

    p_ipfilter_test = ipfilter_sub.add_parser(
        "test",
        help="Test one IPv4 address against the filter.",
        parents=parents,
    )
    p_ipfilter_test.add_argument("ip", help="IPv4 address to test.")
    p_ipfilter_test.set_defaults(func=_cmd_ipfilter_test)

    # --- daemon ---
    p_daemon = sub.add_parser("daemon", help="Daemon lifecycle (M2 stub).", parents=parents)
    d_sub = p_daemon.add_subparsers(dest="daemon_command", metavar="<action>")
    p_d_start = d_sub.add_parser("start", help="Start daemon (stub).", parents=parents)
    p_d_start.set_defaults(func=_cmd_daemon_start)
    p_d_stop = d_sub.add_parser("stop", help="Stop daemon (stub).", parents=parents)
    p_d_stop.set_defaults(func=_cmd_daemon_stop)

    return parser


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    # Configure a console logger first so even config-loading diagnostics are tagged.
    configure_logging("INFO")

    # Windows consoles default to legacy code pages; JSON output must not die on
    # non-cp1251 characters from real file names.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    # Configure logging lazily (optional deps already guarded).
    cfg = load_config(save_if_missing=True)
    configured_level = cfg.get("logging", {}).get("level", "INFO")
    configured_file = cfg.get("logging", {}).get("file")
    configure_logging(configured_level, log_file=configured_file)
    log.debug(
        f"Logging configured: level={configured_level}, "
        f"file={configured_file or 'console-only'}"
    )

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0
    try:
        return func(args)
    except Exception as exc:
        log.exception(f"Command failed: type={type(exc).__name__}, error={exc}")
        raise


if __name__ == "__main__":
    sys.exit(main())
