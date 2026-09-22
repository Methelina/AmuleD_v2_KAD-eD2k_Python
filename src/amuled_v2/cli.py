"""Command-line interface for AmuleD_v2.

Provides an argparse-based English CLI with optional ``--json`` output.
Commands:
  - ``status``              — show backend, db path, table counts, version.
  - ``config show``         — print current JSONC config.
  - ``config set <key> <v>``— set a dotted config key (type-inferred).
  - ``init``                — ensure runtime dirs and default config exist.
  - ``daemon start/stop``   — M2 stubs returning not_implemented.

Dependencies (duckdb, rich) are optional at runtime; ``--help`` works without
them installed.  Network/protocol modules are not imported.

src/amuled_v2/cli.py
Version:     0.4.2
Author:      Soror L.'.L.'.
Updated:     2026-09-22

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
import json
import sys
from typing import Sequence

from amuled_v2 import __app_name__, __version__, __version_string__
from amuled_v2.config import config_set, config_show, load_config
from amuled_v2.daemon import start_daemon, stop_daemon
from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

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
    if args.json:
        _print_json(result)
    else:
        _print_text(f"{__version_string__} Status", [
            f"version    : {result['version']}",
            f"backend    : {result['backend']}",
            f"db_path    : {result['db_path']}",
            f"tables     : {result['tables']}",
            f"tcp_port   : {result['network']['client_tcp_port']}",
            f"udp_port   : {result['network']['client_udp_port']}",
            f"ed2k       : {result['network']['enable_ed2k']}",
            f"kad        : {result['network']['enable_kad']}",
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
