"""AmuleD v0.6.0 Interactive Menu -- a thin interactive shell over the CLI.

A synchronous, console-only interactive menu that shells every operation out
to ``python -m amuled_v2 <args> --json`` via :mod:`subprocess`.  No protocol,
network, or state logic is reimplemented here; the menu only renders JSON.

scripts/amuled_menu.py
Version:     0.6.0
Author:      Soror L'.L'.
Updated:     2026-09-26

Patch Notes v0.6.0 (Soror L'.L'.):
  [*] KAD status screen now reads the unified kernel (kernel_status.json +
      `daemon status` over IPC); the standalone spider hint was replaced
      with the `serve` hint (stage U: the kernel includes the spider).
Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Thin interactive menu over the AmuleD CLI (Server, KAD, Share, Search,
      Downloads, Status, IP filter).
  [+] Centralised cli() / cli_text() subprocess helpers with JSON parsing and
      robust error fallback.
  [+] Paginated search results viewer with per-result download / source lookup.
  [+] Live long-wait handling for download run via progress polling.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
STATUS_FILE = ROOT / "db" / "kernel_status.json"
DEFAULT_SERVER = "176.123.5.89:4725"

configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled.jsonl",
)
log = get_tagged_logger(LogTags.CLI, "menu")


# ------------------------------------------------------------------
# Console hygiene
# ------------------------------------------------------------------
def _setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    if os.name == "nt":
        os.system("")
    print("=" * 60)
    print("AmuleD v0.6.0 Interactive Menu -- by Soror L'.L'.")
    print("=" * 60)
    print()


# ------------------------------------------------------------------
# Subprocess helpers
# ------------------------------------------------------------------
def _menu_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["AMULED_ROOT"] = str(ROOT)
    return env


def _extract_json(stdout: str) -> Any:
    """Find the first '{' in stdout and parse JSON from there.

    The CLI may emit leading log lines to stderr/stdout; the JSON payload
    itself is the last thing printed.  We strip forward to the first '{' to
    be tolerant of interleaved diagnostics.
    """
    idx = stdout.find("{")
    if idx < 0:
        raise ValueError("no JSON object found in output")
    return json.loads(stdout[idx:])


def cli(*args: str, timeout: int = 180) -> dict:
    """Run ``python -m amuled_v2 *args --json`` and return parsed JSON dict."""
    cmd = [sys.executable, "-m", "amuled_v2", *args, "--json"]
    log.debug("CLI invoke: cmd=%s timeout=%d", " ".join(cmd), timeout)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_menu_env(),
            timeout=timeout,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("CLI timeout: args=%s timeout=%d", args, timeout)
        return {"status": "error", "reason": f"command timed out after {timeout}s"}
    except FileNotFoundError as exc:
        log.error("CLI executable not found: error=%s", exc)
        return {"status": "error", "reason": str(exc)}

    if proc.returncode != 0:
        tail = proc.stderr.strip()[-500:] if proc.stderr else proc.stdout.strip()[-500:]
        log.warning(
            "CLI non-zero exit: rc=%d args=%s tail=%s",
            proc.returncode, args, tail,
        )
    try:
        return _extract_json(proc.stdout)
    except Exception as exc:
        tail = (proc.stdout + proc.stderr).strip()[-500:]
        log.warning("CLI JSON parse failed: error=%s tail=%s", exc, tail)
        return {"status": "error", "reason": str(exc), "raw_tail": tail}


def cli_text(*args: str, timeout: int = 180) -> str:
    """Run ``python -m amuled_v2 *args`` in text mode (no --json) and return stdout."""
    cmd = [sys.executable, "-m", "amuled_v2", *args]
    log.debug("CLI text invoke: cmd=%s timeout=%d", " ".join(cmd), timeout)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_menu_env(),
            timeout=timeout,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return f"[menu] command timed out after {timeout}s"
    except FileNotFoundError as exc:
        return f"[menu] executable not found: {exc}"
    return proc.stdout + proc.stderr


# ------------------------------------------------------------------
# Input helpers
# ------------------------------------------------------------------
def ask(prompt: str, default: str = "") -> str:
    try:
        raw = input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        raise
    raw = raw.strip()
    return raw if raw else default


def ask_int(prompt: str, default: int | None = None) -> int:
    while True:
        raw = ask(prompt, "" if default is None else str(default))
        if not raw and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("  Please enter a valid integer.")


def ask_yes_no(prompt: str, default: str = "n") -> bool:
    while True:
        raw = ask(prompt + " [y/N]: ", default).lower()
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no", ""):
            return False
        print("  Please answer y or n.")


def pause() -> None:
    try:
        input("Press Enter to continue...")
    except (KeyboardInterrupt, EOFError):
        print()


def ask_hash(prompt: str = "Hash: ") -> str:
    while True:
        raw = ask(prompt).lower().strip()
        if len(raw) == 32 and all(c in "0123456789abcdef" for c in raw):
            return raw
        print("  Please enter a valid 32-hex ED2K hash.")


# ------------------------------------------------------------------
# Rendering helpers
# ------------------------------------------------------------------
def hr(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def human_size(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if n < 0:
        return f"-{human_size(-n)}"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def render_table(rows: list[dict], headers: list[str], widths: list[int]) -> None:
    def _fmt_row(cells: list[str]) -> str:
        parts = []
        for cell, width in zip(cells, widths):
            if len(cell) > width:
                cell = cell[: max(0, width - 1)] + "\u2026"
            parts.append(cell.ljust(width))
        return "  " + "  ".join(parts)

    print(_fmt_row(headers))
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        cells = [str(row.get(h, "")) for h in headers]
        print(_fmt_row(cells))


def render_json(d: Any) -> None:
    try:
        print(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True))
    except (TypeError, ValueError) as exc:
        log.warning("JSON render failed: error=%s", exc)
        print(json.dumps(str(d), ensure_ascii=False))


def render_kv(d: Any, indent: int = 0) -> None:
    pad = "  " * indent
    if not isinstance(d, dict):
        print(f"{pad}{d}")
        return
    for key, value in d.items():
        if isinstance(value, dict):
            print(f"{pad}{key}:")
            render_kv(value, indent + 1)
        elif isinstance(value, list):
            print(f"{pad}{key}: [{len(value)} items]")
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    print(f"{pad}  [{i}]")
                    render_kv(item, indent + 2)
                else:
                    print(f"{pad}  [{i}] {item}")
        else:
            print(f"{pad}{key}: {value}")


# ------------------------------------------------------------------
# Status renderers
# ------------------------------------------------------------------
def render_status(result: dict) -> None:
    if not isinstance(result, dict):
        render_json(result)
        return
    if "status" in result and result["status"] != "ok":
        print(f"  Error: {result.get('reason', result.get('status', 'unknown'))}")
        return
    if "status" not in result:
        render_kv(result)
        return
    print(f"  Backend : {result.get('backend', '?')}")
    print(f"  DB path : {result.get('db_path', '?')}")
    print(f"  Tables  : {result.get('tables', '?')}")
    net = result.get("network", {})
    if net:
        print(f"  TCP port: {net.get('client_tcp_port')}")
        print(f"  UDP port: {net.get('client_udp_port')}")
        print(f"  ED2K    : {net.get('enable_ed2k')}")
        print(f"  KAD     : {net.get('enable_kad')}")
    conns = result.get("connections", {})
    if conns:
        print(f"  ED2K conn: {conns.get('ed2k_connected')}")
        print(f"  KAD conn : {conns.get('kad_connected')}")
        srv = conns.get("server")
        if srv:
            print(f"  Server  : {srv}")
    ss = result.get("source_stats")
    if ss:
        print(
            f"  Sources : {ss.get('total_sources', '?')} "
            f"({ss.get('distinct_files', '?')} files)"
        )


def render_server_failures(result: dict) -> None:
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status'))}")
        return
    print(f"  Blacklisted: {result.get('blacklisted_count', 0)}")
    print(f"  Tracked    : {result.get('tracked_count', 0)}")
    print()
    for row in result.get("blacklisted", []):
        print(
            f"  BANNED {row['ip']}:{row['port']} "
            f"failures={row.get('failures')} "
            f"until={row.get('blacklisted_until')} "
            f"({row.get('last_error', '?')})"
        )
    for row in result.get("tracked", []):
        print(
            f"  TRACK  {row['ip']}:{row['port']} "
            f"failures={row.get('failures')}"
        )


def render_sources(result: dict) -> None:
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status'))}")
        return
    sources = result.get("sources", [])
    if not sources:
        print("  No sources found.")
        return
    rows = []
    for s in sources:
        ip = s.get("ip") or "low-id"
        tcp = s.get("tcp_port") or (s.get("client_port"))
        rows.append({
            "Address": f"{ip}:{tcp}" if tcp else ip,
            "Type": s.get("source_type", "?"),
            "Dialable": str(s.get("dialable", "?")),
        })
    render_table(rows, ["Address", "Type", "Dialable"], [30, 12, 8])
    print()
    print(f"  Total sources : {result.get('source_count', len(sources))}")
    print(f"  Saved sources : {result.get('saved_sources', 0)}")


def render_ipfilter(result: dict) -> None:
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status'))}")
        return
    print(f"  Path    : {result.get('path', '?')}")
    print(f"  Ranges  : {result.get('range_count', '?')}")
    print(f"  Max Lvl : {result.get('max_level', '?')}")


def render_ipfilter_test(result: dict) -> None:
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status'))}")
        return
    print(f"  IP       : {result.get('ip', '?')}")
    print(f"  Filtered : {result.get('filtered', '?')}")
    rng = result.get("range")
    if rng:
        print(
            f"  Range    : {rng.get('start')} - {rng.get('end')} "
            f"level={rng.get('level')} {rng.get('description', '')}"
        )


# ------------------------------------------------------------------
# Results viewer (shared by search flows)
# ------------------------------------------------------------------
PAGE_SIZE = 15


def _result_rows(result: dict) -> list[dict]:
    raw = result.get("results", [])
    if not isinstance(raw, list):
        return []
    rows = []
    for item in raw:
        rows.append({
            "hash": item.get("hash", ""),
            "name": item.get("name", ""),
            "size": item.get("size", 0),
            "sources": item.get("sources", 0),
        })
    return rows


def _result_source_count(item: dict) -> int:
    if isinstance(item.get("source_count"), int):
        return item["source_count"]
    sources = item.get("sources")
    if isinstance(sources, int):
        return sources
    if isinstance(sources, list):
        return len(sources)
    return 0


def results_viewer(result: dict, origin_label: str = "results") -> None:
    rows = _result_rows(result)
    if not rows:
        print(f"  No results for '{origin_label}'.")
        return

    page = 0
    total = len(rows)

    while True:
        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, total)
        page_rows = rows[start:end]

        print()
        hr(f"Search results ({total} total, page {page + 1}/{(total - 1) // PAGE_SIZE + 1})")
        table_rows = []
        for i, r in enumerate(page_rows, start=start + 1):
            table_rows.append({
                "No": str(i),
                "Size": human_size(r["size"]),
                "Src": str(r["sources"]),
                "Name": r["name"],
            })
        render_table(
            table_rows,
            ["No", "Size", "Src", "Name"],
            [5, 10, 5, 70],
        )
        print()
        print("  Commands: n=next, p=prev, <number>=pick, <1,3,5 or 2-5>=multi-download, s=new search, q=back")

        try:
            cmd = ask("  > ").lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if cmd == "" or cmd == "q":
            return
        if cmd == "n":
            if end < total:
                page += 1
            else:
                print("  Already on last page.")
            continue
        if cmd == "p":
            if page > 0:
                page -= 1
            else:
                print("  Already on first page.")
            continue
        if cmd == "s":
            return
        picks = _parse_multi_select(cmd, total)
        if picks is not None:
            if not picks:
                print(f"  No valid numbers in: {cmd!r}")
                continue
            _multi_download([rows[i - 1] for i in picks])
            continue
        try:
            idx = int(cmd)
        except ValueError:
            print(f"  Unknown command: {cmd!r}")
            continue
        if 1 <= idx <= total:
            _result_submenu(rows[idx - 1])
        else:
            print(f"  Number out of range (1-{total}).")


def _parse_multi_select(cmd: str, total: int) -> list[int] | None:
    """Parse '1,3,5' or '2-5' or mixed '1,4-6' into 1-based numbers.

    Returns None when the input is not a multi-select expression at all
    (so the caller can fall through to single-number handling).
    """
    parts = [p.strip() for p in cmd.split(",") if p.strip()]
    if len(parts) < 2 and not ("-" in cmd and cmd.replace("-", "").isdigit()):
        return None
    picks: list[int] = []
    for part in parts:
        if "-" in part:
            lo_raw, _, hi_raw = part.partition("-")
            try:
                lo, hi = int(lo_raw), int(hi_raw)
            except ValueError:
                print(f"  Skipping invalid range: '{part}'")
                continue
            if lo > hi:
                lo, hi = hi, lo
            picks.extend(range(lo, hi + 1))
        else:
            try:
                picks.append(int(part))
            except ValueError:
                print(f"  Skipping invalid number: '{part}'")
    return [n for n in picks if 1 <= n <= total]


def _multi_download(picked: list[dict]) -> None:
    """v1-style bulk download: add every picked result, then run them all."""
    print(f"  Picked {len(picked)} file(s):")
    for item in picked:
        print(f"    {item.get('name', '?')} ({human_size(item.get('size', 0))})")
    if not ask_yes_no(f"Add all {len(picked)} to downloads?", "y"):
        return
    added: list[dict] = []
    for item in picked:
        link = _build_ed2k_link(
            item.get("name", ""), int(item.get("size", 0)), item.get("hash", "")
        )
        result = cli("download", "add", link, timeout=60)
        if result.get("status") == "ok":
            added.append(item)
            print(f"  Added : {item.get('name', '?')}")
        else:
            print(
                f"  FAILED: {item.get('name', '?')} -> "
                f"{result.get('reason', result.get('status', 'error'))}"
            )
    if not added:
        return
    if not ask_yes_no(f"Start downloading {len(added)} file(s) now?", "y"):
        return
    for item in added:
        print()
        hr(f"Downloading: {item.get('name', '?')}")
        _long_download_run(item.get("hash", ""))
    print()
    print(f"  Batch finished ({len(added)} file(s) processed).")


def _result_submenu(result_item: dict) -> None:
    name = result_item.get("name", "")
    size = result_item.get("size", 0)
    file_hash = result_item.get("hash", "")
    while True:
        print()
        hr(f"Result: {name}")
        print("  [1] Download this file")
        print("  [2] Find sources (KAD) for this hash")
        print("  [3] Back to results")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "1":
            _download_from_result(name, size, file_hash)
        elif choice == "2":
            kad_source_search(file_hash, size)
        elif choice == "3" or choice == "":
            return
        else:
            print(f"  Unknown choice: {choice!r}")


def _sanitize_name(name: str) -> str:
    return name.replace("|", "%7C").replace("/", "_")


def _build_ed2k_link(name: str, size: int, file_hash: str) -> str:
    safe = _sanitize_name(name)
    return f"ed2k://|file|{safe}|{size}|{file_hash}|/"


def _download_from_result(name: str, size: int, file_hash: str) -> None:
    link = _build_ed2k_link(name, size, file_hash)
    print(f"  Link: {link}")
    result = cli("download", "add", link, timeout=60)
    if result.get("status") == "ok":
        print(f"  Added: {result.get('name', '?')} [{result.get('hash', '?')}]")
    else:
        print(f"  Add failed: {result.get('reason', result.get('status', 'error'))}")
        return
    if not ask_yes_no("Start downloading now?", "n"):
        return
    _long_download_run(file_hash)


def _long_download_run(file_hash: str) -> None:
    done = threading.Event()
    result_box: list = []

    def _worker() -> None:
        result_box.append(cli("download", "run", file_hash, timeout=900))
        done.set()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    start = time.monotonic()
    while not done.is_set():
        elapsed = time.monotonic() - start
        print(f"  [download] elapsed={elapsed:.0f}s hash={file_hash} (waiting for completion...)")
        if done.wait(timeout=5):
            break
    if result_box:
        result = result_box[0]
        print()
        if result.get("status") == "ok":
            outcome = result.get("outcome", {})
            if isinstance(outcome, dict):
                print(
                    f"  Downloaded: {outcome.get('bytes_received', 0)} bytes, "
                    f"blocks={outcome.get('blocks_received', 0)}, "
                    f"detail={outcome.get('detail', '?')}"
                )
            finalized = result.get("finalized")
            if isinstance(finalized, dict):
                print(f"  Finalized: {finalized.get('target', '?')}")
            print(f"  Status: complete")
        else:
            print(f"  Download error: {result.get('reason', result.get('status', 'error'))}")
    if ask_yes_no("Open downloads list?", "y"):
        _print_download_list()


def _print_download_list() -> None:
    output = cli_text("download", "list", timeout=30)
    print()
    print(output, end="")


# ------------------------------------------------------------------
# Kernel/KAD status (reads db/kernel_status.json + daemon status over IPC)
# ------------------------------------------------------------------
def show_kad_status() -> None:
    if not STATUS_FILE.exists():
        print("  Kernel is not running (no kernel_status.json).")
        print("  Hint: run '.\\AmuleD_Run.ps1 serve' — the kernel includes the KAD spider.")
        return
    result = cli("daemon", "status", timeout=30)
    if result.get("status") != "ok" or not result.get("running"):
        print("  Kernel is not running.")
        return
    spider = result.get("spider") or {}
    print()
    print(f"  running      : yes")
    print(f"  serve_port   : {result.get('serve_port', '?')}")
    print(f"  connections  : {result.get('active_connections', 0)}")
    print(f"  uptime_s     : {result.get('uptime_s', 0)}")
    print(f"  pool_size    : {spider.get('pool_size', 0)}")
    print(f"  alive_est    : {spider.get('alive_estimate', 0)}")
    print(f"  cycles       : {spider.get('uptime_cycles', 0)}")


# ------------------------------------------------------------------
# Search flow helpers
# ------------------------------------------------------------------
def _search_server_flow() -> None:
    query = ask("Search query: ", "music")
    if not query:
        return
    server = ask(f"Server ip:port [{DEFAULT_SERVER}]: ", DEFAULT_SERVER)
    if not server:
        return
    result = cli("search", "server", f"--server={server}", f"--query={query}", timeout=120)
    if result.get("status") != "ok":
        print(f"  Search error: {result.get('reason', result.get('status', 'error'))}")
        pause()
        return
    results_viewer(result, f"server search '{query}'")


def _search_global_flow() -> None:
    query = ask("Search query: ", "music")
    if not query:
        return
    result = cli("search", "global", f"--query={query}", timeout=120)
    if result.get("status") != "ok":
        print(f"  Search error: {result.get('reason', result.get('status', 'error'))}")
        pause()
        return
    results_viewer(result, f"global search '{query}'")


def kad_search_flow() -> None:
    query = ask("KAD keyword search: ", "music")
    if not query:
        return
    timeout_s = ask_int("Timeout (seconds) [45]: ", 45)
    result = cli("kad", "search", query, f"--timeout={timeout_s}", timeout=timeout_s + 30)
    if result.get("status") != "ok":
        print(f"  KAD search error: {result.get('reason', result.get('status', 'error'))}")
        pause()
        return
    results_viewer(result, f"kad search '{query}'")


def kad_source_search(file_hash: str, size: int) -> None:
    result = cli(
        "kad", "sources", file_hash,
        f"--size={size or 0}",
        "--timeout=45",
        timeout=90,
    )
    hr(f"KAD sources for {file_hash}")
    render_sources(result)
    pause()


def _ed2k_source_search_flow() -> None:
    file_hash = ask_hash("ED2K hash (32 hex): ")
    if not file_hash:
        return
    size_raw = ask("File size (bytes, empty=0): ", "0")
    try:
        size = int(size_raw)
    except ValueError:
        size = 0
    server = ask(f"Server ip:port [{DEFAULT_SERVER}]: ", DEFAULT_SERVER)
    if not server:
        return
    result = cli(
        "sources", "ed2k",
        f"--server={server}",
        f"--hash={file_hash}",
        f"--size={size}",
        "--save",
        timeout=120,
    )
    hr(f"ED2K sources for {file_hash}")
    render_sources(result)
    pause()


def _saved_sources_flow() -> None:
    file_hash = ask("Optional hash filter (empty=any): ", "")
    args = ["sources", "list", "--json"]
    if file_hash:
        args = ["sources", "list", f"--hash={file_hash}", "--json"]
    result = cli(*args, timeout=30)
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
        pause()
        return
    sources = result.get("sources", [])
    if not sources:
        print("  No saved sources found.")
        pause()
        return
    rows = []
    for s in sources:
        rows.append({
            "Hash": str(s.get("hash", ""))[:12],
            "Client": f"{s.get('client_id', '?')}:{s.get('client_port', '?')}",
            "Server": f"{s.get('server_ip', '?')}:{s.get('server_port', '?')}",
            "Type": s.get("source_type", "?"),
        })
    hr("Saved sources")
    render_table(rows, ["Hash", "Client", "Server", "Type"], [14, 22, 22, 10])
    print(f"\n  Total: {result.get('source_count', len(sources))}")
    pause()


# ------------------------------------------------------------------
# Server submenu
# ------------------------------------------------------------------
def server_menu() -> None:
    while True:
        print()
        hr("Server")
        print("  [1] Client status")
        print("  [2] Search on server")
        print("  [3] Global search")
        print("  [4] ED2K sources by hash")
        print("  [5] Saved sources list")
        print("  [6] Server failures / blacklist")
        print("  [7] Forgive server")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            hr("Client status")
            render_status(cli("status", timeout=30))
            pause()
        elif choice == "2":
            _search_server_flow()
        elif choice == "3":
            _search_global_flow()
        elif choice == "4":
            _ed2k_source_search_flow()
        elif choice == "5":
            _saved_sources_flow()
        elif choice == "6":
            hr("Server failures / blacklist")
            render_server_failures(cli("servers", "failures", timeout=30))
            pause()
        elif choice == "7":
            _forgive_server()
        else:
            print(f"  Unknown choice: {choice!r}")


def _forgive_server() -> None:
    ip = ask("Server IP: ")
    if not ip:
        return
    port_raw = ask("Server port: ")
    try:
        port = int(port_raw)
    except ValueError:
        print("  Invalid port.")
        return
    result = cli("servers", "forgive", ip, str(port), timeout=30)
    hr("Forgive server")
    if result.get("status") == "ok":
        print(f"  Forgiven: {ip}:{port}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


# ------------------------------------------------------------------
# KAD submenu
# ------------------------------------------------------------------
def kad_menu() -> None:
    while True:
        print()
        hr("KAD network")
        print("  [1] KAD network status")
        print("  [2] KAD keyword search")
        print("  [3] KAD file sources")
        print("  [4] Saved sources list")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            hr("KAD network status")
            show_kad_status()
            pause()
        elif choice == "2":
            kad_search_flow()
        elif choice == "3":
            _kad_source_search_flow()
        elif choice == "4":
            _saved_sources_flow()
        else:
            print(f"  Unknown choice: {choice!r}")


def _kad_source_search_flow() -> None:
    file_hash = ask_hash("ED2K hash (32 hex): ")
    if not file_hash:
        return
    size_raw = ask("File size in bytes (empty=0): ", "0")
    try:
        size = int(size_raw)
    except ValueError:
        size = 0
    kad_source_search(file_hash, size)


# ------------------------------------------------------------------
# Share submenu
# ------------------------------------------------------------------
def share_menu() -> None:
    while True:
        print()
        hr("Share")
        print("  [1] List shared files")
        print("  [2] Add file or directory")
        print("  [3] Scan shared directories")
        print("  [4] Remove file")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            _share_list()
        elif choice == "2":
            _share_add()
        elif choice == "3":
            _share_scan()
        elif choice == "4":
            _share_remove()
        else:
            print(f"  Unknown choice: {choice!r}")


def _share_list() -> None:
    result = cli("share", "list", "--json", timeout=30)
    hr("Shared files")
    if result.get("status") != "ok":
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
        pause()
        return
    files = result.get("files", [])
    dirs = result.get("directories", [])
    if dirs:
        print(f"  Directories ({len(dirs)}):")
        for d in dirs:
            print(f"    {d}")
    if not files:
        print("  No shared files.")
    else:
        print(f"\n  Files ({len(files)}):")
        rows = []
        for f in files:
            rows.append({
                "Hash": str(f.get("hash", ""))[:12],
                "Size": human_size(f.get("size", 0)),
                "Name": str(f.get("name", "")),
            })
        render_table(rows, ["Hash", "Size", "Name"], [14, 10, 60])
    print(f"\n  Total files: {result.get('file_count', len(files))}")
    pause()


def _share_add() -> None:
    path = ask("Path to add: ")
    if not path:
        return
    print("  Scanning and hashing (this may take a while)...")
    output = cli_text("share", "add", path, "--no-progress", timeout=600)
    print()
    print(output, end="")
    pause()


def _share_scan() -> None:
    print("  Scanning shared directories...")
    output = cli_text("share", "scan", "--no-progress", timeout=600)
    print()
    print(output, end="")
    pause()


def _share_remove() -> None:
    file_hash = ask_hash("Hash of file to remove (32 hex): ")
    if not file_hash:
        return
    result = cli("share", "remove", "file", file_hash, timeout=30)
    hr("Remove shared file")
    if result.get("status") in ("ok", "not_found"):
        removed = result.get("removed", False)
        print(f"  Hash  : {file_hash}")
        print(f"  Removed: {removed}")
        if result.get("name"):
            print(f"  Name  : {result['name']}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


# ------------------------------------------------------------------
# Downloads submenu
# ------------------------------------------------------------------
def downloads_menu() -> None:
    while True:
        print()
        hr("Downloads")
        print("  [1] List downloads")
        print("  [2] Add download")
        print("  [3] Run now")
        print("  [4] Pause")
        print("  [5] Resume")
        print("  [6] Cancel")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            _print_download_list()
            pause()
        elif choice == "2":
            _download_add()
        elif choice == "3":
            _download_run_prompt()
        elif choice == "4":
            _download_pause()
        elif choice == "5":
            _download_resume()
        elif choice == "6":
            _download_cancel()
        else:
            print(f"  Unknown choice: {choice!r}")


def _download_add() -> None:
    print("  Enter an ed2k:// link, or press Enter to build one from hash+size+name.")
    raw = ask("  ed2k link (or leave blank to build): ", "")
    if raw.lower().startswith("ed2k://"):
        link = raw
    else:
        file_hash = ask_hash("  Hash (32 hex): ")
        if not file_hash:
            return
        size_raw = ask("  Size (bytes): ", "0")
        try:
            size = int(size_raw)
        except ValueError:
            print("  Invalid size.")
            return
        name = ask("  Name: ", "")
        if not name:
            print("  Name cannot be empty.")
            return
        link = _build_ed2k_link(name, size, file_hash)
    result = cli("download", "add", link, timeout=60)
    hr("Download add")
    if result.get("status") == "ok":
        print(f"  Hash  : {result.get('hash', '?')}")
        print(f"  Name  : {result.get('name', '?')}")
        print(f"  Size  : {result.get('size', '?')}")
        print(f"  Queue : {result.get('status', '?')}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


def _download_run_prompt() -> None:
    file_hash = ask_hash("Hash to download (32 hex): ")
    if not file_hash:
        return
    _long_download_run(file_hash)


def _download_pause() -> None:
    file_hash = ask_hash("Hash to pause (32 hex): ")
    if not file_hash:
        return
    result = cli("download", "pause", file_hash, timeout=30)
    hr("Download pause")
    if result.get("status") == "ok":
        print(f"  Hash  : {result.get('hash', '?')}")
        print(f"  Name  : {result.get('name', '?')}")
        print(f"  Queue : {result.get('status', '?')}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


def _download_resume() -> None:
    file_hash = ask_hash("Hash to resume (32 hex): ")
    if not file_hash:
        return
    result = cli("download", "resume", file_hash, timeout=30)
    hr("Download resume")
    if result.get("status") == "ok":
        print(f"  Hash  : {result.get('hash', '?')}")
        print(f"  Name  : {result.get('name', '?')}")
        print(f"  Queue : {result.get('status', '?')}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


def _download_cancel() -> None:
    file_hash = ask_hash("Hash to cancel (32 hex): ")
    if not file_hash:
        return
    if not ask_yes_no(f"Cancel download {file_hash[:8]}...?", "n"):
        return
    result = cli("download", "cancel", file_hash, timeout=30)
    hr("Download cancel")
    if result.get("status") == "ok":
        print(f"  Hash        : {result.get('hash', '?')}")
        print(f"  Cancelled   : {result.get('cancelled', '?')}")
        print(f"  Files removed: {result.get('files_removed', 0)}")
    else:
        print(f"  Error: {result.get('reason', result.get('status', 'error'))}")
    pause()


# ------------------------------------------------------------------
# IP filter submenu
# ------------------------------------------------------------------
def ipfilter_menu() -> None:
    while True:
        print()
        hr("IP filter")
        print("  [1] Status")
        print("  [2] Test IP")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            hr("IP filter status")
            render_ipfilter(cli("ipfilter", "status", timeout=15))
            pause()
        elif choice == "2":
            ip = ask("  IP to test: ")
            if not ip:
                return
            hr("IP filter test")
            render_ipfilter_test(cli("ipfilter", "test", ip, timeout=15))
            pause()
        else:
            print(f"  Unknown choice: {choice!r}")


# ------------------------------------------------------------------
# Main menu
# ------------------------------------------------------------------
def main_menu() -> None:
    while True:
        print()
        hr("Main menu")
        print("  [1] Server")
        print("  [2] KAD network")
        print("  [3] Share")
        print("  [4] Search")
        print("  [5] Downloads")
        print("  [6] Client status")
        print("  [7] IP filter")
        print("  [0] Quit")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            print("Bye.")
            return
        if choice == "0":
            print("Bye.")
            return
        elif choice == "1":
            server_menu()
        elif choice == "2":
            kad_menu()
        elif choice == "3":
            share_menu()
        elif choice == "4":
            _search_submenu()
        elif choice == "5":
            downloads_menu()
        elif choice == "6":
            hr("Client status")
            render_status(cli("status", timeout=30))
            pause()
        elif choice == "7":
            ipfilter_menu()
        else:
            print(f"  Unknown choice: {choice!r}")


def _search_submenu() -> None:
    while True:
        print()
        hr("Search")
        print("  [1] Search on server (ED2K TCP)")
        print("  [2] Global search (ED2K UDP)")
        print("  [3] KAD keyword search")
        print("  [4] ED2K sources by hash")
        print("  [5] Saved sources list")
        print("  [0] Back")
        try:
            choice = ask("  > ")
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "0":
            return
        elif choice == "1":
            _search_server_flow()
        elif choice == "2":
            _search_global_flow()
        elif choice == "3":
            kad_search_flow()
        elif choice == "4":
            _ed2k_source_search_flow()
        elif choice == "5":
            _saved_sources_flow()
        else:
            print(f"  Unknown choice: {choice!r}")


def main() -> None:
    _setup_console()
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        print("Bye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
