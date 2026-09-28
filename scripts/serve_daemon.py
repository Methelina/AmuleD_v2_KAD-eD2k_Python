"""AmuleD kernel launcher (thin wrapper over core.kernel.run_kernel).

Stage U: this process IS the AmuleD kernel — one permanent DuckDB
connection, the KAD spider maturation loop, the incoming peer listener
with KAD source republication, and the IPC control server for the CLI.
The standalone scripts/kad_spider.py is superseded (its DuckDB saves
cannot open while the kernel owns the db — by design, not a bug).

Usage (through the single runtime dispatcher, project doctrine):

    .\\AmuleD_Run.ps1 serve                # kernel: spider + listener + IPC
    .\\AmuleD_Run.ps1 serve --no-spider    # listener + republish only
    .\\AmuleD_Run.ps1 serve --once         # one publish pass, then exit

scripts/serve_daemon.py
Version:     0.3.2
Author:      Soror L.'.L.'.
Updated:     2026-09-25

Patch Notes v0.3.2 (Soror L.'.L'.):
  [!] REMOVED faulthandler.dump_traceback_later() - the root cause of the
      three 2026-09-28 kernel deaths (0xc0000005 at python312.dll+0x2877d0,
      inside _Py_DumpTraceback): its watchdog thread reads live threads'
      frame lists without pausing them, and a frame freed mid-read crashes
      the process.  Liveness monitoring moved to the launcher
      (kernel_status.json heartbeat); faulthandler.enable() stays for real
      fatal faults.

Patch Notes v0.3.1 (Soror L.'.L'.):
  [+] faulthandler.enable(all_threads=True) into logs\\kernel_watchdog_dump.txt:
      the kernel died three times on 2026-09-28 (6:36, 9:06, 15:25) with a
      0xc0000005 access violation in python312.dll (same offset 0x2877d0)
      during a live download race; the timeout watchdog could not capture
      the faulting stack, the crash guard can.

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] Body moved to core/kernel.py (AmuleDKernel); this file is a CLI shim.
"""

from __future__ import annotations

import argparse
import faulthandler
import sys
from pathlib import Path

from amuled_v2.core.kernel import run_kernel


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AmuleD v0.6.0 unified kernel: spider + listener + IPC."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single KAD source-publish pass and exit (no listener).",
    )
    parser.add_argument(
        "--publish-timeout",
        type=float,
        default=25.0,
        help="Lookup window per file during the publish pass (seconds).",
    )
    parser.add_argument(
        "--publish-limit",
        type=int,
        default=0,
        help="Max shared files per publish pass (0 = config value).",
    )
    parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Disable the KAD source republication loop entirely.",
    )
    parser.add_argument(
        "--no-spider",
        action="store_true",
        help="Disable the in-process KAD spider maturation loop.",
    )
    # Crash guard + watchdog policy (revised 2026-09-28, see v0.3.2 notes):
    # faulthandler.enable() catches REAL fatal faults (access violations)
    # synchronously on the faulting thread - safe.  dump_traceback_later()
    # is BANNED: its watchdog thread walks other threads' stacks without
    # pausing them, and reading a frame list that the owning thread is
    # concurrently freeing crashed the process with 0xc0000005 inside
    # _Py_DumpTraceback (python312.dll+0x2877d0) - crashes 6:36 / 9:06 /
    # 15:25 on 2026-09-28 all landed on that exact offset.  Liveness is
    # now monitored OUTSIDE the process via the kernel_status.json
    # heartbeat (AmuleD_Run.ps1 serve).
    _watchdog = Path("logs") / "kernel_watchdog_dump.txt"
    _watchdog.parent.mkdir(exist_ok=True)
    _watchdog_fh = open(_watchdog, "a", buffering=1)
    faulthandler.enable(file=_watchdog_fh, all_threads=True)
    return run_kernel(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
