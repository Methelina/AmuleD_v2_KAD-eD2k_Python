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
Version:     0.3.0
Author:      Soror L.'.L.'.
Updated:     2026-09-25

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] Body moved to core/kernel.py (AmuleDKernel); this file is a CLI shim.
"""

from __future__ import annotations

import argparse
import sys

from amuled_v2.core.kernel import run_kernel


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AmuleD v0.5.1 unified kernel: spider + listener + IPC."
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
    return run_kernel(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
