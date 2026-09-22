"""Entry-point for ``python -m amuled_v2``.

Delegates to :func:`amuled_v2.cli.main` so that the project can be launched
as a module from the project root after package installation or path setup.

src/amuled_v2/__main__.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Module entry point delegating to cli.main().
"""

from amuled_v2.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
