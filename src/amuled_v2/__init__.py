"""AmuleD_v2 — pure Python ED2K/Kademlia client.

AmuleD is a clean-room, cross-platform reimplementation of the ED2K and
Kademlia P2P protocols in pure Python 3.12.  This module exposes the public
display name, package version, and formatted version string.

src/amuled_v2/__init__.py
Version:     0.6.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.6.0 (Soror L.'.L'.):
  [+] Stage U phase 3: read-only CLI routed over kernel IPC; unified kernel
      owns DuckDB while spider/listener/republish keep running.

Patch Notes v0.5.1 (Soror L.'.L'.):
  [+] Added live ED2K search/source stack and explicit search channels.

Patch Notes v0.4.3 (Soror L.'.L'.):
  [+] Added direct CLI shared-file scanning and DuckDB maintenance commands.
  [+] Added optional tqdm progress reporting for ED2K hashing.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package root with __version__ = "0.1.0".
  [+] Synopsis block and package docstring.
"""

__app_name__ = "AmuleD"
__version__ = "0.6.0"
__version_string__ = f"{__app_name__} v{__version__}"

__all__ = ["__app_name__", "__version__", "__version_string__"]
