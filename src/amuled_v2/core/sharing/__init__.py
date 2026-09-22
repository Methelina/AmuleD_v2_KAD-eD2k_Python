"""AmuleD_v2 sharing package.

src/amuled_v2/core/sharing/__init__.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package marker for shared-file import, scanning, and link generation.
  [+] Re-exports the sharing persistence API.
"""

from .shared_files import (
    SharedFile,
    SharingError,
    generate_ed2k_link,
    load_shareddir_dat,
    load_shared_files_json,
    scan_shared_directories,
    scan_shared_directory,
)

__all__ = [
    "SharedFile",
    "SharingError",
    "generate_ed2k_link",
    "load_shareddir_dat",
    "load_shared_files_json",
    "scan_shared_directories",
    "scan_shared_directory",
]
