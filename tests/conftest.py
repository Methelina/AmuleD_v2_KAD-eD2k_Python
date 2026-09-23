"""Shared pytest configuration.

Redirects pytest temporary directories (tmp_path / pytest-of-*) away from
the system drive: download-queue tests create real-sized *.part files and
must never land on C:.

tests/conftest.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Redirected pytest temp base to the project cache drive.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_PROJECT_TMP = Path(__file__).resolve().parents[1] / ".cache" / "tmp"
_PROJECT_TMP.mkdir(parents=True, exist_ok=True)

os.environ["TMP"] = str(_PROJECT_TMP)
os.environ["TEMP"] = str(_PROJECT_TMP)
os.environ["TMPDIR"] = str(_PROJECT_TMP)
tempfile.tempdir = str(_PROJECT_TMP)
