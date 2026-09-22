"""Minimal JSONC (JSON-with-comments) loader and dumper.

Strips ``//`` line comments and ``/* */`` block comments that appear outside
of JSON string literals, then delegates to the stdlib :mod:`json`.  If the
stdlib parser fails and :mod:`json5` is installed, falls back to
``json5.load`` for a more permissive parse.  Also provides a
:func:`dump_json` helper with deterministic key ordering and indentation.

src/amuled_v2/jsonc.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Comment-stripping JSONC loader with json5 fallback.
  [+] dump_json helper with sorted keys and indent=2.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

# ------------------------------------------------------------------
# Comment stripping
# ------------------------------------------------------------------

def strip_jsonc_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments outside of string literals.

    Walks the text character by character tracking whether we are inside a
    double-quoted string (with ``\\`` escape handling) and accumulates
    output with comments omitted.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        # Not in a string — detect comments.
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                # Line comment — skip to end of line.
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                # Block comment — skip to closing */.
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


# ------------------------------------------------------------------
# Loading
# ------------------------------------------------------------------

def load_jsonc(data: str) -> Any:
    """Parse a JSONC string into Python objects."""
    cleaned = strip_jsonc_comments(data)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore[import-untyped]
        except ImportError:
            raise
        return json5.loads(cleaned)


def load_jsonc_file(path: str | Path) -> Any:
    """Read and parse a JSONC file."""
    with open(path, "r", encoding="utf-8") as fh:
        return load_jsonc(fh.read())


# ------------------------------------------------------------------
# Dumping
# ------------------------------------------------------------------

def dump_json(
    obj: Any,
    path: str | Path | None = None,
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> str:
    """Serialize *obj* to a JSON string (or write to *path*).

    When *path* is provided the string is written there; otherwise it is
    returned.
    """
    text = json.dumps(obj, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
    if path is not None:
        buf = io.StringIO(text)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
    return text
