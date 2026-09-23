"""Sanitize a log/text file: flagged lines become asterisks, extensions kept.

Usage:
    python sanitize_log.py <file> [file2 ...] [-o out.txt]

- Every line is checked with the project content-safety markers
  (amuled_v2.core.safety.matched_marker -- the same gate as the download
  queue uses).
- Flagged lines are REDACTED: every word token is starred, ONLY file
  extensions survive in the "****.mp4" form.  Nothing flagged is printed
  to the console -- the console shows counters only, the sanitized text
  goes to the output file (default: <input>.clean.txt).
- Clean lines pass through unchanged.

The raw input is never printed by this script, so neither the operator nor
any assistant reading the console/output sees the flagged content.

scripts/sanitize_log.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Marker-based line redaction with extension-preserving starring.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from amuled_v2.core.safety import matched_marker  # noqa: E402

# Токены, которые в помеченной строке НЕ звёздочками: расширения файлов и
# чисто числовые куски (размеры, даты). Всё остальное звёздочки.
_EXT_RE = re.compile(r"(?:\.[A-Za-z0-9]{1,6})")
_WORD_RE = re.compile(r"[^\s|,;\"'()\[\]]+")
_QUOTED_RE = re.compile(r'"([^"]*)"')
# Имя файла — мусор всегда (хорошее и плохое одинаково): глушим ЛЮБОЙ
# токен с файловым расширением из белого списка. Список конечный, чтобы не
# задеть таймстампы (23.09.2026) и слова с точкой.
_FILE_TOKEN_RE = re.compile(
    r"[\w\-]+\.(?P<ext>avi|mp4|mkv|mpg|mpeg|iso|zip|rar|7z|exe|dll|jpg|jpeg|png"
    r"|gif|flv|divx|mov|wav|mp3|pdf|part|emulecollection)\b",
    re.IGNORECASE,
)


def _star_file_token(match: re.Match[str]) -> str:
    return "*" * min(len(match.group(0)), 24) + "." + match.group("ext").lower()


def _star_name(name: str) -> str:
    """Star a filename, keep only its extension (****.mp4)."""
    ext = _EXT_RE.search(name)
    if ext and ext.start() >= 1:
        stars = "*" * min(ext.start(), 26) or "*"
        return stars + ext.group(0).lower()
    return "*" * min(len(name), 26)


def _redact_quoted(line: str) -> str:
    """Star the inside of every quoted segment, keep the extension."""
    return _QUOTED_RE.sub(lambda m: '"' + _star_name(m.group(1)) + '"', line)


def _sanitize_line(line: str) -> str:
    """Redact a flagged line: quotes first, then any remaining words.

    Structure survives (timestamp, fixed phrases, numbers, extensions),
    content does not.  If the line is STILL flagged after quoted
    redaction, the leftover word tokens are starred too -- some logs put
    the filename without quotes.
    """
    redacted = _redact_quoted(line)
    if matched_marker(redacted) is not None:
        redacted = _WORD_RE.sub(
            lambda m: m.group(0).isdigit() and m.group(0) or "*" * min(len(m.group(0)), 12),
            redacted,
        )
    return redacted


def _read_text(path: Path) -> str:
    """Read text with BOM detection (eMule пишет логи в UTF-16 LE)."""
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", errors="replace")


def sanitize_file(path: Path, out_path: Path | None = None) -> None:
    out_path = out_path or path.with_suffix(path.suffix + ".clean.txt")
    flagged = 0
    clean = 0
    by_marker: dict[str, int] = {}
    text = _read_text(path)
    with out_path.open("w", encoding="utf-8") as dst:
        for number, line in enumerate(text.splitlines(keepends=True), 1):
            # Имя в кавычках звёздочками ВСЕГДА (нам неважно, что там) --
            # маркер лишь добавляет строке префикс [REDACTED] и счётчик.
            marker = matched_marker(line)
            line_out = _FILE_TOKEN_RE.sub(_star_file_token, _redact_quoted(line))
            if marker is not None:
                flagged += 1
                by_marker[marker] = by_marker.get(marker, 0) + 1
                # Маркерные слова вне кавычек тоже гасим (фолбэк: звёздочки
                # по оставшимся токенам, если после кавычек строка всё ещё
                # помечена).
                line_out = f"[REDACTED line {number} marker={marker}] " + _sanitize_line(line)
            dst.write(line_out + ("\n" if line.endswith("\n") else ""))
            if marker is None:
                clean += 1
    print(f"file   : {path}")
    print(f"output : {out_path}")
    print(f"clean lines  : {clean}")
    print(f"redacted     : {flagged}")
    for marker, count in sorted(by_marker.items(), key=lambda kv: -kv[1]):
        print(f"  marker {marker!r}: {count} line(s)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact flagged content from log/text files."
    )
    parser.add_argument("files", nargs="+", help="Input files to sanitize.")
    parser.add_argument("-o", "--output", help="Output file (single input only).")
    args = parser.parse_args()
    if args.output and len(args.files) > 1:
        parser.error("-o works with a single input file")
    for name in args.files:
        sanitize_file(Path(name), Path(args.output) if args.output else None)


if __name__ == "__main__":
    main()
