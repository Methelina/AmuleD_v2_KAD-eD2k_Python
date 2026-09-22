"""Tagged logging infrastructure for AmuleD_v2.

Every diagnostic message produced by the client carries a stable uppercase
module tag as its first token, for example ``[DOWNLOAD] Block stored``.  The
tag is also stored on the log record as ``amuled_tag`` so GUI windows and
offline scripts can split one stream into per-module views without parsing
message prose.

Console output remains parser-friendly:

    2026-09-22 22:55:35 | INFO | [CLI] Command completed

The default file output uses one JSON object per line, which keeps tags,
levels, logger names, timestamps, and messages directly machine-readable.

src/amuled_v2/logging_setup.py
Version:     0.3.2
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.3.2 (Soror L.'.L'.):
  [+] Added mandatory tagged logging infrastructure and stable module tags.
  [+] Added TaggedLogger with console and optional JSONL file output.
  [+] Added machine-readable ``amuled_tag`` on every diagnostic record.
  [*] Preserved optional Rich console rendering on stderr without making Rich
      required, keeping stdout reserved for command output.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial stdlib logging setup with optional Rich handler.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

try:
    from rich.logging import RichHandler  # type: ignore[import-untyped]
    _HAS_RICH = True
except ImportError:  # pragma: no cover - exercised when rich absent
    _HAS_RICH = False

__all__ = [
    "LogTags",
    "LogTags",
    "TaggedLogger",
    "configure_logging",
    "get_tagged_logger",
    "normalize_tag",
    "TAG_PATTERN",
]

TAG_PATTERN = re.compile(r"^[A-Z][A-Z0-9_-]{1,31}$")

_VALID_TAGS = {
    "APP",
    "CLI",
    "CONFIG",
    "STATE",
    "IMPORT",
    "SERVER",
    "KAD",
    "ED2K",
    "SEARCH",
    "DOWNLOAD",
    "UPLOAD",
    "PEER",
    "SHARE",
    "HASH",
    "CODEC",
    "SECURITY",
    "IPFILTER",
    "NAT",
    "DAEMON",
    "INSTALL",
    "RUNNER",
    "TEST",
}

# Kept as explicit documentation for contributors and future GUI filters.
KNOWN_TAGS = frozenset(_VALID_TAGS)


class LogTags:
    """Stable tags used by GUI windows and offline log splitters."""

    APP = "APP"
    CLI = "CLI"
    CONFIG = "CONFIG"
    STATE = "STATE"
    IMPORT = "IMPORT"
    SERVER = "SERVER"
    KAD = "KAD"
    ED2K = "ED2K"
    SEARCH = "SEARCH"
    DOWNLOAD = "DOWNLOAD"
    UPLOAD = "UPLOAD"
    PEER = "PEER"
    SHARE = "SHARE"
    HASH = "HASH"
    CODEC = "CODEC"
    SECURITY = "SECURITY"
    IPFILTER = "IPFILTER"
    NAT = "NAT"
    DAEMON = "DAEMON"
    INSTALL = "INSTALL"
    RUNNER = "RUNNER"
    TEST = "TEST"


def normalize_tag(tag: str) -> str:
    """Validate and return a stable uppercase logging tag."""
    normalized = tag.strip().upper()
    if normalized not in _VALID_TAGS:
        raise ValueError(
            f"unknown logging tag: {tag!r}; known tags: {', '.join(sorted(_VALID_TAGS))}"
        )
    if not TAG_PATTERN.fullmatch(normalized):
        raise ValueError(f"invalid logging tag format: {tag!r}")
    return normalized


class TaggedLogger:
    """Logger adapter that guarantees one stable module tag per message."""

    __slots__ = ("_logger", "tag")

    def __init__(self, logger: logging.Logger, tag: str) -> None:
        self._logger = logger
        self.tag = normalize_tag(tag)

    def _prepare(self, message: str) -> str:
        text = str(message)
        if text.startswith(f"[{self.tag}]"):
            return text
        return f"[{self.tag}] {text}"

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("amuled_tag", self.tag)
        self._logger.debug(self._prepare(message), *args, stacklevel=2, **kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("amuled_tag", self.tag)
        self._logger.info(self._prepare(message), *args, stacklevel=2, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("amuled_tag", self.tag)
        self._logger.warning(self._prepare(message), *args, stacklevel=2, **kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("amuled_tag", self.tag)
        self._logger.error(self._prepare(message), *args, stacklevel=2, **kwargs)

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("amuled_tag", self.tag)
        self._logger.critical(self._prepare(message), *args, stacklevel=2, **kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("exc_info", True)
        self.error(message, *args, **kwargs)


class _TagFilter(logging.Filter):
    """Attach the module tag from the message to the record."""

    def filter(self, record: logging.LogRecord) -> bool:
        match = re.match(r"^\[([A-Z][A-Z0-9_-]{1,31})\]", record.getMessage())
        record.amuled_tag = match.group(1) if match else "APP"
        return True


class _PlainFormatter(logging.Formatter):
    """Single-line console format optimized for grep and GUI filters."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        return f"{timestamp} | {record.levelname} | {record.getMessage()}"


class _JsonlFormatter(logging.Formatter):
    """One JSON object per line for offline log processing."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "tag": getattr(record, "amuled_tag", "APP"),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def configure_logging(
    level: str = "INFO",
    *,
    log_file: str | Path | None = None,
) -> None:
    """Configure the project logger with console and optional JSONL file output.

    The function is idempotent: existing ``amuled_v2`` handlers are replaced on
    every call.  Rich is used for console rendering when installed, but all
    messages remain plain tagged text.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("amuled_v2")
    logger.setLevel(numeric_level)
    logger.propagate = False

    for old_handler in list(logger.handlers):
        logger.removeHandler(old_handler)

    tag_filter = _TagFilter()
    if _HAS_RICH:
        from rich.console import Console

        console: logging.Handler = RichHandler(
            console=Console(file=sys.stderr, stderr=True),
            show_time=False,
            show_level=False,
            show_path=False,
            markup=False,
            rich_tracebacks=True,
        )
        console.setFormatter(_PlainFormatter())
    else:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(_PlainFormatter())
    console.addFilter(tag_filter)
    console.setLevel(numeric_level)
    logger.addHandler(console)

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8", mode="a")
        file_handler.setFormatter(_JsonlFormatter())
        file_handler.addFilter(tag_filter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)


def get_tagged_logger(tag: str, child: str | None = None) -> TaggedLogger:
    """Return a project logger bound to *tag*."""
    name = "amuled_v2"
    if child:
        name = f"{name}.{child}"
    return TaggedLogger(logging.getLogger(name), tag)
