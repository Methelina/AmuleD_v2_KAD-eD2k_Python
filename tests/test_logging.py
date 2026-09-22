"""Tests for the tagged logging doctrine.

Verifies stable module tags, parser-friendly console formatting, machine-readable
JSONL file output, and rejection of unknown tags.  These tests isolate logging
handlers from the real project log file.

tests/test_logging.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested tag normalization, tagged formatting, record tagging, and unknown
      tag rejection.
  [+] Tested console and JSONL formatters with the stable ``[TAG]`` contract.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from amuled_v2.logging_setup import (
    KNOWN_TAGS,
    LogTags,
    _JsonlFormatter,
    _PlainFormatter,
    _TagFilter,
    configure_logging,
    get_tagged_logger,
    normalize_tag,
)


def test_known_tags_include_future_gui_views() -> None:
    expected = {
        "APP", "CLI", "CONFIG", "STATE", "IMPORT", "SERVER", "KAD", "ED2K",
        "SEARCH", "DOWNLOAD", "UPLOAD", "PEER", "SHARE", "HASH", "CODEC",
        "SECURITY", "IPFILTER", "NAT", "DAEMON", "INSTALL", "RUNNER", "TEST",
    }
    assert expected == set(KNOWN_TAGS)
    assert LogTags.DOWNLOAD in KNOWN_TAGS


@pytest.mark.parametrize("tag", ["CLI", "download", " Kad "])
def test_normalize_tag_is_case_insensitive(tag: str) -> None:
    assert normalize_tag(tag) == tag.strip().upper()


def test_normalize_tag_rejects_unknown_and_malformed_tags() -> None:
    with pytest.raises(ValueError):
        normalize_tag("NOT_A_TAG")
    with pytest.raises(ValueError):
        normalize_tag("[BAD")


def test_tagged_logger_prepends_exactly_one_tag() -> None:
    logger = logging.getLogger("amuled_v2.test.tagged")
    logger.setLevel(logging.DEBUG)
    records: list[logging.LogRecord] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger.addHandler(Collector())
    tagged = get_tagged_logger(LogTags.DOWNLOAD, "test.tagged")
    tagged._logger = logger
    tagged.debug("Block stored: index=%d", 7)
    tagged.info("[DOWNLOAD] Already tagged")

    assert records[0].getMessage() == "[DOWNLOAD] Block stored: index=7"
    assert records[0].amuled_tag == "DOWNLOAD"
    assert records[1].getMessage() == "[DOWNLOAD] Already tagged"
    assert records[1].amuled_tag == "DOWNLOAD"
    assert len(records) == 2


def test_tag_filter_and_plain_formatter_are_parser_friendly() -> None:
    record = logging.LogRecord(
        name="amuled_v2.cli",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="[CLI] Command completed",
        args=(),
        exc_info=None,
    )
    assert _TagFilter().filter(record) is True
    assert record.amuled_tag == "CLI"

    line = _PlainFormatter().format(record)
    assert line.endswith("| INFO | [CLI] Command completed")
    assert line.count("[CLI]") == 1


def test_jsonl_formatter_writes_machine_readable_tag() -> None:
    record = logging.LogRecord(
        name="amuled_v2.download",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="[DOWNLOAD] Source timeout",
        args=(),
        exc_info=None,
    )
    _TagFilter().filter(record)
    payload = json.loads(_JsonlFormatter().format(record))
    assert payload == {
        "timestamp": payload["timestamp"],
        "level": "WARNING",
        "tag": "DOWNLOAD",
        "logger": "amuled_v2.download",
        "message": "[DOWNLOAD] Source timeout",
    }


def test_configure_logging_writes_tagged_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "diagnostics.jsonl"
    configure_logging("DEBUG", log_file=log_path)
    logger = get_tagged_logger(LogTags.IMPORT, "test.configure")
    logger.info("Import completed: files=%d", 3)

    logging.shutdown()
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["tag"] == "IMPORT"
    assert payload["message"] == "[IMPORT] Import completed: files=3"
