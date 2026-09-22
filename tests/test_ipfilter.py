"""Offline tests for IP filtering and server blacklisting.

Pure parser and policy checks; no network, no fake servers.

tests/test_ipfilter.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested eMule ipfilter.dat range, single, and CIDR forms.
  [+] Tested level-threshold matching and malformed-line skipping.
  [+] Tested server failure counting, blacklist cooldown, and selection.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from amuled_v2.core.ipfilter import (
    DEFAULT_FILTER_LEVEL,
    IpFilter,
    load_ipfilter_file,
)
from amuled_v2.core.server_filter import ServerFilter


@pytest.fixture()
def filter_file(tmp_path: Path) -> Path:
    target = tmp_path / "ipfilter.dat"
    target.write_text(
        "\n".join(
            [
                "# comment line",
                "",
                "010.000.000.000 - 010.255.255.255 , 200 , bogus net",
                "192.168.1.1 , 100 , single host",
                "203.0.113.0/24 , 255 , cidr block",
                "999.1.1.1 - 2.2.2.2 , 255 , malformed line",
            ]
        ),
        encoding="utf-8",
    )
    return target


def test_ipfilter_parses_all_forms(filter_file: Path) -> None:
    ip_filter = load_ipfilter_file(filter_file)
    assert len(ip_filter) == 3  # the malformed line is skipped

    bogus = ip_filter.match("10.1.2.3")
    assert bogus is not None and bogus.level == 200
    single = ip_filter.match("192.168.1.1")
    assert single is not None and single.level == 100
    cidr = ip_filter.match("203.0.113.77")
    assert cidr is not None and cidr.level == 255
    assert ip_filter.match("8.8.8.8") is None


def test_ipfilter_threshold(filter_file: Path) -> None:
    ip_filter = load_ipfilter_file(filter_file)
    assert ip_filter.is_filtered("10.1.2.3") is True          # 200 >= 127
    assert ip_filter.is_filtered("192.168.1.1") is False      # 100 < 127
    assert ip_filter.is_filtered("192.168.1.1", level_threshold=100) is True
    assert ip_filter.is_filtered("203.0.113.1") is True       # 255 >= 127
    assert ip_filter.is_filtered("8.8.8.8") is False


def test_ipfilter_rejects_invalid_range(tmp_path: Path) -> None:
    from amuled_v2.core.ipfilter import IpFilterError, _parse_line

    with pytest.raises(IpFilterError):
        _parse_line("10.0.0.5 - 10.0.0.1 , 255 , inverted")


def test_server_filter_blacklists_after_threshold() -> None:
    server_filter = ServerFilter(failure_threshold=3, cooldown_seconds=60)
    assert server_filter.report_failure("10.0.0.1", 4661) is False
    assert server_filter.report_failure("10.0.0.1", 4661) is False
    assert server_filter.report_failure("10.0.0.1", 4661) is True
    assert server_filter.is_blacklisted("10.0.0.1", 4661) is True

    verdict = server_filter.evaluate("10.0.0.1", 4661)
    assert verdict.allowed is False
    assert "blacklisted" in verdict.reason

    server_filter.report_success("10.0.0.1", 4661)
    assert server_filter.is_blacklisted("10.0.0.1", 4661) is False


def test_server_filter_cooldown_expires() -> None:
    server_filter = ServerFilter(failure_threshold=1, cooldown_seconds=0.05)
    assert server_filter.report_failure("10.0.0.2", 4661) is True
    assert server_filter.is_blacklisted("10.0.0.2", 4661) is True
    time.sleep(0.06)
    assert server_filter.is_blacklisted("10.0.0.2", 4661) is False


def test_server_filter_applies_ipfilter(filter_file: Path) -> None:
    ip_filter = load_ipfilter_file(filter_file)
    server_filter = ServerFilter(ip_filter=ip_filter)
    allowed = server_filter.evaluate("176.123.5.89", 4725)
    assert allowed.allowed is True
    rejected = server_filter.evaluate("10.1.2.3", 4661)
    assert rejected.allowed is False
    assert "ipfilter" in rejected.reason


def test_server_filter_select_orders_allowed_first() -> None:
    server_filter = ServerFilter(failure_threshold=1)
    server_filter.report_failure("10.0.0.9", 4661)
    verdicts = server_filter.select_servers(
        [("10.0.0.9", 4661), ("176.123.5.89", 4725)]
    )
    assert verdicts[0].host == "176.123.5.89"
    assert verdicts[1].allowed is False


def test_server_filter_statistics() -> None:
    server_filter = ServerFilter(ip_filter=IpFilter())
    server_filter.report_failure("10.0.0.3", 4661)
    stats = server_filter.statistics()
    assert stats["tracked_servers"] == 1
    assert stats["blacklisted_servers"] == 0
    assert stats["ipfilter_ranges"] == 0
