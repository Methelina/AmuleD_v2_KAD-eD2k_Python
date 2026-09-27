"""Unit tests for the KAD spider stage-X rotation bookkeeping.

Covered here: the per-node ``fails`` counter survives the JSON cache
roundtrip (build_pool) so eviction state is not lost between restarts.

tests/test_kad_spider.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import json

from amuled_v2.core.kad.spider import build_pool, prune_pool


def test_fails_survive_cache_roundtrip(tmp_path) -> None:
    root = tmp_path
    (root / "db").mkdir(parents=True)
    cache = {
        "own_id": "AA" * 16,
        "nodes": {
            "80.1.2.3:4662": {
                "kad_id": "BB" * 16,
                "tcp": 4662,
                "ver": 8,
                "hellos": 3,
                "pings": 1,
                "fails": 2,
                "last_seen": 1_700_000_000.0,
                "udp_key": "",
            },
            "81.4.5.6:4711": {
                "kad_id": "CC" * 16,
                "tcp": 4711,
                "ver": 8,
                "hellos": 0,
                "pings": 0,
                "last_seen": 1_700_000_000.0,
            },
        },
    }
    (root / "db" / "kad_nodes.json").write_text(
        json.dumps(cache), encoding="utf-8"
    )
    pool = build_pool(root, cache)
    assert pool[("80.1.2.3", 4662)]["fails"] == 2
    assert pool[("81.4.5.6", 4711)]["fails"] == 0


def test_prune_pool_keeps_recent_nodes(tmp_path) -> None:
    import time

    root = tmp_path
    (root / "db").mkdir(parents=True)
    cache = {
        "own_id": "AA" * 16,
        "nodes": {
            "80.1.2.3:4662": {"last_seen": time.time(), "hellos": 1},
        },
    }
    (root / "db" / "kad_nodes.json").write_text(
        json.dumps(cache), encoding="utf-8"
    )
    pool = build_pool(root, cache)
    assert prune_pool(pool) == 0
    assert ("80.1.2.3", 4662) in pool
