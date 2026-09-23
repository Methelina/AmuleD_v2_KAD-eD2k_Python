"""Tests for the mandatory content-safety gate (core/safety.py).

tests/test_safety.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Marker matching and age+context pattern coverage.
"""

from __future__ import annotations

import pytest

from amuled_v2.core.safety import ContentPolicyError, check_name_safe


def test_strong_markers_blocked() -> None:
    for name in (
        "some (pthc) collection.avi",
        "Pedo video.mp4",
        "HussyFan clip.avi",
        "LS-Magazine set.jpg",
        "child porn movie.avi",
    ):
        with pytest.raises(ContentPolicyError):
            check_name_safe(name)


def test_age_plus_context_blocked() -> None:
    with pytest.raises(ContentPolicyError):
        check_name_safe("video with 10yo girl sex.avi")
    with pytest.raises(ContentPolicyError):
        check_name_safe("clip 12 y.o. nude.mkv")


def test_benign_names_pass() -> None:
    for name in (
        "Ubuntu 25.10 desktop amd64.iso",
        "The Godfather 1972.mkv",
        "Lolita (1962) Kubrick.avi",  # «lolita» без сексуального контекста
        "Queen - Freddie Mercury Video Collection.avi",
    ):
        check_name_safe(name)  # не должно поднимать исключений
