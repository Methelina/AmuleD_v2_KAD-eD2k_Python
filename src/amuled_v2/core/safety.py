"""Mandatory content-safety gate for the download queue.

ContentPolicyError is raised BEFORE a file enters the download queue when
its name matches child-safety markers.  The gate is intentionally
non-configurable and non-disableable: KAD/server searches surface such
content on their own (poisoned results, random collections), and the only
reliable protection is refusing the transfer at queue-add time.

The marker list uses STRONG indicators only (no borderline single words on
their own -- e.g. "lolita" alone is a legitimate novel name) to keep false
positives near zero while catching the real thing.  Extend the list ONLY
with equally unambiguous markers.

src/amuled_v2/core/safety.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Mandatory CSAM name gate for download queue additions.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from amuled_v2.logging_setup import LogTags, get_tagged_logger

__all__ = ["ContentPolicyError", "check_name_safe", "matched_marker"]

log = get_tagged_logger(LogTags.SECURITY, "core.safety")

# Однозначные маркеры CSAM (нижний регистр, проверяются подстрокой).
_MARKER_TERMS: Tuple[str, ...] = (
    "pthc",
    "pedo",
    "hussyfan",
    "hussy-fan",
    "baby-j",
    "babyj",
    "kidzilla",
    "ptsc",
    "ls-model",
    "ls-models",
    "ls-magazine",
    "ls magazine",
    "candydoll",
    "vichatter",
    "webeweb",
    "child porn",
    "childporn",
    "child sex",
    "kdv rbv",
    "everlovin",
    "goldensunern",
    "gay preteen",
    "preteen gay",
    "preteen sex",
    "preteen porn",
    "preteen nude",
    "preteen fuck",
)

# Число + "yo" в связке с сексуальным маркером: "10yo ... sex" и т.п.
_AGE_PATTERN = re.compile(
    r"\b\d{1,2}\s*(?:y\.?\s*/?\s*o\.?\b|years?\s*old)\b", re.IGNORECASE
)
_SEX_PATTERN = re.compile(
    r"\b(?:sex|porn|porno|xxx|nude|naked|fuck|hardcore|erotic|teen)\b",
    re.IGNORECASE,
)


class ContentPolicyError(Exception):
    """Raised when a file name matches child-safety markers."""

    def __init__(self, name: str, marker: str) -> None:
        self.name = name
        self.marker = marker
        super().__init__(
            f"download blocked by content policy: matched marker {marker!r}"
        )


def matched_marker(name: str) -> Optional[str]:
    """Return the first matching marker for *name*, or None if safe."""
    lowered = name.lower()
    for marker in _MARKER_TERMS:
        if marker in lowered:
            return marker
    if _AGE_PATTERN.search(lowered) and _SEX_PATTERN.search(lowered):
        return "age+sexual-context pattern"
    return None


def check_name_safe(name: str) -> None:
    """Raise ContentPolicyError when *name* matches safety markers.

    Called before any download queue insertion.  Never returns a value;
    safe names simply pass through.  The decision is logged at WARNING so
    every blocked attempt is visible in the JSONL diagnostics.
    """
    marker = matched_marker(name)
    if marker is not None:
        log.warning(
            "content policy block: marker=%r, name=%.80r", marker, name
        )
        raise ContentPolicyError(name, marker)
