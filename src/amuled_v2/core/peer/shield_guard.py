"""eMule-network shield-compliance guard (eMuleAI shield.conf parity).

Encodes the ban/punish triggers observed in a live eMuleAI 1.6.0
``config/shield.conf`` (recon: tmp/recon/emuleai-shield-conf.recon.md)
as checkable invariants for AmuleD's wire presentation:

- banned HELLO tag IDs (unknown-tag leecher signatures),
- banned EMULEINFO tag IDs,
- banned nickname substrings (hard/soft leecher user names),
- modstring rules (an eMule-compatible client must write NO modstring:
  ``^amule`` / ``^Amule`` inside a modstring is a HARD ban; the tag
  ET_MOD_STRING (0xD2) itself is blacklisted when it appears in HELLO).

Oracle: K:\Software\eMuleAI_v1.6.0_x64\config\shield.conf; punishment
model: BaseClient.cpp SetPunishment/Ban (:1415-1464, see
docs/recon/From_Cloude/Cloud_Prompt_Answer.md).

src/amuled_v2/core/peer/shield_guard.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Banned HELLO/EMULEINFO tag-ID sets transcribed from the live
      shield.conf (active entries only; commented-out entries excluded).
  [+] Banned nickname substring list (hard+soft leecher user names).
  [+] check_hello_tags / check_info_tags / check_nickname / check_modstring
      helpers returning the offending entries (callers log them).
"""

from __future__ import annotations

from typing import Iterable

__all__ = [
    "BANNED_HELLO_TAG_IDS",
    "BANNED_INFO_TAG_IDS",
    "BANNED_NICKNAME_SUBSTRINGS",
    "MOD_STRING_TAG_ID",
    "check_hello_tags",
    "check_info_tags",
    "check_nickname",
    "check_modstring",
]

# ---------------------------------------------------------------------------
# Unknown Hello Tags (shield.conf section 5, active entries).
# Several of these are hard-leecher signatures (DarkMule, MD5 Community,
# eMuleReactor, Chinese leechers); ANY hit feeds the leecher score.
# ---------------------------------------------------------------------------
BANNED_HELLO_TAG_IDS: frozenset[int] = frozenset(
    {
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17,  # DodgeBoards / eVorteX family
        0x22,                                # DarkMule v6 eVorteX
        0x54, 0x7A, 0xCA,                    # new DarkMule (CT_DARK / SNAFU)
        0x4D,                                # pimp my mule (00de) misuse
        0x5D, 0x6B, 0x6C, 0x74, 0x87,        # md4 family
        0x76, 0xCD,                          # donkey2002
        0x79,                                # Bionic
        0x83,                                # Fusspi
        0x87,                                # md4
        0x88, 0x8C,                          # LSD7c
        0x8D,                                # unknown leecher (client v60)
        0x94, 0xC4, 0xC8, 0xCE, 0xCF,        # MD5 Community / 00.de
        0x97, 0x98, 0x9C, 0xDA,              # eMuleReactor / Rumata
        0xD2,                                # ET_MOD_STRING in HELLO (wrong
                                             # packet; modstring belongs in
                                             # EMULEINFO only, and we write
                                             # none at all)
        0xEC,                                # SpeedMule
        0xF0, 0xF4,                          # eMuleReactor
    }
)

# ---------------------------------------------------------------------------
# Unknown Info Tags (shield.conf section 6, active entries).
# ---------------------------------------------------------------------------
BANNED_INFO_TAG_IDS: frozenset[int] = frozenset(
    {
        0x13, 0x14, 0x17,                    # DodgeBoards
        0x2F,                                # OMEGA v.07
        0x36, 0x5B, 0xA6,                    # eMule v0.26 Leecher
        0x50, 0xB1, 0xB4, 0xC8, 0xC9,        # Bionic
        0x60,                                # Hunter
        0x76,                                # DodgeBoards
        0xDA,                                # Rumata (rus)
    }
)

# ET_MOD_STRING — the modstring tag; legal ONLY inside EMULEINFO, and we
# write no modstring at all (an empty modstring renders as official).
MOD_STRING_TAG_ID = 0xD2

# ---------------------------------------------------------------------------
# Hard+Soft Leecher User Name substrings (shield.conf sections 3-4,
# active entries; case-insensitive substring match, as the shield does).
# ---------------------------------------------------------------------------
BANNED_NICKNAME_SUBSTRINGS: tuple[str, ...] = (
    "flashget",
    "ketamine",
    "tuotu",
    "kaggo.com",
    "applejuice",
    "wikinger",
    "rockforce",
    "rc-atlantis",
    "fireball",
    "sunpower",
    "razorback",
    "playmule",
    "edonkey2008",
    "torenkey",
    "rappi",
    "community",
    "[verycd]",
    "lionet",
    "l!onet",
    "li()net",
    "l!0net",
    "emuleech",
    "mkp2p",
    "titanmule",
    "titanesel.tk",
    "egomule",
    "-=egoist=-",
    "muli_checka",
    "00de.de",
    "unKnown poison",
    "futurezone-reloaded",
    "gate-to-darkness.com",
)


def check_hello_tags(tag_ids: Iterable[int]) -> list[int]:
    """Return the banned HELLO tag IDs found in ``tag_ids`` (empty = clean)."""
    return sorted(set(tag_ids) & BANNED_HELLO_TAG_IDS)


def check_info_tags(tag_ids: Iterable[int]) -> list[int]:
    """Return the banned EMULEINFO tag IDs found in ``tag_ids``."""
    return sorted(set(tag_ids) & BANNED_INFO_TAG_IDS)


def check_nickname(nickname: str) -> str | None:
    """First banned substring contained in ``nickname`` (None = clean).

    Match is case-insensitive, mirroring the shield's default matching
    (only ``^``-prefixed entries are case-sensitive; the aggressive ones
    are covered here for safety).
    """
    lowered = nickname.lower()
    for needle in BANNED_NICKNAME_SUBSTRINGS:
        if needle in lowered:
            return needle
    return None


def check_modstring(modstring: str | None) -> str | None:
    """None is the only fully safe modstring for an eMule-compatible client.

    An empty/None modstring returns None (clean).  Any text value is
    reported as an offending entry: ``^amule`` / ``^Amule`` in a modstring
    is a HARD ban and every other value risks a list hit somewhere in the
    ecosystem — AmuleD presents itself as an official-shaped client.
    """
    if not modstring:
        return None
    return modstring
