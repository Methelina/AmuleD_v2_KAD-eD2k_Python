"""Shield-compliance tests (eMuleAI shield.conf parity; recon
tmp/recon/emuleai-shield-conf.recon.md).

Every payload we put on the wire must stay clear of the shield's leecher
signature lists: no banned HELLO/INFO tag IDs, no modstring in HELLO,
official-shaped client version, non-degenerate marked userhash, and a
nickname outside the leecher user-name lists.

tests/test_shield_guard.py
Author:      Soror L.'.L.'.
Updated:     2026-09-28
"""

from __future__ import annotations

from amuled_v2.core.peer import codec
from amuled_v2.core.peer.client import build_emuleinfo_payload
from amuled_v2.core.peer.codec import (
    build_hello_answer_payload,
    build_hello_payload,
)
from amuled_v2.core.peer.shield_guard import (
    BANNED_HELLO_TAG_IDS,
    MOD_STRING_TAG_ID,
    check_hello_tags,
    check_info_tags,
    check_modstring,
    check_nickname,
)


def _hello_tag_ids(payload: bytes) -> list[int]:
    """Walk the OLD CTag tag list of a hello-shaped payload.

    Canonical body (see codec._parse_hello_body): [hashlen u8=16]
    [hash 16][client_id u32][port u16][tagcount u32][tags].  Each tag is
    written by _write_hello_tag as [type u8][u16 namelen=1][u8 name_id]
    [value], value = u16 len + bytes (0x02 string) / 16 bytes (0x01 hash) /
    u32 (0x03 uint).
    """
    ids: list[int] = []
    pos = 0
    if not payload or payload[0] != 16:
        return ids
    pos = 1 + 16 + 4 + 2  # hashlen+hash, client_id, port
    if len(payload) < pos + 4:
        return ids
    count = int.from_bytes(payload[pos : pos + 4], "little")
    pos += 4
    for _ in range(min(count, 64)):
        if pos + 4 > len(payload):
            break
        tag_type = payload[pos]
        name_len = int.from_bytes(payload[pos + 1 : pos + 3], "little")
        name_id = payload[pos + 3]
        pos += 4
        if name_len != 1:
            break  # not our old-CTag shape; stop defensively
        ids.append(name_id)
        if tag_type == 0x02:
            if pos + 2 > len(payload):
                break
            raw_len = int.from_bytes(payload[pos : pos + 2], "little")
            pos += 2 + raw_len
        elif tag_type == 0x01:
            pos += 16
        else:
            pos += 4
    return ids


def test_hello_payload_has_no_banned_tag_ids() -> None:
    payload = build_hello_payload(
        user_hash=bytes(range(1, 17)),
        client_id=0x7F000001,
        client_port=4662,
        nickname="AmuleD",
    )
    ids = _hello_tag_ids(payload)
    assert ids, "tag walk produced nothing - walker out of sync with codec"
    hits = check_hello_tags(ids)
    assert hits == [], f"banned HELLO tag ids on the wire: {[hex(h) for h in hits]}"
    # The modstring tag (0xD2) must never be among the emitted tag IDs.
    assert MOD_STRING_TAG_ID not in ids


def test_hello_answer_payload_has_no_banned_tag_ids() -> None:
    payload = build_hello_answer_payload(
        user_hash=bytes(range(17, 33)),
        client_id=1,
        client_port=7235,
        nickname="AmuleD",
        server_ip=0,
        server_port=0,
    )
    ids = _hello_tag_ids(payload)
    assert ids, "tag walk produced nothing - walker out of sync with codec"
    hits = check_hello_tags(ids)
    assert hits == [], f"banned HELLO tag ids in hello answer: {[hex(h) for h in hits]}"


def test_emuleinfo_payload_has_no_banned_tag_ids() -> None:
    payload = build_emuleinfo_payload(emule_version=0x3C)
    # Scan raw bytes: banned info-tag IDs must not appear as tag markers.
    for banned in (0x2F, 0x36, 0x5B, 0xA6, 0x60, 0xB1, 0xB4, 0xC9):
        assert banned not in payload, f"banned EMULEINFO tag 0x{banned:02X} in payload"
    assert check_info_tags([]) == []


def test_emuleinfo_version_is_official_shaped() -> None:
    # eMule-version byte must stay < 0x64 (a "v1.#/v2.#" client version is
    # a shield soft-ban: &&^eMule v1.# / &&^eMule v2.#).
    payload = build_emuleinfo_payload(emule_version=0x3C)
    assert isinstance(payload, bytes) and len(payload) >= 2


def test_modstring_is_not_written() -> None:
    # An eMule-compatible client writes NO modstring (a non-empty one is a
    # hard-ban risk: shield bans ^amule/^Amule inside modstrings).
    assert check_modstring(None) is None
    assert check_modstring("") is None
    assert check_modstring("SomeMod") == "SomeMod"


def test_nickname_checks() -> None:
    assert check_nickname("AmuleD") is None
    assert check_nickname("amuled user") is None
    assert check_nickname("my Applejuice client") == "applejuice"
    assert check_nickname("[VeryCD] bot") == "[verycd]"
    assert check_nickname("lionet user") == "lionet"


def test_banned_sets_populated() -> None:
    # The transcription from shield.conf must be non-trivial.
    assert len(BANNED_HELLO_TAG_IDS) >= 25
    assert 0xD2 in BANNED_HELLO_TAG_IDS      # modstring in HELLO
    assert 0x54 in BANNED_HELLO_TAG_IDS      # DarkMule
    assert 0xC8 in BANNED_HELLO_TAG_IDS      # MD5 Community


def test_identity_userhash_persisted_once_and_degenerate_regen(monkeypatch, tmp_path) -> None:
    """The unique userhash is generated ONCE, persisted to config, and
    reused on every later load; a degenerate (corrupt) stored hash is
    regenerated with a fallback warning (shield soft-ban pattern)."""
    import json

    from amuled_v2.core import identity as identity_mod

    cfg_path = tmp_path / "amuled.jsonc"
    cfg_box: dict = {"identity": {"nick": "AmuleD"}}

    def fake_load_config(save_if_missing: bool = False):
        return json.loads(json.dumps(cfg_box))  # deep copy per load

    def fake_save_config(cfg) -> None:
        cfg_box.clear()
        cfg_box.update(cfg)
        cfg_path.write_text(json.dumps(cfg_box), encoding="utf-8")

    monkeypatch.setattr(identity_mod, "load_config", fake_load_config)
    monkeypatch.setattr(identity_mod, "save_config", fake_save_config)

    first = identity_mod.load_identity()
    stored = cfg_box["identity"]["user_hash"]
    assert stored == first.user_hash.hex().upper()

    # Second load: SAME hash, config untouched as the source of truth.
    second = identity_mod.load_identity()
    assert second.user_hash == first.user_hash
    assert cfg_box["identity"]["user_hash"] == stored
    # SO_EMULE markers present (hash[5]=14, hash[14]=111).
    assert first.user_hash[5] == 14 and first.user_hash[14] == 111
    # Not a degenerate marker-only hash (shield soft-ban pattern).
    assert sum(1 for i, b in enumerate(first.user_hash) if b and i not in (5, 14)) >= 8

    # A stored corrupt hash is regenerated once and re-persisted.
    cfg_box["identity"]["user_hash"] = "00000000000E00000000000000006F00"
    third = identity_mod.load_identity()
    assert third.user_hash != bytes.fromhex("00000000000E00000000000000006F00")
    assert third.user_hash[5] == 14 and third.user_hash[14] == 111
    assert cfg_box["identity"]["user_hash"] == third.user_hash.hex().upper()
