"""Local client identity: the single source of userhash/nick/TCP port.

Stage S unifies the handshake identity across KAD publish and the incoming
peer listener.  In eMule the same 16-byte userhash backs both the ED2K
HELLO and the Kademlia source publish
(``CKademlia::GetPrefs()->GetClientHash()`` returns ``GetUserHash()``,
Prefs.cpp:84/279-297); the standalone client follows that model with one
identity stored in the config.

The identity section of ``config/amuled.jsonc``::

    "identity": {
        "user_hash": null,     # 32 hex chars; generated+persisted if null
        "nick": "AmuleD",
        "tcp_port": 0,         # 0 = ephemeral (serve daemon advertises the
                               # actual bound port in KAD source entries)
        "client_id": 0         # 0 = unknown/HighID unresolved (standalone)
    }

src/amuled_v2/core/identity.py
Version:     0.1.0
Author:      Soror L'.L'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added AppIdentity dataclass (user_hash/nick/tcp_port/client_id).
  [+] Added load_identity() reading config, generating and persisting a new
      random userhash on first use (mirrors eMule preferences.dat behavior).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from amuled_v2.config import load_config, save_config
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.APP, "core.identity")

__all__ = [
    "AppIdentity",
    "IdentityError",
    "load_identity",
]


class IdentityError(RuntimeError):
    """Raised on malformed identity configuration."""


@dataclass(frozen=True)
class AppIdentity:
    """The local client's identity shared by KAD publish and the listener."""

    user_hash: bytes
    nickname: str
    tcp_port: int = 0
    client_id: int = 0

    def __post_init__(self) -> None:
        if len(self.user_hash) != 16:
            raise IdentityError(
                f"user_hash must be exactly 16 bytes, got {len(self.user_hash)}"
            )
        if not self.nickname:
            raise IdentityError("nickname must be a non-empty string")
        if not 0 <= self.tcp_port <= 0xFFFF:
            raise IdentityError(f"tcp_port out of UInt16 range: {self.tcp_port}")
        if not 0 <= self.client_id <= 0xFFFFFFFF:
            raise IdentityError(f"client_id out of UInt32 range: {self.client_id}")

    def to_local_identity(self, *, tcp_port: int | None = None) -> "Any":
        """Build the listener's ``LocalIdentity`` for the HELLOANSWER.

        ``tcp_port`` overrides the configured port; the serve daemon passes
        the actually bound port so the answer matches the advertised one.
        """
        from amuled_v2.core.peer.listener import LocalIdentity

        return LocalIdentity(
            user_hash=self.user_hash,
            client_id=self.client_id,
            tcp_port=self.tcp_port if tcp_port is None else tcp_port,
            nickname=self.nickname,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_hash": self.user_hash.hex().upper(),
            "nick": self.nickname,
            "tcp_port": self.tcp_port,
            "client_id": self.client_id,
        }


def _parse_user_hash(raw: Any) -> bytes | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise IdentityError(f"identity.user_hash must be a hex string, got {raw!r}")
    cleaned = raw.strip()
    if len(cleaned) != 32:
        raise IdentityError(
            f"identity.user_hash must be 32 hex digits, got {len(cleaned)}"
        )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise IdentityError(f"identity.user_hash is not hex: {raw!r}") from exc


def load_identity() -> AppIdentity:
    """Load the identity from config, generating+persisting the userhash.

    A missing/empty ``identity.user_hash`` produces a fresh random 16-byte
    hash that is immediately written back to the config file, so the
    identity is stable across restarts (eMule keeps it in preferences.dat).
    """
    cfg = load_config()
    section = cfg.get("identity") or {}
    user_hash = _parse_user_hash(section.get("user_hash"))
    if user_hash is None:
        user_hash = os.urandom(16)
        cfg.setdefault("identity", {})["user_hash"] = user_hash.hex().upper()
        save_config(cfg)
        log.info(
            "identity: generated new user_hash and persisted it to config"
        )
    nick = section.get("nick") or "AmuleD"
    tcp_port = int(section.get("tcp_port") or 0)
    client_id = int(section.get("client_id") or 0)
    identity = AppIdentity(
        user_hash=user_hash,
        nickname=str(nick),
        tcp_port=tcp_port,
        client_id=client_id,
    )
    log.info(
        "identity: loaded nick=%s tcp_port=%d client_id=%d",
        identity.nickname,
        identity.tcp_port,
        identity.client_id,
    )
    return identity
