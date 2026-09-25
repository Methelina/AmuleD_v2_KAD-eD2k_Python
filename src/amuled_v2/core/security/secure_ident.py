"""SecureIdent interface adapter (stage C skeleton; crypto is a mock).

eMule proves a client's userhash ownership with an RSA signature exchange
(``srchybrid/Security.cpp``: ``CSecureIdentState`` transitions,
``SRV_*``/``Cryptography::`` primitives).  AmuleD's credit ledger (stage C)
attributes traffic to userhashes WITHOUT cryptographic verification, exactly
like eMule treats unverified clients (the "bad guy has an advantage" model
of credits stays intact: verified hashes merely earn a bonus multiplier).

This module defines the integration surface only.  Every cryptographic
operation is a stub:

# WIP by external developer: RSA key generation, challenge signing and
# signature verification per Security.cpp / Cryptography.cpp are implemented
# in the external obfuscation/SecureIdent session.  See
# docs/Cloud_Prompt_Help_Plz.md.

src/amuled_v2/core/security/secure_ident.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added SecureIdentState (mirrors CSecureIdentState: IS_NOTAVAILABLE /
      IS_IDNEEDED / IS_SIGNED IDs) and SecureIdentProvider with
      sign/verify/has_keys stubs marked WIP by external developer.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SECURITY, "core.security.secure_ident")

__all__ = [
    "SecureIdentError",
    "SecureIdentState",
    "SecureIdentInfo",
    "SecureIdentProvider",
]


class SecureIdentError(RuntimeError):
    """Raised by SecureIdent operations that are not available yet."""


class SecureIdentState(enum.IntEnum):
    """Mirror of ``CSecureIdentState`` (Security.cpp:50-56)."""

    NOT_AVAILABLE = 0     # IS_NOTAVAILABLE: peer announced no SecureIdent
    ID_NEEDED = 1         # IS_IDNEEDED: we want the peer's public key
    SIGNED_ID = 2         # IS_SIGNED: peer presented a signed identification


@dataclass(frozen=True)
class SecureIdentInfo:
    """Verification result attributed to one userhash."""

    user_hash: str
    state: SecureIdentState
    verified: bool = False
    bonus_multiplier: float = 1.0   # eMule: verified clients earn >1.0
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_hash": self.user_hash,
            "state": self.state.name,
            "verified": self.verified,
            "bonus_multiplier": self.bonus_multiplier,
            "detail": self.detail,
        }


@dataclass
class SecureIdentProvider:
    """Integration surface for SecureIdent; cryptography is a mock.

    Callers (upload/download accounting, HELLO handling) use
    :meth:`evaluate` to learn whether a userhash may earn the verified
    bonus.  Until the external session lands the RSA machinery, every
    signature operation raises :class:`SecureIdentError` and ``evaluate``
    reports ``verified=False`` with ``bonus_multiplier=1.0`` — matching
    eMule's treatment of clients that never present a signed ID.
    """

    # WIP by external developer: private key material (Preferences.cpp
    # userhash-bound RSA keys) is generated and stored by the external
    # SecureIdent session; the stub intentionally holds no keys.
    _key_pair: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def has_keys(self) -> bool:
        """True once the external track provisions our signing keys."""
        return bool(self._key_pair)

    def sign(self, challenge: bytes) -> bytes:
        """Sign a SecureIdent challenge with our private key (stub)."""
        raise SecureIdentError(
            "SecureIdent signing is not implemented yet: "
            "WIP by external developer (Security.cpp RSA machinery)"
        )

    def verify(self, user_hash: str, signature: bytes, challenge: bytes) -> bool:
        """Verify a peer's SecureIdent signature (stub)."""
        raise SecureIdentError(
            "SecureIdent verification is not implemented yet: "
            "WIP by external developer (Security.cpp RSA machinery)"
        )

    def evaluate(self, user_hash: str) -> SecureIdentInfo:
        """Credit-model verdict for a userhash: unverified until proven.

        The signature verification path is the external track; today every
        client is treated as unverified (no bonus), which is safe: credits
        still accrue, they just never multiply.
        """
        info = SecureIdentInfo(
            user_hash=user_hash.strip().lower(),
            state=SecureIdentState.NOT_AVAILABLE,
            verified=False,
            bonus_multiplier=1.0,
            detail="secure ident pending external implementation",
        )
        log.debug(
            "secure ident evaluated: user_hash=%s, verified=False (mock)",
            info.user_hash,
        )
        return info
