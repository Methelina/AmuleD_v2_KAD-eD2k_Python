"""SecureIdent (SUI) — real RSA implementation (stage X).

Implements the eMule SecureIdent machinery per ClientCredits.cpp /
BaseClient.cpp:

- RSA 384-bit key pair (RSAKEYSIZE, Opcodes.h:154), stored Base64-encoded
  as PKCS#1 DER in ``cryptkey.dat`` (CryptoPP ``InvertibleRSAFunction::
  DEREncode`` compatible — the exact eMule on-disk format);
- public key blob = PKCS#1 RSAPublicKey DER (CryptoPP ``Save``), fits the
  80-byte ``MAXPUBKEYSIZE`` wire limit (a 384-bit blob is ~58 bytes);
- signature = RSASSA-PKCS1-v1_5/SHA-1 over
  ``[peer pubkey blob][challenge u32 LE][optional v2 IP block]`` — the
  construction of ``CreateSignature``/``VerifyIdent``, 48 bytes for a
  384-bit modulus;
- PyCryptodome (already a project dependency) via ``RSA.construct`` —
  ``RSA.generate`` refuses < 1024 bits, but construction from components
  works at 384, and ``pkcs1_15`` accepts a 48-byte modulus for SHA-1.

src/amuled_v2/core/security/secure_ident.py
Version:     0.3.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.3.0 (Soror L.'.L'.):
  [*] Key generation/signing switched to PyCryptodome (RSA.construct +
      pkcs1_15): getPrime for the two 192-bit primes, library DER
      (export_key pkcs=1) for cryptkey.dat, battle-tested padding.

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Real RSA SUI core (replaces the v0.1.0 mock): 384-bit key pair in
      the exact eMule cryptkey.dat format, sign/verify per
      ClientCredits.cpp CreateSignature/VerifyIdent (SHA-1, v1/v2 IP
      block), evaluate() with a verified bonus of 2.0.
"""

from __future__ import annotations

import base64
import enum
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import getPrime

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SECURITY, "core.security.secure_ident")

__all__ = [
    "SecureIdentError",
    "SecureIdentState",
    "SecureIdentInfo",
    "SecureIdentProvider",
    "CRYPT_CIP_REMOTECLIENT",
    "CRYPT_CIP_LOCALCLIENT",
    "CRYPT_CIP_NONECLIENT",
]

RSA_KEY_BITS = 384          # RSAKEYSIZE, Opcodes.h:154
MAX_PUBKEY_SIZE = 80        # MAXPUBKEYSIZE, ClientCredits.h:23
E = 65537
CRYPT_CIP_REMOTECLIENT = 10
CRYPT_CIP_LOCALCLIENT = 20
CRYPT_CIP_NONECLIENT = 30


class SecureIdentError(RuntimeError):
    """Raised by SecureIdent operations on key/format/verification errors."""


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


# ---------------------------------------------------------------------------
# Minimal DER (PKCS#1) writers — the public blob must be a raw
# RSAPublicKey SEQUENCE {n, e} (CryptoPP Save format); PyCryptodome would
# emit a SubjectPublicKeyInfo wrapper instead, so the two INTEGERs are
# written here.
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def _der_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:           # positive integers need a leading zero
            body = b"\x00" + body
    return bytes((0x02,)) + _der_len(len(body)) + body


def _der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return bytes((0x30,)) + _der_len(len(body)) + body


def _generate_key(bits: int) -> Any:
    """Fresh RSA private key.

    PyCryptodome's ``RSA.generate`` refuses < 1024 bits, so the 384-bit
    key is built from components instead (eMule's RSAKEYSIZE is 384).
    """
    e = E
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return RSA.construct((n, e, d, p, q), consistency_check=True)


def _public_blob(key: Any) -> bytes:
    """Raw PKCS#1 RSAPublicKey DER (CryptoPP Save format, NOT SPKI)."""
    return _der_seq(_der_int(key.n), _der_int(key.e))


def _sign_data(key: Any, data: bytes) -> bytes:
    return pkcs1_15.new(key).sign(SHA1.new(data))


def _verify_data(pubkey_blob: bytes, signature: bytes, data: bytes) -> bool:
    if not 10 <= len(pubkey_blob) <= MAX_PUBKEY_SIZE:
        return False
    try:
        pub = RSA.import_key(pubkey_blob)
    except (ValueError, IndexError, TypeError):
        return False
    try:
        pkcs1_15.new(pub).verify(SHA1.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


@dataclass
class SecureIdentProvider:
    """RSA signing/verification core for the SecureIdent protocol.

    - ``ensure_keys`` loads ``cryptkey.dat`` (Base64 PKCS#1 DER) or
      generates a fresh 384-bit pair on first run — ClientCredits.cpp
      ``InitalizeCrypting``/``CreateKeyPair``.
    - ``public_blob`` is the wire blob (PKCS#1 RSAPublicKey DER,
      <= ``MAX_PUBKEY_SIZE``).
    - ``create_signature(pubkey_blob, challenge, ip_kind, ip_bytes)``
      mirrors ``CreateSignature``: signs
      ``[peer pubkey][challenge u32 LE][optional IP block]`` with
      RSASSA-PKCS1-v1_5/SHA-1.
    - ``verify_signature`` mirrors ``VerifyIdent``: recomputes the same
      construction against the CLAIMED pubkey blob and compares.
    """

    key_path: Path
    key_bits: int = RSA_KEY_BITS
    _key: Any = field(default=None, repr=False, compare=False)
    _public_blob: bytes = field(default=b"", repr=False, compare=False)
    _verified: dict[str, bool] = field(default_factory=dict, repr=False)

    # -- key material ----------------------------------------------------

    @property
    def has_keys(self) -> bool:
        return self._key is not None

    @property
    def public_blob(self) -> bytes:
        if self._key is None:
            raise SecureIdentError("SecureIdent keys are not initialized")
        return self._public_blob

    def ensure_keys(self) -> None:
        """Load cryptkey.dat or generate a new pair (InitalizeCrypting)."""
        if self._key is not None:
            return
        if self.key_path.exists():
            try:
                der = base64.b64decode(self.key_path.read_bytes())
                self._key = RSA.import_key(der)
            except Exception as exc:
                # ClientCredits.cpp: load failure -> regenerate.
                log.warning(
                    "cryptkey.dat unreadable, regenerating: path=%s, error=%s",
                    self.key_path, exc,
                )
        if self._key is None:
            self._key = _generate_key(self.key_bits)
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            der = self._key.export_key(format="DER", pkcs=1)
            self.key_path.write_bytes(base64.b64encode(der))
            log.info(
                "SecureIdent key pair generated: path=%s, bits=%d",
                self.key_path, self.key_bits,
            )
        self._public_blob = _public_blob(self._key)
        if len(self._public_blob) > MAX_PUBKEY_SIZE:
            raise SecureIdentError(
                f"public key blob exceeds {MAX_PUBKEY_SIZE} bytes: "
                f"{len(self._public_blob)}"
            )

    # -- signing / verification -------------------------------------------

    @staticmethod
    def build_challenge_data(
        signer_pubkey_blob: bytes,
        challenge: int,
        ip_kind: int = 0,
        ip_bytes: bytes = b"",
    ) -> bytes:
        """Signed string per CreateSignature: [signer pubkey][challenge LE][IP block].

        eMule signs the SIGNER's own pubkey blob (BaseClient.cpp
        SendSignaturePacket passes `this`); the verifier rebuilds the same
        string with the signer's blob learned from OP_PUBLICKEY.
        """
        data = bytearray(signer_pubkey_blob)
        data += struct.pack("<I", challenge & 0xFFFFFFFF)
        if ip_kind:
            data += ip_bytes + bytes((ip_kind,))
        return bytes(data)

    def create_signature(
        self,
        challenge: int,
        ip_kind: int = 0,
        ip_bytes: bytes = b"",
    ) -> bytes:
        """RSASSA-PKCS1-v1_5/SHA-1 signature over [our blob][challenge][IP?]."""
        if self._key is None:
            raise SecureIdentError("SecureIdent keys are not initialized")
        data = self.build_challenge_data(
            self._public_blob, challenge, ip_kind, ip_bytes
        )
        return _sign_data(self._key, data)

    @staticmethod
    def verify_signature(
        signer_pubkey_blob: bytes,
        signature: bytes,
        challenge: int,
        ip_kind: int = 0,
        ip_bytes: bytes = b"",
    ) -> bool:
        """Verify a peer signature with the SIGNER's claimed pubkey blob."""
        if not 10 <= len(signer_pubkey_blob) <= MAX_PUBKEY_SIZE:
            return False
        data = SecureIdentProvider.build_challenge_data(
            signer_pubkey_blob, challenge, ip_kind, ip_bytes
        )
        return _verify_data(signer_pubkey_blob, signature, data)

    # -- credit-model API ---------------------------------------------------

    def mark_verified(self, user_hash: str) -> None:
        self._verified[user_hash.strip().lower()] = True

    def evaluate(self, user_hash: str) -> SecureIdentInfo:
        uh = user_hash.strip().lower()
        verified = bool(self._verified.get(uh))
        info = SecureIdentInfo(
            user_hash=uh,
            state=SecureIdentState.SIGNED_ID if verified else SecureIdentState.NOT_AVAILABLE,
            verified=verified,
            bonus_multiplier=2.0 if verified else 1.0,
            detail="secure ident verified" if verified else "not verified",
        )
        log.debug("secure ident evaluated: user_hash=%s, verified=%s", uh, verified)
        return info

    # -- legacy raw API (kept for callers) -----------------------------------

    def sign(self, challenge: bytes) -> bytes:
        """Sign a raw challenge string with our key."""
        if self._key is None:
            raise SecureIdentError("SecureIdent keys are not initialized")
        return _sign_data(self._key, challenge)

    def verify(self, user_hash: str, signature: bytes, challenge: bytes) -> bool:
        stored = self._verified.get(user_hash.strip().lower())
        log.debug("secure ident raw verify: user_hash=%s, stored=%s", user_hash, stored)
        return bool(stored)
