"""Client-to-server ED2K TCP constants and login-message builder.

Implements the offline wire-message foundation described by
``docs/PROTOCOL_MATRIX.md``, section 4.  The login builder emits an
``OP_LOGINREQUEST`` payload exactly as framed by the ED2K server protocol:
user hash, client ID, client port, tag count, then four new-format tags.

src/amuled_v2/core/ed2k/constants.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added client-to-server TCP opcodes and server capability flags.
  [+] Added aMule-compatible software version constants.
  [+] Added strict LoginRequest model and payload/packet builder.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from amuled_v2.core.codec.binary import BinaryWriter
from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.packet import Packet, encode_packet
from amuled_v2.core.codec.tags import Ed2kTag, TagError, write_new_tag
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.ED2K, "core.ed2k.constants")

__all__ = [
    "C2STCP",
    "ClientCapability",
    "SoftwareId",
    "EDONKEY_PROTOCOL_VERSION",
    "A_MULE_VERSION",
    "LoginRequest",
    "ProtocolError",
    "build_login_payload",
    "build_login_packet",
]


class ProtocolError(ValueError):
    """Raised when an ED2K protocol message cannot be constructed."""


class C2STCP:
    """Client-to-server TCP opcode identifiers."""

    LOGINREQUEST = 0x01
    REJECT = 0x05
    GETSERVERLIST = 0x14
    OFFERFILES = 0x15
    SEARCHREQUEST = 0x16
    DISCONNECT = 0x18
    GETSOURCES = 0x19
    SEARCH_USER = 0x1A
    CALLBACKREQUEST = 0x1C
    QUERY_MORE_RESULT = 0x21
    GETSOURCES_OBFU = 0x23
    SERVERLIST = 0x32
    SEARCHRESULT = 0x33
    SERVERSTATUS = 0x34
    CALLBACKREQUESTED = 0x35
    CALLBACK_FAIL = 0x36
    SERVERMESSAGE = 0x38
    IDCHANGE = 0x40
    SERVERIDENT = 0x41
    FOUNDSOURCES = 0x42
    USERS_LIST = 0x43
    FOUNDSOURCES_OBFU = 0x44


class ClientCapability:
    """Client capabilities announced in the login server-flags tag."""

    ZLIB = 0x0001
    IP_IN_LOGIN = 0x0002
    AUXPORT = 0x0004
    NEWTAGS = 0x0008
    UNICODE = 0x0010
    RELATEDSEARCH = 0x0040
    TYPE_INTEGER = 0x0080
    LARGEFILES = 0x0100
    SUPPORTCRYPT = 0x0200
    REQUESTCRYPT = 0x0400
    REQUIRECRYPT = 0x0800


class SoftwareId:
    """Stable ED2K software identifiers used in version tags."""

    AMULE = 3


EDONKEY_PROTOCOL_VERSION = 0x3C
_A_MULE_MAJOR = 2
_A_MULE_MINOR = 3
_A_MULE_UPDATE = 3
A_MULE_VERSION = (
    (SoftwareId.AMULE << 24)
    | (_A_MULE_MAJOR << 17)
    | (_A_MULE_MINOR << 10)
    | (_A_MULE_UPDATE << 7)
)

_HEX16 = re.compile(r"^[0-9a-fA-F]{32}$")


@dataclass(frozen=True)
class LoginRequest:
    """Values encoded into an ``OP_LOGINREQUEST`` payload."""

    user_hash: bytes
    client_id: int
    client_port: int
    nickname: str
    edonkey_version: int = EDONKEY_PROTOCOL_VERSION
    emule_version: int = A_MULE_VERSION
    capabilities: int = (
        ClientCapability.ZLIB
        | ClientCapability.AUXPORT
        | ClientCapability.NEWTAGS
        | ClientCapability.UNICODE
        | ClientCapability.LARGEFILES
        | ClientCapability.SUPPORTCRYPT
        | ClientCapability.REQUESTCRYPT
    )

    def __post_init__(self) -> None:
        if len(self.user_hash) != 16:
            raise ProtocolError("user hash must contain exactly 16 bytes")
        if not 0 <= self.client_id <= 0xFFFFFFFF:
            raise ProtocolError(f"client ID out of UInt32 range: {self.client_id}")
        if not 0 <= self.client_port <= 0xFFFF:
            raise ProtocolError(f"client port out of UInt16 range: {self.client_port}")
        if not self.nickname:
            raise ProtocolError("nickname cannot be empty")
        if len(self.nickname.encode("utf-8")) > 0xFFFF:
            raise ProtocolError("nickname exceeds UInt16 encoded length")
        if not 0 <= self.edonkey_version <= 0xFFFFFFFF:
            raise ProtocolError("ED2K version out of UInt32 range")
        if not 0 <= self.emule_version <= 0xFFFFFFFF:
            raise ProtocolError("eMule version out of UInt32 range")
        if not 0 <= self.capabilities <= 0xFFFFFFFF:
            raise ProtocolError("capabilities out of UInt32 range")

    @classmethod
    def create(
        cls,
        *,
        nickname: str,
        client_id: int = 0,
        client_port: int = 8089,
        user_hash: bytes | None = None,
        enable_security: bool = True,
    ) -> "LoginRequest":
        """Create a login request with a fresh user hash when none is supplied."""
        if user_hash is None:
            user_hash = os.urandom(16)
        capabilities = (
            ClientCapability.ZLIB
            | ClientCapability.AUXPORT
            | ClientCapability.NEWTAGS
            | ClientCapability.UNICODE
            | ClientCapability.LARGEFILES
        )
        if enable_security:
            capabilities |= ClientCapability.SUPPORTCRYPT
            capabilities |= ClientCapability.REQUESTCRYPT
        return cls(
            user_hash=user_hash,
            client_id=client_id,
            client_port=client_port,
            nickname=nickname,
            capabilities=capabilities,
        )


def _login_tags(request: LoginRequest) -> list[Ed2kTag]:
    return [
        Ed2kTag(name_id=0x01, type=0x02, value=request.nickname),
        Ed2kTag(name_id=0x11, type=0x03, value=request.edonkey_version),
        Ed2kTag(name_id=0x20, type=0x03, value=request.capabilities),
        Ed2kTag(name_id=0xFB, type=0x03, value=request.emule_version),
    ]


def build_login_payload(request: LoginRequest) -> bytes:
    """Encode *request* as the raw ``OP_LOGINREQUEST`` payload."""
    writer = BinaryWriter()
    writer.write_hash16(request.user_hash)
    writer.write_u32(request.client_id)
    writer.write_u16(request.client_port)
    tags = _login_tags(request)
    writer.write_u32(len(tags))
    for tag in tags:
        try:
            write_new_tag(tag, writer)
        except TagError as exc:
            log.error(f"Login tag encoding failed: tag_id=0x{tag.name_id:02X}, error={exc}")
            raise ProtocolError(f"cannot encode login tag: {exc}") from exc
    payload = writer.to_bytes()
    log.debug(
        f"Login payload built: client_id={request.client_id}, "
        f"port={request.client_port}, payload_size={len(payload)}"
    )
    return payload


def build_login_packet(request: LoginRequest) -> bytes:
    """Encode *request* as a complete ED2K TCP ``OP_LOGINREQUEST`` packet."""
    packet = Packet(
        protocol=EDONKEY,
        opcode=C2STCP.LOGINREQUEST,
        payload=build_login_payload(request),
    )
    encoded = encode_packet(packet)
    log.info(
        f"Login packet built: opcode=0x{packet.opcode:02X}, size={len(encoded)}"
    )
    return encoded
