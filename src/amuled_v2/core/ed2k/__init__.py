"""ED2K client-protocol package.

src/amuled_v2/core/ed2k/__init__.py
Version:     0.3.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.3.0 (Soror L.'.L'.):
  [+] Added asyncio ED2K server TCP session and server response exports.

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added client-to-server constants and OP_LOGINREQUEST builder exports.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package marker for ED2K server-list and future protocol modules.
  [+] Re-exports server persistence API for CLI and import layers.
"""

from .constants import (
    A_MULE_VERSION,
    C2STCP,
    ClientCapability,
    EDONKEY_PROTOCOL_VERSION,
    LoginRequest,
    ProtocolError,
    SoftwareId,
    build_login_packet,
    build_login_payload,
)
from .server_client import (
    Ed2kServerClient,
    LoginResult,
    ServerIdChange,
    ServerIdentity,
    ServerMessage,
    ServerSessionError,
    ServerStatus,
)
from .server_met import (
    SERVER_MET_VERSION,
    ServerMetError,
    ServerRecord,
    StaticServer,
    load_server_met,
    load_static_servers,
    merge_server_lists,
    parse_server_met,
)

__all__ = [
    "A_MULE_VERSION",
    "C2STCP",
    "ClientCapability",
    "EDONKEY_PROTOCOL_VERSION",
    "LoginRequest",
    "ProtocolError",
    "SoftwareId",
    "build_login_packet",
    "build_login_payload",
    "Ed2kServerClient",
    "LoginResult",
    "ServerIdentity",
    "ServerIdChange",
    "ServerMessage",
    "ServerSessionError",
    "ServerStatus",
    "SERVER_MET_VERSION",
    "ServerMetError",
    "ServerRecord",
    "StaticServer",
    "load_server_met",
    "load_static_servers",
    "merge_server_lists",
    "parse_server_met",
]
