"""ED2K client-protocol package.

src/amuled_v2/core/ed2k/__init__.py
Version:     0.5.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.5.0 (Soror L.'.L'.):
  [+] Added ED2K file-link parsing, global search, and source response exports.

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
from .links import (
    Ed2kFileLink,
    Ed2kLinkError,
    build_ed2k_file_link,
    parse_ed2k_file_link,
)
from .server_client import (
    Ed2kServerClient,
    FoundSource,
    FoundSources,
    LoginResult,
    SearchResult,
    SearchResultResponse,
    SearchResultsBatch,
    ServerIdChange,
    ServerIdentity,
    ServerMessage,
    ServerSessionError,
    ServerStatus,
    build_get_sources_payload,
    build_global_search_payload,
    parse_found_sources,
    parse_search_results,
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
from .udp_global import (
    C2SUDP,
    GlobalSearchAggregate,
    GlobalServerEndpoint,
    GlobalUdpSearch,
    GlobalUdpSearchError,
    build_udp_search_payload,
    build_udp_search_req3_prefix,
    encode_udp_packet,
    parse_udp_packet,
)

__all__ = [
    "A_MULE_VERSION",
    "C2STCP",
    "ClientCapability",
    "EDONKEY_PROTOCOL_VERSION",
    "Ed2kFileLink",
    "Ed2kLinkError",
    "LoginRequest",
    "ProtocolError",
    "SoftwareId",
    "build_login_packet",
    "build_login_payload",
    "build_ed2k_file_link",
    "parse_ed2k_file_link",
    "Ed2kServerClient",
    "FoundSource",
    "FoundSources",
    "LoginResult",
    "SearchResult",
    "SearchResultsBatch",
    "ServerIdentity",
    "ServerIdChange",
    "ServerMessage",
    "ServerSessionError",
    "ServerStatus",
    "build_get_sources_payload",
    "build_global_search_payload",
    "parse_found_sources",
    "parse_search_results",
    "SERVER_MET_VERSION",
    "ServerMetError",
    "ServerRecord",
    "StaticServer",
    "load_server_met",
    "load_static_servers",
    "merge_server_lists",
    "parse_server_met",
    "C2SUDP",
    "GlobalSearchAggregate",
    "GlobalServerEndpoint",
    "GlobalUdpSearch",
    "GlobalUdpSearchError",
    "build_udp_search_payload",
    "build_udp_search_req3_prefix",
    "encode_udp_packet",
    "parse_udp_packet",
]
