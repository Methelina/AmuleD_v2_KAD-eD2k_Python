"""AmuleD_v2 peer (client-to-client) codec package.

Re-exports the public peer TCP wire codec so callers import from
``core.peer.codec`` directly.

src/amuled_v2/core/peer/__init__.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package marker re-exporting C2CTCP opcodes, peer dataclasses,
      build/parse payload functions, PeerCodecError, and the asyncio
      PeerClient download session.
"""

from .client import (
    C2CEMULE,
    DownloadOutcome,
    EMULE_PROTOCOL,
    EMBLOCK_SIZE,
    PeerClient,
    PeerInfo,
    PeerSessionError,
)
from .codec import (
    C2CTCP,
    FileNameAnswer,
    FileStatus,
    HashSetAnswer,
    Hello,
    HelloAnswer,
    PeerCodecError,
    RequestParts,
    SendingPart,
    build_hello_answer_payload,
    build_hello_payload,
    build_request_filename_payload,
    build_request_parts_i64_payload,
    build_request_parts_payload,
    parse_compressed_part,
    parse_compressed_part_i64,
    parse_file_hash_payload,
    parse_filename_answer,
    parse_file_status,
    parse_hashset_answer,
    parse_hello,
    parse_hello_answer,
    parse_queue_rank,
    parse_request_parts,
    parse_request_parts_i64,
    parse_sending_part,
    parse_sending_part_i64,
)

__all__ = [
    "C2CEMULE",
    "C2CTCP",
    "EMULE_PROTOCOL",
    "EMBLOCK_SIZE",
    "DownloadOutcome",
    "FileNameAnswer",
    "FileStatus",
    "HashSetAnswer",
    "Hello",
    "HelloAnswer",
    "PeerClient",
    "PeerCodecError",
    "PeerInfo",
    "PeerSessionError",
    "RequestParts",
    "SendingPart",
    "build_hello_answer_payload",
    "build_hello_payload",
    "build_request_filename_payload",
    "build_request_parts_i64_payload",
    "build_request_parts_payload",
    "parse_compressed_part",
    "parse_compressed_part_i64",
    "parse_file_hash_payload",
    "parse_filename_answer",
    "parse_file_status",
    "parse_hashset_answer",
    "parse_hello",
    "parse_hello_answer",
    "parse_queue_rank",
    "parse_request_parts",
    "parse_request_parts_i64",
    "parse_sending_part",
    "parse_sending_part_i64",
]

