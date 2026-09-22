"""Real connection-state tracking for search-channel resolution.

AUTO search must not guess whether the ED2K and KAD networks are reachable.
This module keeps the client's actual connection state in one place and feeds
it to the eMule AUTO resolver.  State updates arrive from live sessions (the
ED2K TCP client reports every login and disconnect) and from explicit network
toggles.

src/amuled_v2/core/connection_state.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added a connection-state manager reflecting actual ED2K/KAD state.
  [+] Added ED2K server bookkeeping for AUTO resolution inputs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.ED2K, "core.connection_state")

__all__ = ["ConnectionSnapshot", "ConnectionStateManager", "get_connection_state"]


@dataclass
class ConnectionSnapshot:
    """One consistent view of the client's network state."""

    ed2k_connected: bool = False
    kad_connected: bool = False
    server_host: Optional[str] = None
    server_port: Optional[int] = None
    server_users: int = 0
    server_files: int = 0
    server_is_static: bool = False
    server_count: int = 0
    updated_at: float = field(default_factory=time.time)


class ConnectionStateManager:
    """Holds the client's actual ED2K and KAD connection state."""

    def __init__(self) -> None:
        self._snapshot = ConnectionSnapshot()

    @property
    def snapshot(self) -> ConnectionSnapshot:
        return ConnectionSnapshot(
            ed2k_connected=self._snapshot.ed2k_connected,
            kad_connected=self._snapshot.kad_connected,
            server_host=self._snapshot.server_host,
            server_port=self._snapshot.server_port,
            server_users=self._snapshot.server_users,
            server_files=self._snapshot.server_files,
            server_is_static=self._snapshot.server_is_static,
            server_count=self._snapshot.server_count,
        )

    def set_ed2k_connected(
        self,
        connected: bool,
        *,
        server_host: Optional[str] = None,
        server_port: Optional[int] = None,
        server_users: int = 0,
        server_files: int = 0,
        server_is_static: bool = False,
    ) -> None:
        """Record one ED2K TCP session transition."""
        self._snapshot.ed2k_connected = connected
        self._snapshot.server_host = server_host if connected else None
        self._snapshot.server_port = server_port if connected else None
        self._snapshot.server_users = server_users if connected else 0
        self._snapshot.server_files = server_files if connected else 0
        self._snapshot.server_is_static = server_is_static if connected else False
        self._snapshot.updated_at = time.time()
        log.info(
            "ED2K connection state updated: connected=%s, server=%s:%s, "
            "users=%d, files=%d",
            connected,
            server_host,
            server_port,
            self._snapshot.server_users,
            self._snapshot.server_files,
        )

    def set_kad_connected(self, connected: bool) -> None:
        """Record one KAD network transition."""
        self._snapshot.kad_connected = connected
        self._snapshot.updated_at = time.time()
        log.info("KAD connection state updated: connected=%s", connected)

    def set_server_count(self, count: int) -> None:
        """Record the number of known servers used by AUTO resolution."""
        self._snapshot.server_count = max(0, int(count))

    def update_from_server_client(self, client: object) -> None:
        """Pull live state from one connected Ed2kServerClient session."""
        logged_in = bool(getattr(client, "logged_in", False))
        host = getattr(client, "host", None)
        port = getattr(client, "port", None)
        status = getattr(client, "status", None)
        self.set_ed2k_connected(
            logged_in,
            server_host=host,
            server_port=port,
            server_users=getattr(status, "users", 0) or 0,
            server_files=getattr(status, "files", 0) or 0,
        )


_manager: ConnectionStateManager | None = None


def get_connection_state() -> ConnectionStateManager:
    """Return the shared connection-state manager."""
    global _manager
    if _manager is None:
        _manager = ConnectionStateManager()
    return _manager
