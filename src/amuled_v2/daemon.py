"""Daemon lifecycle stub (M2 placeholder).

Provides a :class:`DaemonState` dataclass that records the intended daemon
status, PID tracking fields, and proxy settings placeholder.  Process
management functions :func:`start_daemon` and :func:`stop_daemon` return a
structured ``not_implemented`` response with exit code 0 for the M2
skeleton — actual daemonization is deferred to M14.

src/amuled_v2/daemon.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] DaemonState dataclass with status, pid, proxy placeholder.
  [+] start_daemon / stop_daemon stubs returning not_implemented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------


@dataclass
class DaemonState:
    """Intended daemon runtime state (M2 placeholder)."""

    status: str = "stopped"
    pid: int | None = None
    proxy_enabled: bool = False
    proxy_host: str | None = None
    proxy_port: int | None = None


@dataclass
class DaemonInfo:
    """Response payload returned by daemon commands."""

    status: str
    message: str
    implemented: bool = True
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "implemented": self.implemented,
            "data": self.data,
        }


# ------------------------------------------------------------------
# Lifecycle stubs (M2)
# ------------------------------------------------------------------


def start_daemon() -> tuple[int, DaemonInfo]:
    """Stub: returns not_implemented with exit code 0."""
    info = DaemonInfo(
        status="not_implemented",
        message="Daemon process management is not yet implemented (M14).",
        implemented=False,
    )
    return 0, info


def stop_daemon() -> tuple[int, DaemonInfo]:
    """Stub: returns not_implemented with exit code 0."""
    info = DaemonInfo(
        status="not_implemented",
        message="Daemon process management is not yet implemented (M14).",
        implemented=False,
    )
    return 0, info
