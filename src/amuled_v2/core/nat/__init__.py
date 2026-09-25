"""NAT traversal (UPnP IGD / NAT-PMP) — stage X.

src/amuled_v2/core/nat/__init__.py
Author:  Soror L.'.L.'.
Updated: 2026-09-26
"""

from amuled_v2.core.nat.upnp import map_tcp_port, unmap_tcp_port

__all__ = ["map_tcp_port", "unmap_tcp_port"]
