"""Asyncio-managed ED2K server session with eMule-parity auto-connect.

Oracle context (eMuleAI 1.6.0):
  EmuleDlg.cpp:9105-9109 AutoConnectIfNeeded -> StartConnection(false) ->
  serverconnect->ConnectToAnyServer() (:9093) + CKademlia::Start() (:9097);
  ServerConnect.cpp RetryConnectTimer (:429-445) retries
  ConnectToAnyServer(m_uStartAutoConnectPos, true, true) while disconnected,
  rotating the start position across the server list (:370-376, :439-440);
  a static-only filter uses GetAutoConnectToStaticServersOnly() && isAuto
  (ServerConnect.cpp:96-112).  Our project persists per-server failures with
  cooldown in DuckDB, so blacklisted servers are filtered here.

src/amuled_v2/core/ed2k/server_session.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-29

Patch Notes v0.1.1 (Soror L.'.L.'.):
  [+] FIX live (2026-09-29): candidate building passed config KEYS
      ("server_met"/"static_servers") to the path resolver instead of the
      configured VALUES, so both lists silently resolved to nonexistent
      paths and autoconnect always saw zero candidates; _build_candidates
      now takes the servers config section. StaticServer records
      (.host field, .priority int) are now handled alongside ServerRecord
      (.address property, .priority() method).
  [+] FIX live (2026-09-29): default root was parents[3] = src directory
      (copied from the shallower kernel_control.py); corrected to
      parents[4] = project root, otherwise relative server-list paths never
      resolve.

Patch Notes v0.1.0 (Soror L.'.L.'.):
  [+] ServerSessionManager: held ED2K server session with eMule-style auto-connect,
      start-position rotation, candidate building from static + server.met,
      and keepalive push-read loop.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Optional

from amuled_v2.core.ed2k.server_client import (
    Ed2kServerClient,
    LoginRequest,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SERVER, "core.ed2k.server_session")

__all__ = ["ServerSessionManager"]

_LOG_NO_CANDIDATES_MSG = "SERVER autoconnect: no candidate servers"


class ServerSessionManager:
    """Maintain a held eD2K server session against an auto-connect candidate list.

    Mirrors eMule's ``CServerConnect`` ``RetryConnectTimer`` / ``ConnectToAnyServer``
    rotation: candidates are tried in priority order starting at a persistent index
    that advances on each failure and wraps modulo the list length.
    """

    def __init__(
        self,
        *,
        state: Any,
        config_loader: Callable[[], dict[str, Any]],
        tcp_port: int,
        user_hash: bytes,
        nickname: str,
        client_factory: Optional[Callable[..., Ed2kServerClient]] = None,
        root: Optional[Path] = None,
    ) -> None:
        if root is None:
            # src/amuled_v2/core/ed2k/server_session.py -> project root
            # (four levels up; kernel_control.py uses parents[3] because it
            # lives one directory shallower).
            root = Path(__file__).resolve().parents[4]
        self._state = state
        self._config_loader = config_loader
        self._tcp_port = tcp_port
        self._user_hash = user_hash
        self._nickname = nickname
        self._client_factory: Callable[..., Ed2kServerClient] = (
            client_factory if client_factory is not None else Ed2kServerClient
        )
        self._root = Path(root)
        self._pos: int = 0
        self._attempts: int = 0
        self._logins: int = 0
        self._last_error: Optional[str] = None
        self._connected: bool = False
        self._server: Optional[str] = None
        self._autoconnect: bool = True
        self._no_candidates_logged: bool = False

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _load_servers_config(self) -> dict[str, Any]:
        try:
            cfg = self._config_loader()
        except Exception as exc:
            log.warning("SERVER config load fallback: error=%r", exc)
            cfg = {}
        if not isinstance(cfg, dict):
            log.warning(
                "SERVER config load fallback: root is not a dict, got=%r", type(cfg)
            )
            cfg = {}
        servers_cfg = cfg.get("servers") or {}
        if not isinstance(servers_cfg, dict):
            log.warning(
                "SERVER config load fallback: 'servers' is not a dict, got=%r",
                type(servers_cfg),
            )
            servers_cfg = {}
        return servers_cfg

    def _cfg_float(self, servers_cfg: dict[str, Any], key: str, default: float) -> float:
        value = servers_cfg.get(key, default)
        try:
            return float(value) if value is not None else default
        except (TypeError, ValueError) as exc:
            log.warning(
                "SERVER config %s fallback: value=%r, error=%r, default=%s",
                key, value, exc, default,
            )
            return default

    # ------------------------------------------------------------------
    # Candidate building
    # ------------------------------------------------------------------

    def _load_static_records(self, path: Path) -> list[Any]:
        if not path.exists():
            log.debug("SERVER static server list not found: %s", path)
            return []
        try:
            from amuled_v2.core.ed2k.server_met import load_static_servers as _load_static
        except Exception as exc:
            log.warning("SERVER static import fallback: %s, error=%r", path, exc)
            return []
        try:
            return list(_load_static(str(path)))
        except Exception as exc:
            log.warning("SERVER static load fallback: %s, error=%r", path, exc)
            return []

    def _load_met_records(self, path: Path) -> list[Any]:
        if not path.exists():
            log.debug("SERVER server.met not found: %s", path)
            return []
        try:
            from amuled_v2.core.ed2k.server_met import load_server_met as _load_met
        except Exception as exc:
            log.warning("SERVER server.met import fallback: %s, error=%r", path, exc)
            return []
        try:
            return list(_load_met(str(path)))
        except Exception as exc:
            log.warning("SERVER server.met load fallback: %s, error=%r", path, exc)
            return []

    def _resolve_path(self, name: str) -> Path:
        try:
            raw = str(name) if name else ""
        except Exception as exc:
            log.warning("SERVER path resolve fallback: name=%r, error=%r", name, exc)
            return Path("")
        if not raw:
            return Path("")
        p = Path(raw)
        if p.is_absolute():
            return p
        return self._root / p

    def _blacklist_set(self) -> Optional[set[tuple[str, int]]]:
        try:
            entries = self._state.list_blacklisted_servers() or []
        except Exception as exc:
            log.warning("SERVER blacklist read fallback: error=%r", exc)
            return None
        result: set[tuple[str, int]] = set()
        for entry in entries:
            try:
                ip = str(entry.get("ip") or entry.get("address") or entry.get("host"))
                port = int(entry.get("port"))
                result.add((ip, port))
            except Exception as exc:
                log.warning(
                    "SERVER blacklist parse fallback: entry=%r, error=%r", entry, exc
                )
                continue
        return result

    def _record_to_candidate(
        self, record: Any
    ) -> Optional[tuple[str, int, bool, int]]:
        # Two record shapes share this builder:
        #  - ServerRecord (server.met): .address property, .priority() method;
        #  - StaticServer (staticservers.dat): .host field, .priority int.
        try:
            ip_str = str(
                getattr(record, "address", None) or getattr(record, "host", "")
            ).strip()
            port = int(getattr(record, "port"))
            if not ip_str:
                raise ValueError("record has no ip/host")
        except Exception as exc:
            log.warning(
                "SERVER candidate parse fallback: record=%r, error=%r", record, exc
            )
            return None
        priority = 0
        try:
            prio = getattr(record, "priority", 0)
            priority = int(prio() if callable(prio) else prio)
        except Exception:
            priority = 0
        return (ip_str, port, True, priority)

    def _build_candidates(
        self, servers_cfg: dict[str, Any]
    ) -> list[tuple[str, int, bool, int]]:
        static_records = self._load_static_records(
            self._resolve_path(str(servers_cfg.get("static_servers") or ""))
        )
        met_records = self._load_met_records(
            self._resolve_path(str(servers_cfg.get("server_met") or ""))
        )

        seen: dict[tuple[str, int], tuple[str, int, bool, int]] = {}
        for record in static_records:
            cand = self._record_to_candidate(record)
            if cand is None:
                continue
            key = (cand[0], cand[1])
            if key not in seen:
                seen[key] = cand
        for record in met_records:
            cand = self._record_to_candidate(record)
            if cand is None:
                continue
            key = (cand[0], cand[1])
            if key not in seen:
                seen[key] = (cand[0], cand[1], False, cand[3])

        blacklist = self._blacklist_set()
        candidates: list[tuple[str, int, bool, int]] = []
        for ip_str, port, is_static, priority in seen.values():
            if blacklist is not None:
                try:
                    if (str(ip_str), int(port)) in blacklist:
                        continue
                except Exception as exc:
                    log.warning(
                        "SERVER blacklist match fallback: server=%s:%d, error=%r",
                        ip_str, port, exc,
                    )
                    continue
            candidates.append((ip_str, port, is_static, priority))

        candidates.sort(key=lambda c: (not c[2], -c[3]))
        return candidates

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        return {
            "autoconnect": bool(self._autoconnect),
            "connected": bool(self._connected),
            "server": self._server,
            "last_error": self._last_error,
            "attempts": int(self._attempts),
            "logins": int(self._logins),
        }

    # ------------------------------------------------------------------
    # Single candidate attempt
    # ------------------------------------------------------------------

    async def _try_candidate(
        self, ip_str: str, port: int, connect_timeout_s: float
    ) -> Optional[Ed2kServerClient]:
        login_request = LoginRequest.create(
            nickname=self._nickname,
            client_id=0,
            client_port=int(self._tcp_port),
            user_hash=self._user_hash,
            enable_security=True,
        )
        try:
            client = self._client_factory(
                host=ip_str,
                port=port,
                login_request=login_request,
                connect_timeout=connect_timeout_s,
                response_timeout=connect_timeout_s,
            )
        except Exception as exc:
            log.warning(
                "SERVER autoconnect client factory failed: server=%s:%d, error=%r",
                ip_str, port, exc,
            )
            return None

        try:
            await asyncio.wait_for(client.connect(), timeout=connect_timeout_s + 5)
            await asyncio.wait_for(client.login(), timeout=connect_timeout_s + 15)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            log.warning(
                "SERVER autoconnect attempt failed: server=%s:%d, error=%r",
                ip_str, port, exc,
            )
            try:
                self._state.record_server_failure(
                    ip_str, port, reason=str(exc)[:200]
                )
            except Exception as inner:
                log.warning(
                    "SERVER failure record fallback: server=%s:%d, error=%r",
                    ip_str, port, inner,
                )
            try:
                await client.close()
            except Exception as inner:
                log.warning(
                    "SERVER client close fallback: server=%s:%d, error=%r",
                    ip_str, port, inner,
                )
            return None

        try:
            self._state.record_server_success(ip_str, port)
        except Exception as exc:
            log.warning(
                "SERVER success record fallback: server=%s:%d, error=%r",
                ip_str, port, exc,
            )
        return client

    # ------------------------------------------------------------------
    # Hold a connected session
    # ------------------------------------------------------------------

    async def _hold_session(
        self,
        client: Ed2kServerClient,
        ip_str: str,
        port: int,
        keepalive_timeout_s: float,
        stop: asyncio.Event,
    ) -> None:
        self._connected = True
        self._server = f"{ip_str}:{port}"
        log.info("SERVER session held: server=%s:%d", ip_str, port)
        while not stop.is_set():
            try:
                got = await client.next_push(timeout=keepalive_timeout_s)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.info(
                    "SERVER session lost: server=%s:%d, error=%r", ip_str, port, exc
                )
                break
            if not got:
                continue
        self._connected = False
        self._server = None
        try:
            await client.close()
        except Exception as exc:
            log.warning(
                "SERVER session close fallback: server=%s:%d, error=%r",
                ip_str, port, exc,
            )

    # ------------------------------------------------------------------
    # Wait helper respecting stop
    # ------------------------------------------------------------------

    async def _wait_stop_or_retry(
        self, stop: asyncio.Event, timeout: float
    ) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            servers_cfg = self._load_servers_config()

            if not bool(servers_cfg.get("autoconnect")):
                self._autoconnect = False
                snapshot_val = self.snapshot()
                snapshot_val["autoconnect"] = False
                await self._wait_stop_or_retry(stop, 30)
                continue
            self._autoconnect = True

            retry_interval_s = self._cfg_float(servers_cfg, "retry_interval_s", 300.0)
            connect_timeout_s = self._cfg_float(servers_cfg, "connect_timeout_s", 10.0)
            keepalive_timeout_s = self._cfg_float(
                servers_cfg, "keepalive_timeout_s", 60.0
            )

            candidates = self._build_candidates(servers_cfg)
            if not candidates:
                self._last_error = "no candidate servers"
                if not self._no_candidates_logged:
                    log.info(_LOG_NO_CANDIDATES_MSG)
                    self._no_candidates_logged = True
                await self._wait_stop_or_retry(stop, retry_interval_s)
                continue
            self._no_candidates_logged = False

            num = len(candidates)
            start = self._pos % num
            rotated = candidates[start:] + candidates[:start]

            connected_client: Optional[Ed2kServerClient] = None
            for idx, (ip_str, port, _is_static, _priority) in enumerate(rotated):
                self._pos = (start + idx) % num
                self._attempts += 1
                connected_client = await self._try_candidate(
                    ip_str, port, connect_timeout_s
                )
                if connected_client is not None and connected_client.logged_in:
                    self._logins += 1
                    await self._hold_session(
                        connected_client, ip_str, port, keepalive_timeout_s, stop
                    )
                    break
            else:
                connected_client = None

            await self._wait_stop_or_retry(stop, retry_interval_s)
