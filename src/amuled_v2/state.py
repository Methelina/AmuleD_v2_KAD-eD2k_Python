"""DuckDB-backed runtime state for AmuleD_v2.

Provides the portable persistence layer for schema metadata, imported servers,
static servers, shared-file metadata, and shared directories.  A small JSON
store remains available only as a bootstrap fallback when DuckDB is absent.

src/amuled_v2/state.py
Version:     0.3.2
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.3.2 (Soror L.'.L'.):
  [+] Added tagged STATE diagnostics for backend connections, migrations, and
      repository save counts.

Patch Notes v0.3.1 (Soror L.'.L'.):
  [+] Added schema migration 2 for imported servers, static servers, shared
      files, and shared directories.
  [+] Added idempotent repository methods used by `import ... --save`.
  [*] Preserved lazy connection handling and status reporting.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial lazy DuckDB backend with JSON bootstrap fallback.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Iterable

from amuled_v2.logging_setup import LogTags, get_tagged_logger
from amuled_v2.paths import DB_FILE, STATE_JSON, ensure_runtime_dirs

log = get_tagged_logger(LogTags.STATE, "state")

if TYPE_CHECKING:
    from amuled_v2.core.ed2k import ServerRecord, StaticServer
    from amuled_v2.core.sharing import SharedFile

try:
    import duckdb  # type: ignore[import-untyped]
    _HAS_DUCKDB = True
except ImportError:  # pragma: no cover - exercised only without DuckDB
    _HAS_DUCKDB = False

_CURRENT_SCHEMA_VERSION = 2
_JSON_STORE: dict[str, Any] | None = None


# ------------------------------------------------------------------
# DuckDB schema
# ------------------------------------------------------------------

def _migrate_v1(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS kv_meta (
            key   VARCHAR PRIMARY KEY,
            value VARCHAR
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)"
    )


def _migrate_v2(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            ip          UINTEGER NOT NULL,
            port        UINTEGER NOT NULL,
            address     VARCHAR NOT NULL,
            name        VARCHAR NOT NULL,
            description VARCHAR NOT NULL,
            priority    INTEGER NOT NULL,
            version     VARCHAR NOT NULL,
            users       BIGINT NOT NULL,
            files       BIGINT NOT NULL,
            aux_ports   VARCHAR NOT NULL,
            is_static   BOOLEAN NOT NULL,
            PRIMARY KEY (ip, port)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS static_servers (
            host     VARCHAR NOT NULL,
            port     UINTEGER NOT NULL,
            name     VARCHAR NOT NULL,
            priority INTEGER NOT NULL,
            PRIMARY KEY (host, port)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS shared_files (
            file_hash VARCHAR PRIMARY KEY,
            name      VARCHAR NOT NULL,
            size      BIGINT NOT NULL,
            path      VARCHAR,
            priority  INTEGER NOT NULL,
            imported  BOOLEAN NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS shared_directories (
            path VARCHAR PRIMARY KEY
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (2)"
    )


def _init_duckdb(con: Any) -> None:
    """Apply all pending schema migrations."""
    log.debug("Initializing DuckDB schema")
    _migrate_v1(con)
    row = con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    current = row[0] if row and row[0] is not None else 0
    if current < 2:
        _migrate_v2(con)
        log.info("DuckDB schema migrated to version 2")
    else:
        log.debug("DuckDB schema is current")


# ------------------------------------------------------------------
# JSON bootstrap fallback
# ------------------------------------------------------------------

def _json_get_store() -> dict[str, Any]:
    global _JSON_STORE
    if _JSON_STORE is None:
        ensure_runtime_dirs()
        if STATE_JSON.exists():
            with open(STATE_JSON, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise ValueError(f"invalid JSON state root: {STATE_JSON}")
            _JSON_STORE = loaded
        else:
            _JSON_STORE = {"schema_migrations": [], "kv_meta": {}}
    return _JSON_STORE


def _json_save_store() -> None:
    ensure_runtime_dirs()
    with open(STATE_JSON, "w", encoding="utf-8") as handle:
        json.dump(_JSON_STORE, handle, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------
# Public backend
# ------------------------------------------------------------------

class StateBackend:
    """Portable runtime state backed by DuckDB."""

    def __init__(self) -> None:
        self.backend: str = "duckdb" if _HAS_DUCKDB else "json-fallback"
        self.db_path: str = str(DB_FILE)
        self._con: Any | None = None

    def connect(self) -> None:
        if self._con is not None:
            return
        ensure_runtime_dirs()
        if _HAS_DUCKDB:
            log.debug(f"Connecting DuckDB state: {DB_FILE}")
            self._con = duckdb.connect(str(DB_FILE))
            _init_duckdb(self._con)
        else:
            log.warning("DuckDB unavailable; using JSON bootstrap fallback")
            self._con = _json_get_store()

    def _require_duckdb(self) -> Any:
        if self._con is None:
            self.connect()
        if self.backend != "duckdb" or self._con is None:
            raise RuntimeError("repository operations require the DuckDB backend")
        return self._con

    def get_status(self) -> dict[str, Any]:
        if self._con is None:
            self.connect()
        status: dict[str, Any] = {
            "backend": self.backend,
            "db_path": self.db_path,
            "tables": {},
        }
        if self.backend == "duckdb":
            tables = self._con.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'main' ORDER BY table_name"
            ).fetchall()
            for (table_name,) in tables:
                status["tables"][table_name] = self._con.execute(
                    f'SELECT COUNT(*) FROM "{table_name}"'
                ).fetchone()[0]
        else:
            store = self._con or {}
            status["tables"]["schema_migrations"] = len(
                store.get("schema_migrations", [])
            )
            status["tables"]["kv_meta"] = len(store.get("kv_meta", {}))
        return status

    def save_servers(self, records: Iterable["ServerRecord"]) -> int:
        con = self._require_duckdb()
        count = 0
        for record in records:
            con.execute(
                """
                INSERT OR REPLACE INTO servers (
                    ip, port, address, name, description, priority, version,
                    users, files, aux_ports, is_static
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.ip,
                    record.port,
                    record.address,
                    record.name,
                    record.description,
                    record.priority,
                    record.version,
                    record.users,
                    record.files,
                    record.aux_ports,
                    record.static,
                ),
            )
            count += 1
        log.info(f"Saved servers to state: {count}")
        return count

    def save_static_servers(self, records: Iterable["StaticServer"]) -> int:
        con = self._require_duckdb()
        count = 0
        for record in records:
            con.execute(
                """
                INSERT OR REPLACE INTO static_servers (
                    host, port, name, priority
                ) VALUES (?, ?, ?, ?)
                """,
                (record.host, record.port, record.name, record.priority),
            )
            count += 1
        log.info(f"Saved static servers to state: {count}")
        return count

    def save_shared_files(self, records: Iterable["SharedFile"]) -> int:
        con = self._require_duckdb()
        count = 0
        for record in records:
            con.execute(
                """
                INSERT OR REPLACE INTO shared_files (
                    file_hash, name, size, path, priority, imported
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.hash_hex,
                    record.name,
                    record.size,
                    record.path,
                    record.priority,
                    record.imported,
                ),
            )
            count += 1
        log.info(f"Saved shared files to state: {count}")
        return count

    def save_shared_directories(self, directories: Iterable[str]) -> int:
        con = self._require_duckdb()
        count = 0
        for directory in directories:
            con.execute(
                "INSERT OR REPLACE INTO shared_directories (path) VALUES (?)",
                (str(directory),),
            )
            count += 1
        log.info(f"Saved shared directories to state: {count}")
        return count

    def close(self) -> None:
        if self._con is not None and self.backend == "duckdb":
            self._con.close()
        self._con = None


# ------------------------------------------------------------------
# Shared backend instance
# ------------------------------------------------------------------

_state: StateBackend | None = None


def get_state() -> StateBackend:
    global _state
    if _state is None:
        _state = StateBackend()
    return _state
