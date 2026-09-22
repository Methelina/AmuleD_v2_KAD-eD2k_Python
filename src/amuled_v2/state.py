"""DuckDB-backed runtime state for AmuleD_v2.

Provides the portable persistence layer for schema metadata, imported servers,
static servers, shared-file metadata, and shared directories.  A small JSON
store remains available only as a bootstrap fallback when DuckDB is absent.
The shared repository supports direct scanning transactions so removed or
missing files do not leave stale rows behind.

src/amuled_v2/state.py
Version:     0.5.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.5.0 (Soror L.'.L'.):
  [+] Added schema migration 3 and persistence for ED2K file sources.
  [+] Added source listing with optional file-hash filtering.

Patch Notes v0.4.3 (Soror L.'.L'.):
  [+] Added transactional replacement of one shared directory scan.
  [+] Added shared directory/file listing, lookup, and removal operations.
  [*] Directory rescans delete rows whose source files no longer exist.
  [*] File removal now reports false when the hash was already absent.

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
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from amuled_v2.logging_setup import LogTags, get_tagged_logger
from amuled_v2.paths import DB_FILE, STATE_JSON, ensure_runtime_dirs

log = get_tagged_logger(LogTags.STATE, "state")

if TYPE_CHECKING:
    from amuled_v2.core.ed2k import FoundSources, ServerRecord, StaticServer
    from amuled_v2.core.sharing import SharedFile

try:
    import duckdb  # type: ignore[import-untyped]
    _HAS_DUCKDB = True
except ImportError:  # pragma: no cover - exercised only without DuckDB
    _HAS_DUCKDB = False

_CURRENT_SCHEMA_VERSION = 3
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


def _migrate_v3(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS file_sources (
            file_hash   VARCHAR NOT NULL,
            client_id   UINTEGER NOT NULL,
            client_port UINTEGER NOT NULL,
            source_type VARCHAR NOT NULL,
            server_ip   VARCHAR NOT NULL,
            server_port UINTEGER NOT NULL,
            user_hash   VARCHAR,
            first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (file_hash, client_id, client_port, source_type)
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (3)"
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
        current = 2
    if current < 3:
        _migrate_v3(con)
        log.info("DuckDB schema migrated to version 3")
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

    def save_found_sources(
        self,
        record: "FoundSources",
        *,
        server_ip: str,
        server_port: int,
        source_type: str = "ed2k_server",
    ) -> int:
        """Persist sources returned by one ED2K source lookup."""
        con = self._require_duckdb()
        count = 0
        for source in record.sources:
            con.execute(
                """
                INSERT OR REPLACE INTO file_sources (
                    file_hash, client_id, client_port, source_type,
                    server_ip, server_port, user_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.file_hash.hex().upper(),
                    source.client_id,
                    source.client_port,
                    source_type,
                    server_ip,
                    server_port,
                    source.user_hash.hex().upper() if source.user_hash else None,
                ),
            )
            count += 1
        log.info(f"Saved file sources to state: file={record.file_hash.hex().upper()}, count={count}")
        return count

    def list_file_sources(
        self,
        file_hash: str | None = None,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List persisted source rows, optionally filtered by ED2K hash."""
        con = self._require_duckdb()
        if limit < 0:
            raise ValueError("limit must be non-negative")
        if file_hash:
            normalized = file_hash.strip().lower()
            if len(normalized) != 32:
                raise ValueError("file hash must contain 32 hexadecimal digits")
            bytes.fromhex(normalized)
            rows = con.execute(
                """
                SELECT file_hash, client_id, client_port, source_type,
                       server_ip, server_port, user_hash, first_seen, last_seen
                FROM file_sources
                WHERE lower(file_hash) = ?
                ORDER BY client_id, client_port
                LIMIT ?
                """,
                (normalized, limit),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT file_hash, client_id, client_port, source_type,
                       server_ip, server_port, user_hash, first_seen, last_seen
                FROM file_sources
                ORDER BY file_hash, client_id, client_port
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "hash": row[0],
                "client_id": row[1],
                "client_port": row[2],
                "source_type": row[3],
                "server_ip": row[4],
                "server_port": row[5],
                "user_hash": row[6],
                "first_seen": str(row[7]),
                "last_seen": str(row[8]),
            }
            for row in rows
        ]

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
                (self._normalize_path(directory),),
            )
            count += 1
        log.info(f"Saved shared directories to state: {count}")
        return count

    def replace_shared_directory_scan(
        self,
        directory: str | Path,
        records: Iterable["SharedFile"],
    ) -> dict[str, Any]:
        """Atomically replace one directory's file set with a fresh scan.

        Existing rows under *directory* that are absent from *records* are
        deleted, preventing stale entries after files are renamed, moved, or
        deleted.  The directory row is always upserted.
        """
        con = self._require_duckdb()
        root = Path(directory).expanduser().resolve()
        root_text = self._normalize_path(root)
        prefix = root_text.rstrip("\\/") + "\\"

        con.execute("BEGIN TRANSACTION")
        try:
            con.execute(
                "INSERT OR REPLACE INTO shared_directories (path) VALUES (?)",
                (root_text,),
            )

            saved = 0
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
                        self._normalize_path(record.path) if record.path else None,
                        record.priority,
                        record.imported,
                    ),
                )
                saved += 1

            existing = con.execute(
                """
                SELECT file_hash, path FROM shared_files
                WHERE starts_with(lower(path), lower(?))
                """,
                (prefix,),
            ).fetchall()
            scanned_paths = {
                self._normalize_path(record.path).lower()
                for record in records
                if record.path is not None
            }
            stale_hashes = [
                file_hash
                for file_hash, path in existing
                if (path or "").lower() not in scanned_paths
            ]
            removed = 0
            for file_hash in stale_hashes:
                con.execute(
                    "DELETE FROM shared_files WHERE file_hash = ?",
                    (file_hash,),
                )
                removed += 1

            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            log.exception(f"Shared directory scan rollback: path={root_text}")
            raise

        result = {
            "directory": root_text,
            "saved_files": saved,
            "removed_files": removed,
        }
        log.info(
            f"Replaced shared directory scan: path={root_text}, "
            f"saved={saved}, removed={removed}"
        )
        return result

    def list_shared_directories(self) -> list[str]:
        """Return registered shared directories in stable path order."""
        con = self._require_duckdb()
        rows = con.execute(
            "SELECT path FROM shared_directories ORDER BY lower(path)"
        ).fetchall()
        return [row[0] for row in rows]

    def list_shared_files(
        self,
        *,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return shared-file rows in stable name/hash order."""
        con = self._require_duckdb()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        rows = con.execute(
            """
            SELECT file_hash, name, size, path, priority, imported
            FROM shared_files
            ORDER BY lower(name), file_hash
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return [
            {
                "hash": row[0],
                "name": row[1],
                "size": row[2],
                "path": row[3],
                "priority": row[4],
                "imported": row[5],
            }
            for row in rows
        ]

    def get_shared_file(self, file_hash: str) -> dict[str, Any] | None:
        """Return one shared-file row by ED2K hash, or ``None``."""
        normalized = file_hash.strip().lower()
        if len(normalized) != 32:
            raise ValueError("file hash must contain 32 hexadecimal digits")
        bytes.fromhex(normalized)
        con = self._require_duckdb()
        row = con.execute(
            """
            SELECT file_hash, name, size, path, priority, imported
            FROM shared_files WHERE lower(file_hash) = ?
            """,
            (normalized,),
        ).fetchone()
        if row is None:
            return None
        return {
            "hash": row[0],
            "name": row[1],
            "size": row[2],
            "path": row[3],
            "priority": row[4],
            "imported": row[5],
        }

    def remove_shared_file(self, file_hash: str) -> bool:
        """Remove one shared-file row by ED2K hash."""
        normalized = file_hash.strip().lower()
        if len(normalized) != 32:
            raise ValueError("file hash must contain 32 hexadecimal digits")
        bytes.fromhex(normalized)
        con = self._require_duckdb()
        existed = con.execute(
            "SELECT COUNT(*) FROM shared_files WHERE lower(file_hash) = ?",
            (normalized,),
        ).fetchone()[0] > 0
        if existed:
            con.execute(
                "DELETE FROM shared_files WHERE lower(file_hash) = ?",
                (normalized,),
            )
        log.info(f"Removed shared file: hash={normalized}, removed={existed}")
        return existed

    def remove_shared_directory(
        self,
        directory: str | Path,
        *,
        remove_files: bool = True,
    ) -> dict[str, Any]:
        """Remove a shared directory and optionally all file rows under it."""
        con = self._require_duckdb()
        root_text = self._normalize_path(directory)
        prefix = root_text.rstrip("\\/") + "\\"
        con.execute("BEGIN TRANSACTION")
        try:
            removed_files = 0
            if remove_files:
                removed_files = con.execute(
                    "SELECT COUNT(*) FROM shared_files WHERE starts_with(lower(path), lower(?))",
                    (prefix,),
                ).fetchone()[0]
                con.execute(
                    "DELETE FROM shared_files WHERE starts_with(lower(path), lower(?))",
                    (prefix,),
                )
            directory_row = con.execute(
                "SELECT path FROM shared_directories WHERE lower(path) = lower(?)",
                (root_text,),
            ).fetchone()
            con.execute(
                "DELETE FROM shared_directories WHERE lower(path) = lower(?)",
                (root_text,),
            )
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            log.exception(f"Shared directory removal rollback: path={root_text}")
            raise
        removed_directory = directory_row is not None
        result = {
            "directory": root_text,
            "directory_removed": removed_directory,
            "files_removed": remove_files,
            "removed_files": removed_files,
        }
        log.info(
            f"Removed shared directory: path={root_text}, "
            f"directory={removed_directory}, files={removed_files}"
        )
        return result

    def _normalize_path(self, path: str | Path) -> str:
        """Return a stable absolute path string for portable persistence."""
        return str(Path(path).expanduser().resolve())

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
