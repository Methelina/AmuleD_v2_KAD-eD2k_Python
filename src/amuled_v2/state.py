"""DuckDB-backed runtime state for AmuleD_v2.

Provides the portable persistence layer for schema metadata, imported servers,
static servers, shared-file metadata, and shared directories.  A small JSON
store remains available only as a bootstrap fallback when DuckDB is absent.
The shared repository supports direct scanning transactions so removed or
missing files do not leave stale rows behind.

src/amuled_v2/state.py
Version:     0.6.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.6.0 (Soror L.'.L'.):
  [+] Added schema migration 4 for persisted search results.
  [+] Added search-result save, listing, filtering, and clearing.
  [*] Repeated source rows now update last_seen instead of resetting it.
  [+] Added source expiry, pruning, forgetting, and statistics.

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
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from amuled_v2.logging_setup import LogTags, get_tagged_logger
from amuled_v2.paths import DB_FILE, STATE_JSON, ensure_runtime_dirs

log = get_tagged_logger(LogTags.STATE, "state")

if TYPE_CHECKING:
    from amuled_v2.core.ed2k import FoundSources, SearchResultsBatch, ServerRecord, StaticServer
    from amuled_v2.core.sharing import SharedFile

try:
    import duckdb  # type: ignore[import-untyped]
    _HAS_DUCKDB = True
except ImportError:  # pragma: no cover - exercised only without DuckDB
    _HAS_DUCKDB = False

_CURRENT_SCHEMA_VERSION = 6
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


def _migrate_v4(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS search_results (
            query           VARCHAR NOT NULL,
            channel         VARCHAR NOT NULL,
            file_hash       VARCHAR NOT NULL,
            name            VARCHAR NOT NULL,
            size            BIGINT NOT NULL,
            sources         INTEGER NOT NULL,
            complete_sources INTEGER NOT NULL,
            server          VARCHAR NOT NULL,
            tags            VARCHAR,
            client_id       UINTEGER,
            client_port     UINTEGER,
            first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (query, channel, file_hash)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS search_sessions (
            session_id      VARCHAR PRIMARY KEY,
            query           VARCHAR NOT NULL,
            channel         VARCHAR NOT NULL,
            server          VARCHAR NOT NULL,
            started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result_count    INTEGER NOT NULL DEFAULT 0,
            active          BOOLEAN NOT NULL DEFAULT TRUE
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (4)"
    )


def _open_duckdb_with_retry(database: Path, *, attempts: int = 20, delay: float = 1.0) -> Any:
    """Open DuckDB, retrying briefly when another process still holds the lock.

    Killed CLI runs can leave the database file locked for a few seconds on
    Windows; retrying is friendlier than failing the whole command.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return duckdb.connect(str(database))
        except Exception as exc:  # duckdb.IOException and friends
            last_error = exc
            if attempt < attempts - 1:
                log.warning(
                    "DuckDB lock retry: attempt=%d, delay=%.1fs, error=%s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)
    raise RuntimeError(f"cannot open DuckDB state {database}: {last_error}") from last_error


def _migrate_v5(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            file_hash      VARCHAR PRIMARY KEY,
            name           VARCHAR NOT NULL,
            size           BIGINT NOT NULL,
            part_path      VARCHAR NOT NULL,
            status         VARCHAR NOT NULL,
            downloaded     BIGINT NOT NULL DEFAULT 0,
            created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (5)"
    )


def _migrate_v6(con: Any) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS server_blacklist (
            ip             VARCHAR NOT NULL,
            port           UINTEGER NOT NULL,
            failures       INTEGER NOT NULL DEFAULT 0,
            last_error     VARCHAR,
            blacklisted_at TIMESTAMP,
            blacklisted_until TIMESTAMP,
            updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ip, port)
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (6)"
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
        current = 3
    if current < 4:
        _migrate_v4(con)
        log.info("DuckDB schema migrated to version 4")
        current = 4
    if current < 5:
        _migrate_v5(con)
        log.info("DuckDB schema migrated to version 5")
        current = 5
    if current < 6:
        _migrate_v6(con)
        log.info("DuckDB schema migrated to version 6")
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
            self._con = _open_duckdb_with_retry(DB_FILE)
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

    def save_search_results_batch(
        self,
        batch: "SearchResultsBatch",
        *,
        persist_tags: bool = True,
    ) -> int:
        """Persist one accumulated search batch; repeated hits update last_seen."""
        con = self._require_duckdb()
        server_text = f"{batch.server_host}:{batch.server_port}"
        count = 0
        for result in batch.results:
            tags_json = None
            if persist_tags:
                tags_json = json.dumps(
                    [tag.to_dict() for tag in result.tags],
                    ensure_ascii=False,
                )
            con.execute(
                """
                INSERT INTO search_results (
                    query, channel, file_hash, name, size, sources,
                    complete_sources, server, tags, client_id, client_port
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (query, channel, file_hash) DO UPDATE SET
                    name      = excluded.name,
                    size      = excluded.size,
                    sources   = excluded.sources,
                    complete_sources = excluded.complete_sources,
                    server    = excluded.server,
                    tags      = excluded.tags,
                    client_id = excluded.client_id,
                    client_port = excluded.client_port,
                    last_seen = get_current_timestamp()
                """,
                (
                    batch.query,
                    batch.channel,
                    result.file_hash.hex().upper(),
                    result.name,
                    result.size,
                    result.sources,
                    result.complete_sources,
                    server_text,
                    tags_json,
                    result.client_id,
                    result.client_port,
                ),
            )
            count += 1
        con.execute(
            """
            INSERT INTO search_sessions (
                session_id, query, channel, server, result_count, active
            ) VALUES (?, ?, ?, ?, ?, FALSE)
            ON CONFLICT (session_id) DO UPDATE SET
                last_activity = get_current_timestamp(),
                result_count  = search_sessions.result_count + excluded.result_count
            """,
            (
                batch.session_id,
                batch.query,
                batch.channel,
                server_text,
                len(batch.results),
            ),
        )
        log.info(
            "Saved search results to state: query=%r, channel=%s, saved=%d, "
            "session=%s",
            batch.query,
            batch.channel,
            count,
            batch.session_id,
        )
        return count

    def list_servers(self) -> list[dict[str, Any]]:
        """List persisted ED2K servers for UDP global search."""
        con = self._require_duckdb()
        rows = con.execute(
            """
            SELECT ip, port, address, name FROM servers
            ORDER BY priority DESC, users DESC, name
            """
        ).fetchall()
        return [
            {
                "ip": row[0],
                "port": row[1],
                "address": row[2],
                "name": row[3],
            }
            for row in rows
        ]

    def list_search_results(
        self,
        *,
        query: str | None = None,
        channel: str | None = None,
        hash_prefix: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List persisted search results with optional filters."""
        con = self._require_duckdb()
        if limit < 0:
            raise ValueError("limit must be non-negative")
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append("lower(query) = lower(?)")
            params.append(query)
        if channel:
            conditions.append("channel = ?")
            params.append(channel)
        if hash_prefix:
            prefix = hash_prefix.strip().lower()
            if not prefix or any(c not in "0123456789abcdef" for c in prefix):
                raise ValueError("hash prefix must contain hexadecimal digits")
            conditions.append("starts_with(lower(file_hash), ?)")
            params.append(prefix)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        rows = con.execute(
            f"""
            SELECT query, channel, file_hash, name, size, sources,
                   complete_sources, server, first_seen, last_seen
            FROM search_results
            {where}
            ORDER BY last_seen DESC, lower(name)
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            {
                "query": row[0],
                "channel": row[1],
                "hash": row[2],
                "name": row[3],
                "size": row[4],
                "sources": row[5],
                "complete_sources": row[6],
                "server": row[7],
                "first_seen": str(row[8]),
                "last_seen": str(row[9]),
            }
            for row in rows
        ]

    def get_search_result_tags(self, file_hash: str) -> list[dict[str, Any]]:
        """Return stored full tag dictionaries for one result hash."""
        normalized = file_hash.strip().lower()
        if len(normalized) != 32:
            raise ValueError("file hash must contain 32 hexadecimal digits")
        bytes.fromhex(normalized)
        con = self._require_duckdb()
        rows = con.execute(
            "SELECT tags FROM search_results WHERE lower(file_hash) = ?",
            (normalized,),
        ).fetchall()
        tags: list[dict[str, Any]] = []
        for (tags_json,) in rows:
            if not tags_json:
                continue
            decoded = json.loads(tags_json)
            if isinstance(decoded, list):
                tags.extend(item for item in decoded if isinstance(item, dict))
        return tags

    def clear_search_results(
        self,
        *,
        query: str | None = None,
    ) -> int:
        """Delete cached search results, optionally scoped to one query."""
        con = self._require_duckdb()
        if query:
            removed = con.execute(
                "SELECT COUNT(*) FROM search_results WHERE lower(query) = lower(?)",
                (query,),
            ).fetchone()[0]
            con.execute(
                "DELETE FROM search_results WHERE lower(query) = lower(?)",
                (query,),
            )
            con.execute(
                "DELETE FROM search_sessions WHERE lower(query) = lower(?)",
                (query,),
            )
        else:
            removed = con.execute("SELECT COUNT(*) FROM search_results").fetchone()[0]
            con.execute("DELETE FROM search_results")
            con.execute("DELETE FROM search_sessions")
        log.info("Cleared search results: query=%r, removed=%d", query, removed)
        return removed

    def list_search_sessions(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List recorded search sessions, newest first."""
        con = self._require_duckdb()
        rows = con.execute(
            """
            SELECT session_id, query, channel, server, started_at,
                   last_activity, result_count, active
            FROM search_sessions
            ORDER BY last_activity DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "session_id": row[0],
                "query": row[1],
                "channel": row[2],
                "server": row[3],
                "started_at": str(row[4]),
                "last_activity": str(row[5]),
                "result_count": row[6],
                "active": row[7],
            }
            for row in rows
        ]

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
                INSERT INTO file_sources (
                    file_hash, client_id, client_port, source_type,
                    server_ip, server_port, user_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (file_hash, client_id, client_port, source_type) DO UPDATE SET
                    server_ip   = excluded.server_ip,
                    server_port = excluded.server_port,
                    user_hash   = excluded.user_hash,
                    last_seen   = get_current_timestamp()
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

    def forget_file_sources(self, file_hash: str) -> int:
        """Delete all persisted source rows for one ED2K file hash."""
        normalized = file_hash.strip().lower()
        if len(normalized) != 32:
            raise ValueError("file hash must contain 32 hexadecimal digits")
        bytes.fromhex(normalized)
        con = self._require_duckdb()
        removed = con.execute(
            "SELECT COUNT(*) FROM file_sources WHERE lower(file_hash) = ?",
            (normalized,),
        ).fetchone()[0]
        con.execute(
            "DELETE FROM file_sources WHERE lower(file_hash) = ?",
            (normalized,),
        )
        log.info("Forgot file sources: hash=%s, removed=%d", normalized, removed)
        return removed

    def prune_file_sources(
        self,
        *,
        max_age_hours: float | None = None,
        dead_only: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Delete expired or dead source rows.

        Rows are expired when ``last_seen`` is older than *max_age_hours*.
        Dead sources are low-id rows (``client_id`` below the high-id
        threshold) that have not been seen again within *max_age_hours* as
        well; with ``dead_only`` only those are removed.
        """
        con = self._require_duckdb()
        age_hours = max_age_hours if max_age_hours is not None else 24 * 7
        if age_hours <= 0:
            raise ValueError("max_age_hours must be positive")
        cutoff = datetime.now() - timedelta(hours=age_hours)
        if dead_only:
            conditions = (
                "last_seen < ? AND client_id < 16000000",
            )
            params: list[Any] = [cutoff]
        else:
            conditions = "last_seen < ?"
            params = [cutoff]
        counted = con.execute(
            f"SELECT COUNT(*) FROM file_sources WHERE {conditions}",
            params,
        ).fetchone()[0]
        if dry_run or counted == 0:
            return {
                "matched": counted,
                "pruned": 0 if dry_run else counted,
                "dry_run": dry_run,
                "max_age_hours": age_hours,
                "dead_only": dead_only,
            }
        con.execute(f"DELETE FROM file_sources WHERE {conditions}", params)
        log.info(
            "Pruned file sources: matched=%d, max_age_hours=%s, dead_only=%s",
            counted,
            age_hours,
            dead_only,
        )
        return {
            "matched": counted,
            "pruned": counted,
            "dry_run": False,
            "max_age_hours": age_hours,
            "dead_only": dead_only,
        }

    def get_source_statistics(self) -> dict[str, Any]:
        """Return aggregate source counts for status reporting."""
        con = self._require_duckdb()
        total, distinct_files = con.execute(
            "SELECT COUNT(*), COUNT(DISTINCT file_hash) FROM file_sources"
        ).fetchone()
        row = con.execute(
            """
            SELECT source_type, COUNT(*) FROM file_sources
            GROUP BY source_type ORDER BY source_type
            """
        ).fetchall()
        by_type = {kind: count for kind, count in row}
        high_id, low_id = con.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE client_id >= 16000000),
                COUNT(*) FILTER (WHERE client_id < 16000000)
            FROM file_sources
            """
        ).fetchone()
        return {
            "total_sources": total,
            "distinct_files": distinct_files,
            "by_type": by_type,
            "high_id_sources": high_id,
            "low_id_sources": low_id,
        }

    def add_download(
        self,
        *,
        file_hash: str,
        name: str,
        size: int,
        part_path: str,
        status: str,
    ) -> None:
        """Insert one queued download row."""
        con = self._require_duckdb()
        con.execute(
            """
            INSERT INTO downloads (
                file_hash, name, size, part_path, status, downloaded
            ) VALUES (?, ?, ?, ?, ?, 0)
            """,
            (file_hash.upper(), name, size, part_path, status),
        )
        log.info(
            "Added download: hash=%s, name=%r, size=%d, status=%s",
            file_hash,
            name,
            size,
            status,
        )

    def get_download(self, file_hash: str) -> dict[str, Any] | None:
        con = self._require_duckdb()
        row = con.execute(
            """
            SELECT file_hash, name, size, part_path, status, downloaded,
                   created_at, updated_at
            FROM downloads WHERE lower(file_hash) = ?
            """,
            (file_hash.lower(),),
        ).fetchone()
        if row is None:
            return None
        return {
            "hash": row[0],
            "name": row[1],
            "size": row[2],
            "part_path": row[3],
            "status": row[4],
            "downloaded": row[5],
            "created_at": str(row[6]),
            "updated_at": str(row[7]),
        }

    def list_downloads(self, *, limit: int = 100) -> list[dict[str, Any]]:
        con = self._require_duckdb()
        rows = con.execute(
            """
            SELECT file_hash, name, size, part_path, status, downloaded,
                   created_at, updated_at
            FROM downloads
            ORDER BY created_at, file_hash
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "hash": row[0],
                "name": row[1],
                "size": row[2],
                "part_path": row[3],
                "status": row[4],
                "downloaded": row[5],
                "created_at": str(row[6]),
                "updated_at": str(row[7]),
            }
            for row in rows
        ]

    def set_download_status(self, file_hash: str, status: str) -> bool:
        con = self._require_duckdb()
        con.execute(
            """
            UPDATE downloads
            SET status = ?, updated_at = get_current_timestamp()
            WHERE lower(file_hash) = ?
            """,
            (status, file_hash.lower()),
        )
        return con.execute(
            "SELECT COUNT(*) FROM downloads WHERE lower(file_hash) = ?",
            (file_hash.lower(),),
        ).fetchone()[0] > 0

    def update_download_progress(
        self,
        file_hash: str,
        *,
        downloaded_bytes: int,
        status: str,
    ) -> None:
        con = self._require_duckdb()
        con.execute(
            """
            UPDATE downloads
            SET downloaded = ?, status = ?, updated_at = get_current_timestamp()
            WHERE lower(file_hash) = ?
            """,
            (downloaded_bytes, status, file_hash.lower()),
        )

    def remove_download(self, file_hash: str) -> bool:
        con = self._require_duckdb()
        existed = con.execute(
            "SELECT COUNT(*) FROM downloads WHERE lower(file_hash) = ?",
            (file_hash.lower(),),
        ).fetchone()[0] > 0
        con.execute(
            "DELETE FROM downloads WHERE lower(file_hash) = ?",
            (file_hash.lower(),),
        )
        return existed

    def record_server_failure(
        self,
        ip: str,
        port: int,
        *,
        reason: str,
        threshold: int = 3,
        cooldown_hours: float = 0.5,
    ) -> bool:
        """Increment one server's failure count; blacklist at threshold.

        Returns True when this call put the server on the blacklist.
        """
        con = self._require_duckdb()
        con.execute(
            """
            INSERT INTO server_blacklist (ip, port, failures, last_error, updated_at)
            VALUES (?, ?, 1, ?, get_current_timestamp())
            ON CONFLICT (ip, port) DO UPDATE SET
                failures = CASE
                    WHEN server_blacklist.blacklisted_until IS NOT NULL
                         AND server_blacklist.blacklisted_until > get_current_timestamp()
                    THEN server_blacklist.failures
                    WHEN server_blacklist.blacklisted_until IS NOT NULL
                         AND server_blacklist.blacklisted_until <= get_current_timestamp()
                    THEN 1
                    ELSE server_blacklist.failures + 1
                END,
                last_error = excluded.last_error,
                updated_at = get_current_timestamp()
            """,
            (ip, port, reason),
        )
        failures = con.execute(
            "SELECT failures FROM server_blacklist WHERE ip = ? AND port = ?",
            (ip, port),
        ).fetchone()[0]
        if failures >= threshold:
            until = datetime.now() + timedelta(hours=cooldown_hours)
            con.execute(
                """
                UPDATE server_blacklist
                SET blacklisted_at = get_current_timestamp(),
                    blacklisted_until = ?
                WHERE ip = ? AND port = ?
                """,
                (until, ip, port),
            )
            log.warning(
                "Server blacklisted: ip=%s, port=%d, failures=%d, "
                "cooldown_hours=%s, reason=%s",
                ip,
                port,
                failures,
                cooldown_hours,
                reason,
            )
            return True
        return False

    def record_server_success(self, ip: str, port: int) -> None:
        """Clear one server's failure history after a working exchange."""
        con = self._require_duckdb()
        con.execute(
            "DELETE FROM server_blacklist WHERE ip = ? AND port = ?",
            (ip, port),
        )

    def list_blacklisted_servers(self) -> list[dict[str, Any]]:
        """Return currently blacklisted servers."""
        con = self._require_duckdb()
        rows = con.execute(
            """
            SELECT ip, port, failures, last_error, blacklisted_until
            FROM server_blacklist
            WHERE blacklisted_until IS NOT NULL
              AND blacklisted_until > ?
            ORDER BY blacklisted_until
            """,
            (datetime.now(),),
        ).fetchall()
        return [
            {
                "ip": row[0],
                "port": row[1],
                "failures": row[2],
                "last_error": row[3],
                "blacklisted_until": str(row[4]),
            }
            for row in rows
        ]

    def list_server_failures(self) -> list[dict[str, Any]]:
        """Return all tracked servers with their failure counts."""
        con = self._require_duckdb()
        rows = con.execute(
            """
            SELECT ip, port, failures, last_error, updated_at
            FROM server_blacklist
            ORDER BY failures DESC, updated_at DESC
            """
        ).fetchall()
        return [
            {
                "ip": row[0],
                "port": row[1],
                "failures": row[2],
                "last_error": row[3],
                "updated_at": str(row[4]),
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
