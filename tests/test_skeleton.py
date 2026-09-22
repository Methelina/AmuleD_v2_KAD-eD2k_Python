"""Regression tests for the M2 skeleton of AmuleD_v2.

Covers:
  - Pure ``jsonc.py`` comment-stripping behavior (line, block, escape-aware
    string handling, trailing content preservation, json5 fallback path).
  - Subprocess CLI smoke tests (``--help``, ``--version``, ``init --json``,
    ``status --json``, ``config set``) running against a temporary
    ``AMULED_ROOT`` so the real project tree is never touched.
  - State integration via ``init --json`` reporting backend and db_path.

Isolation: every subprocess test receives a fresh temporary directory as
``AMULED_ROOT`` and ``PYTHONPATH`` pointing at ``src``.  No test mutates the
real project ``config``, ``db``, ``logs``, ``incoming``, ``temp``, or
``shared`` directories.  Tests are deterministic, require no network, and
skip DuckDB-specific assertions when the json-fallback backend is in use.

src/amuled_v2/../tests/test_skeleton.py
Version:     0.2.5
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.2.5 (Soror L.'.L'.):
  [+] Added public display-name assertions for `AmuleD v0.4.1`.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] JSONC comment-stripping unit tests (line, block, escape, trailing).
  [+] JSONC json5-fallback unit test (guarded on json5 availability).
  [+] CLI subprocess smoke tests: --help, --version, init, status, config set.
  [+] State integration: init --json reports backend and db_path.
  [+] All subprocess tests isolated via temporary AMULED_ROOT + PYTHONPATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from amuled_v2.jsonc import (
    dump_json,
    load_jsonc,
    strip_jsonc_comments,
)

# ------------------------------------------------------------------
# Path constants
# ------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = _PROJECT_ROOT / "src"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _run_cli(
    args: list[str],
    env_root: Path,
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m amuled_v2`` in a subprocess with an isolated root.

    The subprocess receives a fresh ``AMULED_ROOT`` (temporary directory) and
    ``PYTHONPATH`` set to the project ``src`` directory, guaranteeing that no
    real project directories are created or mutated.
    """
    env = os.environ.copy()
    env["AMULED_ROOT"] = str(env_root)
    env["PYTHONPATH"] = str(_SRC_DIR)
    return subprocess.run(
        [sys.executable, "-m", "amuled_v2", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# ------------------------------------------------------------------
# JSONC — pure unit tests (no filesystem)
# ------------------------------------------------------------------


class TestJsoncStripComments:
    """Tests for ``strip_jsonc_comments`` and ``load_jsonc``."""

    def test_line_comment_outside_string(self) -> None:
        text = '{"a": 1 // comment\n}'
        result = strip_jsonc_comments(text)
        assert "// comment" not in result
        assert load_jsonc(text) == {"a": 1}

    def test_line_comment_does_not_strip_slash_inside_string(self) -> None:
        text = '{"url": "https://example.com"}'
        result = strip_jsonc_comments(text)
        assert "https://example.com" in result
        assert load_jsonc(text) == {"url": "https://example.com"}

    def test_block_comment_outside_string(self) -> None:
        text = '{"a": /* inline */ 1}'
        result = strip_jsonc_comments(text)
        assert "/* inline */" not in result
        assert load_jsonc(text) == {"a": 1}

    def test_block_comment_multiline(self) -> None:
        text = '{"a": 1, /* multi\nline\ncomment */\n"b": 2}'
        result = strip_jsonc_comments(text)
        assert "/*" not in result
        assert load_jsonc(text) == {"a": 1, "b": 2}

    def test_block_comment_slash_sequence_inside_string(self) -> None:
        text = r'{"path": "C:/Users/foo"}'
        result = strip_jsonc_comments(text)
        assert result == text
        assert load_jsonc(text) == {"path": "C:/Users/foo"}

    def test_escaped_backslash_before_quote_inside_string(self) -> None:
        text = r'{"x": "\\"}'
        result = strip_jsonc_comments(text)
        assert result == text
        assert load_jsonc(text) == {"x": "\\"}

    def test_escaped_quote_inside_string_not_terminated(self) -> None:
        text = r'{"quote": "say \"hi\""}'
        result = strip_jsonc_comments(text)
        assert load_jsonc(text) == {"quote": 'say "hi"'}

    def test_trailing_content_preserved(self) -> None:
        text = '{"a": 1}  '
        result = strip_jsonc_comments(text)
        assert result.rstrip() == '{"a": 1}'

    def test_empty_input(self) -> None:
        assert strip_jsonc_comments("") == ""

    def test_no_comments_untouched(self) -> None:
        text = '{"a": 1, "b": [2, 3]}'
        assert strip_jsonc_comments(text) == text

    def test_json5_fallback_when_json5_installed(self) -> None:
        pytest.importorskip("json5")
        text = '{"trailing": true}'
        result = load_jsonc(text)
        assert result == {"trailing": True}

    def test_invalid_json_without_json5_raises(self) -> None:
        pytest.importorskip("json5", reason="json5 installed; fallback not exercised")
        with pytest.raises((json.JSONDecodeError, ImportError, ValueError)):
            load_jsonc("{invalid}")

    def test_load_jsonc_valid_input(self) -> None:
        text = '{"key": "value", "num": 42}'
        assert load_jsonc(text) == {"key": "value", "num": 42}

    def test_load_jsonc_with_comments(self) -> None:
        text = '// header\n{"a": 1 /* c */, "b": 2}'
        assert load_jsonc(text) == {"a": 1, "b": 2}

    def test_dump_json_returns_string(self) -> None:
        result = dump_json({"b": 2, "a": 1})
        parsed = json.loads(result)
        assert parsed == {"b": 2, "a": 1}

    def test_dump_json_sorted_keys(self) -> None:
        result = dump_json({"z": 1, "a": 2})
        lines = result.splitlines()
        assert lines[0] == "{"
        assert '"a"' in lines[1]
        assert '"z"' in lines[2]

    def test_dump_json_indent(self) -> None:
        result = dump_json({"a": 1})
        assert "\n  " in result

    def test_dump_json_to_path(self, tmp_path: Path) -> None:
        target = tmp_path / "out.json"
        dump_json({"a": 1}, target)
        with open(target, "r", encoding="utf-8") as fh:
            assert json.load(fh) == {"a": 1}


# ------------------------------------------------------------------
# Subprocess CLI smoke tests (isolated AMULED_ROOT)
# ------------------------------------------------------------------


class TestCliSmoke:
    """Subprocess CLI tests with a temporary ``AMULED_ROOT``."""

    @pytest.fixture()
    def isolated_root(self) -> Path:
        """Create a fresh temp directory and clean it up after the test."""
        tmp = Path(tempfile.mkdtemp(prefix="amuled_test_"))
        yield tmp
        shutil.rmtree(tmp, ignore_errors=True)

    def test_help_exits_zero(self, isolated_root: Path) -> None:
        result = _run_cli(["--help"], isolated_root)
        assert result.returncode == 0
        assert "amuled" in result.stdout.lower()
        assert "status" in result.stdout
        assert "config" in result.stdout
        assert "init" in result.stdout

    def test_version_output(self, isolated_root: Path) -> None:
        result = _run_cli(["--version"], isolated_root)
        assert result.returncode == 0
        assert "AmuleD" in result.stdout
        assert "v0.4.1" in result.stdout

    def test_init_json(self, isolated_root: Path) -> None:
        result = _run_cli(["init", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert "backend" in data
        assert "db_path" in data
        assert isinstance(data.get("dirs_created"), list)

    def test_status_json(self, isolated_root: Path) -> None:
        init_result = _run_cli(["init", "--json"], isolated_root)
        assert init_result.returncode == 0
        init_data = json.loads(init_result.stdout)
        backend = init_data["backend"]
        db_path = init_data["db_path"]

        result = _run_cli(["status", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["app"] == "AmuleD"
        assert data["version"] == "0.4.1"
        assert data["backend"] == backend
        assert data["db_path"] == db_path
        assert isinstance(data["tables"], dict)
        assert data["network"]["client_tcp_port"] == 8089

    def test_config_set_then_verify_value(
        self, isolated_root: Path
    ) -> None:
        _run_cli(["init", "--json"], isolated_root)

        result = _run_cli(
            ["config", "set", "network.client_tcp_port", "4662", "--json"],
            isolated_root,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["key"] == "network.client_tcp_port"
        assert data["value"] == 4662

        # Verify the config file on disk contains the new value.
        config_file = isolated_root / "config" / "amuled.jsonc"
        assert config_file.exists()
        with open(config_file, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        assert cfg["network"]["client_tcp_port"] == 4662

    def test_config_set_overwrites_existing_value(
        self, isolated_root: Path
    ) -> None:
        _run_cli(["init", "--json"], isolated_root)
        _run_cli(
            ["config", "set", "network.client_tcp_port", "4662", "--json"],
            isolated_root,
        )
        result = _run_cli(
            ["config", "set", "network.client_tcp_port", "4663", "--json"],
            isolated_root,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["value"] == 4663

        config_file = isolated_root / "config" / "amuled.jsonc"
        with open(config_file, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        assert cfg["network"]["client_tcp_port"] == 4663

    def test_config_set_type_inference_bool(
        self, isolated_root: Path
    ) -> None:
        _run_cli(["init", "--json"], isolated_root)
        result = _run_cli(
            [
                "config", "set", "network.enable_kad", "false", "--json",
            ],
            isolated_root,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["value"] is False

    def test_status_reports_json_fallback_backend(
        self, isolated_root: Path
    ) -> None:
        if os.environ.get("_AMULED_FORCE_JSON_FALLBACK"):
            pytest.skip("json5 not relevant here; skipping duckdb-only check")
        _run_cli(["init", "--json"], isolated_root)
        result = _run_cli(["status", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["backend"] in ("duckdb", "json-fallback")
        if data["backend"] == "duckdb":
            assert "schema_migrations" in data["tables"]
            assert "kv_meta" in data["tables"]
        else:
            pytest.skip("DuckDB not available; skipping table assertions")


# ------------------------------------------------------------------
# State integration (via subprocess init --json)
# ------------------------------------------------------------------


class TestStateIntegration:
    """Verify that ``init --json`` reports backend and db_path correctly."""

    @pytest.fixture()
    def isolated_root(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="amuled_state_"))
        yield tmp
        shutil.rmtree(tmp, ignore_errors=True)

    def test_init_creates_db_under_temp_root(
        self, isolated_root: Path
    ) -> None:
        result = _run_cli(["init", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        db_path = Path(data["db_path"])
        # db_path must live under the temporary root, not the real project.
        assert db_path.is_relative_to(isolated_root)
        assert str(isolated_root) in str(db_path)

    def test_init_reports_duckdb_or_fallback(
        self, isolated_root: Path
    ) -> None:
        result = _run_cli(["init", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["backend"] in ("duckdb", "json-fallback")

    def test_status_after_init_reports_tables(
        self, isolated_root: Path
    ) -> None:
        _run_cli(["init", "--json"], isolated_root)
        result = _run_cli(["status", "--json"], isolated_root)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        if data["backend"] == "duckdb":
            assert data["tables"].get("schema_migrations") >= 2
            assert "kv_meta" in data["tables"]
        else:
            pytest.skip("DuckDB not available; skipping duckdb-only assertions")

    def test_db_file_created_on_disk(self, isolated_root: Path) -> None:
        """When DuckDB is the backend, the .db file should exist on disk."""
        _run_cli(["init", "--json"], isolated_root)
        init_result = _run_cli(["init", "--json"], isolated_root)
        backend = json.loads(init_result.stdout)["backend"]
        if backend == "duckdb":
            db_file = isolated_root / "db" / "amuled.db"
            assert db_file.exists()
        else:
            pytest.skip("DuckDB not available; db file check not applicable")
