"""Tests for the `python -m synthaea_ml.data.manifest` CLI wrapper.

Kept in a separate module from `test_manifest.py` (which covers the underlying
dataclass and helper functions) so a reader can find the CLI surface in one
place. Every test exercises `_main()` directly rather than shelling out, so
the assertions run against the exact `argparse` parser this repo ships and
not a subprocess-mediated view of it.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import (
    DEFAULT_BASELINE_FILENAME,
    MANIFEST_FILENAME,
    _main,
    _parse_capture_time,
    load_manifest,
)

# --- fixtures --------------------------------------------------------------


def _baseline(dir_: Path, name: str = DEFAULT_BASELINE_FILENAME) -> Path:
    """Write a tiny 3-sample JSONL baseline into `dir_` and return its path."""
    p = dir_ / name
    p.write_text(
        '{"argv":["whoami"]}\n'
        '{"argv":["ls","-la"]}\n'
        '{"argv":["cat","/etc/hostname"]}\n',
        encoding="utf-8",
    )
    return p


def _run(*argv: str) -> tuple[int, str, str]:
    """Run `_main` with the given argv, capturing stdout/stderr and exit code.

    Argparse's own error path raises `SystemExit(2)` before we can return
    from `_main`; catching it here lets tests assert on both the return code
    and the message printed to stderr.
    """
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = _main(list(argv))
        except SystemExit as e:
            code = int(e.code) if e.code is not None else 0
    return code, stdout.getvalue(), stderr.getvalue()


# --- write happy paths -----------------------------------------------------


def test_write_happy_path_creates_manifest_json(tmp_path):
    _baseline(tmp_path)
    code, out, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "WSL2 Ubuntu 24.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
        "--capturer-ref", "test-run-1",
    )
    assert code == 0, err
    assert (tmp_path / MANIFEST_FILENAME).exists()
    manifest = load_manifest(tmp_path)
    assert manifest.platform == "linux"
    assert manifest.workload_label == "dev"
    assert manifest.sample_count == 3
    assert manifest.capturer_ref == "test-run-1"
    assert f"wrote {tmp_path / MANIFEST_FILENAME}" in out


def test_write_supports_baseline_filename_override(tmp_path):
    _baseline(tmp_path, name="baseline_benign.jsonl")
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
        "--baseline-filename", "baseline_benign.jsonl",
    )
    assert code == 0, err
    assert (tmp_path / MANIFEST_FILENAME).exists()
    manifest = load_manifest(tmp_path)
    assert manifest.sample_count == 3


def test_write_accepts_offset_timezone_not_only_z(tmp_path):
    _baseline(tmp_path)
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "server-idle",
        "--capture-start", "2026-09-14T11:00:00+02:00",
        "--capture-end", "2026-09-14T19:00:00+02:00",
    )
    assert code == 0, err
    manifest = load_manifest(tmp_path)
    # Times normalised to UTC on write, regardless of input offset.
    assert manifest.capture_start == "2026-09-14T09:00:00Z"
    assert manifest.capture_end == "2026-09-14T17:00:00Z"


# --- write error paths -----------------------------------------------------


def test_write_rejects_unknown_platform(tmp_path):
    _baseline(tmp_path)
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "solaris",
        "--os-version", "11",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    assert code == 2
    assert "solaris" in err or "invalid choice" in err


def test_write_rejects_unknown_workload_label(tmp_path):
    _baseline(tmp_path)
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dektop-user",  # typo
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    assert code == 2
    assert "dektop-user" in err or "invalid choice" in err


def test_write_rejects_naive_capture_time(tmp_path):
    _baseline(tmp_path)
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00",  # no timezone
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    assert code == 2
    # argparse wraps the ValueError from _parse_capture_time
    assert "timezone" in err.lower() or "invalid" in err.lower()


def test_write_reports_missing_baseline_as_operation_failure(tmp_path):
    # No baseline file at all — write_manifest raises FileNotFoundError,
    # which the CLI reports on stderr and returns 1 (operation failure,
    # not a usage error).
    code, _, err = _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    assert code == 1
    assert "baseline not found" in err.lower()


# --- verify --------------------------------------------------------------


def test_verify_happy_path(tmp_path):
    _baseline(tmp_path)
    _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    code, out, err = _run("verify", str(tmp_path))
    assert code == 0, err
    assert "ok" in out.lower()


def test_verify_detects_mutated_baseline(tmp_path):
    baseline = _baseline(tmp_path)
    _run(
        "write", str(tmp_path),
        "--platform", "linux",
        "--os-version", "22.04",
        "--workload-label", "dev",
        "--capture-start", "2026-09-14T09:00:00Z",
        "--capture-end", "2026-09-14T17:00:00Z",
    )
    # Mutate content without regenerating the manifest.
    baseline.write_text('{"argv":["evil"]}\n', encoding="utf-8")
    code, _, err = _run("verify", str(tmp_path))
    assert code == 1
    assert "hash mismatch" in err.lower() or "sample count" in err.lower()


def test_verify_reports_missing_manifest_as_operation_failure(tmp_path):
    _baseline(tmp_path)
    # No manifest.json written — verify_manifest raises FileNotFoundError.
    code, _, err = _run("verify", str(tmp_path))
    assert code == 1
    assert "manifest not found" in err.lower()


# --- _parse_capture_time unit tests ---------------------------------------


def test_parse_capture_time_requires_timezone():
    with pytest.raises(ValueError, match="timezone"):
        _parse_capture_time("2026-09-14T09:00:00")


def test_parse_capture_time_accepts_z_suffix():
    dt = _parse_capture_time("2026-09-14T09:00:00Z")
    assert dt.utcoffset().total_seconds() == 0


def test_parse_capture_time_accepts_offset_suffix():
    dt = _parse_capture_time("2026-09-14T09:00:00+02:00")
    assert dt.utcoffset().total_seconds() == 0  # normalised to UTC
    assert dt.hour == 7
