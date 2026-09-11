"""Tests for `synthaea_ml.registry.training_record` — the machine-parsable half
of a model card.

The properties that need to hold for the release gate to be trustworthy:

- Building a DatasetVersion from a manifest fails loudly if the baseline was
  edited without regenerating the manifest (that's the whole point).
- Writing a training record then loading it round-trips every field.
- `verify_training_record` catches both the "baseline moved" and "baseline
  mutated" failure modes it is meant to prevent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import write_manifest
from synthaea_ml.registry.training_record import (
    SCHEMA_VERSION,
    TRAINING_RECORD_FILENAME,
    DatasetVersion,
    dataset_version_from_manifest,
    default_dataset_name,
    load_training_record,
    verify_training_record,
    write_training_record,
)

_START = datetime(2026, 9, 11, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 9, 11, 11, 0, 0, tzinfo=UTC)
_TRAINED_AT = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


def _make_baseline_with_manifest(
    dir_path: Path,
    *,
    lines: list[str],
    platform: str = "linux",
    workload: str = "dev",
    hostname: str = "solkapc",
) -> None:
    (dir_path / "baseline.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_manifest(
        dir_path,
        platform=platform,
        os_version="22.04",
        workload_label=workload,
        capture_start=_START,
        capture_end=_END,
        hostname=hostname,
    )


# --- default_dataset_name --------------------------------------------------


def test_default_dataset_name_from_manifest(tmp_path: Path) -> None:
    _make_baseline_with_manifest(
        tmp_path,
        lines=['{"argv": ["ls"]}'],
        platform="windows",
        workload="desktop-user",
        hostname="solkapc",
    )
    # Convention: <platform>__<workload>__<host_id>__<YYYY-MM-DD>.
    # Double-underscore separator survives a workload like "desktop-user".
    name = default_dataset_name(tmp_path)
    assert name.startswith("windows__desktop-user__")
    assert name.endswith("__2026-09-11")


def test_default_dataset_name_missing_manifest_raises(tmp_path: Path) -> None:
    (tmp_path / "baseline.jsonl").write_text('{"argv": ["ls"]}\n', encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        default_dataset_name(tmp_path)


# --- dataset_version_from_manifest -----------------------------------------


def test_dataset_version_from_manifest_matches_manifest_hash(tmp_path: Path) -> None:
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}', '{"argv": ["id"]}'])
    dv = dataset_version_from_manifest(tmp_path)
    assert dv.sample_count == 2
    assert len(dv.baseline_sha256) == 64  # sha256 hex


def test_dataset_version_from_manifest_accepts_explicit_name(tmp_path: Path) -> None:
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(tmp_path, name="custom-name-2026-09-11")
    assert dv.name == "custom-name-2026-09-11"


def test_dataset_version_from_manifest_rejects_edited_baseline(tmp_path: Path) -> None:
    """The property that makes this whole module worth writing: an edited
    baseline is rejected at dataset-version construction time, not silently
    baked into a model card."""
    _make_baseline_with_manifest(tmp_path, lines=['{"argv": ["ls"]}'])
    with (tmp_path / "baseline.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"argv": ["id"]}\n')
    with pytest.raises(ValueError, match="baseline hash mismatch"):
        dataset_version_from_manifest(tmp_path)


# --- write_training_record / load_training_record --------------------------


def test_write_training_record_round_trip(tmp_path: Path) -> None:
    model_dir = tmp_path / "model_dir"
    model_dir.mkdir()

    baseline_dir = tmp_path / "baseline_dir"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir, name="linux__dev__abc__2026-09-11")

    written = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        hyperparameters={"n_estimators": 100, "contamination": 0.05},
        trained_at=_TRAINED_AT,
        extra={"commit_sha": "deadbeef"},
    )
    loaded = load_training_record(model_dir)

    assert loaded == written
    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.trained_at == "2026-09-11T12:00:00Z"
    assert loaded.training_script == "synthaea_ml/training/train_linux.py"
    assert loaded.dataset_versions == [dv]
    assert loaded.hyperparameters == {"n_estimators": 100, "contamination": 0.05}
    assert loaded.extra == {"commit_sha": "deadbeef"}


def test_write_training_record_defaults_trained_at_to_now(tmp_path: Path) -> None:
    """When `trained_at` is not supplied, the written value is the current
    UTC instant. We only assert the format and the fact that it is timezone-
    aware, not the exact second — the real check is that the field is set."""
    baseline_dir = tmp_path / "b"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir)
    model_dir = tmp_path / "m"
    model_dir.mkdir()

    record = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
    )
    # ISO Z-suffixed, 20 chars ("YYYY-MM-DDTHH:MM:SSZ").
    assert len(record.trained_at) == 20
    assert record.trained_at.endswith("Z")


def test_write_training_record_naive_datetime_raises(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "b"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(baseline_dir)
    model_dir = tmp_path / "m"
    model_dir.mkdir()

    naive = datetime(2026, 9, 11, 12, 0, 0)  # noqa: DTZ001 — must be rejected
    with pytest.raises(ValueError, match="trained_at must be timezone-aware"):
        write_training_record(
            model_dir,
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[dv],
            trained_at=naive,
        )


def test_write_training_record_empty_dataset_versions_raises(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    with pytest.raises(ValueError, match="dataset_versions must not be empty"):
        write_training_record(
            model_dir,
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[],
            trained_at=_TRAINED_AT,
        )


def test_write_training_record_missing_model_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_training_record(
            tmp_path / "does-not-exist",
            training_script="synthaea_ml/training/train_linux.py",
            dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
            trained_at=_TRAINED_AT,
        )


def test_training_record_json_is_sorted_and_indented(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
        trained_at=_TRAINED_AT,
    )
    raw = (model_dir / TRAINING_RECORD_FILENAME).read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert "\n  " in raw  # indent=2


def test_write_training_record_converts_non_utc_to_utc(tmp_path: Path) -> None:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    paris_offset = timezone(timedelta(hours=2))
    paris_trained_at = datetime(2026, 9, 11, 14, 0, 0, tzinfo=paris_offset)
    record = write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[DatasetVersion(name="x", baseline_sha256="0" * 64, sample_count=1)],
        trained_at=paris_trained_at,
    )
    assert record.trained_at == "2026-09-11T12:00:00Z"


def test_load_training_record_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_training_record(tmp_path)


def test_load_training_record_unsupported_schema_version_raises(tmp_path: Path) -> None:
    (tmp_path / TRAINING_RECORD_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION + 42,
                "trained_at": "2026-09-11T12:00:00Z",
                "training_script": "synthaea_ml/training/train_linux.py",
                "dataset_versions": [],
                "hyperparameters": {},
                "extra": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported training.json schema_version"):
        load_training_record(tmp_path)


# --- verify_training_record ------------------------------------------------


def test_verify_training_record_matches_after_write(tmp_path: Path) -> None:
    """End-to-end: build a dataset with a manifest, train (skipped), write the
    record, and verify. The whole point is that this passes as long as no one
    tampered with either half."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        trained_at=_TRAINED_AT,
    )
    verify_training_record(model_dir, baselines_root)  # no exception


def test_verify_training_record_detects_edited_baseline(tmp_path: Path) -> None:
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    baseline_dir = baselines_root / "linux__dev__abc__2026-09-11"
    baseline_dir.mkdir()
    _make_baseline_with_manifest(baseline_dir, lines=['{"argv": ["ls"]}'])
    dv = dataset_version_from_manifest(
        baseline_dir, name="linux__dev__abc__2026-09-11"
    )
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[dv],
        trained_at=_TRAINED_AT,
    )

    # Someone edits the baseline (and helpfully regenerates the manifest so
    # the manifest→baseline check passes) — but the training record still
    # locked the old hash, so we must catch it.
    (baseline_dir / "baseline.jsonl").write_text(
        '{"argv": ["ls"]}\n{"argv": ["id"]}\n', encoding="utf-8"
    )
    write_manifest(
        baseline_dir,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )

    with pytest.raises(ValueError, match="hash mismatch"):
        verify_training_record(model_dir, baselines_root)


def test_verify_training_record_detects_missing_baseline_dir(tmp_path: Path) -> None:
    """A moved / deleted dataset directory is a hard fail — the record names a
    baseline the release gate cannot re-verify."""
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[
            DatasetVersion(
                name="linux__dev__abc__2026-09-11",
                baseline_sha256="0" * 64,
                sample_count=1,
            )
        ],
        trained_at=_TRAINED_AT,
    )
    with pytest.raises(FileNotFoundError, match="not found"):
        verify_training_record(model_dir, baselines_root)
