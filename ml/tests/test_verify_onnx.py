"""Tests for the platform dispatch in `synthaea_ml.export.verify_onnx`.

Before this dispatch existed, every registry model — Linux or Windows — was
sanity-checked against the Windows command-line samples, so a Linux model's
scores were uniformly (and misleadingly) negative: none of those tokens
belong in the Linux feature space. These tests lock the two signals
`sanity_samples_for` uses to pick the right sample set, and the precedence
between them (a `training.json` dataset platform wins over the legacy
directory-name convention).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from synthaea_ml.export.verify_onnx import VerificationError, sanity_samples_for
from synthaea_ml.registry.training_record import DatasetVersion, write_training_record
from synthaea_ml.training.train_linux import SANITY_CHECK_SAMPLES as LINUX_SAMPLES
from synthaea_ml.training.train_windows import SANITY_CHECK_SAMPLES as WINDOWS_SAMPLES


def _model_dir(tmp_path: Path, family: str, version: str = "0.1.0") -> Path:
    d = tmp_path / family / version
    d.mkdir(parents=True)
    return d


def _write_training_record(model_dir: Path, *, dataset_name: str) -> None:
    write_training_record(
        model_dir,
        training_script="synthaea_ml/training/train_linux.py",
        dataset_versions=[
            DatasetVersion(name=dataset_name, baseline_sha256="a" * 64, sample_count=10)
        ],
        trained_at=datetime(2026, 9, 15, tzinfo=UTC),
    )


# --- legacy entries: dispatch on the registry directory name ----------------


def test_legacy_linux_dir_gets_linux_samples(tmp_path: Path) -> None:
    model_dir = _model_dir(tmp_path, "cmdline-iforest-linux")
    assert sanity_samples_for(model_dir) == LINUX_SAMPLES


def test_legacy_windows_dir_gets_windows_samples(tmp_path: Path) -> None:
    model_dir = _model_dir(tmp_path, "cmdline-iforest-windows")
    assert sanity_samples_for(model_dir) == WINDOWS_SAMPLES


def test_unrecognized_dir_name_with_no_training_record_raises(tmp_path: Path) -> None:
    model_dir = _model_dir(tmp_path, "cmdline-iforest-mystery")
    with pytest.raises(VerificationError, match="cannot determine platform"):
        sanity_samples_for(model_dir)


# --- training.json present: dispatch on the dataset platform ----------------


def test_training_record_platform_is_used_when_present(tmp_path: Path) -> None:
    # Directory name gives no hint either way — only the training record does.
    model_dir = _model_dir(tmp_path, "cmdline-iforest-v2")
    _write_training_record(model_dir, dataset_name="linux__dev__abc123__2026-09-11")
    assert sanity_samples_for(model_dir) == LINUX_SAMPLES


def test_training_record_platform_wins_over_directory_name(tmp_path: Path) -> None:
    """The precedence this dispatch exists for: a `training.json` is ground
    truth about what the model was actually trained on, so it must win even
    when the (possibly stale or copy-pasted) directory name disagrees."""
    model_dir = _model_dir(tmp_path, "cmdline-iforest-linux")
    _write_training_record(model_dir, dataset_name="windows__dev__abc123__2026-09-11")
    assert sanity_samples_for(model_dir) == WINDOWS_SAMPLES


def test_training_record_with_unknown_platform_falls_back_to_directory_name(
    tmp_path: Path,
) -> None:
    model_dir = _model_dir(tmp_path, "cmdline-iforest-linux")
    _write_training_record(model_dir, dataset_name="macos__dev__abc123__2026-09-11")
    assert sanity_samples_for(model_dir) == LINUX_SAMPLES
