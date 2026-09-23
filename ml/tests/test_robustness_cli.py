"""Tests for robustness CLI (robustness_cli.py)."""

import json
from pathlib import Path

import pytest

from synthaea_ml.evaluation.robustness_cli import _find_previous_version, verify_robustness
from synthaea_ml.registry.training_record import (
    DatasetVersion,
    MutationTestResult,
    RobustnessCard,
    TrainingRecord,
)


def _create_test_record_with_robustness(
    scenario_name: str = "test_scenario",
    escape_rate: float = 0.10,
) -> TrainingRecord:
    """Helper to create a TrainingRecord with robustness card."""
    mutation_result = MutationTestResult(
        mutation_class="base64_encode",
        intensity="light",
        original_score=-0.1,
        mutated_score=0.05,
        score_delta=0.15,
        threshold=0.0,
        escaped=True,
        seed=42,
    )

    robustness_card = RobustnessCard(
        scenario_name=scenario_name,
        scenario_yaml_sha256="abc" * 21 + "d",
        tested_at="2026-09-23T10:00:00Z",
        mutation_results=[mutation_result],
        escape_rate=escape_rate,
        median_score_degradation=0.10,
        worst_case_degradation=0.15,
    )

    dataset_version = DatasetVersion(
        name="test_dataset",
        baseline_sha256="def" * 21 + "e",
        sample_count=100,
    )

    return TrainingRecord(
        schema_version=3,
        trained_at="2026-09-23T10:00:00Z",
        training_script="test.py",
        dataset_versions=[dataset_version],
        robustness_cards=[robustness_card],
    )


def test_find_previous_version(tmp_path: Path) -> None:
    """Test finding previous version directory."""
    # Create version directories
    registry_dir = tmp_path / "cmdline-iforest-linux"
    registry_dir.mkdir()

    (registry_dir / "0.1.0").mkdir()
    (registry_dir / "0.2.0").mkdir()
    (registry_dir / "0.2.1").mkdir()
    (registry_dir / "0.3.0").mkdir()

    # Test finding previous patch version
    prev = _find_previous_version(registry_dir / "0.2.1")
    assert prev == registry_dir / "0.2.0"

    # Test finding previous minor version
    prev = _find_previous_version(registry_dir / "0.3.0")
    # Should find 0.2.* (latest patch in previous minor)
    assert prev is not None
    assert prev.name.startswith("0.2")

    # Test no previous version
    prev = _find_previous_version(registry_dir / "0.1.0")
    assert prev is None


def test_verify_robustness_pass(tmp_path: Path, capsys) -> None:
    """Test verify_robustness passes with good metrics."""
    model_dir = tmp_path / "model"
    model_dir.mkdir()

    record = _create_test_record_with_robustness(escape_rate=0.08)
    record_path = model_dir / "model_record.json"
    record_path.write_text(json.dumps(record.to_dict()), encoding="utf-8")

    result = verify_robustness(model_dir, max_escape_rate=0.15, max_median_degradation=0.20)

    assert result is True
    captured = capsys.readouterr()
    assert "PASS" in captured.out
    assert "8.00%" in captured.out  # escape rate


def test_verify_robustness_fail_escape_rate(tmp_path: Path, capsys) -> None:
    """Test verify_robustness fails when escape rate exceeds threshold."""
    model_dir = tmp_path / "model"
    model_dir.mkdir()

    record = _create_test_record_with_robustness(escape_rate=0.20)
    record_path = model_dir / "model_record.json"
    record_path.write_text(json.dumps(record.to_dict()), encoding="utf-8")

    result = verify_robustness(model_dir, max_escape_rate=0.15, max_median_degradation=0.20)

    assert result is False
    captured = capsys.readouterr()
    assert "FAIL" in captured.out
    assert "20.00%" in captured.out  # escape rate


def test_verify_robustness_regression(tmp_path: Path, capsys) -> None:
    """Test regression checking between versions."""
    registry_dir = tmp_path / "cmdline-iforest-linux"
    registry_dir.mkdir()

    # Create previous version (0.1.0) with 8% escape rate
    prev_dir = registry_dir / "0.1.0"
    prev_dir.mkdir()
    prev_record = _create_test_record_with_robustness(escape_rate=0.08)
    (prev_dir / "model_record.json").write_text(
        json.dumps(prev_record.to_dict()), encoding="utf-8"
    )

    # Create current version (0.2.0) with 10% escape rate (2% increase, within threshold)
    curr_dir = registry_dir / "0.2.0"
    curr_dir.mkdir()
    curr_record = _create_test_record_with_robustness(escape_rate=0.10)
    (curr_dir / "model_record.json").write_text(
        json.dumps(curr_record.to_dict()), encoding="utf-8"
    )

    # Should pass (2% increase < 5% threshold)
    result = verify_robustness(curr_dir, no_regression=True, max_regression_increase=0.05)
    assert result is True
    captured = capsys.readouterr()
    assert "Regression check" in captured.out
    assert "8.00% → 10.00%" in captured.out


def test_verify_robustness_regression_fail(tmp_path: Path, capsys) -> None:
    """Test regression check fails when escape rate increases too much."""
    registry_dir = tmp_path / "cmdline-iforest-linux"
    registry_dir.mkdir()

    # Create previous version with 8% escape rate
    prev_dir = registry_dir / "0.1.0"
    prev_dir.mkdir()
    prev_record = _create_test_record_with_robustness(escape_rate=0.08)
    (prev_dir / "model_record.json").write_text(
        json.dumps(prev_record.to_dict()), encoding="utf-8"
    )

    # Create current version with 20% escape rate (12% increase, exceeds threshold)
    curr_dir = registry_dir / "0.2.0"
    curr_dir.mkdir()
    curr_record = _create_test_record_with_robustness(escape_rate=0.20)
    (curr_dir / "model_record.json").write_text(
        json.dumps(curr_record.to_dict()), encoding="utf-8"
    )

    # Should fail (12% increase > 5% threshold)
    result = verify_robustness(curr_dir, no_regression=True, max_regression_increase=0.05)
    assert result is False
    captured = capsys.readouterr()
    assert "REGRESSION" in captured.out
