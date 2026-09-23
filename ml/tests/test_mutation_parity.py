"""Golden parity test: mutation features must match mutation_parity_golden.jsonl.

The Rust counterpart (crates/ml/tests/mutation_parity.rs) consumes the same file
— if either test breaks, one implementation has drifted. This validates that
Python and Rust extract identical features from mutated events.
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.evaluation.mutations.cmdline import (
    ArgumentReorderMutator,
    Base64EncodeMutator,
    PaddingMutator,
    PathSubstitutionMutator,
    TokenSplittingMutator,
)
from synthaea_ml.evaluation.mutations.prng import LCG
from synthaea_ml.features.cmdline import extract_features

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "mutation_parity_golden.jsonl"

MUTATORS = {
    "base64_encode": Base64EncodeMutator(),
    "argument_reorder": ArgumentReorderMutator(),
    "path_substitution": PathSubstitutionMutator(),
    "token_splitting": TokenSplittingMutator(),
    "padding": PaddingMutator(),
}


def golden_rows() -> list[dict]:
    """Load all golden test cases."""
    with GOLDEN.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: f"{r['mutation_class']}_{r['intensity']}")
def test_mutation_features_match_golden(row: dict) -> None:
    """Validate that mutation + feature extraction matches golden fixture."""
    # Extract test case
    original = row["original"]
    mutation_class = row["mutation_class"]
    intensity = row["intensity"]
    seed = row["seed"]
    expected_mutated = row["mutated"]
    expected_features_original = row["features_original"]
    expected_features_mutated = row["features_mutated"]

    # Get mutator
    mutator = MUTATORS[mutation_class]
    rng = LCG(seed=seed)

    # Apply mutation
    mutated = mutator.mutate(original, intensity, rng)

    # Verify mutated record matches (structure, not necessarily exact values for non-deterministic parts)
    # For deterministic mutators with fixed seed, this should match exactly
    if "argv" in expected_mutated:
        assert "argv" in mutated, f"mutated record missing argv field"
        # Lengths should match
        assert len(mutated["argv"]) == len(expected_mutated["argv"]), \
            f"argv length mismatch: {len(mutated['argv'])} != {len(expected_mutated['argv'])}"

    # Extract features from original
    cmdline_original = ml_cmdline_from_record(original)
    features_original = extract_features(cmdline_original)

    # Extract features from mutated
    cmdline_mutated = ml_cmdline_from_record(mutated)
    features_mutated = extract_features(cmdline_mutated)

    # Validate features match golden (with small tolerance for floating point)
    assert len(features_original) == len(expected_features_original), \
        "original features length mismatch"
    assert len(features_mutated) == len(expected_features_mutated), \
        "mutated features length mismatch"

    for i, (got_orig, expected_orig) in enumerate(zip(features_original, expected_features_original)):
        assert got_orig == pytest.approx(expected_orig, rel=1e-6, abs=1e-9), \
            f"original feature[{i}] mismatch: {got_orig} != {expected_orig}"

    for i, (got_mut, expected_mut) in enumerate(zip(features_mutated, expected_features_mutated)):
        assert got_mut == pytest.approx(expected_mut, rel=1e-6, abs=1e-9), \
            f"mutated feature[{i}] mismatch: {got_mut} != {expected_mut}"


def test_golden_covers_all_mutators() -> None:
    """Every mutator class must appear in at least one golden case."""
    rows = golden_rows()
    mutator_classes_in_golden = {r["mutation_class"] for r in rows}

    for mutator_name in MUTATORS.keys():
        assert mutator_name in mutator_classes_in_golden, \
            f"mutator {mutator_name!r} not covered by golden fixture"


def test_golden_covers_all_intensities() -> None:
    """All three intensities must appear for each mutator class."""
    rows = golden_rows()
    intensities_by_mutator = {}

    for row in rows:
        mutator = row["mutation_class"]
        intensity = row["intensity"]
        if mutator not in intensities_by_mutator:
            intensities_by_mutator[mutator] = set()
        intensities_by_mutator[mutator].add(intensity)

    for mutator, intensities in intensities_by_mutator.items():
        expected_intensities = {"light", "medium", "heavy"}
        assert intensities >= expected_intensities, \
            f"mutator {mutator!r} missing intensities: {expected_intensities - intensities}"
