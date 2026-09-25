"""Golden parity test: lineage.py must reproduce fixtures/lineage_golden.jsonl exactly.

The Rust counterpart (crates/ml/tests/lineage_golden.rs) consumes the same file — if
either of the two tests breaks, one implementation has drifted from the other and the embedded
ONNX model would be scoring vectors inconsistent with its training.
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.features.lineage import FEATURE_NAMES, extract_features

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "lineage_golden.jsonl"


def golden_rows() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: r["name"])
def test_features_match_golden(row: dict) -> None:
    """Verify Rust/Python parity for each golden test case."""
    got = extract_features(row["event"])
    expected = row["features"]
    assert len(got) == len(expected) == len(FEATURE_NAMES)
    for name, g, e in zip(FEATURE_NAMES, got, expected, strict=True):
        assert g == pytest.approx(e, rel=1e-6, abs=1e-9), (
            f"feature {name!r} drifted for test case {row['name']!r}: {g} != {e} — "
            "check ml/tests/fixtures/lineage_golden.jsonl"
        )


def test_golden_covers_every_feature() -> None:
    """Every feature must be non-zero in at least one golden case — otherwise the file does
    not actually lock that column."""
    rows = golden_rows()
    for i, name in enumerate(FEATURE_NAMES):
        assert any(r["features"][i] != 0.0 for r in rows), f"no golden case exercises {name!r}"


def test_golden_covers_all_parent_types() -> None:
    """Ensure we have test cases for shells, webservers, and office apps."""
    rows = golden_rows()
    names = [r["name"] for r in rows]

    # Check coverage of key attack patterns
    assert any("bash" in name or "shell" in name for name in names), "missing shell parent tests"
    assert any("nginx" in name or "webserver" in name or "w3wp" in name for name in names), "missing webserver parent tests"
    assert any("winword" in name or "excel" in name or "office" in name for name in names), "missing office parent tests"
    assert any("system_path" in name for name in names), "missing system path tests"
    assert any("suspicious_path" in name for name in names), "missing suspicious path tests"


def test_golden_covers_case_insensitivity() -> None:
    """Case-insensitive matching is a critical parity point."""
    rows = golden_rows()
    assert any("case_insensitive" in r["name"] for r in rows), "no case-insensitive test cases"
