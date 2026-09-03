"""Golden parity test: features.py must reproduce data/features_golden.jsonl exactly.

The Rust counterpart (crates/ml golden feature test) consumes the same file — if
either of the two tests breaks, one implementation has drifted from the other and the embedded
ONNX model would be scoring vectors inconsistent with its training. See generate_golden.py for
what to do.
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.features.cmdline import FEATURE_NAMES, extract_features

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "features_golden.jsonl"


def golden_rows() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: repr(r["cmdline"][:40]))
def test_features_match_golden(row: dict) -> None:
    got = extract_features(row["cmdline"])
    expected = row["features"]
    assert len(got) == len(expected) == len(FEATURE_NAMES)
    for name, g, e in zip(FEATURE_NAMES, got, expected, strict=True):
        assert g == pytest.approx(e, rel=1e-6, abs=1e-9), (
            f"feature {name!r} drifted for {row['cmdline']!r}: {g} != {e} — "
            "see tests/generate_golden.py"
        )


def test_golden_covers_every_feature() -> None:
    """Every feature must be non-zero in at least one golden case — otherwise the file does
    not actually lock that column."""
    rows = golden_rows()
    for i, name in enumerate(FEATURE_NAMES):
        assert any(r["features"][i] != 0.0 for r in rows), f"no golden case exercises {name!r}"


def test_golden_covers_non_ascii() -> None:
    """Non-ASCII cmdlines are the main parity pitfall (bytes vs characters,
    Unicode digits) — the golden file must contain some."""
    assert any(not r["cmdline"].isascii() for r in golden_rows())
