"""Capture-format parity (issue #109), Python side: `aggregate_correlation` must
reproduce `fixtures/capture_correlation_golden.jsonl` from `fixtures/capture_events.jsonl`.

The Rust counterpart is `crates/ml/tests/capture_parity.rs`. If either breaks, the
agent's `events.jsonl` and the trainer disagree on the correlation vector. Regenerate
with `fixtures/gen_capture_parity.py` only on a deliberate format change.
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.data.aggregate_correlation import charger_events, vecteurs_par_pid

FIXTURES = Path(__file__).resolve().parent / "fixtures"
S = 1_000_000_000


def golden_rows() -> list[dict]:
    path = FIXTURES / "capture_correlation_golden.jsonl"
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: f"pid{r['pid']}")
def test_vectors_match_golden(row: dict) -> None:
    events = charger_events(FIXTURES / "capture_events.jsonl")
    vectors = {v["pid"]: v["features"] for v in vecteurs_par_pid(events, 60 * S, 1)}
    assert row["pid"] in vectors
    got = vectors[row["pid"]]
    assert len(got) == len(row["features"])
    for g, e in zip(got, row["features"], strict=True):
        assert g == pytest.approx(e, rel=1e-6, abs=1e-9)
