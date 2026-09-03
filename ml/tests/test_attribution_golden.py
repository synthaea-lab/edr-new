"""Attribution parity seam, Python side: recompute the committed golden fixture with
the reference implementation and require an exact-ish match. The Rust side asserts the
same file (`crates/ml/tests/attribution_golden.rs`); a failure on either side means
the two implementations have drifted — fix the drift, do not regenerate the fixture
unless the semantic change is deliberate on both sides.
"""

import json
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("onnx")

from attribution_reference import attribute, load_forest

FIXTURES = Path(__file__).resolve().parents[2] / "crates" / "ml" / "tests" / "fixtures"
TOL = 1e-9


def test_reference_matches_golden():
    golden = json.loads((FIXTURES / "attribution_golden.json").read_text())
    forest = load_forest(str(FIXTURES / golden["model"]))
    assert len(forest.trees) == golden["n_trees"]
    assert forest.n_features == golden["n_features"]
    for i, case in enumerate(golden["cases"]):
        contributions, depth, expected_depth = attribute(forest, case["x"])
        assert contributions == pytest.approx(case["contributions"], abs=TOL), f"case {i}"
        assert depth == pytest.approx(case["depth"], abs=TOL), f"case {i}"
        assert expected_depth == pytest.approx(case["expected_depth"], abs=TOL), f"case {i}"


def test_decomposition_telescopes():
    golden = json.loads((FIXTURES / "attribution_golden.json").read_text())
    forest = load_forest(str(FIXTURES / golden["model"]))
    for case in golden["cases"]:
        contributions, depth, expected_depth = attribute(forest, case["x"])
        assert sum(contributions) == pytest.approx(expected_depth - depth, abs=TOL)
