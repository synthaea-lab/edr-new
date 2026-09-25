"""Tests for conformal calibration (issue #46)."""

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from synthaea_ml.calibration import (
    calibrate_threshold,
    compute_feature_bounds,
)


def test_threshold_at_target_percentile():
    """Conformal threshold should match the target FP rate percentile."""
    # Generate synthetic calibration set
    np.random.seed(42)
    X_cal = np.random.randn(100, 5).astype(np.float32)

    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X_cal)  # Fit on same data for simplicity (real training uses 70/30 split)

    # Target: 5 FP per 1000 events/day → 0.5% FP rate → 0.5th percentile
    cal = calibrate_threshold(clf, X_cal, fp_budget=5.0, benign_rate_per_day=1000.0)

    # Check threshold is at approximately the 0.5th percentile of scores
    scores = clf.decision_function(X_cal)
    expected = np.percentile(scores, 0.5)

    assert cal.threshold == pytest.approx(expected, abs=1e-4)
    assert cal.fp_budget_per_endpoint_day == 5.0
    assert cal.benign_baseline_rate == 1000.0
    assert cal.calibration_set_size == 100


def test_fp_budget_conversion():
    """Different FP budgets should produce different thresholds."""
    np.random.seed(42)
    X_cal = np.random.randn(100, 5).astype(np.float32)

    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X_cal)

    # Tighter budget → lower percentile → lower threshold (more rejections)
    cal_tight = calibrate_threshold(clf, X_cal, fp_budget=1.0, benign_rate_per_day=1000.0)
    cal_loose = calibrate_threshold(clf, X_cal, fp_budget=10.0, benign_rate_per_day=1000.0)

    # Tighter budget should have lower threshold (reject more)
    assert cal_tight.threshold < cal_loose.threshold


def test_bounds_with_margin():
    """Feature bounds should expand beyond observed min/max by the margin."""
    X = np.array(
        [
            [0.0, 10.0],
            [2.0, 20.0],
            [4.0, 30.0],
        ],
        dtype=np.float32,
    )
    feature_names = ["length", "entropy"]

    bounds = compute_feature_bounds(X, feature_names, margin=0.1)

    # Feature 0: min=0, max=4, range=4, margin=10% → bounds [-0.4, 4.4]
    assert bounds.min_values[0] == pytest.approx(-0.4, abs=1e-5)
    assert bounds.max_values[0] == pytest.approx(4.4, abs=1e-5)

    # Feature 1: min=10, max=30, range=20, margin=10% → bounds [8, 32]
    assert bounds.min_values[1] == pytest.approx(8.0, abs=1e-5)
    assert bounds.max_values[1] == pytest.approx(32.0, abs=1e-5)

    assert bounds.feature_names == ["length", "entropy"]


def test_bounds_constant_feature():
    """Constant features (zero range) should not cause division by zero."""
    X = np.array(
        [
            [5.0, 10.0],
            [5.0, 20.0],
            [5.0, 30.0],
        ],
        dtype=np.float32,
    )
    feature_names = ["constant", "varying"]

    bounds = compute_feature_bounds(X, feature_names, margin=0.1)

    # Constant feature: range=0, margin fallback to 1.0 → bounds [4.9, 5.1]
    assert bounds.min_values[0] == pytest.approx(4.9, abs=1e-5)
    assert bounds.max_values[0] == pytest.approx(5.1, abs=1e-5)


def test_bounds_feature_names_mismatch():
    """Mismatched feature_names length should raise ValueError."""
    X = np.array([[1.0, 2.0, 3.0]], dtype=np.float32)
    feature_names = ["a", "b"]  # Only 2 names, but X has 3 columns

    with pytest.raises(ValueError, match="feature_names length.*must match"):
        compute_feature_bounds(X, feature_names, margin=0.05)
