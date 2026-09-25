"""Split-conformal calibration for Isolation Forest models.

Maps a false positive budget (e.g., ≤5 FP/endpoint/day) to a decision_function
threshold via split-conformal prediction. Also computes per-feature bounds for
out-of-distribution (OOD) detection.

References:
    - Vovk et al. (2005): "Algorithmic Learning in a Random World" (conformal prediction)
    - Issue #46: Conformal FP-budget thresholds + OOD guards
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass(frozen=True)
class ConformalCalibration:
    """Conformal prediction calibration metadata.

    Records the threshold computed from a calibration set to meet a stated FP
    budget (e.g., ≤5 false positives per endpoint per day).
    """

    fp_budget_per_endpoint_day: float
    """Maximum acceptable false positives per endpoint per day (e.g., 5.0)."""

    threshold: float
    """decision_function threshold: anomaly if score < threshold."""

    calibration_set_size: int
    """Number of samples in the calibration set (30% of training data)."""

    benign_baseline_rate: float
    """Estimated benign events per endpoint per day (for FP rate conversion)."""

    calibrated_at: str
    """ISO 8601 UTC timestamp when calibration was performed."""


@dataclass(frozen=True)
class FeatureBounds:
    """Per-feature [min, max] bounds for out-of-distribution detection.

    Computed from the training set (70%) with a margin to avoid false OOD
    rejections on legitimate edge cases.
    """

    feature_names: list[str]
    """Feature names in order (must match model input)."""

    min_values: list[float]
    """Minimum allowed value per feature (inclusive)."""

    max_values: list[float]
    """Maximum allowed value per feature (inclusive)."""


def calibrate_threshold(
    model: IsolationForest,
    X_cal: np.ndarray,
    fp_budget: float,
    benign_rate_per_day: float,
) -> ConformalCalibration:
    """Compute a conformal threshold for a stated FP budget.

    Uses split-conformal prediction: score the calibration set and pick the
    threshold that yields the desired FP rate.

    Args:
        model: Trained Isolation Forest (fitted on 70% split).
        X_cal: Calibration feature matrix (30% holdout), shape (n_samples, n_features).
        fp_budget: Maximum acceptable false positives per endpoint per day (e.g., 5.0).
        benign_rate_per_day: Estimated benign events per endpoint per day (e.g., 1000.0).

    Returns:
        ConformalCalibration with the computed threshold and metadata.

    Example:
        >>> clf = IsolationForest(contamination=0.05, random_state=42)
        >>> clf.fit(X_train)
        >>> cal = calibrate_threshold(clf, X_cal, fp_budget=5.0, benign_rate_per_day=1000.0)
        >>> # Now use cal.threshold as the decision boundary: anomaly if score < threshold
    """
    scores = model.decision_function(X_cal)

    # Target FP rate: if benign_rate = 1000 events/day and fp_budget = 5,
    # we want to accept at most 5/1000 = 0.5% FP rate
    fp_rate = fp_budget / benign_rate_per_day

    # Conformal percentile: reject the lowest (fp_rate * 100)% of calibration scores
    # Example: fp_rate = 0.005 → percentile = 0.5 → threshold at 0.5th percentile
    # Scores below this threshold are anomalies
    percentile = fp_rate * 100.0

    # IsolationForest: negative scores = anomalous, positive = normal
    # We want the threshold such that (fp_rate * 100)% of benign samples score below it
    threshold = float(np.percentile(scores, percentile))

    return ConformalCalibration(
        fp_budget_per_endpoint_day=fp_budget,
        threshold=threshold,
        calibration_set_size=len(X_cal),
        benign_baseline_rate=benign_rate_per_day,
        calibrated_at=datetime.now(UTC).isoformat(),
    )


def compute_feature_bounds(
    X: np.ndarray,
    feature_names: list[str],
    margin: float = 0.05,
) -> FeatureBounds:
    """Compute per-feature [min, max] bounds with a margin.

    Args:
        X: Training feature matrix, shape (n_samples, n_features).
        feature_names: Feature names in order (must match X columns).
        margin: Relative margin to add beyond observed min/max (default 5%).
            A margin of 0.05 expands each feature's range by 5% on both sides
            to avoid false OOD rejections on legitimate edge cases.

    Returns:
        FeatureBounds with per-feature min/max arrays.

    Example:
        >>> bounds = compute_feature_bounds(X_train, FEATURE_NAMES, margin=0.05)
        >>> # Later, in Rust: reject vectors outside [min_values[i], max_values[i]]
    """
    if X.shape[1] != len(feature_names):
        raise ValueError(
            f"feature_names length ({len(feature_names)}) must match "
            f"X columns ({X.shape[1]})"
        )

    mins = X.min(axis=0)
    maxs = X.max(axis=0)
    ranges = maxs - mins

    # Expand bounds by margin (avoid division by zero for constant features)
    margin_abs = margin * np.where(ranges > 0, ranges, 1.0)

    return FeatureBounds(
        feature_names=list(feature_names),
        min_values=(mins - margin_abs).tolist(),
        max_values=(maxs + margin_abs).tolist(),
    )
