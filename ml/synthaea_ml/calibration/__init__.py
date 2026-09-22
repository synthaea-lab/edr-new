"""Calibration modules: Bayesian LLR (calibrate_llr) and conformal prediction (calibrate_conformal).

- calibrate_llr: T1 hand-calibrated LLRs for behavior vectors
- calibrate_conformal: Split-conformal FP-budget thresholds for ML models (issue #46)
"""

from synthaea_ml.calibration.calibrate_conformal import (
    ConformalCalibration,
    FeatureBounds,
    calibrate_threshold,
    compute_feature_bounds,
)

__all__ = [
    "ConformalCalibration",
    "FeatureBounds",
    "calibrate_threshold",
    "compute_feature_bounds",
]
