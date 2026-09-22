"""Trains an Isolation Forest on the correlation vectors (2nd ML scorer) and exports it to ONNX.

SKELETON — waiting for the first real dataset: `ml/data/correlation_train.jsonl`,
produced by `aggregate_correlation.py` from an `edr-cli capture-events` lab session
(~10-15 min of normal activity). See `docs/design/design-correlation-ml-vector.md`.

Scorer **distinct** from the cmdline scorer (`train_linux.py` / `train.py`): never the same
model file, never merged into a single feature space (decision of 2026-08-27). Output:
`ml/model_correlation.onnx`, loaded on the Rust side by a future `CorrelationScorer` (not yet
written) then injected as an LLR term into the correlator's `update_belief()` (architecture to
be validated with Florian).

Choices to settle on real data (provisional values below):
  - `contamination`: 0.01-0.02 anticipated — the behavioral counts of a normal process are
    close to zero and tightly clustered, the benign cluster should separate better than on the
    text features (which run at 0.05). To be confirmed on the real baseline.
  - threshold: conformal calibration (issue #46) — computes threshold from FP budget once
    real baselines are available.
  - agent gate: do not score a vector with `event_count < 3` (nearly empty window) — applied
    on the Rust side, not at training time.

Usage: `python3 train_correlation.py`  (venv `ml/.venv`: scikit-learn / skl2onnx / onnx).
"""

import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from synthaea_ml.calibration import calibrate_threshold, compute_feature_bounds
from synthaea_ml.features.correlation import FEATURE_NAMES

DATA_PATH = Path(__file__).parent / "data" / "correlation_train.jsonl"
MODEL_PATH = Path(__file__).parent / "model_correlation.onnx"
METADATA_PATH = Path(__file__).parent / "model_correlation_metadata.json"

CONTAMINATION = 0.02  # provisional — see docstring
MIN_EVENT_COUNT_GATE = 3  # documentation for the Rust scorer, not applied here
EVENT_COUNT_IDX = FEATURE_NAMES.index("event_count")

# Conformal calibration parameters (issue #46) — provisional until real baselines
FP_BUDGET_PER_ENDPOINT_DAY = 5.0
BENIGN_RATE_PER_DAY = 1000.0  # Estimated processes scored per day
FEATURE_BOUNDS_MARGIN = 0.05

# Sanity check — synthetic vectors, until we have real lab samples.
SANITY_CHECK_SAMPLES = {
    # spawn_count, connect_count, filewrite_count, uniq_daddr, uniq_dport,
    # has_full_chain, span_s, event_count
    "benign (quiet process)": [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0],
    "benign (network client)": [1.0, 2.0, 0.0, 1.0, 1.0, 0.0, 3.0, 3.0],
    "suspicious (full dropper)": [1.0, 4.0, 3.0, 1.0, 2.0, 1.0, 1.5, 8.0],
    "suspicious (multi-dest scan)": [1.0, 20.0, 0.0, 15.0, 15.0, 0.0, 4.0, 21.0],
}


def load_dataset() -> np.ndarray:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} not found — run a capture (`edr-cli capture-events`) "
            "then `python aggregate_correlation.py`."
        )
    vecs = []
    for line in DATA_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            vecs.append(json.loads(line)["features"])
    if not vecs:
        raise ValueError(f"{DATA_PATH} is empty.")
    return np.array(vecs, dtype=np.float32)


def main() -> None:
    X = load_dataset()
    print(
        f"Training set: {X.shape[0]} vectors × {X.shape[1]} features ({', '.join(FEATURE_NAMES)})"
    )

    # Split 70/30 for conformal calibration (issue #46)
    X_train, X_cal = train_test_split(X, test_size=0.3, random_state=42)
    print(f"Split: {len(X_train)} training, {len(X_cal)} calibration")

    clf = IsolationForest(n_estimators=100, contamination=CONTAMINATION, random_state=42)
    clf.fit(X_train)

    # Conformal calibration: compute threshold for FP budget
    conformal_cal = calibrate_threshold(
        clf,
        X_cal,
        fp_budget=FP_BUDGET_PER_ENDPOINT_DAY,
        benign_rate_per_day=BENIGN_RATE_PER_DAY,
    )
    print(
        f"Conformal calibration: threshold={conformal_cal.threshold:.4f} "
        f"for ≤{FP_BUDGET_PER_ENDPOINT_DAY} FP/endpoint/day"
    )

    # Compute feature bounds for OOD detection
    bounds = compute_feature_bounds(
        X_train,
        list(FEATURE_NAMES),
        margin=FEATURE_BOUNDS_MARGIN,
    )
    print(f"Feature bounds computed with {FEATURE_BOUNDS_MARGIN*100}% margin")

    # Same skl2onnx/onnx pin as train_linux.py / train.py — see their comment.
    onnx_model = to_onnx(clf, X_train[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    MODEL_PATH.write_bytes(onnx_model.SerializeToString())
    print(f"Model exported → {MODEL_PATH}")

    # Export metadata for Rust scorer (issue #46)
    metadata = {
        "threshold": conformal_cal.threshold,
        "feature_bounds": {
            "feature_names": bounds.feature_names,
            "min_values": bounds.min_values,
            "max_values": bounds.max_values,
        },
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Metadata exported: {METADATA_PATH}")

    print("\nSanity check (scikit-learn):")
    for label, vec in SANITY_CHECK_SAMPLES.items():
        feats = np.array([vec], dtype=np.float32)
        score = clf.decision_function(feats)[0]
        verdict = "ANOMALY" if clf.predict(feats)[0] == -1 else "normal"
        print(f"  {label}: score={score:+.3f} -> {verdict}")

    print(
        f"\nRust scorer reminder: do not score if feature[{EVENT_COUNT_IDX}] "
        f"(event_count) < {MIN_EVENT_COUNT_GATE}."
    )


if __name__ == "__main__":
    main()
