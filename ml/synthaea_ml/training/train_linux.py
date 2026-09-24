"""Trains an Isolation Forest on the benign Linux baseline and exports it to ONNX.

Dedicated second model, mirroring `train_windows.py`: one model per OS, no mixing
Linux+Windows in a single score space (statistical dilution rather than real
calibration - see `docs/PLAN.md`).

Input contract: a **baseline directory** (`--dataset`) containing:

- `baseline.jsonl`: one exec record per line, `{"argv": [...]}` on Linux.
- `manifest.json`: the sidecar written by `synthaea_ml.data.manifest` - see PR #170
  in the #44 stack.

The manifest is verified before training runs; a mutated baseline is rejected here,
not silently baked into a model card. After training, `model.onnx` and `training.json`
are written to `--output-dir` (a registry version directory). Rule 3 of
`ml/README.md` (a registry model can be rebuilt from its recorded dataset versions)
is enforced by these two writes together.

Usage:
    python -m synthaea_ml.training.train_linux \\
        --dataset ml/datasets/baselines/linux__dev__abc__2026-09-11/ \\
        --output-dir ml/registry/cmdline-iforest-linux/0.2.0/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from synthaea_ml.calibration import (
    calibrate_threshold,
    compute_feature_bounds,
)
from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.data.manifest import DEFAULT_BASELINE_FILENAME
from synthaea_ml.features.cmdline import FEATURE_NAMES, extract_features
from synthaea_ml.registry.training_record import (
    dataset_version_from_manifest,
    write_training_record,
)

TRAINING_SCRIPT = "synthaea_ml/training/train_linux.py"
MODEL_FILENAME = "model.onnx"
METADATA_FILENAME = "model_metadata.json"

# Conformal calibration parameters (issue #46)
FP_BUDGET_PER_ENDPOINT_DAY = 5.0
"""Maximum acceptable false positives per endpoint per day."""

BENIGN_RATE_PER_DAY = 1000.0
"""Estimated benign events per endpoint per day (for FP rate conversion).

This is a conservative estimate — production endpoints may see more or fewer
events depending on workload. The threshold can be recalibrated when larger
baselines become available (#44).
"""

FEATURE_BOUNDS_MARGIN = 0.05
"""Relative margin for feature bounds (5% expansion beyond observed min/max)."""

# contamination=0.05, a deliberate decision after testing 0.02 (see this file's git
# history). At 0.02, the curl healthcheck false positive disappeared but the ML signal on
# a short, real malicious case (the isolated `base64 -d` exec event, captured in the lab
# on 2026-08-24: cmdline = "base64\0-d\0") collapsed to nearly zero (score -0.001, versus
# -0.035 at 0.05) - with only 71 baseline examples, the model's boundary is too fuzzy to
# eliminate this false positive without losing the signal on the true positive. Explicit
# choice: keep a sharp ML signal on the malicious case rather than a silent ML on a
# benign one, especially since this scenario is intercepted anyway by the deterministic
# T1059.004 rule regardless of the ML score (see threat-model.md - ML is never the final
# judge). The curl healthcheck false positive at 0.05 thus remains a known and accepted
# limitation (already documented before these features were added, see docs/PLAN.md).
HYPERPARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "contamination": 0.05,
    "random_state": 42,
}

# Linux sanity check - mirror of SANITY_CHECK_SAMPLES on the Windows side.
# Benign: taken as-is from the captured baseline. Suspicious: the isolated `base64 -d`
# exec event captured in the lab on 2026-08-24 (see the contamination comment above)
# and the Docker healthcheck documented as a known false positive (docs/PLAN.md) -
# included here to track it, not because it necessarily has to score as an anomaly.
SANITY_CHECK_SAMPLES = {
    "benign (whoami)": "whoami\0",
    "benign (lab script)": "bash\0/tmp/benign_activity.sh\0",
    "benign (modprobe)": "/sbin/modprobe\0-q\0--\0binfmt-0090\0",
    "suspicious (base64 decode)": "base64\0-d\0",
    "known FP (curl health)": "curl\0-f\0http://backend:8000/api/health/\0",
}


def load_baseline(baseline_dir: Path) -> list[str]:
    """Load `baseline_dir/baseline.jsonl` and rebuild the NUL-terminated representation
    `extract_features` expects (identical to `ExecEvent::ml_cmdline` on the Rust side).

    Deduplication is by cmdline string: a process that runs 10 000 times adds one
    sample, so the boundary stays representative rather than being dragged toward the
    most repeated command line.
    """
    baseline_path = baseline_dir / DEFAULT_BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline not found: {baseline_path}")

    cmdlines: list[str] = []
    for line in baseline_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cmdlines.append(ml_cmdline_from_record(json.loads(line)))

    seen: set[str] = set()
    unique: list[str] = []
    for c in cmdlines:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    print(f"Baseline: {len(cmdlines)} entries -> {len(unique)} unique after deduplication")
    return unique


def _run_sanity_check(clf: IsolationForest) -> None:
    """Print the sanity-check scores. Not a gate - the ONNX parity check that
    `verify_onnx` runs against the shipped model is the real one - but a quick sniff
    test that the training loss did not collapse the boundary to a single sign."""
    print("\nSanity check (scikit-learn, before ONNX loading on the Rust side):")
    for label, cmdline in SANITY_CHECK_SAMPLES.items():
        feats = np.array([extract_features(cmdline)], dtype=np.float32)
        score = clf.decision_function(feats)[0]
        pred = clf.predict(feats)[0]
        verdict = "ANOMALY" if pred == -1 else "normal"
        print(f"  {label}: score={score:+.3f} -> {verdict}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        nargs="+",
        help=(
            "One or more baseline directories (each contains baseline.jsonl + "
            "manifest.json). Multiple datasets concatenate their samples and "
            "each shows up as its own DatasetVersion in the training record."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Registry version directory (model.onnx + training.json are written here).",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Verify each manifest before touching anything else. A mutated baseline is
    # rejected here (raises ValueError from verify_manifest) rather than silently
    # producing a model that points at a dataset version it was not trained on.
    dataset_versions = [dataset_version_from_manifest(d) for d in args.dataset]

    cmdlines: list[str] = []
    for d in args.dataset:
        cmdlines.extend(load_baseline(d))
    # Dedupe once across the concatenated samples so a command line seen in two
    # captures does not double-weight the boundary.
    cmdlines = list(dict.fromkeys(cmdlines))
    print(f"Concatenated & re-deduped across {len(args.dataset)} dataset(s): {len(cmdlines)} unique samples")

    X = np.array([extract_features(c) for c in cmdlines], dtype=np.float32)

    # Split 70/30 for conformal calibration (issue #46)
    X_train, X_cal = train_test_split(X, test_size=0.3, random_state=42)
    print(f"Split: {len(X_train)} training, {len(X_cal)} calibration")

    clf = IsolationForest(**HYPERPARAMETERS)
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

    # skl2onnx 1.20 does not yet follow the `ai.onnx.ml` v4 domain emitted by default
    # with onnx 1.22 - explicitly pinned to the latest version this skl2onnx can consume.
    onnx_model = to_onnx(clf, X_train[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    model_path = args.output_dir / MODEL_FILENAME
    model_path.write_bytes(onnx_model.SerializeToString())

    # Export metadata for Rust scorer (issue #46)
    metadata = {
        "threshold": conformal_cal.threshold,
        "feature_bounds": {
            "feature_names": bounds.feature_names,
            "min_values": bounds.min_values,
            "max_values": bounds.max_values,
        },
    }
    metadata_path = args.output_dir / METADATA_FILENAME
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Metadata exported: {metadata_path}")

    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=dataset_versions,
        hyperparameters=HYPERPARAMETERS,
        conformal_calibration=conformal_cal,
        feature_bounds=bounds,
    )

    print(f"Model trained on {len(cmdlines)} benign examples -> {args.output_dir}")

    _run_sanity_check(clf)


if __name__ == "__main__":
    main()
