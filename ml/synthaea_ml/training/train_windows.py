"""Trains an Isolation Forest on the benign Windows baseline and exports it to ONNX.

**Windows-only model** (decision of 2026-08-27, see the Linux mirror train_linux.py's
docstring): one model per OS, no mixing Linux+Windows in a single score space
(statistical dilution rather than real calibration - see `docs/PLAN.md`). ML scores
remain an experimental complement anyway, never a final judge (see threat-model.md).

Input contract: a **baseline directory** (`--dataset`) containing:

- `baseline.jsonl`: one exec record per line, `{"cmdline": "C:\\Windows\\..."}` on
  Windows. ETW does not populate `argv[]`, so the flat cmdline string is used
  directly as one token.
- `manifest.json`: the sidecar written by `synthaea_ml.data.manifest` - see PR #170
  in the #44 stack.

The manifest is verified before training runs; a mutated baseline is rejected here,
not silently baked into a model card. After training, `model.onnx` and `training.json`
are written to `--output-dir` (a registry version directory). Rule 3 of
`ml/README.md` (a registry model can be rebuilt from its recorded dataset versions)
is enforced by these two writes together.

Usage:
    python -m synthaea_ml.training.train_windows \\
        --dataset ml/datasets/baselines/windows__desktop-user__abc__2026-09-11/ \\
        --output-dir ml/registry/cmdline-iforest-windows/0.2.0/
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
from synthaea_ml.data.manifest import DEFAULT_BASELINE_FILENAME
from synthaea_ml.evaluation.robustness import run_robustness_evaluation
from synthaea_ml.features.cmdline import FEATURE_NAMES, extract_features
from synthaea_ml.registry.training_record import (
    RobustnessCard,
    dataset_version_from_manifest,
    write_training_record,
)

TRAINING_SCRIPT = "synthaea_ml/training/train_windows.py"
MODEL_FILENAME = "model.onnx"
METADATA_FILENAME = "model_metadata.json"

# Conformal calibration parameters (issue #46)
FP_BUDGET_PER_ENDPOINT_DAY = 5.0
BENIGN_RATE_PER_DAY = 1000.0
FEATURE_BOUNDS_MARGIN = 0.05

# contamination=0.05 - same value as the Linux model (train_linux.py), for the same
# reason: with a baseline example count of the same order of magnitude, a lower
# contamination (0.02) would drown the ML signal on short true positives (e.g. an
# isolated `base64 -d`) with no real gain on false positives. See train_linux.py's
# HYPERPARAMETERS comment for the full decision context.
HYPERPARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "contamination": 0.05,
    "random_state": 42,
}

# Windows sanity check - distinguishes legitimate vs suspicious cmdlines.
# The benign cmdlines reflect the ETW format (full image path, few arguments).
# The malicious cmdlines simulate encoded payloads or suspicious paths (AppData).
#
# Also imported by synthaea_ml.export.verify_onnx as its parity oracle: keep the keys
# and shape stable, or update verify_onnx in the same change.
SANITY_CHECK_SAMPLES = {
    "benign (svchost)": "C:\\Windows\\System32\\svchost.exe",
    "benign (powershell)": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "suspicious (AppData)": (
        "C:\\Users\\solka\\AppData\\Roaming\\Microsoft\\WindowsApps\\RuntimeBroker.exe"
    ),
    "suspicious (base64 ps)": "powershell.exe -EncodedCommand ZWNobyBoZWxsbw==",
    "suspicious (Temp)": "C:\\Users\\solka\\AppData\\Local\\Temp\\payload.exe",
}


def load_baseline(baseline_dir: Path) -> list[str]:
    """Load `baseline_dir/baseline.jsonl` and return unique cmdlines.

    Windows baseline format is `{"cmdline": "C:\\\\Windows\\\\..."}` - the ETW-captured
    full image path, no argv splitting on this platform. Deduplication is by cmdline
    string: a process that runs 10 000 times adds one sample.
    """
    baseline_path = baseline_dir / DEFAULT_BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline not found: {baseline_path}")

    cmdlines: list[str] = []
    for line in baseline_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cmdlines.append(json.loads(line)["cmdline"])

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
    parser.add_argument(
        "--robustness-scenarios",
        type=Path,
        nargs="*",
        default=[],
        help="Optional scenario yamls for adversarial robustness evaluation (issue #45).",
    )
    parser.add_argument(
        "--robustness-events",
        type=Path,
        help=(
            "Optional events.jsonl or baseline.jsonl file for robustness evaluation. "
            "If provided, uses real events from this file instead of synthetic events."
        ),
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
    print(
        f"Concatenated & re-deduped across {len(args.dataset)} dataset(s): "
        f"{len(cmdlines)} unique samples"
    )

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

    # Run robustness evaluation if scenarios provided
    robustness_cards: list[RobustnessCard] = []
    if args.robustness_scenarios:
        print(f"\nRunning robustness evaluation on {len(args.robustness_scenarios)} scenario(s)...")
        if args.robustness_events:
            print(f"  Using events from: {args.robustness_events}")
        for scenario_path in args.robustness_scenarios:
            try:
                card = run_robustness_evaluation(
                    model=clf,
                    scenario_yaml=scenario_path,
                    tier="T0",
                    mutation_seed=42,
                    events_source=args.robustness_events,
                )
                robustness_cards.append(card)
                print(
                    f"  {card.scenario_name}: escape_rate={card.escape_rate:.2%}, "
                    f"median_degradation={card.median_score_degradation:+.3f}"
                )
            except Exception as e:
                print(f"  WARNING: robustness evaluation failed for {scenario_path}: {e}")

    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=dataset_versions,
        robustness_cards=robustness_cards,
        hyperparameters=HYPERPARAMETERS,
        conformal_calibration=conformal_cal,
        feature_bounds=bounds,
    )

    print(f"Model trained on {len(cmdlines)} benign examples -> {args.output_dir}")

    _run_sanity_check(clf)


if __name__ == "__main__":
    main()
