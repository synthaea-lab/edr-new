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

from synthaea_ml.data.manifest import DEFAULT_BASELINE_FILENAME
from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.registry.training_record import (
    dataset_version_from_manifest,
    write_training_record,
)

TRAINING_SCRIPT = "synthaea_ml/training/train_windows.py"
MODEL_FILENAME = "model.onnx"

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

    clf = IsolationForest(**HYPERPARAMETERS)
    clf.fit(X)

    # skl2onnx 1.20 does not yet follow the `ai.onnx.ml` v4 domain emitted by default
    # with onnx 1.22 - explicitly pinned to the latest version this skl2onnx can consume.
    onnx_model = to_onnx(clf, X[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    model_path = args.output_dir / MODEL_FILENAME
    model_path.write_bytes(onnx_model.SerializeToString())

    write_training_record(
        args.output_dir,
        training_script=TRAINING_SCRIPT,
        dataset_versions=dataset_versions,
        hyperparameters=HYPERPARAMETERS,
    )

    print(f"Model trained on {len(cmdlines)} benign examples -> {args.output_dir}")

    _run_sanity_check(clf)


if __name__ == "__main__":
    main()
