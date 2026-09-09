"""Trains an Isolation Forest on the benign Linux baseline and exports it to ONNX.

Dedicated second model, mirroring `train.py` (Windows) — see its docstring for context:
one model per OS, no mixing Linux+Windows in a single score space (statistical dilution
rather than real calibration). `ml/data/baseline_benign.jsonl` (71 lines, real capture in a
WSL2 lab, week 8, see `capture_to_baseline.py`) had been waiting for this script since
2026-08-27 (see git blame of `train.py`).

Input format differs from the Windows baseline: `{"argv": [...]}` (list of tokens), not
`{"cmdline": "..."}`. Rebuilt here through `synthaea_ml.data.canonical.cmdline_str` into
the same NUL-terminated representation as `schema::ExecEvent::ml_cmdline` on the Rust
side, so `extract_features` (shared with `train.py`) produces the vectors the agent
scores at runtime.

Usage: `python3 train_linux.py` (from a venv with scikit-learn/skl2onnx/onnx/onnxruntime
installed — see `ml/.venv`).
"""

import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.features.cmdline import extract_features

DATA_PATH_LINUX = Path(__file__).parent / "data" / "baseline_benign.jsonl"
MODEL_PATH = Path(__file__).parent / "model_linux.onnx"

# Linux sanity check — mirror of SANITY_CHECK_SAMPLES on the Windows side (train.py).
# Benign: taken as-is from the captured baseline. Suspicious: the isolated `base64 -d` exec
# event captured in the lab on 2026-08-24 (see the contamination comment in train.py) and the
# Docker healthcheck documented as a known false positive (docs/PLAN.md) — included here to
# track it, not because it necessarily has to score as an anomaly.
SANITY_CHECK_SAMPLES = {
    "benign (whoami)": "whoami\0",
    "benign (lab script)": "bash\0/tmp/benign_activity.sh\0",
    "benign (modprobe)": "/sbin/modprobe\0-q\0--\0binfmt-0090\0",
    "suspicious (base64 decode)": "base64\0-d\0",
    "known FP (curl health)": "curl\0-f\0http://backend:8000/api/health/\0",
}


def load_baseline() -> list[str]:
    """Loads the Linux baseline — one exec record per line (`{"argv": [...]}`, or
    `{"cmdline": "..."}` for the Windows fallback) — and rebuilds the NUL-terminated
    representation `extract_features` expects, identical to `ExecEvent::ml_cmdline` on
    the Rust side."""
    if not DATA_PATH_LINUX.exists():
        raise FileNotFoundError(f"Linux baseline not found: {DATA_PATH_LINUX}")

    cmdlines = []
    for line in DATA_PATH_LINUX.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cmdlines.append(ml_cmdline_from_record(json.loads(line)))

    # Deduplication — keep unique cmdlines only.
    seen = set()
    unique = []
    for c in cmdlines:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    print(f"Baseline: {len(cmdlines)} entries → {len(unique)} unique after deduplication")
    return unique


def main() -> None:
    cmdlines = load_baseline()
    X = np.array([extract_features(c) for c in cmdlines], dtype=np.float32)

    # contamination=0.05 — same value as the Windows model (train.py), for the same reason:
    # with a baseline example count of the same order of magnitude (71 here, 66-137 on the
    # Windows side), a lower contamination (0.02) would drown the signal on short true
    # positives (e.g. an isolated `base64 -d`) with no real gain on false positives (the
    # Docker/containerd noise remains a known limitation anyway, see docs/PLAN.md).
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X)

    # Same pin as train.py — see its comment about skl2onnx/onnx.
    onnx_model = to_onnx(clf, X[:1], target_opset={"": 18, "ai.onnx.ml": 3})
    MODEL_PATH.write_bytes(onnx_model.SerializeToString())
    print(f"Model trained on {len(cmdlines)} benign examples, exported to {MODEL_PATH}")

    print("\nSanity check (scikit-learn, before ONNX loading on the Rust side):")
    for label, cmdline in SANITY_CHECK_SAMPLES.items():
        feats = np.array([extract_features(cmdline)], dtype=np.float32)
        score = clf.decision_function(feats)[0]
        pred = clf.predict(feats)[0]
        verdict = "ANOMALY" if pred == -1 else "normal"
        print(f"  {label}: score={score:+.3f} -> {verdict}")


if __name__ == "__main__":
    main()
