"""Trains an Isolation Forest on the benign baseline and exports it to ONNX.

**Windows only for now, decision of 2026-08-27.** Mixing Linux+Windows in a single model
(done for a while between PR #7 and this fix) calibrated the anomaly boundary on a mixed space
through mere statistical dilution rather than real calibration — same principle as "one model
per OS" already agreed on by the team (a Linux distro and Windows are two distributions too
different for a single coherent score space, see docs/PLAN.md). `baseline_benign.jsonl`
(Linux, 71 lines, week 8) is therefore no longer consumed by this script — not deleted,
waiting for a dedicated second Linux model (not done yet, no dual model until that work is
picked back up). ML scores remain an experimental complement anyway, never a final judge
(see threat-model.md).

Usage: `python3 train.py` (from a venv with scikit-learn/skl2onnx/onnx/onnxruntime installed).
"""

import json
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

from synthaea_ml.features.cmdline import extract_features

DATA_PATH_WINDOWS = Path(__file__).parent / "data" / "baseline_capture_windows.jsonl"
DATA_PATH_WINDOWS2 = Path(__file__).parent / "data" / "baseline_capture2.jsonl"
MODEL_PATH = Path(__file__).parent / "model.onnx"

# Windows sanity check — distinguishes legitimate vs suspicious cmdlines.
# The benign cmdlines reflect the ETW format (full image path, few arguments).
# The malicious cmdlines simulate encoded payloads or suspicious paths (AppData).
SANITY_CHECK_SAMPLES = {
    "benign (svchost)": "C:\\Windows\\System32\\svchost.exe",
    "benign (powershell)": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "suspicious (AppData)": (
        "C:\\Users\\solka\\AppData\\Roaming\\Microsoft\\WindowsApps\\RuntimeBroker.exe"
    ),
    "suspicious (base64 ps)": "powershell.exe -EncodedCommand ZWNobyBoZWxsbw==",
    "suspicious (Temp)": "C:\\Users\\solka\\AppData\\Local\\Temp\\payload.exe",
}


def load_baseline() -> list[str]:
    """Loads the Windows-only baseline — {"cmdline": "C:\\Windows\\..."}, full image path,
    captured via ETW (`edr-cli capture-baseline`). See the module docstring: no mixing with
    the Linux baseline until a dedicated second model is built."""
    cmdlines = []

    for path in (DATA_PATH_WINDOWS, DATA_PATH_WINDOWS2):
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    cmdlines.append(json.loads(line)["cmdline"])

    if not cmdlines:
        raise FileNotFoundError("No Windows baseline found in ml/data/")

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

    # contamination=0.05, a deliberate decision after testing 0.02 (see this file's git
    # history). At 0.02, the curl healthcheck false positive disappeared but the ML signal on a
    # short, real malicious case (the isolated `base64 -d` exec event, captured in the lab on
    # 2026-08-24: cmdline = "base64\0-d\0") collapsed to nearly zero (score -0.001, versus
    # -0.035 at 0.05) — with only 71 baseline examples, the model's boundary is too fuzzy to
    # eliminate this false positive without losing the signal on the true positive. Explicit
    # choice: keep a sharp ML signal on the malicious case rather than a silent ML on a benign
    # one, especially since this scenario is intercepted anyway by the deterministic T1059.004
    # rule regardless of the ML score (see threat-model.md — ML is never the final judge). The
    # curl healthcheck false positive at 0.05 thus remains a known and accepted limitation
    # (already documented before these features were added, see docs/PLAN.md).
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X)

    # skl2onnx 1.20 does not yet follow the `ai.onnx.ml` v4 domain emitted by default with
    # onnx 1.22 — explicitly pinned to the latest version this skl2onnx can consume.
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
