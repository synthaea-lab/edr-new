"""Regenerates the correlation-scorer (T2) parity fixture:

    crates/ml/tests/fixtures/correlation_scorer.onnx     (a small 8-feature IsolationForest)
    crates/ml/tests/fixtures/correlation_scorer_golden.jsonl  (events -> onnxruntime score)

The `verify_onnx` seam for the T2 *inference path*, the counterpart of
`gen_scorer_fixture.py` for T0. It pins the Rust `ort` score (via `ml::CorrelationScorer`,
which extracts the vector from an `EventBus`) to the Python onnxruntime score computed
from the same events through `synthaea_ml.features.correlation` — the definitions the
Rust side mirrors.

Cases are *event lists*, not raw vectors: that exercises the whole chain
(events -> per-pid window -> 8-feature vector -> model), the same shape as
`features_golden.jsonl`. Each golden line is `{"events": [...], "pid": N, "score": f}`;
`score` is `null` for windows below the Rust-side `MIN_EVENT_COUNT` gate (the model is
never asked, the scorer returns `None`).

Run from `ml/tests/fixtures/` with a venv holding numpy, scikit-learn, skl2onnx, onnx,
onnxruntime:

    python3 gen_correlation_scorer_fixture.py

Regenerate only on a deliberate change to the correlation feature definition or the
model recipe (a seam change — retrain the shipped model too), never to paper over a
red parity test.
"""

import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from synthaea_ml.features.correlation import FEATURE_NAMES, extract_features

OUT_DIR = Path(__file__).resolve().parents[3] / "crates" / "ml" / "tests" / "fixtures"
MIN_EVENT_COUNT = 3  # mirror of ml::scorer::correlation::MIN_EVENT_COUNT
GATE_IDX = FEATURE_NAMES.index("event_count")

MS = 1_000_000
S = 1_000_000_000


def exec_ev(pid, ts_ns):
    return {"type": "exec", "pid": pid, "ts_ns": ts_ns}


def connect_ev(pid, ts_ns, daddr, dport):
    return {"type": "connect", "pid": pid, "ts_ns": ts_ns, "daddr_v4": list(daddr), "dport": dport}


def write_ev(pid, ts_ns):
    return {"type": "fileopen", "pid": pid, "ts_ns": ts_ns, "flags": 0o1 | 0o100}  # O_WRONLY|O_CREAT


# ── Training distribution: what a normal process's window looks like ──────────
# Low counts, tight spans, at most one or two destinations. Seeded so the learned
# boundary is meaningful rather than random.
_rng = np.random.default_rng(23)


def _benign_window(n: int) -> list[list[float]]:
    out = []
    for _ in range(n):
        spawn = float(_rng.integers(1, 3))
        connect = float(_rng.integers(0, 4))
        fw = float(_rng.integers(0, 3))
        uniq_d = min(connect, float(_rng.integers(0, 2)))
        uniq_p = min(connect, float(_rng.integers(0, 3)))
        chain = 1.0 if (spawn >= 1 and connect >= 1 and fw >= 1) else 0.0
        span = float(_rng.uniform(0.1, 6.0))
        ev = spawn + connect + fw
        out.append([spawn, connect, fw, uniq_d, uniq_p, chain, span, ev])
    return out


train_x = np.array(_benign_window(400), dtype=np.float32)

# contamination 0.02: behavioural counts of a normal process sit near zero and cluster
# tightly — the benign blob separates better than on text features (0.05). Matches
# train_correlation.py. Tree count / sample cap kept small (like gen_scorer_fixture.py):
# this fixture pins Rust==Python inference, not detection quality.
model = IsolationForest(
    n_estimators=20, max_samples=64, contamination=0.02, random_state=42
)
model.fit(train_x)

onnx_model = to_onnx(model, train_x, target_opset={"ai.onnx.ml": 3, "": 18})
model_path = OUT_DIR / "correlation_scorer.onnx"
model_path.write_bytes(onnx_model.SerializeToString())

# ── Golden cases: event lists spanning benign, beacon, scan, dropper, gated ───
LOCAL = (127, 0, 0, 1)
C2 = (203, 0, 113, 7)
GOLDEN_CASES = [
    # quiet network client — a couple of events, one destination
    {"pid": 1001, "events": [exec_ev(1001, 0), connect_ev(1001, 1 * S, LOCAL, 443),
                             connect_ev(1001, 2 * S, LOCAL, 443)]},
    # routine build-ish: spawn + a few writes
    {"pid": 1002, "events": [exec_ev(1002, 0), write_ev(1002, 1 * S), write_ev(1002, 2 * S),
                             write_ev(1002, 3 * S)]},
    # beacon: one dest, many connects, steady cadence
    {"pid": 1003, "events": [exec_ev(1003, 0)] + [connect_ev(1003, i * 900 * MS, C2, 4444)
                                                  for i in range(1, 14)]},
    # full dropper chain: spawn + write + external connect, tight span
    {"pid": 1004, "events": [exec_ev(1004, 0), write_ev(1004, 200 * MS),
                             connect_ev(1004, 500 * MS, C2, 8080),
                             connect_ev(1004, 900 * MS, C2, 8080)]},
    # fan-out scan: many destinations, many ports
    {"pid": 1005, "events": [exec_ev(1005, 0)] + [connect_ev(1005, i * 100 * MS, (10, 0, 0, i), 1000 + i)
                                                  for i in range(1, 20)]},
    # gated: only two events for the pid -> scorer returns None, model not asked
    {"pid": 1006, "events": [exec_ev(1006, 0), connect_ev(1006, 1 * S, LOCAL, 80)]},
    # gated: pid absent from the window entirely
    {"pid": 9999, "events": [exec_ev(1, 0), connect_ev(2, 1 * S, LOCAL, 80)]},
]

sess = onnxruntime.InferenceSession(model_path.read_bytes(), providers=["CPUExecutionProvider"])
lines = []
for case in GOLDEN_CASES:
    vec = extract_features(case["events"], case["pid"])
    if vec[GATE_IDX] < MIN_EVENT_COUNT:
        score = None
    else:
        x = np.array([vec], dtype=np.float32)
        score = float(sess.run(["scores"], {"X": x})[0].reshape(-1)[0])
    lines.append(json.dumps({"events": case["events"], "pid": case["pid"], "score": score}))

# Sanity: onnxruntime and scikit-learn must agree on the scored cases (verify_onnx).
scored = [c for c in GOLDEN_CASES
          if extract_features(c["events"], c["pid"])[GATE_IDX] >= MIN_EVENT_COUNT]
xs = np.array([extract_features(c["events"], c["pid"]) for c in scored], dtype=np.float32)
skl = model.decision_function(xs)
onnx = sess.run(["scores"], {"X": xs})[0].reshape(-1)
assert np.allclose(skl, onnx, atol=1e-5), f"onnx vs sklearn diverge:\n{skl=}\n{onnx=}"

(OUT_DIR / "correlation_scorer_golden.jsonl").write_text("\n".join(lines) + "\n")
print(f"wrote {model_path} ({model_path.stat().st_size} bytes) and correlation_scorer_golden.jsonl")
for line in lines:
    row = json.loads(line)
    print(f"  pid={row['pid']:<5} score={row['score']}")
