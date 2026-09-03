"""Regenerates the attribution parity fixture consumed by BOTH sides of the seam:

    crates/ml/tests/fixtures/isoforest_small.onnx     (the model)
    crates/ml/tests/fixtures/attribution_golden.json  (inputs -> expected attributions)

A small Isolation Forest is trained on seeded synthetic data and exported through the
real skl2onnx converter — so the committed model has the exact graph layout production
models have (one TreeEnsembleRegressor per tree behind a Gather). Expected values come
from `ml/tests/attribution_reference.py`; `crates/ml/tests/attribution_golden.rs`
asserts the Rust implementation reproduces them.

Run from `ml/tests/fixtures/` with a venv holding numpy, scikit-learn, skl2onnx, onnx:

    python3 gen_attribution_fixture.py

Regenerate only when the attribution *definition* changes (that is a seam change —
both sides must move together), never to paper over a parity failure.
"""

import json
import sys
from pathlib import Path

import numpy as np
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attribution_reference import attribute, load_forest

OUT_DIR = Path(__file__).resolve().parents[3] / "crates" / "ml" / "tests" / "fixtures"
N_FEATURES = 7

rng = np.random.default_rng(42)
# Benign-ish cluster with a little structure between features.
base = rng.normal(loc=[4.0, 2.0, 0.5, 8.0, 1.0, 3.0, 0.2], scale=0.7, size=(256, N_FEATURES))
base[:, 2] = np.abs(base[:, 2])

model = IsolationForest(n_estimators=10, max_samples=64, random_state=42)
model.fit(base)

# Pin the opsets to what production models use (old/ml exports: ai.onnx.ml 3, core 18).
onnx_model = to_onnx(model, base.astype(np.float32), target_opset={"ai.onnx.ml": 3, "": 18})
model_path = OUT_DIR / "isoforest_small.onnx"
model_path.write_bytes(onnx_model.SerializeToString())

# Five in-distribution inputs, three engineered outliers.
cases_x = np.vstack(
    [
        base[:5],
        np.array(
            [
                [9.0, 2.0, 0.5, 8.0, 1.0, 3.0, 0.2],  # one feature far out
                [4.0, -3.0, 6.0, 8.0, 1.0, 3.0, 0.2],  # two features out
                [12.0, 9.0, 9.0, -4.0, 7.0, 11.0, 5.0],  # everything out
            ]
        ),
    ]
).astype(np.float32)

forest = load_forest(str(model_path))
cases = []
for x in cases_x:
    contributions, depth, expected_depth = attribute(forest, x)
    cases.append(
        {
            "x": [float(v) for v in x],
            "contributions": contributions,
            "depth": depth,
            "expected_depth": expected_depth,
        }
    )

# Semantic gate: our effective depth must order the cases exactly as the model's own
# anomaly score does — decision_function is monotone-increasing in expected path
# length (deep = normal), so the two orderings must be identical. If this fails, the
# attribution semantics have drifted from what actually ships.
import onnxruntime

sess = onnxruntime.InferenceSession(model_path.read_bytes(), providers=["CPUExecutionProvider"])
onnx_scores = sess.run(["scores"], {"X": cases_x})[0].reshape(-1)
ours = np.array([c["depth"] for c in cases])
if not np.array_equal(np.argsort(ours), np.argsort(onnx_scores)):
    raise SystemExit(
        f"effective depth disagrees with model score ordering:\n{ours=}\n{onnx_scores=}"
    )
sklearn_scores = model.decision_function(cases_x)
assert np.allclose(onnx_scores, sklearn_scores, atol=1e-5), "onnx vs sklearn scores diverge"

golden = {
    "model": "isoforest_small.onnx",
    "n_trees": len(forest.trees),
    "n_features": forest.n_features,
    "cases": cases,
}
(OUT_DIR / "attribution_golden.json").write_text(json.dumps(golden, indent=2) + "\n")
print(f"wrote {model_path} ({model_path.stat().st_size} bytes) and attribution_golden.json")
