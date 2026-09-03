# ml — Training Pipeline (Python)

Offline ML pipeline: feature extraction from captured telemetry, model training
(per-platform and correlation-level), calibration, and ONNX export for on-device
inference by `crates/ml`.

Planned contents (migrated from `old/ml` after review):

| File / dir | Purpose |
| --- | --- |
| `features.py` | Event-level feature extraction shared with the Rust side |
| `behavior_features.py` | Behavior-aggregation features |
| `correlation_features.py` | Case/correlation-level features |
| `train.py`, `train_linux.py` | Model training entry points |
| `train_correlation.py` | Correlation-model training |
| `calibrate_llr.py` | Bayesian log-likelihood-ratio calibration |
| `capture_to_baseline.py` | Turn captured benign telemetry into baselines |
| `verify_onnx.py` | Parity check: ONNX output vs. training framework output |
| `data/` | Datasets and baselines (not committed) |
| `tests/` | Pipeline tests |

Rule: the feature definitions here and in `crates/ml` must never drift apart —
parity is enforced by `verify_onnx.py` and cross-language tests.
