# ml — The ML Space

Everything about the learned half of the detection stack lives here: datasets, feature
definitions, model training, calibration, evaluation, and export to ONNX for on-device
inference by `crates/ml`. This is a first-class part of the product, not a scripts
folder — the thesis is that a learned model raises the cost of evasion through
generalization, and that only holds if this pipeline is reproducible and measured.

## Inference tiers

| Tier | Runs | Model | Trained from |
| --- | --- | --- | --- |
| T0 — event scoring | on-device | per-event anomaly (e.g. cmdline features, Isolation Forest) | benign captures per platform |
| T1 — behavior | on-device | aggregated per-entity behavior scoring | scenario + benign captures |
| T2 — correlation | on-device | case scorer over correlated detections (with Bayesian LLR calibration) | labeled correlation traces |
| T3 — fleet | server-side | rarity / per-tenant baselines | fleet telemetry (control plane) |

T0–T2 export to ONNX (the reference format) plus a flat inference artifact that ships to
agents via canary rings and is evaluated natively by `crates/ml` (ADR-0002); T3 lives
with the control plane and never ships to endpoints.

## Layout

| Path | Purpose |
| --- | --- |
| `synthaea_ml/` | The Python package — see subpackage docstrings |
| `synthaea_ml/features/` | Feature definitions — the Rust parity seam (fixtures shared with `crates/ml`) |
| `synthaea_ml/data/` | Capture parsing, dataset building, labeling |
| `synthaea_ml/models/` | Model definitions per tier |
| `synthaea_ml/training/` | Training entry points per tier/platform |
| `synthaea_ml/calibration/` | Bayesian LLR calibration |
| `synthaea_ml/evaluation/` | Metrics, FP governance, scenario-replay evaluation |
| `synthaea_ml/export/` | ONNX export, flat inference artifacts (ADR-0002), parity verification (`verify_onnx`) |
| `datasets/` | Data on disk (not committed) — documented layout below |
| `registry/` | Versioned model artifacts + model cards — what ships |
| `notebooks/` | Experiments; anything load-bearing graduates into the package |
| `tests/` | Unit tests + Rust/Python parity fixtures |

## The three rules

1. **Feature parity is enforced, not hoped for.** Every feature has a definition here
   and in `crates/ml`; both test against the same fixture vectors. Drift is a CI
   failure, and drift in production is a silent model lobotomy.
2. **No model ships without an evaluation record.** Each registry entry carries a model
   card: training data provenance, metrics, FP rate against benign baselines, and the
   scenario-replay results. FP governance is a release gate.
3. **Reproducibility.** A registry model can be rebuilt from its recorded dataset
   versions and config. Notebooks are for exploration only.

Migration source: `old/ml` (features, train*, calibrate_llr, verify_onnx,
capture_to_baseline, aggregate_correlation, tests) — issue #14 maps files to this
layout.
