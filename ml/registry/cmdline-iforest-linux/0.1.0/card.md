# cmdline-iforest-linux 0.1.0 — Model Card

- **Tier**: T0 (per-event cmdline anomaly) · **Family**: Isolation Forest (skl2onnx export)
- **Status**: **reference-only, NOT shippable** — migration artifact from the old
  iteration (old/ml/model_linux.onnx, trained 2026-08 by train_linux.py on a Linux lab
  baseline capture). It predates the registry's evaluation gates.
- **Training data**: Linux lab baseline capture (old iteration; dataset not versioned
  under the current datasets/ scheme — reproducibility criterion NOT met).
- **Evaluation**: sanity-check samples only (verify_onnx parity vs scikit-learn).
  No FP-budget measurement, no robustness card, no scenario-replay record.
- **Ship criteria**: a successor trained via synthaea_ml/training/train_linux.py on a
  versioned dataset, with FP governance + robustness cards, replaces this entry.
  Until then this artifact serves as the verify_onnx oracle input and a dev fixture.
