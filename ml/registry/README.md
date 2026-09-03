# ml/registry — Model Registry

The models that ship. One directory per model, one subdirectory per version:

    registry/<model>/<version>/
      model.onnx        # the artifact (large binaries may move to LFS/release storage)
      card.md           # model card — REQUIRED, see below
      config.json       # training config for reproducibility

The model card records: purpose and tier, training data (dataset versions), metrics,
FP rate against benign baselines, scenario-replay results, known limitations, and the
parity-fixture hash it was verified against. No card, no ship — the control plane's
content distribution only picks up carded versions.
