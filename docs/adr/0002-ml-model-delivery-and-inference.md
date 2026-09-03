# ADR-0002: ML models ship as data; inference is a native Rust evaluator, ONNX is the reference format

- **Status**: accepted
- **Date**: 2026-09-03

## Context

The `ml/` pipeline trains the on-device tiers (T0–T2) and exports them for inference by
`crates/ml`. Two coupled decisions were left open by the old iteration:

**Delivery.** The old agent embedded models at compile time (`include_bytes!`), so every
model update was an agent release. The new ML space plans canary-ring shipping via the
`updater`/`registry` machinery, which is incompatible with compile-time embedding.

**Inference runtime.** All current and planned on-device models are tree ensembles
(Isolation Forests) or similarly simple classical models. `skl2onnx` exports these using
the `ai.onnx.ml` operator set (`TreeEnsembleRegressor` et al.), not the neural-network
core opset. That quietly constrains the runtime choice: the `ai.onnx.ml` ops are fully
supported by `ort` (bindings to Microsoft's onnxruntime, a large C++ library), but only
partially and unreliably by pure-Rust runtimes such as `tract`. "We ship ONNX" therefore
means "the agent links onnxruntime" — megabytes of C++ in a binary deployed to every
endpoint, a native library to build or fetch per target (3 OSes × x86_64/aarch64), for
models whose inference is walking if/else trees.

Meanwhile the pipeline already has the machinery that makes a hand-rolled evaluator safe:
`verify_onnx`-style parity checks and golden fixtures enforced in CI on both sides of the
Rust/Python seam.

## Decision

1. **Models are data, not code.** Agents load model artifacts from the update channel
   (signed, versioned, shipped via canary rings from `ml/registry/`). `crates/ml` never
   embeds a model via `include_bytes!`. Absence of a model artifact means the
   corresponding scorer is disabled, not a fallback model.
2. **Inference is a native Rust evaluator in `crates/ml`.** The shipped artifact is a
   flat encoding of the model (for tree ensembles: node arrays of feature index,
   threshold, children, leaf value, plus normalization constants), emitted by
   `synthaea_ml/export/` alongside the ONNX file. `crates/ml` implements a small
   dependency-free walker per model family, not a general ONNX runtime.
3. **ONNX remains the reference format and verification oracle.** Training still exports
   ONNX; onnxruntime (Python side only) remains the oracle. Golden fixtures pin three
   points to identical scores (within epsilon): scikit-learn ↔ ONNX (existing
   `verify_onnx`) and ONNX ↔ the flat artifact as evaluated by the Rust walker. A CI
   failure on either seam blocks the model, same policy as feature parity.

## Consequences

- Model updates decouple from agent releases: retrain → registry → canary ring, no
  rebuild. The FP-governance gate applies to the artifact, not the binary.
- The agent stays pure Rust: no C++ toolchain in agent builds, no per-target onnxruntime
  binaries, smaller attack/audit surface, and `cargo test --workspace` exercises
  inference on all three OSes without native fixtures.
- We commit to one evaluator per model *family* (~100 lines each; one tree walker covers
  every forest across T0–T2). A future model type outside the flat format's reach —
  e.g. a real neural net — needs either a new evaluator or a revisit of this ADR;
  adopting `ort` at that point is the documented fallback and touches only `crates/ml`
  and `export/`, since ONNX artifacts are already produced and verified today.
- The flat format is a new versioned contract between `synthaea_ml/export/` and
  `crates/ml`: golden fixtures required (parity-seam rule), and a format change is a
  version bump, not a silent edit — same policy as the event schema.
- Signing/verification of model artifacts becomes a hard prerequisite for shipping ML:
  a model is agent-controlling input, so the `updater` trust chain must cover it before
  the first canary ring, not after.
