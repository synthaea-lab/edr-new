# ADR-0002: ML models ship as data; inference is onnxruntime (`ort`), statically linked

- **Status**: accepted
- **Date**: 2026-09-03

## Context

The `ml/` pipeline trains the on-device tiers (T0–T2) and exports them to ONNX for
inference by `crates/ml`. Two coupled decisions were left open by the old iteration:

**Delivery.** The old agent embedded models at compile time (`include_bytes!`), so every
model update was an agent release. The new ML space plans canary-ring shipping via the
`updater`/`registry` machinery, which is incompatible with compile-time embedding.

**Inference runtime.** `skl2onnx` exports tree models using the `ai.onnx.ml` operator
set (`TreeEnsembleRegressor` et al.). Those ops are fully supported by `ort` (bindings
to Microsoft's onnxruntime, a large C++ library) but only partially by pure-Rust
runtimes such as `tract`. The considered alternative — a hand-rolled native tree
evaluator with ONNX kept as reference format — was rejected: it ties every new model
family to bespoke evaluator work in `crates/ml`, while `ort` runs anything the Python
side can export, keeping the training side free to evolve (including beyond trees)
without touching the agent.

Linking mode matters more than usual because the agent runs as SYSTEM/root: a
dynamically loaded onnxruntime is a library-hijack/side-loading surface inside the EDR
itself, and it makes the updater version two artifacts in lockstep. Dynamic linking
also saves nothing: it moves bytes from the executable into a shipped library, leaving
the install footprint identical.

## Decision

1. **Models are data, not code.** Agents load ONNX model artifacts from the update
   channel (signed, versioned, shipped via canary rings from `ml/registry/`).
   `crates/ml` never embeds a model via `include_bytes!`. Absence of a model artifact
   means the corresponding scorer is disabled, not a fallback model.
2. **Inference is onnxruntime via the `ort` crate, statically linked** into the agent
   binary. Dynamic linking (build-time or `load-dynamic`/dlopen) is rejected for the
   endpoint agent: no separate native library to hijack, sign, or version.
3. **Binary size is managed with onnxruntime's reduced-ops build, not linking mode.**
   Start on the standard static binaries and measure; if the agent outgrows its size
   budget, pin a custom onnxruntime build compiled with only the operators our models
   use (a cached per-target CI artifact). `verify_onnx` remains the oracle that the
   shipped runtime + model reproduce scikit-learn's scores.

## Consequences

- Model updates decouple from agent releases: retrain → registry → canary ring, no
  rebuild. The FP-governance gate applies to the artifact, not the binary.
- Any model type the Python side can export to ONNX ships with zero agent changes —
  tree ensembles today, other families later — at the cost of carrying onnxruntime
  (tens of MB statically linked before op reduction) on every endpoint.
- Agent builds gain a native C++ dependency: prebuilt or CI-built onnxruntime static
  libs per target (3 OSes, x86_64/aarch64). `cargo test --workspace` on the ML crate
  needs those libs available in CI.
- One signed agent binary: no runtime library search path, no side-loading surface, no
  updater lockstep between agent and runtime. Upgrading onnxruntime is an agent
  release — acceptable, since runtime upgrades are rare and model upgrades (the
  frequent case) ride the data channel.
- Signing/verification of model artifacts becomes a hard prerequisite for shipping ML:
  a model is agent-controlling input, so the `updater` trust chain must cover it before
  the first canary ring, not after.
