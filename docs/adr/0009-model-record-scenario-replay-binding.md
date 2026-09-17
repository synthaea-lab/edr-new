# ADR-0009: Model record binds scenario-replay results; `training.json` renamed to `model_record.json`

- **Status**: proposed
- **Date**: 2026-09-17

## Context

Two independent facts have converged and left a gap the registry cannot express
today:

- **#44's decisions 1 and 2** (Jean's proposition, posted 2026-09-16): a sidecar
  YAML per scenario (`lab/scenarios/<name>.yaml`) declaring an
  `expected_detections` schema of shape `{technique, rule, min_count, tolerance}`.
  Decision 3 (storage) is Florian's; decision 4 (binding to the model card) is
  this ADR.

- **The registry's ship criterion** (`ml/registry/README.md`) declares "no card,
  no ship — the control plane's content distribution only picks up carded
  versions" and requires `scenario-replay results` in every card. But no schema
  exists for those results, no code enforces "no card, no ship", and the
  control-plane distribution itself is not yet built — the same pattern of
  intent-documented-in-README, mechanism-not-built already noted in ADR-0006 for
  policy distribution.

`ml/synthaea_ml/registry/training_record.py` already binds datasets to a model
version by content hash (`baseline_sha256`): a dataset can move on disk without
invalidating the record, but a mutated baseline cannot pass
`verify_training_record` even under the same path. **There is no equivalent
binding for scenario YAMLs and their replay results.** The record concept exists,
it just does not yet cover the replay side of the ship criterion.

The (upcoming) trainer glue and (upcoming) release gate both mentioned in
`training_record.py`'s doc are the writers and consumers this ADR sets the
contract for.

## Decision

1. **Extend the model record with `scenario_replays: list[ScenarioReplayResult]`**.
   Each entry binds to its source scenario YAML by content hash
   (`scenario_yaml_sha256`), the same principle as the existing `baseline_sha256`.
   Mutating a scenario YAML invalidates every record that references it.

2. **Rename `training.json` → `model_record.json`**. The file already covers more
   than training input (it binds datasets) and will now also cover replay
   outcomes — a lifecycle record, not a training record. Verified by Jean before
   this ADR (`find . -name "training.json"` returns nothing anywhere in the
   repo): the name lives only in code, as the constant `TRAINING_RECORD_FILENAME`
   in `training_record.py:43`. No on-disk migration to do; the rename is a pure
   code refactor of the constant and its tests. Doing it now costs zero;
   delaying it costs a real migration once real models start writing the file.

3. **Bump `SCHEMA_VERSION` 1 → 2**. New required fields: `scenario_replays`,
   `Environment` sub-record on each replay. Readers reject v1 (matches the
   pattern already in use in `manifest.py`).

## Schema

```python
@dataclass(frozen=True)
class Environment:
    """OS/kernel/arch on which the replay ran. Minimum for v1;
    libc, glibc/musl and toolchain versions are v2 candidates (Deferred)."""
    os: str          # "linux" | "windows" | "darwin"
    kernel: str      # `platform.release()` verbatim, cross-platform via the Python
                     # stdlib helper — on Linux/macOS the value equals `uname -r`
                     # (e.g. "6.6.0-generic", "23.6.0"); on Windows it is the major
                     # version only (e.g. "10"), NOT the full build (that would be
                     # `platform.version()` or `[System.Environment]::OSVersion.Version`
                     # under PowerShell). Chosen for uniform API and single source
                     # over precision — a full Windows build string would need its
                     # own field, deferred until we have a case that requires it.
    arch: str        # "x86_64" | "aarch64" | ...

@dataclass(frozen=True)
class ExpectedDetection:
    """Mirror of #44's decision-2 schema inside the replay record."""
    technique: str   # opaque string — may combine techniques ("T1105/T1059/T1071")
    rule: str        # rule identifier (`Alert.technique` or `CorrelationAlert.rule`)
    min_count: int   # minimum alerts required for pass
    tolerance: int   # allowed overshoot: pass iff observed_count ≤ min_count + tolerance

@dataclass(frozen=True)
class ObservedDetection:
    """What the replay actually observed for one (technique, rule) tuple."""
    technique: str
    rule: str
    count: int

@dataclass(frozen=True)
class ScenarioReplayResult:
    """One replay run against one scenario, one environment."""
    scenario_name: str          # matches `lab/scenarios/<name>.yaml` stem
    scenario_yaml_sha256: str   # content hash — mutation invalidates the binding
    run_at: str                 # ISO 8601 UTC, e.g. "2026-09-17T10:15:00Z"
    environment: Environment
    expected_detections: list[ExpectedDetection]
    observed_detections: list[ObservedDetection]
    passed: bool                # AND across all expected — cached from computation below
```

## Passing criterion

For each `ExpectedDetection` in a scenario, the replay looks up a matching
`ObservedDetection` by exact string equality on `(technique, rule)`.

- Missing observation → fail.
- `observed_count < min_count` → fail (under-detection).
- `observed_count > min_count + tolerance` → fail (over-detection — noisy rule).
- Otherwise → pass.

`ScenarioReplayResult.passed` is `True` iff every `ExpectedDetection` in the
scenario passes. The field is cached (writer computes it, gate re-computes to
verify) so a reader can filter on it without re-running the criterion.

## Ship gate contract (explicit)

`verify_provenance()` in `ml/synthaea_ml/export/verify_onnx.py` (the release gate,
line 159 today) will additionally enforce, in strict mode:

1. `model_record.json` exists in the version directory.
2. Its `schema_version` equals 2 (v1 is rejected).
3. Every `dataset_version.baseline_sha256` matches the on-disk manifest's
   `sample_sha256` (unchanged from today's `verify_training_record`).
4. Every `scenario_replay.scenario_yaml_sha256` matches the on-disk
   `lab/scenarios/<scenario_name>.yaml` (new).
5. Every `scenario_replay.passed` is `True`, and re-computing the passing
   criterion from `expected_detections`/`observed_detections` agrees with the
   cached value (a mutated `passed` field is caught).

The gate stays a single call site — `verify_provenance()` at
`verify_onnx.py:159` — with the extension flowing through the already-existing
`verify_training_record()` helper.

## Consequences

- **Zero migration cost on rename.** No `training.json` exists anywhere on disk,
  no code references the string `"training.json"` outside `training_record.py`
  (verified pre-ADR, referenced above). The rename is a pure refactor of one
  constant and its tests.

- **`card.md` content stays out of scope.** The registry README's "no card, no
  ship" remains a declaration of intent; the gate today verifies dataset
  provenance only, and this ADR extends it to replay provenance only —
  card content is neither read nor verified. Mechanising a `card.md` existence
  and content check is orthogonal and would deserve its own ADR-0010 when it
  becomes a priority. Called out explicitly here so a future reader does not
  mistake this ADR's silence for a "no card, no ship" mechanism.

- **Existing placeholder models** (`cmdline-iforest-linux/0.1.0`,
  `cmdline-iforest-windows/0.1.0`) are already flagged
  `reference-only, NOT shippable` in their cards — they predate the training
  record concept entirely. This ADR does not migrate them; they remain
  reference-only until replaced by fresh models trained under the v2 schema.

- **The upcoming trainer glue** (mentioned in `training_record.py`'s crate doc)
  now has a definite contract to write against. Same for the release gate.

- **`is_modeled()` side effect from ADR-0008** (event_count and span_s widen when
  NetworkFlow is added) is orthogonal to this ADR — it affects vector
  construction, not the record schema. No interaction.

## Deferred

- **`card.md` existence and content check** — deserves ADR-0010. Open questions:
  does the gate parse the markdown (fragile), check required section headers
  only, or cross-check `card.md`'s claims against `model_record.json` (which is
  trusted) to catch a card that promises capabilities the record does not
  attest?

- **Extended environment**: libc (glibc vs musl), toolchain versions (rustc,
  ONNX runtime), CPU model. Kept minimal in v1 because no case yet exists where
  a replay passed on glibc and failed on musl; if #178's uprobes verification
  surfaces such a case, extend `Environment` then.

- **Multi-run stability**: today's schema records one run per
  `(model_version, scenario, environment)` tuple. A v2 variant could carry a
  list of runs with a pass ratio to catch flaky detections. Explicitly not v1.

- **`render_card.py`**: script that regenerates the "Scenario Replay Results"
  section of `card.md` from `model_record.json`. Nice-to-have; humans can write
  the section by hand for now.

## References

- ADR-0002 — ML model delivery and inference (the ONNX registry this ADR
  extends).
- ADR-0008 — NetworkFlow feeds the correlation vector (unblocks the fresh
  baseline that will drive the first v2 model record).
- Issue #44 — first NetworkFlow-inclusive baseline capture; Jean's proposition
  on the issue posts decisions 1 (sidecar YAML) and 2 (`expected_detections`
  schema), which this ADR consumes.
- `ml/registry/README.md` — the "no card, no ship" declaration this ADR
  partially mechanises (dataset + replay provenance, not card content).
- `ml/synthaea_ml/registry/training_record.py` — the module this ADR extends
  and renames.
- `ml/synthaea_ml/export/verify_onnx.py:159` — `verify_provenance()`, the
  release gate that will enforce the extended contract.
