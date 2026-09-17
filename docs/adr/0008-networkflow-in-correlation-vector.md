# ADR-0008: NetworkFlow feeds the correlation vector, not the behavior vector

- **Status**: accepted
- **Date**: 2026-09-16

## Context

#193 (`sensor-linux-netlink` conntrack) landed a new `Event::NetworkFlow`
source and, deliberately, stopped short of feeding it into any ML feature
vector — the same `NetworkFlow` events flow into rules today (BEACON via
`check_beacon_flow`) but no ML model consumes them. That deferral was
correct: silently adding a new source to a feature vector shifts the space
every already-calibrated model was trained against.

Two ML vectors exist in this workspace and both are natural candidates:

- **T1: `BehaviorVector`** (`crates/correlator/src/behavior.rs`) — feeds
  the BAYES rule (`crates/correlator/src/bayes.rs`). Positional struct
  (`bayes.rs` indexes by match index), fragile to a mid-struct insertion.
  Today it carries `connect_count`, `distinct_dports` — already touching
  the network-signal surface, but from `Event::Connect` only.
- **T2: correlation vector** (`crates/ml/src/features/correlation.rs`) —
  feeds the Isolation Forest correlation model. Already carries
  `unique_daddr_count`, `unique_dport_count` from `Event::Connect`. No
  ONNX artifact exists yet in the registry — no trained model is running
  against this vector in production.

The rules layer has already made a related choice: BEACON has both
`check_beacon` (Connect) and `check_beacon_flow` (NetworkFlow) and they
converge on the same `record_beacon` state. Connect and NetworkFlow are
treated as two views of the same phenomenon by the deterministic layer.

## Decision

1. **NetworkFlow feeds T2 only, not T1.**

2. **T2 absorbs the sources**: the existing `unique_daddr_count` and
   `unique_dport_count` fields count distinct destinations across
   `Event::Connect` AND `Event::NetworkFlow`, rather than being split
   into per-source variants. One number for "unique destinations this
   process touched", regardless of which sensor captured it.

3. **MVP feature scope**: extend the two existing counters only.
   `flows_per_second` and `long_lived_flow_count` are v2 candidates
   (see "Deferred", below).

## Rationale

Three reasons anchor "T2 only":

- **Semantic fit.** T2 is already the network-signal vector; extending it
  is a prolongation of an existing structure. T1's role is broader
  behavior — putting a second network source there dilutes that role.
- **Structural fragility of T1.** `BehaviorVector` is positional; a new
  field must be appended, and even then couples the ML surface with
  `bayes.rs`'s match indexing. Adding to T2 avoids that entire class of
  risk.
- **Avoids the double-alert failure mode** flagged in the #193 review:
  if both T1 and T2 consumed NetworkFlow, correlated Connect/NetworkFlow
  events would risk two independent scores from two ML models on the
  same underlying phenomenon. One model, one verdict.

A natural counter-argument: an attacker whose traffic is captured only
by netlink (and not by the `Connect` uprobe) would be invisible to T1.
This is acceptable **because it is already covered by the rules layer**:
`check_beacon_flow` fires on `NetworkFlow` independently of
`check_beacon`. The netlink-only attacker gets caught deterministically
before the ML layer is consulted. This is not a gap; it's a precedent.

"Absorb" over "coexist" (single field spanning both sources, versus
per-source `unique_daddr_from_connect` / `unique_daddr_from_netflow`
variants):

- The model wants to know "how many distinct destinations did this
  process touch", not "which sensor saw them". An attacker doesn't
  choose which sensor captures their traffic; a feature that reflects
  that ambiguity is a feature the model can't use.
- Splitting the sources doubles the feature count for no discriminative
  gain; each variant would be highly correlated with the other on
  non-attacker traffic and add noise.
- Consistent with the rules-layer precedent (BEACON unifies both
  sources into one state).

## Implementation notes

Two Rust edits, both in `crates/ml/src/features/correlation.rs`:

1. **`is_modeled()` filter**: extended to match `Event::NetworkFlow`
   alongside the existing arms. This is intentional and has a
   documented side effect (see below).

2. **daddr/dport aggregation loop**: today it matches `Event::Connect`
   only; add a parallel arm for `Event::NetworkFlow` that reads
   `daddr` / `dport` from that variant and feeds the same
   `HashSet<IpAddr>` / `HashSet<u16>` accumulators as Connect.

**Python parity**: `ml/synthaea_ml/features/correlation.py`
carries the same logic in Python and is the source of truth for the
training-time feature computation. The two edits above must be mirrored
there **before** #44 generates the first NetworkFlow-inclusive baseline,
otherwise Rust-inference and Python-training feature values will
diverge and the parity fixture (`ml/tests/fixtures/gen_capture_parity`)
will fail on the first capture.

**Documented side effect on `is_modeled()`**: this filter gates the
entire vector, not just the daddr/dport pair. `event_count` and
`span_s` (which count events that pass `is_modeled`) will therefore
increase for any process that has netlink traffic, not just via the
two fields being absorbed. `connect_count` in T1's `BehaviorVector` is
not affected — it's filtered by an explicit `matches!(Event::Connect(_))`
inside its own accumulator, independent of T2's `is_modeled`. This
side effect is acceptable: it's cosmetically visible in event counts,
not a source of double-attribution.

## Consequences

- **No production regression.** `model_correlation.onnx` is not in the
  registry today; no model runs against this vector, so the feature
  space shift is a shift of an unused surface. This ADR captures the
  intent before that surface is used, not after.

- **#44 baseline invalidation.** The current
  `linux-wsl2-solkapc-2026-09-09-v2` baseline predates this ADR and
  netlink-source events. A fresh capture is required before any
  training run against the new vector — that's step (2) of the
  original #193 review sequence, unblocked by this ADR being step (3).

- **`BehaviorVector`/T1 remains network-source-agnostic.** Its
  `connect_count` / `distinct_dports` continue to see Connect only.
  Explicitly out-of-scope for this ADR; changing that later would be a
  separate decision recorded in another ADR.

- **v2 candidates deferred** (see "Deferred"): the correlation vector
  keeps its current arity growth minimal for now.

## Deferred (v2)

These features are worth adding on top of the "absorb" MVP, but not
today:

- **`flows_per_second`** — beacon-cadence signal, complementary to
  BEACON's deterministic rule. Requires a windowing decision (over
  what interval — the process lifetime? a rolling window?).
- **`long_lived_flow_count`** — long-established connections
  (>60s of same-tuple traffic). Signature-close to C2, but requires a
  duration threshold decision and depends on the reliability of
  netlink's connection-lifetime attribution.

Explicitly discarded from the MVP (from the #193 review discussion):

- **Volume features** (`bytes_sent_p50`/`_p95`) — `bytes_sent` is
  `None` by default on a standard Linux host (`nf_conntrack_acct=off`).
  Half the volume signal is non-computable without an infra change,
  so the whole family stays out until we decide whether to require
  the sysctl.
- **Per-port histograms** (well-known / registered / ephemeral /
  listener drift buckets) — potentially discriminative but per-event
  cost, and #193's listener-drift rule already lives in that space
  with a different mechanism. No collision risk (one-shot new socket
  vs continuous histogram), but no ML-side value that BEACON +
  listener-drift don't already deliver deterministically. Revisit if
  a training run on the MVP vector under-fits.

## References

- #193 — `sensor-linux-netlink` conntrack + listener drift (merged);
  the review comment on that PR is the seed of this ADR.
- `crates/correlator/src/bayes.rs` — T1 consumer, `BehaviorVector`
  positional indexing.
- `crates/ml/src/features/correlation.rs` — T2 vector construction.
- `ml/synthaea_ml/features/correlation.py` — Python
  parity for training.
- ADR-0002 — ML model delivery and inference.
- Issue #44 — first NetworkFlow-inclusive baseline capture (unblocked
  by this ADR).
