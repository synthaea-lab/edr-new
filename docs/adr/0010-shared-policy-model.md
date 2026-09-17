# ADR-0010: Shared policy model — schema, versioning, signature, layered overrides

- **Status**: proposed
- **Date**: 2026-09-17

## Context

The `policy` crate today (281 lines) holds two useful but disconnected pieces:

- **Static exclusion helpers** — `is_trusted_system_path`,
  `name_exclusion_applies`, `expected_parents`, `parent_exclusion_applies`.
  Pure functions consumed by `rules` and `correlator` for masquerade
  detection (issue #107). No serialisation, no distribution. Fine as-is.
- **`EventLogPolicy` struct** — flags gating the four
  `sensor-windows-eventlog` poll targets (service installs, scheduled
  tasks, account creations, logon events). In-code default, explicitly
  **without** a `serde` derive: today's flag is a plain Rust value read
  by the `agent` binary and converted into the sensor's own type at
  construction time (ADR-0006). Fine for a single sensor, fragile as a
  general pattern: every new sensor with a policy-visible knob would
  invent its own struct, its own default, its own agent-side glue.

The crate's own top-level doc calls out where this leads: *"Policies are
versioned and signed; distributed by the control plane, enforced by the
agent — this crate holds the shared types and evaluation logic so both
sides agree by construction."* None of "versioned", "signed",
"distributed" or "shared with the control plane" is mechanised today.
The M8 control plane (not started) will eventually push policy updates
to agents in the field; the M6 updater (primitives shipped, wiring
open) will apply them under canary rings (ADR-0006 pattern). Neither
has a contract to write to.

Deferring the design any longer forces every next feature that wants a
policy-visible knob (M6 response actions, M11 model activation, custom
per-technique thresholds, compliance modes) to reproduce the
`EventLogPolicy` pattern — a plain struct with an in-code default — and
we pay the migration cost N times when the shared model finally lands.

## Decision

**Introduce a canonical `Policy` document as the single format the agent
and (upcoming) control plane exchange.** Not distribution mechanism, not
signature key management — those are their own ADRs when their host
subsystem starts. This ADR fixes the on-the-wire and in-memory shape,
its evolution rules, and its layering.

1. **Top-level structure** — `Policy` is
   `PolicyMetadata` + `PolicyPayload`. Metadata carries the identity of
   the document; payload carries the actionable content. Split
   deliberate: metadata reads without deserialising the payload
   (release gate can check version-and-signature before parsing the
   body), and payload can grow independently of metadata's fixed shape.

2. **Versioning** — two orthogonal numbers, both required:
   - `schema_version: u32` — this document's structural schema. Readers
     reject a `schema_version` they do not know (`manifest.py` pattern,
     also ADR-0009's pattern for the model record).
   - `policy_version: u64` — monotone identifier assigned by the issuer
     (control plane) on each publish. The agent applies a policy iff
     its `policy_version` is strictly greater than the currently active
     one — prevents rollback attacks and duplicate-apply.

3. **Signature** — `metadata.signature` is Ed25519 over the JSON
   canonicalisation of the document with the `signature` field replaced
   by a fixed placeholder. Canonicalisation is deterministic
   pretty-printed JSON (indent=2, keys sorted, no trailing whitespace)
   — the same format `model_record.json` uses (ADR-0009), for one less
   thing to remember. Ed25519 chosen for: small keys (32 bytes public,
   64 bytes signature), well-audited implementations in Rust
   (`ed25519-dalek`), no round-trip to a KMS in-band.

4. **Serialisation** — canonical JSON as above. Same reasoning as
   `model_record.json`: human-readable for triage, machine-diff-able,
   round-trips through `serde` cleanly, and one canonicalisation
   already lives in the workspace.

5. **Layered overrides (per-host)** — a per-host override document
   carries the same shape as `Policy` but with all payload sections
   optional. The agent applies a computed `Policy = baseline ⊕ overrides`
   at boot and on every policy update, where `⊕` is a
   **field-level override** (present in overrides → replaces baseline
   field; absent → keeps baseline field). No merge-inside-a-section
   (no per-key merging of maps inside a section): a section is either
   from baseline or from override, as a whole. This is deliberate to
   keep the merge trivially reasoned about at review time and by the
   ship gate — and it matches how `EventLogPolicy`'s current
   "all-or-nothing at struct level" already behaves.

## Payload sections (initial)

The payload carries **named sections** in an open-ended map. Each
section is a versioned sub-schema in its own right, so the payload
grows without a `schema_version` bump every time a new sensor lands.

Sections in v1:

- `sensors` — per-sensor toggles and knobs. `sensors.windows_eventlog`
  absorbs today's `EventLogPolicy`; `sensors.linux_ebpf`,
  `sensors.macos_endpointsecurity` (once M4 lands), etc., grow
  under the same key.
- `rules` — allowlist / denylist of rule identifiers, and per-rule
  overrides (threshold multipliers, mode: alert / silent / off).
- `models` — which ONNX model versions the agent is authorised to load
  (referenced by registry path + version, e.g.
  `cmdline-iforest-linux/0.2.0`); the release gate ADR-0009 can be
  extended to cross-check a loaded model against this list.
- `response` — the response actions permitted at each verdict tier
  (`kill`, `quarantine`, `isolate`, `live_session`); everything defaults
  to `deny` until explicitly enabled per action per policy.
- `thresholds` — global scoring / correlation thresholds (BAYES cut,
  correlation window, spool retention). Bounded numeric ranges enforced
  at parse time.
- `compliance_mode` — enum (`ComplianceMode::None | PciDss | HIPAA | ...`)
  gating built-in redaction and retention rules. Today's `ComplianceMode`
  enum (referenced in sensor uprobes, flagged as not-safe-yet by Jean on
  #178) becomes a first-class policy field, not a compile-time constant.

**Reserved**: `experimental` — a namespace where fields not covered by
`schema_version` can live. Readers ignore unknown keys under
`experimental`; anywhere else in the payload is strict.

## Consequences

- **Zero regression on today's helpers.** `is_trusted_system_path`,
  `name_exclusion_applies`, `expected_parents`,
  `parent_exclusion_applies` stay as free functions on the crate;
  they are used by rules for the masquerade check and do not belong in
  the policy document (they are compile-time truth, not distributed
  configuration).

- **`EventLogPolicy` migrates to `Policy.payload.sensors.windows_eventlog`**
  as a section in v1. The current struct definition and its
  `EventLogConfig` glue in the agent stay as-is temporarily; the
  implementation PR that follows this ADR wires the section reader
  through the same `EventLogConfig` translation, so no sensor code
  changes. `EventLogPolicy` is deprecated but not removed in v1 to give
  callers a stepping stone.

- **The release gate can grow model-authorisation checks** on top of
  the ADR-0009 provenance checks. `verify_provenance` is the natural
  place — if a loaded model's registry entry is not listed in
  `policy.payload.models`, reject. Deferred to a follow-up; the hook
  point lands with this ADR's implementation.

- **Setting `agent`'s effective compliance mode** stops being a
  compile-time constant. The uprobes PII scrub Jean flagged on #178 as
  "OFF by default, opt-in explicit" gains a policy toggle, and the
  audit of what triggers the scrub is centralised in the policy doc.

- **Signature verification is required on load** in strict mode. In
  dev mode a warning-only mode is available (documented next to the
  release gate's `SYNTHAEA_STRICT_PROVENANCE` env var, same pattern).

- **The N-1 struct problem is avoided.** Every next sensor / rule /
  model / response action grows a new payload section, not a new
  top-level type in the `policy` crate.

## Deferred

- **Signature key management** — where the public key lives on the
  agent, how it rotates, how a compromised key is revoked. Deserves
  its own ADR when M8 lands and the control plane actually starts
  issuing signed policies. Until then the implementation ships with a
  test-only key pair and an explicit "not production" flag.

- **Distribution mechanism** — canary rings via the M6 updater
  (ADR-0006 pattern), rollback on unhealthy fleet fraction, staged
  rollout by ring. Referenced but not designed here.

- **Backwards-compat readers across schema versions** — if v1 ever
  needs to co-exist with v2 in the field (staged migration), that
  needs a plan for what a v1 agent does with a v2 payload (reject vs.
  parse-strict + drop unknown sections). Today's decision: reject.
  Revisit when the first schema bump becomes real.

- **Rollback of a failed policy application** — if `policy_version`
  N+1 breaks the fleet, the M6 updater needs an atomic rollback path
  and a way to prevent the same broken version from being reapplied.
  Wiring the atomic swap and the rollback marker is M6 work.

- **Encryption-at-rest of the policy on disk** — the policy is
  configuration, not credentials, so cleartext-with-signature is fine
  for v1. Encryption stays available for a future ADR if the policy
  ever needs to carry actual secrets (rare in this shape).

## References

- ADR-0006 — Eventlog channel allowlist and volume counters (the
  original in-code `EventLogPolicy`; also cites the canary rings
  pattern this ADR points to for distribution).
- ADR-0009 — Model record binds scenario-replay results (the
  canonical JSON serialisation shape this ADR reuses, and the
  release-gate insertion point a future model-authorisation check
  would hook into).
- `crates/policy/src/lib.rs` — the crate this ADR extends.
- `agent/src/commands/windows.rs:56` — `eventlog_config()`, today's
  in-code `EventLogPolicy` → `EventLogConfig` translation; unchanged
  by this ADR but rebased onto the section reader in the follow-up
  implementation PR.
- Issue #23 — "Build policy: shared policy model" (this ADR's issue).
- Issue #107 — expected-parent verification (the reason the
  masquerade helpers live in this crate; unaffected).
