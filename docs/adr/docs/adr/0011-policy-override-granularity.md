# ADR-0011: Policy override granularity — map-level sensors and safety-critical sub-objects

- **Status**: proposed
- **Date**: 2026-09-18

## Context

Post-merge review of ADR-0010 (PR #225, merged 2026-09-18) by @old-dov surfaced
two coupled questions about the override layering rule the ADR defined:

1. **Map-typed sections.** ADR-0010 states: *"a section is either from baseline
   or from override, as a whole"*. This reads unambiguously at the top-level
   payload, but `sensors` is a multi-sensor **map** (`sensors.windows_eventlog`,
   `sensors.linux_ebpf`, `sensors.macos_endpointsecurity`, ...), and the
   whole-section rule as written would force every override that touches one
   sensor to rewrite every other sensor's sub-document too. The intent when
   ADR-0010 was drafted was per-sensor override (each key of the map as an
   independent override unit), but that intent was never spelled out, which
   leaves the letter of the ADR at odds with what any sensible operator would
   want to do.

2. **Where to declare a section safety-critical.** The proposed extension to
   ADR-0010 was to mark certain sections as `safety-critical` — parse-time
   rejection of a partial override to prevent silent disabling of security
   controls (e.g. an operator overriding `sensors.windows_eventlog` and
   forgetting `redaction.pii_scrub_enabled`, silently turning PII scrub off —
   the exact regression Hugo flagged as an open surface on #178). Declaring
   `safety-critical` at the top-level section (whole `sensors`) is too coarse:
   it re-introduces the same "rewrite every unrelated sensor" problem as (1).
   The right level is the sub-object where the security-relevant fields
   actually live.

These two questions share a resolution: pin down the exact granularity of
override merge, then apply `safety-critical` at that same granularity.

## Decision

Two clarifications to ADR-0010, both effective from v1 of the policy schema:

### 1. Map-typed sections merge at the key level

A payload section whose schema is a `map<string, sub-document>` is merged at
the map-key level: an override document containing `sensors.linux_ebpf`
replaces only the `linux_ebpf` sub-document; every other key in `sensors`
(`windows_eventlog`, `macos_endpointsecurity`, ...) is kept from the baseline.

The "section is either from baseline or from override, as a whole" rule from
ADR-0010 stands at the **sub-document level**: within one sensor's sub-document
(e.g. `sensors.linux_ebpf`), the field-omission-keeps-baseline rule does *not*
recurse — the sub-document is present as a whole or kept from baseline as a
whole. The rule shifts one level of nesting deeper for maps, and nothing else
about ADR-0010's merge semantics changes.

Sections not modelled as maps (`compliance_mode`, `thresholds`, ...) keep
ADR-0010's original whole-section rule unchanged.

### 2. Safety-critical is a sub-object attribute, not a section-level one

A **sub-object** (either a whole non-map section, or one map-value in a
map-typed section) can be marked `safety-critical`. When an override contains a
`safety-critical` sub-object, the parser requires the sub-object to be
**complete** — every field the schema declares must be present. A partial
override of a safety-critical sub-object is rejected at parse time with an
explicit error naming the missing fields; the policy is not applied and the
agent keeps its current effective policy.

Safety-critical sub-objects in v1:

- `compliance_mode` (whole non-map section — the whole enum + hint fields must
  travel together, partial override never made sense here).
- `sensors.<any-sensor>.redaction` (the redaction sub-document of each sensor
  that declares one — today `sensors.windows_eventlog.redaction`,
  `sensors.linux_uprobes.redaction`; extended per-sensor as future ADR-0010
  payload sections gain a `redaction` sub-doc).

Any override touching one of these must replace the sub-object entirely, not a
subset of its fields.

## Consequences

- The "override per sensor" ergonomics ADR-0010 aimed at is preserved — an
  operator can override `sensors.linux_ebpf.tls_enabled` without knowing or
  touching any other sensor.
- The silent-disable-security-control risk (partial override of a redaction
  sub-doc dropping the omitted fields back to their absent default) is closed
  at parse time, not at review time. A reviewer no longer has to reason about
  "did the operator remember every field of `sensors.windows_eventlog.redaction`?"
  — the parser does it.
- The parser gains one small responsibility: a list of safety-critical
  sub-object paths (or an equivalent per-field schema attribute), and a
  completeness check applied when an override contains one of them. The exact
  mechanism (a `safety_critical: true` schema flag versus a hardcoded
  `SAFETY_CRITICAL_PATHS = ["compliance_mode", "sensors.*.redaction"]` in the
  parser) is an implementation detail deferred to the PR that lands the
  section reader.
- ADR-0010's spec of `Policy = baseline ⊕ overrides` is preserved; this ADR
  only pins down what ⊕ means at each level, without changing its intent.

## Deferred

- **Which additional sub-objects gain safety-critical status.** Likely
  candidates as their sections land: `response.action_allowlist` (M6 —
  automated response actions), `models` (M11 — model activation), any future
  `sensors.<sensor>.exfiltration_taps` sub-doc. Added case by case rather than
  speculatively.
- **Mechanism** (schema flag vs. hardcoded path list) — implementation choice
  in the follow-up PR that wires the section reader; the ADR only fixes what
  the constraint means, not how the parser expresses it.
- **Deeper-nested maps** (e.g. a future `rules.<rule_id>` map with per-rule
  sub-docs) reuse Decision 1 by recursion at their map level; if a
  qualitatively new schema shape emerges, revisit here.

## References

- ADR-0010 — the ADR this one precises (PR #225, merged 2026-09-18).
- Discussion on Discord 2026-09-18 (@old-dov, @Sollykhan) — the review that
  surfaced both questions.
- Issue #178 — Hugo's original PII-surface finding, the concrete regression
  vector this ADR closes for `sensors.*.redaction`.
- Issue #23 — "Build policy: shared policy model" (parent issue of ADR-0010
  and this ADR).
