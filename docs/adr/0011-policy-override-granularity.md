# ADR-0011: Policy override granularity — map-level units and safety-critical sub-objects (amends ADR-0010)

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

## Override granularity summary

Three granularities of override apply, depending on how the target field is
modelled in the payload schema. This table is the dispatch reference — a
given target is characterised by which rows apply to it, not by belonging to
exactly one row (`compliance_mode` for instance is both a flat section and
safety-critical).

| Granularity                                    | Merge rule                                                                        | Example                                                                                     |
|------------------------------------------------|-----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **Flat section** (non-map)                     | Section as a whole is either from baseline or from override; omitted → keep baseline. | `thresholds`, `compliance_mode`, `experimental`                                             |
| **Map-typed section** (map key → sub-document) | Merged at the map-key level: per-entry override unit; entries not present in override are kept from baseline. | `sensors.<capteur>`; (later) `rules.<rule_id>`                                              |
| **Safety-critical sub-object**                 | Must be **complete** when it appears in an override; partial override is rejected at parse time and the policy is not applied. | `compliance_mode` (the whole flat section), `sensors.<capteur>.redaction` (one sub-doc per sensor) |

Anything in the payload that a future ADR-0010 amendment adds is classified
against this table before it lands, so the intent is not left implicit again.

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

### 3. Safety-critical declaration mechanism for v1: hardcoded path list

For v1, safety-critical sub-objects are declared as a **hardcoded list in
the parser** (`SAFETY_CRITICAL_PATHS = ["compliance_mode",
"sensors.*.redaction"]`, exact form TBD in the implementation PR). This
matches the "open-ended payload sections that grow additively" principle
established by ADR-0010: the schema itself stays declarative, the parser
carries the safety-critical semantics as code the reviewer can read in one
place. A schema-level `safety_critical: true` attribute or a runtime registry
earns its own ADR when a future section actually needs safety-critical
semantics *and* the hardcoded list becomes a real obstacle (an operator or
integrator pain, not a speculative one).

## Consequences

- The "override per sensor" ergonomics ADR-0010 aimed at is preserved — an
  operator can override `sensors.linux_ebpf.tls_enabled` without knowing or
  touching any other sensor.
- The silent-disable-security-control risk (partial override of a redaction
  sub-doc dropping the omitted fields back to their absent default) is closed
  at parse time, not at review time. A reviewer no longer has to reason about
  "did the operator remember every field of `sensors.windows_eventlog.redaction`?"
  — the parser does it.
- The parser gains one small responsibility: the hardcoded
  `SAFETY_CRITICAL_PATHS` list (Decision 3) and a completeness check applied
  when an override contains one of those paths. Bounded scope, one place to
  audit.
- ADR-0010's spec of `Policy = baseline ⊕ overrides` is preserved; this ADR
  only pins down what ⊕ means at each level and how safety-critical is
  declared, without changing ADR-0010's intent.

## Deferred

- **Which additional sub-objects gain safety-critical status.** Likely
  candidates as their sections land: `response.action_allowlist` (M6 —
  automated response actions), `models` (M11 — model activation), any future
  `sensors.<sensor>.exfiltration_taps` sub-doc. Added to the hardcoded list
  case by case as the sections themselves land, not speculatively.
- **Migration from hardcoded list to schema-declared attribute.** Left to a
  future ADR triggered by real operator or integrator pain, not by aesthetics.
- **Deeper-nested maps** (e.g. a future `rules.<rule_id>` map with per-rule
  sub-docs, or a per-sensor `rules` submap) reuse Decision 1 by recursion at
  their map level; if a qualitatively new schema shape emerges, revisit here.

## References

- ADR-0010 — the ADR this one precises (PR #225, merged 2026-09-18).
- Discussion on Discord 2026-09-18 (@old-dov, @Sollykhan) — the review that
  surfaced both questions and the request to make the granularity dispatch
  explicit as a table, and to trancher the declaration mechanism (hardcoded
  vs. extensible) in the ADR rather than leave it in Deferred.
- Issue #178 — Hugo's original PII-surface finding, the concrete regression
  vector this ADR closes for `sensors.*.redaction`.
- Issue #23 — "Build policy: shared policy model" (parent issue of ADR-0010
  and this ADR).
