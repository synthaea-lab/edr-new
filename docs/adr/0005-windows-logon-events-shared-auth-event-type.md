# ADR-0005: Windows logon/session events via a shared `Event::Auth` type

- **Status**: accepted
- **Date**: 2026-09-07

## Context

Issue #94 ("Done when") asks for Windows logon/session telemetry — events
**4624** (successful logon), **4625** (failed logon), **4648** (explicit-
credential logon, a classic RunAs/lateral-movement signal), and **4672**
(special privileges assigned to a new logon) — normalized end-to-end, sharing
its event type with `sensor-linux-journal`'s future authentication telemetry
(sshd accept/failure, `su`/`sudo`, PAM sessions). `sensor-linux-journal` is
currently a doc-only stub (`crates/sensors/linux/journal/src/lib.rs`) with zero
implementation, so this is a forward design requirement, not an existing shape
to copy: this ADR is what defines that shared shape.

The persistence work in ADR-0004 set a precedent for reusing an existing
`Event` variant (`FileOpenEvent`) rather than adding a new one, specifically
because that reuse was explicitly pragmatic — pending a dedicated event family
that did not yet have a reason to exist. Logon events are a different
situation: the whole point of #94's requirement is a type two platforms share,
which is not what `FileOpenEvent` (a filesystem concept) is for. Reusing it
here would be forcing the wrong shape rather than deferring a real one, so this
ADR adds a dedicated `Event::Auth(AuthEvent)` variant instead.

Issue #94 additionally asks for a policy-configurable channel allowlist plus
per-channel volume counters. That part is **out of scope for this ADR and this
round of work** — `crates/policy` currently has no configuration/allowlist
concept at all (only two pure path-trust functions), and `store::BoundedMap`'s
LRU-eviction shape does not fit a small fixed set of channel counters. Scoped
down deliberately (see the follow-up issue this ADR proposes) rather than
designing a policy subsystem as a side effect of a schema change.

## Decision

Add `schema::AuthEvent` / `AuthOutcome` / `AuthKind` and a new
`Event::Auth(AuthEvent)` variant (`crates/schema/src/lib.rs`). Deliberately
narrower than either platform's native audit record — only what a
cross-platform lateral-movement/privilege-escalation rule can actually use
today (`outcome`, `kind`, `target_user`, `target_user_sid`, `source_address`,
`status_code`); platform-only detail that doesn't generalize (a Windows
`LogonType` code, a Linux PAM service name) is left out rather than added
speculatively, per this crate's additive-only discipline.

`meta` (the existing `EventMeta`) identifies the process that *reported* the
event (LSASS for all four Windows event IDs — the
"Microsoft-Windows-Security-Auditing" provider runs inside it), while
`target_user`/`target_user_sid` identify the account the event is *about*.
These are already distinct concepts elsewhere in the schema (an `ExecEvent`'s
`meta.pid` is the executing process, not necessarily who is "responsible" for
it), so no new field was needed to carry that distinction — see
`sensor-windows-eventlog::xml::LogonEvent`'s doc for exactly which Windows
`Subject*`/`Target*` field feeds which schema field per event ID (4672 in
particular has no `Target*` field at all: the Subject *is* the account
receiving the privileges, so it is reported as `target_user` too for schema
uniformity).

Implemented in `sensor-windows-eventlog` (`crates/sensors/windows/eventlog`),
alongside the two persistence detections, since all four event IDs live on the
same Security channel already being polled there — a fourth poll thread would
duplicate the channel read for no benefit, so instead one poller queries all
four IDs together and dispatches by each block's own `<EventID>`
(`sensor.rs::poll_logon_events`/`to_auth_event`). Per ADR-0004's still-open
item, this reads the channel via `wevtutil` polling like the rest of the
crate, not a fresh `EvtSubscribe` evaluation — consistency with the two
existing pollers, not a re-confirmation that logon events hit the same ETW
wall 4698 did.

**Field names are not yet lab-verified.** Unlike 7045/4698 (both empirically
confirmed against a real `wevtutil qe .../f:xml` capture during the original
#94 investigation), the 4624/4625/4648/4672 field names used here
(`TargetUserSid`, `LogonType`, `IpAddress`, `Status`/`SubStatus`,
`PrivilegeList`, …) are the standard, publicly documented Microsoft
Security-auditing schema, not yet reconciled against this project's lab VM.
Whoever validates this should capture real events for all four IDs and diff
them against `xml.rs`'s test fixtures before relying on this in production.

### `SCHEMA_VERSION` bump and fixture-versioning precedent

A new `Event` variant is a new possible `"type"` tag value in the serialized
form — serialization-visible per the crate's own rule, so `SCHEMA_VERSION`
moves from 1 to 2, with a new `tests/fixtures/v2/` directory
(`tests/golden.rs` now reads from it) and `tests/v1_compat.rs` added to pin
that the frozen `tests/fixtures/v1/*.json` still deserialize under the
current `Event` type (they do — a new `#[non_exhaustive]` variant breaks
nothing for readers of old data).

This is the **first version bump since the crate's inception**, so there was
no established precedent for what a new fixture directory should contain:
only the new/changed fixtures, or a full fresh snapshot of every fixture at
the current version. This ADR records the choice made here — **a full fresh
snapshot** (`v2/` holds all 7 pre-existing fixtures, copied verbatim and
unmodified, plus the 2 new `auth_logon`/`auth_logon_failure` fixtures) — so
that a later bump has something to follow or deliberately reconsider. The
reasoning: `tests/golden.rs` reads fixtures from one directory constant, so a
"changed-only" `v2/` would need golden tests to read some fixtures from `v1/`
and others from `v2/` depending on which changed — more bookkeeping for no
benefit at this fixture count, and it would make a fixture's directory a
second, easy-to-miss place recording whether it changed. A full snapshot's
downside (storage of duplicate JSON) is trivial at this scale; revisit if it
ever isn't.

## Consequences

- `schema::sensor::Capabilities` gains `auth_events: bool`;
  `EventLogSensor::capabilities()` sets it `true` alongside the existing
  `file_events: true`.
- The "Logon" and "Special Logon" audit subcategories (GUIDs
  `{0CCE9215-...}` / `{0CCE921B-...}`, same locale-independence reasoning as
  4698's) are enabled best-effort at sensor startup
  (`enable_logon_audit`), same non-fatal pattern as
  `enable_scheduled_task_audit`. Unlike 4698's "Other Object Access Events",
  both are part of Windows' default audit policy out of the box, so this is
  reinforcement against a hardened/custom policy, not the primary enablement
  path — a failure here is logged at a lower level of concern than a 4698
  failure would be.
- 4648 alone does not distinguish a successful from a failed explicit-credential
  logon (it has no status field — that is what a subsequent 4624/4625 is for),
  so it is always reported as `AuthOutcome::Success`, meaning "the attempt was
  observed", not "and it succeeded". Rules consuming `AuthKind::ExplicitCredentials`
  must not read `outcome` as an authentication verdict for this one kind.
- Deferred, tracked as a follow-up rather than folded into this ADR: the
  policy-configurable channel allowlist and per-channel volume counters from
  #94's remaining checklist item. **Now implemented — see
  `docs/adr/0006-eventlog-channel-allowlist-and-volume-counters.md`**, which
  also found that `sensor-*` crates cannot depend on `policy` at all
  (`tools/check-deps.py`), so the allowlist type has to be split across a
  `policy` type and a separate sensor-side config type bridged by `agent` —
  not the single `policy::EventLogAllowlist` this ADR originally sketched.
