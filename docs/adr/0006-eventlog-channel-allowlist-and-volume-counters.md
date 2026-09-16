# ADR-0006: `sensor-windows-eventlog` channel allowlist and volume counters

- **Status**: accepted
- **Date**: 2026-09-07

## Context

Issue #94's remaining "Done when" item, deferred by ADR-0005: a policy-
configurable allowlist over which `sensor-windows-eventlog` channels/event
groups are active, plus per-channel volume counters. ADR-0005 scoped this out
because, at the time, it looked like it might require designing a
policy-loading subsystem that does not exist in this codebase. Looking closer
before starting this ADR:

- `crates/policy`'s own crate doc says policies are "versioned and signed;
  distributed by the control plane" — but nothing in the workspace actually
  loads, parses, or distributes a policy document yet. Every existing item in
  `policy` (`is_trusted_system_path`, `name_exclusion_applies`) is a plain
  function called directly; there is no in-flight "current policy" value
  anywhere. So adding a plain struct with a `Default` impl to `policy` is
  consistent with what is already there, not a new kind of infrastructure.
- `crates/config`'s crate doc draws the line this workspace already intends:
  "local, per-install agent configuration... distinct from `policy`, which is
  versioned, signed, and distributed by the control plane at runtime." A
  channel allowlist is exactly the kind of thing that line puts in `policy`,
  not `config`.
- `tools/check-deps.py` is unambiguous: `sensor-*` crates depend only on
  `schema` (and, for a Linux sensor pair, their own wire crate). `policy` is
  base-tier and depends only on `schema` too. Neither crate may depend on the
  other. **`sensor-windows-eventlog` cannot read `policy::EventLogPolicy`
  directly** — this is the one hard constraint the design has to route around.

So the real scope here is smaller than ADR-0005 assumed: a plain policy type
(no distribution mechanism — that is a separate, larger, and currently
unstarted piece of work, tracked as a follow-up below, not invented here) and
the sensor-side toggle/counter mechanism it configures.

## Decision

Two independent plain-data types, one per side of the dependency boundary
`check-deps.py` enforces, plus a manual conversion at the one place both
types are in scope:

- **`policy::EventLogPolicy`** (`crates/policy/src/lib.rs`) — three `bool`
  fields, one per `sensor-windows-eventlog` poll target
  (`service_installs_enabled`, `scheduled_tasks_enabled`,
  `logon_events_enabled`), `Default` = all `true`. No `serde` derive: nothing
  in this workspace loads a policy document yet, so a serialization format
  would be speculative. The first struct this crate has ever held.
- **`sensor_windows_eventlog::EventLogConfig`** (`crates/sensors/windows/eventlog/src/sensor.rs`)
  — the same three fields, sensor-side. `EventLogSensor::with_config` takes
  one; `EventLogSensor::new` is `with_config(EventLogConfig::default())`, so
  existing callers (and the conformance suite, once it exists) see no change.
  A disabled group's poll thread is never spawned in `run` — not filtered
  after querying — so a disabled group costs nothing, not even the
  `wevtutil` call. `capabilities()` now reflects the config
  (`auth_events: self.config.logon_events_enabled`, `file_events` true if
  either file-producing group is on) rather than a static value, per the
  `Capabilities` doc's own rule ("must reflect what `run` actually emits").
- **`agent/src/commands/windows.rs`** bridges them: `eventlog_config(&policy::EventLogPolicy) -> sensor_windows_eventlog::EventLogConfig`,
  a manual field-by-field copy (not a `From` impl — an impl needs one of the
  two types local to the crate it's written in, and neither crate may depend
  on the other, so the binary is the only legal place for this code to live).
  Today `run_windows_sensors` calls this with `policy::EventLogPolicy::default()`
  — there is no live policy document to load yet, so this is the same
  behavior as before this ADR (everything enabled), wired through the new
  types rather than actually configurable end-to-end yet.

**Volume counters**: `sensor_windows_eventlog::EventLogCounters` — one
`AtomicU64` per poll target, incremented once per event actually normalized
and handed to the sink (a block skipped for missing/unusable fields is not
counted — it was already filtered out as noise, not telemetry).
`EventLogSensor::counters()` returns a cloneable `Arc` handle, readable from
any thread while `run` is active. Nothing in this workspace currently reads
it — `crates/conformance` is a doc-only stub, and no diagnostics/health
surface exists yet — so this ADR adds the primitive, not a consumer for it.

## Consequences

- `policy` gains its first dependency-free struct; `agent` gains its first
  dependency on `policy` (previously zero — checked before writing this ADR).
- The "channel allowlist" is real and testable (`EventLogConfig`/`EventLogPolicy`
  each have their own unit tests; `EventLogSensor::capabilities` has tests for
  the disabled-group cases) but **not yet backed by a live, loadable policy
  document** — `policy::EventLogPolicy::default()` is the only value ever
  constructed today. Wiring an actual control-plane-distributed policy
  (parsing, signature verification, hot-reload) is unstarted and explicitly
  out of scope here; it is a substantially larger piece of work than this
  ADR's channel-toggle plumbing and deserves its own design pass whenever
  it's prioritized — most likely alongside `config`'s own eventual file-loading
  story, since the two crates will want a similar loading mechanism.
- No CLI flag exposes `EventLogConfig` yet either (`agent`'s `clap` surface is
  unchanged) — the only lever today is editing
  `policy::EventLogPolicy::default()`'s literal field values and rebuilding,
  which is not "configurable" in any operationally useful sense. A real
  follow-up (CLI flag, config file, or actual policy loading — whichever
  lands first) is needed before this reaches an operator.
- `EventLogCounters` has no reader yet. The natural next step is a
  diagnostics/health surface in `agent` (none exists) or wiring it into
  `crates/conformance` once that crate has real content — either is future
  work, not blocked by anything added here.
