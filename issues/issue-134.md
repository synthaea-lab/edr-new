# Issue #134: Agent Health Telemetry

**PR:** #157
**Branch:** `feat/134-agent-health-telemetry`
**Status:** Open, Mergeable

## Summary

Periodic health beacon infrastructure for the agent. A background thread collects
counters from sensors, spool, and enrichment queue, then emits a `HealthBeacon`
at a fixed cadence (default 30s). The beacon flows through a separate channel
(not the Event pipeline) so it doesn't pollute telemetry consumers.

"Silence is a detection": an agent that stops beaconing is as suspicious as one
that stops sending events.

## Files Changed

### New Files
- `agent/src/time.rs` — Shared `now_ns()` helper to avoid duplication between
  health.rs and sink.rs

### Modified Files
- `crates/schema/src/lib.rs` — Added `SensorHealth` and `HealthBeacon` types
  (standalone, NOT in `Event` enum)
- `crates/tamper/src/heartbeat.rs` — Added `sensor_health()` method returning
  `Vec<schema::SensorHealth>`
- `crates/tamper/Cargo.toml` — Added `schema` dependency
- `agent/src/health.rs` — `HealthCollector` with traits for testability
- `agent/src/main.rs` — Added `mod time`
- `agent/src/sink.rs` — Uses shared `crate::time::now_ns()`

## Implementation Details

### Schema Types (crates/schema/src/lib.rs)

```rust
pub struct SensorHealth {
    pub name: String,
    pub pulse_count: u64,
    pub silent: bool,
}

pub struct HealthBeacon {
    pub timestamp_ns: u64,
    pub agent_version: String,
    pub sensors: Vec<SensorHealth>,
    pub spool_bytes: u64,
    pub spool_dropped: u64,
    pub enrich_dropped: u64,
}
```

**Design decision:** `HealthBeacon` is NOT a variant of `Event`. Health beacons
have no `EventMeta` (no originating process), so putting them in the Event enum
would create a panic path in `Event::meta()`. They flow through a separate
transport channel.

### Health Collector (agent/src/health.rs)

Trait-based design for testability:

- `DroppedCounter` — reads enrichment queue drop count
- `SensorHealthSource` — reads sensor health snapshots
- `SpoolStatsSource` — reads spool byte/drop counts

The collector runs in a dedicated thread with interruptible sleep (Condvar-based)
for graceful shutdown.

### Tamper Integration (crates/tamper/src/heartbeat.rs)

`SilenceMonitor::sensor_health()` returns `Vec<schema::SensorHealth>` directly,
avoiding type duplication.

## Review Fixes (Commit 4182508)

### Blocking Issues Fixed

1. **SCHEMA_VERSION reverted** — Kept at 9 (was incorrectly bumped to 10).
   No fixture needed since HealthBeacon isn't serialized as an Event variant.

2. **Removed Event::HealthBeacon** — Health beacons emit through separate
   channel, not the telemetry Event enum. This avoids panic path in `meta()`.

3. **Restored original Event::meta()** — No `meta_opt()` needed; all Event
   variants have meta.

4. **Changed emit callback** — Takes `HealthBeacon` directly, not `Event`.

### Additional Improvements

- Interruptible sleep using `Condvar` for graceful shutdown
- Shared `time::now_ns()` helper extracted to dedicated module
- `tamper::SilenceMonitor` returns `Vec<schema::SensorHealth>` directly
- Fixed log macro format (log crate, not tracing structured syntax)

## Tests

All tests pass:
- `agent::health::tests::collects_health_beacon` — verifies beacon collection
- `agent::health::tests::stop_interrupts_sleep` — verifies graceful shutdown
- `tamper::heartbeat::tests::*` — 6 tests for silence detection

## Not Yet Wired

Integration with main loop pending transport (#24). The collector is ready but
not spawned in `cmd_run()` yet.

## Related Issues

- #24 — Transport mTLS (health beacons will use the transport layer)
- #108 — EventSpool two-phase drain/ack (spool stats fed to health beacon)
