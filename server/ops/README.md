# server/ops — Fleet Operations Dashboard

The operator's view: an EDR that cannot see its own health degrades silently.

- **Agent health**: version spread across rings, last check-in, sensor status per
  capability (from `Capabilities` + conformance), watchdog restarts, tamper events
- **Telemetry accounting**: the observable-loss counters the agent already keeps —
  spool drops, scan-queue sheds, bounded-map evictions, ring-buffer drops — surfaced
  per host and fleet-wide, with alerting on anomalies (a host that stops losing AND
  stops sending is a tamper signal)
- **Rollout control**: ring status for binaries/content/models, halt/rollback state
- **Ingest health**: lag, volume by event type, per-tenant quotas
