# Issue #83: Fleet Operations Dashboard (server/ops)

**Component:** `server/ops`
**Branch:** `feat/83-ops-dashboard`
**Status:** Blocked (depends on #28, #134)

## Summary

Build the fleet operations dashboard — the operator's view of fleet health, telemetry
accounting, rollout control, and ingest health. An EDR that cannot see its own health
degrades silently.

## Acceptance Criteria

- [ ] Dashboard shows lab fleet health incl. per-host loss counters
- [ ] Killing a sensor on one VM is visible (capability degraded) within a heartbeat
- [ ] Ring status reflects a content rollout with halt state

## Dependencies

### Critical Blockers

#### Issue #28: Scaffold server (Next.js + PostgreSQL)
**Status:** OPEN
**Why needed:**
- Next.js App Router + TypeScript base
- PostgreSQL schema + migrations
- Ingest route handlers for receiving agent data
- docker-compose dev environment

**What #83 needs from #28:**
- `/api/ingest/health` endpoint to receive HealthBeacon from agents
- Database schema for storing agent health state
- Authentication/authorization for ops dashboard routes
- Base UI layout and routing structure

#### Issue #134: Agent Health Telemetry
**Status:** PR #157 open, mergeable
**Why needed:**
- HealthBeacon data structure (agent_version, sensors, spool stats)
- SensorHealth data (name, pulse_count, silent flag)
- Periodic health beacon emission from agents

**What #83 needs from #134:**
```rust
// From crates/schema/src/lib.rs
pub struct HealthBeacon {
    pub timestamp_ns: u64,
    pub agent_version: String,
    pub sensors: Vec<SensorHealth>,
    pub spool_bytes: u64,
    pub spool_dropped: u64,
    pub enrich_dropped: u64,
}

pub struct SensorHealth {
    pub name: String,
    pub pulse_count: u64,
    pub silent: bool,
}
```

**Integration points:**
1. Agent sends HealthBeacon to `/api/ingest/health` every 30s (default interval)
2. Server stores in `agent_health_beacons` table
3. Dashboard queries for latest beacon per agent + time-series data
4. Server-side alerting on beacon silence (agent stopped beaconing)

### Related Issues

- **Issue #108:** EventSpool two-phase drain/ack (PR #156)
  - Provides spool stats (spool_bytes, spool_dropped) for telemetry accounting
  - Dashboard will surface per-host and fleet-wide spool drop counts

- **Issue #24:** Transport mTLS (PR #158)
  - Health beacons flow through transport layer to server
  - Dashboard needs agent identity from mTLS enrollment

## Features

### 1. Agent Health View

**Data sources:**
- `HealthBeacon` from agents (via #134)
- Agent enrollment records (mTLS cert metadata)
- Watchdog restart logs
- Tamper events (from `tamper` crate)

**UI Components:**
- Fleet overview: agent count by status (healthy, degraded, silent, offline)
- Per-agent detail:
  - Last check-in timestamp
  - Agent version
  - Sensor status table (name, pulse_count, silent flag)
  - Capability status from `Capabilities` + conformance
  - Watchdog restart history
  - Tamper events timeline

**Alerts:**
- Agent silent for > heartbeat interval (server-side beacon gap detection)
- Sensor silent (from SensorHealth.silent flag)
- Watchdog restart spike
- Tamper event detected

### 2. Telemetry Accounting

**Observable-loss counters:**
- Per-agent:
  - `spool_dropped` (from HealthBeacon)
  - `enrich_dropped` (from HealthBeacon)
  - Scan-queue sheds (future: needs agent instrumentation)
  - Bounded-map evictions (future: needs agent instrumentation)
  - Ring-buffer drops (future: needs agent instrumentation)

- Fleet-wide aggregations:
  - Total loss counters across fleet
  - Loss rate time-series
  - Per-host comparison (detect outliers)

**Anomaly detection:**
- Host that stops losing AND stops sending → tamper signal
- Sudden spike in loss counters → capacity issue
- Persistent high loss on single host → local resource issue

**UI Components:**
- Loss counter dashboard with time-series graphs
- Per-host loss breakdown table
- Fleet-wide loss trends
- Alerting rules configuration

### 3. Rollout Control

**Data sources:**
- Agent version from HealthBeacon
- Ring assignments (from enrollment/policy)
- Content version distribution status
- Model version distribution status

**UI Components:**
- Ring status table:
  - Ring name
  - Binary version target vs actual spread
  - Content version target vs actual spread
  - Model version target vs actual spread
  - Agent count per version
- Rollout halt/rollback controls
- Canary health monitoring (cross-ref with health metrics)

**Workflow:**
- Start rollout → agents in ring X pull new version
- Monitor health beacons for regressions
- Auto-halt on anomaly (watchdog restart spike, sensor silent, loss spike)
- Manual rollback if needed

### 4. Ingest Health

**Metrics:**
- Event ingest rate (events/sec by type)
- Ingest lag (event timestamp_ns vs ingestion timestamp)
- Per-tenant quotas and usage
- Queue depths (if applicable)

**UI Components:**
- Ingest rate time-series graph
- Lag histogram
- Tenant quota usage table
- Queue depth gauges

## Technical Design

### Database Schema (PostgreSQL)

```sql
-- Agent health beacons (time-series)
CREATE TABLE agent_health_beacons (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id),
    timestamp_ns BIGINT NOT NULL,
    agent_version TEXT NOT NULL,
    spool_bytes BIGINT NOT NULL,
    spool_dropped BIGINT NOT NULL,
    enrich_dropped BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, timestamp_ns)
);
CREATE INDEX idx_beacons_agent_time ON agent_health_beacons(agent_id, timestamp_ns DESC);

-- Sensor health (child records of beacon)
CREATE TABLE sensor_health (
    id BIGSERIAL PRIMARY KEY,
    beacon_id BIGINT NOT NULL REFERENCES agent_health_beacons(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pulse_count BIGINT NOT NULL,
    silent BOOLEAN NOT NULL
);
CREATE INDEX idx_sensor_health_beacon ON sensor_health(beacon_id);

-- Agent registry (from enrollment, simplified view)
CREATE TABLE agents (
    id UUID PRIMARY KEY,
    hostname TEXT NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ,
    mtls_cert_fingerprint TEXT NOT NULL,
    ring TEXT, -- rollout ring assignment
    UNIQUE(mtls_cert_fingerprint)
);
CREATE INDEX idx_agents_last_seen ON agents(last_seen DESC);
```

### API Routes

```typescript
// server/app/api/ingest/health/route.ts
// POST /api/ingest/health
// Receives HealthBeacon from agents, stores in DB
// Authentication: mTLS client cert (agent identity)

// server/app/api/ops/fleet-health/route.ts
// GET /api/ops/fleet-health
// Returns fleet health summary + per-agent status
// Authentication: user session (ops role required)

// server/app/api/ops/agent/[id]/health/route.ts
// GET /api/ops/agent/{id}/health?since={timestamp}
// Returns health beacon time-series for one agent
// Authentication: user session (ops role required)

// server/app/api/ops/loss-counters/route.ts
// GET /api/ops/loss-counters
// Returns fleet-wide telemetry loss aggregations
// Authentication: user session (ops role required)
```

### UI Pages

```
server/app/ops/
├── layout.tsx                  # Ops dashboard layout
├── page.tsx                    # Fleet overview (main dashboard)
├── agents/
│   ├── page.tsx               # Agent list with filters
│   └── [id]/
│       ├── page.tsx           # Agent detail view
│       └── health/page.tsx    # Agent health time-series
├── loss/
│   └── page.tsx               # Telemetry accounting dashboard
├── rollout/
│   ├── page.tsx               # Ring status + rollout control
│   └── [ring]/page.tsx        # Ring detail view
└── ingest/
    └── page.tsx               # Ingest health metrics
```

### React Components (Sketches)

```typescript
// components/ops/FleetHealthOverview.tsx
// - Agent count by status (healthy, degraded, silent)
// - Time-series of fleet health
// - Recent alerts list

// components/ops/AgentHealthCard.tsx
// - Agent hostname, version, last seen
// - Sensor status badges (green/yellow/red)
// - Loss counter summary
// - Link to detail view

// components/ops/SensorStatusTable.tsx
// - Table: sensor name, pulse_count, silent flag, status badge
// - Sortable, filterable

// components/ops/LossCounterChart.tsx
// - Time-series line chart: spool_dropped, enrich_dropped
// - Per-agent and fleet-wide views

// components/ops/RolloutStatusTable.tsx
// - Table: ring, target version, actual spread, agent count
// - Halt/rollback action buttons
```

## Implementation Plan

### Phase 1: Foundation (depends on #28 landing)
1. Database migrations for agent_health_beacons, sensor_health, agents tables
2. `/api/ingest/health` endpoint to receive HealthBeacon
3. Background job to detect beacon silence (server-side)
4. Basic agent registry (enrollment creates agent record)

### Phase 2: Fleet Health Dashboard
1. `/ops` page layout and navigation
2. `/ops/agents` list view with last-seen timestamps
3. `/ops/agents/[id]` detail view with sensor status table
4. Fleet health overview component (agent count by status)
5. Real-time updates (polling or websocket)

### Phase 3: Telemetry Accounting
1. Loss counter aggregation queries
2. `/ops/loss` dashboard with time-series charts
3. Anomaly detection rules (configurable thresholds)
4. Alerting on loss spikes

### Phase 4: Rollout Control
1. Ring assignment schema + API
2. `/ops/rollout` ring status table
3. Version spread calculation (actual vs target)
4. Halt/rollback controls

### Phase 5: Ingest Health
1. Ingest metrics collection (event rate, lag)
2. `/ops/ingest` dashboard
3. Per-tenant quota tracking

## Testing Strategy

### Integration Tests
- Agent sends HealthBeacon → stored in DB → appears in dashboard
- Sensor goes silent → dashboard shows red status within 1 heartbeat
- Agent stops beaconing → server detects silence → alert fires

### E2E Tests (Playwright)
- Navigate to /ops → see fleet overview
- Click agent → see detail view with sensor table
- Kill sensor on test VM → verify degraded status appears
- Rollout to ring → verify version spread updates

### Load Tests
- 1000 agents sending beacons every 30s → DB write load
- Dashboard query performance with 1000+ agents

## Monitoring & Observability

- Ingest endpoint latency (p50, p99)
- Database query performance (slow query log)
- Beacon gap alerts (how many agents silent)
- Dashboard page load time
- Alerting rule evaluation lag

## Security Considerations

- Ops dashboard requires authenticated user session (not agent mTLS)
- RBAC: ops role required to access /ops routes
- Rate limiting on ingest endpoint (per agent)
- SQL injection prevention (parameterized queries)
- XSS prevention (sanitize agent-provided strings in UI)

## Open Questions

1. **Beacon retention policy:** How long to keep health beacons in DB?
   - Proposal: 30 days raw, then downsample to hourly aggregates for 1 year

2. **Real-time updates:** Polling vs WebSocket for dashboard?
   - Proposal: Start with polling (every 5s), upgrade to WebSocket if needed

3. **Alerting integration:** In-app alerts vs external (PagerDuty, email)?
   - Proposal: In-app first, then integrate with server/integrations (#88)

4. **Multi-tenancy:** Ops dashboard per tenant or global (for MSP)?
   - Proposal: Per-tenant by default (filter by tenant_id), global view for admin

## Documentation Needed

- Ops dashboard user guide (screenshots, workflows)
- Alerting rules configuration guide
- Rollout procedure runbook
- Beacon silence troubleshooting guide

## Related Code Locations

- Agent health beacon implementation: `agent/src/health.rs` (from #134)
- Schema types: `crates/schema/src/lib.rs` (HealthBeacon, SensorHealth)
- Tamper detection: `crates/tamper/src/heartbeat.rs` (SilenceMonitor)
- Spool stats: `crates/store/src/spool.rs` (from #108)

## Notes

- This is a foundational feature — visibility into fleet health is critical
- The dashboard design should prioritize operator efficiency (glanceable status)
- Anomaly detection rules must be tunable (different fleets have different baselines)
- Loss counters are "observable loss" — we know we dropped, we just report it honestly
