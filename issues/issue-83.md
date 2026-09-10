# Issue #83: Fleet Operations Dashboard (server/ops)

**Component:** `server/ops`
**Branch:** `feat/83-ops-dashboard`
**Status:** BLOCKED — depends on #28 (server scaffold) and #134 (agent health telemetry)

---

## Résumé Exécutif

Dashboard d'opérations pour visualiser la santé de la flotte EDR en temps réel: agents actifs/silencieux, état des capteurs, compteurs de perte de télémétrie, contrôle de rollout, et santé d'ingestion.

### Dépendances Critiques

**Issue #28: Server Scaffold (Next.js + PostgreSQL)** — BLOQUANT
- Status: OPEN, pas démarré
- Requis: Next.js setup, PostgreSQL, endpoint `/api/ingest/health`, auth
- Sans #28, impossible de commencer #83

**Issue #134: Agent Health Telemetry** — REQUIS
- Status: PR #157 OPEN, MERGEABLE ✅
- Fournit: `HealthBeacon` structure (agent version, sensors status, loss counters)
- Reste à faire: intégrer transport (#24), câbler dans agent main loop

### Flux de Données (Agent → Server → Dashboard)

```
Agent (HealthCollector #134)
  ├─ Collecte toutes les 30s:
  │   ├─ SensorHealth (name, pulse_count, silent)
  │   ├─ spool_bytes, spool_dropped (EventSpool #108)
  │   └─ enrich_dropped (EnrichQueue)
  └─► Émet HealthBeacon via Transport (#24)
        │
        ▼
Server (#28 + #83)
  ├─ POST /api/ingest/health (reçoit HealthBeacon)
  ├─ Stocke: agent_health_beacons + sensor_health tables
  ├─ Background job: détecte agents silencieux
  └─ GET /api/ops/* (queries pour dashboard)
        │
        ▼
Dashboard UI (#83)
  ├─ /ops — Fleet overview (agents par statut)
  ├─ /ops/agents/[id] — Agent detail (sensors, loss counters)
  ├─ /ops/loss — Telemetry accounting (fleet-wide)
  └─ /ops/rollout — Ring status + version spread
```

### Schema PostgreSQL (mappé sur #134)

```sql
CREATE TABLE agent_health_beacons (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID NOT NULL,
    timestamp_ns BIGINT NOT NULL,      -- HealthBeacon.timestamp_ns
    agent_version TEXT NOT NULL,       -- HealthBeacon.agent_version
    spool_bytes BIGINT NOT NULL,       -- HealthBeacon.spool_bytes
    spool_dropped BIGINT NOT NULL,     -- HealthBeacon.spool_dropped
    enrich_dropped BIGINT NOT NULL,    -- HealthBeacon.enrich_dropped
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sensor_health (
    id BIGSERIAL PRIMARY KEY,
    beacon_id BIGINT NOT NULL REFERENCES agent_health_beacons(id),
    name TEXT NOT NULL,                -- SensorHealth.name
    pulse_count BIGINT NOT NULL,       -- SensorHealth.pulse_count
    silent BOOLEAN NOT NULL            -- SensorHealth.silent
);
```

### Acceptance Criteria

- [ ] Dashboard shows lab fleet health incl. per-host loss counters
- [ ] Killing a sensor on one VM is visible (capability degraded) within a heartbeat
- [ ] Ring status reflects a content rollout with halt state

### Next Steps

1. **PRIORITÉ 1:** Merge PR #157 (Agent health telemetry)
2. **PRIORITÉ 2:** Démarrer Issue #28 (Server scaffold)
3. Une fois #28 + #134 complétés → implémenter #83

---

## Documentation Détaillée

### Dependencies

#### Issue #28: Scaffold server (Next.js + PostgreSQL)
**Status:** OPEN

**What #83 needs from #28:**
- `/api/ingest/health` endpoint to receive HealthBeacon from agents
- Database schema for storing agent health state (agent_health_beacons, sensor_health)
- Authentication/authorization (mTLS for agents, user session for dashboard)
- Base UI layout and routing structure (Next.js App Router)
- docker-compose dev environment

#### Issue #134: Agent Health Telemetry
**Status:** PR #157 open, mergeable

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

#### Related Issues

- **Issue #108:** EventSpool two-phase drain/ack (PR #156)
  - Provides spool stats (spool_bytes, spool_dropped) for telemetry accounting
  - Dashboard surfaces per-host and fleet-wide spool drop counts

- **Issue #24:** Transport mTLS (PR #158)
  - Health beacons flow through transport layer to server
  - Dashboard needs agent identity from mTLS enrollment

### Features

#### 1. Agent Health View

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

#### 2. Telemetry Accounting

**Observable-loss counters:**
- Per-agent:
  - `spool_dropped` (from HealthBeacon)
  - `enrich_dropped` (from HealthBeacon)
  - Scan-queue sheds (future: needs agent instrumentation)
  - Bounded-map evictions (future: needs agent instrumentation)

- Fleet-wide aggregations:
  - Total loss counters across fleet
  - Loss rate time-series
  - Per-host comparison (detect outliers)

**Anomaly detection:**
- Host that stops losing AND stops sending → tamper signal
- Sudden spike in loss counters → capacity issue
- Persistent high loss on single host → local resource issue

#### 3. Rollout Control

**Data sources:**
- Agent version from HealthBeacon
- Ring assignments (from enrollment/policy)
- Content version distribution status
- Model version distribution status

**UI Components:**
- Ring status table: ring name, version target vs actual spread, agent count
- Rollout halt/rollback controls
- Canary health monitoring (cross-ref with health metrics)

#### 4. Ingest Health

**Metrics:**
- Event ingest rate (events/sec by type)
- Ingest lag (event timestamp_ns vs ingestion timestamp)
- Per-tenant quotas and usage
- Queue depths (if applicable)

### Technical Design

#### API Routes

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

#### UI Pages

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

#### Critical Queries

**Fleet health overview:**
```sql
-- Latest beacons per agent
SELECT DISTINCT ON (agent_id)
    agent_id,
    timestamp_ns,
    agent_version,
    spool_dropped,
    enrich_dropped,
    received_at
FROM agent_health_beacons
ORDER BY agent_id, timestamp_ns DESC;

-- Count agents by status
WITH latest AS (...)
SELECT
    COUNT(*) FILTER (WHERE received_at > NOW() - INTERVAL '60 seconds') AS healthy,
    COUNT(*) FILTER (WHERE received_at BETWEEN NOW() - INTERVAL '5 minutes'
                                          AND NOW() - INTERVAL '60 seconds') AS degraded,
    COUNT(*) FILTER (WHERE received_at < NOW() - INTERVAL '5 minutes') AS silent
FROM latest;
```

**Sensor status per agent:**
```sql
SELECT
    sh.name,
    sh.pulse_count,
    sh.silent,
    b.timestamp_ns
FROM sensor_health sh
JOIN agent_health_beacons b ON sh.beacon_id = b.id
WHERE b.agent_id = $1
ORDER BY b.timestamp_ns DESC
LIMIT 10;
```

**Loss counter aggregation:**
```sql
-- Fleet-wide loss over last hour
SELECT
    SUM(spool_dropped) as total_spool_dropped,
    SUM(enrich_dropped) as total_enrich_dropped,
    COUNT(*) as beacon_count
FROM agent_health_beacons
WHERE received_at > NOW() - INTERVAL '1 hour';
```

### Implementation Plan

#### Phase 1: Foundation (depends on #28 landing)
1. Database migrations for agent_health_beacons, sensor_health, agents tables
2. `/api/ingest/health` endpoint to receive HealthBeacon
3. Background job to detect beacon silence (server-side)
4. Basic agent registry (enrollment creates agent record)

#### Phase 2: Fleet Health Dashboard
1. `/ops` page layout and navigation
2. `/ops/agents` list view with last-seen timestamps
3. `/ops/agents/[id]` detail view with sensor status table
4. Fleet health overview component (agent count by status)
5. Real-time updates (polling or websocket)

#### Phase 3: Telemetry Accounting
1. Loss counter aggregation queries
2. `/ops/loss` dashboard with time-series charts
3. Anomaly detection rules (configurable thresholds)
4. Alerting on loss spikes

#### Phase 4: Rollout Control
1. Ring assignment schema + API
2. `/ops/rollout` ring status table
3. Version spread calculation (actual vs target)
4. Halt/rollback controls

#### Phase 5: Ingest Health
1. Ingest metrics collection (event rate, lag)
2. `/ops/ingest` dashboard
3. Per-tenant quota tracking

### Testing Strategy

#### Integration Tests
- Agent sends HealthBeacon → stored in DB → appears in dashboard
- Sensor goes silent → dashboard shows red status within 1 heartbeat
- Agent stops beaconing → server detects silence → alert fires

#### E2E Tests (Playwright)
- Navigate to /ops → see fleet overview
- Click agent → see detail view with sensor table
- Kill sensor on test VM → verify degraded status appears
- Rollout to ring → verify version spread updates

#### Load Tests
- 1000 agents sending beacons every 30s → DB write load
- Dashboard query performance with 1000+ agents

### Risks and Mitigations

**Risk 1: #28 not started yet**
- Impact: Blocks all #83 implementation
- Mitigation: Prioritize #28, deliver incrementally (ingest endpoint first)

**Risk 2: Performance with 1000+ agents × 2 beacons/min**
- Impact: 120k inserts/hour
- Mitigation: Batch inserts, table partitioning, auto-purge (30 days), optimized indexes

**Risk 3: #134 not wired in agent yet**
- Impact: No data to test dashboard
- Mitigation: Create mock data generator, test with synthetic beacons

**Risk 4: Dashboard query latency**
- Impact: Degraded UX
- Mitigation: Materialized views, caching (Redis), incremental updates

### Success Metrics

**Performance Targets:**
- Beacon ingestion latency: < 100ms p99
- Dashboard page load: < 2s
- Fleet overview update: < 500ms
- Support: 1000 agents @ 2 beacons/min

**Observability:**
- Ingest endpoint error rate < 0.1%
- Silence detection lag < 60s
- Dashboard query time < 200ms p95

### Open Questions

1. **Beacon retention:** How long to keep raw beacons in DB?
   - Proposal: 30 days raw, then downsample to hourly aggregates for 1 year

2. **Real-time updates:** Polling vs WebSocket for dashboard?
   - Proposal: Start with polling (every 5s), upgrade to WebSocket if needed

3. **Alerting integration:** In-app alerts vs external (PagerDuty, email)?
   - Proposal: In-app first, then integrate with server/integrations (#88)

4. **Multi-tenancy:** Ops dashboard per tenant or global (for MSP)?
   - Proposal: Per-tenant by default (filter by tenant_id), global view for admin

### Related Code Locations

- Agent health beacon: `agent/src/health.rs` (from #134)
- Schema types: `crates/schema/src/lib.rs` (HealthBeacon, SensorHealth)
- Tamper detection: `crates/tamper/src/heartbeat.rs` (SilenceMonitor)
- Spool stats: `crates/store/src/spool.rs` (from #108)
- Server README: `server/README.md`
- ADR-0001: `docs/adr/0001-server-stack-nextjs-postgres.md`
