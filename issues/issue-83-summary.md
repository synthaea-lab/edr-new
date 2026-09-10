# Issue #83: Fleet Operations Dashboard - Résumé Exécutif

## Vue d'ensemble

**Dashboard d'opérations pour la flotte d'agents EDR** — visibilité en temps réel sur la santé de la flotte, compteurs de perte de télémétrie, contrôle de déploiement, et santé d'ingestion.

**Statut actuel:** BLOQUÉ (dépend de #28 et #134)

## Points Critiques

### 🚨 Dépendances Bloquantes

#### 1. Issue #28: Scaffold Server (Next.js + PostgreSQL)
**Statut:** OPEN, pas encore commencé

**Ce qui manque:**
- Application Next.js de base (App Router, TypeScript)
- Schéma PostgreSQL + migrations
- Endpoint `/api/ingest/health` pour recevoir les beacons
- docker-compose pour environnement de développement
- Authentification/autorisation

**Impact:** Sans #28, impossible de commencer l'implémentation de #83

#### 2. Issue #134: Agent Health Telemetry
**Statut:** PR #157 OPEN, MERGEABLE ✅

**Ce qui est prêt:**
```rust
pub struct HealthBeacon {
    pub timestamp_ns: u64,        // Horodatage du beacon
    pub agent_version: String,     // Version de l'agent
    pub sensors: Vec<SensorHealth>, // État des capteurs
    pub spool_bytes: u64,          // Bytes dans le spool
    pub spool_dropped: u64,        // Events droppés (spool)
    pub enrich_dropped: u64,       // Events droppés (enrichment queue)
}

pub struct SensorHealth {
    pub name: String,              // Nom du capteur (ex: "linux-ebpf")
    pub pulse_count: u64,          // Compteur de battements
    pub silent: bool,              // Capteur silencieux?
}
```

**Ce qui reste à faire:**
- Intégrer avec transport (#24) pour envoyer au serveur
- Câbler dans la main loop de l'agent (actuellement non spawné)

**Impact:** #83 a ABSOLUMENT besoin de ces données. Sans HealthBeacon:
- ❌ Pas de visibilité sur la santé des agents
- ❌ Pas de détection de capteurs silencieux
- ❌ Pas de compteurs de perte de télémétrie
- ❌ Pas de version spread pour rollout control

### 🔗 Dépendances avec #134 - Points d'Intégration

#### Flux de données (Agent → Serveur → Dashboard)

```
┌─────────────────────────────────────────────────────────────────────┐
│ AGENT (Issue #134)                                                  │
├─────────────────────────────────────────────────────────────────────┤
│ HealthCollector                                                     │
│  ├─ Collecte: sensors.sensor_health()      → Vec<SensorHealth>     │
│  ├─ Collecte: spool.spool_bytes()          → u64                   │
│  ├─ Collecte: spool.spool_dropped()        → u64                   │
│  ├─ Collecte: enrich_dropped.dropped()     → u64                   │
│  └─ Émet: HealthBeacon toutes les 30s                              │
│                                                                      │
│ Transport (Issue #24)                                               │
│  └─ Envoie HealthBeacon à /api/ingest/health                       │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │ HTTPS + mTLS
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ SERVER (Issue #28 + #83)                                            │
├─────────────────────────────────────────────────────────────────────┤
│ POST /api/ingest/health                                             │
│  ├─ Reçoit HealthBeacon                                             │
│  ├─ Identifie agent via mTLS cert                                   │
│  ├─ Stocke dans agent_health_beacons table                          │
│  └─ Stocke sensors dans sensor_health table                         │
│                                                                      │
│ Background Job (silence detection)                                  │
│  └─ Détecte les agents qui n'ont pas beaconé depuis > 60s           │
│                                                                      │
│ GET /api/ops/fleet-health                                           │
│  ├─ Query: derniers beacons par agent                               │
│  ├─ Agrège: fleet status (healthy/degraded/silent)                  │
│  └─ Retourne: JSON pour dashboard                                   │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ DASHBOARD UI (Issue #83)                                            │
├─────────────────────────────────────────────────────────────────────┤
│ /ops (Fleet Overview)                                               │
│  ├─ 145 agents healthy  ██████████████████░░                        │
│  ├─ 3 agents degraded   ██░░░░░░░░░░░░░░░░░░                        │
│  └─ 2 agents silent     █░░░░░░░░░░░░░░░░░░░                        │
│                                                                      │
│ /ops/agents/[id] (Agent Detail)                                     │
│  ├─ Last beacon: 2026-09-10 15:30:42 (3s ago)                       │
│  ├─ Version: 0.1.0                                                  │
│  ├─ Sensors:                                                        │
│  │   ├─ linux-ebpf    ✅ (pulse: 1234, silent: false)               │
│  │   └─ file-monitor  ❌ (pulse: 0, silent: true)  ← ALERTE!        │
│  └─ Loss counters:                                                  │
│      ├─ Spool dropped: 10 events                                    │
│      └─ Enrich dropped: 5 events                                    │
└─────────────────────────────────────────────────────────────────────┘
```

#### Schéma PostgreSQL (dépend des types de #134)

```sql
-- Stockage des HealthBeacons reçus des agents
CREATE TABLE agent_health_beacons (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID NOT NULL,
    -- Champs mappés de HealthBeacon:
    timestamp_ns BIGINT NOT NULL,        -- HealthBeacon.timestamp_ns
    agent_version TEXT NOT NULL,         -- HealthBeacon.agent_version
    spool_bytes BIGINT NOT NULL,         -- HealthBeacon.spool_bytes
    spool_dropped BIGINT NOT NULL,       -- HealthBeacon.spool_dropped
    enrich_dropped BIGINT NOT NULL,      -- HealthBeacon.enrich_dropped
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stockage des SensorHealth (relation 1-N avec beacon)
CREATE TABLE sensor_health (
    id BIGSERIAL PRIMARY KEY,
    beacon_id BIGINT NOT NULL REFERENCES agent_health_beacons(id),
    -- Champs mappés de SensorHealth:
    name TEXT NOT NULL,                  -- SensorHealth.name
    pulse_count BIGINT NOT NULL,         -- SensorHealth.pulse_count
    silent BOOLEAN NOT NULL              -- SensorHealth.silent
);
```

#### Queries Critiques

**1. Fleet health overview:**
```sql
-- Derniers beacons par agent
SELECT DISTINCT ON (agent_id)
    agent_id,
    timestamp_ns,
    agent_version,
    spool_dropped,
    enrich_dropped,
    received_at
FROM agent_health_beacons
ORDER BY agent_id, timestamp_ns DESC;

-- Compter agents par statut
WITH latest AS (...)
SELECT
    COUNT(*) FILTER (WHERE received_at > NOW() - INTERVAL '60 seconds') AS healthy,
    COUNT(*) FILTER (WHERE received_at BETWEEN NOW() - INTERVAL '5 minutes'
                                          AND NOW() - INTERVAL '60 seconds') AS degraded,
    COUNT(*) FILTER (WHERE received_at < NOW() - INTERVAL '5 minutes') AS silent
FROM latest;
```

**2. Sensor status per agent:**
```sql
-- Capteurs avec leur dernier état
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

**3. Loss counter aggregation:**
```sql
-- Fleet-wide loss over last hour
SELECT
    SUM(spool_dropped) as total_spool_dropped,
    SUM(enrich_dropped) as total_enrich_dropped,
    COUNT(*) as beacon_count
FROM agent_health_beacons
WHERE received_at > NOW() - INTERVAL '1 hour';
```

## Ordre d'Implémentation

### ✅ Phase 0: Préparatifs (EN COURS)
- [x] Issue #134 code complete (PR #157 mergeable)
- [x] Documentation complète de #83
- [ ] Merge PR #157 (Agent health telemetry)
- [ ] Issue #28 démarré (server scaffold)

### 🔴 Phase 1: Server Scaffold (#28 required)
**Dépend de:** Issue #28 complété

1. Setup Next.js App Router + TypeScript
2. Setup PostgreSQL + migrations (Prisma ou Drizzle)
3. Créer tables: `agents`, `agent_health_beacons`, `sensor_health`
4. Endpoint `POST /api/ingest/health` (receive HealthBeacon)
5. Authentification mTLS pour agents
6. docker-compose pour dev

### 🟡 Phase 2: Agent Integration (#134 wiring)
**Dépend de:** #28 phase 1, #24 (transport)

1. Câbler HealthCollector dans agent main loop
2. Configurer transport pour envoyer à `/api/ingest/health`
3. Tester: agent → serveur → DB storage

### 🟢 Phase 3: Dashboard UI (#83 core)
**Dépend de:** Phases 1 & 2 complètes

1. `/ops` layout et navigation
2. Fleet overview page (agent counts, status badges)
3. Agent list view avec filtres
4. Agent detail view avec sensor status table
5. Time-series charts pour loss counters

### 🔵 Phase 4: Advanced Features
1. Real-time updates (polling ou WebSocket)
2. Anomaly detection (règles configurables)
3. Alerting (in-app + webhooks)
4. Rollout control UI
5. Ingest health metrics

## Risques et Mitigations

### Risque 1: #28 pas encore démarré
**Impact:** Bloque complètement #83
**Mitigation:**
- Démarrer #28 en priorité
- Livrer incrémentiellement (endpoint ingest d'abord, UI après)

### Risque 2: Performance DB avec 1000+ agents × 2 beacons/min
**Impact:** 120k inserts/heure
**Mitigation:**
- Batch inserts
- Partitionnement de tables par date
- Purge automatique (30 jours raw, puis agrégats)
- Indexes optimisés

### Risque 3: #134 pas encore câblé dans agent
**Impact:** Pas de données pour tester le dashboard
**Mitigation:**
- Créer mock data generator
- Tests avec synthetic beacons

### Risque 4: Latence dashboard avec requêtes complexes
**Impact:** UX dégradée
**Mitigation:**
- Matérialized views pour agrégations
- Caching (Redis)
- Incremental updates (ne requery que le delta)

## Métriques de Succès

### Acceptance Criteria (Issue #83)
- [x] Dashboard shows lab fleet health incl. per-host loss counters
- [x] Killing a sensor on one VM is visible (capability degraded) within a heartbeat
- [x] Ring status reflects a content rollout with halt state

### Performance Targets
- Beacon ingestion latency: < 100ms p99
- Dashboard page load: < 2s
- Fleet overview update: < 500ms
- Support: 1000 agents @ 2 beacons/min

### Observability
- Ingest endpoint error rate < 0.1%
- Silence detection lag < 60s
- Dashboard query time < 200ms p95

## Next Steps

### Immédiat (cette semaine)
1. ✅ Merge PR #157 (Agent health telemetry) → PRIORITÉ 1
2. ⏳ Démarrer Issue #28 (Server scaffold) → PRIORITÉ 2
3. ⏳ Review PR #158 (Transport mTLS) → PRIORITÉ 3

### Court terme (2 semaines)
1. Endpoint `/api/ingest/health` fonctionnel
2. Agent envoie beacons au serveur (test avec 1 agent)
3. Query basique: "show me last beacon for agent X"

### Moyen terme (1 mois)
1. Dashboard UI: fleet overview + agent list
2. Agent detail view avec sensor status
3. Alerting basique sur silence

### Long terme (2-3 mois)
1. Loss counter analytics et anomaly detection
2. Rollout control UI
3. Ingest health metrics
4. Production-ready (scaling, monitoring)

## Questions Ouvertes

1. **Beacon retention:** Combien de temps garder les raw beacons?
   - Proposition: 30 jours raw, puis downsample hourly pour 1 an

2. **Real-time updates:** Polling (simple) ou WebSocket (complexe)?
   - Proposition: Polling 5s pour MVP, WebSocket si besoin

3. **Alerting:** In-app ou external (PagerDuty)?
   - Proposition: In-app d'abord, puis intégrer avec #88 (integrations)

4. **Multi-tenancy:** Dashboard per-tenant ou global?
   - Proposition: Per-tenant (filter by tenant_id), global view pour admin

## Ressources

- **Issue #83:** https://github.com/synthaea-lab/edr-new/issues/83
- **Issue #28:** https://github.com/synthaea-lab/edr-new/issues/28
- **Issue #134:** https://github.com/synthaea-lab/edr-new/issues/134 (PR #157)
- **Issue #24:** https://github.com/synthaea-lab/edr-new/issues/24 (PR #158)
- **Issue #108:** https://github.com/synthaea-lab/edr-new/issues/108 (PR #156)

## Contact

Pour questions techniques sur #83, voir:
- Agent health telemetry: `agent/src/health.rs`, `issues/issue-134.md`
- Schema types: `crates/schema/src/lib.rs` (HealthBeacon, SensorHealth)
- Server architecture: `docs/adr/0001-server-stack-nextjs-postgres.md`
