# Issue #62: Fleet Correlation & Adaptive Posture (server/fleet)

**Component:** `server/fleet`
**Branch:** À créer — `feat/62-fleet-correlation-posture`
**Status:** BLOCKED — depends on #28, #72, #76, #78 (M8/M9 prerequisites)
**Milestone:** M9 — Fleet Intelligence
**Layer:** Layer 7 (Cross-endpoint correlation) in the 10-layer detection stack

---

## Résumé Exécutif

Layer 7 du stack de détection: corrélation d'incidents à l'échelle de la flotte et posture adaptative. Quand un cas de sécurité émerge sur un hôte, le système identifie automatiquement le "blast radius" (hôtes liés par identité, réseau, ou inventaire logiciel) et élève leur niveau d'alerte.

**La thèse défensive:** Les signaux dérivés de la flotte (corrélation cross-endpoint + posture adaptative) sont précisément ceux qu'un attaquant ne peut pas reproduire en téléchargeant nos binaires et content offline.

### Deux Halves Complémentaires

#### 1. Fleet Correlation
Joindre les détections/cases de plusieurs hosts en un seul **fleet-level case** via entités partagées:
- Identités réseau (même utilisateur connecté)
- Paires source/destination (mouvement latéral)
- File hashes (`intel`/`enrich` — même malware sur N hosts)
- Software inventory matches (même package vulnérable)
- Network neighbors (peers avec communication récente)

Extension naturelle du modèle "cases, not alerts" à son scope logique: la flotte entière.

#### 2. Adaptive Posture
Quand un case dépasse un seuil de sévérité, émettre un **posture change** pour les agents dans le blast-radius calculé:
- **Canal de distribution:** Signed `policy` channel (authoritative) + peer gossip via `crates/mesh` (fast + resilient)
- **Contenu posture overlay:**
  - ML thresholds abaissés (détection plus rapide)
  - Télémétrie élargie (collection scope widened)
  - Heartbeat interval raccourci
  - Response gates optionnellement plus strictes
- **Expiration automatique:** Les états heightened décroissent au lieu de s'accumuler (server-enforced)

### Posture: Deux Canaux de Propagation

```
Detection on Host A (severity > threshold)
  │
  ▼
server/fleet (blast-radius computation via graph)
  │
  ├─► Server path (authoritative)
  │   └─► Signed policy channel → agents in blast-radius
  │         └─► Policy verified + applied
  │
  └─► Mesh path (fast + resilient)
      └─► crates/mesh P2P gossip → network neighbors
            └─► Posture hint (advisory until verified)
                  └─► Server corroboration → full posture
```

**Mesh advantage:** Un pool offline peut encore élever son alertness collective suite à une détection locale, sans dépendre du control plane.

### Guardrails de Sécurité (by design, not bolt-on)

1. **Heighten-only invariant:** Posture ne DÉSACTIVE jamais rien, seulement heighten
2. **Audited like response actions:** Changements de posture logged + traceable
3. **Signed communication:** Mesh hints carry originating signature (replays dropped)
4. **Server-enforced expiry:** Prevents accumulation, ensures decay
5. **Advisory mesh hints:** Ne s'appliquent qu'après corroboration serveur
6. **No command channel:** Mesh ne peut jamais faire exécuter quoi que ce soit

---

## Dépendances Critiques

### BLOQUANTS (M8 Foundation)

**Issue #28: Server Scaffold (Next.js + PostgreSQL)** — BLOQUANT ❌
- Status: OPEN, pas démarré
- Requis: Next.js setup, PostgreSQL, authentication (ADR-0003), API foundation
- Reason: Impossible d'implémenter server/fleet sans infrastructure serveur

**Issue #77: Datalake (Full-Fidelity Telemetry)** — BLOQUANT ❌
- Status: M8, pas démarré
- Requis: Event ingest, storage substrate, retention policies
- Reason: Graph rebuild + correlation queries requièrent raw telemetry access

### REQUIS (M9 Fleet Intelligence)

**Issue #72: Entity Graph** — REQUIS ❌
- Status: M9, pas démarré (drafted in `server/graph/README.md`)
- Fournit: Blast-radius computation (graph neighborhood traversal)
- Reason: Correlation et posture dépendent tous deux du graph

**Issue #76: Prevalence (First-Seen/Rarity)** — REQUIS ❌
- Status: M9, pas démarré (drafted in `server/prevalence/README.md`)
- Fournit: Per-tenant rarity signals pour contextualiser detections
- Reason: Fleet correlation utilise prevalence pour assess spreading

**Issue #78: Cloud Detection** — REQUIS ❌
- Status: M9, pas démarré (drafted in `server/cloud-detection/README.md`)
- Fournit: Streaming/scheduled/retrospective detection modes
- Reason: Cross-fleet detection feeds into fleet cases

### INTÉGRATIONS NÉCESSAIRES

**Issue #79: P2P Mesh** — PARTIELLEMENT LANDED ⚠️
- Status: `crates/mesh/src/lib.rs` a skeleton code (peer attestation + posture gossip)
- Requis: Compléter posture gossip component
- Reason: Mesh path for posture propagation (fast + offline-resilient)

**Issue #23: Shared Policy Model** — REQUIS ❌
- Status: M7, drafted in `crates/policy/src/lib.rs`
- Fournit: Signed, versioned policy types (posture est policy overlay)
- Reason: Posture shipped via policy channel requires policy infrastructure

**Issue #24: Transport (mTLS + Spooled)** — OPEN ⏳
- Status: PR #158 OPEN
- Fournit: Secure agent ↔ server communication
- Reason: Policy distribution channel

---

## Architecture: Flux de Données Complet

### Path 1: Fleet Correlation (Detection → Fleet Case)

```
Agent A (detection X)
  └─► Transport → server/datalake (ingest)
        │
        ├─► server/graph (graph update: entities + edges)
        │     │
        │     ├─► Node: Process (pid=1234, hash=abc123)
        │     ├─► Node: Identity (user=alice)
        │     ├─► Edge: logged-in (host_A → alice)
        │     └─► Edge: same-hash-as (hash_abc123)
        │
        └─► server/fleet (correlation logic)
              │
              ├─► Query graph: "Find hosts with:"
              │     ├─► Same logged-in user (alice)
              │     ├─► Same file hash (abc123)
              │     └─► Recent network communication
              │
              ├─► Join with detections from other hosts
              │     ├─► Agent B: detection Y (same hash)
              │     └─► Agent C: detection Z (same user)
              │
              └─► Emit: Fleet-level case
                    ├─► Case ID: FLEET-001
                    ├─► Entities: [host_A, host_B, host_C, alice, hash_abc123]
                    ├─► Evidence: [detection_X, detection_Y, detection_Z]
                    ├─► Severity: computed from aggregated evidence
                    └─► Blast-radius: {B, C, D, E} (graph neighborhood)
```

### Path 2: Adaptive Posture (Case → Posture Change)

```
Fleet Case (severity > threshold)
  │
  ▼
server/fleet (posture decision)
  │
  ├─► Compute blast-radius (graph traversal)
  │     ├─► Same subnet neighbors
  │     ├─► Same logged-in identities
  │     ├─► Same software inventory
  │     └─► Peers with recent lateral comm
  │
  ├─► Generate posture overlay
  │     {
  │       "case_id": "FLEET-001",
  │       "severity": "high",
  │       "expiry_ts": now + 4h,
  │       "ml_thresholds": {"cmdline": 0.7 → 0.5},
  │       "collection_scope": "widened",
  │       "heartbeat_interval": 60s → 30s,
  │       "response_gates": "stricter"
  │     }
  │
  ├─► Server path (authoritative)
  │   └─► Sign with policy key
  │         └─► POST /api/policy/posture → agents [B,C,D,E]
  │               └─► Agent verifies signature
  │                     └─► Apply posture overlay
  │
  └─► Mesh path (fast + resilient)
      └─► server/fleet → crates/mesh gossip seed
            └─► Mesh propagates to network neighbors
                  └─► Agents receive posture hint (advisory)
                        ├─► Verify signature (originating case)
                        ├─► Check against server (corroboration)
                        └─► Apply if verified

Automatic Expiry (server background job)
  ├─► Every 5 min: scan active posture states
  ├─► Expired? → emit posture reset
  └─► Agents revert to baseline thresholds
```

### Path 3: Mesh Offline Resilience

```
Agent A (offline pool, no server connectivity)
  └─► Local detection (high severity)
        └─► crates/mesh (peer gossip)
              ├─► Sign posture hint with enrollment key
              ├─► Broadcast to discovered peers [B,C,D]
              │     └─► Peers receive hint (advisory)
              │           ├─► Verify signature
              │           ├─► Apply heightened posture (local)
              │           └─► Re-gossip to their neighbors
              │
              └─► When connectivity restored:
                    └─► Server receives attestation reports
                          └─► Validates mesh-propagated posture
                                └─► Sends authoritative policy update
```

---

## Composants à Implémenter

### 1. `server/fleet/correlation.rs` — Fleet Correlation Logic

**Responsibilities:**
- Consommer detections de `server/datalake` (ingest stream)
- Query `server/graph` pour entités partagées
- Joindre detections cross-host en fleet cases
- Compute aggregated severity scores

**Key Functions:**

```rust
/// Correlate a new detection with existing fleet state
pub async fn correlate_detection(
    detection: Detection,
    graph: &EntityGraph,
    existing_cases: &CaseStore,
) -> Result<Option<FleetCase>> {
    // 1. Extract entities from detection
    let entities = extract_entities(&detection)?;

    // 2. Graph traversal: find related hosts
    let related_hosts = graph.traverse_neighbors(&entities, max_depth=2)?;

    // 3. Query existing detections on related hosts
    let related_detections = existing_cases
        .find_by_hosts(&related_hosts)
        .within_window(Duration::hours(24))?;

    // 4. Join criteria: shared entities
    let matches = related_detections
        .filter(|d| shares_entities(d, &entities))
        .collect();

    // 5. If matches found → fleet case (new or update existing)
    if !matches.is_empty() {
        let case = FleetCase::new()
            .with_detections(vec![detection].chain(matches))
            .with_severity(compute_severity(&matches))
            .build()?;

        Ok(Some(case))
    } else {
        Ok(None)
    }
}

/// Extract shared entities for correlation
fn extract_entities(detection: &Detection) -> Vec<Entity> {
    // Identity, file hash, network endpoints, software inventory
}

/// Check if two detections share correlation entities
fn shares_entities(d1: &Detection, entities: &[Entity]) -> bool {
    // Same user, hash, source/dest pair, inventory item
}

/// Compute aggregated severity from multiple detections
fn compute_severity(detections: &[Detection]) -> Severity {
    // Max severity + count factor + diversity bonus
}
```

**Storage Schema (PostgreSQL):**

```sql
-- Fleet-level cases
CREATE TABLE fleet_cases (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    severity VARCHAR(16) NOT NULL, -- low/medium/high/critical
    status VARCHAR(16) NOT NULL,   -- open/investigating/resolved
    title TEXT NOT NULL,
    description TEXT,

    -- Aggregated from constituent detections
    technique_ids TEXT[], -- MITRE ATT&CK
    entity_ids UUID[],    -- Hosts, identities, hashes involved

    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- Many-to-many: fleet case ↔ detections
CREATE TABLE fleet_case_detections (
    fleet_case_id UUID NOT NULL,
    detection_id UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (fleet_case_id, detection_id),
    FOREIGN KEY (fleet_case_id) REFERENCES fleet_cases(id),
    FOREIGN KEY (detection_id) REFERENCES detections(id)
);

-- Indexes for correlation queries
CREATE INDEX idx_fleet_cases_tenant_status
    ON fleet_cases(tenant_id, status) WHERE status != 'resolved';
CREATE INDEX idx_fleet_cases_severity
    ON fleet_cases(tenant_id, severity) WHERE severity IN ('high', 'critical');
CREATE INDEX idx_fleet_case_detections_detection
    ON fleet_case_detections(detection_id);
```

### 2. `server/fleet/posture.rs` — Adaptive Posture Logic

**Responsibilities:**
- Monitor fleet cases pour severity threshold triggers
- Compute blast-radius via graph traversal
- Generate signed posture overlays
- Emit via policy channel + mesh gossip seed
- Track active postures + enforce expiry

**Key Functions:**

```rust
/// Decide if a case triggers posture change
pub async fn evaluate_posture_trigger(
    case: &FleetCase,
    config: &PostureConfig,
) -> Option<PostureTrigger> {
    if case.severity >= config.threshold {
        Some(PostureTrigger {
            case_id: case.id,
            severity: case.severity,
            reason: format!("Fleet case {} severity {}", case.id, case.severity),
        })
    } else {
        None
    }
}

/// Compute blast-radius from case entities
pub async fn compute_blast_radius(
    case: &FleetCase,
    graph: &EntityGraph,
    config: &BlastRadiusConfig,
) -> Result<Vec<AgentId>> {
    let mut agents = HashSet::new();

    // 1. Direct hosts involved in case
    agents.extend(case.host_ids());

    // 2. Graph neighborhood traversal
    for entity in &case.entity_ids {
        // Same subnet
        if config.include_subnet {
            agents.extend(graph.same_subnet(entity)?);
        }

        // Same logged-in identities
        if config.include_identities {
            agents.extend(graph.same_identity(entity)?);
        }

        // Same software inventory (vulnerable package)
        if config.include_inventory {
            agents.extend(graph.same_software(entity)?);
        }

        // Network neighbors (recent lateral comm)
        if config.include_network_neighbors {
            agents.extend(
                graph.network_neighbors(entity, window=Duration::hours(24))?
            );
        }
    }

    Ok(agents.into_iter().collect())
}

/// Generate posture overlay from trigger
pub fn generate_posture_overlay(
    trigger: &PostureTrigger,
    config: &PostureConfig,
) -> PostureOverlay {
    PostureOverlay {
        case_id: trigger.case_id,
        severity: trigger.severity,
        issued_at: Utc::now(),
        expires_at: Utc::now() + config.duration,

        ml_thresholds: config.ml_thresholds.clone(), // e.g., cmdline: 0.7 → 0.5
        collection_scope: config.collection_scope, // widened
        heartbeat_interval: config.heartbeat_interval, // 60s → 30s
        response_gates: config.response_gates, // stricter
    }
}

/// Emit posture via server path (signed policy)
pub async fn emit_posture_server(
    overlay: &PostureOverlay,
    agents: &[AgentId],
    policy_signer: &PolicySigner,
    api_client: &ApiClient,
) -> Result<()> {
    // 1. Sign overlay with policy key
    let signed = policy_signer.sign(overlay)?;

    // 2. Distribute via policy channel
    for agent_id in agents {
        api_client
            .post_policy_update(agent_id, &signed)
            .await?;
    }

    // 3. Audit log
    audit_log::posture_emitted(overlay, agents)?;

    Ok(())
}

/// Emit posture via mesh path (gossip seed)
pub async fn emit_posture_mesh(
    overlay: &PostureOverlay,
    agents: &[AgentId],
    mesh_client: &MeshClient,
) -> Result<()> {
    // Seed gossip to initial agents, mesh propagates
    mesh_client.seed_posture_hint(overlay, agents).await?;
    Ok(())
}

/// Background job: enforce expiry
pub async fn expire_postures(
    posture_store: &PostureStore,
    api_client: &ApiClient,
) -> Result<()> {
    let now = Utc::now();
    let expired = posture_store.find_expired(now)?;

    for posture in expired {
        // Emit reset to agents
        let reset = PostureReset {
            case_id: posture.case_id,
            expired_at: now,
        };

        api_client.post_posture_reset(&posture.agent_ids, &reset).await?;

        // Mark as expired in DB
        posture_store.mark_expired(posture.id)?;
    }

    Ok(())
}
```

**Storage Schema (PostgreSQL):**

```sql
-- Active posture states
CREATE TABLE posture_states (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    expired BOOLEAN DEFAULT FALSE,

    -- Overlay content
    severity VARCHAR(16) NOT NULL,
    ml_thresholds JSONB NOT NULL,
    collection_scope VARCHAR(32) NOT NULL,
    heartbeat_interval_secs INTEGER NOT NULL,
    response_gates VARCHAR(32),

    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (case_id) REFERENCES fleet_cases(id)
);

-- Many-to-many: posture ↔ agents
CREATE TABLE posture_agents (
    posture_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    applied_at TIMESTAMPTZ,

    PRIMARY KEY (posture_id, agent_id),
    FOREIGN KEY (posture_id) REFERENCES posture_states(id),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

-- Audit trail
CREATE TABLE posture_audit (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    posture_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    action VARCHAR(32) NOT NULL, -- emitted/applied/expired/reset
    agent_id UUID,
    channel VARCHAR(16) NOT NULL, -- server/mesh

    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (posture_id) REFERENCES posture_states(id)
);

-- Indexes
CREATE INDEX idx_posture_states_active
    ON posture_states(tenant_id, expires_at) WHERE NOT expired;
CREATE INDEX idx_posture_agents_agent
    ON posture_agents(agent_id);
CREATE INDEX idx_posture_audit_tenant_time
    ON posture_audit(tenant_id, timestamp DESC);
```

### 3. `crates/mesh/posture_gossip.rs` — P2P Posture Propagation

**Responsibilities:**
- Receive posture hints from peers
- Verify signatures (originating case + enrollment key)
- Propagate to discovered neighbors (bounded fan-out)
- Report to server for corroboration
- Apply only after server validation

**Key Functions:**

```rust
/// Receive posture hint from peer
pub fn handle_posture_hint(
    &mut self,
    hint: PostureHint,
    peer_id: &PeerId,
) -> Result<()> {
    // 1. Verify signature (enrollment PKI)
    if !self.verify_signature(&hint, peer_id)? {
        warn!("Dropped unsigned posture hint from {}", peer_id);
        self.report_invalid_hint(peer_id, &hint)?;
        return Ok(());
    }

    // 2. Check for replay (seen before?)
    if self.hint_cache.contains(&hint.id) {
        return Ok(()); // Already processed
    }

    // 3. Advisory application (local heighten)
    self.apply_advisory_posture(&hint)?;

    // 4. Server corroboration (async)
    self.request_server_validation(&hint)?;

    // 5. Re-gossip to neighbors (bounded fan-out)
    self.propagate_hint(&hint)?;

    // 6. Cache to prevent loops
    self.hint_cache.insert(hint.id);

    Ok(())
}

/// Apply posture hint locally (advisory, until server confirms)
fn apply_advisory_posture(&mut self, hint: &PostureHint) -> Result<()> {
    // Heighten-only check
    if !hint.is_heighten_only() {
        warn!("Rejected posture hint attempting to lower guards");
        return Ok(());
    }

    // Apply with "advisory" flag (full application awaits server)
    self.local_posture.apply_advisory(hint)?;

    info!("Applied advisory posture from case {}", hint.case_id);
    Ok(())
}

/// Request server validation of hint
fn request_server_validation(&self, hint: &PostureHint) -> Result<()> {
    // Queued async request to server
    self.validation_queue.push(ValidationRequest {
        hint_id: hint.id,
        case_id: hint.case_id,
        received_from: hint.peer_id,
        received_at: Utc::now(),
    })?;

    Ok(())
}

/// Propagate hint to neighbors (bounded)
fn propagate_hint(&self, hint: &PostureHint) -> Result<()> {
    // Fixed fan-out (e.g., 3 neighbors)
    let neighbors = self.peer_discovery.sample_neighbors(3);

    for neighbor in neighbors {
        // Rate limit check
        if self.rate_limiter.allow(&neighbor) {
            self.send_hint(&neighbor, hint)?;
        }
    }

    Ok(())
}

/// Server confirms hint → full posture application
pub fn handle_server_validation(
    &mut self,
    validation: PostureValidation,
) -> Result<()> {
    if validation.valid {
        // Upgrade advisory → full posture
        self.local_posture.confirm_advisory(validation.hint_id)?;
        info!("Server validated posture {}", validation.hint_id);
    } else {
        // Rollback advisory
        self.local_posture.rollback_advisory(validation.hint_id)?;
        warn!("Server rejected posture {}", validation.hint_id);
    }

    Ok(())
}
```

**Wire Protocol (additions to `crates/mesh`):**

```rust
/// Mesh message types
pub enum MeshMessage {
    PeerAttestation(Attestation),    // Existing
    PostureHint(PostureHint),        // NEW for #62
}

/// Posture hint propagated P2P
#[derive(Serialize, Deserialize)]
pub struct PostureHint {
    pub id: Uuid,
    pub case_id: Uuid,
    pub severity: Severity,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    // Overlay content (same as PostureOverlay)
    pub ml_thresholds: HashMap<String, f64>,
    pub collection_scope: CollectionScope,
    pub heartbeat_interval: Duration,

    // Signature from originating server
    pub signature: Vec<u8>,
    pub signer_pubkey: Vec<u8>,
}

impl PostureHint {
    /// Verify heighten-only invariant
    pub fn is_heighten_only(&self) -> bool {
        // Check that thresholds only go DOWN (more sensitive)
        // and collection only WIDENs (never narrows)
    }
}
```

### 4. API Endpoints (`server/api/fleet.ts`)

```typescript
// GET /api/fleet/cases
// List fleet-level cases
export async function GET(req: NextRequest) {
  const { tenantId } = await authenticate(req);
  const { severity, status, limit } = parseQuery(req);

  const cases = await db.fleetCase.findMany({
    where: {
      tenantId,
      ...(severity && { severity }),
      ...(status && { status }),
    },
    include: {
      detections: true,
      entities: true,
    },
    orderBy: { createdAt: 'desc' },
    take: limit || 50,
  });

  return Response.json({ cases });
}

// GET /api/fleet/cases/:id
// Get fleet case details with graph visualization
export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const { tenantId } = await authenticate(req);

  const case = await db.fleetCase.findUnique({
    where: { id: params.id, tenantId },
    include: {
      detections: { include: { agent: true } },
      entities: true,
    },
  });

  if (!case) return notFound();

  // Build subgraph for visualization
  const graph = await buildCaseSubgraph(case.id);

  return Response.json({ case, graph });
}

// GET /api/fleet/posture/active
// List active posture states
export async function GET(req: NextRequest) {
  const { tenantId } = await authenticate(req);

  const postures = await db.postureState.findMany({
    where: {
      tenantId,
      expired: false,
      expiresAt: { gt: new Date() },
    },
    include: {
      case: true,
      agents: { include: { agent: true } },
    },
  });

  return Response.json({ postures });
}

// POST /api/policy/posture (agent endpoint)
// Agents request posture validation
export async function POST(req: NextRequest) {
  const { agentId } = await authenticateAgent(req);
  const { hintId, caseId } = await req.json();

  // Validate hint against known posture states
  const posture = await db.postureState.findUnique({
    where: { caseId },
  });

  if (!posture || posture.expired) {
    return Response.json({ valid: false });
  }

  // Verify agent is in blast-radius
  const inBlastRadius = await db.postureAgent.findFirst({
    where: { postureId: posture.id, agentId },
  });

  return Response.json({
    valid: !!inBlastRadius,
    overlay: inBlastRadius ? posture : null,
  });
}
```

### 5. Console UI (`server/console/fleet/*`)

**Pages à créer:**

1. **`/fleet/cases`** — Fleet Cases Overview
   - Table: Case ID, severity, hosts involved, status, created
   - Filters: severity, status, time range
   - Click → case detail

2. **`/fleet/cases/[id]`** — Case Detail + Graph Visualization
   - Case metadata (severity, technique IDs, timeline)
   - Graph visualization (hosts, identities, hashes as nodes; edges as relations)
   - Constituent detections (expandable list)
   - Active posture state (if any)
   - Actions: escalate, resolve, create playbook

3. **`/fleet/posture`** — Active Postures Dashboard
   - Table: Case, severity, blast-radius size, issued, expires
   - Expiry countdown
   - Agent breakdown (applied/pending)
   - Manual override: extend, expire, reset

4. **`/ops/posture-audit`** — Posture Audit Trail
   - Timeline: all posture events (emitted/applied/expired)
   - Filters: case, agent, channel (server/mesh)
   - Mesh propagation tree visualization

---

## Configuration Types

### `PostureConfig` (server-side)

```rust
pub struct PostureConfig {
    /// Severity threshold for triggering posture
    pub threshold: Severity, // e.g., High

    /// Posture duration before auto-expiry
    pub duration: Duration, // e.g., 4 hours

    /// Blast-radius computation settings
    pub blast_radius: BlastRadiusConfig,

    /// Overlay content
    pub ml_thresholds: HashMap<String, f64>, // Model → threshold
    pub collection_scope: CollectionScope,
    pub heartbeat_interval: Duration,
    pub response_gates: ResponseGates,
}

pub struct BlastRadiusConfig {
    pub include_subnet: bool,
    pub include_identities: bool,
    pub include_inventory: bool,
    pub include_network_neighbors: bool,
    pub max_radius: usize, // Cap on blast-radius size
}
```

### `crates/policy` shared types

```rust
/// Posture overlay (sent to agents)
pub struct PostureOverlay {
    pub case_id: Uuid,
    pub severity: Severity,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    pub ml_thresholds: HashMap<String, f64>,
    pub collection_scope: CollectionScope,
    pub heartbeat_interval: Duration,
    pub response_gates: Option<ResponseGates>,
}

/// Collection scope
pub enum CollectionScope {
    Baseline,      // Normal
    Widened,       // More events collected
    Comprehensive, // Full collection
}

/// Response gates
pub enum ResponseGates {
    Normal,   // Standard approval flow
    Stricter, // Require additional approval
}
```

---

## Séquence d'Implémentation

### Phase 1: Foundations (depends on #28, #72, #77)

1. **Schema setup**
   - `fleet_cases`, `fleet_case_detections` tables
   - `posture_states`, `posture_agents`, `posture_audit` tables
   - Indexes

2. **Shared types** (depends on #23)
   - `crates/policy`: `PostureOverlay`, `CollectionScope`, `ResponseGates`
   - Serialization tests (JSON fixtures)

3. **API stubs**
   - `GET /api/fleet/cases`
   - `GET /api/fleet/cases/:id`
   - `GET /api/fleet/posture/active`
   - `POST /api/policy/posture`

### Phase 2: Fleet Correlation (depends on #72, #76, #78)

4. **`server/fleet/correlation.rs`**
   - `correlate_detection()` logic
   - Entity extraction
   - Graph traversal for shared entities
   - Case creation/update

5. **Background job: correlation processor**
   - Subscribe to detection ingest stream
   - Batch processing (every 30s)
   - Error handling + dead letter queue

6. **Tests: correlation scenarios**
   - Same user, different hosts
   - Same file hash across fleet
   - Lateral movement (network neighbors)
   - False positive: unrelated detections

### Phase 3: Adaptive Posture (server path)

7. **`server/fleet/posture.rs`**
   - `evaluate_posture_trigger()`
   - `compute_blast_radius()` via graph
   - `generate_posture_overlay()`
   - `emit_posture_server()` (signed policy)

8. **Policy signer integration** (depends on #23)
   - Sign posture with policy key
   - Verify on agent side

9. **Background job: expiry enforcer**
   - Scan every 5 min for expired postures
   - Emit reset to agents
   - Mark as expired in DB

10. **Tests: posture lifecycle**
    - Trigger → emit → apply → expire
    - Blast-radius computation
    - Signature verification

### Phase 4: Mesh Posture Gossip (depends on #79)

11. **`crates/mesh/posture_gossip.rs`**
    - `handle_posture_hint()`
    - Signature verification
    - Advisory application
    - Re-gossip with bounded fan-out

12. **Server validation endpoint**
    - Agents request corroboration
    - Validate hint against DB
    - Return signed confirmation

13. **Tests: mesh propagation**
    - Offline pool propagation
    - Replay attack detection
    - Heighten-only invariant enforcement
    - Server validation flow

### Phase 5: Console UI

14. **Fleet cases pages**
    - `/fleet/cases` (list + filters)
    - `/fleet/cases/[id]` (detail + graph viz)

15. **Posture dashboards**
    - `/fleet/posture` (active states)
    - `/ops/posture-audit` (audit trail)

16. **Graph visualization component**
    - D3.js or Cytoscape.js
    - Nodes: hosts, identities, hashes
    - Edges: spawned, logged-in, same-hash-as

### Phase 6: Integration & Tuning

17. **End-to-end testing**
    - Real detection → correlation → posture → mesh propagation
    - Multi-tenant isolation
    - Performance testing (large blast-radius)

18. **Observability**
    - Metrics: correlation rate, posture triggers, mesh propagation latency
    - Alerts: stuck cases, expiry failures, mesh loops

19. **Documentation**
    - API docs (OpenAPI)
    - Operator guide (posture tuning)
    - Incident playbook (manual posture reset)

---

## Tests: Scénarios Critiques

### Correlation Tests

```rust
#[tokio::test]
async fn test_correlate_same_user_different_hosts() {
    // Setup: 2 agents, same logged-in user "alice"
    let graph = mock_graph_with_identity("alice", vec!["host_a", "host_b"]);

    // Detection on host_a
    let det_a = Detection::new("host_a", "alice", TechniqueId::T1078);
    correlate_detection(det_a, &graph, &store).await.unwrap();

    // Detection on host_b (same user) → should join into fleet case
    let det_b = Detection::new("host_b", "alice", TechniqueId::T1021);
    let case = correlate_detection(det_b, &graph, &store).await.unwrap();

    assert!(case.is_some());
    let case = case.unwrap();
    assert_eq!(case.detections.len(), 2);
    assert!(case.entity_ids.contains(&Entity::Identity("alice")));
}

#[tokio::test]
async fn test_correlate_same_hash_across_fleet() {
    // Setup: 3 agents, same malware hash
    let hash = "abc123";
    let graph = mock_graph_with_hash(hash, vec!["host_a", "host_b", "host_c"]);

    // Detections on 3 hosts
    let det_a = Detection::new("host_a", hash);
    let det_b = Detection::new("host_b", hash);
    let det_c = Detection::new("host_c", hash);

    correlate_detection(det_a, &graph, &store).await.unwrap();
    correlate_detection(det_b, &graph, &store).await.unwrap();
    let case = correlate_detection(det_c, &graph, &store).await.unwrap();

    assert!(case.is_some());
    assert_eq!(case.unwrap().detections.len(), 3);
}
```

### Posture Tests

```rust
#[tokio::test]
async fn test_posture_trigger_and_blast_radius() {
    let config = PostureConfig::default_high_severity();

    // Fleet case with high severity
    let case = FleetCase::new()
        .severity(Severity::High)
        .entities(vec![Entity::Host("host_a"), Entity::Identity("alice")])
        .build();

    // Should trigger
    let trigger = evaluate_posture_trigger(&case, &config).await;
    assert!(trigger.is_some());

    // Compute blast-radius (same identity + subnet)
    let graph = mock_graph_with_subnet("10.0.1.0/24", vec!["host_a", "host_b", "host_c"]);
    let radius = compute_blast_radius(&case, &graph, &config.blast_radius).await.unwrap();

    assert!(radius.contains(&"host_b"));
    assert!(radius.contains(&"host_c"));
}

#[tokio::test]
async fn test_posture_expiry() {
    // Create posture with 1-hour expiry
    let posture = PostureState::new()
        .expires_at(Utc::now() + Duration::hours(1))
        .build();

    store.save(&posture).await.unwrap();

    // Fast-forward time
    tokio::time::sleep(Duration::hours(1) + Duration::minutes(1)).await;

    // Expiry job should clean it up
    expire_postures(&store, &api_client).await.unwrap();

    let expired = store.find_by_id(posture.id).await.unwrap();
    assert!(expired.expired);
}
```

### Mesh Tests

```rust
#[tokio::test]
async fn test_mesh_posture_gossip_propagation() {
    let mut mesh = MeshNode::new("agent_a");

    // Receive posture hint from peer
    let hint = PostureHint::new()
        .case_id(Uuid::new_v4())
        .severity(Severity::High)
        .sign_with(mock_enrollment_key());

    mesh.handle_posture_hint(hint.clone(), &"peer_b").unwrap();

    // Should apply advisory posture
    assert!(mesh.local_posture.is_heightened());

    // Should re-gossip to neighbors
    assert_eq!(mesh.outbound_hints.len(), 3); // Fan-out = 3
}

#[tokio::test]
async fn test_mesh_replay_rejection() {
    let mut mesh = MeshNode::new("agent_a");
    let hint = PostureHint::new().id(Uuid::new_v4()).sign_with(mock_key());

    // First time: accepted
    mesh.handle_posture_hint(hint.clone(), &"peer_b").unwrap();
    assert!(mesh.hint_cache.contains(&hint.id));

    // Second time: rejected (replay)
    mesh.handle_posture_hint(hint.clone(), &"peer_b").unwrap();
    assert_eq!(mesh.local_posture.apply_count, 1); // Not applied twice
}

#[tokio::test]
async fn test_heighten_only_invariant() {
    let mut mesh = MeshNode::new("agent_a");

    // Malicious hint attempting to LOWER threshold (disable detection)
    let bad_hint = PostureHint::new()
        .ml_thresholds(hashmap! { "cmdline" => 0.9 }) // Higher = less sensitive
        .sign_with(mock_key());

    mesh.handle_posture_hint(bad_hint, &"peer_b").unwrap();

    // Should reject
    assert!(!mesh.local_posture.is_heightened());
}
```

---

## Métriques & Observabilité

### Metrics to Emit

**Correlation:**
- `fleet.correlation.detections_processed` (counter)
- `fleet.correlation.cases_created` (counter)
- `fleet.correlation.cases_updated` (counter)
- `fleet.correlation.graph_query_duration_ms` (histogram)

**Posture:**
- `fleet.posture.triggers` (counter, by severity)
- `fleet.posture.blast_radius_size` (histogram)
- `fleet.posture.active_states` (gauge)
- `fleet.posture.expired` (counter)
- `fleet.posture.emit_duration_ms` (histogram, by channel: server/mesh)

**Mesh:**
- `mesh.posture.hints_received` (counter)
- `mesh.posture.hints_propagated` (counter)
- `mesh.posture.signature_failures` (counter)
- `mesh.posture.replay_rejections` (counter)
- `mesh.posture.server_validations` (counter, by result: valid/invalid)

### Alerts

- **Stuck cases:** Fleet case open > 7 days without update
- **Expiry failure:** Posture state expired but not cleaned up (background job failure)
- **Mesh loop:** Hint ID seen > 10 times (gossip loop detection)
- **Blast-radius too large:** > 1000 agents (potential config error or widespread attack)

---

## Sécurité: Threat Model

### Attack Scenarios & Mitigations

**1. Attacker weaponizes posture to DoS fleet**
- **Attack:** Trigger many high-severity cases → spam posture changes → exhaust agent resources
- **Mitigation:**
  - Rate limit posture emissions (max N per hour per tenant)
  - Blast-radius cap (max 1000 agents)
  - Expiry enforcement (auto-decay)
  - Audit trail (detect abuse patterns)

**2. Mesh gossip amplification attack**
- **Attack:** Replay old posture hints in loop → flood network
- **Mitigation:**
  - Hint cache (prevent replay)
  - Bounded fan-out (fixed 3 neighbors)
  - Rate limiting (max hints/sec per peer)
  - Signature verification (unauthenticated peers dropped)

**3. Forge posture to disable detection**
- **Attack:** Send malicious mesh hint lowering ML thresholds
- **Mitigation:**
  - **Heighten-only invariant** (enforced in code)
  - Signature verification (unsigned hints dropped)
  - Server validation (advisory until confirmed)
  - Audit trail (forged attempts logged)

**4. Lateral movement via mesh channel**
- **Attack:** Use mesh P2P as covert command channel
- **Mitigation:**
  - **No command execution** (mesh is read-only)
  - Typed messages only (attestation + posture)
  - Enrollment PKI (unenrolled peers ignored)
  - Server visibility (all mesh activity reported)

**5. Exfiltrate fleet topology via correlation**
- **Attack:** Infer network structure from case correlations
- **Mitigation:**
  - Multi-tenant isolation (cases never cross tenants)
  - RBAC on console (case visibility per role)
  - Audit trail (who accessed which cases)

---

## Documentation Requise

### For Operators

1. **Posture Tuning Guide**
   - When to adjust severity threshold
   - Blast-radius configuration best practices
   - Expiry duration recommendations

2. **Incident Playbooks**
   - Manual posture reset (if automation fails)
   - Force-expire stuck posture
   - Investigate mesh loop

3. **Troubleshooting**
   - Case not correlating (check graph data)
   - Posture not applying (check policy signature)
   - Mesh not propagating (check peer discovery)

### For Developers

1. **API Documentation (OpenAPI)**
   - All `/api/fleet/*` endpoints
   - Request/response schemas
   - Authentication requirements

2. **Architecture Diagrams**
   - Fleet correlation flow
   - Posture propagation (server + mesh)
   - Database schema (ERD)

3. **Integration Guide**
   - Consuming fleet cases in SOAR
   - Feeding external threat intel into correlation
   - Custom posture policies

---

## Dépendances de Code

### Crates Utilisés

```toml
# server/fleet/Cargo.toml
[dependencies]
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.8", features = ["postgres", "uuid", "chrono"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
anyhow = "1"

# Workspace crates
schema = { path = "../../crates/schema" }
policy = { path = "../../crates/policy" }

# server modules (once #28 lands)
server-graph = { path = "../graph" }
server-datalake = { path = "../datalake" }
server-prevalence = { path = "../prevalence" }
```

### Agent-Side (for mesh posture)

```toml
# crates/mesh/Cargo.toml
[dependencies]
# ... existing deps ...

# NEW for posture gossip
policy = { path = "../policy" } # Shared types
ed25519-dalek = "2" # Signature verification
```

---

## Critères d'Acceptation

### Must-Have (MVP)

- [ ] Fleet cases joignent detections by shared identity
- [ ] Fleet cases joignent detections by shared file hash
- [ ] Posture triggered when case severity ≥ High
- [ ] Blast-radius computed via graph (same subnet + identity)
- [ ] Posture emitted via signed policy channel
- [ ] Posture auto-expires after configured duration
- [ ] Console UI: list fleet cases, view case detail
- [ ] Console UI: view active postures
- [ ] Tests: correlation scenarios (identity, hash, network)
- [ ] Tests: posture lifecycle (trigger, emit, apply, expire)

### Nice-to-Have (Post-MVP)

- [ ] Mesh posture gossip (P2P propagation)
- [ ] Mesh offline resilience (pool without server connectivity)
- [ ] Correlation by network neighbors (lateral movement)
- [ ] Correlation by software inventory (vulnerable package spread)
- [ ] Graph visualization in console (D3.js case subgraph)
- [ ] Posture audit trail UI
- [ ] Manual posture override (extend, reset)
- [ ] Retrospective correlation (new detections join old cases)

---

## Risques & Mitigations

| Risque | Impact | Probabilité | Mitigation |
|--------|--------|-------------|------------|
| **Graph perf at scale** | Blast-radius queries timeout on large fleets | Medium | Indexed graph queries, caching, blast-radius cap |
| **Posture spam** | Too many triggers → agent resource exhaustion | Low | Rate limiting, severity threshold tuning |
| **Mesh loops** | Gossip amplification | Medium | Hint cache, bounded fan-out, replay detection |
| **False correlation** | Unrelated detections joined (false positive) | Medium | Conservative entity matching, time windows, operator review |
| **Dependency delays** | #28/#72/#76/#78 not ready | High | **BLOQUANT** — cannot start without M8/M9 foundation |

---

## Timeline Estimate

**Assumptions:**
- #28 (server scaffold) complete
- #72 (entity graph) complete
- #76 (prevalence) complete
- #77 (datalake) complete
- #78 (cloud-detection) complete

**Effort (sequential):**
- Phase 1 (Foundations): 1 week
- Phase 2 (Correlation): 2 weeks
- Phase 3 (Posture server): 2 weeks
- Phase 4 (Mesh gossip): 2 weeks
- Phase 5 (Console UI): 1 week
- Phase 6 (Integration): 1 week

**Total:** ~9 weeks (with all dependencies met)

**Critical path:** #28 → #72 → #62

---

## Références

### Design Docs

- `/home/emile/Documents/synthea/edr-repo/server/fleet/README.md` — Fleet correlation + posture spec
- `/home/emile/Documents/synthea/edr-repo/server/graph/README.md` — Entity graph (blast-radius substrate)
- `/home/emile/Documents/synthea/edr-repo/crates/mesh/src/lib.rs` — P2P mesh design (posture gossip)
- `/home/emile/Documents/synthea/edr-repo/docs/detection/layers.md` — Layer 7 context
- `/home/emile/Documents/synthea/edr-repo/docs/roadmap.md` — M9 milestone definition

### Related Issues

- **#28:** Server scaffold (Next.js + PostgreSQL) — BLOQUANT
- **#72:** Entity graph — REQUIS
- **#76:** Prevalence (first-seen/rarity) — REQUIS
- **#77:** Datalake (full-fidelity telemetry) — BLOQUANT
- **#78:** Cloud detection — REQUIS
- **#79:** P2P mesh — Posture gossip component
- **#23:** Shared policy model — Posture overlay types
- **#24:** Transport (mTLS) — Policy distribution channel
- **#83:** Fleet ops dashboard — Consumer of fleet health (related but independent)

---

## Changelog

| Date | Action | Author |
|------|--------|--------|
| 2026-09-11 | Initial documentation (issue drafted) | Claude |

---

**Status:** DRAFTED — Comprehensive spec complete, awaiting M8/M9 dependencies before implementation can begin.

**Next Action:** Monitor #28/#72/#76/#77/#78 progress; begin Phase 1 (foundations) once all blockers cleared.
