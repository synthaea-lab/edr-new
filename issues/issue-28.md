# Issue #28: Server Scaffold - Next.js + PostgreSQL (Control Plane Foundation)

**Component:** `server/` (all modules)
**Branch:** À créer — `feat/28-server-scaffold`
**Status:** OPEN — NOT STARTED
**Milestone:** M8 — Control-plane foundation
**Priority:** 🔴 CRITICAL PATH — Bloque #62, #72, #76, #77, #78, #83, #89

---

## Résumé Exécutif

Issue #28 est le **SINGLE POINT OF FAILURE** pour toute la stack M8/M9/M10. C'est le fondement du control plane qui permet à tous les composants serveur d'exister.

**Le problème:** Sans serveur, pas d'infrastructure pour:
- Recevoir les détections des agents (ingest)
- Stocker les données (PostgreSQL)
- Afficher les cases (console)
- Gérer les policies (API)
- Opérer la flotte (ops dashboard)

**La solution:** Scaffolder une application Next.js moderne avec PostgreSQL, prête à accueillir tous les modules M8/M9/M10.

### Acceptation Criteria (depuis GitHub)

- [ ] Agent enrolls, uploads detections; they appear in the console case list
- [ ] Heartbeat-silence detection server-side
- [ ] docker-compose up gives a working dev stack

---

## Architecture: Le Control Plane

### Stack Technique (ADR-0001)

**Décision architecturale:** Une application Next.js + PostgreSQL unique

**Justification:**
- Taille de flotte: milliers d'agents, pas millions (throughput modéré)
- Vélocité d'itération > performance brute (team familiarity)
- Self-hosting simple: un seul docker-compose
- Escape hatch: si ingest volume explose, split en service séparé (même DB)

**Stack:**
```
Next.js 14+ (App Router)
  ├─ TypeScript (strict mode)
  ├─ Server Actions / Route Handlers
  └─ React Server Components

PostgreSQL 15+
  ├─ Migrations (Prisma/Drizzle/pg-migrate)
  ├─ Row-Level Security (tenant isolation)
  └─ Partitioning (telemetry tables by date)

Authentication (ADR-0003)
  └─ better-auth
      ├─ Email/SSO (OIDC/SAML)
      ├─ Organization plugin (tenancy)
      └─ RBAC (analyst/responder/admin/read-only)

Deployment
  ├─ docker-compose (dev + self-hosting)
  ├─ mTLS terminating proxy (nginx/caddy)
  └─ Future: Kubernetes/cloud-native split
```

### Tenancy Architecture (ADR-0003)

**Principe:** Tenant ID first-class dès la première migration

```sql
-- Every table has tenant_id
CREATE TABLE detections (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    timestamp TIMESTAMPTZ NOT NULL,
    ...
    -- Row-Level Security enforces tenant isolation
);

-- Organization = Tenant
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
```

**Isolation:**
- Queries filtrées par tenant_id (RLS policy)
- Audit log par tenant
- Partitioning par tenant pour grandes tables
- MSSP-style: teams = sub-tenants (future)

### Modules du Control Plane

```
server/
├─ ingest/         → M8 - Endpoints agent (events, heartbeats)
├─ api/            → M8 - Management API (enrollment, policy, cases)
├─ console/        → M8 - Analyst UI (case triage)
├─ ops/            → M10 - Fleet ops dashboard (#83)
├─ datalake/       → M8 - Telemetry lake (#77)
├─ graph/          → M9 - Entity graph (#72)
├─ fleet/          → M9 - Fleet correlation + posture (#62)
├─ prevalence/     → M9 - First-seen/rarity (#76)
├─ cloud-detection/→ M9 - Streaming/scheduled/retrospective detection (#78)
├─ hunt/           → M10 - Threat hunting (#61)
├─ forensics/      → M10 - DFIR workbench (#70)
├─ assistant/      → M10 - AI assistant (#75)
├─ disruption/     → M10 - Playbooks (#64)
└─ integrations/   → M10 - SOAR/ticketing (#88)
```

**Ordre d'implémentation:**
1. **M8 (Foundation):** ingest, api, console basique, datalake
2. **M9 (Fleet Intelligence):** graph, fleet, prevalence, cloud-detection
3. **M10 (Analyst & Ops):** ops, hunt, forensics, assistant, disruption

---

## Composants à Implémenter

### 1. Project Setup & Infrastructure

#### 1.1 Next.js Application Scaffold

```bash
# Create Next.js app
npx create-next-app@latest server \
  --typescript \
  --tailwind \
  --app \
  --no-src-dir \
  --import-alias "@/*"

cd server
```

**Configuration (`next.config.js`):**
```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: true,
  },
  // mTLS proxy passes agent identity via header
  async headers() {
    return [
      {
        source: '/api/ingest/:path*',
        headers: [
          { key: 'X-Client-Cert-Verified', value: 'SUCCESS' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
```

#### 1.2 PostgreSQL Schema & Migrations

**ORM Choice:** Prisma (type-safe, migrations intégrées)

**Schema Foundation (`prisma/schema.prisma`):**
```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Tenancy foundation
model Tenant {
  id        String   @id @default(uuid())
  name      String
  createdAt DateTime @default(now()) @map("created_at")

  // Relations
  agents     Agent[]
  detections Detection[]
  cases      Case[]

  @@map("tenants")
}

// Agent enrollment
model Agent {
  id           String   @id @default(uuid())
  tenantId     String   @map("tenant_id")
  enrollmentId String   @unique @map("enrollment_id") // mTLS cert subject
  hostname     String?
  version      String?
  lastSeen     DateTime @map("last_seen")
  createdAt    DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@map("agents")
  @@index([tenantId, lastSeen])
}

// Detection storage
model Detection {
  id        String   @id @default(uuid())
  tenantId  String   @map("tenant_id")
  agentId   String   @map("agent_id")
  timestamp DateTime
  technique String   // MITRE ATT&CK technique
  severity  String   // low/medium/high/critical

  // Event data (JSON)
  event     Json
  meta      Json

  createdAt DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@map("detections")
  @@index([tenantId, timestamp])
  @@index([agentId, timestamp])
}

// Case management
model Case {
  id          String   @id @default(uuid())
  tenantId    String   @map("tenant_id")
  title       String
  description String?
  severity    String
  status      String   // open/investigating/resolved
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@map("cases")
  @@index([tenantId, status, createdAt])
}

// Audit log
model AuditLog {
  id        String   @id @default(uuid())
  tenantId  String   @map("tenant_id")
  userId    String   @map("user_id")
  action    String   // enrollment.create, case.update, policy.deploy, etc.
  resource  String   // cases/123, agents/456
  details   Json?
  timestamp DateTime @default(now())

  @@map("audit_logs")
  @@index([tenantId, timestamp])
  @@index([userId, timestamp])
}
```

**Migrations:**
```bash
npx prisma migrate dev --name init
npx prisma generate
```

#### 1.3 Authentication Setup (better-auth)

**Installation:**
```bash
npm install better-auth @better-auth/react
```

**Configuration (`lib/auth.ts`):**
```typescript
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";

export const auth = betterAuth({
  database: {
    provider: "postgresql",
    url: process.env.DATABASE_URL!,
  },
  emailAndPassword: {
    enabled: true,
  },
  plugins: [
    organization({
      // Organization = Tenant
      allowUserToCreateOrganization: false, // Admin-only
    }),
  ],
});

export type Session = typeof auth.$Infer.Session;
```

**Middleware (`middleware.ts`):**
```typescript
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

export async function middleware(req: NextRequest) {
  const session = await auth.api.getSession({
    headers: req.headers,
  });

  // Public routes
  if (req.nextUrl.pathname.startsWith("/api/ingest")) {
    // Agent endpoints (mTLS auth)
    return NextResponse.next();
  }

  // Protected routes
  if (!session) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  // Inject tenant context
  const headers = new Headers(req.headers);
  headers.set("x-tenant-id", session.user.organizationId);

  return NextResponse.next({
    request: { headers },
  });
}

export const config = {
  matcher: [
    "/console/:path*",
    "/api/((?!ingest|auth).*)",
  ],
};
```

#### 1.4 Docker Compose (Dev Stack)

**`docker-compose.yml`:**
```yaml
version: "3.8"

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: synthaea
      POSTGRES_USER: synthaea
      POSTGRES_PASSWORD: synthaea_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synthaea"]
      interval: 5s
      timeout: 5s
      retries: 5

  server:
    build:
      context: .
      dockerfile: Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://synthaea:synthaea_dev@postgres:5432/synthaea
      NEXTAUTH_URL: http://localhost:3000
      NEXTAUTH_SECRET: dev_secret_change_in_production
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run dev

  # mTLS terminating proxy (nginx)
  proxy:
    image: nginx:alpine
    depends_on:
      - server
    ports:
      - "8443:8443" # Agent ingest (mTLS)
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro

volumes:
  postgres_data:
```

**Nginx mTLS Config (`nginx.conf`):**
```nginx
events {
    worker_connections 1024;
}

http {
    upstream server {
        server server:3000;
    }

    server {
        listen 8443 ssl;

        # Server cert
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        # Client cert verification (mTLS)
        ssl_client_certificate /etc/nginx/certs/ca.crt;
        ssl_verify_client on;

        location /api/ingest/ {
            proxy_pass http://server;
            proxy_set_header X-Client-Cert-Verified $ssl_client_verify;
            proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;
        }
    }
}
```

---

### 2. Ingest Module (`server/ingest/`)

#### 2.1 Detection Upload Endpoint

**Route:** `app/api/ingest/detection/route.ts`

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

// Validation schema
const DetectionSchema = z.object({
  timestamp_ns: z.number(),
  technique: z.string(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  event: z.object({
    // Event fields from schema crate
  }),
  meta: z.object({
    // EventMeta fields
  }),
});

export async function POST(req: NextRequest) {
  // Verify mTLS auth
  const certVerified = req.headers.get("X-Client-Cert-Verified");
  const certSubject = req.headers.get("X-Client-Cert-Subject");

  if (certVerified !== "SUCCESS" || !certSubject) {
    return NextResponse.json(
      { error: "Unauthorized" },
      { status: 401 }
    );
  }

  // Extract agent enrollment ID
  const enrollmentId = extractEnrollmentId(certSubject);

  // Find agent (tenant context)
  const agent = await prisma.agent.findUnique({
    where: { enrollmentId },
    include: { tenant: true },
  });

  if (!agent) {
    return NextResponse.json(
      { error: "Agent not enrolled" },
      { status: 403 }
    );
  }

  // Parse body
  const body = await req.json();
  const detection = DetectionSchema.parse(body);

  // Store detection
  await prisma.detection.create({
    data: {
      tenantId: agent.tenantId,
      agentId: agent.id,
      timestamp: new Date(detection.timestamp_ns / 1_000_000),
      technique: detection.technique,
      severity: detection.severity,
      event: detection.event,
      meta: detection.meta,
    },
  });

  // Update agent last-seen
  await prisma.agent.update({
    where: { id: agent.id },
    data: { lastSeen: new Date() },
  });

  return NextResponse.json({ status: "accepted" });
}

function extractEnrollmentId(certSubject: string): string {
  // Parse X.509 subject DN
  // Example: CN=agent-abc123,O=synthaea
  const match = certSubject.match(/CN=([^,]+)/);
  return match ? match[1] : "";
}
```

#### 2.2 Heartbeat Endpoint

**Route:** `app/api/ingest/heartbeat/route.ts`

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(req: NextRequest) {
  const certSubject = req.headers.get("X-Client-Cert-Subject");
  if (!certSubject) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const enrollmentId = extractEnrollmentId(certSubject);

  // Update last-seen timestamp
  await prisma.agent.update({
    where: { enrollmentId },
    data: { lastSeen: new Date() },
  });

  return NextResponse.json({ status: "ok" });
}
```

#### 2.3 Heartbeat-Silence Detection (Background Job)

**Cron Job:** `app/api/cron/detect-silent-agents/route.ts`

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const SILENCE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

export async function GET(req: NextRequest) {
  // Verify cron auth token
  const authHeader = req.headers.get("Authorization");
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const threshold = new Date(Date.now() - SILENCE_THRESHOLD_MS);

  // Find silent agents
  const silentAgents = await prisma.agent.findMany({
    where: {
      lastSeen: { lt: threshold },
    },
    include: { tenant: true },
  });

  // Create cases for silent agents
  for (const agent of silentAgents) {
    await prisma.case.create({
      data: {
        tenantId: agent.tenantId,
        title: `Agent Silent: ${agent.hostname || agent.id}`,
        description: `Agent has not sent heartbeat for >5 minutes. Last seen: ${agent.lastSeen.toISOString()}`,
        severity: "high",
        status: "open",
      },
    });
  }

  return NextResponse.json({
    silentAgents: silentAgents.length,
  });
}
```

**Trigger:** Vercel Cron ou cron externe (curl)

---

### 3. API Module (`server/api/`)

#### 3.1 Enrollment API

**Route:** `app/api/enrollment/route.ts`

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

export async function POST(req: NextRequest) {
  const tenantId = await getTenantId(req);
  const body = await req.json();

  const { enrollmentId, hostname, version } = body;

  // Check if agent already enrolled
  const existing = await prisma.agent.findUnique({
    where: { enrollmentId },
  });

  if (existing) {
    return NextResponse.json({ status: "already_enrolled" });
  }

  // Enroll agent
  const agent = await prisma.agent.create({
    data: {
      tenantId,
      enrollmentId,
      hostname,
      version,
      lastSeen: new Date(),
    },
  });

  // Audit log
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: req.headers.get("x-user-id")!,
      action: "enrollment.create",
      resource: `agents/${agent.id}`,
      details: { enrollmentId, hostname },
    },
  });

  return NextResponse.json({ status: "enrolled", agentId: agent.id });
}
```

#### 3.2 Case Query API

**Route:** `app/api/cases/route.ts`

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

export async function GET(req: NextRequest) {
  const tenantId = await getTenantId(req);
  const { searchParams } = new URL(req.url);

  const status = searchParams.get("status");
  const severity = searchParams.get("severity");
  const limit = parseInt(searchParams.get("limit") || "50");

  const cases = await prisma.case.findMany({
    where: {
      tenantId,
      ...(status && { status }),
      ...(severity && { severity }),
    },
    orderBy: { createdAt: "desc" },
    take: limit,
  });

  return NextResponse.json({ cases });
}
```

---

### 4. Console Module (`server/console/`)

#### 4.1 Case List Page

**Page:** `app/console/cases/page.tsx`

```typescript
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { CaseList } from "@/components/CaseList";

export default async function CasesPage() {
  const session = await auth.api.getSession();
  if (!session) return null;

  const tenantId = session.user.organizationId;

  const cases = await prisma.case.findMany({
    where: { tenantId },
    orderBy: { createdAt: "desc" },
    take: 100,
  });

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Cases</h1>
      <CaseList cases={cases} />
    </div>
  );
}
```

**Component:** `components/CaseList.tsx`

```typescript
"use client";

import { Case } from "@prisma/client";

interface Props {
  cases: Case[];
}

export function CaseList({ cases }: Props) {
  return (
    <div className="space-y-4">
      {cases.map((case_) => (
        <div
          key={case_.id}
          className="border rounded-lg p-4 hover:bg-gray-50"
        >
          <div className="flex justify-between items-start">
            <div>
              <h3 className="font-semibold">{case_.title}</h3>
              <p className="text-sm text-gray-600">{case_.description}</p>
            </div>
            <div className="flex gap-2">
              <span
                className={`px-2 py-1 rounded text-xs ${
                  case_.severity === "critical"
                    ? "bg-red-100 text-red-800"
                    : case_.severity === "high"
                    ? "bg-orange-100 text-orange-800"
                    : "bg-yellow-100 text-yellow-800"
                }`}
              >
                {case_.severity}
              </span>
              <span className="px-2 py-1 rounded text-xs bg-blue-100 text-blue-800">
                {case_.status}
              </span>
            </div>
          </div>
          <div className="text-xs text-gray-500 mt-2">
            Created {new Date(case_.createdAt).toLocaleString()}
          </div>
        </div>
      ))}
    </div>
  );
}
```

---

## Séquence d'Implémentation

### Phase 1: Foundation (Semaine 1-2)

1. ✅ **Project setup**
   - Create Next.js app
   - Install dependencies (Prisma, better-auth, Tailwind)
   - Configure TypeScript

2. ✅ **PostgreSQL schema**
   - Define Prisma schema (tenants, agents, detections, cases, audit_logs)
   - Run initial migration
   - Test connection

3. ✅ **Authentication**
   - Setup better-auth
   - Create login page
   - Test session management

4. ✅ **Docker Compose**
   - Write docker-compose.yml
   - Test `docker-compose up`
   - Verify PostgreSQL connectivity

### Phase 2: Ingest (Semaine 2-3)

5. ✅ **Detection endpoint**
   - `/api/ingest/detection` route handler
   - mTLS auth verification
   - Detection storage
   - Agent last-seen update

6. ✅ **Heartbeat endpoint**
   - `/api/ingest/heartbeat` route handler
   - Timestamp update

7. ✅ **Silent agent detection**
   - Cron job `/api/cron/detect-silent-agents`
   - Case creation for silent agents

### Phase 3: Console (Semaine 3-4)

8. ✅ **Case list page**
   - `/console/cases` page
   - Fetch cases from DB
   - Display in table/cards

9. ✅ **Basic navigation**
   - Sidebar with links
   - Header with tenant/user info

### Phase 4: API Foundation (Semaine 4)

10. ✅ **Enrollment API**
    - `/api/enrollment` endpoint
    - Agent enrollment logic
    - Audit logging

11. ✅ **Case query API**
    - `/api/cases` endpoint
    - Filtering (status, severity)
    - Pagination

### Phase 5: Testing & Polish (Semaine 5)

12. ✅ **Integration tests**
    - Agent enrollment flow
    - Detection upload → case list
    - Silent agent detection

13. ✅ **Documentation**
    - README with setup instructions
    - API documentation
    - Environment variables guide

---

## Tests: Scénarios d'Acceptation

### Test 1: Agent Enrollment & Detection Upload

**Scenario:** Agent enrolls, uploads detections; they appear in the console case list

```bash
# 1. Start stack
docker-compose up -d

# 2. Create tenant + user (via console UI or seed script)
npm run seed

# 3. Enroll agent (simulate mTLS)
curl -X POST http://localhost:3000/api/enrollment \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-test-001" \
  -H "Content-Type: application/json" \
  -d '{
    "enrollmentId": "agent-test-001",
    "hostname": "test-vm-01",
    "version": "0.1.0"
  }'

# 4. Upload detection
curl -X POST http://localhost:3000/api/ingest/detection \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-test-001" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp_ns": 1726048800000000000,
    "technique": "T1059.001",
    "severity": "high",
    "event": {},
    "meta": {}
  }'

# 5. Verify in console
# Open http://localhost:3000/console/cases
# Should see detection in case list

# ✅ PASS if detection appears in console
```

### Test 2: Heartbeat-Silence Detection

**Scenario:** Heartbeat-silence detection server-side

```bash
# 1. Enroll agent
curl -X POST http://localhost:3000/api/enrollment \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-silent-test" \
  -d '{"enrollmentId": "agent-silent-test", "hostname": "silent-vm"}'

# 2. Send heartbeat
curl -X POST http://localhost:3000/api/ingest/heartbeat \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-silent-test"

# 3. Wait 6 minutes (> silence threshold)
sleep 360

# 4. Trigger cron job
curl http://localhost:3000/api/cron/detect-silent-agents \
  -H "Authorization: Bearer $CRON_SECRET"

# 5. Check console for "Agent Silent" case
# Open http://localhost:3000/console/cases
# Should see case: "Agent Silent: silent-vm"

# ✅ PASS if silent agent case created
```

### Test 3: Docker Compose Dev Stack

**Scenario:** docker-compose up gives a working dev stack

```bash
# 1. Clean start
docker-compose down -v
docker-compose up -d

# 2. Wait for services to be healthy
sleep 10

# 3. Check PostgreSQL
docker-compose exec postgres pg_isready -U synthaea
# Expected: postgres:5432 - accepting connections

# 4. Check server
curl http://localhost:3000/api/health
# Expected: {"status":"ok"}

# 5. Check console access
curl -I http://localhost:3000/console/cases
# Expected: 200 or 302 (redirect to login)

# ✅ PASS if all services respond
```

---

## Dépendances

### Upstream (Requis AVANT #28)

**Aucune** — #28 est le fondement, il ne dépend de rien

### Downstream (Bloqués PAR #28)

#### M8 Foundation
- **#77 (Datalake)** — Needs PostgreSQL + ingest endpoint
- **#89 (better-auth tenancy)** — Integrated in #28

#### M9 Fleet Intelligence
- **#62 (Fleet Correlation)** — Needs server/fleet/ module + PostgreSQL
- **#72 (Entity Graph)** — Needs server/graph/ module + PostgreSQL
- **#76 (Prevalence)** — Needs server/prevalence/ module + PostgreSQL
- **#78 (Cloud Detection)** — Needs server/cloud-detection/ + datalake

#### M10 Analyst & Operations
- **#83 (Fleet Ops Dashboard)** — Needs server/ops/ + console infrastructure
- **#61 (Hunt)** — Needs server/hunt/ + datalake
- **#70 (DFIR)** — Needs server/forensics/
- **#75 (Assistant)** — Needs server/assistant/
- **#64 (Disruption)** — Needs server/disruption/
- **#88 (SOAR Integrations)** — Needs server/integrations/

**Total bloqué par #28:** ~15 issues (toute la stack M8/M9/M10)

---

## Risques & Mitigations

### Risques Critiques

#### 1. Complexité d'implémentation sous-estimée (70% probabilité)

**Risque:** "Just scaffold Next.js + Postgres" sounds simple, mais:
- mTLS termination tricky (nginx config, cert validation)
- better-auth organization setup non-trivial
- Prisma migrations + tenant RLS require careful design
- First agent connection debugging time-consuming

**Impact:** Délai 2-3 semaines → cascade sur toute M8/M9

**Mitigation:**
- Time-box Phase 1: 2 semaines maximum, cut features si needed
- Prototype mTLS proxy first (blocker for ingest)
- Use better-auth examples (don't reinvent)
- Keep schema simple (add tables later, not now)

#### 2. mTLS Proxy Configuration (60% probabilité)

**Risque:** nginx/caddy cert verification config errors:
- Wrong CA chain
- Header not passed correctly
- Cert subject parsing breaks

**Impact:** Agents cannot authenticate → ingest down → full stop

**Mitigation:**
- Test with curl + client cert BEFORE agent integration
- Log all cert verification details (debug mode)
- Fallback: API key auth for dev (remove in prod)

#### 3. Tenancy Isolation Bugs (40% probabilité)

**Risque:** Queries leak data across tenants:
- Forgot `where: { tenantId }` in a query
- RLS policy misconfigured
- Audit log not enforcing tenant

**Impact:** **SECURITY BREACH** — data exposure

**Mitigation:**
- Row-Level Security on ALL tables (fail-safe)
- Integration tests with 2+ tenants
- Code review checklist: "tenant filter present?"
- Middleware MUST inject tenant context

### Risques Moyens

#### 4. Docker Compose Dev Experience (50% probabilité)

**Risque:** `docker-compose up` is slow/broken:
- Hot reload not working
- Volume mounts permission issues
- Port conflicts with other services

**Impact:** Developer velocity down, team frustrated

**Mitigation:**
- Test on clean Linux VM (not just macOS)
- Document port conflicts + solutions
- Provide `make` targets (make dev, make reset)

#### 5. Database Migration Strategy Unclear (40% probabilité)

**Risque:** Prisma migrations don't fit production needs:
- Zero-downtime migrations required later
- Partitioning needs raw SQL
- RLS policies not in Prisma DSL

**Impact:** Refactor migration tooling later (weeks lost)

**Mitigation:**
- Accept Prisma for MVP, plan migration to Drizzle/pg-migrate
- Document raw SQL for partitions/RLS
- Keep schema simple (easy to migrate)

---

## Métriques de Succès

### Product Metrics

**Primary:**
- ✅ **Agent enrollment success rate:** >99% (mTLS auth working)
- ✅ **Detection ingest latency:** p95 < 1s (from agent POST to DB insert)
- ✅ **Console page load time:** < 2s (case list initial render)

**Secondary:**
- Silent agent detection accuracy: 100% (no false positives)
- Tenant isolation: 0 data leaks (security critical)

### Operational Metrics

**Infrastructure:**
- docker-compose startup time: < 30s (postgres + server ready)
- PostgreSQL query performance: p95 < 100ms (case list query)

**Developer Experience:**
- Time to first "Hello World" detection: < 15 minutes (from git clone)
- Hot reload working: code change → browser refresh < 3s

---

## Documentation Requise

### For Operators

1. **Deployment Guide**
   - docker-compose setup
   - mTLS cert generation (CA, server, client)
   - Environment variables
   - Database backups

2. **Troubleshooting**
   - "Agent can't connect" → Check mTLS logs
   - "Detections not appearing" → Check ingest endpoint logs
   - "Silent agent false positive" → Adjust threshold

### For Developers

1. **Development Setup**
   - Prerequisites (Node.js 18+, Docker)
   - `npm install` → `docker-compose up`
   - Running tests
   - Database migrations

2. **Architecture**
   - Tenancy model (organization = tenant)
   - mTLS flow (nginx → Next.js → Prisma)
   - Module structure (ingest/api/console)

3. **Adding a New Module**
   - Create `server/mymodule/` directory
   - Add Prisma schema changes
   - Create API routes
   - Update documentation

---

## Critères d'Acceptation Détaillés

### ✅ Criterion 1: Agent enrolls, uploads detections; they appear in console

**Steps to Verify:**
1. Start stack: `docker-compose up`
2. Create tenant (via seed script or console)
3. Generate mTLS cert for test agent
4. Call `/api/enrollment` with client cert
5. Call `/api/ingest/detection` with detection payload
6. Open console: `http://localhost:3000/console/cases`
7. **PASS:** Detection visible in case list within 5 seconds

**Acceptance:**
- [ ] Agent enrollment succeeds (returns `{"status":"enrolled"}`)
- [ ] Detection upload succeeds (returns `{"status":"accepted"}`)
- [ ] Detection appears in console case list
- [ ] Case shows correct: title, severity, timestamp
- [ ] Multi-tenant isolation: tenant A cannot see tenant B's cases

### ✅ Criterion 2: Heartbeat-silence detection server-side

**Steps to Verify:**
1. Enroll agent
2. Send heartbeat: `POST /api/ingest/heartbeat`
3. Wait 6 minutes (> 5min silence threshold)
4. Trigger cron: `GET /api/cron/detect-silent-agents`
5. Open console: check for "Agent Silent" case
6. **PASS:** Case created automatically

**Acceptance:**
- [ ] Heartbeat updates `agent.last_seen` timestamp
- [ ] Cron job finds silent agent (last_seen > 5 min ago)
- [ ] Case created with title "Agent Silent: {hostname}"
- [ ] Severity = "high"
- [ ] Status = "open"

### ✅ Criterion 3: docker-compose up gives a working dev stack

**Steps to Verify:**
1. Clean environment: `docker-compose down -v`
2. Start: `docker-compose up -d`
3. Wait 30 seconds
4. Check postgres: `docker-compose exec postgres pg_isready`
5. Check server: `curl http://localhost:3000/api/health`
6. Check console: `curl http://localhost:3000/console`
7. **PASS:** All services respond

**Acceptance:**
- [ ] PostgreSQL healthy (accepting connections)
- [ ] Server responds to `/api/health` (status 200)
- [ ] Console loads (status 200 or 302 to login)
- [ ] Nginx proxy responds on port 8443
- [ ] Logs show no errors
- [ ] Hot reload working (edit file → browser updates)

---

## Timeline Estimé

### Optimiste (5 semaines)

**Semaine 1:** Foundation
- Days 1-2: Project setup, Prisma schema, Docker Compose
- Days 3-4: better-auth setup, login page
- Day 5: Integration test (stack up, login works)

**Semaine 2:** Ingest
- Days 1-2: Detection endpoint + mTLS proxy config
- Day 3: Heartbeat endpoint
- Day 4: Silent agent detection cron
- Day 5: Test agent → ingest → DB flow

**Semaine 3:** Console
- Days 1-2: Case list page + styling
- Day 3: Navigation, header, sidebar
- Day 4: Case detail page (basic)
- Day 5: Polish UI

**Semaine 4:** API & Testing
- Days 1-2: Enrollment API, case query API
- Days 3-4: Integration tests (3 acceptance criteria)
- Day 5: Bug fixes

**Semaine 5:** Documentation & Polish
- Days 1-2: README, deployment guide, troubleshooting
- Days 3-4: Code cleanup, PR review
- Day 5: Merge to main

**Total:** 5 semaines (optimiste)

### Réaliste (8 semaines)

**+2 semaines:** mTLS proxy config debugging
**+1 semaine:** Tenancy isolation bugs + RLS setup
**Total:** 8 semaines

### Pessimiste (12 semaines)

**+2 semaines:** better-auth organization setup issues
**+2 semaines:** Performance problems (DB query optimization)
**Total:** 12 semaines

---

## Next Actions

### Immediate (Week 1)

1. 📋 **Create branch:** `feat/28-server-scaffold`
2. 🔨 **Project setup:** `npx create-next-app server`
3. 🔨 **Prisma schema:** Define base tables (tenants, agents, detections, cases)
4. 🔨 **Docker Compose:** Write docker-compose.yml
5. ✅ **Test:** `docker-compose up` → PostgreSQL + server running

### Short-term (Week 2-4)

6. 🔨 **mTLS proxy:** Configure nginx with client cert verification
7. 🔨 **Ingest endpoints:** `/api/ingest/detection` + `/api/ingest/heartbeat`
8. 🔨 **Console:** Basic case list page
9. ✅ **Test:** Agent → detection → console (end-to-end)

### Medium-term (Week 5-8)

10. 🔨 **API foundation:** Enrollment, case queries
11. 🔨 **Silent agent detection:** Cron job
12. ✅ **Acceptance tests:** All 3 criteria passing
13. 📝 **Documentation:** README, deployment guide
14. 🎯 **PR:** Merge feat/28-server-scaffold → main

---

## Références

### Design Docs

- `server/README.md` — Control plane architecture overview
- `docs/adr/0001-server-stack-nextjs-postgres.md` — Stack choice rationale
- `docs/adr/0003-better-auth-console.md` — Tenancy & authentication
- `docs/roadmap.md` lines 123-126 — M8 milestone definition

### Related Issues

**Blocked by #28 (downstream):**
- #62 (Fleet Correlation)
- #72 (Entity Graph)
- #76 (Prevalence)
- #77 (Datalake)
- #78 (Cloud Detection)
- #83 (Fleet Ops Dashboard)
- #89 (better-auth tenancy integration)

### Tech Stack References

- [Next.js App Router Docs](https://nextjs.org/docs/app)
- [Prisma Docs](https://www.prisma.io/docs)
- [better-auth Docs](https://www.better-auth.com/docs)
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

---

## Changelog

| Date | Action | Author |
|------|--------|--------|
| 2026-09-11 | Spécification complète créée | Claude |

---

**Status:** OPEN — Spécification complète, implémentation pas démarrée
**Critical Path:** OUI — Bloque toute la stack M8/M9/M10
**Estimated Start:** À définir
**Estimated Duration:** 5-12 semaines selon complexité

**Next:** Créer branch `feat/28-server-scaffold` et commencer Phase 1 (Foundation)
