# server — Control Plane

One modern Next.js (App Router, TypeScript) + PostgreSQL application — see
[ADR-0001](../docs/adr/0001-server-stack-nextjs-postgres.md).

| Path | Purpose |
| --- | --- |
| `ingest/` | Agent-facing endpoints — event/detection upload, heartbeats; mTLS terminated in front (proxy/sidecar) |
| `api/` | Management API — enrollment/PKI, policy distribution, fleet inventory, case queries, audit log |
| `console/` | Analyst console — case-centric triage UI, fleet health, content/model distribution |

All three are facets of the single Next.js app until scale forces a split (the ADR
records the escape hatch). Postgres schema and migrations live here once scaffolded.
