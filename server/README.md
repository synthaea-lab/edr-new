# server — Control Plane

One modern Next.js (App Router, TypeScript) + PostgreSQL application — see
[ADR-0001](../docs/adr/0001-server-stack-nextjs-postgres.md).

| Path | Purpose |
| --- | --- |
| `ingest/` | Agent-facing endpoints — event/detection upload, heartbeats; mTLS terminated in front (proxy/sidecar) |
| `api/` | Management API — enrollment/PKI, policy distribution, fleet inventory, case queries, audit log |
| `console/` | Analyst console — case-centric triage UI, fleet health, content/model distribution |
| `hunt/` | Threat hunting — saved/scheduled hunts over fleet telemetry, graduation into detection content |
| `fleet-correlation/` | Cross-machine case correlation + adaptive posture (a detection on one host raises the alertness of related hosts) |
| `disruption/` | Attack disruption — case-level playbooks: isolate device, suspend user, block indicators |
| (planned) `export/` | SIEM forwarding — vendor connectors (Splunk HEC, Sentinel, Elastic) shipping cases/detections fleet-wide; agents only ever emit neutral formats via `sinks` |

All three are facets of the single Next.js app until scale forces a split (the ADR
records the escape hatch). Postgres schema and migrations live here once scaffolded.
