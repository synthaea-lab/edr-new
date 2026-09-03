# server — Control Plane

One modern Next.js (App Router, TypeScript) + PostgreSQL application — see
[ADR-0001](../docs/adr/0001-server-stack-nextjs-postgres.md). Authentication and
tenancy build on better-auth ([ADR-0003](../docs/adr/0003-better-auth-console.md)):
organization = tenant, RBAC on member roles, tenant id first-class from the first
migration; agent identity stays the mTLS enrollment PKI — the two never mix.

| Path | Purpose |
| --- | --- |
| `ingest/` | Agent-facing endpoints — event/detection upload, heartbeats; mTLS terminated in front (proxy/sidecar) |
| `api/` | Management API — enrollment/PKI, policy distribution, fleet inventory, case queries, audit log |
| `console/` | Analyst console — case-centric triage UI, fleet health, content/model distribution |
| `ops/` | Fleet operations — agent health, observable-loss counters, ring rollout, ingest health |
| `integrations/` | SOAR/ticketing/paging — bidirectional case workflow (Jira, ServiceNow, PagerDuty, webhooks) |
| `datalake/` | Telemetry lake — full-fidelity raw events, columnar/partitioned; substrate for cloud detection, hunting, graph/prevalence rebuilds, ML corpora |
| `cloud-detection/` | Cloud-based detection: streaming on ingest, scheduled sweeps, and retrospective replay of new content over history |
| `hunt/` | Threat hunting — saved/scheduled hunts over fleet telemetry, graduation into detection content |
| `fleet/` | Cross-machine case correlation + adaptive posture (a detection on one host raises the alertness of related hosts) |
| `graph/` | Entity graph — fleet-wide entities/relations projection backing cases, fleet correlation, hunting, prevalence |
| `prevalence/` | Reputation/prevalence (Layer 5): fleet first-seen/rarity counters feeding detection and triage |
| `forensics/` | DFIR workbench — triage acquisitions (via live-response), case timeline, artifact parsing, chain of custody |
| `assistant/` | Analyst AI assistant — grounded narratives/navigation over cases and the graph; never scores |
| `disruption/` | Attack disruption — case-level playbooks: isolate device, suspend user, block indicators |
| (planned) `export/` | SIEM forwarding — vendor connectors (Splunk HEC, Sentinel, Elastic) shipping cases/detections fleet-wide; agents only ever emit neutral formats via `sinks` |

All three are facets of the single Next.js app until scale forces a split (the ADR
records the escape hatch). Postgres schema and migrations live here once scaffolded.
