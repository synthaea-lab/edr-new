# server — Control Plane

The Synthaea control plane (new in this iteration — designed but never built in the old
codebase). Technology choices (language, storage, framework) are deliberately not locked yet.

| Path | Purpose |
| --- | --- |
| `ingest/` | Event and detection ingestion from agents — mTLS endpoint, validation, detection store |
| `api/` | Management API — enrollment/PKI, policy, fleet inventory, case queries, audit log |
| `console/` | Web console — triage UI, case view, fleet health, content/model distribution |
