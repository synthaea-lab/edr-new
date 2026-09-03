# ADR-0001: Control plane is a Next.js + PostgreSQL application

- **Status**: accepted
- **Date**: 2026-09-03

## Context

The control plane (enrollment, policy, ingest, case store, console) needs a stack. The
old iteration left this open; an ADR from that era (0012) already leaned toward a
Next.js management console. Team familiarity and iteration speed matter more here than
raw throughput: fleet sizes in scope are thousands of agents, not millions.

## Decision

One modern Next.js application (App Router, TypeScript, server actions / route
handlers) backed by PostgreSQL is the control plane: management API, console UI, and
the initial ingest endpoint. Postgres holds enrollment/PKI records, policy versions,
detections, cases, and the audit log.

## Consequences

- One deployable, one database — self-hosting stays a docker-compose, matching the
  self-hosting goal.
- Agent transport must terminate mTLS in front of Next.js (reverse proxy passing the
  client cert, or a thin sidecar) — client-cert auth is not native to serverless-style
  handlers. The `transport` crate treats this as an implementation detail behind one
  endpoint contract.
- If ingest volume ever outgrows route handlers, ingest splits into its own service
  writing to the same Postgres — schema shared, console untouched. That split is the
  planned escape hatch, not a rewrite.
- Event archives beyond Postgres comfort (raw telemetry at scale) go to object
  storage/SIEM export, not into Postgres — the detection store keeps cases and
  detections, not the firehose.
