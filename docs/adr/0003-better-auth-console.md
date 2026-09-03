# ADR-0003: Console authentication and tenancy build on better-auth

- **Status**: accepted
- **Date**: 2026-09-03

## Context

The control plane (ADR-0001: one Next.js + PostgreSQL app) needs authentication,
organizations/tenancy, and RBAC. Tenancy shapes the Postgres schema, so the choice
must precede real server code — retrofitting tenant isolation is the classic
expensive refactor.

## Decision

Use **better-auth** as the authentication and organization/tenancy foundation for
the console and management API: email/SSO authentication, sessions, and its
organization plugin as the tenancy primitive (organization = tenant; teams for
MSSP-style grouping). RBAC (analyst / responder / admin / read-only, per-tenant) is
modeled on top of better-auth's member/role machinery; every privileged action
checks role AND tenant and lands in the audit log.

Scope boundary: better-auth authenticates HUMANS (and API tokens for
`server/integrations`). Agent identity remains the mTLS enrollment PKI in
`transport` — the two trust domains never mix.

## Consequences

- Tenant id becomes a first-class column from the first migration; every server
  module (ingest, hunt, fleet, lake partitioning) is tenant-scoped by construction.
- SSO (OIDC/SAML via better-auth plugins) is configuration, not a project.
- We inherit better-auth's session/security model and update cadence — a dependency
  worth pinning and watching like any other security-critical one.
- Response/disruption authorization gets its identity source: playbook approvals and
  live-response sessions bind to a better-auth identity in the audit trail.
