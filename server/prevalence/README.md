# server/prevalence — Reputation & Prevalence (Layer 5)

How common is this hash / process name / parent-child pair / domain — on this fleet,
and globally? Rarity is one of the highest-value, cheapest detection signals, and it
is exactly the fleet-derived half of the thesis an attacker cannot reproduce offline.

Planned shape:
- Continuous counters from ingest: first-seen / last-seen / host-count per tenant for
  hashes (from enrich), image paths, parent→child transitions, and domains
- **Feeds detection**: per-site rarity flows into T0/T1 features via the adaptation
  loop (docs/detection/ml.md), and "first execution on the fleet" becomes a
  correlator evidence type
- **Feeds the console**: every hash/process in a case shows "seen on N hosts,
  first seen <date>" — the single most-used triage fact
- Global (cross-tenant) prevalence only ever as opt-in, aggregated, k-anonymous
  statistics — per-tenant data stays per-tenant
