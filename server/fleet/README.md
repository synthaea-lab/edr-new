# server/fleet — Cross-Machine Correlation & Adaptive Posture

Incident correlation across the fleet: detections from one machine change how the
rest of the pool is watched. A case on one host raises the alertness of related hosts
— same subnet, same logged-in identity, same software inventory, peers it recently
talked to laterally.

Two halves:
- **Correlation**: join detections/cases across hosts by shared entities (identity,
  source/destination pairs, file hashes from `intel`/`enrich`) into one fleet-level
  case — the "cases, not alerts" model extended to its natural scope.
- **Adaptive posture**: a case above a severity threshold emits a *posture change*
  for a computed blast-radius set of agents — shipped through the normal signed
  `policy` channel (a posture is a policy overlay: lowered ML thresholds, widened
  telemetry, shortened heartbeat interval, optional stricter response gates), with
  automatic expiry so heightened states decay instead of accumulating.

Guardrails: posture changes are audited like response actions; an attacker must not
be able to weaponize them (posture never *disables* anything, only heightens; expiry
is server-enforced).
