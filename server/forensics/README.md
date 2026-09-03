# server/forensics — DFIR Investigation Workbench

Deep-dive investigation on top of a case (the Trellix/HX-style layer): when triage
needs more than the correlated evidence, the analyst pivots here.

Planned shape:
- **Triage acquisitions**: one-click collection packages from an endpoint — process
  listing, autoruns/persistence points, browser artifacts, prefetch/shimcache (Win),
  shell history, targeted file/memory-region grabs. Every acquisition rides the
  `live-response` channel and its policy/audit gates — forensics adds packages and
  parsing, never a second remote-access mechanism.
- **Timeline**: unified, filterable timeline for a case — sensor events, detections,
  acquisition artifacts, and analyst annotations on one axis.
- **Artifact parsing**: server-side parsers turn raw acquisitions into structured,
  searchable records attached to the case (and into the entity graph).
- **Evidence integrity**: acquisitions are hashed at collection, stored immutably,
  and the chain of custody (who collected what, when, from where) is part of the
  case's audit record.
