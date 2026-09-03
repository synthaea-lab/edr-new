# server/hunt — Threat Hunting

Analyst-driven hunting over fleet telemetry: ad-hoc queries across the event and
detection stores, saved hunts, and scheduled hunts that page an analyst on new matches.

Planned shape:
- Query layer over the Postgres detection/case store plus the telemetry lake
  (`server/datalake`); hunts run over both
- Hunt = a saved, versioned query with an owner, a schedule, and a result history —
  a hunt that matches repeatedly graduates into detection content (a Sigma rule or
  IOC set), closing the loop from hunting to automated detection
- Live endpoint queries (ask one host "what is running right now?") ride the `response::live`
  channel with its policy gates, not a separate mechanism
