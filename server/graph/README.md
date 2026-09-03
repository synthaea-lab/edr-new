# server/graph — Entity Graph

The fleet-wide graph of entities and their relations, built continuously from
ingested events and detections: hosts, processes (lineage), identities, files (by
hash), network endpoints/domains, and the edges between them (spawned, wrote,
connected-to, logged-in, same-hash-as).

One graph, four consumers:
- **Cases** — a case is a subgraph plus evidence; the console renders it as such
- **Fleet correlation** (`server/fleet`) — blast-radius = graph neighborhood
- **Hunting** (`server/hunt`) — pivots ("everywhere this hash ran", "everything this
  identity touched") are graph traversals
- **Prevalence** (`server/prevalence`) — node degree/frequency is the raw material

Kept honest: the graph is a *projection* of the stores (rebuildable from events),
bounded by retention, and never the system of record.
