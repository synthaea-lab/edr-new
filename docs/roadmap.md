# Roadmap

The milestones follow the **architecture** of the EDR: each is one layer of the stack,
so an issue's milestone tells you which architectural block it builds. Two subsystems —
the **endpoint** (the agent pipeline) and the **control plane** (the server) — each a
stack of layers, plus a parallel ML track. Issue numbers are the source of truth for
scope; this file only orders them.

Last reviewed 2026-09-04.

## Product philosophy: collect first, everywhere — on every platform at once

An EDR is only as good as the telemetry it captured. **You cannot retroactively detect
on data you never collected** — but you *can* replay new detections over data you kept
(retrospective detection, M9/#78). So the bottom architectural layer — collection — is
built first and broadest, on **all three platforms in parallel**: Linux, Windows, and
macOS are independent tracks sharing only the already-done schema/`Sensor` contract, so
none waits on another (each is gated solely by its own lab). Everything above collection
is a consumer of it. The agent runs and spools standalone, so the control plane is built
*after* the endpoint collects broadly — it arrives to drain and analyze what the agents
already gathered.

## The stack → the milestones

```
ENDPOINT ──────────────────────────────────────────────────────────────
  kernel/OS sources   ETW+EventLog (Win) · eBPF/LSM/uprobes/netlink/       M2 · Collection · Linux
                      journald (Linux) · EndpointSecurity+NE+UnifiedLog     M3 · Collection · Windows
                      (macOS)  —  one sensor contract, sources inventoried  M4 · Collection · macOS
  ───────────────────────────────────────────────────────────────────
  sensors → enrich (hash·sig) · store · rules/sigma/yara/ml/intel/         M5 · On-device detection
  deception · correlator → scored cases (Bayesian LLR)
  ───────────────────────────────────────────────────────────────────
  verdict → response (kill·quarantine·isolate + live) · tamper · mesh ·    M6 · On-device response
  updater (canary rings) · watchdog                                             & resilience
  ───────────────────────────────────────────────────────────────────
  sinks · transport (mTLS, spooled) · ipc · ui (tray) · cli · config ·     M7 · Agent edge
  policy · packaging                                                            & interfaces
CONTROL PLANE ─────────────────────────────────────────────────────────
  Next.js + PostgreSQL · better-auth tenancy · ingest → datalake ·         M8 · Control-plane foundation
  api/console · enrollment·PKI · policy · triage · audit
  ───────────────────────────────────────────────────────────────────
  cloud-detection (streaming·scheduled·RETROSPECTIVE) · fleet cases +      M9 · Fleet intelligence
  adaptive posture · graph · prevalence · hunt
  ───────────────────────────────────────────────────────────────────
  forensics (DFIR) · disruption (isolate·suspend·block) · assistant        M10 · Analyst & operations
  (grounded LLM) · ops · integrations (SOAR) · export (SIEM)
────────────────────────────────────────────────────────────────────────
  T0–T2 models · features · calibration · corpus · adaptation              M11 · ML track (parallel)
```

## Milestones

| # | Milestone | Subsystem · layer | State |
| --- | --- | --- | --- |
| M1 | Linux walking skeleton | proof: one event end to end | ✅ done |
| M2 | Collection · Linux | endpoint · sensor fabric (track A) | in progress |
| M3 | Collection · Windows | endpoint · sensor fabric (track B) | ETW landed; expansion open |
| M4 | Collection · macOS | endpoint · sensor fabric (track C) | not started |
| M5 | On-device detection | endpoint · enrich/store/engines/correlator | engines shipped; content open |
| M6 | On-device response & resilience | endpoint · response/tamper/updater/mesh | primitives shipped; wiring open |
| M7 | Agent edge & interfaces | endpoint · transport/ipc/ui/cli/policy/pkg | sinks shipped; rest open |
| M8 | Control-plane foundation | plane · server/ingest/datalake/PKI | not started |
| M9 | Fleet intelligence | plane · cloud-detect/fleet/graph/prevalence/hunt | not started |
| M10 | Analyst & operations | plane · forensics/disruption/assistant/ops | not started |
| M11 | ML track | parallel · models/features/adaptation | inference shipped; pipeline open |

Milestone numbers ascend the stack: endpoint bottom-up (M2–M7), then control plane
(M8–M10), with the parallel ML track last (M11). Every new issue is filed into its
architectural layer.

## Build order (the stack is also the dependency order)

The architecture is layered by dependency, so building bottom-up *is* the critical path:

1. **Collect (M2 ∥ M3 ∥ M4)** — all three platforms in parallel, as their labs allow.
   The heart of the current work; everything above consumes it.
2. **Detect (M5)** — the engines already run on-device; what remains is content and
   coverage (ATT&CK spine, detection-as-code, intel, deception, memory, ransomware) and
   moving enrichment off the drain thread (#126).
3. **Respond & harden (M6)** — response, the self-protection primitives' agent wiring,
   the updater's canary rings, mesh.
4. **Edge (M7)** — transport (the first thing the plane will talk to), ipc/ui/cli,
   config, policy, packaging. `#23 policy → #24 transport` is the sub-critical path here.
5. **Control-plane foundation (M8)** — server + auth + ingest + datalake; the great
   unblocker for everything fleet-level, built once the agents collect and can ship.
6. **Fleet intelligence (M9)** then **Analyst & operations (M10)** — the plane's upper
   layers, each gated on M8.

The **ML track (M11)** runs alongside throughout, feeding on the telemetry the
collection layers gather — richer sources mean richer features.

## Layer detail

### M2/M3/M4 — Collection (sensor fabric, three parallel platform tracks)

*One sensor contract; sources inventoried, never assumed.* Each track is gated only by
its own lab.

- **Linux (M2):** eBPF sources #90 uprobes · #91 lsm (also the inline-block path #25 uses) · #92 netlink · #93 journal; audit fallback #34; container #80; JA4/SNI #86; device-control telemetry #84; inventory #87; collection quality #53 CO-RE · #111 probe filename; provisioning + musl/rolling-kernel labs #113/#123/#124.
- **Windows (M3):** ETW #20 ✅ + P2–P8 expansion #21 · eventlog #94 · DotNET/SMB #97; the x86 lab #22; conformance matrix #35.
- **macOS (M4):** EndpointSecurity #32 + widening #96; NetworkExtension #33; unified-log #95.

### M5 — On-device detection

Enrich → store → engines → correlator. The engines (rules, sigma, yara, ml, correlator,
enrich, store) shipped; open work is content and coverage: ATT&CK structured fields #74,
detection-as-code #73, schema version contract #114, on-device intel #60, deception #81,
memory scanning #85, ransomware pack #82, and async enrichment off the drain thread #126.

### M6 — On-device response & resilience

Verdict → response #25 + live sessions #63; self-protection (tamper #71, watchdog
backoff/liveness/artifact #101–103, spike #104, hardening #112, trusted-process identity
#107 — the heartbeat + integrity primitives already shipped); updater with canary rings
#30; P2P mesh #79; long-term kernel driver / PPL-ELAM #39.

### M7 — Agent edge & interfaces

Transport (mTLS, spooled) #24 + spool ack #108; ipc #26; ui/tray #31; cli #27; config
#19; the shared policy model #23; packaging #36/#37/#38. Sub-path: `#23 → #24`.

### M8 — Control-plane foundation

Next.js + PostgreSQL (ADR-0001) + better-auth tenancy (ADR-0003) #28/#89; ingest →
datalake full-fidelity telemetry #77; api/console with enrollment·PKI·policy·triage·audit.

### M9 — Fleet intelligence

Cloud-detection (streaming·scheduled·**retrospective**) #78; fleet correlation + adaptive
posture #62; entity graph #72; prevalence first-seen/rarity #76; hunt → content #61.

### M10 — Analyst & operations

DFIR forensics #70; disruption playbooks #64; grounded-LLM assistant #75; fleet-health
ops #83; SOAR/ticketing integrations #88; SIEM export #29.

### M11 — ML track (parallel)

#13 ✅ → {format parity #109, ort static #110} → corpus #44 → {robustness #45, conformal/
OOD #46, lineage features #48} → per-site adaptation #49 → narratives #50. #47
attributions partly landed. #109/#110 first: the pipeline must read real captures and the
scorer must match ADR-0002 before training.
