# server/disruption — Attack Disruption

Automated, case-level containment: when a case crosses a confidence threshold and
policy allows, the control plane executes a disruption playbook scoped to the case —
not a human-speed reaction to a single alert.

Planned actions (each gated by policy, fully audited, reversible where possible):
- **Isolate device** — network isolation executed by the agent's `response` crate
  (allow only control-plane traffic), triggered fleet-side for every host in the case
- **Suspend user** — disable/step-up the implicated identity via directory connectors
  (Entra ID / AD / Okta), server-side
- **Block indicators** — push the case's IOCs (hashes, domains, IPs) to the fleet via
  `intel` sets and to boundary controls via the export module
- **Quarantine artifacts** — case-wide quarantine of dropped files via `response`

Design rule: disruption composes actions that already exist agent-side; this module
owns the *decision* (case threshold + policy) and the *orchestration* (fan-out,
rollback, audit), never new endpoint capability.
