# Detection as Code

Detection content is software: versioned, reviewed, tested, and deployed like it.
Most of the pipeline already exists — this documents the contract and names the gaps.

## Already enforced
- **Versioned + reviewed**: all content lives in `rules/` (Sigma, YARA), changed only
  by PR.
- **Tested in CI**: the content workflow runs each engine's suite — every shipped
  rule must load/compile (hard failure naming the file) AND fire on a crafted
  matching sample, one per rule. Dead content cannot merge (this caught a rule that
  had been silently dead in the old iteration).
- **Loud engine validation**: unsupported constructs are rejected at load with the
  construct named, never silently skipped.

## The remaining contract (tracked per issue)
- **Rule metadata schema**: required fields per rule — ATT&CK technique(s), severity,
  platform, references, false-positive notes — linted in the content suite.
- **Per-rule negative samples**: alongside the matching sample, known-benign lookalikes
  that must NOT fire (the FP regression suite for content).
- **Ring deployment**: content ships via canary rings (`updater`/policy), with per-ring
  detection/FP telemetry and automatic halt — the same guardrails as models.
- **Hunt graduation**: `server/hunt` promotes a repeatedly-matching hunt into a draft
  rule PR, closing the analyst → content loop.
