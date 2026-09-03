# Ransomware Protection Pack

A dedicated vertical over existing machinery — no new engine, one wired reflex:

1. **Canary tripwires** (`deception`): sentinel files in high-value directories;
   a write/rename/delete touching one is the earliest, cheapest encryption signal.
2. **Burst detection** (`rules`/`correlator`): mass rename/write patterns per pid
   within a short window + extension-churn and entropy-of-written-content features
   (T1486). Windows fidelity depends on delete/rename file events (audit F-6, #21).
3. **Reflex response** (`response` + policy): on a corroborated signal (canary +
   burst), kill the process tree and quarantine the binary — the one scenario where
   seconds matter enough to justify the most aggressive default policy ships with.
4. **Recovery posture**: the case records the damage manifest (files touched in the
   window) so restoration tooling has a scope; VSS/snapshot integration is a later
   Windows item.

Acceptance is scenario-driven: a lab encryptor (benign, marker-based) must be killed
before it processes more than N canary-adjacent files.
