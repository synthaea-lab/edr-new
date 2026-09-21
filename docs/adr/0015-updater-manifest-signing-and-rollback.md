# ADR-0015: Updater — staged self-update, manifest signing, and rollback (Linux-first slice)

- **Status**: proposed
- **Date**: 2026-09-21

## Context

`crates/updater` is an empty stub (no dependencies, module doc only). Issue #30
asks for "staged, signature-verified self-update with rollback" plus "rule/model
download via canary rings" — two different problems wearing one issue number.

Two other ADRs already assume the updater exists and defer hard questions to it:

- ADR-0010 (shared policy model) names Ed25519 as the policy-signing scheme and
  explicitly defers "distribution mechanism — canary rings via the M6 updater"
  and "rollback of a failed policy application ... the M6 updater needs an atomic
  rollback path and a way to prevent the same broken version from being
  reapplied" — the exact rollback problem a binary self-update also has.
- ADR-0002 (ML model delivery) states "the `updater` trust chain must cover [a
  model] before the first canary ring" as a hard prerequisite.

`crates/tamper::integrity::Manifest` already hashes-and-compares
`(path, sha256)` pairs against the live filesystem, and its own doc says
"the manifest is the root of trust: its authenticity is the updater's job
(signed distribution, ADR-0001)" — a stale citation; ADR-0001 is the server
stack and has no signing content. There is no ADR that actually specifies the
updater's manifest format or signing scheme. `docs/architecture/threat-model.md`
names issue #30 directly: "the manifest chain (updater #30) is the root of
trust" for detecting a swapped binary.

No signing crate exists in the workspace despite ADR-0010's Ed25519 choice —
`ed25519-dalek` has zero hits anywhere, including `Cargo.lock` transitively.
`ring` (0.17.14) is already present transitively (via `ureq`'s TLS stack in
`crates/transport`) and supports Ed25519 (`ring::signature`) — a reuse
candidate that avoids introducing a new top-level dependency for the first
implementation.

Platform reality is uneven. Linux packaging (issue #36) already ships a
concrete layout the updater is meant to manage: package-owned
`bootstrap/{agent,watchdog,cli}` (never touched by the updater) plus a
`current -> bootstrap` symlink and an empty `versions/` directory tree meant
for updater-managed version swaps. Windows packaging (issue #37) has no
equivalent — the MSI drops binaries directly into `INSTALLFOLDER`, no
versioned layout, and code-signing is explicitly "not yet decided." macOS
packaging doesn't exist yet at all.

Issue #30 as written is too large for one implementation pass across three
platforms plus a network content-distribution system. This ADR scopes a first,
concrete slice: **binary self-update on Linux only**, using the existing
packaging layout and `tamper::Manifest` shape. Canary-ring *content*
distribution (rules, models — issues #73, #49) and Windows/macOS binary
self-update are named and deferred, not designed here.

## Decision

1. **Scope**: this ADR covers signed, staged, rollback-capable **binary**
   self-update (agent/watchdog/cli) on **Linux only**. Content distribution
   (rule/model updates via canary rings, per-ring telemetry, auto-halt) and
   Windows/macOS binary self-update are explicitly out of scope — see
   Deferred.

2. **Manifest shape**: reuse `tamper::integrity::Manifest`'s `(PathBuf, sha256
   hex)` entries as the payload, wrapped in a versioned, signed envelope
   following ADR-0010's document shape:
   - `schema_version: u32` — readers reject an unknown value.
   - `release_version: u64` — monotone, strictly increasing; a downloaded
     manifest with a `release_version` not greater than the currently
     installed one is rejected outright (anti-rollback-attack, same
     reasoning as ADR-0010's `policy_version`).
   - `entries: BTreeMap<PathBuf, String>` — path (relative to the version
     directory) → expected sha256 hex, same field this ADR's payload borrows
     from `tamper::integrity::Manifest`.
   - `signature` — Ed25519 over the canonical JSON serialization (indent=2,
     sorted keys, `signature` field replaced with a fixed placeholder before
     signing) — identical canonicalization rule to ADR-0010/ADR-0009, so
     there is exactly one canonicalizer in the workspace, not a second one
     for updater manifests.

3. **Signature verification via `ring`**, not `ed25519-dalek`. Same algorithm
   ADR-0010 named; different crate, because `ring` is already a transitive
   dependency and `ed25519-dalek` would be a new one for the same
   capability. This is an implementation substitution, not a scheme change —
   ADR-0010's choice of *Ed25519* stands.

4. **Key material**: ships with a **test-only keypair** and an explicit
   `SYNTHAEA_UPDATER_TEST_KEY` (or equivalent) marker distinguishing it from a
   production key, mirroring ADR-0010's `SYNTHAEA_STRICT_PROVENANCE`-style
   dev/prod split. Real key generation, storage, and rotation are deferred
   (see Deferred) — this ADR fixes the verification mechanism, not key
   custody.

5. **Layout and atomic swap**: extends the existing Linux packaging
   convention (`packaging/linux/README.md`) rather than inventing a new one.
   `updater`:
   - downloads/stages a new release under `versions/vX.Y.Z/` (never touches
     `bootstrap/`),
   - verifies the manifest signature, then every listed file's sha256 against
     what was staged,
   - on success, atomically repoints the `current` symlink at the new
     `versions/vX.Y.Z/` directory (`rename(2)` on the symlink, not an in-place
     edit — a crash mid-swap leaves either the old or the new target, never a
     half-written one),
   - triggers a controlled restart of the watchdog-supervised agent/watchdog
     process against the new `current` target.

6. **Rollback**: the previous `versions/` directory is kept (not deleted) until
   the new release passes a health check. Health check reuses
   `tamper::heartbeat::SilenceMonitor` machinery already in the agent: if the
   newly started process's heartbeat doesn't advance within a bounded window,
   the updater flips `current` back to the previous version directory and
   marks the failed `release_version` as banned — a banned version is refused
   even if offered again (closes the exact gap ADR-0010 flagged: "a way to
   prevent the same broken version from being reapplied").

## Consequences

- `tamper::integrity::Manifest` gains no new fields or API — the updater's
  signed envelope is a wrapper around the same `(path, sha256)` shape, built
  once verification succeeds, then handed to the existing `Manifest::verify()`
  for the ongoing runtime integrity check `tamper` already does. The stale
  `integrity.rs` comment citing ADR-0001 is corrected to cite this ADR.

- First real cryptographic-signing dependency in the workspace (`ring`'s
  `signature` module). No new top-level crate added.

- `updater` becomes the one process authorized to write `versions/` and flip
  `current` — `docs/architecture/threat-model.md`'s "only `updater` may
  change [installed artifacts]" line gets an actual mechanism behind it.
  `agent::protected` (issue #71's protected-resource monitor) still has no
  concept of "this write came from the legitimate updater" (that gap is
  pre-existing, tracked on #71, unaffected by this ADR) — until it does, an
  update in progress will trigger protected-resource alerts on its own writes;
  acceptable for this slice, flagged for whoever wires that allowlist next.

- Windows and macOS binary self-update remain unimplemented after this ADR.
  `updater`'s Linux-specific pieces are `cfg(target_os = "linux")`-gated,
  matching the sensor-crate convention (empty stub elsewhere) rather than a
  cross-platform no-op API surface that would misleadingly suggest parity.

- Canary-ring *content* distribution (rules, models) is unaffected by this
  ADR and remains fully open — #73 and #49 still need their own design for
  ring membership, per-ring telemetry, and auto-halt. This ADR's
  `release_version`/rollback mechanism is written so a future content-update
  ADR can reuse it rather than invent a second one, but that reuse is not
  designed here.

## Deferred

- **Production key generation, storage, and rotation** — ships test-only for
  this slice, same posture ADR-0010 took for policy signing. Needs its own
  decision once there's a real control-plane release process to sign against.
- **Canary-ring content distribution mechanics** (rule/model updates,
  per-ring telemetry, auto-halt on regression) — issues #73/#49, a separate
  ADR when that work starts.
- **Windows binary self-update** — no versioned-layout convention exists yet
  (the MSI installs flat into `INSTALLFOLDER`); needs its own design,
  possibly MSI-driven re-install rather than a symlink-style swap.
- **macOS binary self-update** — no packaging exists yet at all.
- **`agent::protected`'s updater allowlist** — recognizing the updater as a
  legitimate writer to avoid self-triggered protected-resource alerts during
  an update; tracked on #71.
- **Download transport security beyond TLS** — this ADR assumes fetching over
  the same mTLS-terminated channel the rest of the fleet uses
  (`threat-model.md` line 30); no additional transport hardening designed here.

## References

- Issue #30 — "Build updater: self-update + content distribution client"
  (this ADR's issue; scopes down to the binary-self-update half).
- Issue #73 — "Detection-as-code ... ring deployment" (shares the canary-ring
  mechanism, deferred here).
- Issue #49 — "Per-site model adaptation loop" (explicitly depends on
  "#30 (updater rings)").
- ADR-0010 — Shared policy model (canonical JSON, `schema_version`/monotone
  version pattern, Ed25519 choice this ADR's signature scheme follows).
- ADR-0009 — Model record / scenario-replay binding (the canonical JSON
  precedent ADR-0010 and this ADR both reuse).
- ADR-0002 — ML model delivery and inference (names the updater trust chain
  as a hard prerequisite for shipping models).
- `crates/tamper/src/integrity.rs` — the `Manifest`/`verify()` API this ADR's
  envelope wraps.
- `docs/architecture/threat-model.md` — names issue #30 as the intended root
  of trust for the installed-artifact integrity chain.
- `packaging/README.md`, `packaging/linux/README.md` — the
  bootstrap/current/versions layout this ADR extends rather than replaces.
