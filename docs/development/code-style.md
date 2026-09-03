# Code style: Clean Code principles and Rust practice

The bar this codebase holds itself to, and how each rule is enforced. Everything here
is either checked by CI (workspace lints in the root `Cargo.toml`, clippy with
`-D warnings` on three OSes, `cargo fmt`, `tools/check-deps.py`) or reviewed against
explicitly. If a rule matters and nothing enforces it, the fix is to add enforcement,
not to hope.

## Naming

- Names say **what** something is or does, in domain vocabulary (`SlidingCounter`,
  `is_trusted_system_path`, `drain_oldest`) — never mechanism trivia or abbreviations
  a newcomer must decode.
- One concept, one word, everywhere: an alert is an `Alert`, a detection a
  `Detection`, an event an `Event`; do not alternate between synonyms.
- Booleans and predicates read as questions (`is_duplicate`, `has_write_intent`,
  `needs_tail_repair`).
- Kernel/OS nomenclature wins over lint aesthetics where it is the clearer name:
  `pid`/`ppid`, `comm`, `daddr`/`dport` are the domain's words (this is why
  `clippy::similar_names` is deliberately not enabled).

## Functions

- Small, one level of abstraction per function. A dispatcher dispatches
  (`DetectionSink::on_event` routes to `detect_exec` / `detect_file_open` /
  `detect_connect`); the routed-to function does the work.
- No boolean flag parameters that change what a function means — write two functions.
- Command/query separation: a function either computes an answer or mutates state;
  the exceptions (like `SlidingCounter::record`, which prunes and counts) say so in
  their doc comment.
- Zero function-length or cognitive-complexity clippy findings is the observed state
  of the codebase; keep it that way by extracting, not by suppressing.

## Comments and documentation

- A comment states what the code **cannot** say: an invariant, a calibration
  decision, a lesson from a real incident (dates and scenario names welcome —
  "NjRAT FP 2026-08-28" is worth more than a paragraph of theory). Never what the
  next line does.
- Every `pub` item has a doc comment. Functions returning `Result` document
  `# Errors`; functions that can panic document `# Panics` (both enforced:
  `missing_errors_doc`, `missing_panics_doc`).
- Identifiers in prose are backticked (`doc_markdown` enforces it).
- Every `unsafe` block carries a `// SAFETY:` comment stating why its invariants
  hold (`undocumented_unsafe_blocks = deny`).
- Historical provenance comments (`old/...` paths) are allowed; commented-out code
  is not — delete it, git remembers.

## Errors

- Library crates define typed errors with `thiserror`; only binaries use `anyhow`.
- No `unwrap`/`expect` outside tests and provably-infallible cases — and a
  provably-infallible `expect` states its proof in the message or a `# Panics` doc.
- Failure handling is a design decision, stated where it happens: enrichment
  *degrades* (a field goes missing, the event survives), the spool *sheds oldest
  and counts the loss*, content loading *fails loudly* (broken shipped rules are a
  bug, not a warning). Pick the stance deliberately and write it down.
- Never log event payload contents at info level (`tracing`, structured fields).

## Boundaries and dependencies

- `schema` is the platform boundary and is semi-frozen; `policy` sits beside it.
  Sensor crates depend only on `schema` (+ their wire crate); detection crates never
  depend on a sensor; leaf crates depend only on the base tier. Enforced by
  `tools/check-deps.py` in CI — a new crate is classified in the same change.
- Platform-specific code lives **only** in `crates/sensors/*`, target-gated.
- `pub(crate)` by default. A crate's `pub` surface is its contract: minimal,
  deliberate, documented. `#[must_use]` on value-returning methods
  (`must_use_candidate` enforces it).

## State and resources

- Detection state on a long-lived agent is **bounded and observable**: LRU maps
  (`store::BoundedMap`) with eviction counters, bounded queues that shed and count
  (`yara::ScanQueue`, `store::EventSpool`). An unbounded `HashMap` keyed by
  attacker-influencable input is a memory-DoS bug.
- Reads from the filesystem on the event path are budgeted (`MAX_HASH_BYTES`,
  `MAX_SCAN_BYTES`), bounded (`Read::take`), and guarded (`is_file()` before open —
  a FIFO blocks forever).
- Windows of time are true sliding windows (timestamp deques), not reset buckets —
  reset buckets drop in-window events at the boundary.

## Detection-specific honesty

- Exclusions and allowlists document **why** each entry exists, with the date and
  scenario that produced the false positive.
- A name-keyed exclusion is a bypass unless gated on evidence (image path in a
  trusted location today — `policy::is_trusted_system_path`; signature and expected
  parent as the durable fix, issue #107).
- Attribution never fabricates: when identity resolution fails, the value is
  `User::Unknown` / `None`, not a plausible guess (the agent's own token is exactly
  wrong for the processes it could not open).

## Tests

- Every bug fix lands with the regression test that would have caught it, named
  after the behavior (`self_spawn_window_slides_instead_of_resetting`,
  `torn_tail_is_repaired_on_reopen`) and commented with the finding it pins.
- Golden fixtures are the parity mechanism (schema serialization, ML features):
  fixtures are superseded, never edited.
- Tests go through the public API; reaching into internals is a smell that the
  contract is missing something.
- Float comparisons in tests use an explicit epsilon, never `==`.

## Enforcement summary

| Rule | Enforced by |
| --- | --- |
| Formatting | `cargo fmt` (CI) |
| Lint bar, all targets, 3 OSes | `cargo clippy -- -D warnings` (CI) |
| Curated lint set | `[workspace.lints]` in the root `Cargo.toml` |
| `dbg!`/`todo!`/`unimplemented!` never ship | `dbg_macro`, `todo`, `unimplemented` = deny |
| `// SAFETY:` on every unsafe block | `undocumented_unsafe_blocks` = deny |
| Docs: backticks, `# Errors`, `# Panics`, `#[must_use]` | `doc_markdown`, `missing_errors_doc`, `missing_panics_doc`, `must_use_candidate` |
| Dependency direction | `tools/check-deps.py` (CI) |
| License/advisory hygiene | `cargo deny` (CI) |
| Shipped content compiles and fires | content suites (`sigma`, `yara` tests, CI) |

Cross-target note: local clippy only lints the code compiled for the host. Before
touching platform-gated code, lint it for its platform
(`cargo clippy -p sensor-windows --target x86_64-pc-windows-msvc`,
`cargo clippy -p sensor-linux --target x86_64-unknown-linux-gnu`) — this caught a
Windows-only compile break that a macOS-only check missed.
