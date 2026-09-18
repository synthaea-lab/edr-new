# ADR-0004: Windows persistence detection via eventlog polling — `FileOpenEvent` with high-bit `flags`, not a dedicated variant

- **Status**: accepted (backfilled 2026-09-17)
- **Date**: originally decided 2026-08 during issue #94 sensor design; recorded here
  after the fact when three consumers (ADR-0009, `stateless.rs` docstring, and
  `xml.rs` module doc) started referencing an ADR file that had never been written.

## Context

`sensor-windows-eventlog` (issue #94) needs to surface three Windows
persistence events into the agent's detection pipeline:

- Event **7045** (System log) — "A service was installed in the system"
  → T1543.003.
- Event **4698** (Security log) — "A scheduled task was created"
  → T1053.005.
- Event **4720** (Security log) — "A user account was created"
  → T1136.001.

Two options existed at the time:

**Option A — dedicated `Event::Persistence(PersistenceEvent)` variant** in
`schema::Event`, with sub-tag fields (`kind: ServiceInstall | ScheduledTask
| AccountCreated`, `service_name`, `image_path`, `task_name`, `action_path`,
`account_name`, `account_sid`, …). Semantically the cleanest — persistence is
its own event category, not a file open.

**Option B — reuse `FileOpenEvent`** with a set of high-bit `flags`
sentinel values (`FLAG_PERSISTENCE_ARTIFACT`,
`FLAG_PERSISTENCE_TASK_ARTIFACT`, `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT`)
and place the technique-specific fields into the two `FileOpenEvent`
slots that already exist:

* `path` — the "artifact path" (service image path / scheduled-task
  action path / new account SID).
* `meta.comm` — the "artifact leaf name" (service name / task leaf name
  / account SAM name).

Option A is textbook. Option B is pragmatic reuse.

## Decision

**Option B — reuse `FileOpenEvent` with high-bit `flags`.**

Three reasons anchored this choice at the time and still hold today:

1. **No `SCHEMA_VERSION` bump.** A new `Event::Persistence` variant
   forces every consumer (sinks, correlator, ML feature extractors,
   sigma engine, replay tools) to grow a match arm before the schema
   version can be bumped and shipped. Reusing `FileOpenEvent` keeps
   everything binary-compatible: consumers that don't care about the
   flag see the event pass through unchanged; consumers that care
   (`check_scheduled_task_persistence` and its siblings in `rules`)
   test the flag explicitly.

2. **Bit space is cheap.** `FileOpenEvent::flags` is already a
   platform-native `u32`, and `disposition_to_flags` on the Windows
   side only ever produces `O_WRONLY` (0o1) / `O_CREAT` (0o100). The
   top three bits (`0x0800_0000`, `0x1000_0000`, `0x2000_0000`) can
   never collide with a real disposition value from any current or
   plausible-future sensor. One bit per persistence technique keeps
   the family explicit, additive, and inspectable.

3. **The rule side gets a clean test.** A rule that fires only on
   persistence events reads
   `if event.flags & FLAG_PERSISTENCE_TASK_ARTIFACT == 0 { return None; }`
   and knows nothing else about the sensor's shape.
   `sensor-windows-eventlog` produces these events, and if a future
   Linux equivalent surfaces the same class of signal it can reuse the
   same flag scheme (or add a Linux-specific bit alongside), no
   schema-side change required.

## Field mapping (per technique)

For every persistence event, the same shape:

| Field | T1543.003 (7045) | T1053.005 (4698) | T1136.001 (4720) |
|---|---|---|---|
| `flags` | `FLAG_PERSISTENCE_ARTIFACT` | `FLAG_PERSISTENCE_TASK_ARTIFACT` | `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` |
| `path` | Service image path | Task action path (from `<Command>` + `<Arguments>`) | New account SID (`S-1-5-21-...`) |
| `meta.comm` | Service name | Task leaf name | SAM account name |
| `meta.pid` | Reporting process PID (`sc.exe`, `schtasks.exe`, LSASS for 4720) | (same) | (same) |

The rule that fires on each event reads only `flags`, `path` and
`meta.comm`; it does not care that these events came from eventlog
polling versus a real file `open()`.

## Consequences

- **Zero `SCHEMA_VERSION` bump for the persistence family.** The three
  events land under an existing variant with an already-`u32` field.
  Every existing consumer sees the events pass through unchanged.
- **Semantic mismatch is documented, not hidden.** A `FileOpenEvent`
  carrying `FLAG_PERSISTENCE_TASK_ARTIFACT` is not a file open — the
  reader has to check the flag before making assumptions about what
  `path` means. The doc comments on each of the three flag constants
  in `crates/schema/src/lib.rs` spell this out explicitly.
- **Additive per technique.** T1136.001 (event 4720, account creation)
  was added in September 2026 by reserving a third bit
  (`FLAG_PERSISTENCE_ACCOUNT_ARTIFACT = 0x0800_0000`) — same pattern,
  no ripple on the rest of the workspace. Future persistence
  techniques (registry Run keys #74, WMI subscriptions, etc.) can take
  the same pattern until we hit the bit budget.
- **The dedicated `Event::Persistence` variant remains an option** for
  a later, quieter revision when the shape has clearly outgrown the
  reuse — for example when a persistence event needs fields
  `FileOpenEvent` cannot naturally carry (registry key path with type
  and value data, a WMI namespace + query, …). This ADR expects that
  transition to be triggered by concrete field pressure, not by
  aesthetic preference.

## References

- Issue #94 — `sensor-windows-eventlog` original scope.
- `crates/schema/src/lib.rs` — `FLAG_PERSISTENCE_ARTIFACT`,
  `FLAG_PERSISTENCE_TASK_ARTIFACT`, `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT`
  definitions and rationale.
- `crates/sensors/windows/eventlog/src/{lib,sensor,xml}.rs` — the
  producer.
- `crates/rules/src/stateless.rs` — the three consumer rules
  (`check_service_install_persistence`,
  `check_scheduled_task_persistence`,
  `check_account_creation_persistence`).
- ADR-0009 — model record scenario-replay binding (references ADR-0004
  in explaining why persistence flows through `FileOpenEvent`).
- ADR-0005 — Windows logon events shared `AuthEvent` type (a
  sibling decision made in the same design pass, where the AuthEvent
  approach *was* preferred over the FileOpenEvent-reuse pattern —
  precisely because logon events needed fields `FileOpenEvent` could
  not naturally carry).
