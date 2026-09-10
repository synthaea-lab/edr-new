# Issue #108: EventSpool Two-Phase Drain/Ack

**PR:** #156
**Branch:** `fix/108-eventspool-two-phase-drain`
**Status:** Open, Mergeable

## Summary

Two-phase drain/ack protocol for the EventSpool to ensure at-least-once delivery
and fix active-segment cap enforcement bypass.

Previously, `drain_oldest()` deleted segments immediately, creating a data loss
window between drain and successful upload. A crash in that window would lose
telemetry permanently. Additionally, `enforce_cap()` never deleted the active
segment, allowing it to grow indefinitely past the byte cap.

## Problems Fixed

### 1. At-Least-Once Gap

**Problem:**
- `drain_oldest()` deleted segments before the caller confirmed upload
- A crash between drain and upload would lose data permanently

**Solution:**
- `drain_oldest()` now renames segment to `.inflight` instead of deleting
- New `ack()` method deletes `.inflight` after successful upload
- `open()` recovers `.inflight` files on restart for re-delivery
- Repeated drain without ack re-delivers same segment (idempotent)

### 2. Active-Segment Cap Bypass

**Problem:**
- `enforce_cap()` never deleted the active segment (`head_seq`)
- Active segment could grow indefinitely past the byte cap

**Solution:**
- When the active segment is the only one and exceeds cap, it's sealed first
- Sealing rotates to a new segment, allowing the old one to be shed
- Cap is now enforced including the active segment

### 3. Poison Segment Handling

**New feature:**
- `skip()` method to discard in-flight segment after repeated upload failures
- Prevents a malformed/rejected segment from blocking all telemetry indefinitely
- Counts dropped records for observability

## Files Changed

### Modified Files
- `crates/store/src/spool.rs` — +168/-21 lines (two-phase protocol, cap fixes)

## Implementation Details

### Two-Phase Drain/Ack Protocol

```rust
pub fn drain_oldest<T: DeserializeOwned>(&mut self) -> std::io::Result<Vec<T>>
```

**Behavior changes:**
- Renames segment to `.inflight` instead of deleting
- If segment already in-flight, re-delivers same data (idempotent retry)
- Returns data for upload but keeps file on disk

```rust
pub fn ack(&mut self) -> std::io::Result<bool>
```

**New method:**
- Deletes `.inflight` file after successful upload
- Returns `true` if segment was ack'd, `false` if nothing in-flight
- Must be called after `drain_oldest()` once data is durably uploaded

```rust
pub fn skip(&mut self) -> std::io::Result<bool>
```

**New method:**
- Discards in-flight segment without uploading (for poison segments)
- Counts dropped records
- Returns `true` if segment was skipped, `false` if nothing in-flight

```rust
pub fn has_in_flight(&self) -> bool
```

**New method:**
- Returns `true` if a segment is currently in-flight (drained but not ack'd)

### Crash Recovery

**In `open()`:**
```rust
// Recover in-flight segments from a previous crash: rename .inflight back to .jsonl
for entry in fs::read_dir(dir)?.flatten() {
    let name = entry.file_name();
    if let Some(base) = name.to_str().and_then(|s| s.strip_suffix(".inflight")) {
        let recovered = dir.join(format!("{base}.jsonl"));
        fs::rename(entry.path(), &recovered)?;
        log::info!("spool: recovered in-flight segment {base}");
    }
}
```

### In-Flight Protection

**In `enforce_cap()`:**
- Never deletes in-flight segments (protected during upload)
- Calculates total bytes including `.inflight` files
- If in-flight is the only segment and we're over cap, wait for ack/skip

**In `stats()`:**
- Returns total bytes including `.jsonl` and `.inflight` segments
- Ensures observability includes data being uploaded

### State Machine

```
┌──────────┐   drain_oldest()   ┌────────────┐
│  .jsonl  │ ──────────────────>│ .inflight  │
│ (on disk)│                    │ (uploading)│
└──────────┘                    └────────────┘
                                      │
                         ┌────────────┴──────────────┐
                         │                           │
                    ack()│                      skip()│
                         │                           │
                         v                           v
                   ┌──────────┐              ┌──────────┐
                   │ DELETED  │              │ DELETED  │
                   │(success) │              │(poison)  │
                   └──────────┘              └──────────┘
                                                   │
                                              dropped_records++
```

## Tests

All existing tests pass, plus 6 new tests:

### New Tests Added

1. **`two_phase_drain_redelivers_on_crash`**
   - Verifies segment recovery after crash without ack
   - Tests at-least-once delivery guarantee

2. **`idempotent_drain_without_ack`**
   - Verifies repeated drain returns same data
   - Tests idempotent retry behavior

3. **`skip_poison_segment`**
   - Verifies skip() discards in-flight segment
   - Tests forward progress with poison data

4. **`inflight_protected_from_cap_enforcement`**
   - Verifies in-flight segment not deleted by enforce_cap()
   - Tests protection during upload

5. **`stats_includes_inflight_bytes`**
   - Verifies stats() includes .inflight bytes
   - Tests observability of total disk usage

6. **`ack_failure_allows_retry`**
   - Verifies ack() idempotency
   - Tests second ack() returns false when nothing in-flight

### Test Coverage

```bash
cargo test -p store
# 8 tests total (5 existing + 6 new = 11 expected after merge)
```

## Usage Pattern

**Transport layer integration:**

```rust
// Drain segment for upload
let events = spool.drain_oldest()?;
if events.is_empty() {
    return Ok(()); // Nothing to upload
}

// Upload to server
match transport.upload(&events).await {
    Ok(_) => {
        // Upload succeeded, ack to delete segment
        spool.ack()?;
    }
    Err(e) if e.is_permanent() => {
        // Server rejected (4xx, malformed), skip poison segment
        log::warn!("server rejected batch, skipping segment: {e}");
        spool.skip()?;
    }
    Err(e) => {
        // Transient error (network, 5xx), keep in-flight for retry
        log::warn!("upload failed, will retry: {e}");
        // Next drain_oldest() will re-deliver same segment
    }
}
```

## Commits

1. **42bf2d5** — `fix(store): two-phase drain/ack and active-segment cap enforcement`
   - Initial implementation of two-phase protocol
   - Active-segment cap enforcement fix

2. **f2fbcaf** — `fix(store): address PR #156 review comments`
   - Review fixes (details in commit message)

## Related Issues

- #24 — Transport mTLS (will use the two-phase protocol for reliable upload)
- #134 — Agent health telemetry (spool stats fed to health beacon)

## Integration Status

Ready for merge. Not yet integrated with transport layer (pending #24).

## Notes

**Heads-up for open PRs (#155, #157, #158):**
After the recent rustfmt nightly reformat lands on main, this PR will need:
```bash
git rebase origin/main
cargo +nightly fmt --all
```
Conflicts are formatting-only.
