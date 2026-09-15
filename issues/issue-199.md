# Issue #199: Unbounded Self-Referential CPU Loop in Container Attribution

**Status:** Fixed in PR #201 (pending merge)
**Created:** 2026-09-15
**Severity:** Critical
**Impact:** Agent unusable, detection pipeline starved

## Problem Summary

The Linux agent enters an unbounded feedback loop from the moment it starts, pinning ~100-110% of one CPU core indefinitely and preventing `exec`/`connect` events from reaching the detection pipeline. This causes the walking-skeleton BEACON scenario to silently fail, and makes the agent effectively unusable in production.

## Root Cause

Self-referential feedback loop in container ID attribution:

1. `sys_enter_openat` eBPF probe captures every `open()`/`openat()` syscall system-wide
2. For every `FileOpenEvent`, `ExecEvent`, and `ConnectEvent`, the userspace drain loop calls `read_container_id(pid)` to attribute container context
3. `read_container_id()` performs `std::fs::read_to_string("/proc/{pid}/cgroup")` — itself an `open()` syscall
4. This triggers a **new** `FileOpenEvent` for the same PID
5. The new event goes back through the drain loop, calling `read_container_id()` again
6. Infinite loop: `file_open` → `read_container_id()` → `open()` → `file_open` → ∞

**Why it resonates:** `file_open` is the only event type whose attribution step performs the exact syscall class it's watching. The loop is unbounded because there's no debounce, cache, or self-PID exclusion.

## Evidence

### Arch Linux (Hyper-V, kernel 6.6.9)
- Agent PID 15861: 103.2% CPU sustained
- 80,268 of ~150k events were `path=/proc/15861/cgroup` (agent reading its own cgroup file)
- Confirmed via `top` that 15861 was the live agent PID

### Ubuntu 24.04 (WSL2)
- Agent PID 114022: 109-110% CPU sustained over 90+ seconds
- `TIME+` climbing linearly: 0:14 → 1:29
- Event count climbing: 15,488 → 34,642 in ~80 seconds
- All flooded events had `comm="agent"`

### Impact on Detection
- `events.jsonl` contains **only** `file_open` events (0 `exec`, 0 `connect`)
- `lab/scenarios/beacon.sh` produces **zero alerts**
- eBPF sensor logs show 22 `connect` events captured, but they never reach the sink (congested drain loop)

## Reproduction

```bash
# On any Linux box with eBPF probes built
sudo target/release/agent run

# Wait ~10 seconds
top -bn1 | grep agent           # Pinned at ~100% CPU
wc -l events.jsonl              # Tens of thousands within seconds

# Check event distribution
python3 -c "import json,collections as c; \
  print(c.Counter(json.loads(l)['type'] for l in open('events.jsonl') if l.strip()))"
# Result: Counter({'file_open': N})  — no exec, no connect
```

## Solution: Container ID Cache (PR #201)

### Architecture Decision

**Why cache, not self-PID exclusion?**

Excluding the agent's own PID from `sys_enter_openat` would only close this one instance. The resonance pattern (attribution performing the exact syscall it's watching) isn't specific to the agent — it could recur for any process. A cache fixes the root cause (redundant re-reads) rather than just the symptom.

Additional benefit: Fixes the legitimate case flagged in the code's own prior doc comment — a busy process opening many files shouldn't re-read `/proc/{pid}/cgroup` on every single file operation.

### Implementation

**`ContainerIdCache` structure** (`crates/sensors/linux/userspace/src/sensor.rs`):

```rust
struct ContainerIdCache {
    entries: HashMap<u32, CacheEntry>,
    order: VecDeque<u32>,  // LRU tracking
}

struct CacheEntry {
    id: Option<String>,
    none_attempts: u8,  // Retry counter for runc init race
}

const CONTAINER_ID_CACHE_CAP: usize = 4096;
const NONE_RETRY_LIMIT: u8 = 5;
```

**Key design decisions:**

1. **LRU eviction with 4096 capacity** — No TTL needed because cgroup membership is stable over a PID's lifetime. PID reuse after exit is bounded by capacity, not wired to `sched_process_exit` tracking (same "approximate is fine" philosophy as `FlowPortDedup`)

2. **Retry logic for None results** — Handles a different race condition discovered during validation: `runc`'s init process does several `file_open`s before moving into the container's cgroup and `execve`-ing into the target command. Without retries, every containerized process would be permanently latched to `None` on first observation. The cache now retries up to 5 times before trusting a `None` result as final.

3. **Background Docker API resolution** — Hand-rolled Docker Engine API client over `/var/run/docker.sock` (no HTTP dependency) that resolves image/name asynchronously so it never blocks the drain loop. First event goes out with container ID only; image/name catch up on subsequent events.

### Breaking the Loop

```
Before: file_open → read_container_id() → open(/proc/pid/cgroup)
        → NEW file_open → read_container_id() → ∞

After:  file_open → read_container_id() → [CACHE HIT] ✅
                                        → [CACHE MISS] → open() → cached → subsequent reads are hits
```

## Validation

### Before (Ubuntu/WSL2, stock main)
- Agent PID pinned at 103-110% CPU from startup
- `TIME+` climbing linearly, never settling
- `events.jsonl` contains only `file_open` (0 `exec`, 0 `connect`)
- `lab/scenarios/beacon.sh`: zero alerts

### After (PR #201 branch, same system)
- Idles at **0% CPU** before scenarios run
- CPU time: `0:00.33` after ~11 seconds wall time
- `comm="agent"` never appears in its own event stream
- `exec`/`connect` events reach `events.jsonl` normally
- `lab/scenarios/beacon.sh` fires correctly:
  ```json
  {"technique":"T1071/T1041","message":"pid=160380 comm=nc → 127.0.0.1:4444 | 3x in 60s — suspected beaconing"}
  ```
- Full detection pipeline working: correlator respawn detection (T1059/T1071) + Bayesian alert

### End-to-End Validation (Arch Hyper-V VM)
- Real `dockerd` (docker.io 29.1.3) with `debian:12-slim` container
- Container ID, image, and name all resolve correctly
- T1611 (Escape to Host) detection fires for `docker exec <container> sh -c 'exec 3</proc/1/root/etc/hostname; sleep 3'`

## Known Limitations

### Exit Race Coverage Gap (documented in #204)

Container attribution loses the race for single-shot processes whose entire lifetime is one `open()` then exit (e.g., `cat <path>`). By the time the drain loop attempts to read `/proc/<pid>/cgroup`, the process is already gone.

**Why retry logic doesn't help:** The runc-init retry mechanism (5 attempts) targets a different race where the process is alive but hasn't moved into the container cgroup yet. For already-exited processes, every retry attempt within the same event burst sees identical `ENOENT`, never succeeding.

**Impact:** Container-conditioned detection rules have a blind spot for one-shot commands. A slow/deliberate container escape (shell that stays alive) is detected correctly; a fast one-shot command is silently missed.

**Documented on:** `read_container_id()` and `check_proc_root_escape()` doc comments

**Fix requires:** Capturing container ID kernel-side at probe time (e.g., `bpf_get_current_cgroup_id()`) rather than resolving lazily against `/proc` at drain time. Out of scope for #199.

## Work Phases

### Phase 1: Container ID Cache (Complete)
- **Commits:** c8755a5
- **Changes:**
  - Added `ContainerIdCache` with LRU eviction
  - Integrated into `read_container_id()` call path
  - Capacity: 4096 entries
  - No TTL (cgroup membership is stable)
- **Result:** Breaks the self-referential loop

### Phase 2: Docker Integration + T1611 Rule (Complete)
- **Commits:** 44763c3
- **Changes:**
  - Docker Engine API client (`docker.rs`, no HTTP dep)
  - Background resolution task for image/name lookup
  - Retry logic for runc init window race
  - T1611 detection rule (container escape via `/proc/<pid>/root`)
- **Completes:** Issue #80 part 2/2

### Phase 3: Validation (Complete)
- **Platforms:** Ubuntu/WSL2, Arch/Hyper-V
- **Tests:**
  - Unit: 47/47 sensor-linux + 43/43 rules (6 new for T1611)
  - Integration: `lab/scenarios/beacon.sh` fires correctly
  - End-to-end: Real Docker daemon, T1611 confirmed
- **Result:** CPU idle, full pipeline operational

## Metrics

### Performance Impact
- **CPU usage:** 103-110% sustained → 0% idle
- **Cache overhead:** Single HashMap lookup per event
- **Cache hit rate:** Expected >95% for typical workloads
- **Memory:** ~256KB for 4096 PIDs (64 bytes per entry)

### Fixed Symptoms
- ✅ CPU pinned at 100%+
- ✅ `events.jsonl` flooded with agent's own `file_open` events
- ✅ `exec`/`connect` events starved from detection pipeline
- ✅ BEACON scenario silently failing
- ✅ Full detection pipeline operational

## Related Issues

- **#80:** Container attribution phase 2 (Docker API, T1611) — completed in same PR
- **#204:** Exit race for single-shot processes — documented limitation, separate issue

## Files Modified

### Core Implementation
- `crates/sensors/linux/userspace/src/sensor.rs`
  - `ContainerIdCache` struct and implementation
  - `get_or_fetch()` with retry logic
  - Integration into drain loop at sensor.rs:442/448/454

### Docker Integration
- `crates/sensors/linux/userspace/src/docker.rs` (new)
  - Hand-rolled Docker Engine API client
  - `DockerInfoCache` for image/name caching
  - Background resolution task

### Detection Rules
- `crates/rules/src/lib.rs`
  - `check_proc_root_escape()` for T1611
  - Container-aware detection logic

### Tests
- `crates/sensors/linux/userspace/src/sensor.rs`
  - Cache behavior tests
  - Retry logic tests
  - LRU eviction tests
- `crates/rules/src/lib.rs`
  - 6 new tests for T1611 detection

## References

- **PR #201:** sensor-linux: fix container-id self-feeding CPU loop, resolve image/name, add T1611 rule (#199, #80)
- **Commits:**
  - c8755a5: Cache container-id attribution per pid, fix self-feeding loop
  - 44763c3: Resolve container image/name via Docker API, add T1611 rule
- **Lab validation:** Arch Hyper-V VM (#124), Ubuntu 24.04 WSL2
- **Scenario validation:** `lab/scenarios/beacon.sh`

## Lessons Learned

1. **Attribution syscalls are observable:** Any attribution method that performs the same syscall class being monitored creates potential resonance. Cache or deduplicate aggressively.

2. **Self-observation is inevitable:** Don't rely on perfect self-exclusion. The agent's own operations will appear in its telemetry — design for graceful handling rather than perfect filtering.

3. **Caching beats exclusion for root causes:** Point fixes (self-PID exclusion) address symptoms; caching addresses the underlying redundancy pattern and benefits all processes, not just the edge case.

4. **Process lifecycle races are common:** Both the runc init window (process alive, not yet in cgroup) and the exit window (process gone before read) require explicit handling. Lazy `/proc` resolution is inherently racy for short-lived processes.

5. **Defense in depth:** Even with the cache fix, the exit race (#204) remains. Full coverage requires kernel-side capture, not just userspace optimization.

---

**Status:** PR #201 open, validated end-to-end on two platforms
**Next:** Merge PR #201, monitor for cache effectiveness in production, consider kernel-side capture for #204
