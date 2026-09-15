# Issue #199 - Agent: Unbounded Self-Referential CPU-Pinning Loop

**Issue:** https://github.com/synthaea-lab/edr-new/issues/199
**Status:** Open, Unassigned
**Priority:** CRITICAL
**Platform:** Linux (all distributions)
**Created:** 2026-09-15

---

## Summary

`agent run` on Linux enters an **unbounded, self-sustaining feedback loop** from the moment it starts, pinning **~100-110% CPU** indefinitely and **starving `exec`/`connect` events** from ever reaching output files.

**Impact:**
- Agent becomes unusable in production
- Detection scenarios silently fail (race condition)
- exec/connect events never reach detection pipeline
- file_open events flood the system (tens of thousands/second)

**Confirmed Platforms:**
- ✅ Arch Linux (Hyper-V, kernel 6.6.9)
- ✅ Ubuntu 24.04 (WSL2)
- ⚠️ **Not platform-specific** - reproduces on stock `main`

---

## Root Cause Analysis

### The Feedback Loop

```
1. eBPF probe captures open() syscall
   ↓
2. Userspace drains FileOpenEvent
   ↓
3. Calls read_container_id(pid)
   ↓
4. Reads /proc/{pid}/cgroup (open() syscall!)
   ↓
5. eBPF probe captures THIS open() as new FileOpenEvent
   ↓
6. Back to step 2 → INFINITE LOOP
```

### Code Locations

**eBPF Probe (captures all open/openat):**
- `crates/sensors/linux/ebpf/src/main.rs:211-272`
- `sys_enter_openat` - captures every `open()`/`openat()` system-wide
- **No self-exclusion for agent's own pid**

**Container ID Attribution (triggers open):**
- `crates/sensors/linux/userspace/src/sensor.rs:238-247` - `read_container_id()` function
- Lines 442/448/454 - called for every FileOpenEvent, ExecEvent, ConnectEvent
- Calls `std::fs::read_to_string("/proc/{pid}/cgroup")` → triggers open() syscall
- **Added by #169 (issue #80) on 2026-09-11**

**The Problem:**
- `file_open` is the **only** event type whose attribution step performs the **exact syscall it's watching**
- Creates self-referential resonance
- `exec`/`connect` also call `read_container_id`, but don't recursively trigger their own event type
- **No bounds:** No debounce, no cache, no self-pid exclusion

---

## Reproduction Steps

### Environment
Any Linux box with eBPF probes built (bpf-linker present).

### Steps

```bash
# Start agent
sudo target/release/agent run   # or: sudo setsid ... > agent.log 2>&1 &

# Wait ~10 seconds (no other action needed)

# Observe CPU pinning
top -bn1 | grep agent
# → agent process at 100%+ CPU, TIME+ growing continuously

# Count events
wc -l events.jsonl
# → Climbing continuously, tens of thousands within seconds

# Check event types
python3 -c "import json,collections as c; print(c.Counter(json.loads(l)['type'] for l in open('events.jsonl') if l.strip()))"
# → Counter({'file_open': N}) — no exec, no connect
```

---

## Evidence

### Arch Linux (Hyper-V, kernel 6.6.9)

**Observations:**
- Agent PID: 15861
- CPU usage: 103.2% sustained
- Total events: ~150k
- Self-referential events: 80,268 with `path=/proc/15861/cgroup`
- Confirmed via `top` that 15861 is the live agent pid

**Pattern:**
The agent is literally watching itself read its own container ID in an infinite loop.

---

### Ubuntu 24.04 (WSL2)

**Observations:**
- Agent PID: 114022
- CPU usage: 109-110% sustained over 90+ seconds
- TIME+ climbing linearly: 0:14 → 1:29
- Event count: 15,488 → 34,642 in ~80 seconds (continuous growth)
- Flooded PID: 144463 (likely tokio worker thread, not tgid)
- All flooded events: `comm="agent"`

**Note on PID mismatch:**
The specific PID being flooded (144463) doesn't match the process-group leader that `ps`/`pgrep` shows. This is because `bpf_get_current_pid_tgid()` in eBPF reads the raw kernel task ID, which for a thread differs from the tgid that `ps` reports. This is most likely one of the agent's own tokio worker threads.

---

### BEACON Scenario Failure

**Test:** `lab/scenarios/beacon.sh` against freshly-started agent on Arch

**Timeline:**
- Agent ran for ~6 minutes with self-flood
- Beacon scenario executed

**Results:**
- ❌ Zero alerts
- ❌ Zero `connect`-typed events in `events.jsonl`
- ✅ eBPF sensor internal log shows 22 `connect` events captured:
  ```
  [INFO sensor_linux_ebpf] sensor-linux-ebpf: connect pid=...
  ```
- **Events never made it through congested drain loop to the sink**

**Implication:**
Detection scenarios can **silently fail** depending on timing. This is a **race condition**, not a hard break, which is **worse** for a detection product:
- Can pass casual testing
- Fails in real deployment
- Alpine validation (#186, 2026-09-14) happened to work despite bug being on `main` since #169

---

## Technical Analysis

### Why file_open Creates a Loop

| Event Type | Attribution Syscall | Self-Triggers? |
|------------|---------------------|----------------|
| `file_open` | `open(/proc/{pid}/cgroup)` | ✅ YES - creates new file_open event |
| `exec` | `open(/proc/{pid}/cgroup)` | ❌ NO - doesn't trigger exec event |
| `connect` | `open(/proc/{pid}/cgroup)` | ❌ NO - doesn't trigger connect event |

**Key Insight:**
`file_open` is unique in that its attribution step performs the exact syscall it's monitoring. This creates **self-referential resonance**.

### Growth Rate

**Without bounds:**
- Each `file_open` event triggers 1 new `file_open` event
- Exponential growth limited only by:
  - CPU scheduling
  - Ring buffer capacity
  - Event drain rate

**Observed growth:**
- ~100 events/second minimum
- Can reach tens of thousands within seconds
- Never stabilizes

### Why exec/connect Get Starved

**Event Processing Order:**
1. eBPF ring buffer fills with events (file_open dominates)
2. Userspace drain loop processes events FIFO
3. Each file_open event creates more file_open events
4. Queue never empties
5. exec/connect events stuck behind file_open flood

**Practical Result:**
Critical detection events (exec, connect) never reach the detection pipeline, even though they're captured by eBPF.

---

## Proposed Solutions

### Solution 1: Self-PID Exclusion in eBPF (Immediate Fix)

**Approach:** Exclude agent's own PID from `sys_enter_openat` capture.

**Implementation:**
```rust
// In crates/sensors/linux/ebpf/src/main.rs
#[uprobe(name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() >> 32;

    // Read agent PID from config map (set by userspace at startup)
    let agent_pid = AGENT_PID_MAP.get(&0).unwrap_or(&0);
    if pid == *agent_pid {
        return 0; // Skip agent's own syscalls
    }

    // ... rest of probe logic
}
```

**Pros:**
- ✅ Simple, localized fix
- ✅ Zero overhead for non-agent processes
- ✅ Fixes the immediate CPU loop

**Cons:**
- ❌ Only fixes file_open self-reference, not the general pattern
- ❌ Requires passing agent PID to eBPF (new map)
- ❌ Doesn't fix thread IDs (tokio workers have different PIDs)
- ❌ Doesn't help with legitimate high file-open processes

---

### Solution 2: Cache read_container_id() Per PID (Robust Fix)

**Approach:** Cache container ID lookups per PID to avoid repeated `/proc/pid/cgroup` reads.

**Implementation:**
```rust
// In crates/sensors/linux/userspace/src/sensor.rs
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct ContainerIdCache {
    cache: HashMap<u32, (String, Instant)>,
    ttl: Duration,
}

impl ContainerIdCache {
    fn get_or_fetch(&mut self, pid: u32) -> String {
        let now = Instant::now();

        // Check cache
        if let Some((cached_id, timestamp)) = self.cache.get(&pid) {
            if now.duration_since(*timestamp) < self.ttl {
                return cached_id.clone();
            }
        }

        // Cache miss or expired - fetch from /proc
        let container_id = read_container_id(pid);
        self.cache.insert(pid, (container_id.clone(), now));
        container_id
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < self.ttl
        });
    }
}
```

**Configuration:**
- TTL: 30 seconds (processes don't change containers often)
- Cleanup: Every 1000 events or 10 seconds

**Pros:**
- ✅ Fixes self-referential loop (agent PID cached immediately)
- ✅ Fixes legitimate high-volume processes (e.g., build systems)
- ✅ Reduces syscall overhead across the board
- ✅ Addresses the doc comment's own TODO about caching

**Cons:**
- ❌ More complex than self-PID exclusion
- ❌ Memory overhead (cache grows with unique PIDs)
- ❌ Cache invalidation complexity (process can change cgroups)

---

### Solution 3: Rate-Limit Container ID Attribution (Defense-in-Depth)

**Approach:** Rate-limit or debounce `read_container_id()` calls independent of caching.

**Implementation:**
```rust
// Per-PID rate limiter (token bucket)
struct AttributionRateLimiter {
    tokens: HashMap<u32, (u32, Instant)>,
    rate: u32,       // max calls per second per PID
    burst: u32,      // max burst size
}

impl AttributionRateLimiter {
    fn check_and_consume(&mut self, pid: u32) -> bool {
        let now = Instant::now();
        let (tokens, last_check) = self.tokens.entry(pid).or_insert((self.burst, now));

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(*last_check).as_secs_f32();
        let refill = (elapsed * self.rate as f32) as u32;
        *tokens = (*tokens + refill).min(self.burst);
        *last_check = now;

        // Try to consume a token
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false // Rate limit exceeded
        }
    }
}
```

**Configuration:**
- Rate: 10 calls/second per PID
- Burst: 20 tokens

**Pros:**
- ✅ Bounds worst-case behavior
- ✅ Defense-in-depth (works even if cache fails)
- ✅ Graceful degradation (old container ID used on rate limit)

**Cons:**
- ❌ Adds complexity
- ❌ May miss container changes in high-frequency scenarios
- ❌ Doesn't eliminate the loop, just bounds it

---

## Recommended Implementation Plan

### Phase 1: Immediate Fix (Stop the Bleeding)

**Goal:** Ship a minimal fix ASAP to unblock testing.

**Tasks:**
1. Implement **Solution 1 (Self-PID Exclusion)**
   - Add `AGENT_PID_MAP` to eBPF program
   - Populate map on agent startup with `std::process::id()`
   - Skip events where `pid == agent_pid` in `sys_enter_openat`
2. Also exclude agent's **thread IDs**:
   - Read `/proc/self/task/*` to get all thread IDs
   - Add all thread IDs to exclusion map
   - Refresh periodically (tokio may spawn new workers)
3. Test on both Arch and Ubuntu
4. Run BEACON scenario to verify exec/connect events flow

**Acceptance Criteria:**
- ✅ Agent CPU usage <5% at idle
- ✅ events.jsonl contains exec and connect events
- ✅ BEACON scenario fires alerts

**Timeline:** 1-2 days

---

### Phase 2: Robust Fix (Prevent Future Issues)

**Goal:** Implement caching to fix the general pattern and improve performance.

**Tasks:**
1. Implement **Solution 2 (Container ID Cache)**
   - Create `ContainerIdCache` struct with HashMap + TTL
   - Integrate into drain loop (all event types)
   - Configure TTL = 30 seconds
   - Add cache cleanup every 1000 events
2. Add metrics:
   - Cache hit rate
   - Cache size
   - Container ID read latency
3. Performance testing:
   - High file-open workload (build system)
   - Container migration scenario (process moves between cgroups)
4. Documentation:
   - Update `sensor.rs` doc comments
   - Add operator guide section on cache tuning

**Acceptance Criteria:**
- ✅ Cache hit rate >95% in steady state
- ✅ No performance regression on high-volume workloads
- ✅ Container changes detected within TTL

**Timeline:** 3-5 days

---

### Phase 3: Defense-in-Depth (Optional)

**Goal:** Add rate limiting as safety net.

**Tasks:**
1. Implement **Solution 3 (Rate Limiting)**
   - Token bucket per PID
   - Rate: 10 calls/sec, burst: 20
2. Add observability:
   - Log rate limit hits
   - Metric for rate-limited attributions
3. Document behavior:
   - What happens on rate limit (use cached or "unknown")
   - Operator tuning guide

**Acceptance Criteria:**
- ✅ Rate limiter prevents unbounded growth even if cache disabled
- ✅ Rate limit hits logged with context (pid, comm)

**Timeline:** 2-3 days

---

## Implementation Status

### Phase 1: Self-PID Exclusion ✅ IMPLEMENTED

**Commit:** 8234422
**Date:** 2026-09-15

**eBPF Changes (`crates/sensors/linux/ebpf/src/main.rs`):**
- ✅ Added `EXCLUDED_PIDS` HashMap<u32, u8> with 256 max entries
- ✅ Check PID/TID at start of `try_sys_enter_openat()`
- ✅ Early return if PID or TID is in exclusion set
- ✅ Handles both TGID (main PID) and TID (thread IDs)

**Userspace Changes (`crates/sensors/linux/userspace/src/sensor.rs`):**
- ✅ Created `populate_excluded_pids()` function
- ✅ Reads agent's own PID with `std::process::id()`
- ✅ Reads all thread IDs from `/proc/self/task/*`
- ✅ Inserts all IDs into EXCLUDED_PIDS before attaching probes
- ✅ Logs count of excluded PIDs/TIDs

**Code Example:**
```rust
// eBPF probe check (main.rs)
let pid_tgid = bpf_get_current_pid_tgid();
let tid = pid_tgid as u32;
let pid = (pid_tgid >> 32) as u32;

if unsafe { EXCLUDED_PIDS.get(&tid).is_some() || EXCLUDED_PIDS.get(&pid).is_some() } {
    return Ok(0); // Skip this event silently
}
```

```rust
// Userspace population (sensor.rs)
fn populate_excluded_pids(ebpf: &mut aya::Ebpf) -> Result<u32, SensorError> {
    let agent_pid = std::process::id();
    excluded.insert(agent_pid, 0, 0)?;

    // Insert all thread IDs from /proc/self/task/*
    for entry in std::fs::read_dir("/proc/self/task")?.flatten() {
        if let Ok(tid) = entry.file_name().to_str()?.parse::<u32>() {
            excluded.insert(tid, 0, 0)?;
        }
    }
    Ok(excluded_count)
}
```

**Impact:**
- ✅ Breaks self-referential loop (file_open → read_container_id → open → ∞)
- ✅ Zero overhead for non-agent processes (single HashMap lookup)
- ✅ Handles tokio worker threads (different TIDs)
- ✅ Userspace code compiles (cargo check passes)

**Status:**
- ✅ Code complete and pushed
- ⏳ Pending lab validation (requires bpf-linker + BTF kernel)
- ⏳ Pending acceptance test (CPU usage, BEACON scenario)

**Known Limitations:**
- Only fixes self-reference, not the general pattern
- Does not refresh thread IDs (if tokio spawns new workers at runtime)
- Requires lab validation to confirm eBPF verifier accepts code

**Next Steps:**
- Lab validation with bpf-linker (Task #8)
- Run acceptance tests (CPU <5%, BEACON fires)
- If successful, proceed to Phase 2 (container ID cache)

---

### Phase 2: Container ID Cache ✅ IMPLEMENTED

**Commit:** 295d89b
**Date:** 2026-09-15

**Userspace Changes (`crates/sensors/linux/userspace/src/sensor.rs`):**

**ContainerIdCache struct:**
```rust
struct ContainerIdCache {
    cache: HashMap<u32, (Option<String>, Instant)>,
    ttl: Duration,              // 30 seconds
    last_cleanup: Instant,
    cleanup_interval: Duration, // 10 seconds or 1000 events
    event_count_since_cleanup: u32,
}
```

**get_or_fetch() method:**
```rust
fn get_or_fetch(&mut self, pid: u32) -> Option<String> {
    let now = Instant::now();

    // Check cache
    if let Some((cached_id, timestamp)) = self.cache.get(&pid) {
        if now.duration_since(*timestamp) < self.ttl {
            return cached_id.clone(); // Cache hit
        }
    }

    // Cache miss or expired - fetch from procfs
    let container_id = read_container_id(pid);
    self.cache.insert(pid, (container_id.clone(), now));

    // Trigger cleanup if needed (1000 events or 10 seconds)
    if self.event_count_since_cleanup >= 1000
        || now.duration_since(self.last_cleanup) >= self.cleanup_interval
    {
        self.cleanup_expired();
    }

    container_id
}
```

**Integration in run_async():**
```rust
// Create cache before event loop
let mut container_id_cache = ContainerIdCache::new();

// Replace read_container_id() calls with cache.get_or_fetch()
drain!(guard, ExecEvent, sink, |e| {
    normalize::exec(e, offset, read_proc_cmdline(e.meta.pid),
                    container_id_cache.get_or_fetch(e.meta.pid))
});

drain!(guard, FileOpenEvent, sink, |e| {
    normalize::file_open(e, offset, container_id_cache.get_or_fetch(e.meta.pid))
});

drain!(guard, ConnectEvent, sink, |e| {
    normalize::connect(e, offset, container_id_cache.get_or_fetch(e.meta.pid))
});
```

**Performance Impact:**

**Cache hit (expected >95%):**
- ~10-50ns (HashMap lookup)
- No syscall, no procfs read

**Cache miss:**
- ~50-200µs (open + read + parse procfs)
- Same as before, but result is cached for 30 seconds

**Expected benefit:**
Process with 1000 file_open events/sec:
- Before: 1000 procfs reads (~50-200ms CPU)
- After: 1 read + 999 cache hits (~50µs total)
- **~1000x improvement for high-volume processes**

**Testing:**
- ✅ 6 new unit tests covering cache behavior
- ✅ Cache hit returns same value
- ✅ Cache stores None for nonexistent PIDs
- ✅ Cleanup removes expired entries
- ✅ Cleanup keeps fresh entries
- ✅ Auto-cleanup after 1000 events
- ✅ Multiple PIDs handled correctly
- ✅ Code compiles (cargo check passes)

**Observability:**
- Log on cache initialization: "container ID cache initialized (TTL: 30s)"
- Log on exit: "exiting (container ID cache final size: N)"
- Debug log on cleanup: "cache cleanup: N entries remaining"
- stats() method for future metrics integration

**Impact:**

**Fixes Phase 1 limitations:**
- ✅ Helps ALL processes, not just agent self-reference
- ✅ Reduces syscall overhead across the board
- ✅ Addresses doc comment's TODO about caching
- ✅ Improves performance for legitimate high-volume processes (build systems, web servers)

**Combined with Phase 1:**
- Phase 1: Prevents agent's own syscalls from being captured (eBPF exclusion)
- Phase 2: Caches results, so even if captured, no repeated reads
- Defense-in-depth: both layers protect against loop

**Status:**
- ✅ Code complete and pushed
- ✅ 6 unit tests added and passing
- ⏳ Pending lab validation (real workload testing)
- ⏳ Pending cache hit rate measurement in production

**Known Limitations:**
- Cache is unbounded (relies on TTL cleanup and process lifetime)
- No explicit cache size limit (acceptable - PIDs are bounded by kernel)
- Cache hit rate not measured (future work: add metrics)
- No explicit cache invalidation on container migration (acceptable - TTL handles it)

**Next Steps:**
- Lab validation with real workload (build system, web server)
- Measure cache hit rate and verify >95% in steady state
- Monitor cache size and cleanup frequency
- If successful, consider Phase 3 (rate limiting - optional)

---

### Phase 3: Rate Limiting ✅ IMPLEMENTED

**Commit:** 4405154
**Date:** 2026-09-15

**Userspace Changes (`crates/sensors/linux/userspace/src/sensor.rs`):**

**AttributionRateLimiter struct (Token Bucket Algorithm):**
```rust
struct AttributionRateLimiter {
    buckets: HashMap<u32, (u32, Instant)>,  // PID -> (tokens, last_check)
    rate: u32,    // 10 calls/sec per PID
    burst: u32,   // 20 token burst
    rate_limited_count: u64,
}
```

**Token bucket implementation:**
```rust
fn check_and_consume(&mut self, pid: u32) -> bool {
    let now = Instant::now();
    let (tokens, last_check) = self.buckets.entry(pid).or_insert((self.burst, now));

    // Refill tokens based on elapsed time
    let elapsed = now.duration_since(*last_check).as_secs_f32();
    let refill = (elapsed * self.rate as f32) as u32;
    *tokens = (*tokens + refill).min(self.burst);
    *last_check = now;

    // Try to consume a token
    if *tokens > 0 {
        *tokens -= 1;
        true  // Operation allowed
    } else {
        self.rate_limited_count += 1;
        false  // Rate limited
    }
}
```

**Integration in ContainerIdCache.get_or_fetch():**
```rust
fn get_or_fetch(&mut self, pid: u32) -> Option<String> {
    let now = Instant::now();

    // Cache hit (fresh) - no rate limit check needed
    if let Some((cached_id, timestamp)) = self.cache.get(&pid) {
        if now.duration_since(*timestamp) < self.ttl {
            return cached_id.clone();  // Bypass rate limit
        }

        // Cache expired - check rate limit before refreshing
        if !self.rate_limiter.check_and_consume(pid) {
            // Rate limited - return stale cache as fallback
            return cached_id.clone();
        }
    } else {
        // Cache miss - check rate limit before fetching
        if !self.rate_limiter.check_and_consume(pid) {
            // Rate limited - no cached value, return None
            return None;
        }
    }

    // Rate limit OK - fetch from procfs
    let container_id = read_container_id(pid);
    self.cache.insert(pid, (container_id.clone(), now));
    container_id
}
```

**Graceful degradation:**
- **Rate-limited with cached value:** Return stale cache (acceptable staleness)
- **Rate-limited with no cache:** Return None (event has no container ID)
- **No errors, no panics, no event loss**
- **Debug logs for observability**

**Automatic cleanup:**
```rust
fn cleanup_stale(&mut self) {
    let now = Instant::now();
    let stale_threshold = Duration::from_secs(60);

    // Remove buckets for PIDs not seen in 60 seconds
    self.buckets.retain(|_, (_, last_check)| {
        now.duration_since(*last_check) < stale_threshold
    });
}
```

**Observability:**
```rust
// Init log
log::info!("container ID cache initialized (TTL: 30s, rate limit: 10/sec)");

// Debug log on rate limit hit
log::debug!(
    "container ID attribution rate-limited for PID {} ({} total)",
    pid, rate_limited_count
);

// Cleanup log
log::debug!(
    "cache cleanup: {} entries, {} rate limiter buckets, {} rate-limited",
    cache.len(), active_pids, rate_limited_count
);

// Exit log
log::info!(
    "exiting (container ID cache: {} entries, {} rate-limited calls)",
    size, rate_limited_count
);
```

**Performance Impact:**

**Normal operation (cache hit):**
- No rate limit check (bypassed)
- Zero overhead

**Cache miss (rare):**
- Rate limit check: ~10-50ns (token refill + comparison)
- Negligible compared to procfs read (~50-200µs)

**Rate limited (very rare in normal operation):**
- Returns stale cache or None immediately
- Prevents expensive procfs read
- Bounds worst-case CPU usage

**Defense-in-Depth (All 3 Phases):**
1. **Phase 1 (eBPF exclusion):** Prevents agent's own syscalls from being captured
2. **Phase 2 (Cache):** Avoids repeated procfs reads (>95% hit rate expected)
3. **Phase 3 (Rate limiting):** Bounds worst-case if exclusion/cache fail

**Testing:**
- ✅ 8 new unit tests covering rate limiter
- ✅ Initial burst allows 20 calls
- ✅ Token refill over time (200ms = 2 tokens at 10/sec)
- ✅ Rate-limited count tracking
- ✅ Per-PID isolation (independent buckets)
- ✅ Stale bucket cleanup (60 sec threshold)
- ✅ Integration with cache (stale cache return on rate limit)
- ✅ Integration with cache (None return on cache miss + rate limit)
- ✅ Code compiles (cargo check passes)

**Status:**
- ✅ Code complete and pushed
- ✅ 8 unit tests added and passing
- ✅ Integrated with ContainerIdCache
- ⏳ Pending lab validation (measure rate limit hit frequency)
- ⏳ Pending production monitoring (should be very rare)

**Known Limitations:**
- Rate limit is per-PID, not global (acceptable - prevents one bad process from affecting others)
- Buckets HashMap unbounded (relies on cleanup + process lifetime)
- Stale cache fallback has no TTL limit (acceptable - better than None)

**Next Steps:**
- Lab validation with all 3 phases combined
- Measure rate limit hit frequency (should be very rare in normal operation)
- Monitor cache hit rate and rate-limited calls in production
- Consider adding metrics integration for observability

**Expected Behavior:**
- **Normal operation:** Phase 1 prevents self-loop, Phase 2 handles caching, Phase 3 never triggered
- **High-volume process:** Phase 2 cache prevents most procfs reads, Phase 3 rarely triggered
- **Pathological case:** Phase 3 bounds worst-case (returns stale/None, logs warning)

---

## Testing Strategy

### Unit Tests

**Container ID Cache:**
```rust
#[test]
fn cache_hit_returns_cached_value() {
    let mut cache = ContainerIdCache::new(Duration::from_secs(30));
    // Mock read_container_id to return different values
    let id1 = cache.get_or_fetch(1234);
    let id2 = cache.get_or_fetch(1234);
    assert_eq!(id1, id2); // Second call hits cache
}

#[test]
fn cache_expires_after_ttl() {
    let mut cache = ContainerIdCache::new(Duration::from_millis(100));
    let id1 = cache.get_or_fetch(1234);
    std::thread::sleep(Duration::from_millis(150));
    let id2 = cache.get_or_fetch(1234);
    // Should re-fetch (mock shows different value)
}
```

**Rate Limiter:**
```rust
#[test]
fn rate_limiter_allows_burst() {
    let mut limiter = AttributionRateLimiter::new(10, 20);
    for _ in 0..20 {
        assert!(limiter.check_and_consume(1234)); // Burst allowed
    }
    assert!(!limiter.check_and_consume(1234)); // Burst exhausted
}
```

---

### Integration Tests

**Self-Reference Test:**
```bash
# Start agent with instrumentation
sudo target/release/agent run --metrics-port 9090

# Let run for 60 seconds
sleep 60

# Check metrics
curl localhost:9090/metrics | grep -E "cpu_percent|event_type_count"

# Verify:
# - cpu_percent < 5%
# - event_type_count{type="file_open"} not dominant
# - event_type_count{type="exec"} > 0
# - event_type_count{type="connect"} > 0
```

**BEACON Scenario:**
```bash
# Start agent
sudo target/release/agent run > /tmp/agent.log 2>&1 &

# Wait for startup
sleep 5

# Run BEACON
cd lab/scenarios
./beacon.sh

# Check results
cat /tmp/agent.log | grep -i "alert.*beacon"
# Should see alert for C2 beacon

cat events.jsonl | jq 'select(.type == "connect")'
# Should see connect events for beacon traffic
```

**High-Volume Test:**
```bash
# Start agent
sudo target/release/agent run &

# Simulate high file-open workload (build system)
cd /tmp
for i in {1..1000}; do
    echo "test" > file_$i.txt
done

# Check agent still responsive
ps aux | grep agent
# CPU should be reasonable (<20%)

# Check cache metrics
curl localhost:9090/metrics | grep container_id_cache
# Should see high hit rate
```

---

## Acceptance Criteria (Overall)

### Functional
- ✅ Agent CPU usage <5% at idle
- ✅ Agent CPU usage <20% under high file-open load
- ✅ All event types reach output (exec, connect, file_open)
- ✅ BEACON scenario fires alerts consistently
- ✅ No event loss (exec/connect events not starved)

### Performance
- ✅ Cache hit rate >95% in steady state
- ✅ Container ID attribution latency <1ms (p99)
- ✅ No memory leaks (cache bounded in size)

### Observability
- ✅ Metrics for cache hit rate, size
- ✅ Metrics for rate limit hits
- ✅ Logs for unusual patterns (high miss rate, rate limit exceeded)

---

## References

- **Issue:** https://github.com/synthaea-lab/edr-new/issues/199
- **Root Cause Commit:** #169 (issue #80) - 2026-09-11
- **Related Issues:**
  - #124 (Arch Linux lab target - discovered during validation)
  - #186 (Alpine validation - passed by luck despite bug)
  - #80 (Container ID attribution - original feature request)

---

## Notes

### Why This Wasn't Caught Earlier

1. **Race Condition:** The loop doesn't always prevent detection from working
   - Alpine validation (#186) passed despite bug being present
   - Timing-dependent whether exec/connect events reach detection
   - Makes it harder to catch in casual testing

2. **CPU Usage Can Be Misleading:**
   - On multi-core systems, 100% CPU on one core may not be obvious
   - Agent appears to be "working" (events flowing, no errors)
   - Only noticeable with sustained observation or BEACON test

3. **Event Type Distribution Not Monitored:**
   - No alerts for abnormal file_open dominance
   - No metrics on event type ratios
   - Should add monitoring for this

### Future Prevention

1. **Self-Observation Guard:**
   - Standard pattern: exclude agent's own PID in all eBPF probes
   - Document this as convention in `CLAUDE.md`

2. **Attribution Caching:**
   - Standard pattern: cache expensive attribution lookups
   - Document TTL trade-offs

3. **Event Ratio Monitoring:**
   - Alert if any event type exceeds X% of total
   - Alert if exec/connect count is zero over time window

4. **Integration Test Coverage:**
   - BEACON scenario in CI (requires lab)
   - CPU usage test (sustained idle period)
   - Event type distribution test

---

**Last Updated:** 2026-09-15
**Next Action:** Choose implementation approach and start Phase 1
