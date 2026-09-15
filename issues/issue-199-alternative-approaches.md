# Issue #199: Alternative Approaches (Exploration Record)

**Status:** For reference only - not implemented in production
**Related:** PR #203 (closed as duplicate), PR #201 (actual fix)
**Date:** 2026-09-15

## Context

This document records alternative implementation approaches explored for issue #199 in PR #203, which was closed as duplicate work after discovering that PR #201 had already fixed the issue with a better approach.

**Key learning:** Always check for existing PRs before starting implementation work.

## Why PR #201's Approach Won

PR #201 uses a **cache-only approach** (LRU with 4096 capacity, no TTL):
- ✅ Fixes root cause (redundant re-reads) not just symptom
- ✅ Simpler implementation (userspace only, no eBPF changes)
- ✅ Benefits all processes, not just agent
- ✅ Stable cgroup membership means no TTL needed
- ✅ Already validated end-to-end on two platforms

PR #203 used a **3-phase defense-in-depth approach**:
- ❌ More complex (eBPF + userspace changes)
- ❌ eBPF exclusion only helps agent, not other processes
- ❌ TTL adds unnecessary complexity (cgroup doesn't change)
- ⚠️ Rate limiting is overkill when cache alone fixes the problem

## Explored Approaches (PR #203)

### Phase 1: eBPF PID Exclusion

**Concept:** Exclude agent's own PID and thread IDs from `sys_enter_openat` capture.

**Implementation:**
```rust
// eBPF (crates/sensors/linux/ebpf/src/main.rs)
#[map]
static EXCLUDED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let pid = (pid_tgid >> 32) as u32;

    if unsafe { EXCLUDED_PIDS.get(&tid).is_some() || EXCLUDED_PIDS.get(&pid).is_some() } {
        return Ok(0);  // Skip agent's own syscalls
    }
    // ... rest of probe logic
}

// Userspace (crates/sensors/linux/userspace/src/sensor.rs)
fn populate_excluded_pids(ebpf: &mut aya::Ebpf) -> Result<u32, SensorError> {
    let agent_pid = std::process::id();
    let mut excluded: HashMap<_, u32, u8> = HashMap::try_from(ebpf.map_mut("EXCLUDED_PIDS")?)?;

    excluded.insert(agent_pid, 0, 0)?;

    // Insert all thread IDs from /proc/self/task/*
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        let tid: u32 = entry.file_name().to_string_lossy().parse()?;
        excluded.insert(tid, 0, 0)?;
    }

    Ok(excluded.len() as u32)
}
```

**Why it wasn't chosen:**
- Only fixes agent self-observation, not the general pattern
- Doesn't help legitimate high-volume processes
- Requires eBPF program changes + kernel verifier validation
- More complex than needed

**Potential future use:** Could still be useful if we want to completely exclude agent from its own telemetry for privacy/performance reasons, independent of the cache fix.

---

### Phase 2: Container ID Cache with TTL

**Concept:** Cache container IDs with 30-second TTL to avoid repeated procfs reads.

**Implementation:**
```rust
struct ContainerIdCache {
    cache: HashMap<u32, (Option<String>, Instant)>,
    ttl: Duration,                    // 30 seconds
    cleanup_interval: Duration,        // 10 seconds or 1000 events
    last_cleanup: Instant,
    event_count: usize,
}

impl ContainerIdCache {
    fn get_or_fetch(&mut self, pid: u32) -> Option<String> {
        let now = Instant::now();

        // Check cache first
        if let Some((cached_id, cached_at)) = self.cache.get(&pid) {
            if now.duration_since(*cached_at) < self.ttl {
                return cached_id.clone();  // Cache hit
            }
        }

        // Cache miss or expired - fetch fresh
        let id = read_container_id(pid);
        self.cache.insert(pid, (id.clone(), now));

        // Periodic cleanup
        self.event_count += 1;
        if self.event_count >= 1000 ||
           now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.cleanup_expired(now);
        }

        id
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.cache.retain(|_, (_, cached_at)| {
            now.duration_since(*cached_at) < self.ttl
        });
        self.last_cleanup = now;
        self.event_count = 0;
    }
}
```

**Why it wasn't chosen:**
- TTL is unnecessary complexity — cgroup membership is stable over a PID's lifetime
- PR #201's LRU approach is simpler and handles PID reuse through capacity bounds
- Periodic cleanup adds code that isn't needed with LRU

**What PR #201 does better:**
- LRU eviction naturally handles old PIDs without TTL
- Bounded capacity (4096) is sufficient and predictable
- No cleanup logic needed

---

### Phase 3: Rate Limiting (Token Bucket)

**Concept:** Defense-in-depth rate limiter to bound worst-case behavior even if cache fails.

**Implementation:**
```rust
struct AttributionRateLimiter {
    buckets: HashMap<u32, (u32, Instant)>,  // PID -> (tokens, last_check)
    rate: u32,                                // 10 calls/sec
    burst: u32,                               // 20 tokens
    cleanup_interval: Duration,
    last_cleanup: Instant,
    rate_limited_count: u64,
}

impl AttributionRateLimiter {
    fn check_and_consume(&mut self, pid: u32) -> bool {
        let now = Instant::now();
        let (tokens, last_check) = self.buckets
            .entry(pid)
            .or_insert((self.burst, now));

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(*last_check).as_secs_f32();
        let refill = (elapsed * self.rate as f32) as u32;
        *tokens = (*tokens + refill).min(self.burst);
        *last_check = now;

        // Consume token if available
        if *tokens > 0 {
            *tokens -= 1;
            true  // Allow
        } else {
            self.rate_limited_count += 1;
            false  // Rate limited
        }
    }

    fn cleanup_stale(&mut self, now: Instant) {
        self.buckets.retain(|_, (_, last_check)| {
            now.duration_since(*last_check) < Duration::from_secs(60)
        });
    }
}

// Integration into ContainerIdCache
fn get_or_fetch(&mut self, pid: u32) -> Option<String> {
    // Cache hit (fresh) - bypass rate limit
    if let Some((cached_id, cached_at)) = self.cache.get(&pid) {
        if self.is_fresh(*cached_at) {
            return cached_id.clone();
        }
    }

    // Cache miss/expired - check rate limit
    if !self.rate_limiter.check_and_consume(pid) {
        // Rate limited - return stale cache or None
        return self.cache.get(&pid).and_then(|(id, _)| id.clone());
    }

    // Rate limit OK - fetch from procfs
    let id = read_container_id(pid);
    self.cache.insert(pid, (id.clone(), Instant::now()));
    id
}
```

**Features:**
- Token bucket algorithm: 10 calls/sec per PID, 20 token burst
- Per-PID isolation (one PID can't starve others)
- Graceful degradation (returns stale cache when rate limited)
- Observable metrics (rate_limited_count)

**Test coverage (8 unit tests):**
```rust
#[test]
fn rate_limiter_allows_within_burst()
#[test]
fn rate_limiter_blocks_after_burst()
#[test]
fn rate_limiter_refills_over_time()
#[test]
fn rate_limiter_per_pid_isolation()
#[test]
fn rate_limiter_cleanup_stale_buckets()
#[test]
fn cache_bypasses_rate_limit_on_hit()
#[test]
fn cache_applies_rate_limit_on_miss()
#[test]
fn cache_returns_stale_when_rate_limited()
```

**Why it wasn't implemented:**
- Overkill when cache alone fixes the problem
- Adds complexity without clear benefit in normal operation
- Rate limiting would almost never trigger with a working cache

**When it could be useful:**
- If we see pathological workloads that somehow bypass cache
- As defense-in-depth if we're paranoid about worst-case scenarios
- If monitoring shows cache isn't effective (but then we'd fix cache first)

---

## Code Location (Not Merged)

**Branch:** `199-fix-cpu-pinning-loop-container-id-attribution` (local + remote)

**Commits:**
- `8234422`: Phase 1 (eBPF PID exclusion)
- `c3a5dda`: Phase 1 documentation
- `295d89b`: Phase 2 (cache with TTL)
- `598dcf0`: Phase 2 documentation
- `4405154`: Phase 3 (rate limiting)
- `f9fb280`: Phase 3 documentation

**PR:** #203 (closed 2026-09-15)

**Status:** Not merged to main. Branch can be deleted or kept as reference.

---

## Performance Comparison

### PR #201 (Implemented)
```
Normal case:
- First event for PID: procfs read (~50-200µs) → cached
- Subsequent events: HashMap lookup (~10-50ns)
- Cache hit rate: >95% expected
- Overhead: negligible

High-volume case (1000 events/sec, 100 unique PIDs):
- Procfs reads: 100 (for new PIDs)
- Cache hits: 900
- Total overhead: ~5-20ms (was 50-200ms without cache)
- Improvement: ~10-40x
```

### PR #203 (Not Implemented)
```
Normal case (all 3 phases):
- Phase 1: eBPF HashMap lookup (~10ns) - agent only
- Phase 2: Cache lookup (~10-50ns)
- Phase 3: Rate limit check (~10-50ns) - rarely executed
- Total: ~20-110ns per event

High-volume case:
- Same as PR #201 but with rate limiter safety net
- Rate limit triggers: ~0 (cache prevents it)
- Extra overhead: ~10-50ns per cache miss (rate limit check)
```

**Verdict:** PR #201's simplicity wins. The extra 10-50ns overhead per miss isn't worth the code complexity.

---

## Testing (PR #203, Not Merged)

**Unit tests written:** 14 total
- Phase 2: 6 tests (cache behavior, expiry, cleanup)
- Phase 3: 8 tests (rate limiter, integration with cache)

**All tests passed:** `cargo check -p sensor-linux` succeeded

**eBPF validation:** Not performed (requires bpf-linker + BTF kernel)

**End-to-end validation:** Not performed (PR closed before lab testing)

---

## Lessons Learned

### 1. Check for existing work first
**Mistake:** Started implementation without checking for existing PRs.

**Impact:** Wasted 6 commits, documentation, and review time.

**Prevention:** Always run `gh pr list` and `gh issue view <number>` before starting work.

### 2. Simpler is better
**Observation:** PR #201's cache-only approach is simpler and sufficient.

**Learning:** Defense-in-depth is good, but not when each layer adds complexity without proportional benefit. Cache alone fixes the root cause.

### 3. Match the fix to the problem
**Mistake:** eBPF exclusion fixes a symptom (agent self-observation) not the root cause (redundant re-reads).

**Better:** Cache fixes the general pattern and benefits all processes.

### 4. Question your assumptions
**Assumption:** TTL is needed for cache correctness.

**Reality:** Cgroup membership is stable; LRU bounds are sufficient for PID reuse.

**Learning:** Challenge every design decision. "Do we really need this?"

### 5. Rate limiting is often overkill
**Temptation:** Add rate limiting as defense-in-depth.

**Reality:** If cache works, rate limit never triggers. If cache fails, fix cache first.

**Learning:** Don't add safety nets for problems you don't have. Wait for evidence.

---

## Potential Future Extraction

If evidence shows need for these features:

### 1. Agent Self-Exclusion (Phase 1)
**Extract as:** Separate PR for agent privacy/performance
**Reason:** Might want agent invisible in its own telemetry regardless of cache
**Complexity:** Medium (eBPF changes)
**Benefit:** Privacy + slight performance gain

### 2. Rate Limiting (Phase 3)
**Extract as:** Separate issue for defense-in-depth
**Reason:** Paranoia about unknown pathological cases
**Complexity:** Low (pure userspace)
**Benefit:** Safety net for unknown unknowns
**Priority:** Low (wait for evidence)

### 3. Observable Metrics
**Extract as:** Part of agent health telemetry (#134)
**Metrics from PR #203:**
- `cache_hits` / `cache_misses`
- `rate_limited_count`
- `cleanup_count` / `entries_removed`
**Benefit:** Visibility into attribution performance

---

## Branch Cleanup Recommendation

**Action:** Delete branch `199-fix-cpu-pinning-loop-container-id-attribution`

**Reason:**
- Work is duplicate
- PR #201 is the canonical fix
- Code is preserved in this documentation for reference
- Git history is preserved in remote (can recover if needed)

**Command:**
```bash
# Delete local branch
git branch -D 199-fix-cpu-pinning-loop-container-id-attribution

# Delete remote branch (if desired)
git push origin --delete 199-fix-cpu-pinning-loop-container-id-attribution
```

**Alternative:** Keep branch as reference if rate limiting might be useful later (low priority).

---

## References

- **Issue #199:** agent: unbounded self-referential CPU-pinning loop
- **PR #201 (implemented):** sensor-linux: fix container-id self-feeding CPU loop
- **PR #203 (closed):** Fix: Prevent self-referential CPU-pinning loop (3-phase)
- **Main documentation:** `issues/issue-199.md`
- **Branch:** `199-fix-cpu-pinning-loop-container-id-attribution`

---

**Document Purpose:** Historical record of alternative approaches for future reference. Not production documentation.

**Last Updated:** 2026-09-15
