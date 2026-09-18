# ADR-0014: Self-protection vs. hiding — which malware-style techniques we adopt

- **Status**: accepted
- **Date**: 2026-09-18

## Context

Issue #104 asked a focused question: adversaries routinely try to kill or blind the
endpoint agent as step one of an intrusion, and malware has a well-catalogued set of
persistence/self-protection/anti-tamper techniques for surviving removal. Some of those
same technique *classes* are legitimate for a consented, admin-installed security agent
to use on itself. Some cross into rootkit territory — hiding from the very operator who
installed the agent — and must be refused regardless of how effective they'd be.

This ADR is the record of that line, decided *after* shipping the concrete
self-protection work the survey needed to be grounded in rather than speculative:
`tamper` (heartbeat, integrity primitives), watchdog install-surface hardening and
binary pinning (#103), and the agent's sensor-silence detection, protected-resource
monitoring, and kill-loudness (#71). `docs/architecture/threat-model.md` is the living
document for *how* each shipped control works; this ADR is *why* each technique class
was in or out of scope in the first place, so the answer is on record rather than
implied by what happened to get built.

The trust boundary from the threat model applies here unchanged: we design for an
adversary with administrator/root but not ring-0. A kernel-mode adversary defeats any
user-mode control, ours included — that ceiling is named, not hidden, and only moves
with the kernel-floor milestones (#39 Windows driver/PPL/ELAM, #91 Linux BPF-LSM, macOS
System Extensions).

## Decision

Five technique classes, each classified **adopt / reject / defer**, mapped to
MITRE ATT&CK where a mapping exists:

### 1. Persistence redundancy (T1547, T1543) — **Adopt**

Multiple independent restart anchors, so removing one doesn't disable protection.
Already shipped and load-bearing: the agent and watchdog mutually supervise each other
(`PR_SET_PDEATHSIG`, #216) *and* the OS service manager restarts the watchdog
independently (`systemd Restart=always` / SCM `sc failure` / launchd `KeepAlive`) — two
layers, neither a single point of failure. The line that keeps this out of malware
territory: every restart anchor is a **declared, admin-visible service unit**, not a
hidden scheduled task or registry run key planted without the operator's knowledge.
`systemctl status`/`sc query`/`launchctl list` shows exactly what's supervising what.

### 2. Process/service protection (PPL, ES system extension, hardened unit) — **Adopt**

Overlaps tamper resistance directly. Already shipped on Linux: `watchdog::tamper`
(#103) refuses to install into a world-writable directory, hardens the installed
binaries'/unit file's permissions, hash-pins the running agent binary and re-verifies it
every supervise-loop tick, and detects service-definition drift (content or
enabled-state) against a snapshot taken at install time. Windows PPL and the macOS
System Extension equivalents are **the same decision, deferred on implementation**
(they need the kernel-floor milestone #39, not a different verdict) — adopted in
principle now, shipped per-platform as each milestone lands.

### 3. Watchdog mutual-guard — **Adopt, conditioned on staying observable**

A pattern shared with malware "guardian" threads: two cooperating processes that
restart each other. The technique itself is neutral; what makes it legitimate here is
that every restart is **logged, not concealed** — the watchdog's supervise loop prints
and records every exit/respawn cycle, backoff decisions are visible
(`ExitClass::FastCrash` vs. `Healthy`), and #71's kill-loudness now additionally
attributes *who* triggered a termination attempt before the process dies. A guardian
pattern that hid its own restarts from the process list or system logs would fail this
condition and move to reject — we did not build one.

### 4. Anti-tamper hooks / self-defense drivers — **Defer**

Kernel callbacks blocking `OpenProcess`/kill on the agent is powerful and legitimate in
principle (this is exactly what Windows PPL *is* — a kernel-enforced "you cannot
terminate this, but it is still fully visible in Task Manager" guarantee, not
concealment). It is high-privilege, high-risk to get wrong, and explicitly the
kernel-floor milestone's job (#39), not something to bolt on ad hoc from user mode.
Deferred, not rejected: the goal (prevent, don't just detect) is accepted; the
implementation waits for the milestone built to do it safely.

### 5. Hiding from enumeration (hooking, DKOM, unlinking from the process list, hidden
files, rootkit techniques) — **Reject**

Rejected outright, independent of effectiveness. A defensive agent must stay visible
and auditable to the machine owner: hiding from the operator is indistinguishable from
malware, breaks the trust the whole product depends on, trips other AV/EDR heuristics
(which correctly flag hiding behavior regardless of intent), and defeats incident
response — a responder who cannot see the agent cannot reason about the box it's
running on. Explicitly out of scope for the same reason: evasion of other security
products, detection-avoidance, or anything that makes the agent's presence deniable to
the machine owner. Every self-protection control shipped so far (#71, #103) makes a
tampering *attempt* loud and attributable; none of them make the *agent* harder to see.

## Consequences

- **What becomes easier:** the line is decidable per-technique going forward without
  relitigating first principles — "does this make an attack on the agent loud, or does
  it make the agent quiet" answers most future proposals. Persistence redundancy,
  process protection, and mutual-guarding are pre-approved patterns; anything that
  reduces the agent's visibility to its own operator is pre-rejected.
- **What becomes harder:** we accept a real ceiling — a same-privilege adversary can
  still momentarily kill or suspend the agent (the kill-both-fast race in
  `threat-model.md`), and we deliberately do not close that gap with concealment. The
  bet is that attribution + fleet visibility is the correct trade against a same-tier
  adversary, and that only ring-0 (#39, #91) legitimately closes the rest.
- **What we committed to:** every future self-protection proposal gets checked against
  this ADR before it ships, not just against "does it work." Concrete adopt items are
  linked here rather than re-surveyed: persistence redundancy and the watchdog
  mutual-guard (#216, #102), process/service protection and tamper resistance (#103),
  sensor-silence/protected-resource/kill-loudness (#71). Anti-tamper hooks stay tracked
  under the kernel-floor milestone (#39) rather than getting their own issue.
