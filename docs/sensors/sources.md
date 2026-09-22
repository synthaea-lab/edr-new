# Telemetry Source Inventory

Every observation mechanism each platform offers, with its status here. The rule:
an unused source is a **visible decision with a reason**, never an unknown. Status
is one of: **used** (code on `main`), **built** (code on `main`, runtime
prerequisite outstanding), **planned** (issue filed), **rejected** (deliberate,
reason given). Each platform splits into an *in use / planned* table (what the
signal is, what it detects, what it costs) and a *rejected* table (the reason is
the row).

MITRE tags are the techniques as actually tagged in `crates/rules`/`correlator`,
not aspirational mappings. "Cost & requirements" states privilege and overhead as
this codebase observed them — several rows carry empirical findings that
contradict the documentation.

## Linux

See [linux-telemetry-matrix.md](linux-telemetry-matrix.md) for the full
hook/event/fields/MITRE/overhead/kernel/privilege/OSS-comparison detail behind
each row, including the evaluated-but-not-implemented tier (fanotify, fentry,
SELinux AVC, seccomp, …) and the SELinux-on-server validation gap.

### In use / planned

| Mechanism | Status | Events / signal | MITRE | Cost & requirements | Where / issue |
| --- | --- | --- | --- | --- | --- |
| eBPF tracepoints | used | exec/fork/exit with argv; file open/write/delete/rename/chmod/chown; connect/bind/listen/accept; UDP send | T1059, T1071/T1041, T1105, T1485/T1486 (write/rename bursts), T1070.004, T1222 | Low (ring buffer, in-kernel filters). Root or `CAP_BPF`+`CAP_PERFMON`; 5.10+ practically (CO-RE) | `sensors/linux/ebpf` + `userspace` (#262/#263 phases) |
| eBPF uprobes | used | TLS plaintext (OpenSSL/BoringSSL/GnuTLS `SSL_read`/`SSL_write`), shell readline input | T1071 (pre-encryption C2 visibility), T1059 (interactive shells) | Medium — per-library symbol attach; byte budget + redaction on capture. Root | `sensors/linux/uprobes` (#90) |
| BPF-LSM | used | `file_open` at the security decision point — a deliberate double observation vs. the tracepoint path (blinding check); the io_uring-proof vantage; inline-block ready | T1562 (tamper/evasion context); T1070.006 via `inode_setattr` (planned hook) | Low. 5.7+ (`CONFIG_BPF_LSM`), root. Inline blocking waits on the verdict model | `sensors/linux/lsm` (#91; block: #131/#133) |
| audit netlink | used | Fallback exec + connect where eBPF is unavailable (old kernel, lockdown) — multicast subscribe, coexists with a running `auditd` | T1059, T1071 at degraded fidelity (`parent_lineage: false`, honest) | Higher — userspace parse of the whole stream. `CAP_AUDIT_READ` or root | `sensors/linux/audit` (#34/#247) |
| netlink: sock_diag / conntrack / proc connector | used | Listening-port snapshots (LISTENER-DRIFT), flow 5-tuples + byte counters, process-lifecycle cross-check | T1071/T1041 (beacon volume features), backdoor listeners | Low (10s poll). `sock_diag` confirmed **unprivileged** empirically; proc connector root-only (`EPERM` otherwise) | `sensors/linux/netlink` (#92) |
| journald tail | used | sshd accept/fail, PAM sessions, sudo/su → `Auth`; systemd unit first-start → persistence flag | T1078; T1543.002 (an approximation, documented) | Medium (subprocess + JSON parse, allowlist first). Root in practice — unprivileged `journalctl` can't read auth records on some distros (empirical) | `sensors/linux/journal` (#93) |
| /proc, /sys | used | Startup seeding (`PROC_LINEAGE`, listener baseline) and per-event enrichment (cgroup → container id) | Enrichment only — feeds every technique above | Low; event-triggered reads, never a poll loop over all of `/proc` | `userspace` + container attribution (#80) |
| DNS resolution telemetry | planned | Query/answer joined to the resolving process | T1071.004; DGA/tunneling features | eBPF parse of udp:53 vs. `getaddrinfo` uprobe — mechanism choice in-issue | #267 |
| Injection & fileless-exec syscalls | planned | ptrace operations, `process_vm_*`, `/proc/*/mem` writes, `memfd_create`+exec | T1055, T1620 | New tracepoints on the existing wire | #265 |
| Kernel-surface tamper | planned | `init_module`/`finit_module`/`delete_module`, `bpf(2)` program loads | T1547.006; eBPF-rootkit visibility | Rare events, forward-all | #264 |
| Privilege-change syscalls | planned | `setuid`/`setresuid`/`capset`/`setns` | T1548; container-escape context | | #266 |
| Mount + tamper signals | planned | `mount`/`umount2` → `Mount`; kernel-side kill tracing filtered to agent/security targets → `Signal` — SIGKILL sender attribution that userspace (`kill_loudness`) fundamentally cannot see | T1562; evidence-destroying unmounts | Reuses the v21 platform-neutral variants | #362 |
| Exec environment (allowlist) | planned | `LD_PRELOAD` family + `GLIBC_TUNABLES` at exec, present-only | T1574.006 (loader-level injection) | Allowlist capture, never the whole environment (secrets) | #363 |
| JA4 / TLS metadata + SNI | planned | Client fingerprint + SNI on connect events | T1071 (C2 tooling fingerprints) | | #86 |
| Device telemetry | planned | USB attach/detach + policy enforcement | T1091, T1052 | | `device-control` (#84) |
| Inventory collectors | planned | Diffed asset state (packages, units, cron, …) | Persistence that predates the agent | Snapshot cadence, not events | `inventory` (#87) |

### Rejected

| Mechanism | Why |
| --- | --- |
| custom kernel module | eBPF-only stance: verifier safety, no third-party kernel code |
| ptrace interception | invasive, single-tracer conflicts, evasion tarpit |
| perf hardware counters | rejected (revisit) — niche side-channel detections; cost/benefit unproven |
| AF_PACKET / libpcap full capture | volume without need — conntrack flows (#92) + JA4/SNI (#86) carry the network signal; TLS content is cheaper pre-encryption via uprobes (#90) |
| inotify | coarser than the eBPF file events and fanotify (#34); no process attribution |
| utmp/wtmp/btmp parsing | journald (#93) carries the same logins with provenance |

## Windows

### In use / planned

| Mechanism | Status | Events / signal | MITRE | Cost & requirements | Where / issue |
| --- | --- | --- | --- | --- | --- |
| ETW Kernel-Process | used | Exec with the **real** PEB command line (F-1) and per-event SID + integrity level (F-3); image/DLL load (EID 5) | T1059; T1574.002 (side-loading); lineage for every tree rule | Administrator (kernel-provider session). Session name randomized per start, orphan cleanup + silence watchdog (F-2) | `sensors/windows/etw` (#20/#21) |
| ETW Kernel-Network | used | TCP connect, IPv4 + IPv6 first-class (F-7, connect+send dedup window); UDP send (EID 14, IPv4) | T1071/T1041 (BEACON), T1048; UDP volume for tunneling features | Administrator | `sensors/windows/etw` (#20/#97) |
| ETW Kernel-File | used | File create/write (`NameCreate` EID 12 joined with `CreateNewFile` EID 30, F-6 partial); NT→drive-letter normalization via a real volume map (F-5) | T1105; dropper-chain joins. Full delete/rename semantics arrive with the minifilter (#136) | Administrator | `sensors/windows/etw` |
| ETW DNS-Client | used | Query + answer + status joined to the resolving process (EID 3008; query-started 3006 dropped as noise) | T1071.004; domain-IOC join key | Administrator | `sensors/windows/etw` (#21) |
| ETW Kernel-Registry | used | Value writes (EID 4), NT→`HKLM` path normalization; reads deliberately not taken (volume without value) | T1547.001 (Run keys), T1112 | Administrator | `sensors/windows/etw` (#21) |
| ETW PowerShell | used | Script blocks (EID 4104) **post-decode** — `-EncodedCommand` arrives as plain text; multi-record fragments reassembled by block id | T1059.001, T1027 | Administrator | `sensors/windows/etw` (#21) |
| ETW WMI-Activity | used | WQL queries (EID 23) + method invocations (EID 24, e.g. `Win32_Process.Create`) | T1047; WMI recon | Administrator | `sensors/windows/etw` (#21) |
| ETW DotNETRuntime | used | **Dynamic (in-memory) assembly loads only** (EID 154, `flags & 0x2`) — file-backed loads dropped at the sensor | T1620, T1055 (execute-assembly) | Administrator | `sensors/windows/etw` (#97) |
| ETW SMBClient | used | Outbound SMB connections established (EID 30704; failures dropped) | T1021.002 (lateral movement) | Administrator | `sensors/windows/etw` (#97) |
| Event Log polling | used | Service install 7045, scheduled task 4698, local account 4720 (flag-gated persistence events); logons 4624/4625/4648/4672 → `Auth` | T1543.003, T1053.005, T1136.001, T1078/T1110 | Administrator (Security channel). 2s `wevtutil` poll. Lab-earned (ADR-0004): 7045's classic provider defeats TDH schema resolution, and the Security channel never delivered to an ad-hoc raw-ETW subscriber — `EvtSubscribe` is the evaluated successor | `sensors/windows/eventlog` (#94) |
| WMI/CIM queries | used | Point-in-time inventory | — | Snapshot cadence | `inventory` collectors |
| AMSI ETW | planned | Script/PS/VBS content telemetry | T1059, T1027 | | #282 |
| WEL channel expansion | planned | AppLocker, WDAC, Defender operational, Task-Scheduler operational | Policy-violation + AV-verdict context | | #283 |
| BITS-Client ETW | planned | Background transfer jobs | T1197 | | #284 |
| Terminal Services / RDP session events | planned | Session connect/disconnect/reconnect lifecycle | T1021.001 | | #285 |
| Kerberos / NTLM / LDAP-Client (endpoint side) | planned | Client-side ticket requests (RC4-etype shadow), NTLM validation, LDAP recon bursts — DC-side 4768/4769 stay server-milestone scope, honestly | T1558, T1110; AD recon | | #364 |
| Zone.Identifier ADS (mark-of-the-web) | planned | MotW writes → v21 `FileQuarantine` (`HostUrl`/`ReferrerUrl` read-back); the minifilter supersedes the userland read-back (#136) | T1553.005; download provenance | Userland-now via a Kernel-File suffix match | #365 |
| Socket-table snapshots | planned | `GetExtendedTcpTable` → `ListenPort` + startup baseline — LISTENER-DRIFT does not exist on Windows today | Backdoor listeners | Unprivileged API | #366 |
| Sysmon channel opt-in | planned | ADR-first design decision | — | | #286 |
| Kernel driver tier | planned | Process/image/registry callbacks (#39); ObRegisterCallbacks handle access — the LSASS credential-theft signal (#137); minifilter deletes/renames/pipes/ADS/timestomping/raw-volume (#136); WFP flows + inline block (#138); Threat-Intelligence ETW (#137, needs PPL) | T1003.001, T1055, T1070.006; ransomware primitives | Signed driver, its own distribution tier | `sensors/windows/driver` (#39) |

### Rejected

| Mechanism | Why |
| --- | --- |
| Userland API hooking / detours | stability, AV conflicts, trivially unhookable — ETW + kernel callbacks only |
| Clipboard capture | privacy/noise cost exceeds detection value; commercial norm agrees |
| Raw packet capture (WinPcap/npcap-style) | ETW network + WFP (#138) carry the signal without the driver and volume cost |
| Keystroke / screen capture | privacy line, same reasoning as clipboard |
| Execution-history artifacts (Prefetch, Amcache, Shimcache) | rejected (deferred) — point-in-time forensics, not streaming telemetry; DFIR workbench territory (M10), pulled on demand |

## macOS

### In use / planned

| Mechanism | Status | Events / signal | MITRE | Cost & requirements | Where / issue |
| --- | --- | --- | --- | --- | --- |
| EndpointSecurity core | used | Exec with argv + the kernel's code-signing state at the source (`CS_VALID`, signing/team id); file open/create/rename/unlink; mmap **filtered to writable+shared** (dyld's torrent dropped in-shim); BTM launch-item registration | T1059, T1105, T1485/T1486, T1070.004; T1543.001/.004 + T1547.015 (BTM is the macOS 7045) | Root + ES entitlement + Full Disk Access. **Live-verified**: amfid SIGKILLs an ad-hoc restricted entitlement at exec (error -424), before TCC — Apple grant or SIP+AMFI-relaxed lab only. NOTIFY-only (AUTH blocking is M6). Self-muted against feedback. 10.15+ base, BTM 13+ | `sensors/macos/endpoint-security` (#32; lab: #350) |
| EndpointSecurity widening | used | SSH/console/loginwindow logins → `Auth` (13+); quarantine xattr + `kMDItemWhereFroms` read-back → `FileQuarantine` (the network→file link); mount/unmount; signals **filtered to ES-client targets** (the tamper subset); XPC connects (14+) | T1078; T1553.001 provenance; T1562 tamper | Same as core; per-family availability guards — families newer than the host are skipped at subscribe time | `sensors/macos/endpoint-security` (#96) |
| Unified log | used | sudo outcomes → `Auth`; TCC grant/deny pairs joined on tccd's msgID → `TccDecision`; Gatekeeper scan verdicts → `GatekeeperVerdict` (Mach-O scans only — a script assessment logs `performScan` without a verdict, observed live) | T1548.003; TCC-probing recon; Gatekeeper context on delivery | Admin scope for `log stream`. Three volume gates: daemon-side predicate, exact-message classifier, counted sliding-window shed. Formats undocumented by Apple — pinned by verbatim live-capture tests (the OS-update tripwire). Live-validated end to end | `sensors/macos/unifiedlog` (#95; client attribution: #354) |
| NetworkExtension: filter-data + DNS-proxy | built | Flows with audit-token process attribution (inbound + outbound) → `Connect`, close-time byte counts → `NetworkFlow`; proxied DNS → `DnsQuery` — BEACON consumes macOS flows unchanged | T1071/T1041; domain↔process join | Swift system extension: restricted entitlements + user/MDM approval (`packaging/macos`); versioned NDJSON wire, skew counted never guessed. Agent seam + typed scaffold on `main`; activation + beacon validation outstanding | `sensors/macos/network-extension` (#33; build/lab: #351; wire v2: #353) |
| ES injection/tamper proc events | planned | Task-port acquisition, ptrace, remote thread creation, CS invalidation, suspend/resume, RWX mprotect, pty | T1055, T1562 | The coverage-matrix promise #32/#96 only partially landed | #355 |
| ES security-subsystem events | planned | XProtect verdicts, Gatekeeper user override, native TCC modify (15.4+), OD account manipulation, profile installs, native su/sudo, screen sharing | T1136.001, T1553; OS-verdict context for free | Rare, forward-all; per-family OS gates | #356 |
| ES anti-forensics & file-op completeness | planned | Quarantine **strip** (`DELETEEXTATTR`), timestomp (`UTIMES`/`SETATTRLIST`), hidden flags, APFS clone/exchangedata staging, kext loads, sensitive IOKit opens, remount, unix sockets | T1070.006, T1564.001 | Source-side filters per row | #357 |
| Socket-table snapshots | planned | libproc/sysctl walk → `ListenPort` + startup baseline — **needs no entitlement**, works before any Apple grant | Backdoor listeners; LISTENER-DRIFT parity | Unprivileged | #358 |
| Inventory collectors | planned | Pre-existing launch items, kexts/system extensions, profiles, the standing TCC-grant map, browser artifacts | Persistence that predates the agent | FDA for the TCC.db snapshot | `inventory` (#359) |
| NE TLS SNI / JA4 | planned | ClientHello peek on filter-data flows | T1071 fingerprints — Linux #86 parity | Rides the extension (#351) + wire v2 (#353) | #360 |
| DiskArbitration / IOKit notifications | planned | Device attach/detach | T1091, T1052 | | `device-control` |

### Rejected

| Mechanism | Why |
| --- | --- |
| ES read-side metadata events (stat, lookup, getattrlist, readdir, access, …) | pure volume without mutation — nothing a detection keys on that the write-side events don't already carry |
| NetworkExtension packet-tunnel provider | rejected (revisit) — full-packet capture is cost without need given filter-data + DNS |
| kexts / kauth | deprecated and disallowed by Apple |
| openbsm audit trail | deprecated; ES supersedes |
| FSEvents | coarser than ES file events; no attribution |

Cross-platform note: download provenance is one shape on all three platforms —
Windows mark-of-the-web (#365), the macOS quarantine xattr (shipped, #96), and
browser artifacts via `inventory` — all feeding the platform-neutral
`FileQuarantine` event: the provenance link between a network event and a
dropped file.
