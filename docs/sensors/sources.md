# Telemetry Source Inventory

Every observation mechanism each platform offers, with its status here. The rule:
an unused source is a **visible decision with a reason**, never an unknown. Status
is one of: **used** (code exists/planned in an issue), **planned** (crate drafted,
issue filed), **rejected** (deliberate, reason given).

## Linux

See [linux-telemetry-matrix.md](linux-telemetry-matrix.md) for the full
hook/event/fields/MITRE/overhead/kernel/privilege/OSS-comparison detail behind
each row below.

| Mechanism | Status | Where / why |
| --- | --- | --- |
| eBPF tracepoints/kprobes | used | `sensors/linux/ebpf` + `userspace` |
| eBPF uprobes (TLS plaintext, readline) | planned | `sensors/linux/uprobes` |
| BPF-LSM hooks (io_uring-proof observation + inline blocking; timestomping via utimensat/inode_setattr) | planned | `sensors/linux/lsm` |
| audit netlink + fanotify | planned | `sensors/linux/audit` (fallback, #34) |
| netlink: sock_diag / conntrack / proc connector | planned | `sensors/linux/netlink` |
| journald (auth, service lifecycle) | planned | `sensors/linux/journal` |
| /proc, /sys polling | used | seeding + fallbacks only |
| mount/umount + tamper-signal syscalls | planned | #362 — Linux feed for the platform-neutral v21 `Mount`/`Signal` events; SIGKILL sender attribution kill_loudness can't see |
| exec environment (LD_PRELOAD family, allowlist) | planned | #363 — loader-level injection; #265 covers the syscall-level primitives |
| custom kernel module | **rejected** | eBPF-only stance: verifier safety, no third-party kernel code |
| ptrace interception | **rejected** | invasive, single-tracer conflicts, evasion tarpit |
| perf hardware counters | rejected (revisit) | niche side-channel detections; cost/benefit unproven |
| AF_PACKET / libpcap full capture | **rejected** | volume without need — conntrack flows (#92) + JA4/SNI (#86) carry the network signal |
| inotify | **rejected** | coarser than the eBPF file events and fanotify (#34); no attribution |
| utmp/wtmp/btmp parsing | **rejected** | journald (#93) carries the same logins with provenance |

## Windows

| Mechanism | Status | Where / why |
| --- | --- | --- |
| ETW kernel providers (Process/File/Network) | used | `sensors/windows/etw` |
| ETW expansion (Registry, DNS, image load, AMSI, PowerShell, WMI) | planned | #21 |
| ETW: DotNETRuntime (in-memory assemblies), SMB/RPC/TCPIP | planned | #97 |
| Windows Event Log channels (`wevtutil` polling — `EvtSubscribe` evaluation still pending, see ADR-0004) | used | `sensors/windows/eventlog` (#94) |
| Kernel callbacks: process/image/registry (driver) | planned | `sensors/windows/driver` |
| ObRegisterCallbacks — handle access (LSASS credential-theft signal) | planned | #137 (on driver #39) |
| Minifilter (file deletes/renames/pipes, timestomping via SetInformation, Alternate Data Streams, raw volume access) | planned | #136 (on driver #39) |
| WFP (network filtering + inline block) | planned | #138 (on driver #39) |
| Threat-Intelligence ETW (injection; needs PPL) | planned | #137 (on driver #39) |
| Kerberos / NTLM / LDAP-Client telemetry (endpoint side) | planned | #364 — credential-attack + AD-recon shadow visible from the endpoint; DC-side events stay server-milestone scope |
| Zone.Identifier ADS (mark-of-the-web) | planned | #365 — Windows feed for the platform-neutral v21 `FileQuarantine`; #136's minifilter supersedes the userland read-back |
| Socket-table snapshots (GetExtendedTcpTable) | planned | #366 — sibling of `sensors/linux/netlink` (#92) and macOS #358; the missing LISTENER-DRIFT source |
| WMI/CIM queries | used (inventory) | `inventory` collectors |
| Userland API hooking / detours | **rejected** | stability, AV conflicts, trivially unhookable — ETW + kernel callbacks only |
| Clipboard capture | **rejected** | privacy/noise cost exceeds detection value; commercial norm agrees |
| Raw packet capture (WinPcap/npcap-style) | **rejected** | ETW network + WFP (#138) carry the signal without the driver and volume cost |
| Keystroke / screen capture | **rejected** | privacy line, same reasoning as clipboard |
| Execution-history artifacts (Prefetch, Amcache, Shimcache) | rejected (deferred) | point-in-time forensics, not streaming telemetry — DFIR workbench territory (M10), pulled on demand, not shipped continuously |

## macOS

| Mechanism | Status | Where / why |
| --- | --- | --- |
| EndpointSecurity (core events: exec, file, BTM launch items) | used | `sensors/macos/endpoint-security` (#32) |
| ES catalog widening (login/lw_session/OpenSSH, xattr/quarantine, mount, signal, XPC) | used | `sensors/macos/endpoint-security` (#96) |
| ES injection/tamper proc events (task ports, ptrace, remote threads, CS invalidation, mprotect, pty) | planned | #355 — the coverage-matrix promise #32/#96 only partially landed |
| ES security-subsystem events (XProtect verdicts, Gatekeeper override, TCC modify, OD accounts, profiles, native su/sudo, screen sharing) | planned | #356 |
| ES anti-forensics & file-op completeness (quarantine strip, timestomp, hidden flags, clone/exchangedata, kext/IOKit open, remount, unix sockets) | planned | #357 |
| ES read-side metadata events (stat, lookup, getattrlist, readdir, access, fsgetpath, dup, fcntl, chdir, ...) | **rejected** | pure volume without mutation — nothing a detection keys on that the write-side events don't already carry |
| NetworkExtension: filter-data + DNS-proxy | built (#33 — agent seam + typed extension scaffold; extension build/activation + beacon lab validation is #351, see `packaging/macos`) | `sensors/macos/network-extension` |
| NetworkExtension: TLS SNI / JA4 via filter payload peek | planned | #360 — macOS sibling of Linux #86; packet capture stays rejected |
| NetworkExtension: packet-tunnel provider | rejected (revisit) | full-packet capture is cost without need given filter-data + DNS |
| Socket-table snapshots (libproc / sysctl pcblist) | planned | #358 — sibling of `sensors/linux/netlink` (#92); the one source needing no entitlement |
| Unified log (OSLog predicates: sudo auth, TCC decisions, Gatekeeper verdicts) | used | `sensors/macos/unifiedlog` (#95); requesting-client attribution is #354 |
| Inventory collectors (launch items, kexts, profiles, TCC grants, browser artifacts) | planned | `inventory` (#359) |
| DiskArbitration / IOKit device notifications | planned | `device-control` |
| kexts / kauth | **rejected** | deprecated and disallowed by Apple |
| openbsm audit trail | **rejected** | deprecated; ES supersedes |
| FSEvents | **rejected** | coarser than ES file events; no attribution |

Cross-platform note: download provenance (mark-of-the-web on Windows, quarantine
xattr on macOS via the ES `xattr` widening, browser artifacts via `inventory`) is
tracked with the ES-widening and eventlog issues — the provenance link between a
network event and a dropped file.
