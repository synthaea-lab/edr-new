# Telemetry Source Inventory

Every observation mechanism each platform offers, with its status here. The rule:
an unused source is a **visible decision with a reason**, never an unknown. Status
is one of: **used** (code exists/planned in an issue), **planned** (crate drafted,
issue filed), **rejected** (deliberate, reason given).

## Linux

| Mechanism | Status | Where / why |
| --- | --- | --- |
| eBPF tracepoints/kprobes | used | `sensors/linux/ebpf` + `userspace` |
| eBPF uprobes (TLS plaintext, readline) | planned | `sensors/linux/uprobes` |
| BPF-LSM hooks (io_uring-proof observation + inline blocking; timestomping via utimensat/inode_setattr) | planned | `sensors/linux/lsm` |
| audit netlink + fanotify | planned | `sensors/linux/audit` (fallback, #34) |
| netlink: sock_diag / conntrack / proc connector | planned | `sensors/linux/netlink` |
| journald (auth, service lifecycle) | planned | `sensors/linux/journal` |
| /proc, /sys polling | used | seeding + fallbacks only |
| custom kernel module | **rejected** | eBPF-only stance: verifier safety, no third-party kernel code |
| ptrace interception | **rejected** | invasive, single-tracer conflicts, evasion tarpit |
| perf hardware counters | rejected (revisit) | niche side-channel detections; cost/benefit unproven |

## Windows

| Mechanism | Status | Where / why |
| --- | --- | --- |
| ETW kernel providers (Process/File/Network) | used | `sensors/windows/etw` |
| ETW expansion (Registry, DNS, image load, AMSI, PowerShell, WMI) | planned | #21 |
| ETW: DotNETRuntime (in-memory assemblies), SMB/RPC/TCPIP | planned | #97 |
| Windows Event Log channels (EvtSubscribe) | planned | `sensors/windows/eventlog` (#94) |
| Kernel callbacks: process/image/registry (driver) | planned | `sensors/windows/driver` |
| ObRegisterCallbacks — handle access (LSASS credential-theft signal) | planned | #137 (on driver #39) |
| Minifilter (file deletes/renames/pipes, timestomping via SetInformation, Alternate Data Streams, raw volume access) | planned | #136 (on driver #39) |
| WFP (network filtering + inline block) | planned | #138 (on driver #39) |
| Threat-Intelligence ETW (injection; needs PPL) | planned | #137 (on driver #39) |
| WMI/CIM queries | used (inventory) | `inventory` collectors |
| Userland API hooking / detours | **rejected** | stability, AV conflicts, trivially unhookable — ETW + kernel callbacks only |
| Clipboard capture | **rejected** | privacy/noise cost exceeds detection value; commercial norm agrees |

## macOS

| Mechanism | Status | Where / why |
| --- | --- | --- |
| EndpointSecurity (core events) | planned | `sensors/macos/endpoint-security` (#32) |
| ES catalog widening (login/lw_session/OpenSSH, xattr/quarantine, mount, signal, XPC) | planned | #96 |
| NetworkExtension: filter-data + DNS-proxy | planned | `sensors/macos/network-extension` |
| NetworkExtension: packet-tunnel provider | rejected (revisit) | full-packet capture is cost without need given filter-data + DNS |
| Unified log (OSLog predicates) | planned | `sensors/macos/unifiedlog` |
| DiskArbitration / IOKit device notifications | planned | `device-control` |
| kexts / kauth | **rejected** | deprecated and disallowed by Apple |
| openbsm audit trail | **rejected** | deprecated; ES supersedes |
| FSEvents | **rejected** | coarser than ES file events; no attribution |

Cross-platform note: download provenance (mark-of-the-web on Windows, quarantine
xattr on macOS via the ES `xattr` widening, browser artifacts via `inventory`) is
tracked with the ES-widening and eventlog issues — the provenance link between a
network event and a dropped file.
