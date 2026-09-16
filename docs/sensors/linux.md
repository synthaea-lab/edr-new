# Linux Sensor

eBPF probe design (tracepoints/kprobes), ring buffers, userspace loader, kernel version
support matrix, and GPLv2 licensing boundary.

Container coverage position: containerized workloads (Docker/containerd) share the
host kernel, so the eBPF sensor already observes their execs/connects/file writes —
detection works on container activity today. What container *support* adds is
context (container id + image attribution via cgroups, overlayfs path normalization)
and container-aware content — not a separate container-security product; deep
container runtime security (Falco's territory) and Kubernetes context remain
explicitly out of scope until after v1.

**Status (issue #80):** Attribution foundation landed — `EventMeta::container`
(`ContainerContext.id`) is resolved on every exec/file-open/connect event from
`/proc/<pid>/cgroup` (cgroup v1 `/docker/<id>` and v2 `docker-<id>.scope` /
`cri-containerd-<id>.scope` naming both handled; Kubernetes' `kubepods` nesting is
transparent to the same matching, its pod/namespace context is not extracted).
`image`/`name` are always `None` for now — they need a cached Docker/containerd
socket lookup, deferred to a follow-up PR. Overlayfs path normalization and the
container-aware content (docker-exec lineage, docker.sock mount, privileged-escape
indicators) are also follow-ups; none of the three "Done when" lab-validation items
on #80 are closed by this foundation alone.

**Status (issue #91, BPF-LSM):** Observation-only foundation landed —
`crates/sensors/linux/lsm` loads/attaches the `file_open` LSM hook (compiled into the
same eBPF object as the tracepoint probes) and counts hits, proving the hook fires
regardless of entry path. It never denies (`-EPERM` inline blocking needs a verdict
from `crates/response`/`crates/policy`, which don't exist yet — issues #131, #133).
`bprm_check`/`socket_connect` hooks, a real event feed from this path (vs. the
tracepoint-sourced one), and all three lab-validated "Done when" items on #91 are
follow-ups — this machine has no way to validate a real attach (root needed, and no
confirmation "bpf" is a registered LSM here even though the BTF type is present).

**Status (issue #92, netlink sensors):** Foundation landed for all three —
`crates/sensors/linux/netlink` queries TCP listening/established sockets (IPv4 + IPv6)
via a hand-rolled `NETLINK_SOCK_DIAG` client, joined to owning PID(s) via a `/proc` fd
scan (the same technique `ss`/`lsof` use); verified unprivileged against this dev
machine's real kernel — no root needed for `sock_diag`, confirmed empirically.
`dump_conntrack()` (`NETLINK_NETFILTER`/`ctnetlink`) decodes the kernel's conntrack
table (IPv4 + IPv6): both directions' 5-tuple, status, timeout, and packet/byte
accounting when the kernel provides it — the recursive `nlattr` tree this needed
(`CTA_TUPLE_ORIG` -> `CTA_TUPLE_IP` -> `CTA_IP_V4_SRC`) is what made conntrack "a
distinct netlink sub-protocol" rather than a `sock_diag`-sized job, confirmed against a
real capture on this dev machine byte for byte before being pinned into tests.
Accounting requires `net.netfilter.nf_conntrack_acct=1` on the target kernel — off by
default, confirmed empirically (no `CTA_COUNTERS_*` attribute appears at all until it
is turned on). Unprivileged reachability of conntrack is not characterized (every
capture here ran as root). `CTA_PROTOINFO`'s TCP state (`CTA_PROTOINFO_TCP` ->
`CTA_PROTOINFO_TCP_STATE`) is now decoded too — a third level of `nlattr` nesting,
only present for TCP flows (confirmed empirically: UDP dump entries carry no
`CTA_PROTOINFO` attribute at all). The sibling wscale/flags sub-attributes are decoded
on the wire but not surfaced, same scoping call as `CTA_STATUS`'s individual bits.
`ProcEventSubscription` (`NETLINK_CONNECTOR`, `CN_IDX_PROC` group) decodes live
fork/exec/exit broadcasts — root/`CAP_NET_ADMIN`-only, confirmed against this dev
machine (the kernel rejects an unprivileged subscribe with `EPERM`, reported back as a
`NetlinkError`, not a panic); verified end to end against the real kernel as root.

**Status (issue #92, schema wiring):** Listening sockets now reach `schema::Event` —
`listen_port_events()` maps a snapshot to `Event::ListenPort` (schema v10 -> v11),
resolving each joined PID's `comm`/`ppid`/`gid` from `/proc/<pid>/status` (uid is
kernel-reported by `sock_diag` itself, no `/proc` read needed for that one). An
unattributable PID (exited between the two queries, or another user's process) is
silently skipped, not emitted with fabricated metadata. This is the mapping issue
#92's "listening-port drift" done-when item needs, but nothing yet calls it on a
cadence or diffs consecutive snapshots for drift, and nothing feeds its output to
`crates/correlator`'s `EventBus` — both are a caller's job that doesn't exist yet.
Conntrack flows now reach `schema::Event` too — `conntrack_flow_events()` maps a
`dump_conntrack()` dump to `Event::NetworkFlow` (schema v11 -> v12). A conntrack
entry carries no PID from the kernel at all (unlike `sock_diag`'s inode join), so
attribution instead joins the flow's tuple against a concurrent `sock_diag`
snapshot's `local`/`remote`/state — two orientations are checked (this host as the
connection's initiator, or as the one accepted into), since `ctnetlink` doesn't say
which end `orig` started from, and the `orig`/`reply` byte counters are swapped
accordingly before becoming `bytes_sent`/`bytes_received` for whichever orientation
matched. TCP only (`sock_diag` here never queries UDP, so a UDP flow can never
match); a flow nothing could attribute produces no event, same discipline as
listening sockets. This is the mapping issue #92's "conntrack features reach the
correlator" done-when item needs — polling cadence, the beacon-scenario validation
itself, and `crates/correlator` wiring remain a caller's job that doesn't exist yet
(no lab VM here to build one against). Proc connector's own schema/`tamper` wiring
is still explicitly deferred past this slice — see the crate doc's "Deliberately
not here yet" section for why (its role is a `tamper` cross-check that may not want
to be a `schema::Event` in the first place).

**Status (issue #93, journald):** Foundation landed — `crates/sensors/linux/journal`
tails `journalctl -f -o json` (subprocess, not `libsystemd` FFI — see the crate's
`tail` module doc for why) and classifies an allowlist: sshd accept/fail, PAM
session open/close (any `pam_unix` service, not just sudo), sudo command lines, and
systemd unit start/stop/fail. No `schema::Event` variant yet — the issue's own text
says this event type is shared with Windows 4624/macOS login, and that type does not
exist in `schema` today, so it needs a cross-platform design pass before a Linux-only
PR bakes one in. sshd/`su` classification is built against the standard, documented
log line formats but unverified against a real capture (no `sshd` on this dev box,
`su` needs interactive auth this session can't provide) — lab validation is a
follow-up, same discipline as #91.
