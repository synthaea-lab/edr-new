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

**Status (issue #92, sock_diag):** Foundation landed — `crates/sensors/linux/netlink`
queries TCP listening/established sockets (IPv4 + IPv6) via a hand-rolled
`NETLINK_SOCK_DIAG` client, joined to owning PID(s) via a `/proc` fd scan (the same
technique `ss`/`lsof` use). Verified unprivileged against this dev machine's real
kernel — no root needed for `sock_diag`, confirmed empirically. Conntrack and proc
connector are deliberately not here: both were confirmed reachable in this sandbox
(session had passwordless `sudo`), but each is a distinct netlink sub-protocol with
its own parser (conntrack's attributes are TLV-nested, a meaningfully bigger job than
`sock_diag`'s fixed-size struct) — scoped out to keep this slice reviewable, tracked
as follow-ups on #92, not silently dropped.

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
