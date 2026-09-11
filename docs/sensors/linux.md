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
