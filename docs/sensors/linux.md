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
