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
