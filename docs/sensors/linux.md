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
