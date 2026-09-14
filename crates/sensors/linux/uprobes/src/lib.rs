//! # sensor-linux-uprobes
//!
//! Userspace-function probes (eBPF uprobes) - telemetry the kernel boundary cannot
//! see:
//! - `SSL_read`/`SSL_write` (OpenSSL/BoringSSL/GnuTLS) - plaintext of TLS traffic
//!   BEFORE encryption / after decryption: C2 content visibility with no MITM, no
//!   certificates, no proxy. Budgeted capture (first N bytes, allowlisted comms).
//! - `bash`/`zsh` readline - interactive shell commands at typing time, catching
//!   what execve never sees (shell builtins, history-evading input).
//!
//! Probes attach per-binary (symbol resolution against the on-disk library, tracked
//! across updates); the probe programs join the `ebpf` crate build, this crate owns
//! attachment, symbol resolution, and normalization into schema events.
//!
//! **Status (Phase 4):** Symbol resolution, uprobe attachment, and ring buffer draining
//! are implemented. Normalization to `schema::Event` deferred to Phase 5 (event types
//! don't exist yet - this sensor logs events for now).

#[cfg(target_os = "linux")]
pub mod symbol_resolver;

#[cfg(target_os = "linux")]
mod sensor;

#[cfg(target_os = "linux")]
pub use sensor::UprobesSensor;
