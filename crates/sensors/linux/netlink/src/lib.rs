//! # sensor-linux-netlink
//!
//! Kernel netlink families as a supplementary, zero-probe source:
//! - `sock_diag` — periodic socket-table snapshots (listening/established with
//!   inode→pid join): listen-port telemetry and drift detection without a probe.
//! - `nfnetlink conntrack` — flow accounting (bytes/packets/duration per flow),
//!   giving beacon detection volume/periodicity features events alone lack.
//! - proc connector — fork/exec/exit notifications as a cheap cross-check for the
//!   eBPF stream (a gap between the two is itself a tamper signal).
//!
//! No special kernel config; runs where eBPF cannot; complements, never replaces,
//! the probe-based sensors.
//!
//! **Status (issue #92, foundation):** `sock_diag` is done — [`snapshot`] queries
//! TCP listening/established sockets (IPv4 + IPv6) via a hand-rolled
//! `NETLINK_SOCK_DIAG` client ([`wire`]/[`socket`]) and joins each one to its
//! owning PID(s) by scanning `/proc` ([`proc_join`]), the same technique `ss`/
//! `lsof` use. Verified against this dev machine's real kernel — no root needed
//! (confirmed empirically: `sock_diag` for TCP works unprivileged, unlike
//! conntrack and proc connector below).
//!
//! **`schema::Event` wiring, for listening sockets:** [`listen_port_events`] maps
//! a [`snapshot`] to [`schema::Event::ListenPort`] (`schema` `SCHEMA_VERSION` 10 ->
//! 11) — the mapping issue #92's "listening-port drift" done-when item needs.
//! [`proc_meta`] resolves the `comm`/`ppid`/`gid` a [`schema::EventMeta`] needs
//! from `/proc/<pid>/status` (uid comes straight from the kernel via `sock_diag` —
//! see [`SocketSnapshotEntry::uid`]'s doc); [`normalize`] does the pure
//! entry-plus-proc-info -> `Event` mapping, same split as `sensor-linux`'s own
//! `normalize` module. A joined PID that can't be resolved (exited between the two
//! `/proc` reads, or another user's process without permission) is silently
//! skipped rather than emitted with fabricated metadata — a per-poll, best-effort
//! sample, not a guaranteed-complete one. Established sockets aren't mapped (no
//! drift semantics for them, see [`normalize::listen_port_event`]'s doc); this
//! crate still doesn't decide the polling cadence or run the drift comparison
//! itself — a caller (not yet written) calls [`listen_port_events`] repeatedly and
//! diffs consecutive results. No lab VM here to validate that live, same gap as
//! before this wiring existed.
//!
//! Deliberately **not** here yet:
//! - **conntrack** and **proc connector** — both were confirmed reachable in this
//!   sandbox (this session has passwordless `sudo`), but each is a full netlink
//!   sub-protocol of its own (conntrack's TLV-nested attributes — tuples,
//!   counters — are a meaningfully bigger parser than `sock_diag`'s fixed-size
//!   struct). Scoped out to keep this slice reviewable; tracked as follow-ups on
//!   #92, not silently dropped.
//! - `schema::Event` wiring for conntrack (beacon volume/periodicity features) and
//!   proc connector (the eBPF cross-check): both need design decisions beyond this
//!   slice's scope — conntrack flows carry no PID at all from the kernel (would
//!   need a further join, e.g. against a `sock_diag` snapshot's own tuples, to
//!   attribute one), and the proc connector's role per the issue is a *tamper*
//!   signal (divergence from the eBPF stream), which may not want to be a
//!   `schema::Event` at all rather than an internal `crates/tamper` comparison —
//!   not a call this Linux-only slice should make alone.
//! - `crates/correlator` wiring: [`listen_port_events`] produces `schema::Event`s,
//!   but nothing in this crate hands them to `correlator::EventBus` — that's the
//!   caller's job (the same one that would own the polling cadence above), and no
//!   such caller exists yet for this crate's data.
//! - UDP sockets — `sock_diag` supports them, but "listen/established" (this
//!   issue's own wording) is TCP-state terminology; UDP would need its own
//!   category, not a states-mask filter.
//! - Periodic re-snapshotting / drift detection between snapshots — [`snapshot`]
//!   is a one-shot query; a caller decides the cadence. No lab VM here to
//!   validate the issue's "listening-port drift" done-when item against.

mod normalize;
mod proc_join;
mod proc_meta;
mod wire;

#[cfg(target_os = "linux")]
mod socket;

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
pub use socket::NetlinkError;
pub use wire::{DiagMsg, TCP_ESTABLISHED, TCP_LISTEN};

/// A TCP socket's state, as reported by `sock_diag`. This crate only ever
/// requests [`TCP_ESTABLISHED`]/[`TCP_LISTEN`] (see the crate doc), so `Other` is
/// purely defensive — a kernel returning something outside the requested mask
/// would be a bug worth seeing, not a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Established,
    Listen,
    Other(u8),
}

impl From<u8> for SocketState {
    fn from(raw: u8) -> Self {
        match raw {
            TCP_ESTABLISHED => Self::Established,
            TCP_LISTEN => Self::Listen,
            other => Self::Other(other),
        }
    }
}

/// One socket from a [`snapshot`], joined to the PID(s) holding it open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshotEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: SocketState,
    /// UID of the socket's owning process, from the kernel — independent of the
    /// `/proc` join below, and still populated even when that join finds nothing.
    pub uid: u32,
    pub inode: u32,
    /// PIDs whose open file descriptors point at this socket's inode. Usually
    /// one; more than one when a listener is shared across forked workers before
    /// `exec`; empty when the owning process is in another user's `/proc/<pid>/fd`
    /// (unreadable without root) or already exited between the two queries.
    pub pids: Vec<u32>,
}

impl From<DiagMsg> for SocketSnapshotEntry {
    fn from(msg: DiagMsg) -> Self {
        Self {
            local: SocketAddr::new(msg.local, msg.local_port),
            remote: SocketAddr::new(msg.remote, msg.remote_port),
            state: SocketState::from(msg.state),
            uid: msg.uid,
            inode: msg.inode,
            pids: Vec::new(),
        }
    }
}

/// Takes one snapshot of TCP listening/established sockets, joined to their
/// owning PID(s) where `/proc` permissions allow it.
///
/// # Errors
///
/// See [`NetlinkError`] — the query fails as a whole (rather than returning a
/// partial list) if the kernel can't be reached at all.
#[cfg(target_os = "linux")]
pub fn snapshot() -> Result<Vec<SocketSnapshotEntry>, NetlinkError> {
    let states = (1u32 << TCP_ESTABLISHED) | (1u32 << TCP_LISTEN);
    let msgs = socket::query_tcp_sockets(states)?;
    let inode_pids = proc_join::inode_to_pids();

    Ok(msgs
        .into_iter()
        .map(|msg| {
            let mut entry = SocketSnapshotEntry::from(msg);
            entry.pids = inode_pids
                .get(&u64::from(entry.inode))
                .cloned()
                .unwrap_or_default();
            entry
        })
        .collect())
}

/// Takes one [`snapshot`] and maps every listening socket to a
/// [`schema::Event::ListenPort`], attributed to each PID that holds it open (see
/// [`SocketSnapshotEntry::pids`]'s doc — usually one, occasionally several for a
/// pre-`exec` shared listener, none when unattributable). `timestamp_ns` is
/// stamped on every event as the snapshot time (see
/// [`schema::ListenPortEvent`]'s doc on what that does and doesn't mean).
///
/// Established sockets and unattributed listeners produce no event — see the
/// crate doc's "`schema::Event` wiring" section for why that's a deliberate,
/// documented gap rather than a bug.
///
/// # Errors
///
/// See [`NetlinkError`] — same failure mode as [`snapshot`], which this wraps.
#[cfg(target_os = "linux")]
pub fn listen_port_events(timestamp_ns: u64) -> Result<Vec<schema::Event>, NetlinkError> {
    let entries = snapshot()?;
    Ok(entries
        .iter()
        .flat_map(|entry| {
            entry.pids.iter().filter_map(move |&pid| {
                let proc = proc_meta::resolve(pid)?;
                normalize::listen_port_event(entry, pid, &proc, timestamp_ns)
            })
        })
        .collect())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_runs_end_to_end_against_the_real_kernel_and_proc() {
        let entries = snapshot().expect("unprivileged snapshot must succeed");
        // Nondeterministic which sockets exist right now — the properties that
        // must hold regardless: every entry has a real state (not garbage from a
        // parsing bug) and, when a PID was found, it's still a plausible PID
        // (nonzero — PID 0 is not a real process).
        for entry in &entries {
            assert!(!matches!(entry.state, SocketState::Other(_)));
            for &pid in &entry.pids {
                assert_ne!(pid, 0);
            }
        }
    }

    #[test]
    fn socket_state_from_u8_covers_the_requested_states_and_falls_back() {
        assert_eq!(SocketState::from(TCP_ESTABLISHED), SocketState::Established);
        assert_eq!(SocketState::from(TCP_LISTEN), SocketState::Listen);
        assert_eq!(SocketState::from(7), SocketState::Other(7));
    }

    #[test]
    fn listen_port_events_runs_end_to_end_against_the_real_kernel_and_proc() {
        let events = listen_port_events(42).expect("must succeed, same as snapshot()");
        // Nondeterministic whether any listening socket with an attributable PID
        // exists right now — the property that must hold regardless: every event
        // this produced really is a ListenPort variant with the stamped
        // timestamp and a nonzero PID (proc_meta::resolve only ever returns
        // Some for a PID it actually read from /proc).
        for event in &events {
            let schema::Event::ListenPort(listen) = &event else {
                panic!("listen_port_events must only ever produce ListenPort events");
            };
            assert_eq!(listen.meta.timestamp_ns, 42);
            assert_ne!(listen.meta.pid, 0);
        }
    }
}
