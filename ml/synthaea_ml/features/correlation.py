"""Extraction of the "multi-events per pid" feature vector, for a second ML scorer — a
complement to the cmdline vector (`features.py`), never merged with it into a single model
(decision of 2026-08-27, see docs/design/design-correlation-ml-vector.md).

**Must stay in sync with the Rust mirror** (crates/synthaea-ml/src/correlation_features.rs):
exact same definitions, same output order.

Expected input format: a list of JSON-Lines events, one object per event, as produced by
`edr-cli capture-events` / `edr-cli run` in `events.jsonl`:
    {"type": "exec",     "pid": 1234, "ts_ns": 1000000000, "comm": "curl", "cmdline": "..."}
    {"type": "connect",  "pid": 1234, "ts_ns": 2000000000, "daddr_v4": [127,0,0,1],
                         "dport": 4444, "is_ipv6": false}
    {"type": "fileopen", "pid": 1234, "ts_ns": 3000000000, "path": "...", "flags": 65}

`flags` is logged raw; the filtering on write intent (`O_WRONLY|O_RDWR|O_CREAT`) happens
here, exactly mirroring `synthaea_correlator::TimedEvent::is_file_write` on the Rust side
(`ml/behavior_features.py` applies the same test).
"""

# ── Rust mirror constants (POSIX flags) ───────────────────────────────────────

O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100

FEATURE_NAMES = [
    "spawn_count",
    "connect_count",
    "filewrite_count",
    "unique_daddr_count",
    "unique_dport_count",
    "has_full_chain",
    "span_s",
    "event_count",
]


def _is_file_write(event: dict) -> bool:
    """Mirror of `TimedEvent::is_file_write` (Rust): a `fileopen` with at least one of the
    `O_WRONLY` / `O_RDWR` / `O_CREAT` bits. Deliberately a bitmask test (identical to the Rust
    and to `behavior_features.py`), not a strict `access_mode == O_WRONLY`."""
    return event.get("type") == "fileopen" and bool(
        int(event.get("flags", 0)) & (O_WRONLY | O_RDWR | O_CREAT)
    )


def extract_features(events: list[dict], pid: int) -> list[float]:
    """`events`: all events of a correlation window (not only those of the requested pid —
    the pid filtering happens here, like `EventBus::events_for_pid` on the Rust side)."""
    pid_events = [e for e in events if e["pid"] == pid]

    spawn_count = sum(1 for e in pid_events if e["type"] == "exec")
    connect_count = sum(1 for e in pid_events if e["type"] == "connect")
    filewrite_count = sum(1 for e in pid_events if _is_file_write(e))

    daddrs = {tuple(e["daddr_v4"]) for e in pid_events if e["type"] == "connect"}
    dports = {e["dport"] for e in pid_events if e["type"] == "connect"}

    has_full_chain = (
        1.0 if (spawn_count >= 1 and connect_count >= 1 and filewrite_count >= 1) else 0.0
    )

    if pid_events:
        span_s = (
            max(e["ts_ns"] for e in pid_events) - min(e["ts_ns"] for e in pid_events)
        ) / 1_000_000_000.0
    else:
        span_s = 0.0

    return [
        float(spawn_count),
        float(connect_count),
        float(filewrite_count),
        float(len(daddrs)),
        float(len(dports)),
        has_full_chain,
        span_s,
        float(len(pid_events)),
    ]


# ── Parity with the Rust tests (crates/synthaea-ml/src/correlation_features.rs) ──

if __name__ == "__main__":
    print("=== Tests correlation_features.py (mirror of the Rust tests) ===\n")

    # vecteur_vide_pour_pid_absent
    assert extract_features([], 1234) == [0.0] * 8
    assert extract_features([{"type": "exec", "pid": 1, "ts_ns": 0}], 1234) == [0.0] * 8
    print("[OK] absent pid → zero vector")

    # chaine_complete_a_has_full_chain_a_un
    evs = [
        {"type": "exec", "pid": 99, "ts_ns": 0},
        {
            "type": "connect",
            "pid": 99,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 4444,
        },
        {"type": "fileopen", "pid": 99, "ts_ns": 2_000_000_000, "flags": O_WRONLY | O_CREAT},
    ]
    f = extract_features(evs, 99)
    assert f[0] == 1.0 and f[1] == 1.0 and f[2] == 1.0, f
    assert f[5] == 1.0, "has_full_chain"
    assert f[6] == 2.0, "span_s 0->2s"
    assert f[7] == 3.0, "event_count"
    print(f"[OK] full chain: {f}")

    # spawn_seul_n_a_pas_has_full_chain
    assert extract_features([{"type": "exec", "pid": 1, "ts_ns": 0}], 1)[5] == 0.0
    print("[OK] spawn alone → has_full_chain=0")

    # a read-only fileopen does not count as a filewrite
    ro = [{"type": "fileopen", "pid": 5, "ts_ns": 0, "flags": 0}]  # O_RDONLY
    assert extract_features(ro, 5)[2] == 0.0, "read-only ≠ filewrite"
    print("[OK] fileopen O_RDONLY → filewrite_count=0")

    # destinations_multiples_comptees_une_fois_chacune
    net = [
        {"type": "connect", "pid": 7, "ts_ns": 0, "daddr_v4": [127, 0, 0, 1], "dport": 4444},
        {
            "type": "connect",
            "pid": 7,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 4444,
        },
        {
            "type": "connect",
            "pid": 7,
            "ts_ns": 2_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 8080,
        },
    ]
    fn = extract_features(net, 7)
    assert fn[1] == 3.0, "connect_count"
    assert fn[3] == 1.0, "unique_daddr_count"
    assert fn[4] == 2.0, "unique_dport_count"
    print(f"[OK] distinct destinations: {fn}")

    # pids_differents_isoles
    mix = [
        {"type": "exec", "pid": 1, "ts_ns": 0},
        {
            "type": "connect",
            "pid": 2,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [1, 1, 1, 1],
            "dport": 4444,
        },
    ]
    assert extract_features(mix, 1)[1] == 0.0
    assert extract_features(mix, 2)[0] == 0.0
    print("[OK] isolated pids")

    print("\nAll tests pass.")
