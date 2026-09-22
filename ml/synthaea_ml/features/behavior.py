"""Per-PID behavioral feature extraction — mirror of BehaviorVector (Rust).

These 9 features complement the 9 cmdline features from features.py to form an
18D vector intended for training the behavioral ML model (phase 2).

Input format: list of events for a given PID.
Each event is a dict with at minimum the "type" key:

    exec    : {"type": "exec",     "ts_ns": int, "cmdline": str}
    connect : {"type": "connect",  "ts_ns": int, "daddr_v4": [b0,b1,b2,b3],
                                   "dport": int, "is_ipv6": bool}
    fileopen: {"type": "fileopen", "ts_ns": int, "flags": int}

Fileopen flags (POSIX):
    O_ACCMODE = 0o3, O_WRONLY = 0o1, O_RDWR = 0o2, O_CREAT = 0o100

This extraction is in 1-to-1 correspondence with the
`CorrelationEngine::behavior_vector_for_pid` method of crates/synthaea-correlator/src/lib.rs.
Any change to a feature must be mirrored in both files.

Standalone usage:
    python behavior_features.py
"""

from __future__ import annotations

# ── Rust mirror constants ──────────────────────────────────────────────────────

O_ACCMODE: int = 0o3
O_WRONLY: int = 0o1
O_RDWR: int = 0o2
O_CREAT: int = 0o100

# Suspicious directories — same values as is_suspicious_bv() and is_suspicious_win_path()
_SUSPICIOUS_DIRS = ["appdata", "\\temp\\", "downloads", "desktop", "\\public\\"]

# RFC-1918 private ranges + loopback
_PRIVATE_RANGES = [
    lambda a: a[0] == 10,
    lambda a: a[0] == 172 and 16 <= a[1] <= 31,
    lambda a: a[0] == 192 and a[1] == 168,
    lambda a: a[0] == 127,
]


# ── Helpers ────────────────────────────────────────────────────────────────────


def _is_suspicious(path: str) -> bool:
    """Returns True if the path contains a suspicious directory."""
    lower = path.lower()
    return any(s in lower for s in _SUSPICIOUS_DIRS)


def _is_private_ipv4(addr: list[int]) -> bool:
    """Returns True if the IPv4 address is private or loopback (RFC-1918)."""
    return any(fn(addr) for fn in _PRIVATE_RANGES)


def _is_write(flags: int) -> bool:
    """Write intent — mirror of `schema::has_write_intent` (Rust): access mode
    `O_WRONLY`/`O_RDWR` (a 2-bit field, so the invalid `0o3` combination is NOT a
    write — the kernel refuses it), or `O_CREAT`."""
    access_mode = flags & O_ACCMODE
    return access_mode in (O_WRONLY, O_RDWR) or bool(flags & O_CREAT)


# ── Main extraction ────────────────────────────────────────────────────────────


def extract_behavior_features(events: list[dict]) -> list[float]:
    """Extracts the 9 behavioral features from a PID's event sequence within
    its sliding window.

    The feature order is identical to BehaviorVector::to_vec():
        [has_exec, has_connect, has_filewrite,
         time_exec_to_connect_ms, time_exec_to_filewrite_ms,
         is_suspicious_path,
         connect_count, distinct_dports, dest_is_external]

    Returns a vector of 9 zeros if the list is empty (no events).
    """
    if not events:
        return [0.0] * 9

    exec_events = [e for e in events if e["type"] == "exec"]
    connect_events = [e for e in events if e["type"] == "connect"]
    write_events = [e for e in events if e["type"] == "fileopen" and _is_write(e.get("flags", 0))]

    has_exec = 1.0 if exec_events else 0.0
    has_connect = 1.0 if connect_events else 0.0
    has_filewrite = 1.0 if write_events else 0.0

    # Time deltas (ms)
    first_exec_ns = exec_events[0]["ts_ns"] if exec_events else None
    first_connect_ns = connect_events[0]["ts_ns"] if connect_events else None
    first_filewrite_ns = write_events[0]["ts_ns"] if write_events else None

    if first_exec_ns is not None and first_connect_ns is not None:
        time_exec_to_connect_ms = max(0.0, (first_connect_ns - first_exec_ns) / 1_000_000)
    else:
        time_exec_to_connect_ms = 0.0

    if first_exec_ns is not None and first_filewrite_ns is not None:
        time_exec_to_filewrite_ms = max(0.0, (first_filewrite_ns - first_exec_ns) / 1_000_000)
    else:
        time_exec_to_filewrite_ms = 0.0

    # Suspicious path — PID's first exec
    if exec_events:
        image = exec_events[0]["cmdline"].split("\0")[0]
        is_suspicious_path = 1.0 if _is_suspicious(image) else 0.0
    else:
        is_suspicious_path = 0.0

    # Network
    connect_count = float(len(connect_events))
    dports = {e["dport"] for e in connect_events}
    distinct_dports = float(len(dports))

    dest_is_external = 0.0
    for e in connect_events:
        if not e.get("is_ipv6", False):
            addr = e.get("daddr_v4", [0, 0, 0, 0])
            if not _is_private_ipv4(addr):
                dest_is_external = 1.0
                break

    return [
        has_exec,
        has_connect,
        has_filewrite,
        time_exec_to_connect_ms,
        time_exec_to_filewrite_ms,
        is_suspicious_path,
        connect_count,
        distinct_dports,
        dest_is_external,
    ]


def zero_behavior_features() -> list[float]:
    """Zero behavioral vector — used for baseline entries that only have
    cmdline data (no associated connect/fileopen events)."""
    return [0.0] * 9


# ── Quick tests ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Tests behavior_features.py ===\n")

    # Case 1: exec only (typical baseline)
    ev_exec_seul = [
        {"type": "exec", "ts_ns": 1_000_000_000, "cmdline": "C:\\Windows\\System32\\svchost.exe"}
    ]
    bv = extract_behavior_features(ev_exec_seul)
    assert bv[0] == 1.0, "has_exec expected"
    assert bv[1] == 0.0, "has_connect not expected"
    assert bv[5] == 0.0, "is_suspicious_path not expected for svchost"
    print(f"[OK] exec only (svchost): {bv}")

    # Case 2: suspicious exec + external connect with delta
    ev_dropper = [
        {"type": "exec", "ts_ns": 0, "cmdline": "C:\\Users\\victim\\AppData\\Roaming\\payload.exe"},
        {
            "type": "connect",
            "ts_ns": 500_000_000,
            "daddr_v4": [8, 8, 8, 8],
            "dport": 4444,
            "is_ipv6": False,
        },
        {
            "type": "connect",
            "ts_ns": 600_000_000,
            "daddr_v4": [8, 8, 8, 8],
            "dport": 443,
            "is_ipv6": False,
        },
        {"type": "fileopen", "ts_ns": 1_000_000_000, "flags": O_WRONLY | O_CREAT},
    ]
    bv2 = extract_behavior_features(ev_dropper)
    assert bv2[0] == 1.0, "has_exec"
    assert bv2[1] == 1.0, "has_connect"
    assert bv2[2] == 1.0, "has_filewrite"
    assert abs(bv2[3] - 500.0) < 1.0, f"time_exec_to_connect_ms expected 500, got {bv2[3]}"
    assert abs(bv2[4] - 1000.0) < 1.0, f"time_exec_to_filewrite_ms expected 1000, got {bv2[4]}"
    assert bv2[5] == 1.0, "is_suspicious_path expected (AppData)"
    assert bv2[6] == 2.0, "connect_count=2"
    assert bv2[7] == 2.0, "distinct_dports=2 (4444 and 443)"
    assert bv2[8] == 1.0, "dest_is_external (8.8.8.8)"
    print(f"[OK] full dropper (AppData + 8.8.8.8): {bv2}")

    # Case 3: connect to a private IP — not external
    ev_interne = [
        {
            "type": "connect",
            "ts_ns": 1_000_000_000,
            "daddr_v4": [192, 168, 1, 1],
            "dport": 445,
            "is_ipv6": False,
        },
    ]
    bv3 = extract_behavior_features(ev_interne)
    assert bv3[8] == 0.0, "dest_is_external not expected for 192.168.x.x"
    print(f"[OK] private IP connect: {bv3}")

    # Case 4: zero vector
    assert zero_behavior_features() == [0.0] * 9
    print("[OK] zero_behavior_features()")

    print("\nAll tests pass.")
