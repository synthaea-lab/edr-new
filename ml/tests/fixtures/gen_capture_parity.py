"""Regenerates the capture-format parity fixture (issue #109):

    ml/tests/fixtures/capture_events.jsonl            (schema::Event JSON-Lines, one per line)
    ml/tests/fixtures/capture_correlation_golden.jsonl ({pid, features} per PID)

This is the end-to-end format seam the feature/scorer goldens leave open: it pins the
whole chain the agent runs — a real `events.jsonl` capture (`crates/schema::Event` as
serde serializes it: identity under `meta`, `daddr` a single address string, `file_open`
tag) → per-PID correlation window → 8-feature vector.

  - Python: `synthaea_ml.data.aggregate_correlation` reads it here.
  - Rust:   `crates/ml/tests/capture_parity.rs` deserializes each line as `schema::Event`,
            pushes it through `correlator::EventBus`, and runs
            `ml::features::correlation::extract_features`.

Both must produce the golden vectors. All events sit inside one 60 s correlation window,
so `EventBus` eviction (`global_max - window`) and the aggregator's per-PID window agree.

Run from `ml/tests/fixtures/` with the venv (numpy for nothing here — stdlib only, plus
the package on the path):

    python3 gen_capture_parity.py

Regenerate only on a deliberate change to the correlation feature definition or the
wire format — never to paper over a red parity test.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from synthaea_ml.data.aggregate_correlation import charger_events, vecteurs_par_pid

OUT = Path(__file__).resolve().parent
S = 1_000_000_000
BASE = 1_756_900_000 * S  # arbitrary epoch-ns start, matching the golden.rs style


def meta(pid: int, ppid: int, t_ns: int, comm: str) -> dict:
    return {
        "pid": pid,
        "ppid": ppid,
        "user": {"os": "unix", "uid": 1000, "gid": 1000},
        "timestamp_ns": BASE + t_ns,
        "comm": comm,
    }


def exec_ev(pid, ppid, t_ns, comm, image, argv):
    return {
        "type": "exec",
        "meta": meta(pid, ppid, t_ns, comm),
        "image_path": image,
        "cmdline": " ".join(argv),  # sensor display form — deliberately NOT what ML reads
        "argv": argv,
    }


def connect_ev(pid, ppid, t_ns, comm, daddr, dport):
    return {"type": "connect", "meta": meta(pid, ppid, t_ns, comm), "daddr": daddr, "dport": dport}


def file_open_ev(pid, ppid, t_ns, comm, path, flags):
    return {
        "type": "file_open",
        "meta": meta(pid, ppid, t_ns, comm),
        "path": path,
        "flags": flags,
    }


O_WRONLY_CREAT = 0o101

# A small mixed capture: a quiet shell, a network client, a dropper chain, a fan-out,
# and an event type the correlator ignores (dns_query) that must not perturb anything.
EVENTS = [
    exec_ev(1001, 1, 0, "bash", "/usr/bin/bash", ["bash", "-l"]),
    exec_ev(1001, 1, 1 * S, "ls", "/usr/bin/ls", ["ls", "-la", "/home/user"]),
    exec_ev(1001, 1, 2 * S, "cat", "/usr/bin/cat", ["cat", "/etc/hostname"]),

    exec_ev(1002, 1001, 3 * S, "curl", "/usr/bin/curl", ["curl", "-fsS", "https://mirror.test/x"]),
    connect_ev(1002, 1001, 3 * S + 100_000_000, "curl", "203.0.113.9", 443),
    connect_ev(1002, 1001, 4 * S, "curl", "203.0.113.9", 443),

    exec_ev(1003, 1001, 5 * S, "sh", "/usr/bin/dash", ["sh", "-c", "./stage2"]),
    file_open_ev(1003, 1001, 5 * S + 200_000_000, "sh", "/tmp/stage2", O_WRONLY_CREAT),
    connect_ev(1003, 1001, 5 * S + 500_000_000, "stage2", "198.51.100.4", 8080),
    connect_ev(1003, 1001, 6 * S, "stage2", "198.51.100.4", 8080),
    {"type": "dns_query", "meta": meta(1003, 1001, 6 * S + 10_000_000, "stage2"),
     "query": "c2.test", "qtype": 1, "result": None, "status": 0},

    exec_ev(1004, 1001, 7 * S, "scan", "/tmp/scan", ["/tmp/scan"]),
    *[connect_ev(1004, 1001, 7 * S + i * 100_000_000, "scan", f"10.0.0.{i}", 1000 + i)
      for i in range(1, 9)],

    # single event for a PID — kept in the log, dropped by the default min-events=1? no,
    # min-events=1 keeps it; the Rust gate is a scorer concern, not the extractor's.
    exec_ev(1005, 1, 8 * S, "sleep", "/usr/bin/sleep", ["sleep", "30"]),
]

events_path = OUT / "capture_events.jsonl"
events_path.write_text("".join(json.dumps(e) + "\n" for e in EVENTS), encoding="utf-8")

vectors = vecteurs_par_pid(charger_events(events_path), window_ns=60 * S, min_events=1)
golden_path = OUT / "capture_correlation_golden.jsonl"
golden_path.write_text("".join(json.dumps(v) + "\n" for v in vectors), encoding="utf-8")

print(f"wrote {events_path.name} ({len(EVENTS)} events) and {golden_path.name} "
      f"({len(vectors)} PID vectors)")
for v in vectors:
    print(f"  pid={v['pid']:<5} {v['features']}")
