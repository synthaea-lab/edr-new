"""Empirical calibration of the Bayesian filter's Log-Likelihood Ratios (LLR).

Reads `events.jsonl` (raw events logged by the agent) and `alerts.ndjson`
(emitted alerts), computes the per-PID BehaviorVectors within a 60s sliding
window, splits benign/malicious based on the alerted PIDs, and generates the
empirical LLRs + the corresponding Rust code for `log_likelihood_ratio()`.

Usage:
    python calibrate_llr.py [--events events.jsonl] [--alerts alerts.ndjson]
                            [--window 60] [--min-mal 1] [--out llr_report.txt]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

from synthaea_ml.features.behavior import extract_behavior_features

# ── Constants ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "has_exec",
    "has_connect",
    "has_filewrite",
    "time_exec_to_connect_ms",
    "time_exec_to_filewrite_ms",
    "is_suspicious_path",
    "connect_count",
    "distinct_dports",
    "dest_is_external",
]

# Hand-calibrated LLRs — kept as reference for comparison in the report.
LLR_CURRENT = [0.0, 0.3, 0.7, "0.8/<500ms,0.3/<2s", 0.6, 2.0, "0.1*n,max1.5", 0.5, 1.5]

# Laplace smoothing — prevents log(0) when a bin is unseen in a small sample.
LAPLACE_ALPHA = 0.5


# ── Parsing ────────────────────────────────────────────────────────────────────


def _normalize_event(e: dict) -> dict:
    """Flatten the edr-new nested event format to the flat format expected downstream.

    edr-new format:
        {"type": "exec",      "meta": {"pid": ..., "timestamp_ns": ...}, "cmdline": ...}
        {"type": "connect",   "meta": {...}, "daddr_v4": [...], "dport": ..., "is_ipv6": ...}
        {"type": "connect",   "meta": {...}, "daddr": "1.2.3.4", "dport": ...}  (NAT captures)
        {"type": "file_open", "meta": {...}, "flags": ..., "path": ...}
    Flat format:
        {"type": "exec",     "pid": ..., "ts_ns": ..., "cmdline": ...}
        {"type": "connect",  "pid": ..., "ts_ns": ..., "daddr_v4": [...], "dport": ...}
        {"type": "fileopen", "pid": ..., "ts_ns": ..., "flags": ...}
    """
    meta = e.get("meta")
    if meta is None:
        return e
    e = dict(e)  # shallow copy — do not mutate the caller's dict
    e["pid"] = meta.get("pid", 0)
    e["ts_ns"] = meta.get("timestamp_ns", 0)
    if e.get("type") == "file_open":
        e["type"] = "fileopen"
    # NAT captures emit daddr as a dotted-decimal string; Host-Only captures use
    # daddr_v4 as a list of ints.  Normalise to daddr_v4 so behavior.py is uniform.
    if "daddr" in e and "daddr_v4" not in e:
        try:
            e["daddr_v4"] = [int(b) for b in e["daddr"].split(".")]
        except (ValueError, AttributeError):
            e["daddr_v4"] = [0, 0, 0, 0]
    return e


def load_events(path: Path) -> list[dict]:
    """Load and normalize raw events from an events.jsonl file."""
    events = []
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(_normalize_event(json.loads(line)))
                except json.JSONDecodeError as e:
                    print(f"[warn] events.jsonl line {i} invalid: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(f"[error] {path} not found — run the agent first.", file=sys.stderr)
        sys.exit(1)
    return events


def load_malicious_pids(path: Path) -> set[int]:
    """Extract the alerted PIDs from an alerts.ndjson file."""
    pids: set[int] = set()
    if not path.exists():
        print(f"[warn] {path} not found — no known malicious PIDs.", file=sys.stderr)
        return pids
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                msg = alert.get("message", "")
                for token in msg.split():
                    if token.startswith("pid="):
                        with contextlib.suppress(ValueError):
                            pids.add(int(token[4:].rstrip(",")))
            except json.JSONDecodeError:
                pass
    return pids


# ── Sliding windowing ──────────────────────────────────────────────────────────


def group_by_pid_and_window(
    events: list[dict], window_ns: int
) -> dict[int, list[list[float]]]:
    """Group events by PID, slice into windows of window_ns nanoseconds, and
    return the BehaviorVectors per PID (one vector per non-empty window)."""
    by_pid: dict[int, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("type") in ("exec", "connect", "fileopen"):
            by_pid[e["pid"]].append(e)

    bv_by_pid: dict[int, list[list[float]]] = {}

    for pid, pid_events in by_pid.items():
        pid_events.sort(key=lambda e: e["ts_ns"])
        if not pid_events:
            continue
        vectors = []
        window_start = pid_events[0]["ts_ns"]
        window: list[dict] = []
        for e in pid_events:
            if e["ts_ns"] - window_start > window_ns:
                if window:
                    vectors.append(extract_behavior_features(window))
                window_start = e["ts_ns"]
                window = [e]
            else:
                window.append(e)
        if window:
            vectors.append(extract_behavior_features(window))
        bv_by_pid[pid] = vectors

    return bv_by_pid


# ── Calibration ────────────────────────────────────────────────────────────────


def _discretize(feature_idx: int, value: float) -> str:
    """Discretize a continuous feature value into a named bin.

    Binary features (0.0/1.0) pass through as "0"/"1".
    Continuous features are split into empirically chosen intervals.
    """
    if feature_idx in (0, 1, 2, 5, 8):
        return "1" if value > 0.5 else "0"
    elif feature_idx == 3:  # time_exec_to_connect_ms
        if value == 0.0:
            return "absent"
        elif value < 500:
            return "<500"
        elif value < 2000:
            return "<2000"
        else:
            return ">=2000"
    elif feature_idx == 4:  # time_exec_to_filewrite_ms
        if value == 0.0:
            return "absent"
        elif value < 500:
            return "<500"
        else:
            return ">=500"
    elif feature_idx == 6:  # connect_count
        if value == 0:
            return "0"
        elif value < 5:
            return "1-4"
        elif value < 15:
            return "5-14"
        else:
            return ">=15"
    elif feature_idx == 7:  # distinct_dports
        if value <= 1:
            return "0-1"
        elif value <= 3:
            return "2-3"
        else:
            return ">=4"
    return str(value)


def compute_empirical_llrs(
    bv_by_pid: dict[int, list[list[float]]],
    malicious_pids: set[int],
    alpha: float = LAPLACE_ALPHA,
) -> dict[int, dict[str, float]]:
    """Compute empirical LLRs for each feature bin via Laplace-smoothed counts.

    Returns feature_idx → {bin_name → llr}.
    """
    benign: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    malicious: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    n_benign = 0
    n_malicious = 0

    for pid, vectors in bv_by_pid.items():
        bucket = malicious if pid in malicious_pids else benign
        if pid in malicious_pids:
            n_malicious += len(vectors)
        else:
            n_benign += len(vectors)
        for bv in vectors:
            for i, val in enumerate(bv):
                bucket[i][_discretize(i, val)] += 1.0

    if n_benign == 0 or n_malicious == 0:
        print(
            f"[warn] n_benign={n_benign}, n_malicious={n_malicious}"
            " — not enough data to calibrate.",
            file=sys.stderr,
        )
        return {}

    llr: dict[int, dict[str, float]] = {}
    for i in range(9):
        all_bins = set(benign[i].keys()) | set(malicious[i].keys())
        total_b = sum(benign[i].values()) + alpha * len(all_bins)
        total_m = sum(malicious[i].values()) + alpha * len(all_bins)
        llr[i] = {}
        for b in all_bins:
            p_b = (benign[i].get(b, 0.0) + alpha) / total_b
            p_m = (malicious[i].get(b, 0.0) + alpha) / total_m
            llr[i][b] = math.log(p_m / p_b)

    return llr


# ── Report ─────────────────────────────────────────────────────────────────────


def generate_report(
    llr: dict[int, dict[str, float]],
    n_benign: int,
    n_malicious: int,
) -> str:
    """Render the calibration report as a human-readable string."""
    lines = []
    lines.append("=" * 70)
    lines.append("LLR CALIBRATION REPORT — Synthaea EDR")
    lines.append(f"Benign samples    : {n_benign}")
    lines.append(f"Malicious samples : {n_malicious}")
    lines.append("=" * 70)
    lines.append("")

    for i, name in enumerate(FEATURE_NAMES):
        if i not in llr:
            continue
        lines.append(f"[{i}] {name}")
        lines.append(f"    Current LLR : {LLR_CURRENT[i]}")
        lines.append("    Empirical LLRs per bin:")
        for bin_key, val in sorted(llr[i].items()):
            lines.append(f"        {bin_key:12s} → {val:+.3f}")
        lines.append("")

    lines.append("─" * 70)
    lines.append("SUGGESTED RUST CODE for log_likelihood_ratio():")
    lines.append("─" * 70)
    lines.append(generate_rust(llr))
    return "\n".join(lines)


def generate_rust(llr: dict[int, dict[str, float]]) -> str:
    """Generate the Rust match block for log_likelihood_ratio()."""
    rust = ["fn log_likelihood_ratio(idx: usize, value: f32) -> f32 {", "    match idx {"]

    descs = {
        0: "has_exec",
        1: "has_connect",
        2: "has_filewrite",
        3: "time_exec_to_connect_ms",
        4: "time_exec_to_filewrite_ms",
        5: "is_suspicious_path",
        6: "connect_count",
        7: "distinct_dports",
        8: "dest_is_external",
    }

    for i in range(9):
        rust.append(f"        // {i} — {descs[i]}")
        if i not in llr:
            rust.append(f"        {i} => 0.0,")
            continue

        bins = llr[i]
        if set(bins.keys()) <= {"0", "1"}:
            llr_1 = bins.get("1", 0.0)
            llr_0 = bins.get("0", 0.0)
            rust.append(f"        {i} => if value > 0.5 {{ {llr_1:.2f} }} else {{ {llr_0:.2f} }},")
        elif i == 3:
            v_lt500 = bins.get("<500", 0.0)
            v_lt2000 = bins.get("<2000", 0.0)
            v_absent = bins.get("absent", 0.0)
            rust.append(f"        {i} => {{")
            rust.append(f"            if value > 0.0 && value < 500.0 {{ {v_lt500:.2f} }}")
            rust.append(f"            else if value > 0.0 && value < 2000.0 {{ {v_lt2000:.2f} }}")
            rust.append(f"            else {{ {v_absent:.2f} }}")
            rust.append("        }")
        elif i == 4:
            v_lt500 = bins.get("<500", 0.0)
            v_absent = bins.get("absent", 0.0)
            rust.append(
                f"        {i} => if value > 0.0 && value < 500.0 "
                f"{{ {v_lt500:.2f} }} else {{ {v_absent:.2f} }},"
            )
        elif i == 6:
            v_0 = bins.get("0", 0.0)
            v_1_4 = bins.get("1-4", 0.0)
            v_5_14 = bins.get("5-14", 0.0)
            v_gte = bins.get(">=15", 0.0)
            rust.append(f"        {i} => {{")
            rust.append(f"            if value == 0.0 {{ {v_0:.2f} }}")
            rust.append(f"            else if value < 5.0 {{ {v_1_4:.2f} }}")
            rust.append(f"            else if value < 15.0 {{ {v_5_14:.2f} }}")
            rust.append(f"            else {{ {v_gte:.2f} }}")
            rust.append("        }")
        elif i == 7:
            v_01 = bins.get("0-1", 0.0)
            v_23 = bins.get("2-3", 0.0)
            v_gte = bins.get(">=4", 0.0)
            rust.append(
                f"        {i} => if value <= 1.0 {{ {v_01:.2f} }} "
                f"else if value <= 3.0 {{ {v_23:.2f} }} else {{ {v_gte:.2f} }},"
            )
        else:
            val = bins.get("1", 0.0)
            rust.append(f"        {i} => {val:.2f},")

    rust.append("        _ => 0.0,")
    rust.append("    }")
    rust.append("}")
    return "\n".join(rust)


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", default="events.jsonl", help="Raw events file")
    parser.add_argument("--alerts", default="alerts.ndjson", help="JSON-Lines alerts file")
    parser.add_argument("--window", type=int, default=60, help="Sliding window in seconds")
    parser.add_argument("--min-mal", type=int, default=1, help="Min malicious PIDs required")
    parser.add_argument("--out", default=None, help="Report file (default: stdout)")
    args = parser.parse_args()

    events = load_events(Path(args.events))
    malicious_pids = load_malicious_pids(Path(args.alerts))

    print(
        f"[info] {len(events)} events loaded, {len(malicious_pids)} malicious PIDs: {malicious_pids}",
        file=sys.stderr,
    )

    if len(malicious_pids) < args.min_mal:
        print(
            f"[error] fewer than {args.min_mal} malicious PID(s) in {args.alerts} — "
            "run AsyncRAT or another malware sample before calibrating.",
            file=sys.stderr,
        )
        sys.exit(1)

    window_ns = args.window * 1_000_000_000
    bv_by_pid = group_by_pid_and_window(events, window_ns)

    n_benign = sum(len(v) for pid, v in bv_by_pid.items() if pid not in malicious_pids)
    n_malicious = sum(len(v) for pid, v in bv_by_pid.items() if pid in malicious_pids)

    llr = compute_empirical_llrs(bv_by_pid, malicious_pids)

    report = generate_report(llr, n_benign, n_malicious)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"[info] report written to {args.out}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
