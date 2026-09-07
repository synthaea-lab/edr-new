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

# Current LLRs (hand-calibrated) — reference for comparison.
LLR_ACTUELS = [0.0, 0.3, 0.7, "0.8/<500ms,0.3/<2s", 0.6, 2.0, "0.1*n,max1.5", 0.5, 1.5]

# Laplace smoothing — avoids log(0) when a bin is empty in a small sample.
LAPLACE_ALPHA = 0.5


# ── Parsing ────────────────────────────────────────────────────────────────────


def _normaliser_event(e: dict) -> dict:
    """Normalise le format edr-new (meta imbriqué) vers le format flat attendu.

    Nouveau format (edr-new) :
        {"type": "exec",      "meta": {"pid": ..., "timestamp_ns": ...}, "cmdline": ...}
        {"type": "connect",   "meta": {...}, "daddr_v4": [...], "dport": ..., "is_ipv6": ...}
        {"type": "file_open", "meta": {...}, "flags": ..., "path": ...}
    Format flat attendu :
        {"type": "exec",     "pid": ..., "ts_ns": ..., "cmdline": ...}
        {"type": "connect",  "pid": ..., "ts_ns": ..., "daddr_v4": [...], "dport": ...}
        {"type": "fileopen", "pid": ..., "ts_ns": ..., "flags": ...}
    """
    meta = e.get("meta")
    if meta is not None:
        e = dict(e)  # shallow copy — ne pas muter l'original
        e["pid"] = meta.get("pid", 0)
        e["ts_ns"] = meta.get("timestamp_ns", 0)
        if e.get("type") == "file_open":
            e["type"] = "fileopen"
        # Normalise daddr string → daddr_v4 list[int] (format NAT vs Host-Only)
        if "daddr" in e and "daddr_v4" not in e:
            try:
                e["daddr_v4"] = [int(b) for b in e["daddr"].split(".")]
            except (ValueError, AttributeError):
                e["daddr_v4"] = [0, 0, 0, 0]
    return e


def charger_events(path: Path) -> list[dict]:
    """Loads the raw events from events.jsonl."""
    events = []
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(_normaliser_event(json.loads(line)))
                except json.JSONDecodeError as e:
                    print(f"[warn] events.jsonl line {i} invalid: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(f"[error] {path} not found — run the agent first.", file=sys.stderr)
        sys.exit(1)
    return events


def charger_pids_malveillants(path: Path) -> set[int]:
    """Extracts the alerted PIDs from alerts.ndjson."""
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
                # Extract pid=... from the alert message
                for token in msg.split():
                    if token.startswith("pid="):
                        with contextlib.suppress(ValueError):
                            pids.add(int(token[4:].rstrip(",")))
            except json.JSONDecodeError:
                pass
    return pids


# ── Sliding windowing ──────────────────────────────────────────────────────────


def grouper_par_pid_et_fenetre(events: list[dict], window_ns: int) -> dict[int, list[list[float]]]:
    """Groups the events by PID, slices them into windows of window_ns, and returns
    the BehaviorVectors per PID (several vectors if the PID has events across
    several disjoint windows)."""
    # Group by pid
    par_pid: dict[int, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("type") in ("exec", "connect", "fileopen"):
            par_pid[e["pid"]].append(e)

    bv_par_pid: dict[int, list[list[float]]] = {}

    for pid, pid_events in par_pid.items():
        pid_events.sort(key=lambda e: e["ts_ns"])
        if not pid_events:
            continue
        # Sliding windows: slice the events into chunks of window_ns
        vecteurs = []
        debut = pid_events[0]["ts_ns"]
        fenetre: list[dict] = []
        for e in pid_events:
            if e["ts_ns"] - debut > window_ns:
                if fenetre:
                    vecteurs.append(extract_behavior_features(fenetre))
                debut = e["ts_ns"]
                fenetre = [e]
            else:
                fenetre.append(e)
        if fenetre:
            vecteurs.append(extract_behavior_features(fenetre))
        bv_par_pid[pid] = vecteurs

    return bv_par_pid


# ── Calibration ────────────────────────────────────────────────────────────────


def _discretiser(feature_idx: int, value: float) -> str:
    """Discretizes a continuous feature into bins for the LLR computation.
    Binary features (0.0/1.0) are left as-is.
    Continuous features are split into intervals."""
    if feature_idx in (0, 1, 2, 5, 8):
        # Binary
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


def calculer_llr_empiriques(
    bv_par_pid: dict[int, list[list[float]]],
    pids_malveillants: set[int],
    alpha: float = LAPLACE_ALPHA,
) -> dict[int, dict[str, float]]:
    """Computes the empirical LLRs for each feature.

    Returns a dict feature_idx → {bin → llr}.
    """
    # Count occurrences per class
    benin: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    malveil: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    n_benin = 0
    n_malveil = 0

    for pid, vecteurs in bv_par_pid.items():
        classe = malveil if pid in pids_malveillants else benin
        if pid in pids_malveillants:
            n_malveil += len(vecteurs)
        else:
            n_benin += len(vecteurs)
        for bv in vecteurs:
            for i, val in enumerate(bv):
                bin_key = _discretiser(i, val)
                classe[i][bin_key] += 1.0

    if n_benin == 0 or n_malveil == 0:
        print(
            f"[warn] n_benin={n_benin}, n_malveil={n_malveil} — not enough data to calibrate.",
            file=sys.stderr,
        )
        return {}

    llr: dict[int, dict[str, float]] = {}
    all_bins_per_feat: dict[int, set[str]] = {}

    for i in range(9):
        all_bins = set(benin[i].keys()) | set(malveil[i].keys())
        all_bins_per_feat[i] = all_bins
        total_b = sum(benin[i].values()) + alpha * len(all_bins)
        total_m = sum(malveil[i].values()) + alpha * len(all_bins)
        llr[i] = {}
        for b in all_bins:
            p_b = (benin[i].get(b, 0.0) + alpha) / total_b
            p_m = (malveil[i].get(b, 0.0) + alpha) / total_m
            llr[i][b] = math.log(p_m / p_b)

    return llr


# ── Report ─────────────────────────────────────────────────────────────────────


def generer_rapport(
    llr: dict[int, dict[str, float]],
    n_benin: int,
    n_malveil: int,
) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("LLR CALIBRATION REPORT — Synthaea EDR")
    lines.append(f"Benign samples    : {n_benin}")
    lines.append(f"Malicious samples : {n_malveil}")
    lines.append("=" * 70)
    lines.append("")

    for i, name in enumerate(FEATURE_NAMES):
        if i not in llr:
            continue
        lines.append(f"[{i}] {name}")
        lines.append(f"    Current LLR : {LLR_ACTUELS[i]}")
        lines.append("    Empirical LLRs per bin:")
        for bin_key, val in sorted(llr[i].items()):
            lines.append(f"        {bin_key:12s} → {val:+.3f}")
        lines.append("")

    lines.append("─" * 70)
    lines.append("SUGGESTED RUST CODE for log_likelihood_ratio():")
    lines.append("─" * 70)
    lines.append(generer_rust(llr))
    return "\n".join(lines)


def generer_rust(llr: dict[int, dict[str, float]]) -> str:
    """Generates the Rust match block for log_likelihood_ratio()."""
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
            # Binary feature
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
            # Fallback: take the LLR of bin "1" if binary, else 0
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

    events = charger_events(Path(args.events))
    pids_mal = charger_pids_malveillants(Path(args.alerts))

    print(
        f"[info] {len(events)} events loaded, {len(pids_mal)} malicious PIDs: {pids_mal}",
        file=sys.stderr,
    )

    if len(pids_mal) < args.min_mal:
        print(
            f"[error] fewer than {args.min_mal} malicious PID(s) in {args.alerts} — "
            "run AsyncRAT or another malware sample before calibrating.",
            file=sys.stderr,
        )
        sys.exit(1)

    window_ns = args.window * 1_000_000_000
    bv_par_pid = grouper_par_pid_et_fenetre(events, window_ns)

    # Counts for the report
    n_benin = sum(len(v) for pid, v in bv_par_pid.items() if pid not in pids_mal)
    n_malveil = sum(len(v) for pid, v in bv_par_pid.items() if pid in pids_mal)

    llr = calculer_llr_empiriques(bv_par_pid, pids_mal)

    rapport = generer_rapport(llr, n_benin, n_malveil)

    if args.out:
        Path(args.out).write_text(rapport, encoding="utf-8")
        print(f"[info] report written to {args.out}", file=sys.stderr)
    else:
        print(rapport)


if __name__ == "__main__":
    main()
