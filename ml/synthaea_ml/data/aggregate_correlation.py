"""Aggregates `events.jsonl` into a training set for the correlation scorer (2nd ML scorer).

Reads a raw event log (`events.jsonl`, produced by `edr-cli capture-events` or
`edr-cli run`) and produces **one feature vector per PID**: for each PID, the window is
reconstructed as it would be at its last appearance — all of its events within
`[last_ts - window, last_ts]` — mirroring the eviction semantics of
`synthaea_correlator::EventBus` (`cutoff = latest_ns - window_ns`, keep `ts >= cutoff`).

One vector per PID (not one per fixed time step): decision of 2026-09-02 with Nikolas —
the most complete instant for a PID, and the simplest to align with the Rust side.

This script does **not** do a benign/malicious split: the 2nd scorer's Isolation Forest is
unsupervised, it trains on a benign baseline alone (cf. `train_correlation.py`).
`calibrate_llr.py` (Bayesian filter) is the one that needs the split — don't mix them up.

Output: JSON-Lines, one `{"pid", "features": [...], "feature_names": [...]}` object per line.

Usage:
    python aggregate_correlation.py [--events events.jsonl]
                                    [--out data/correlation_train.jsonl]
                                    [--window 60] [--min-events 1]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from synthaea_ml.features.correlation import FEATURE_NAMES, extract_features

EVENT_TYPES = ("exec", "connect", "fileopen")


def charger_events(path: Path) -> list[dict]:
    """Loads the usable events from events.jsonl (exec/connect/fileopen)."""
    events: list[dict] = []
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"[warn] {path} line {i} invalid: {exc}", file=sys.stderr)
                    continue
                if e.get("type") in EVENT_TYPES and "pid" in e and "ts_ns" in e:
                    events.append(e)
    except FileNotFoundError:
        print(
            f"[error] {path} not found — run `edr-cli capture-events` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return events


def vecteurs_par_pid(events: list[dict], window_ns: int, min_events: int) -> list[dict]:
    """One `extract_features` per PID, over its window at its last appearance."""
    par_pid: dict[int, list[dict]] = defaultdict(list)
    for e in events:
        par_pid[e["pid"]].append(e)

    out: list[dict] = []
    for pid, pid_events in sorted(par_pid.items()):
        pid_events.sort(key=lambda e: e["ts_ns"])
        last_ts = pid_events[-1]["ts_ns"]
        cutoff = last_ts - window_ns
        fenetre = [e for e in pid_events if e["ts_ns"] >= cutoff]
        if len(fenetre) < min_events:
            continue
        feats = extract_features(fenetre, pid)
        out.append({"pid": pid, "features": feats, "feature_names": list(FEATURE_NAMES)})
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--events", type=Path, default=Path("events.jsonl"))
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "data" / "correlation_train.jsonl",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=60.0,
        help="correlation window in seconds (default 60 = CorrelationEngine::new)",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=1,
        help="skip PIDs with fewer than N events in the window",
    )
    args = parser.parse_args()

    events = charger_events(args.events)
    if not events:
        print("[error] no usable events in the log.", file=sys.stderr)
        sys.exit(1)

    vecteurs = vecteurs_par_pid(events, int(args.window * 1_000_000_000), args.min_events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for v in vecteurs:
            f.write(json.dumps(v) + "\n")

    print(
        f"{len(events)} events → {len(vecteurs)} vectors "
        f"(1 per PID, window {args.window:g}s, min-events {args.min_events}) → {args.out}"
    )


if __name__ == "__main__":
    main()
