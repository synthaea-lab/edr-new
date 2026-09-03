"""Converts a raw `edr-cli run` log (stdout, `ExecEvent { ... }` lines) into a benign JSONL
baseline consumable by train.py.

Context: week 8 (docs/PLAN.md) — replaces the 61-line synthetic baseline with a real capture
of lab activity. The log is the `{event:?}` format produced by
edr-agent/src/main.rs::println!("{event:?}") — not native JSON, hence the regex parsing below
rather than direct deserialization.

Usage: `python3 capture_to_baseline.py <log_file> [--out data/baseline_benign.jsonl]`
"""

import argparse
import json
import re
from pathlib import Path

# Captures the content of cmdline: "..." — the value may contain quotes/backslashes escaped
# by Rust's Debug (\", \\, \0, \n, \r, \t), never an unescaped quote.
EXEC_EVENT_RE = re.compile(
    r'ExecEvent \{ pid: (\d+), ppid: (\d+), comm: "(?:[^"\\]|\\.)*", '
    r'cmdline: "((?:[^"\\]|\\.)*)" \}'
)

# Same escapes as produced by Rust's Debug for a &str (see char::escape_debug):
# \0, \n, \r, \t, \\, \" — a generic \u{XX} is not handled here (not expected on a normal
# shell command line; extend if parsing misses lines containing exotic bytes).
_UNESCAPE = {"0": "\0", "n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}


def unescape_rust_debug_str(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in _UNESCAPE:
            out.append(_UNESCAPE[s[i + 1]])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_argv(cmdline: str) -> list[str]:
    """cmdline is `\\0`-separated with a trailing `\\0` (see ExecEvent::cmdline_str on the
    Rust side)."""
    tokens = cmdline.split("\0")
    return [t for t in tokens[:-1]] if tokens and tokens[-1] == "" else [t for t in tokens if t]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", type=Path)
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).parent / "data" / "baseline_benign.jsonl"
    )
    args = parser.parse_args()

    text = args.log_file.read_text(encoding="utf-8", errors="replace")
    seen: set[tuple[str, ...]] = set()
    argv_list: list[list[str]] = []

    for match in EXEC_EVENT_RE.finditer(text):
        raw_cmdline = unescape_rust_debug_str(match.group(3))
        argv = extract_argv(raw_cmdline)
        if not argv:
            continue
        key = tuple(argv)
        if key in seen:
            continue
        seen.add(key)
        argv_list.append(argv)

    with args.out.open("w", encoding="utf-8") as f:
        for argv in argv_list:
            f.write(json.dumps({"argv": argv}) + "\n")

    print(f"{len(argv_list)} unique benign command lines written to {args.out}")


if __name__ == "__main__":
    main()
