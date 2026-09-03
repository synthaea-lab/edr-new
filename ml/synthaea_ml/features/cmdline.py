"""Command-line feature extraction for ML scoring (Isolation Forest).

Seven features in total. The first three (length, entropy, suspicious tokens) are from the
initial MVP (docs/PLAN.md, weeks 6-7). The next four were added later to better separate
Docker/containerd noise (very long but benign command lines, many arguments) from real signal
(an isolated encoded payload, a shell pipe syntax) — see the limitation documented in
docs/PLAN.md (week 8/aarch64) about the generalization of the 3 original features.

**Must stay in sync with the Rust mirror** (agent/edr-ml/src/features.rs): exact same
definitions, same output order. A model trained here and loaded on the Rust side will only
produce consistent scores if both implementations produce identical feature vectors for the
same command line.
"""

import math
from collections import Counter

# Matched as-is (substrings), against the raw command line (including argv `\0` separators,
# cf. edr_schema::ExecEvent::cmdline_str on the Rust side) — no tokenization, to stay strictly
# identical to the Rust behavior (`str::contains`).
SUSPICIOUS_TOKENS = [
    "base64",
    "-d",
    "-D",
    "--decode",
    "chmod +x",
    "/dev/tcp",
    "nc ",
    "| sh",
    "| bash",
    "|sh",
    "|bash",
]

# Shell metacharacters (piping, redirection, substitution, subshell) — generalizes beyond the
# hard-coded `SUSPICIOUS_TOKENS` list, which only covers specific patterns.
SHELL_METACHARS = "|;&$`()<>"

# Windows directories considered suspicious for an executable — a binary in
# AppData/Temp/Public/Downloads has no business running under normal conditions.
SUSPICIOUS_WIN_PATHS = [
    "\\AppData\\",
    "\\Temp\\",
    "\\tmp\\",
    "\\Public\\",
    "\\Downloads\\",
    "\\Desktop\\",
    "%temp%",
    "%appdata%",
]

# Legitimate Windows directories for system executables.
LEGIT_WIN_PATHS = [
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\UUS\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
    "\\ProgramData\\Microsoft\\",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def suspicious_token_count(cmdline: str) -> int:
    return sum(1 for tok in SUSPICIOUS_TOKENS if tok in cmdline)


def token_count(cmdline: str) -> int:
    return sum(1 for tok in cmdline.split("\0") if tok)


def max_token_length(cmdline: str) -> int:
    tokens = [tok for tok in cmdline.split("\0") if tok]
    return max((len(tok) for tok in tokens), default=0)


def shell_metachar_count(cmdline: str) -> int:
    return sum(1 for c in cmdline if c in SHELL_METACHARS)


def digit_ratio(cmdline: str) -> float:
    # ASCII digits only ("0"-"9"), NOT str.isdigit(): isdigit() accepts Unicode digits
    # ("²", "٣"...) that the Rust mirror (char::is_ascii_digit) does not count — parity is
    # locked by tests/data/features_golden.jsonl. No effect on the committed baselines
    # (100% ASCII).
    if not cmdline:
        return 0.0
    return sum(1 for c in cmdline if "0" <= c <= "9") / len(cmdline)


def is_suspicious_win_path(cmdline: str) -> float:
    """1.0 if the path contains a suspicious directory (AppData, Temp, Desktop...),
    0.0 otherwise."""
    cmdline_lower = cmdline.lower()
    return 1.0 if any(p.lower() in cmdline_lower for p in SUSPICIOUS_WIN_PATHS) else 0.0


def is_legit_win_path(cmdline: str) -> float:
    """1.0 if the path is in a legitimate system directory (System32, Program Files...),
    0.0 otherwise."""
    cmdline_lower = cmdline.lower()
    return 1.0 if any(p.lower() in cmdline_lower for p in LEGIT_WIN_PATHS) else 0.0


def extract_features(cmdline: str) -> list[float]:
    return [
        float(len(cmdline)),
        shannon_entropy(cmdline),
        float(suspicious_token_count(cmdline)),
        float(token_count(cmdline)),
        float(max_token_length(cmdline)),
        float(shell_metachar_count(cmdline)),
        digit_ratio(cmdline),
        is_suspicious_win_path(cmdline),
        is_legit_win_path(cmdline),
    ]


FEATURE_NAMES = [
    "length",
    "entropy",
    "suspicious_token_count",
    "token_count",
    "max_token_length",
    "shell_metachar_count",
    "digit_ratio",
    "is_suspicious_win_path",
    "is_legit_win_path",
]
