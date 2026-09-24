"""Lineage feature extraction for process parent-child relationship scoring.

**Must stay in sync with the Rust mirror** (crates/ml/src/features/lineage.rs): exact same
definitions, same output order. A model trained here and loaded on the Rust side will only
produce consistent scores if both implementations produce identical feature vectors for the
same ExecEvent.

These features raise evasion cost: an attacker can rewrite any single command line cheaply,
but producing a normal-looking process lineage is drastically more expensive. Classic attack
patterns include: web server→shell (webshell), office app→interpreter (malicious macro),
shell→binary from suspicious paths (dropper).
"""

from __future__ import annotations

# Shell interpreters (Unix and Windows)
SHELL_COMMS = [
    "bash",
    "sh",
    "zsh",
    "fish",
    "dash",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "pwsh",
]

# Web server process names
WEBSERVER_COMMS = [
    "httpd",
    "nginx",
    "apache2",
    "w3wp.exe",  # IIS worker process
    "w3wp",
    "node",  # Node.js web servers
    "java",  # Tomcat, Spring Boot, etc.
    "dotnet",  # .NET web apps
    "uwsgi",
    "gunicorn",
    "php-fpm",
]

# Microsoft Office applications (classic macro attack vector)
OFFICE_COMMS = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "winword",
    "excel",
    "powerpnt",
    "outlook",
]

# Legitimate system directories (Unix and Windows)
SYSTEM_PATHS = [
    "/usr/bin/",
    "/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/System/Library/",  # macOS system binaries
    "/Library/Apple/",  # macOS Apple-signed binaries
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\UUS\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
]

# Suspicious directories where malware droppers commonly execute from
SUSPICIOUS_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\AppData\\",
    "\\Temp\\",
    "\\tmp\\",
    "\\Public\\",
    "\\Downloads\\",
    "\\Desktop\\",
    "%temp%",
    "%appdata%",
]


def matches_comm_ci(comm: str | None, needles: list[str]) -> bool:
    """Check if a process comm (case-insensitive) matches any item in a list.

    Matches on basename only — "C:\\Windows\\System32\\cmd.exe" matches "cmd.exe", not "cmd".
    """
    if not comm:
        return False
    # Extract basename (handle both Unix / and Windows \ separators)
    basename = comm.split("/")[-1].split("\\")[-1]
    basename_lower = basename.lower()
    return any(basename_lower == needle.lower() for needle in needles)


def matches_path_ci(path: str | None, needles: list[str]) -> bool:
    """Check if a path (case-insensitive) contains any substring from a list."""
    if not path:
        return False
    path_lower = path.lower()
    return any(needle.lower() in path_lower for needle in needles)


def extract_features(event: dict) -> list[float]:
    """Extract 6 lineage features from an ExecEvent.

    Input event dict has optional keys:
    - parent_comm: str | None
    - parent_image_path: str | None

    All features are binary (0.0 or 1.0) for this first phase; fleet-informed rarity
    scoring is deferred to a future issue (#44 + #49 dependencies).

    Returns:
        List of 6 floats in FEATURE_NAMES order.
    """
    parent_comm = event.get("parent_comm")
    parent_image_path = event.get("parent_image_path")

    has_parent = parent_comm is not None or parent_image_path is not None
    parent_comm_is_shell = matches_comm_ci(parent_comm, SHELL_COMMS)
    parent_comm_is_webserver = matches_comm_ci(parent_comm, WEBSERVER_COMMS)
    parent_comm_is_office = matches_comm_ci(parent_comm, OFFICE_COMMS)
    parent_path_is_system = matches_path_ci(parent_image_path, SYSTEM_PATHS)
    parent_path_is_suspicious = matches_path_ci(parent_image_path, SUSPICIOUS_PATHS)

    return [
        1.0 if has_parent else 0.0,
        1.0 if parent_comm_is_shell else 0.0,
        1.0 if parent_comm_is_webserver else 0.0,
        1.0 if parent_comm_is_office else 0.0,
        1.0 if parent_path_is_system else 0.0,
        1.0 if parent_path_is_suspicious else 0.0,
    ]


FEATURE_NAMES = [
    "has_parent_lineage",
    "parent_comm_is_shell",
    "parent_comm_is_webserver",
    "parent_comm_is_office",
    "parent_path_is_system",
    "parent_path_is_suspicious",
]
