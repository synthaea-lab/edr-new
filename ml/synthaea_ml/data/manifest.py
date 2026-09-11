"""Baseline dataset manifest — versioned metadata sidecar next to a `baseline.jsonl`.

Every registry model records the exact dataset versions it was trained on
(rule 3 of `ml/README.md`). A raw JSONL alone does not carry version, provenance
or workload label; this module writes a `manifest.json` sidecar in the same
directory as the baseline, capturing:

- Provenance:  a stable **hash** of the hostname (not the hostname itself), the
  platform / OS version, and a free-form `capturer_ref` for human tracing.
- Workload:    a human-picked label (e.g. `desktop-user`, `dev`, `admin`,
  `server-idle`) so the per-site adaptation loop (see `docs/detection/ml.md`)
  can bin captures by role rather than by identity.
- Time range:  `capture_start` and `capture_end` in UTC ISO-8601.
- Content:     `sample_count` and `sample_sha256` — the hash locks the dataset
  version, so a model card that names this manifest cannot silently point at
  a mutated baseline.

Privacy: `host_id` is `sha256(hostname)[:12]`. Datasets shipped between team
members carry only this hash — the raw hostname never leaves the machine that
produced the capture. Anyone controlling the hostname can obviously derive the
same hash; the goal is minimum non-identifying provenance, not anonymity.

Layout convention next to a baseline:

    ml/datasets/baselines/<platform>-<host_id>-<date>/
        baseline.jsonl        # samples (format unchanged, produced by the sensor
                              # or by `capture_to_baseline.py`)
        manifest.json         # this module writes it

The manifest is fully decoupled from the sample format — `train_linux.py` and
`train_windows.py` continue to read the JSONL as they do today. Loading the
manifest is what the (upcoming) registry glue does.
"""

from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
"""Bumped only when a field changes in a way that breaks readers."""

MANIFEST_FILENAME = "manifest.json"
DEFAULT_BASELINE_FILENAME = "baseline.jsonl"

_HOST_ID_LEN = 12
"""Length in hex chars of the truncated hostname hash. 12 chars = 48 bits — enough
entropy that random collisions are effectively impossible for a fleet, short
enough to be readable in file names."""


@dataclass(frozen=True)
class Manifest:
    """Immutable in-memory representation of a `manifest.json` file."""

    schema_version: int
    host_id: str
    platform: str
    os_version: str
    workload_label: str
    capture_start: str
    capture_end: str
    sample_count: int
    sample_sha256: str
    capturer_ref: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def hash_hostname(hostname: str) -> str:
    """Deterministic 12-hex-char hash of a hostname.

    Same host produces the same `host_id` across captures — that is the point
    of the per-site adaptation loop (same-site samples cluster). Different
    hosts do not collide in any practical fleet size (48 bits, birthday-bound
    ~16M hosts for 1% collision probability).
    """
    if not hostname:
        raise ValueError("hostname must not be empty")
    return hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:_HOST_ID_LEN]


def _hash_file(path: Path) -> str:
    """SHA-256 of a file's byte contents, hex-encoded. Streamed so large baselines
    do not need to fit in memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_samples(path: Path) -> int:
    """One JSONL line = one sample. Blank lines (trailing newline, human edits)
    are skipped, matching what the trainers do."""
    n = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def _isoformat_utc(dt: datetime) -> str:
    """UTC ISO-8601 with a `Z` suffix rather than `+00:00`. The Rust side reads
    dates the same way; sticking to one spelling makes fixtures unambiguous."""
    if dt.tzinfo is None:
        raise ValueError("capture_start / capture_end must be timezone-aware")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_manifest(
    baseline_dir: Path,
    *,
    platform: str,
    os_version: str,
    workload_label: str,
    capture_start: datetime,
    capture_end: datetime,
    hostname: str | None = None,
    baseline_filename: str = DEFAULT_BASELINE_FILENAME,
    capturer_ref: str = "",
    extra: dict[str, str] | None = None,
) -> Manifest:
    """Compute and write `manifest.json` next to `baseline_dir/<baseline_filename>`.

    Args:
        baseline_dir: Directory containing the baseline JSONL. The manifest is
            written here as `manifest.json`.
        platform: `"linux"`, `"windows"`, or `"macos"`. Free-form on purpose —
            the value is what the trainers key off, and adding a new platform
            should not require a schema bump.
        os_version: Free-form OS version tag, e.g. `"22.04"` (Ubuntu),
            `"11 24H2"` (Windows), `"14.5"` (macOS).
        workload_label: Human-picked bin, e.g. `"desktop-user"`, `"dev"`,
            `"admin"`, `"server-idle"`. The per-site adaptation loop groups
            captures by this label.
        capture_start / capture_end: Timezone-aware datetimes. Written as UTC.
        hostname: If `None`, `socket.gethostname()` is used. The value is
            hashed before being stored — the raw hostname never enters the
            manifest.
        baseline_filename: Name of the samples file inside `baseline_dir`.
            Defaults to `"baseline.jsonl"`; captures that keep the original
            file name from the sensor (e.g. `"baseline_capture.jsonl"`)
            can pass it here.
        capturer_ref: Optional free-form tag for human tracing (e.g. the
            machine short name or a run number). Not hashed — do not put
            secrets here.
        extra: Additional string→string metadata to attach without bumping
            the schema. Kept namespaced under `extra` so a future
            typed field cannot collide.

    Returns:
        The `Manifest` that was just written.

    Raises:
        FileNotFoundError: If `baseline_dir/<baseline_filename>` does not exist.
        ValueError: If `capture_start`/`capture_end` are naive datetimes, or
            if `hostname` resolves to an empty string.
    """
    baseline_path = baseline_dir / baseline_filename
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline not found: {baseline_path}")

    effective_hostname = hostname if hostname is not None else socket.gethostname()
    manifest = Manifest(
        schema_version=SCHEMA_VERSION,
        host_id=hash_hostname(effective_hostname),
        platform=platform,
        os_version=os_version,
        workload_label=workload_label,
        capture_start=_isoformat_utc(capture_start),
        capture_end=_isoformat_utc(capture_end),
        sample_count=_count_samples(baseline_path),
        sample_sha256=_hash_file(baseline_path),
        capturer_ref=capturer_ref,
        extra=dict(extra) if extra else {},
    )

    manifest_path = baseline_dir / MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_manifest(baseline_dir: Path) -> Manifest:
    """Read `baseline_dir/manifest.json` and return the `Manifest`.

    Raises:
        FileNotFoundError: If `baseline_dir/manifest.json` does not exist.
        ValueError: If the file is a schema version this reader does not
            know how to decode. The bump-only-on-break policy means a
            higher schema version is a hard fail rather than a warning.
    """
    manifest_path = baseline_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported manifest schema_version: {schema_version!r} "
            f"(this reader knows {SCHEMA_VERSION})"
        )

    return Manifest(
        schema_version=schema_version,
        host_id=payload["host_id"],
        platform=payload["platform"],
        os_version=payload["os_version"],
        workload_label=payload["workload_label"],
        capture_start=payload["capture_start"],
        capture_end=payload["capture_end"],
        sample_count=int(payload["sample_count"]),
        sample_sha256=payload["sample_sha256"],
        capturer_ref=payload.get("capturer_ref", ""),
        extra=dict(payload.get("extra", {})),
    )


def verify_manifest(baseline_dir: Path) -> None:
    """Re-hash the baseline and check it matches `manifest.sample_sha256`.

    Called by the (upcoming) registry glue before a training run — a mismatch
    means the baseline was edited without regenerating the manifest, and
    training against it would silently produce a model card that names a
    dataset version it was not actually trained on.

    Raises:
        FileNotFoundError: See `load_manifest`.
        ValueError: If the recomputed hash or sample count does not match
            what the manifest records.
    """
    manifest = load_manifest(baseline_dir)
    baseline_path = baseline_dir / DEFAULT_BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline not found: {baseline_path}")

    actual_sha = _hash_file(baseline_path)
    if actual_sha != manifest.sample_sha256:
        raise ValueError(
            f"baseline hash mismatch: manifest={manifest.sample_sha256}, "
            f"actual={actual_sha} — baseline was edited without regenerating "
            f"the manifest"
        )
    actual_count = _count_samples(baseline_path)
    if actual_count != manifest.sample_count:
        raise ValueError(
            f"baseline sample count mismatch: manifest={manifest.sample_count}, "
            f"actual={actual_count}"
        )
