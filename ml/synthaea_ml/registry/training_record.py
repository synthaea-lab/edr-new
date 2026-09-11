"""Training record — the machine-parsable half of a model card.

Every registry entry has a human-readable `card.md` alongside its `model.onnx`
(see `ml/registry/README.md`). The card documents purpose, metrics, FP rate,
scenario-replay results and known limitations for a reader.

`training.json` sits next to it, capturing exactly what a machine needs to
answer "was this model trained on the datasets its card claims?" — mechanically
enforcing rule 3 of `ml/README.md`. The (upcoming) trainer glue writes it at
the end of a run, and the (also upcoming) release gate refuses to ship a model
whose recorded dataset versions cannot be re-verified against the baselines
they name.

Layout inside a version directory:

    ml/registry/<model>/<version>/
        model.onnx        # the artifact
        card.md           # for humans
        training.json     # for machines — this module writes/reads it

The record binds each `DatasetVersion` by its `baseline_sha256` (the content
hash the manifest already publishes), not by path — a dataset can move on
disk without invalidating the record, but a mutated baseline cannot pass
`verify_training_record` even if it kept the same path.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from synthaea_ml.data.manifest import (
    DEFAULT_BASELINE_FILENAME,
    load_manifest,
    verify_manifest,
)

SCHEMA_VERSION = 1
"""Bumped only when a field changes in a way that breaks readers."""

TRAINING_RECORD_FILENAME = "training.json"


@dataclass(frozen=True)
class DatasetVersion:
    """One entry in `TrainingRecord.dataset_versions`.

    `baseline_sha256` is the manifest's `sample_sha256` (locking the sample
    file content), and `sample_count` is the manifest's `sample_count`
    (a cheap cross-check that catches a truncated baseline before the
    slower hash comparison does).
    """

    name: str
    baseline_sha256: str
    sample_count: int


@dataclass(frozen=True)
class TrainingRecord:
    """The `training.json` sidecar of a registry model version."""

    schema_version: int
    trained_at: str
    training_script: str
    dataset_versions: list[DatasetVersion]
    hyperparameters: dict[str, object] = field(default_factory=dict)
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        d = asdict(self)
        # dataclass asdict expands frozen children fine; make sure the type is a plain list
        d["dataset_versions"] = [asdict(v) for v in self.dataset_versions]
        return d


def default_dataset_name(baseline_dir: Path) -> str:
    """Derive a human-legible dataset name from the manifest next to a baseline.

    Convention: `<platform>__<workload_label>__<host_id>__<YYYY-MM-DD>`.
    Double underscores separate the four coordinates so a workload label
    containing a single hyphen (`desktop-user`) does not become ambiguous.
    The date is `capture_start[:10]` — day-level granularity is what we bin
    by; sub-day precision belongs in the manifest, not in the name.

    Raises:
        FileNotFoundError: If the manifest is missing.
    """
    manifest = load_manifest(baseline_dir)
    capture_day = manifest.capture_start[:10]  # "2026-09-11" from ISO string
    return (
        f"{manifest.platform}__{manifest.workload_label}__{manifest.host_id}__{capture_day}"
    )


def dataset_version_from_manifest(
    baseline_dir: Path,
    *,
    name: str | None = None,
) -> DatasetVersion:
    """Verify the baseline against its manifest and return a `DatasetVersion`.

    A caller who reads this back — the release gate or a re-training tool —
    can trust `baseline_sha256` to point at unmutated content because we
    just re-hashed the file to check.

    Args:
        baseline_dir: Directory containing `baseline.jsonl` and `manifest.json`.
        name: Optional override. Defaults to `default_dataset_name(baseline_dir)`.

    Raises:
        FileNotFoundError: If baseline or manifest is missing.
        ValueError: If the baseline hash or sample count no longer matches
            the manifest (see `verify_manifest`).
    """
    verify_manifest(baseline_dir)
    manifest = load_manifest(baseline_dir)
    return DatasetVersion(
        name=name if name is not None else default_dataset_name(baseline_dir),
        baseline_sha256=manifest.sample_sha256,
        sample_count=manifest.sample_count,
    )


def write_training_record(
    model_dir: Path,
    *,
    training_script: str,
    dataset_versions: list[DatasetVersion],
    hyperparameters: dict[str, object] | None = None,
    trained_at: datetime | None = None,
    extra: dict[str, str] | None = None,
) -> TrainingRecord:
    """Write `model_dir/training.json`.

    Args:
        model_dir: The registry version directory, e.g.
            `ml/registry/cmdline-iforest-linux/0.2.0/`. Must already exist.
        training_script: Path-like string identifying the entry point,
            e.g. `"synthaea_ml/training/train_linux.py"`. Recorded for
            traceability, not resolved.
        dataset_versions: One entry per baseline the run consumed. Callers
            build these via `dataset_version_from_manifest` so each has a
            re-verifiable hash before it reaches this function.
        hyperparameters: The knobs the run was configured with. Not
            interpreted here — round-trip only.
        trained_at: Timezone-aware datetime, normalised to UTC. Defaults
            to `datetime.now(UTC)`.
        extra: Optional string->string metadata, namespaced under `extra`
            so a future typed field cannot collide.

    Returns:
        The `TrainingRecord` that was just written.

    Raises:
        FileNotFoundError: If `model_dir` does not exist.
        ValueError: If `trained_at` is naive, or `dataset_versions` is empty
            (a training run with no dataset would not lock anything).
    """
    if not model_dir.is_dir():
        raise FileNotFoundError(f"model_dir does not exist: {model_dir}")
    if not dataset_versions:
        raise ValueError("dataset_versions must not be empty")
    if trained_at is None:
        trained_at = datetime.now(UTC)
    if trained_at.tzinfo is None:
        raise ValueError("trained_at must be timezone-aware")

    record = TrainingRecord(
        schema_version=SCHEMA_VERSION,
        trained_at=trained_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        training_script=training_script,
        dataset_versions=list(dataset_versions),
        hyperparameters=dict(hyperparameters) if hyperparameters else {},
        extra=dict(extra) if extra else {},
    )

    (model_dir / TRAINING_RECORD_FILENAME).write_text(
        json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return record


def load_training_record(model_dir: Path) -> TrainingRecord:
    """Read `model_dir/training.json`.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the schema version is not one this reader knows.
    """
    path = model_dir / TRAINING_RECORD_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"training record not found: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported training.json schema_version: {schema_version!r} "
            f"(this reader knows {SCHEMA_VERSION})"
        )

    return TrainingRecord(
        schema_version=schema_version,
        trained_at=payload["trained_at"],
        training_script=payload["training_script"],
        dataset_versions=[
            DatasetVersion(**v) for v in payload["dataset_versions"]
        ],
        hyperparameters=dict(payload.get("hyperparameters", {})),
        extra=dict(payload.get("extra", {})),
    )


def verify_training_record(model_dir: Path, baselines_root: Path) -> None:
    """Re-verify every `DatasetVersion` in `training.json` against the on-disk
    baselines under `baselines_root`.

    The release gate calls this before shipping a model: every referenced
    baseline must still exist on disk under `baselines_root/<name>/` and
    still hash to `baseline_sha256`. Any mismatch is a hard fail — the model
    was trained on data that no longer exists in the form claimed.

    Args:
        model_dir: The registry version directory.
        baselines_root: The parent directory holding baselines by name, e.g.
            `ml/datasets/baselines/`. Each `DatasetVersion.name` is looked up
            as `baselines_root/<name>/`.

    Raises:
        FileNotFoundError: If the training record itself, or any referenced
            baseline directory or its manifest, is missing.
        ValueError: If a referenced baseline's current hash or sample count
            no longer matches what the record locked.
    """
    record = load_training_record(model_dir)
    for dv in record.dataset_versions:
        baseline_dir = baselines_root / dv.name
        if not baseline_dir.is_dir():
            raise FileNotFoundError(
                f"dataset {dv.name!r} not found under {baselines_root}"
            )
        baseline_path = baseline_dir / DEFAULT_BASELINE_FILENAME
        if not baseline_path.exists():
            raise FileNotFoundError(
                f"baseline missing inside {baseline_dir}: expected {DEFAULT_BASELINE_FILENAME}"
            )
        # verify_manifest already checks baseline vs manifest; we then check
        # the manifest's hash matches what the training record locked.
        verify_manifest(baseline_dir)
        current = load_manifest(baseline_dir)
        if current.sample_sha256 != dv.baseline_sha256:
            raise ValueError(
                f"dataset {dv.name!r} hash mismatch: "
                f"training record locked {dv.baseline_sha256}, "
                f"current baseline is {current.sample_sha256}"
            )
        if current.sample_count != dv.sample_count:
            raise ValueError(
                f"dataset {dv.name!r} sample_count mismatch: "
                f"training record locked {dv.sample_count}, "
                f"current baseline has {current.sample_count}"
            )
