"""Verifies an exported ONNX model behaves sanely under `onnxruntime` before it ships —
the validation bridge between the training entry points (scikit-learn) and the agent's
inference (`ort` in crates/ml).

The training scripts already assert ONNX-vs-scikit-learn parity at export time (they
still hold the fitted estimator). This runs on a registry model with no estimator in
hand, so it checks the properties the agent relies on regardless of how the model was
produced:

- the model exposes a ``scores`` output;
- every score is finite (no NaN/inf reaching the correlator's belief update);
- inference is deterministic (same input, same output — twice);
- when the model also emits ``label``, its sign agrees with ``scores`` (``label == -1``
  iff ``score < 0``), the contract `IsolationForest.predict` guarantees.

## Provenance (release gate)

In addition to the ONNX-runtime checks above, each registry version directory is
required to carry a `training.json` recording the datasets it was trained on
(see `synthaea_ml.registry.training_record`, rule 3 of `ml/README.md`). When
present, `verify_training_record` is called: every referenced baseline must still
exist under `ml/datasets/baselines/` and still hash to the value the record locked.

Pre-#44 legacy entries (`cmdline-iforest-{linux,windows}/0.1.0/`) predate the
training record and have no `training.json`. In interactive/dev mode they pass with
a warning. In strict mode, they fail — that is what release CI runs. Toggle with the
`SYNTHAEA_STRICT_PROVENANCE=1` environment variable so the CLI stays compatible.

Exits non-zero on the first violation.

Usage: python -m synthaea_ml.export.verify_onnx [model.onnx ...]
Defaults to every `model.onnx` under ml/registry/.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.registry.training_record import (
    TRAINING_RECORD_FILENAME,
    load_training_record,
    verify_training_record,
)
from synthaea_ml.training.train_linux import SANITY_CHECK_SAMPLES as _LINUX_SAMPLES
from synthaea_ml.training.train_windows import SANITY_CHECK_SAMPLES as _WINDOWS_SAMPLES

REGISTRY = Path(__file__).resolve().parents[2] / "registry"
BASELINES = Path(__file__).resolve().parents[2] / "datasets" / "baselines"

_STRICT_PROVENANCE_ENV = "SYNTHAEA_STRICT_PROVENANCE"

_PLATFORM_SAMPLES: dict[str, dict[str, str]] = {
    "linux": _LINUX_SAMPLES,
    "windows": _WINDOWS_SAMPLES,
}


class VerificationError(AssertionError):
    """A shipped model failed a property the agent depends on."""


def _platform_from_training_record(model_dir: Path) -> str | None:
    """Read the platform a model was trained on off its `training.json`, if any.

    `DatasetVersion.name` follows `default_dataset_name`'s
    `<platform>__<workload_label>__<host_id>__<date>` convention — the platform
    is its first component. Returns `None` when there's no training record
    (pre-#44 legacy entry) or its platform isn't one we have sanity samples for.
    """
    if not (model_dir / TRAINING_RECORD_FILENAME).exists():
        return None
    record = load_training_record(model_dir)
    if not record.dataset_versions:
        return None
    platform = record.dataset_versions[0].name.split("__", 1)[0]
    return platform if platform in _PLATFORM_SAMPLES else None


def _platform_from_model_dir(model_dir: Path) -> str | None:
    """Fall back to the registry family directory name, e.g.
    `cmdline-iforest-linux/0.1.0` -> `"linux"`. Brittle (a naming convention,
    not data) but it is what every pre-#44 legacy entry has to go on."""
    family = model_dir.parent.name
    for platform in _PLATFORM_SAMPLES:
        if family.endswith(f"-{platform}"):
            return platform
    return None


def sanity_samples_for(model_dir: Path) -> dict[str, str]:
    """Pick the sanity-check command lines matching the platform `model_dir` targets.

    Prefers the training record's dataset platform (works once every registry
    entry has a `training.json`, see #44); falls back to the registry directory
    naming convention for legacy entries that predate it. Deliberately does not
    default to either platform's samples when both signals are inconclusive —
    silently scoring a model against the wrong platform's samples is exactly
    the bug this function exists to fix.

    Raises:
        VerificationError: If neither the training record nor the directory
            name resolves to a known platform.
    """
    platform = _platform_from_training_record(model_dir) or _platform_from_model_dir(model_dir)
    if platform is None:
        raise VerificationError(
            f"{model_dir}: cannot determine platform (no training.json dataset "
            f"platform, and directory name doesn't end in -{'/-'.join(_PLATFORM_SAMPLES)})"
        )
    return _PLATFORM_SAMPLES[platform]


def verify(model_path: Path) -> None:
    session = ort.InferenceSession(str(model_path))
    input_name = session.get_inputs()[0].name
    output_names = [o.name for o in session.get_outputs()]
    print(f"{model_path}: input {input_name}, outputs {output_names}")

    if "scores" not in output_names:
        raise VerificationError(f"{model_path}: no 'scores' output (got {output_names})")

    samples = sanity_samples_for(model_path.parent)
    feats = np.array(
        [extract_features(cmdline) for cmdline in samples.values()],
        dtype=np.float32,
    )
    run1 = dict(zip(output_names, session.run(None, {input_name: feats}), strict=True))
    run2 = dict(zip(output_names, session.run(None, {input_name: feats}), strict=True))

    scores = np.asarray(run1["scores"]).reshape(-1)
    if not np.all(np.isfinite(scores)):
        raise VerificationError(f"{model_path}: non-finite score(s): {scores}")

    if not np.array_equal(scores, np.asarray(run2["scores"]).reshape(-1)):
        raise VerificationError(f"{model_path}: inference is not deterministic")

    if "label" in run1:
        labels = np.asarray(run1["label"]).reshape(-1)
        anomalous_label = labels == -1
        anomalous_score = scores < 0
        if not np.array_equal(anomalous_label, anomalous_score):
            raise VerificationError(
                f"{model_path}: label/score sign disagree — "
                f"labels={labels.tolist()} scores={scores.round(4).tolist()}"
            )

    for (label, cmdline), score in zip(samples.items(), scores, strict=True):
        verdict = "ANOMALY" if score < 0 else "normal"
        print(f"  {label}: score={score:+.4f} -> {verdict}")
    print(f"  ok: {len(scores)} samples, finite, deterministic, label/score consistent")


def verify_provenance(model_dir: Path, baselines_root: Path, *, strict: bool) -> None:
    """Check the training record next to a registry model matches the baselines on disk.

    A model_dir without `training.json` is a pre-#44 legacy entry: passes with a
    warning in interactive mode, fails in strict mode. When `training.json` is
    present, `verify_training_record` re-checks every referenced baseline (existence,
    manifest verify, sample_sha256 match) — the release gate that rule 3 of
    `ml/README.md` mandates.

    Raises:
        VerificationError: In strict mode when no `training.json` is found, or
            whenever `verify_training_record` raises.
    """
    training_record = model_dir / TRAINING_RECORD_FILENAME
    if not training_record.exists():
        msg = (
            f"{model_dir}: no {TRAINING_RECORD_FILENAME} — pre-#44 legacy entry, "
            f"provenance not verified"
        )
        if strict:
            raise VerificationError(msg)
        print(f"WARN {msg}", file=sys.stderr)
        return

    try:
        verify_training_record(model_dir, baselines_root)
    except (FileNotFoundError, ValueError) as e:
        # The two exceptions the release gate exists to raise, funneled through
        # our own type so main()'s single except clause catches them.
        raise VerificationError(f"{model_dir}: provenance check failed — {e}") from e
    print("  provenance: ok (training.json + baselines match)")


def _is_strict_provenance() -> bool:
    return os.environ.get(_STRICT_PROVENANCE_ENV, "").lower() in ("1", "true", "yes")


def main() -> None:
    models = [Path(p) for p in sys.argv[1:]] or sorted(REGISTRY.glob("*/*/model.onnx"))
    if not models:
        sys.exit(f"no model.onnx found under {REGISTRY} and none given on the command line")
    strict = _is_strict_provenance()
    failures = 0
    for model in models:
        try:
            verify(model)
            verify_provenance(model.parent, BASELINES, strict=strict)
        except VerificationError as e:
            print(f"FAIL {e}", file=sys.stderr)
            failures += 1
    if failures:
        sys.exit(f"{failures}/{len(models)} model(s) failed verification")


if __name__ == "__main__":
    main()
