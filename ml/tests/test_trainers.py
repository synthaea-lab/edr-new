"""End-to-end tests for the Linux and Windows trainers.

The trainers are what mechanically enforce rule 3 of ml/README.md: they refuse
to run against a baseline that does not verify against its manifest, and every
run they do complete emits a `training.json` next to `model.onnx` that names
the exact `DatasetVersion` the model was trained on.

These tests exercise the full pipeline (manifest -> load -> train -> export -> record)
because the point is that the pieces fit together. IsolationForest fits in a
fraction of a second on the tiny corpora used here.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import write_manifest
from synthaea_ml.registry.training_record import load_training_record
from synthaea_ml.training import train_linux, train_windows

_START = datetime(2026, 9, 11, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 9, 11, 11, 0, 0, tzinfo=UTC)

# Small but non-degenerate corpora - enough distinct rows that IsolationForest has
# something to fit against without the boundary collapsing to a single sign.
_LINUX_SAMPLES = [
    {"argv": ["whoami"]},
    {"argv": ["id"]},
    {"argv": ["ls", "-la"]},
    {"argv": ["bash", "/tmp/x.sh"]},
    {"argv": ["cat", "/etc/hosts"]},
    {"argv": ["ps", "-ef"]},
    {"argv": ["uname", "-a"]},
    {"argv": ["/usr/bin/env", "python3"]},
    {"argv": ["curl", "-fSL", "http://x/y"]},
    {"argv": ["grep", "-r", "foo", "/tmp"]},
]

_WINDOWS_SAMPLES = [
    {"cmdline": "C:\\Windows\\System32\\svchost.exe"},
    {"cmdline": "C:\\Windows\\System32\\lsass.exe"},
    {"cmdline": "C:\\Windows\\explorer.exe"},
    {"cmdline": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    {"cmdline": "C:\\Windows\\System32\\cmd.exe /c dir"},
    {"cmdline": "C:\\Program Files\\Git\\bin\\git.exe status"},
    {"cmdline": "C:\\Windows\\System32\\notepad.exe"},
    {"cmdline": "C:\\Windows\\System32\\taskhostw.exe"},
    {"cmdline": "C:\\Windows\\System32\\wininit.exe"},
    {"cmdline": "C:\\Windows\\System32\\services.exe"},
]


def _write_baseline_dir(
    baseline_dir: Path,
    samples: list[dict[str, object]],
    *,
    platform: str,
    workload: str,
) -> None:
    baseline_dir.mkdir(parents=True, exist_ok=True)
    (baseline_dir / "baseline.jsonl").write_text(
        "\n".join(json.dumps(s) for s in samples) + "\n",
        encoding="utf-8",
    )
    write_manifest(
        baseline_dir,
        platform=platform,
        os_version="test",
        workload_label=workload,
        capture_start=_START,
        capture_end=_END,
        hostname="testhost",
    )


def _run_trainer(
    monkeypatch: pytest.MonkeyPatch,
    module,
    *,
    dataset: list[Path],
    output_dir: Path,
) -> None:
    """Invoke a trainer's main() with the given args, via sys.argv."""
    # `--dataset` uses nargs="+", so one flag followed by all paths.
    argv = [module.TRAINING_SCRIPT, "--dataset", *[str(d) for d in dataset]]
    argv += ["--output-dir", str(output_dir)]
    monkeypatch.setattr("sys.argv", argv)
    module.main()


# --- Linux -----------------------------------------------------------------


def test_train_linux_end_to_end(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dataset = tmp_path / "linux__dev__abc__2026-09-11"
    _write_baseline_dir(dataset, _LINUX_SAMPLES, platform="linux", workload="dev")
    output = tmp_path / "model_out"

    _run_trainer(monkeypatch, train_linux, dataset=[dataset], output_dir=output)

    assert (output / "model.onnx").exists()
    record = load_training_record(output)
    assert record.training_script == "synthaea_ml/training/train_linux.py"
    assert len(record.dataset_versions) == 1
    assert record.dataset_versions[0].sample_count == len(_LINUX_SAMPLES)
    assert record.hyperparameters["n_estimators"] == 100
    assert record.hyperparameters["contamination"] == 0.05


def test_train_linux_rejects_mutated_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset = tmp_path / "linux__dev__abc__2026-09-11"
    _write_baseline_dir(dataset, _LINUX_SAMPLES, platform="linux", workload="dev")
    # Append a sample after the manifest was written - hash no longer matches.
    with (dataset / "baseline.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"argv": ["mutated"]}\n')
    output = tmp_path / "model_out"

    with pytest.raises(ValueError, match="baseline hash mismatch"):
        _run_trainer(monkeypatch, train_linux, dataset=[dataset], output_dir=output)

    # Nothing should have been written on the failure path - the point is not
    # to leave a half-emitted model behind pointing at a phantom dataset.
    assert not (output / "model.onnx").exists()


def test_train_linux_two_datasets_shows_both_versions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset_a = tmp_path / "linux__dev__aaa__2026-09-11"
    dataset_b = tmp_path / "linux__admin__bbb__2026-09-11"
    _write_baseline_dir(dataset_a, _LINUX_SAMPLES, platform="linux", workload="dev")
    _write_baseline_dir(dataset_b, _LINUX_SAMPLES, platform="linux", workload="admin")
    output = tmp_path / "model_out"

    _run_trainer(
        monkeypatch, train_linux, dataset=[dataset_a, dataset_b], output_dir=output
    )

    record = load_training_record(output)
    assert len(record.dataset_versions) == 2
    names = {v.name for v in record.dataset_versions}
    assert any("__dev__" in n for n in names)
    assert any("__admin__" in n for n in names)


# --- Windows ---------------------------------------------------------------


def test_train_windows_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset = tmp_path / "windows__desktop-user__abc__2026-09-11"
    _write_baseline_dir(
        dataset, _WINDOWS_SAMPLES, platform="windows", workload="desktop-user"
    )
    output = tmp_path / "model_out"

    _run_trainer(monkeypatch, train_windows, dataset=[dataset], output_dir=output)

    assert (output / "model.onnx").exists()
    record = load_training_record(output)
    assert record.training_script == "synthaea_ml/training/train_windows.py"
    assert len(record.dataset_versions) == 1
    assert record.dataset_versions[0].sample_count == len(_WINDOWS_SAMPLES)
    # Windows-side name derivation must survive a hyphenated workload label.
    assert "__desktop-user__" in record.dataset_versions[0].name


def test_train_windows_rejects_mutated_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset = tmp_path / "windows__desktop-user__abc__2026-09-11"
    _write_baseline_dir(
        dataset, _WINDOWS_SAMPLES, platform="windows", workload="desktop-user"
    )
    with (dataset / "baseline.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"cmdline": "C:\\\\Windows\\\\mutated.exe"}\n')
    output = tmp_path / "model_out"

    with pytest.raises(ValueError, match="baseline hash mismatch"):
        _run_trainer(monkeypatch, train_windows, dataset=[dataset], output_dir=output)

    assert not (output / "model.onnx").exists()


# --- Argparse contract -----------------------------------------------------


def test_train_linux_missing_dataset_arg_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """argparse should reject a call with only --output-dir. The trainer must not
    accept a fallback to a hard-coded path any more (the whole point of this PR)."""
    monkeypatch.setattr("sys.argv", ["train_linux", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit):
        train_linux.main()


def test_train_windows_missing_dataset_arg_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("sys.argv", ["train_windows", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit):
        train_windows.main()
