"""Tests for `synthaea_ml.evaluation.scenario_replay` — the engine that turns a
scenario yaml + a run's `alerts.ndjson` into ADR-0009's `ScenarioReplayResult`.

The properties that need to hold:

- A scenario passes when every expected (technique, rule) tuple is observed
  within [min_count, min_count + tolerance].
- Under-detection, over-detection and a missing technique entirely all fail
  the scenario, matching `compute_passed`'s own symmetric treatment.
- `scenario_yaml_sha256` really is the sidecar's content hash — mutating the
  yaml changes the recorded hash.
- Malformed/blank lines in `alerts.ndjson` are skipped, not fatal.
- `rule` on an ObservedDetection is copied from the matching
  ExpectedDetection (see the module doc on why this is sound and its limit).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from synthaea_ml.evaluation.scenario_replay import (
    load_expected_detections,
    run_replay,
    tally_alerts_by_technique,
)
from synthaea_ml.registry.training_record import Environment

_ENV = Environment(os="linux", kernel="7.2.4-arch1-2", arch="x86_64")

_SCENARIO_YAML = """\
name: test-beacon
platform: linux
script: beacon.sh
simulates: >
  A test scenario.
expected_detections:
  - technique: "T1071/T1041"
    rule: check_beacon
    min_count: 1
    tolerance: 0
  - technique: "T1059/T1071"
    rule: rule_respawn_connect
    min_count: 1
    tolerance: 1
notes: >
  Test fixture.
"""


def _write_scenario(tmp_path: Path) -> Path:
    p = tmp_path / "test-beacon.yaml"
    p.write_text(_SCENARIO_YAML, encoding="utf-8")
    return p


def _write_alerts(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "alerts.ndjson"
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return p


def _alert(technique: str) -> str:
    return f'{{"timestamp_ns":1,"technique":"{technique}","message":"m"}}'


def test_load_expected_detections_parses_the_sidecar(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    name, expected = load_expected_detections(scenario)
    assert name == "test-beacon"
    assert len(expected) == 2
    assert expected[0].technique == "T1071/T1041"
    assert expected[0].rule == "check_beacon"
    assert expected[0].min_count == 1
    assert expected[0].tolerance == 0


def test_tally_counts_and_skips_malformed_lines(tmp_path: Path) -> None:
    alerts = _write_alerts(
        tmp_path,
        [
            _alert("T1071/T1041"),
            _alert("T1071/T1041"),
            "not json at all",
            "",
            _alert("T1059/T1071"),
        ],
    )
    counts = tally_alerts_by_technique(alerts)
    assert counts == {"T1071/T1041": 2, "T1059/T1071": 1}


def test_replay_passes_when_all_expected_detections_are_satisfied(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    alerts = _write_alerts(
        tmp_path,
        [_alert("T1071/T1041"), _alert("T1059/T1071")],
    )
    result = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result.passed is True
    assert result.scenario_name == "test-beacon"
    assert {o.technique: o.count for o in result.observed_detections} == {
        "T1071/T1041": 1,
        "T1059/T1071": 1,
    }
    # rule is copied from the matching ExpectedDetection, not read off the wire.
    rules = {o.technique: o.rule for o in result.observed_detections}
    assert rules["T1071/T1041"] == "check_beacon"
    assert rules["T1059/T1071"] == "rule_respawn_connect"


def test_replay_fails_on_missing_detection(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    # Only one of the two expected techniques fired.
    alerts = _write_alerts(tmp_path, [_alert("T1071/T1041")])
    result = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result.passed is False


def test_replay_fails_on_over_detection_beyond_tolerance(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    # check_beacon has tolerance=0, min_count=1 — a 2nd hit must fail it.
    alerts = _write_alerts(
        tmp_path,
        [_alert("T1071/T1041"), _alert("T1071/T1041"), _alert("T1059/T1071")],
    )
    result = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result.passed is False


def test_replay_tolerates_within_tolerance_over_detection(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    # rule_respawn_connect has tolerance=1, min_count=1 — a 2nd hit still passes.
    alerts = _write_alerts(
        tmp_path,
        [_alert("T1071/T1041"), _alert("T1059/T1071"), _alert("T1059/T1071")],
    )
    result = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result.passed is True


def test_scenario_yaml_sha256_reflects_content(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    alerts = _write_alerts(tmp_path, [_alert("T1071/T1041"), _alert("T1059/T1071")])
    result = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result.scenario_yaml_sha256 == hashlib.sha256(scenario.read_bytes()).hexdigest()

    # Mutating the yaml changes the hash a fresh replay would record.
    scenario.write_text(_SCENARIO_YAML + "\n# a comment\n", encoding="utf-8")
    result2 = run_replay(scenario, alerts, environment=_ENV, run_at="2026-09-18T12:00:00Z")
    assert result2.scenario_yaml_sha256 != result.scenario_yaml_sha256
