"""Scenario replay engine (issue #44, ADR-0009).

ADR-0009 defined ``ExpectedDetection``/``ObservedDetection``/
``ScenarioReplayResult`` (in ``registry.training_record``) and the passing
criterion (``compute_passed``), but nothing ever produced a
``ScenarioReplayResult`` — PR #229/#232 (the ``lab/scenarios/*.yaml`` sidecars)
were explicitly scoped to format + conversion only, "pas de code moteur de
replay". This module is that engine: given a scenario yaml and the
``alerts.ndjson`` a run against it produced, build the ``ScenarioReplayResult``
ADR-0009's schema and gate expect.

**What this does NOT do:** run the scenario itself. The scenario's own
``script``/``platform`` fields name a `.sh`/`.ps1` that needs a real lab VM
(Hyper-V, see ``lab/vagrant-hyperv/``) to execute meaningfully — automating
that orchestration is a separate concern (SSH/VM lifecycle, not detection
matching) left for a follow-up. This module starts one step downstream: it
takes an already-produced ``alerts.ndjson`` (from any run, lab or CI) and
turns it into the ADR-0009 record.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path

import yaml

from synthaea_ml.registry.training_record import (
    Environment,
    ExpectedDetection,
    ObservedDetection,
    ScenarioReplayResult,
    compute_passed,
)

_HASH_CHUNK = 1 << 16  # 64 KiB, matches training_record.py's own helper.


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def load_expected_detections(scenario_yaml: Path) -> tuple[str, list[ExpectedDetection]]:
    """Parses a ``lab/scenarios/<name>.yaml`` sidecar's ``expected_detections``.

    Returns the scenario's ``name`` field (not the file stem — the sidecar's
    own ``name:`` is the source of truth, matching how the YAML is authored)
    alongside the parsed list.

    Raises:
        KeyError: If the yaml is missing ``name`` or ``expected_detections``,
            or an entry is missing one of the four required fields — a
            malformed sidecar should fail loudly here, not silently produce an
            empty replay result.
    """
    doc = yaml.safe_load(scenario_yaml.read_text(encoding="utf-8"))
    expected = [
        ExpectedDetection(
            technique=entry["technique"],
            rule=entry["rule"],
            min_count=entry["min_count"],
            tolerance=entry["tolerance"],
        )
        for entry in doc["expected_detections"]
    ]
    return doc["name"], expected


def tally_alerts_by_technique(alerts_ndjson: Path) -> dict[str, int]:
    """Counts ``alerts.ndjson`` lines by ``technique``.

    ``AlertRecord`` (``crates/sinks/src/lib.rs``) carries only ``technique``
    and ``message`` — no separate machine-readable rule identifier ever
    reaches the wire (#44's decision 2: matching is by technique string, not
    ATT&CK decomposition). This function does not and cannot recover ``rule``
    from an alert line; see ``run_replay``'s docstring for how the ``rule`` on
    an ``ObservedDetection`` is actually determined.

    A blank line or a line that fails to parse as JSON is skipped rather than
    raising — ``alerts.ndjson`` is a live-agent append-only log, and a torn
    last line from a run that was still writing when captured is an expected,
    recoverable condition, not a reason to lose every count already tallied.
    """
    counts: dict[str, int] = {}
    for line in alerts_ndjson.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        technique = record.get("technique")
        if technique is None:
            continue
        counts[technique] = counts.get(technique, 0) + 1
    return counts


def detect_environment() -> Environment:
    """Best-effort ``Environment`` for the machine this replay actually ran
    on — see ``Environment``'s own doc for why ``kernel`` is
    ``platform.release()`` verbatim rather than a fuller build string."""
    return Environment(
        os=platform.system().lower(),
        kernel=platform.release(),
        arch=platform.machine(),
    )


def run_replay(
    scenario_yaml: Path,
    alerts_ndjson: Path,
    *,
    environment: Environment | None = None,
    run_at: str | None = None,
) -> ScenarioReplayResult:
    """Builds a ``ScenarioReplayResult`` from a scenario sidecar and the
    ``alerts.ndjson`` a run against it produced.

    ``rule`` on each ``ObservedDetection`` is not independently recovered from
    ``alerts.ndjson`` (see ``tally_alerts_by_technique``) — for every
    ``ExpectedDetection`` whose technique has a nonzero tally, the matching
    ``ObservedDetection`` copies that same ``ExpectedDetection``'s own
    ``rule``. This is sound exactly as long as no two rules in one scenario's
    ``expected_detections`` share an identical ``technique`` string — true for
    every scenario in ``lab/scenarios/`` today (each rule there has a
    distinct, if sometimes combined, ATT&CK tag) — and is a real limitation
    worth knowing before adding a scenario that violates it: two same-
    technique rules would have their counts silently merged into whichever
    expected entry is evaluated, since the tally itself is technique-keyed
    with no way to attribute a count to one rule over the other.

    ``environment``/``run_at`` are overridable for tests; production callers
    should leave them as their real-value defaults (autodetected / now).
    """
    scenario_name, expected = load_expected_detections(scenario_yaml)
    counts = tally_alerts_by_technique(alerts_ndjson)

    observed: list[ObservedDetection] = []
    for e in expected:
        count = counts.get(e.technique, 0)
        if count > 0:
            observed.append(ObservedDetection(technique=e.technique, rule=e.rule, count=count))

    return ScenarioReplayResult(
        scenario_name=scenario_name,
        scenario_yaml_sha256=_sha256_file(scenario_yaml),
        run_at=run_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        environment=environment or detect_environment(),
        expected_detections=expected,
        observed_detections=observed,
        passed=compute_passed(expected, observed),
    )
