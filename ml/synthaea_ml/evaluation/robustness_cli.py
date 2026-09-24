"""Robustness CLI commands for CI gate integration (issue #45).

Commands:
- verify: Check robustness metrics against thresholds (CI gate)
- report: Generate human-readable robustness report

Usage:
    python -m synthaea_ml.evaluation.robustness_cli verify \\
        --model-dir ml/registry/cmdline-iforest-linux/0.3.0/ \\
        --max-escape-rate 0.15

    python -m synthaea_ml.evaluation.robustness_cli report \\
        --model-dir ml/registry/cmdline-iforest-linux/0.3.0/ \\
        --output robustness.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from synthaea_ml.registry.training_record import load_training_record


def _find_previous_version(model_dir: Path) -> Path | None:
    """Find the previous version directory for regression checking.

    Args:
        model_dir: Current model version directory.

    Returns:
        Path to previous version directory, or None if not found.
    """
    # Parse version from directory name (e.g., "0.3.0" from ".../0.3.0")
    current_version_str = model_dir.name
    try:
        # Simple version parsing (assumes semantic versioning)
        parts = current_version_str.split(".")
        if len(parts) != 3:
            return None

        major, minor, patch = map(int, parts)

        # Try to find previous versions (decrement patch, then minor, then major)
        registry_dir = model_dir.parent

        # Try patch-1, then minor-1, then major-1
        candidates = []
        if patch > 0:
            candidates.append(f"{major}.{minor}.{patch-1}")
        if minor > 0:
            # Find highest patch in previous minor
            prev_minor_pattern = f"{major}.{minor-1}.*"
            for entry in registry_dir.glob(prev_minor_pattern):
                if entry.is_dir() and entry != model_dir:
                    candidates.append(entry.name)
        if major > 0:
            # Find highest version in previous major
            prev_major_pattern = f"{major-1}.*"
            for entry in registry_dir.glob(prev_major_pattern):
                if entry.is_dir() and entry != model_dir:
                    candidates.append(entry.name)

        # Return first existing candidate
        for candidate in candidates:
            prev_dir = registry_dir / candidate
            if prev_dir.exists() and prev_dir.is_dir():
                return prev_dir

    except (ValueError, IndexError):
        return None

    return None


def verify_robustness(
    model_dir: Path,
    max_escape_rate: float = 0.15,
    max_median_degradation: float = 0.20,
    no_regression: bool = False,
    max_regression_increase: float = 0.05,
) -> bool:
    """Verify robustness metrics against thresholds.

    Args:
        model_dir: Registry version directory containing model_record.json.
        max_escape_rate: Maximum allowed escape rate (default 0.15 = 15%).
        max_median_degradation: Maximum allowed median score degradation.
        no_regression: If True, check for regression vs previous version.
        max_regression_increase: Maximum allowed escape rate increase vs previous
            version (default 0.05 = 5 percentage points).

    Returns:
        True if all checks pass, False otherwise.
    """
    record = load_training_record(model_dir)

    if not record.robustness_cards:
        print(f"ERROR: No robustness cards found in {model_dir}")
        return False

    print(f"Verifying robustness for {len(record.robustness_cards)} scenario(s)...")

    all_passed = True
    for card in record.robustness_cards:
        print(f"\n{card.scenario_name}:")
        print(f"  Escape rate: {card.escape_rate:.2%}")
        print(f"  Median degradation: {card.median_score_degradation:+.3f}")
        print(f"  Worst case degradation: {card.worst_case_degradation:+.3f}")

        if card.escape_rate > max_escape_rate:
            print(f"  FAIL: escape rate {card.escape_rate:.2%} > {max_escape_rate:.2%}")
            all_passed = False

        if card.median_score_degradation > max_median_degradation:
            print(
                f"  FAIL: median degradation {card.median_score_degradation:+.3f} "
                f"> {max_median_degradation:.3f}"
            )
            all_passed = False

    if no_regression:
        prev_dir = _find_previous_version(model_dir)
        if prev_dir:
            try:
                prev_record = load_training_record(prev_dir)
                print(f"\nRegression check against previous version: {prev_dir.name}")

                # Match scenarios by name
                prev_cards_by_name = {c.scenario_name: c for c in prev_record.robustness_cards}

                for card in record.robustness_cards:
                    prev_card = prev_cards_by_name.get(card.scenario_name)
                    if prev_card:
                        escape_increase = card.escape_rate - prev_card.escape_rate
                        print(
                            f"  {card.scenario_name}: {prev_card.escape_rate:.2%} → "
                            f"{card.escape_rate:.2%} (Δ {escape_increase:+.2%})"
                        )

                        if escape_increase > max_regression_increase:
                            print(
                                f"    REGRESSION: escape rate increased by "
                                f"{escape_increase:.2%} (max allowed: {max_regression_increase:.2%})"
                            )
                            all_passed = False
                    else:
                        print(f"  {card.scenario_name}: no previous baseline (new scenario)")

            except (FileNotFoundError, ValueError) as e:
                print(f"\nWARNING: Could not load previous version for regression check: {e}")
        else:
            print("\nWARNING: No previous version found for regression check")

    if all_passed:
        print("\nPASS: All robustness checks passed")
    else:
        print("\nFAIL: Robustness checks failed")

    return all_passed


def generate_report(model_dir: Path, output: Path | None = None) -> None:
    """Generate human-readable robustness report.

    Args:
        model_dir: Registry version directory containing model_record.json.
        output: Output path for report (default: stdout).
    """
    record = load_training_record(model_dir)

    if not record.robustness_cards:
        print("No robustness cards found.")
        return

    lines = []
    lines.append("# Adversarial Robustness Report")
    lines.append("")
    lines.append(f"Model: {model_dir}")
    lines.append(f"Schema version: {record.schema_version}")
    lines.append("")

    for card in record.robustness_cards:
        lines.append(f"## Scenario: {card.scenario_name}")
        lines.append("")
        lines.append(f"- Tested at: {card.tested_at}")
        lines.append(f"- YAML hash: `{card.scenario_yaml_sha256[:16]}...`")
        lines.append(f"- **Escape rate:** {card.escape_rate:.2%}")
        lines.append(f"- **Median score degradation:** {card.median_score_degradation:+.3f}")
        lines.append(f"- **Worst case degradation:** {card.worst_case_degradation:+.3f}")
        lines.append("")

        lines.append("### Mutation Results")
        lines.append("")
        lines.append("| Mutation | Intensity | Original | Mutated | Delta | Escaped |")
        lines.append("|----------|-----------|----------|---------|-------|---------|")

        for result in card.mutation_results[:10]:  # Show first 10
            lines.append(
                f"| {result.mutation_class} | {result.intensity} | "
                f"{result.original_score:+.3f} | {result.mutated_score:+.3f} | "
                f"{result.score_delta:+.3f} | {result.escaped} |"
            )

        if len(card.mutation_results) > 10:
            lines.append(f"| ... | ... | ... | ... | ... | ... |")
            lines.append(f"| ({len(card.mutation_results) - 10} more results) |")

        lines.append("")

    report = "\n".join(lines)

    if output:
        output.write_text(report, encoding="utf-8")
        print(f"Report written to {output}")
    else:
        print(report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify robustness metrics")
    verify_parser.add_argument(
        "--model-dir",
        type=Path,
        required=True,
        help="Registry version directory containing model_record.json",
    )
    verify_parser.add_argument(
        "--max-escape-rate",
        type=float,
        default=0.15,
        help="Maximum allowed escape rate (default: 0.15)",
    )
    verify_parser.add_argument(
        "--max-median-degradation",
        type=float,
        default=0.20,
        help="Maximum allowed median degradation (default: 0.20)",
    )
    verify_parser.add_argument(
        "--no-regression",
        action="store_true",
        help="Check for regression vs previous version",
    )
    verify_parser.add_argument(
        "--max-regression-increase",
        type=float,
        default=0.05,
        help="Maximum allowed escape rate increase vs previous version (default: 0.05)",
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate robustness report")
    report_parser.add_argument(
        "--model-dir",
        type=Path,
        required=True,
        help="Registry version directory containing model_record.json",
    )
    report_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for report (default: stdout)",
    )

    args = parser.parse_args()

    if args.command == "verify":
        passed = verify_robustness(
            args.model_dir,
            args.max_escape_rate,
            args.max_median_degradation,
            args.no_regression,
            args.max_regression_increase,
        )
        sys.exit(0 if passed else 1)
    elif args.command == "report":
        generate_report(args.model_dir, args.output)


if __name__ == "__main__":
    main()
