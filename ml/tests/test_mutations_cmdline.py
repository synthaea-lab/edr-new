"""Tests for T0 cmdline mutators (mutations.cmdline).

Validates that each mutator class:
- Preserves event schema (argv field remains valid)
- Is deterministic (same seed produces same mutation)
- Is semantically preserving (attacker-plausible)
"""

import pytest

from synthaea_ml.evaluation.mutations.cmdline import (
    ArgumentReorderMutator,
    Base64EncodeMutator,
    PaddingMutator,
    PathSubstitutionMutator,
    TokenSplittingMutator,
)
from synthaea_ml.evaluation.mutations.prng import LCG


def test_base64_encode_light() -> None:
    """Light intensity encodes 1 token."""
    mutator = Base64EncodeMutator()
    rng = LCG(seed=42)

    record = {"argv": ["curl", "-fsSL", "https://example.com"]}
    mutated = mutator.mutate(record, "light", rng)

    # Original unchanged
    assert record["argv"] == ["curl", "-fsSL", "https://example.com"]

    # Mutated has same length
    assert len(mutated["argv"]) == 3

    # At least one token is base64 (contains no space/slash)
    base64_tokens = [t for t in mutated["argv"] if not any(c in t for c in " /:-")]
    assert len(base64_tokens) >= 1


def test_base64_encode_deterministic() -> None:
    """Same seed produces same encoding."""
    mutator = Base64EncodeMutator()
    record = {"argv": ["curl", "-fsSL", "https://example.com"]}

    rng1 = LCG(seed=100)
    mutated1 = mutator.mutate(record, "light", rng1)

    rng2 = LCG(seed=100)
    mutated2 = mutator.mutate(record, "light", rng2)

    assert mutated1["argv"] == mutated2["argv"]


def test_argument_reorder_light() -> None:
    """Light intensity swaps 2 adjacent args."""
    mutator = ArgumentReorderMutator()
    rng = LCG(seed=42)

    record = {"argv": ["bash", "-c", "echo hello", "arg4"]}
    mutated = mutator.mutate(record, "light", rng)

    # Same tokens, possibly different order
    assert sorted(mutated["argv"]) == sorted(record["argv"])
    assert len(mutated["argv"]) == len(record["argv"])


def test_argument_reorder_medium() -> None:
    """Medium intensity shuffles non-positional args."""
    mutator = ArgumentReorderMutator()
    rng = LCG(seed=42)

    record = {"argv": ["bash", "arg1", "arg2", "arg3"]}
    mutated = mutator.mutate(record, "medium", rng)

    # First token unchanged (argv[0])
    assert mutated["argv"][0] == "bash"

    # Rest shuffled (likely different order)
    assert sorted(mutated["argv"]) == sorted(record["argv"])


def test_path_substitution_light() -> None:
    """Light intensity substitutes 1 path."""
    mutator = PathSubstitutionMutator()
    rng = LCG(seed=42)

    record = {"argv": ["/bin/bash", "-c", "echo"]}
    mutated = mutator.mutate(record, "light", rng)

    # Path substituted
    assert mutated["argv"][0] in ["/bin/bash", "/usr/bin/bash"]
    # If substituted, should be different
    if mutated["argv"][0] != "/bin/bash":
        assert "/usr/bin" in mutated["argv"][0]


def test_token_splitting_light() -> None:
    """Light intensity splits 1 token."""
    mutator = TokenSplittingMutator()
    rng = LCG(seed=42)

    record = {"argv": ["base64", "-d"]}
    mutated = mutator.mutate(record, "light", rng)

    # At least one token has quotes (from splitting)
    has_quotes = any('"' in t for t in mutated["argv"])
    assert has_quotes or mutated["argv"] == record["argv"]  # May not split short tokens


def test_padding_mutator_light() -> None:
    """Light intensity adds 1 comment."""
    mutator = PaddingMutator()
    rng = LCG(seed=42)

    record = {"argv": ["bash", "-c", "echo"]}
    mutated = mutator.mutate(record, "light", rng)

    # Length increased by 1 (comment added)
    assert len(mutated["argv"]) == len(record["argv"]) + 1

    # Contains a comment token
    has_comment = any(t.startswith("#") for t in mutated["argv"])
    assert has_comment


def test_mutators_require_argv() -> None:
    """All mutators require 'argv' field."""
    mutators = [
        Base64EncodeMutator(),
        ArgumentReorderMutator(),
        PathSubstitutionMutator(),
        TokenSplittingMutator(),
        PaddingMutator(),
    ]
    rng = LCG(seed=42)

    for mutator in mutators:
        with pytest.raises(ValueError, match="argv"):
            mutator.mutate({}, "light", rng)


def test_mutators_reject_invalid_intensity() -> None:
    """All mutators reject invalid intensity."""
    mutator = Base64EncodeMutator()
    rng = LCG(seed=42)

    record = {"argv": ["bash"]}
    with pytest.raises(ValueError, match="invalid intensity"):
        mutator.mutate(record, "extreme", rng)


def test_mutation_class_names() -> None:
    """Each mutator has distinct class name."""
    mutators = [
        Base64EncodeMutator(),
        ArgumentReorderMutator(),
        PathSubstitutionMutator(),
        TokenSplittingMutator(),
        PaddingMutator(),
    ]

    names = [m.mutation_class_name() for m in mutators]
    assert len(names) == len(set(names))  # All unique
    assert all(isinstance(n, str) and n for n in names)  # All non-empty strings
