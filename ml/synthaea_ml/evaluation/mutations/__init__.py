"""Mutation framework for adversarial evaluation (issue #45).

Mutators operate on raw events (before canonical form) to test both extraction
and feature code. Three intensity levels (light/medium/heavy) per mutator.
Deterministic PRNG (Knuth LCG) mirrors Rust robustness tests for parity.
"""

from .base import MutationResult, Mutator
from .prng import LCG

__all__ = ["LCG", "Mutator", "MutationResult"]
