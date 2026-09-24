"""Base framework for mutators.

All mutators operate on raw events (before canonical form) to test both
extraction and feature code. Mutations must be semantically preserving
(attacker-plausible) and deterministic (reproducible via PRNG seed).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .prng import LCG


@dataclass(frozen=True)
class MutationResult:
    """Result of applying one mutation to one event."""

    mutation_class: str
    intensity: str
    original_record: dict[str, Any]
    mutated_record: dict[str, Any]
    seed: int
    metadata: dict[str, Any]


class Mutator(ABC):
    """Base for all mutators.

    Contract:
    - Operates on raw events (before canonical form)
    - Preserves event schema
    - Uses deterministic PRNG
    - Semantically preserving (attacker-plausible)
    - Returns mutated copy (original unchanged)
    """

    @abstractmethod
    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        """Apply mutation at specified intensity.

        Args:
            record: Raw event record to mutate.
            intensity: One of "light", "medium", "heavy".
            rng: Deterministic PRNG for reproducibility.

        Returns:
            Mutated copy of record (original unchanged).

        Raises:
            ValueError: If intensity is invalid or record cannot be mutated.
        """

    @abstractmethod
    def mutation_class_name(self) -> str:
        """Return human-readable name for this mutator class."""
