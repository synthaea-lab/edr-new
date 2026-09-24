"""Deterministic PRNG for reproducible mutation corpus.

Mirrors the LCG in crates/sensors/linux/audit/tests/robustness.rs:L14-19.
Same constants (Knuth's 64-bit LCG), same seed default — Python and Rust
tests can share fixture expectations.
"""


class LCG:
    """Knuth LCG — reproducible corpus, no external deps."""

    def __init__(self, seed: int = 0x59417481):
        """Initialize LCG with seed.

        Args:
            seed: Initial state. Default matches Rust robustness tests.
        """
        self.state = seed

    def next(self) -> int:
        """Advance state and return next value."""
        self.state = (
            (self.state * 6_364_136_223_846_793_005 + 1_442_695_040_888_963_407)
            & 0xFFFFFFFFFFFFFFFF
        )
        return self.state

    def uniform(self, low: int, high: int) -> int:
        """Return integer in [low, high).

        Args:
            low: Inclusive lower bound.
            high: Exclusive upper bound.

        Returns:
            Pseudo-random integer in [low, high).
        """
        return low + ((self.next() >> 33) % (high - low))

    def choice(self, items: list):
        """Select random item from list.

        Args:
            items: Non-empty list.

        Returns:
            One element from items.

        Raises:
            ValueError: If items is empty.
        """
        if not items:
            raise ValueError("cannot choose from empty list")
        return items[self.uniform(0, len(items))]

    def shuffle(self, items: list) -> list:
        """Fisher-Yates shuffle — returns new list, original unchanged.

        Args:
            items: List to shuffle.

        Returns:
            Shuffled copy of items.
        """
        result = items[:]
        for i in range(len(result) - 1, 0, -1):
            j = self.uniform(0, i + 1)
            result[i], result[j] = result[j], result[i]
        return result
