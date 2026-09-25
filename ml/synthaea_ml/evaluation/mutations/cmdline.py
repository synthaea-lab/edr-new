"""T0 command-line mutators for adversarial evaluation.

Five mutation classes, each with light/medium/heavy intensity:
- Base64EncodeMutator: encode tokens
- ArgumentReorderMutator: shuffle arguments
- PathSubstitutionMutator: substitute paths
- TokenSplittingMutator: split tokens with quotes
- PaddingMutator: add whitespace/comments

All mutators operate on argv-style lists (null-separated when serialized).

LIMITATION (PR #405 review): Three of these mutators (Base64EncodeMutator,
TokenSplittingMutator, PaddingMutator) apply shell-syntax evasions directly
to argv, but Linux sensors capture argv AFTER shell parsing (execve). These
mutations produce argv values that cannot occur in practice:
- ba""se64 (shell input) → argv becomes "base64" (quotes stripped)
- # comment (shell input) → ignored by shell, not argv element
- base64-encoded token without decode wrapper → changes what runs

PathSubstitutionMutator and ArgumentReorderMutator (light/medium) are valid
argv-level evasions. The others belong to a future shell-payload mutator
that targets `sh -c` strings, not argv.

See https://github.com/synthaea-lab/edr-new/pull/405#issuecomment-5808683319
"""

import base64
import copy
from typing import Any, ClassVar

from .base import Mutator
from .prng import LCG


class Base64EncodeMutator(Mutator):
    """Encode tokens in base64.

    Light: encode 1 token
    Medium: encode 2-3 tokens
    Heavy: encode all tokens
    """

    def mutation_class_name(self) -> str:
        return "base64_encode"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        if "argv" not in record or not isinstance(record["argv"], list):
            raise ValueError("record must have 'argv' list field")

        mutated = copy.deepcopy(record)
        argv = mutated["argv"]

        if not argv or len(argv) == 0:
            return mutated

        if intensity == "light":
            count = 1
        elif intensity == "medium":
            count = min(3, len(argv))
        elif intensity == "heavy":
            count = len(argv)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        indices = list(range(len(argv)))
        selected = rng.shuffle(indices)[:count]

        for idx in selected:
            if idx < len(argv):
                original = argv[idx]
                encoded = base64.b64encode(original.encode("utf-8")).decode("ascii")
                argv[idx] = encoded

        return mutated


class ArgumentReorderMutator(Mutator):
    """Shuffle command-line arguments.

    Light: swap 2 adjacent args (skip argv[0])
    Medium: shuffle non-positional args (skip argv[0])
    Heavy: same as medium (argv[0] must stay fixed to preserve executable)
    """

    def mutation_class_name(self) -> str:
        return "argument_reorder"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        if "argv" not in record or not isinstance(record["argv"], list):
            raise ValueError("record must have 'argv' list field")

        mutated = copy.deepcopy(record)
        argv = mutated["argv"]

        if len(argv) < 2:
            return mutated

        if intensity == "light":
            # Swap 2 adjacent args (skip argv[0] to preserve executable)
            if len(argv) < 3:
                return mutated
            idx = rng.uniform(1, len(argv) - 1)
            argv[idx], argv[idx + 1] = argv[idx + 1], argv[idx]
        elif intensity == "medium":
            # Shuffle non-positional (keep argv[0] in place)
            if len(argv) > 1:
                tail = argv[1:]
                argv[1:] = rng.shuffle(tail)
        elif intensity == "heavy":
            # Same as medium for now (argv[0] must stay fixed to preserve executable)
            # Future: could add --opt=val ↔ --opt val rewriting on top of shuffle
            if len(argv) > 1:
                tail = argv[1:]
                argv[1:] = rng.shuffle(tail)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        return mutated


class PathSubstitutionMutator(Mutator):
    """Substitute common paths.

    Example: /bin/bash → /usr/bin/bash

    Light: substitute 1 path
    Medium: substitute 2 paths
    Heavy: substitute all paths
    """

    PATH_SUBSTITUTIONS: ClassVar[list[tuple[str, str]]] = [
        ("/bin/", "/usr/bin/"),
        ("/usr/bin/", "/bin/"),
        ("/sbin/", "/usr/sbin/"),
        ("/usr/sbin/", "/sbin/"),
        ("/tmp/", "/var/tmp/"),
        ("/var/tmp/", "/tmp/"),
        ("C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"),
        ("C:\\Windows\\SysWOW64\\", "C:\\Windows\\System32\\"),
    ]

    def mutation_class_name(self) -> str:
        return "path_substitution"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        if "argv" not in record or not isinstance(record["argv"], list):
            raise ValueError("record must have 'argv' list field")

        mutated = copy.deepcopy(record)
        argv = mutated["argv"]

        if intensity == "light":
            max_subs = 1
        elif intensity == "medium":
            max_subs = 2
        elif intensity == "heavy":
            max_subs = len(argv)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        substitutions_made = 0
        for i in range(len(argv)):
            if substitutions_made >= max_subs:
                break
            for old, new in self.PATH_SUBSTITUTIONS:
                if old in argv[i]:
                    argv[i] = argv[i].replace(old, new)
                    substitutions_made += 1
                    break

        return mutated


class TokenSplittingMutator(Mutator):
    """Split tokens using shell quoting.

    Example: base64 → ba""se""64

    Light: split 1 token
    Medium: split 2 tokens
    Heavy: split all tokens
    """

    def mutation_class_name(self) -> str:
        return "token_splitting"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        if "argv" not in record or not isinstance(record["argv"], list):
            raise ValueError("record must have 'argv' list field")

        mutated = copy.deepcopy(record)
        argv = mutated["argv"]

        if not argv:
            return mutated

        if intensity == "light":
            count = 1
        elif intensity == "medium":
            count = min(2, len(argv))
        elif intensity == "heavy":
            count = len(argv)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        indices = list(range(len(argv)))
        selected = rng.shuffle(indices)[:count]

        for idx in selected:
            if idx < len(argv) and len(argv[idx]) > 2:
                token = argv[idx]
                # Split into quoted segments: ab""cd""ef
                parts = []
                for i, char in enumerate(token):
                    if i % 2 == 0:
                        parts.append(char)
                    else:
                        parts.append(f'"{char}"')
                argv[idx] = "".join(parts)

        return mutated


class PaddingMutator(Mutator):
    """Add whitespace and comments to command line.

    Light: add 1 comment
    Medium: add comments and whitespace
    Heavy: add extensive padding
    """

    COMMENTS: ClassVar[list[str]] = [
        "# padding",
        "# comment",
        "# ",
        "## ",
    ]

    def mutation_class_name(self) -> str:
        return "padding"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        if "argv" not in record or not isinstance(record["argv"], list):
            raise ValueError("record must have 'argv' list field")

        mutated = copy.deepcopy(record)
        argv = mutated["argv"]

        if not argv:
            return mutated

        if intensity == "light":
            # Add one comment as an argument
            comment = rng.choice(self.COMMENTS)
            insert_idx = rng.uniform(0, len(argv) + 1)
            argv.insert(insert_idx, comment)
        elif intensity == "medium":
            # Add comments and pad some tokens with spaces
            comment = rng.choice(self.COMMENTS)
            argv.insert(0, comment)
            for i in range(1, len(argv)):
                if rng.uniform(0, 2) == 0:
                    argv[i] = " " + argv[i] + " "
        elif intensity == "heavy":
            # Extensive padding
            for _ in range(3):
                comment = rng.choice(self.COMMENTS)
                insert_idx = rng.uniform(0, len(argv) + 1)
                argv.insert(insert_idx, comment)
            for i in range(len(argv)):
                if rng.uniform(0, 2) == 0:
                    spaces = " " * rng.uniform(1, 4)
                    argv[i] = spaces + argv[i] + spaces
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        return mutated


# Registry of all T0 mutators
# NOTE (PR #405 review): Filtered to only argv-valid mutations.
# Base64EncodeMutator, TokenSplittingMutator, and PaddingMutator apply
# shell-syntax evasions that don't survive exec() and are disabled until
# moved to a shell-payload mutator. PathSubstitutionMutator is the primary
# realistic argv-level evasion.
ALL_T0_MUTATORS = [
    PathSubstitutionMutator(),
    # ArgumentReorderMutator light/medium are valid (skip argv[0]),
    # but heavy reorders argv[0] which changes the executable
    ArgumentReorderMutator(),
]

# Disabled mutators (apply shell-syntax to argv, unrealistic):
# Base64EncodeMutator(),
# TokenSplittingMutator(),
# PaddingMutator(),

