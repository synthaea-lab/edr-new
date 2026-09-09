"""The one canonical command-line form shared by the agent and the training pipeline.

Mirror of `schema::ExecEvent::ml_cmdline` (Rust). The cmdline feature extractor
(`synthaea_ml.features.cmdline`, and its Rust twin) splits tokens on NUL; a
space-joined string silently collapses `token_count` to 1 and inflates
`max_token_length`, so every ML consumer must build its input through here rather
than from a sensor's display `cmdline` string.

- `ml_cmdline_from_record` — the record → ML input string, byte-identical to
  `ExecEvent::ml_cmdline`: NUL-terminated argv on Linux, the flat `cmdline` verbatim on
  Windows/ETW (no argv). This is what training and inference must both feed the
  extractor.
- `argv_from_record` / `cmdline_str` — the two halves, for callers that need the token
  list on its own (`capture_to_baseline` dedups on the argv tuple).
"""

from __future__ import annotations


def ml_cmdline_from_record(record: dict) -> str:
    """The canonical ML cmdline string for one exec / baseline record — the exact
    mirror of `schema::ExecEvent::ml_cmdline` (Rust).

    - ``argv`` present → tokens each followed by NUL (like ``/proc/<pid>/cmdline``),
      which is what the cmdline extractor tokenizes on.
    - no ``argv`` (Windows/ETW) → ``cmdline`` verbatim, one flat token, no terminator.
    """
    argv = record.get("argv")
    if argv:
        return "".join(f"{tok}\0" for tok in argv)
    return str(record.get("cmdline", ""))


def argv_from_record(record: dict) -> list[str]:
    """Canonical argv for one exec / baseline record.

    Priority, matching `schema::ExecEvent::ml_cmdline` and `capture_to_baseline`:

    1. ``argv`` when non-empty — Linux execve, the agent's BaselineSink.
    2. ``cmdline`` split on NUL — a raw eBPF cmdline that was stored NUL-separated.
    3. ``cmdline`` as a single token — Windows/ETW has only a flat command line.
    """
    argv = record.get("argv")
    if argv:
        return [str(t) for t in argv]

    cmdline = record.get("cmdline", "")
    if not cmdline:
        return []
    if "\0" in cmdline:
        return [t for t in cmdline.split("\0") if t]
    return [cmdline]


def cmdline_str(argv: list[str]) -> str:
    """NUL-terminated join of argv tokens — byte-identical to
    `schema::ExecEvent::ml_cmdline` (Rust) for the same tokens. Empty argv → ``""``."""
    return "".join(f"{tok}\0" for tok in argv)
