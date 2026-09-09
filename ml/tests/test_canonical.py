"""Parity: `synthaea_ml.data.canonical` must match `schema::ExecEvent::ml_cmdline`
(Rust). The Rust counterpart is `ml_cmdline_is_the_canonical_nul_joined_form` in
`crates/schema/tests/golden.rs` — the two sets of cases are kept identical.
"""

import pytest

from synthaea_ml.data.canonical import argv_from_record, cmdline_str, ml_cmdline_from_record

# (record, expected argv, expected canonical ML string) — mirror of the Rust test.
CASES = [
    (
        {"cmdline": "curl -fsSL https://x.test", "argv": ["curl", "-fsSL", "https://x.test"]},
        ["curl", "-fsSL", "https://x.test"],
        "curl\0-fsSL\0https://x.test\0",
    ),
    ({"cmdline": "/tmp/payload", "argv": ["/tmp/payload"]}, ["/tmp/payload"], "/tmp/payload\0"),
    # Windows/ETW: no argv → flat cmdline verbatim, no terminator.
    (
        {"cmdline": "powershell.exe -EncodedCommand ZWNobw==", "argv": []},
        ["powershell.exe -EncodedCommand ZWNobw=="],
        "powershell.exe -EncodedCommand ZWNobw==",
    ),
    ({"argv": ["sh", "-c", "chmod +x x"]}, ["sh", "-c", "chmod +x x"], "sh\0-c\0chmod +x x\0"),
    # NUL-separated cmdline, no argv (a raw eBPF capture stored that way).
    ({"cmdline": "ls\0-la\0"}, ["ls", "-la"], "ls\0-la\0"),
    ({}, [], ""),
]


@pytest.mark.parametrize("record,expected_argv,expected_ml", CASES)
def test_canonical_matches_rust(record, expected_argv, expected_ml):
    assert argv_from_record(record) == expected_argv
    assert ml_cmdline_from_record(record) == expected_ml


def test_cmdline_str_is_the_argv_half():
    # cmdline_str always NUL-terminates (argv → string); the Windows-fallback
    # exception lives in ml_cmdline_from_record, not here.
    assert cmdline_str(["a", "b", "c"]) == "a\0b\0c\0"
    assert cmdline_str([]) == ""


def test_ml_string_roundtrips_through_extract_features():
    """The whole point: the canonical string is what the extractor tokenizes."""
    from synthaea_ml.features.cmdline import token_count

    assert token_count(ml_cmdline_from_record({"argv": ["a", "b", "c"]})) == 3
