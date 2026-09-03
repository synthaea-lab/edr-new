# rules/yara

YARA rules for file scanning (memory scanning later), evaluated on-device by the
`yara` crate (YARA-X). Layout convention: `<category>/<family-or-technique>.yar`
(e.g. `malware/xmrig.yar`, `lab/synthaea_lab_payload.yar`).

CI enforces (content workflow, `crates/yara/tests/content.rs`): every shipped rule
file compiles — a broken rule is a hard failure naming the file — and fires on a
crafted matching sample, one per rule. A rule nothing can trigger is dead content.
