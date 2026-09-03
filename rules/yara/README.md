# rules/yara

YARA rules for file and memory scanning, evaluated on-device (planned engine crate:
a YARA-X based scanner feeding detections into the correlator like any other source).
Layout convention: `<category>/<family-or-technique>.yar` (e.g. `malware/xmrig.yar`,
`packers/upx-suspicious.yar`).
