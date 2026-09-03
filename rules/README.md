# rules — Detection Content

Detection content shipped to agents, kept separate from engine code so it can ship on its
own cadence (canary rings). To be migrated/curated from `old/rules` after review.

| Path | Purpose |
| --- | --- |
| `sigma/` | Sigma rules — behavioral detections on the event stream, organized by platform and ATT&CK technique |
| `yara/` | YARA rules — file and memory content scanning, organized by category |
