# ml/datasets

Data on disk — never committed (only this documentation is). Layout:

| Path | Contents |
| --- | --- |
| `captures/` | Raw agent JSONL telemetry captures, named `<platform>-<host>-<date>/` |
| `baselines/` | Benign baselines built from captures (`capture_to_baseline`) |
| `labeled/` | Labeled traces (scenario runs with ground truth) for supervised eval |

Every registry model records exactly which dataset versions it was trained on.
