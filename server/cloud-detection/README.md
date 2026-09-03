# server/cloud-detection — Cloud-Based Detection

Detection that runs where the agent cannot: with the whole fleet's history in view
and no endpoint CPU budget. Three modes over the same content model:

- **Streaming**: rules evaluated on the ingest path (seconds of latency) — detections
  too expensive, too stateful, or too fleet-wide for the device (joins across hosts,
  long windows, heavy regex/ML) land here instead of being cut for budget.
- **Scheduled/batch**: periodic sweeps over the lake — "low and slow" patterns whose
  window (days/weeks) no on-device buffer can hold.
- **Retrospective**: when new content arrives — a fresh IOC set, a new rule, an
  updated model — replay it over lake history and surface *past* matches as
  detections ("this hash was seen on 3 hosts last month"). The capability that turns
  yesterday's unknown into today's case, and structurally impossible on-device.

Contracts:
- One content model: cloud detections are detection-as-code like everything else
  (metadata, samples, CI suites, rings) — Sigma/YARA content marked `scope: cloud`
  plus lake-native analytic rules.
- Output is the same `Detection` type flowing into the same case pipeline — a
  retro-detection is evidence like any other, tagged with its retro provenance.
- Cloud detection AUGMENTS the device (layers 5–9); it never becomes an excuse to
  thin the on-device stack — offline endpoints stay protected by layers 1–4 and 6.
