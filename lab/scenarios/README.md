# lab/scenarios

Scripted, benign-by-construction attack simulations used to validate detections in the
lab. Each scenario documents the detections it is expected to trigger, so a run is an
assertion, not a demo.

To migrate from `old/lab` after review:

| Scenario | Simulates | Expected detections |
| --- | --- | --- |
| `beacon.sh` | Periodic same-destination C2 traffic | BEACON rule, correlation case |
| `dropper-chain.sh` | Download → write → execute chain | download-then-exec, T1105 correlation |
| `respawn-beacon.sh` | Beacon that respawns when killed | BEACON + SELF-SPAWN, case continuity |
| `lineage.sh` | Web-server-named process spawns a shell | T1059 — asserts eBPF parent lineage (ppid/parent_comm) is correct on every kernel row (#53) |
| `dns-exfil.sh` | Data chunked into high-entropy DNS subdomains | T1048.003/T1071.004 correlation (Windows agent only — no Linux DNS sensor yet) |

New scenarios follow the same shape: one script, one documented expectation list,
runnable against any platform's agent from the VM matrix (`../vagrant`).
