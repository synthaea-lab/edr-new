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
| `argv.sh` | Shell one-liner with a base64 decode in its arguments | T1059.004 — asserts argv/cmdline capture (`/proc/<pid>/cmdline`) is correct on every kernel row (#152) |
| `dns-exfil.sh` | Data chunked into high-entropy DNS subdomains | T1048.003/T1071.004 correlation (Windows agent only — no Linux DNS sensor yet) |
| `encoded-powershell.ps1` | `powershell.exe -EncodedCommand <base64>` invocations | T1059.001 — asserts the ExecEvent-side `check_encoded_powershell` rule |
| `scheduled-task-persistence.ps1` | `schtasks.exe /Create` a demo task | T1053.005 — asserts the 4698 → `FLAG_PERSISTENCE_TASK_ARTIFACT` → `check_scheduled_task_persistence` end-to-end pipeline |
| `service-install-persistence.ps1` | `sc.exe create` a demo service (never runs) | T1543.003 — asserts the 7045 → `FLAG_PERSISTENCE_ARTIFACT` → `check_service_install_persistence` end-to-end pipeline |
| `create-account-persistence.ps1` | `net user /add` a benign local SAM account | T1136.001 — asserts the 4720 → `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` → `check_account_creation_persistence` end-to-end pipeline (local SAM only; T1136.002 domain accounts are out of scope) |

The four `.ps1` scenarios above are the Windows demo surface — see `../../demo/`
for the runbook that chains them in the reviewer-facing order.

New scenarios follow the same shape: one script, one documented expectation list,
runnable against any platform's agent from the VM matrix (`../vagrant`).
