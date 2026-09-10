#!/usr/bin/env bash
# "Respawn + connect" validation scenario (hardened T1059/T1071).
#
# Deliberately reproduces a side effect observed in the old iteration's lab on
# 2026-08-25: a listener that restarts on every accepted connection, following the
# same pattern as an implant that respawns after each beacon. Goal: empirically
# verify whether the correlator's respawn+connect rule fires in this real-world case.
#
# Point of attention when reading the correlator code (crates/correlator, issue #12):
# the old rule counted Exec events by literal PID, whereas a real respawn (fork+exec)
# yields a NEW pid on every iteration — SELF-SPAWN on the rules side correlates on
# (ppid, comm) for exactly this reason. Hypothesis to verify during migration: with
# distinct nc processes (different pids), the per-pid spawn count never reaches the
# respawn threshold (3), so the alert never fires under real conditions despite the
# unit test that covers it (that test artificially reuses the same pid for all 3
# Execs). If confirmed, the migrated rule must correlate on (ppid, comm).
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/respawn-beacon.sh
#   3) expected IF the rule works as documented:
#      T1059/T1071 — pid=...: N spawns + network connection — automatic respawn with suspected beaconing
#      expected IF the hypothesis above is confirmed: no respawn alert, only the
#      BEACON alert (validated in the old lab on 2026-08-25). The `rules` SELF-SPAWN
#      alert is Windows-only since #159 and no longer fires here.

set -euo pipefail

PORT=4445
RESPAWNS=4

# Listener in its own session (process group): cleanup must reach the nc child,
# not just the loop — `kill $!` alone leaves an orphaned nc holding the port, and
# the next run's `nc -l` then fails and the loop spins hot (#113).
setsid bash -c '
  while true; do
    nc -l -p "$1" -q1 >/dev/null 2>&1 || nc -l "$1" >/dev/null 2>&1
  done
' bash "$PORT" &
LISTENER_PGID=$!
trap 'kill -- -"$LISTENER_PGID" 2>/dev/null || true' EXIT

sleep 1

echo "Sending $RESPAWNS connections to 127.0.0.1:$PORT (listener respawns each time)..."
for i in $(seq 1 "$RESPAWNS"); do
    echo "ping $i" | nc -w1 127.0.0.1 "$PORT" || true
    echo "  connection $i sent (the listener should have respawned with a new pid)"
    sleep 1
done

echo "Done. Check in the agent terminal whether the respawn-with-beaconing alert is present or absent."
