#!/usr/bin/env bash
# BEACON validation scenario (T1071/T1041).
#
# Simulates a C2 implant "phoning home": opens >= BEACON_THRESHOLD (3) TCP
# connections to the same (comm, dest, port) within BEACON_WINDOW_NS (60s), on a
# port outside STANDARD_PORTS (here 4444, the Metasploit default — not listed).
# See crates/rules/src/state.rs (check_beacon).
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/beacon.sh
#   3) expected in terminal A, on the 3rd connection:
#      T1071/T1041 — pid=... comm=nc → 127.0.0.1:4444 | 3x in 60s — suspected beaconing

set -euo pipefail

PORT=4444
CONNECTIONS=4
INTERVAL=2

listener() {
    while true; do
        nc -l -p "$PORT" >/dev/null 2>&1 || nc -l "$PORT" >/dev/null 2>&1
    done
}

listener &
LISTENER_PID=$!
trap 'kill "$LISTENER_PID" 2>/dev/null || true' EXIT

sleep 1

echo "Sending $CONNECTIONS connections to 127.0.0.1:$PORT (${INTERVAL}s interval)..."
for i in $(seq 1 "$CONNECTIONS"); do
    echo "beacon $i" | nc -w1 127.0.0.1 "$PORT" || true
    echo "  connection $i sent"
    sleep "$INTERVAL"
done

echo "Done. Check for the T1071/T1041 alert in the agent terminal."
