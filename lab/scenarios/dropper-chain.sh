#!/usr/bin/env bash
# Validation scenario for the full dropper chain (T1105/T1059/T1071).
#
# Simulates a process that, within the same time window (60s by default) and under the
# same pid: (1) executes (Exec), (2) connects to the network (Connect), (3) writes a
# file to disk (FileOpen with O_CREAT|O_WRONLY). This is exactly the "download + write"
# pattern of a payload/dropper — curl combines all three in a single process, unlike
# `wget ... && ./payload` (two separate processes, already covered by the T1105 rule
# in crates/rules, based on the write-then-exec correlation).
#
# Exercises the correlator's spawn+connect+filewrite rule (crates/correlator —
# identifiers renamed to English during migration, issue #12).
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/dropper-chain.sh
#   3) expected in terminal A:
#      T1105/T1059/T1071 — pid=...: spawn + network connection + file write — full dropper chain

set -euo pipefail

PORT=8080
OUT_FILE="/tmp/edr-test-dropper-payload"

server() {
    while true; do
        printf 'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload' | nc -l -p "$PORT" -q1 >/dev/null 2>&1 \
            || printf 'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload' | nc -l "$PORT" >/dev/null 2>&1
    done
}

server &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$OUT_FILE"' EXIT

sleep 1

echo "curl -o $OUT_FILE http://127.0.0.1:$PORT/ (exec + connect + filewrite, same pid)..."
curl -s -o "$OUT_FILE" "http://127.0.0.1:$PORT/" || true

echo "Done. Check for the T1105/T1059/T1071 (full dropper chain) alert in the agent terminal."
echo "File written: $OUT_FILE ($( [ -f "$OUT_FILE" ] && wc -c < "$OUT_FILE" || echo 0) bytes)"
