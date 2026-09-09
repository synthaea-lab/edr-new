#!/usr/bin/env bash
# Parent-lineage fidelity scenario (issue #53).
#
# The eBPF probes derive a process's parent from the PROC_LINEAGE fork-tracking map
# (sched_process_fork tracepoint fields + /proc priming), NOT a frozen-offset
# task_struct walk. This scenario is the assertion for "ppid is correct across the
# Linux rows of MATRIX.md": it must produce the same alert on every kernel, whereas
# the old task_struct read returned garbage (ppid=4294901760) on any kernel other
# than the one the bindings were generated from.
#
# Shape: a process named like a web server (a copy of /bin/sh — comm becomes the
# basename) spawns a real shell that runs a command. The T1059 rule
# (check_web_server_spawns_shell) fires only if the child's ppid resolves to the
# "nginx" parent — i.e. only if lineage is correct.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/lineage.sh
#   3) expected: exactly one alert per iteration —
#        T1059 — pid=<child>: web server 'nginx' spawned shell '/bin/sh'
#      plus, on a kernel where lineage were broken (pre-#53): NO alert at all.
#
# Also eyeball the raw exec events (agent run --print-events, or the events sink):
# every '/tmp/nginx' → '/bin/sh' pair must show child.ppid == parent.pid and
# child.parent_comm == "nginx".

set -euo pipefail

FAKE_WEBSERVER=/tmp/nginx
ITERATIONS=3

cleanup() { rm -f "$FAKE_WEBSERVER"; }
trap cleanup EXIT

cp /bin/sh "$FAKE_WEBSERVER"

echo "Spawning $ITERATIONS shells from a process named 'nginx' ($FAKE_WEBSERVER)..."
for i in $(seq 1 "$ITERATIONS"); do
    # The fake web server (comm 'nginx') execs a child shell, which execs a leaf command.
    "$FAKE_WEBSERVER" -c '/bin/sh -c "id >/dev/null"'
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Check the agent terminal: one T1059 alert per iteration means lineage is"
echo "correct on this kernel ($(uname -r)); no alerts means #53 has regressed."
