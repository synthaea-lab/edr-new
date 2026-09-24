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
# Shape: a process named like a web server (a copy of a real shell binary — comm
# becomes the basename) spawns a real shell that runs a command. The T1059 rule
# (check_web_server_spawns_shell) fires only if the child's ppid resolves to the
# "nginx" parent — i.e. only if lineage is correct.
#
# Busybox userlands (Alpine): /bin/sh is a symlink to the busybox multi-call binary,
# which dispatches by argv[0] — copying it to a file named "nginx" breaks its own
# applet lookup ("applet not found"), so this can't just `cp /bin/sh`. We fall back
# to $BASH there instead (a real standalone binary, unaffected by that dispatch) —
# the interpreter actually running this script, not a hardcoded /bin/bash path: the
# script's own shebang already requires bash, so a "no bash available" branch could
# never be reached anyway (#430 review).
#
# Both branches wrap the inner shell in an explicit subshell (parens): bash and dash
# both tail-call-optimize a `-c` script whose entire body is one simple command,
# self-exec'ing in place rather than forking, which would leave the child's ppid
# pointing at this script instead of at the nginx-named process. The subshell forces
# the fork that optimization would otherwise skip — costs nothing on either shell,
# and keeps the two branches identical in shape. Validated live on Alpine 6.18 (PR
# #415 review) — 3/3 alerts, 0 ppid=0.
#
# Usage:
#   1) terminal A: sudo target/release/agent run --events events.jsonl --alerts alerts.ndjson
#   2) terminal B: ./lab/scenarios/lineage.sh
#   3) expected: exactly one alert per iteration —
#        T1059 — pid=<child> comm=sh executed directly by ppid=<nginx-pid> comm=nginx
#        (web server) — suspicious process lineage
#      plus, on a kernel where lineage were broken (pre-#53): NO alert at all.
#
# Also eyeball the raw exec events in events.jsonl: every nginx-comm exec followed by
# a sh-comm exec must show the sh event's ppid equal to the nginx event's pid.

set -euo pipefail

FAKE_WEBSERVER=/tmp/nginx
ITERATIONS=3

cleanup() { rm -f "$FAKE_WEBSERVER"; }
trap cleanup EXIT

SH_TARGET=$(readlink -f /bin/sh 2>/dev/null || echo /bin/sh)
if [[ "$SH_TARGET" == *busybox* ]]; then
    cp "$BASH" "$FAKE_WEBSERVER"
else
    cp /bin/sh "$FAKE_WEBSERVER"
fi
INNER_CMD='(/bin/sh -c "id >/dev/null")'

echo "Spawning $ITERATIONS shells from a process named 'nginx' ($FAKE_WEBSERVER)..."
for i in $(seq 1 "$ITERATIONS"); do
    # The fake web server (comm 'nginx') execs a child shell, which execs a leaf command.
    "$FAKE_WEBSERVER" -c "$INNER_CMD"
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Check the agent terminal: one T1059 alert per iteration means lineage is"
echo "correct on this kernel ($(uname -r)); no alerts means #53 has regressed."
