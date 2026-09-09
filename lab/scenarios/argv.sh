#!/usr/bin/env bash
# argv/cmdline fidelity scenario (issue #152).
#
# The eBPF probe no longer reads argv from `mm->arg_start..arg_end` (the last
# per-kernel frozen offset); the userspace loader reads `/proc/<pid>/cmdline` when it
# drains the exec event. This scenario is the assertion for "argv/cmdline is correct
# across the Linux rows of MATRIX.md": the T1059.004 base64 rule matches on the
# process's `cmdline`, so it fires *only if* the loader captured the argument vector.
#
# Shape: a shell runs a one-liner that contains `base64` and a decode flag. The
# check_base64_decode rule (stateless, cmdline substring) fires iff `cmdline` was
# populated — i.e. iff the `/proc/<pid>/cmdline` read on this kernel worked.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/argv.sh
#   3) expected: exactly one alert per iteration —
#        T1059.004 — pid=<sh> comm=sh: command line contains a base64 decode: sh -c ...
#      No alert means argv/cmdline capture is broken on this kernel ($(uname -r)).
#
# Also eyeball the raw exec events (agent run --print-events): every `sh -c` event
# must show the full `argv` (["sh", "-c", "echo ... | base64 -d ..."]) and a
# space-joined `cmdline`, not an empty vector.
#
# Note: a process that exits within the drain latency (a few ms) legitimately shows
# an empty argv — the accepted race of the userspace read. The `sh -c` pipeline here
# lives long enough that the read is reliable.

set -euo pipefail

ITERATIONS=3
PAYLOAD='ZWNobyBoZWxsbwo='  # "echo hello\n"

echo "Running $ITERATIONS shell invocations with a base64 decode in argv..."
for i in $(seq 1 "$ITERATIONS"); do
    sh -c "echo $PAYLOAD | base64 -d >/dev/null"
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Check the agent terminal: one T1059.004 alert per iteration means argv/"
echo "cmdline capture is correct on this kernel ($(uname -r)); no alerts means #152"
echo "has regressed (the /proc/<pid>/cmdline read returned nothing)."
