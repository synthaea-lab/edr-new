#!/usr/bin/env bash
# Signal-probe filter and tamper attribution scenario (issue #362).
#
# The eBPF kill/tgkill probes are filtered kernel-side by SIGNAL_WATCH_PID to
# signals aimed at the agent itself. This scenario asserts both sides of that
# filter, then the T1562.001 rule (check_security_process_signal) on top of it:
#
#   live         (default) signals between unrelated processes produce ZERO
#                Signal events; a probe (kill -0) to the agent produces one event
#                and no alert; an unprivileged SIGTERM and SIGKILL to the agent
#                (both fail with EPERM, the agent survives) each produce one
#                event and one T1562.001 alert. The probe fires at syscall entry,
#                before the permission check, which is what makes the attempt
#                visible at all.
#   kill         SIGKILLs the agent for real and records this shell's pid.
#   verify-kill  run after restarting the agent: asserts the restarted agent
#                replayed the SIGKILL from the pinned SIGNAL_TAMPER_LAST map and
#                alerted T1562.001 naming the sender recorded by `kill`.
#
# Usage (as root, agent already running, from the agent's working directory or
# with EVENTS/ALERTS pointing at its files):
#   sudo ./lab/scenarios/signal.sh
#   sudo ./lab/scenarios/signal.sh kill
#   (restart the agent)
#   sudo ./lab/scenarios/signal.sh verify-kill
#
# Environment: EVENTS (default events.jsonl), ALERTS (default alerts.ndjson),
# AGENT_PID (default: oldest process named "agent" or "synthaea-agent").

set -euo pipefail

EVENTS=${EVENTS:-events.jsonl}
ALERTS=${ALERTS:-alerts.ndjson}
STATE=/tmp/synthaea-signal-scenario.sender
# Long enough for the enrich queue to append the event to events.jsonl.
FLUSH_WAIT=3
MODE=${1:-live}
FAILURES=0

agent_pid() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        echo "$AGENT_PID"
    else
        pgrep -xo agent || pgrep -xo synthaea-agent || true
    fi
}

count_signal_events() { grep -c '"type":"signal"' "$EVENTS" || true; }
count_tamper_alerts() { grep -c '"technique":"T1562.001"' "$ALERTS" || true; }

# Runs a command as `nobody`, so a signal to the (root) agent fails with EPERM.
as_nobody() {
    if command -v setpriv >/dev/null; then
        setpriv --reuid=65534 --regid=65534 --clear-groups "$@"
    else
        su -s /bin/sh nobody -c "$*"
    fi
}

check() {
    local label=$1 expected=$2 actual=$3
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS  $label ($actual)"
    else
        echo "  FAIL  $label: expected $expected, got $actual"
        FAILURES=$((FAILURES + 1))
    fi
}

require_agent() {
    PID=$(agent_pid)
    if [[ -z "$PID" ]] || ! kill -0 "$PID" 2>/dev/null; then
        echo "No running agent found (set AGENT_PID)." >&2
        exit 2
    fi
    for f in "$EVENTS" "$ALERTS"; do
        [[ -f "$f" ]] || { echo "$f not found (set EVENTS/ALERTS)." >&2; exit 2; }
    done
}

run_live() {
    require_agent
    echo "Agent pid $PID, kernel $(uname -r)"

    echo "1) Unrelated signal traffic (must stay invisible)"
    sleep 300 & local a=$!
    sleep 300 & local b=$!
    local before
    before=$(count_signal_events)
    for _ in $(seq 1 20); do
        kill -0 "$a"
        kill -STOP "$b"
        kill -CONT "$b"
    done
    kill -TERM "$a" "$b"
    wait "$a" "$b" 2>/dev/null || true
    sleep "$FLUSH_WAIT"
    check "Signal events from 62 unrelated signals" 0 $(($(count_signal_events) - before))

    echo "2) Existence probe to the agent (event, no alert)"
    before=$(count_signal_events)
    local alerts_before
    alerts_before=$(count_tamper_alerts)
    kill -0 "$PID"
    sleep "$FLUSH_WAIT"
    check "Signal events from kill -0" 1 $(($(count_signal_events) - before))
    check "T1562.001 alerts from kill -0" 0 $(($(count_tamper_alerts) - alerts_before))

    echo "3) Unprivileged SIGTERM and SIGKILL to the agent (EPERM, still attributed)"
    before=$(count_signal_events)
    alerts_before=$(count_tamper_alerts)
    as_nobody kill -TERM "$PID" 2>/dev/null || true
    as_nobody kill -KILL "$PID" 2>/dev/null || true
    sleep "$FLUSH_WAIT"
    check "Signal events from the two attempts" 2 $(($(count_signal_events) - before))
    check "T1562.001 alerts from the two attempts" 2 $(($(count_tamper_alerts) - alerts_before))
    if kill -0 "$PID" 2>/dev/null; then
        echo "  PASS  agent survived the EPERM attempts"
    else
        echo "  FAIL  agent is gone"
        FAILURES=$((FAILURES + 1))
    fi
    echo "  The survived SIGKILL is cleared from the pinned slot within ~10s, so it"
    echo "  must NOT be reported on the next restart (checked by 'kill' + 'verify-kill')."
}

run_kill() {
    require_agent
    # Wait out the sweep of any SIGKILL attempt from a previous live run, so the
    # slot can only hold the kill below.
    sleep 12
    echo "$$" >"$STATE"
    echo "SIGKILL to agent pid $PID from pid $$ (comm $(cat /proc/$$/comm))"
    kill -KILL "$PID"
    echo "Restart the agent, then run: $0 verify-kill"
}

run_verify_kill() {
    [[ -f "$STATE" ]] || { echo "Run '$0 kill' first." >&2; exit 2; }
    local sender
    sender=$(cat "$STATE")
    echo "Waiting up to 30s for the restarted agent's T1562.001 alert (sender pid $sender)"
    local found=0
    for _ in $(seq 1 30); do
        if grep '"technique":"T1562.001"' "$ALERTS" | grep -q "pid=$sender .*SIGKILL (9)"; then
            found=1
            break
        fi
        sleep 1
    done
    check "SIGKILL alert naming the sender" 1 "$found"
    # Two alerts are fine: the dying agent sometimes drains the live event before
    # the kill lands, and the replay reports it again.
    rm -f "$STATE"
}

case "$MODE" in
    live) run_live ;;
    kill) run_kill ;;
    verify-kill) run_verify_kill ;;
    *) echo "usage: $0 [live|kill|verify-kill]" >&2; exit 2 ;;
esac

if [[ "$MODE" != kill ]]; then
    if [[ "$FAILURES" -eq 0 ]]; then
        echo "All checks passed."
    else
        echo "$FAILURES check(s) failed."
        exit 1
    fi
fi
