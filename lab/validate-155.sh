#!/usr/bin/env bash
# Runs INSIDE a lab VM. Full validation for PR #155 (issue #152 — argv read from
# /proc/<pid>/cmdline) plus the #53 parent-lineage non-regression, on whatever
# kernel this VM happens to run. Prints [PASS] or exits non-zero on the first
# failed assertion.
#
#   vssh ubuntu2204 'bash /synthaea/lab/validate-155.sh'
#
# Repeat across the Linux rows of lab/MATRIX.md — 5.15 (ubuntu2204) is the
# strictest verifier, 6.1 (debian12) the Debian baseline. See
# lab/vagrant-hyperv/RUNBOOK-155.md for the full host-side loop.
set -uo pipefail
cd /synthaea
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

KREL="$(uname -r)"
PRETTY="$(. /etc/os-release; echo "${PRETTY_NAME:-?}")"
echo "=================================================================="
echo " synthaea PR#155 validation — $PRETTY — kernel $KREL"
echo "=================================================================="
fail() { echo; echo "[FAIL] $*"; exit 1; }
ok()   { echo "[ok]   $*"; }
# `grep -c` prints the count but also exits 1 on zero matches — take just the number.
count() { grep -c "$@" 2>/dev/null | head -1; }

echo; echo "== build (agent + sensor-linux, pulls the eBPF probes) =="
cargo build --release -p agent -p sensor-linux 2>&1 | tail -5 || fail "build failed on $KREL"

echo; echo "== BTF =="
[ -r /sys/kernel/btf/vmlinux ] || fail "no /sys/kernel/btf/vmlinux — eBPF sensor cannot attach on $KREL"
ok "BTF present"

echo; echo "== verifier (agent status) =="
sudo ./target/release/agent status | tee /tmp/v155-status.txt || true
acc=$(count 'accepted by the verifier' /tmp/v155-status.txt)
[ "${acc:-0}" -ge 5 ] || fail "only ${acc:-0}/5 eBPF programs accepted by the verifier on $KREL"
ok "$acc/5 programs accepted"

echo; echo "== unit tests (normalize + parse_proc_cmdline + /proc stat) =="
cargo test -p sensor-linux -p sensor-linux-wire 2>&1 | tail -8 || fail "unit tests failed on $KREL"

# --- scenario runner -------------------------------------------------------
run_scenario() {   # $1 = scenario base name under lab/scenarios/
  local s="$1"
  A="/tmp/v155-$s-a"; E="/tmp/v155-$s-e"; L="/tmp/v155-$s.log"
  sudo rm -f "$A" "$E"
  sudo env RUST_LOG=sensor_linux=info ./target/release/agent \
    run --alerts "$A" --events "$E" >"$L" 2>&1 &
  sleep 6
  pgrep -f "target/release/agent run" >/dev/null \
    || { tail -30 "$L" | sed 's/^/    /'; fail "agent exited early running $s on $KREL"; }
  bash "lab/scenarios/$s.sh" >/dev/null 2>&1 || true
  sleep 2
  sudo pkill -f "target/release/agent run" 2>/dev/null || true
  sleep 1
  sudo chmod a+r "$A" "$E" 2>/dev/null || true
}

echo; echo "== scenario: argv  (#152 / #155) =="
run_scenario argv
# The scenario's own assertion: the T1059.004 base64 rule is a cmdline substring
# match, so it fires only if the /proc/<pid>/cmdline read populated the argv.
n=$(count '"T1059.004"' "$A")
echo "  T1059.004 (base64 decode) alerts: ${n:-0}   (expect >= 3)"
[ "${n:-0}" -ge 3 ] || { cat "$A" 2>/dev/null; fail "argv/cmdline NOT captured from /proc/<pid>/cmdline on $KREL — #152 regressed"; }
# The cooperative process the scenario guarantees outlives the drain: its full
# argv must be on the exec event. This is the actual "#152 argv is correct" check.
shargv=$(count '"argv":\["sh","-c","echo ' "$E")
echo "  sh -c events with full argv:       ${shargv:-0}   (expect >= 3)"
[ "${shargv:-0}" -ge 3 ] || { grep '"comm":"sh"' "$E" 2>/dev/null; fail "the cooperative sh -c argv was not captured on $KREL — #152 regressed"; }
# Short-lived children (uname from the scenario's own `$(uname -r)`, a fast
# base64) can legitimately race the drain and show argv:[] — the accepted
# userspace-read race, documented in argv.sh. Informational, not a gate.
empty=$(count '"argv":\[\]' "$E")
echo "  exec events with empty argv:       ${empty:-0}   (race on short-lived procs, informational)"
ok "argv capture correct on $KREL"

echo; echo "== scenario: lineage  (#53 non-regression) =="
run_scenario lineage
n=$(count '"T1059"' "$A")
echo "  T1059 lineage alerts: ${n:-0}   (expect >= 3)"
[ "${n:-0}" -ge 3 ] || { cat "$A" 2>/dev/null; fail "parent lineage broken on $KREL — child ppid did not resolve to 'nginx'"; }
bad=$(grep '/tmp/nginx' "$E" 2>/dev/null | count '"ppid":0')
echo "  /tmp/nginx exec events with ppid=0: ${bad:-0}   (expect 0)"
[ "${bad:-0}" -eq 0 ] || fail "some exec events lost lineage (ppid=0) on $KREL"
ok "lineage + authoritative image correct on $KREL"

echo
echo "=================================================================="
echo " [PASS] kernel $KREL — argv (#152/#155) + lineage (#53)"
echo "=================================================================="
echo
echo "Known non-blocking noise: a 'T1059 ... spawned 3x in 30s ... suspected"
echo "self-spawn' on the shell loop of each scenario — over-aggressive self-spawn"
echo "heuristic, the ppid is correct. Separate calibration issue, not a #155 gate."
