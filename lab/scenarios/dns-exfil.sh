#!/usr/bin/env bash
# Validation scenario for DNS tunnelling / exfiltration over DNS (T1048.003/T1071.004).
#
# Simulates a process that, within one correlation window (60s), issues many DNS
# queries under a single parent domain where each leftmost label is a long,
# high-entropy chunk — the shape produced by iodine / dnscat2 / DNSExfiltrator when
# they encode data into subdomains. Exercises the correlator's rule_dns_exfil
# (crates/correlator).
#
# Telemetry note: DNS events are currently emitted only by the Windows ETW
# DNS-Client sensor (EID 3008). On Linux there is no DNS sensor yet, so this
# scenario is a no-op for detection there until one lands — the rule itself is
# source-agnostic. Run it on a Windows lab host (see lab/MATRIX.md) with the agent
# running to see the alert.
#
# Usage:
#   1) host with agent running:  agent run
#   2) this box:                 ./lab/scenarios/dns-exfil.sh [PARENT_DOMAIN]
#   3) expected in the agent output:
#      T1048.003/T1071.004 — pid=... comm=...: N distinct high-entropy subdomains
#      of <parent> within the window — suspected DNS tunnelling / exfiltration

set -euo pipefail

PARENT="${1:-tunnel.example.invalid}"   # .invalid: never resolves, never leaves the resolver
QUERIES=16

resolve() {
    # Best-effort, order of preference; failure is expected (.invalid / NXDOMAIN).
    if command -v dig >/dev/null 2>&1; then
        dig +tries=1 +time=1 "$1" >/dev/null 2>&1 || true
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup "$1" >/dev/null 2>&1 || true
    else
        getent hosts "$1" >/dev/null 2>&1 || true
    fi
}

rand_label() {
    # 36 base32-ish chars from /dev/urandom — length > 30, high entropy.
    LC_ALL=C tr -dc 'a-z2-7' </dev/urandom | head -c 36
}

echo "Sending $QUERIES encoded-subdomain queries under .$PARENT ..."
for i in $(seq 1 "$QUERIES"); do
    name="$(rand_label).${PARENT}"
    resolve "$name"
    echo "  q$i: $name"
    sleep 0.3
done

echo "Done. Check for the T1048.003/T1071.004 alert in the agent output."
