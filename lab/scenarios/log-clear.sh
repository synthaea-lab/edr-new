#!/usr/bin/env bash
# Log-clearing / anti-forensics scenario (T1070.002, issue #80-adjacent).
#
# check_log_file_delete (crates/rules/src/stateless.rs) fires when a FileDeleteEvent's
# path falls under a known log location (LOG_PATH_PATTERNS: /var/log/,
# /private/var/log/, /log/journal/, .evtx). Deleting logs outright is one of the most
# universal anti-forensics moves in real intrusions — ransomware wiping its tracks
# before or after encryption, a backdoor covering its install, a compromised service
# hiding its own crash. This scenario is that shape with no real target: it creates
# its own throwaway file under /var/log/ and deletes only that.
#
# check_log_clear_exec (the exec-side sibling — journalctl --vacuum, wevtutil cl, the
# macOS unified-log erase) is NOT exercised here: none of its command patterns apply
# on a systemd-less distro (no journalctl binary on Alpine). Validate that half on a
# systemd-based row of the matrix (Ubuntu/Debian) instead.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/log-clear.sh
#   3) expected in terminal A:
#      T1070.002 — pid=...: log file deleted (/var/log/): /var/log/edr-lab-test.log

set -euo pipefail

LOGFILE=/var/log/edr-lab-test.log

cleanup() { rm -f "$LOGFILE"; }
trap cleanup EXIT

echo "Creating a throwaway log file ($LOGFILE)..."
echo "harmless test content, $(date -u +%FT%TZ)" > "$LOGFILE"

echo "Deleting it (the anti-forensics move: T1070.002 Indicator Removal: Clear Logs)..."
rm -f "$LOGFILE"

echo "Done. Check the agent terminal for the T1070.002 alert."
