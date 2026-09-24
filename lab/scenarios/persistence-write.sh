#!/usr/bin/env bash
# Shell-profile persistence scenario (T1037.004, check_persistence_write).
#
# check_persistence_write (crates/rules/src/stateless.rs) fires on a write-intent
# FileOpenEvent whose path contains a known persistence location (.bashrc, .zshrc,
# /etc/cron.d/, /etc/systemd/system/, /etc/profile.d/, launchd directories on macOS).
# Appending a line to a shell profile is one of the oldest, plainest Linux malware
# persistence moves — cryptominers and simple backdoors do it because it needs no
# special privilege beyond what the compromised user already has, and it survives
# every new interactive shell. This scenario is that shape against the user's own
# ~/.bashrc, with a clearly marked, harmless comment line — never sourced as a real
# command, and removed again in cleanup.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/persistence-write.sh
#   3) expected in terminal A:
#      T1037.004/T1053.003 — pid=...: write to a known persistence path (.bashrc): ...

set -euo pipefail

TARGET="$HOME/.bashrc"
MARKER="# edr-lab-test-persistence-marker (harmless — added and removed by lab/scenarios/persistence-write.sh)"

cleanup() {
    [ -f "$TARGET" ] || return 0
    grep -vF "$MARKER" "$TARGET" > "${TARGET}.edr-lab-tmp" 2>/dev/null || true
    mv "${TARGET}.edr-lab-tmp" "$TARGET" 2>/dev/null || true
}
trap cleanup EXIT

touch "$TARGET"
echo "Appending a marker comment to $TARGET (a real write-intent open, never sourced as a command)..."
echo "$MARKER" >> "$TARGET"

echo "Done. Check the agent terminal for the T1037.004/T1053.003 alert."
