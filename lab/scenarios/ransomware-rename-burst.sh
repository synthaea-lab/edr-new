#!/usr/bin/env bash
# Mass-rename ransomware scenario (T1486, check_mass_rename_pattern, issue #262).
#
# check_mass_rename_pattern (crates/rules/src/state.rs) fires when the same pid
# renames RANSOMWARE_RENAME_THRESHOLD (20) or more files within
# RANSOMWARE_RENAME_WINDOW_NS (5s), each rename keeping the original filename intact
# and appending a new suffix (invoice.pdf -> invoice.pdf.locked) — real ransomware's
# near-universal tell, extension-agnostic by design (matches on "old_path is a
# strict prefix of new_path", not a hardcoded extension list).
#
# This scenario creates its own throwaway directory of empty files and renames only
# those — no real data touched, nothing actually encrypted, matching the
# benign-by-construction convention of the rest of lab/scenarios/.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/ransomware-rename-burst.sh
#   3) expected in terminal A:
#      T1486 — pid=...: 20 files renamed with an appended suffix in 5s
#      (e.g. .../file19.docx -> .../file19.docx.locked) — suspected ransomware
#      encryption pass

set -euo pipefail

# $HOME, not /tmp: keeps this scenario independent of the /tmp write-intent carve-out
# (issue #325/#426) — renames aren't filtered there either way (mutation events are
# never dropped, only reads), but $HOME is also the more representative target: real
# ransomware goes after documents, not scratch space.
DIR="$(mktemp -d "$HOME/edr-lab-ransomware-XXXXXX")"
COUNT=22 # a couple past RANSOMWARE_RENAME_THRESHOLD (20) for timing margin

cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

echo "Creating $COUNT throwaway files in $DIR..."
for i in $(seq 0 $((COUNT - 1))); do
    : > "$DIR/file${i}.docx"
done

echo "Renaming all $COUNT files, appending .locked, in a tight loop..."
for i in $(seq 0 $((COUNT - 1))); do
    mv "$DIR/file${i}.docx" "$DIR/file${i}.docx.locked"
done

echo "Done. Check the agent terminal for the T1486 alert."
