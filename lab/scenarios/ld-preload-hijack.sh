#!/usr/bin/env bash
# Dynamic linker hijack scenario (T1574.006, issue #363/#401).
#
# check_ld_preload_hijack (crates/rules/src/stateless.rs) fires when an ExecEvent's
# captured LD_PRELOAD/LD_AUDIT value (issue #363: parse_proc_environ_security reads
# /proc/<pid>/environ for a fixed allowlist — presence only, never the full
# environment) points outside the dynamic linker's own trust set (LD_TRUST_PREFIXES:
# /lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib). This scenario is that shape
# with no payload beyond proving the hook actually loaded: the "hijack" library's
# constructor writes one line to a file and does nothing else — no hooked libc
# symbols, no hiding, no backdoor. What a real LD_PRELOAD rootkit (Azazel, Jynx2,
# vlany, ...) does with that same loaded-constructor moment is out of scope here by
# design; this scenario asserts the detection surface, not a live implant.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/ld-preload-hijack.sh
#   3) expected in terminal A:
#      T1574.006 — pid=...: LD_PRELOAD=/tmp/edr-test-preload.so loads a shared
#      object outside the dynamic linker's trusted search path

set -euo pipefail

SRC=/tmp/edr-test-preload.c
LIB=/tmp/edr-test-preload.so
MARKER=/tmp/edr-test-preload.marker

cleanup() { rm -f "$SRC" "$LIB" "$MARKER"; }
trap cleanup EXIT

cat > "$SRC" <<'C'
/* Proves the LD_PRELOAD constructor ran — nothing else. No hooked symbols,
 * no process/file/network hiding, no backdoor. */
#include <stdio.h>
__attribute__((constructor))
static void mark_loaded(void) {
    FILE *f = fopen("/tmp/edr-test-preload.marker", "w");
    if (f) {
        fputs("loaded\n", f);
        fclose(f);
    }
}
C

echo "Compiling the benign preload library ($LIB, outside the linker trust set)..."
cc -fPIC -shared -o "$LIB" "$SRC"

echo "Running 'ls' with LD_PRELOAD=$LIB (untrusted path)..."
LD_PRELOAD="$LIB" ls >/dev/null

if [ -f "$MARKER" ]; then
    echo "Constructor ran (marker file present) — the preload actually loaded."
else
    echo "WARNING: marker file missing — the preload may not have loaded." >&2
fi

echo "Done. Check the agent terminal for the T1574.006 alert."
