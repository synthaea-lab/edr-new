#!/usr/bin/env bash
# Local lint gate — the same checks CI runs, for when you'd rather not spend the
# CI budget on a a work-in-progress push. Run it inside a provisioned lab VM
# (the toolchain is already there):
#
#   vssh ubuntu2204 'bash /synthaea/lab/lint.sh'
#
# Mirrors `.github/workflows/ci.yml`: fmt + clippy (`-D warnings`, workspace
# minus the bpfel-target ebpf crate) + fmt on the ebpf crate on its own.
set -uo pipefail
cd /synthaea
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

echo "== cargo fmt --check =="
# rustfmt.toml sets unstable options (group_imports, imports_granularity) — stable
# rustfmt ignores them and reports spurious diffs, so format-check on nightly.
cargo +nightly fmt --all --check && echo "  fmt OK" || { echo "  FMT ISSUES ^"; FAIL=1; }

echo
echo "== clippy (workspace, minus sensor-linux-ebpf — same as CI) =="
cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets -- -D warnings 2>&1 \
  | grep -vE '^\s*(Compiling|Checking|Finished|warning: sensor-linux@)' | tail -40
CLIPPY=${PIPESTATUS[0]}
[ "$CLIPPY" -eq 0 ] && echo "  clippy OK" || { echo "  CLIPPY FAILED ^"; FAIL=1; }

echo
echo "== sensor-linux-ebpf: fmt only (clippy needs the bpfel target) =="
cargo +nightly fmt -p sensor-linux-ebpf --check && echo "  ebpf fmt OK" || { echo "  ebpf FMT ISSUES ^"; FAIL=1; }

echo
[ -z "${FAIL:-}" ] && echo "[LINT PASS]" || { echo "[LINT FAIL]"; exit 1; }
