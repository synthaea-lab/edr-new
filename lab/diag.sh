#!/usr/bin/env bash
# eBPF toolchain diagnostic — run inside a lab VM when a build lands WITHOUT the
# embedded probes ("sensor-linux was built without embedded eBPF probes"):
#
#   vssh ubuntu2204 'bash /synthaea/lab/diag.sh'
#
# Checks the three things userspace/build.rs needs (bpf-linker on PATH, a nightly
# with rust-src, an LLVM major that matches), then does a verbose probe build so
# the real rustc/bpf-linker error is visible instead of buried by aya-build.
set -u
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true

echo "=== bpf-linker on PATH ==="
command -v bpf-linker && bpf-linker --version || echo "  bpf-linker NOT on PATH — run: vagrant provision <machine>"
echo
echo "=== ~/.cargo/bin ==="
ls -la "$HOME/.cargo/bin/" | grep -E 'bpf|aya|bindgen' || echo "  none"
echo
echo "=== /usr/local/bin symlinks (sudo's PATH) ==="
ls -la /usr/local/bin/ | grep -E 'bpf|aya|bindgen' || echo "  none"
echo
echo "=== nightly rustc LLVM major ==="
rustup run nightly rustc -Vv 2>&1 | grep -i llvm || echo "  no nightly toolchain?"
echo
echo "=== nightly rust-src component ==="
rustup component list --toolchain nightly 2>/dev/null | grep rust-src || echo "  rust-src missing — rustup component add rust-src --toolchain nightly"
echo
echo "=== system LLVM ==="
llvm-config --version 2>&1 || echo "  no llvm-config"
ls -d /usr/lib/llvm-* 2>/dev/null || echo "  no /usr/lib/llvm-*"
echo
echo "=== verbose probe build ==="
cd /synthaea && cargo build --release -p sensor-linux 2>&1 \
  | grep -iE 'bpf-linker|error|warning: sensor-linux|embedded|Compiling sensor|Finished' | head -30
