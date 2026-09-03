# lab/provisioning — Provider-Neutral VM Setup

Provisioning scripts shared by every virtualization harness. A harness (Vagrant,
Hyper-V, Proxmox, cloud instances, ...) is only responsible for creating a machine and
running these scripts in it — the toolchain and lab setup live here, once.

| Script | Purpose |
| --- | --- |
| `linux-toolchain.sh` | Per-family toolchain (apt / dnf+CRB, rustup stable+nightly, bpf-linker, bindgen-cli, aya-tool), with the LLVM-major alignment the eBPF build needs |
| `windows-toolchain.ps1` (planned) | Rust toolchain + Windows SDK for ETW validation |
| `agent-install.sh` / `.ps1` (planned) | Install a built agent into a lab VM for scenario runs |

Scripts take no harness-specific assumptions: plain bash/PowerShell, idempotent,
runnable over ssh/winrm/cloud-init user data.
