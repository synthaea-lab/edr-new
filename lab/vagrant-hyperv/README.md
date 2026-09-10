# lab/vagrant-hyperv — Hyper-V Harness

One of the lab's virtualization harnesses (see `../README.md`). Sibling of
`../vagrant` (QEMU on Apple Silicon) for **Windows hosts with Hyper-V**. Same
machine matrix (`../MATRIX.md`), same provisioning
(`../provisioning/linux-toolchain.sh`).

Scope: the **Debian-family x86_64** rows. The `aarch64` dimension where issue #53
was originally found needs an arm64 host (the `../vagrant` harness).

| Machine | Kernel | Proves | Box |
| --- | --- | --- | --- |
| `ubuntu2204` (primary) | 5.15 | oldest supported LTS — strictest verifier | `generic/ubuntu2204` |
| `debian12` | 6.1 | Debian stable | `generic/debian12` |

## Host setup — once, ELEVATED PowerShell

```powershell
cd lab\vagrant-hyperv
.\bootstrap.ps1
```

Enables Hyper-V (may need a reboot — re-run after), adds you to *Hyper-V
Administrators* (log out/in once), installs Vagrant, checks the Default Switch.

The Hyper-V provider **requires an elevated shell** for every `vagrant` command
that touches a VM (`up`, `halt`, `ssh`, `destroy`, `rsync`).

## Usage

```powershell
$env:VAGRANT_HYPERV_SWITCH = "Default Switch"   # skip the interactive switch prompt
vagrant up ubuntu2204 --provider hyperv          # ~5 min boot + provisioning
vagrant rsync ubuntu2204                          # re-push the repo after host-side edits
vagrant ssh ubuntu2204
vagrant destroy -f ubuntu2204                     # rollback = destroy + up
```

The repo root is rsynced one-way to `/synthaea` (needs an `rsync` on the host —
Git for Windows ships one at `C:\Program Files\Git\usr\bin\rsync.exe`, or
`winget install cwRsync`). RAM: the boxes use Hyper-V Dynamic Memory, 1 GB
startup up to 4 GB — bring one machine up at a time, and `wsl --shutdown` first
(`helpers.ps1` `vprep` does this). If `vagrant up` still dies with `0x800705AA`
("Ressources système insuffisantes" / cannot allocate RAM), the host has under
~1.5 GB free — close a browser/IDE and retry; the VM balloons back up to 4 GB
for the build once memory frees up.

## Build + test in the VM

```powershell
vagrant ssh ubuntu2204 -c 'cd /synthaea && source ~/.cargo/env && cargo build --release -p agent'
vagrant ssh ubuntu2204 -c 'cd /synthaea && sudo ./target/release/agent status'   # verifier check, all 5 programs
# scenario: agent in one shell, scenario in another
vagrant ssh ubuntu2204 -c 'cd /synthaea && sudo env RUST_LOG=sensor_linux=info ./target/release/agent run --alerts /tmp/a --events /tmp/e &  sleep 4;  bash lab/scenarios/beacon.sh;  sleep 2;  sudo pkill -f "agent run";  grep T1071 /tmp/a'
```

Let the agent create the `--alerts` / `--events` files (a host-user-owned
pre-created file makes its `open()` fail with EACCES). Use `sudo env VAR=...`,
not `sudo VAR=... cmd` — the default sudoers env policy drops the latter.

## Missing boxes (6.8 / 6.12)

`ubuntu2404` (6.8) and `debian13` (6.12) have **no usable Hyper-V Vagrant box**
(`bento/*` dropped Hyper-V; `generic/*` covers only some releases). Options:

- ~~`boxen/ubuntu-24.04`~~ — has a Hyper-V provider but was **tried and
  rejected**: prompts for Windows SMB credentials on every `up` (its `/vagrant`
  is an SMB share) and ships a root disk too small for the Rust + LLVM toolchain
  (provisioning dies with `No space left on device`);
- build a box from the official cloud image (`qemu-img convert -O vhdx`, add a
  `vagrant` user + the insecure key, `vagrant box add`) — ~an evening — this is
  now the remaining path for these two rows;
- or run those two rows on the `../vagrant` (arm64) harness / Florian's matrix.

5.15 is the strictest verifier of the four, so `ubuntu2204` + `debian12` catch
most kernel-portability regressions on their own.
