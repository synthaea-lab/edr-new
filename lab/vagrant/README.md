# lab/vagrant — Vagrant Harness (QEMU / Apple Silicon)

One of possibly several virtualization harnesses for the lab (see `../README.md`).
Implements the machine matrix from `../MATRIX.md`; each VM runs the shared
provisioning from `../provisioning/`. For Windows hosts running Hyper-V, see
`../vagrant-hyperv/`.

## Host setup (macOS / Apple Silicon)

- **QEMU**: `brew install qemu`
- **Vagrant** + the QEMU provider plugin: `vagrant plugin install vagrant-qemu`
- Windows boxes are **amd64** (VirtualBox / Hyper-V): unusable under QEMU on Apple
  Silicon — run them on an x86 host instead (issue #22).

## Host setup (Windows / x86, VirtualBox) — Alpine row only

The `alpine319` machine is amd64, same as the Windows boxes — unusable under QEMU
on Apple Silicon. Unlike them it's a Linux guest, so it doesn't need
`../vagrant-hyperv/`'s Hyper-V provider either: it runs directly on VirtualBox,
which a Windows lab machine already needs for other work.

- **VirtualBox** (any recent 7.x) + **Vagrant**: `winget install Hashicorp.Vagrant`
- Neither installer adds itself to `PATH` reliably on Windows — open a fresh shell
  (or add `C:\Program Files\Vagrant\bin` yourself) before the commands below.

```
cd lab\vagrant
vagrant up alpine319 --provider virtualbox
vagrant ssh alpine319
vagrant destroy -f alpine319   # rollback = destroy + up
```

`generic/alpine319` (3.19/6.6) is the newest Alpine Vagrant Cloud publishes with a
virtualbox/amd64 provider — not the 3.24/6.18 `../MATRIX.md` and issue #123 were
manually validated against, but this row exists to prove musl/BusyBox toolchain
portability, not kernel-version drift (that's the `arch` row's job). Provisioning
is `../provisioning/alpine-toolchain.sh`; verified end to end on this box — build,
`agent status` (5/5 eBPF programs accepted by the verifier), and the full
`lab/scenarios/beacon.sh` walking-skeleton (T1071/T1041 alert fires as expected).

## Usage

```bash
cd lab/vagrant
vagrant up                 # primary machine (ubuntu2404) only
vagrant up debian13        # any machine from the matrix
vagrant ssh ubuntu2404
vagrant status
vagrant rsync ubuntu2404   # re-push the repo after host-side changes
```

Each Linux machine has a dedicated host SSH port (50022, 50122, …) — the QEMU plugin
does not auto-allocate, and distinct ports let several machines run in parallel.

The repository root is rsynced one-way into each VM at `/synthaea` (excluding `.git/`,
`target/`, `old/`, ML venv/datasets). Build inside the VM:

```bash
vagrant ssh ubuntu2404 -c 'cd /synthaea && cargo build --release -p agent'
```

Provisioning installs the family packages, rustup (stable + nightly + rust-src),
bpf-linker (with the LLVM-major alignment), bindgen-cli, and aya-tool — see
`../provisioning/linux-toolchain.sh`. On `fedora41`/`rocky9` no recent-enough LLVM is
available: provisioning continues with a warning and those VMs are replay-only.
