# lab/vagrant — Vagrant Harness (QEMU / Apple Silicon)

One of possibly several virtualization harnesses for the lab (see `../README.md`).
Implements the machine matrix from `../MATRIX.md`; each VM runs the shared
provisioning from `../provisioning/`. For Windows hosts, see `../vagrant-hyperv/`.

## Host setup (macOS / Apple Silicon)

- **QEMU**: `brew install qemu`
- **Vagrant** + the QEMU provider plugin: `vagrant plugin install vagrant-qemu`
- Windows boxes are **amd64** (VirtualBox / Hyper-V): unusable under QEMU on Apple
  Silicon — run them on an x86 host instead (issue #22).

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
