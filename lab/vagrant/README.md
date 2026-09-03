# lab/vagrant — Vagrant Harness

One of possibly several virtualization harnesses for the lab (see `../README.md`).
Implements the machine matrix from `../MATRIX.md` with Vagrant; provisioning is NOT
defined here — each VM runs the shared scripts from `../provisioning/`.

Known-working host setup (migrated from `old/lab/vagrant` after review):

- **macOS / Apple Silicon**: QEMU + the `vagrant-qemu` plugin. Linux arm64 boxes for
  every Linux row of the matrix; one dedicated host SSH port per machine (the QEMU
  plugin does not auto-allocate), so several VMs run in parallel. Repo synced one-way
  into each VM (no `.git/`, no `target/`).
- **Windows boxes are amd64** (VirtualBox / Hyper-V): unusable under QEMU on Apple
  Silicon — they run on an x86 host with VirtualBox or Hyper-V instead.

Contents (to migrate from `old/lab/vagrant`):

- `Vagrantfile` — machine definitions, providers, ports, sync
