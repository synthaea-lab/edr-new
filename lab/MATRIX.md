# Lab Machine Matrix

The canonical list of machines the lab must be able to produce, harness-independent.
Every harness (`vagrant/`, or your own) should be able to bring up any Linux row; the
Windows and macOS rows carry their own host constraints.

## Why a kernel matrix

The eBPF probes are largely tracepoint-driven — parent lineage from `sched_process_fork`
fields, the executed image from `sched_process_exec` (issues #53/#111), no per-kernel
freeze for either. One frozen-offset read remains: `cmdline` via `mm->arg_start..arg_end`
(the `vmlinux*` bindings), correct only on the kernel they were generated from. So every
kernel row is a genuine portability test case — that `mm` read, plus tracepoint record
layout, `__data_loc` handling, BTF at load, and verifier behaviour, all drift across
versions. Not redundancy.

| Machine | Family | Kernel | Proves |
| --- | --- | --- | --- |
| ubuntu-24.04 (primary) | Debian | 6.8 | primary dev/validation target |
| ubuntu-22.04 | Debian | 5.15 | oldest supported LTS kernel |
| debian-12 | Debian | 6.1 | Debian stable |
| debian-13 | Debian | 6.12 | newest kernel drift |
| fedora-41 | RPM | 6.11 | RPM family; replay-only where LLVM too old for eBPF builds |
| rocky-9 | RPM (RHEL) | 5.14 | enterprise RHEL-clone baseline; replay-only |
| windows-11 / windows-10 | Windows client | — | ETW sensor validation |
| windows-server | Windows server | — | ETW on server SKUs |
| macos | macOS | — | EndpointSecurity validation — real hardware or Tart/UTM; no Vagrant box |

Additions to this file are the trigger for harness updates, not the other way around.
