# ADR-0012: Windows kernel driver framework — classic WDK/C for the minifilter core, not `windows-drivers-rs` yet

- **Status**: proposed
- **Date**: 2026-09-18

## Context

Issue #39 ("Windows kernel driver (minifilter, ELAM/PPL) — long term") is the
framework that #136 (minifilter file telemetry), #137 (handle-access +
injection telemetry), and #138 (WFP network telemetry) all depend on. Nothing
exists yet beyond a placeholder README in `crates/sensors/windows/driver/`
noting the crate is intentionally **not** a cargo workspace member, since
kernel drivers have their own build/signing pipeline.

Two things are worth separating, because #39's body conflates them:

1. **ELAM + attestation signing** (PPL protection, tamper-resistance,
   production distribution) — genuinely gated on Microsoft Virus Initiative
   (MVI) membership, an organizational process outside engineering's control.
2. **The minifilter itself and kernel callbacks** (#136/#137's actual
   telemetry) — these can be developed and validated today in the lab using
   Windows **test-signing mode** (`bcdedit /set testsigning on`), the standard
   way to develop and load an unsigned/test-signed driver before a production
   signing path exists. Nothing about writing the minifilter requires MVI.

This ADR only covers (2): what language/framework to build the minifilter
core in, and what the lab prerequisites are. It does not resolve (1), which
stays an organizational decision tracked on #39 itself.

### Environment audit (2026-09-18, on the machine likely to do this work first)

- Visual Studio 2022 BuildTools is installed, **with** the
  `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` component (MSVC
  compiler + linker) — the baseline either option below needs.
- **No WDK** is installed: `Windows Kits\10\Include` only has the SDK
  (`10.0.26100.0`), no `km\` kernel headers, no `fltKernel.h`. The WDK is a
  separate installer + VS extension from Microsoft, not part of BuildTools by
  default.
- **No LLVM** (`llvm-config` not found, not present via `winget`) — this is
  specifically required by `windows-drivers-rs` for its bindgen step.
- **Test-signing is off** (default state, never enabled on this machine).

So today, neither path is ready to build immediately — the WDK itself is
the first missing piece regardless of language choice.

### Option A — Classic WDK in C

The Microsoft-documented, sample-backed path. `fs-minifilter` samples exist
in the official [Microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples)
repo covering exactly this shape of work (`FltRegisterFilter`,
pre/post-operation callbacks on `IRP_MJ_CREATE`/`IRP_MJ_SET_INFORMATION`,
etc.). Mature tooling (WDK + Visual Studio driver project templates,
`infverif`, `traceview`/WPP for kernel logging), broad community and
Microsoft support, and every existing tutorial/StackOverflow answer for
minifilter development assumes this stack.

Cost: breaks the repo's "everything in Rust" convention. The driver becomes
a second language surface the team maintains, bridged to the Rust agent via
some IPC mechanism (a named pipe or a custom `DeviceIoControl` interface is
the standard pattern — FltMgr already gives user-mode communication ports
(`FltCreateCommunicationPort`) for exactly this).

### Option B — `windows-drivers-rs` (Microsoft's official Rust WDK bindings)

Fetched from the project's own README (2026-09-18): "in early stages of
development and **is not yet recommended for production use**." It provides
FFI bindings + some safe abstractions for **WDM, KMDF** (1.33 on crates.io),
**UMDF** (2.33), and Win32 services — there is no mention of minifilter
(`FltMgr`)-specific safe wrappers. Building a minifilter on top of this today
would mean raw, unsafe FFI against `fltKernel.h`-equivalent bindings that
don't yet exist in the project, i.e. doing the hard, error-prone part
ourselves with none of the safety benefit Rust is supposed to buy here.

Also requires LLVM 17.0.6 specifically (bindgen dependency) and `cargo-make`,
neither installed. Kernel-mode Rust additionally requires `#![no_std]` +
`panic = "abort"` + a custom allocator — a real, unfamiliar-to-the-team
constraint on top of unfamiliar kernel APIs.

## Decision

**Proposed**: build the minifilter core (#136) and kernel callbacks (#137) in
C against the classic WDK, following the Microsoft `fs-minifilter` sample as
a starting skeleton, communicating with the existing Rust agent process
through a `FltCreateCommunicationPort` connection (kernel side) /
named-pipe-equivalent (user side) — the same boundary pattern the agent
already uses for other IPC (see `agent/src/ipc.rs` for precedent, if it
exists — needs confirming before implementation).

Revisit `windows-drivers-rs` once it documents `FltMgr` support and drops
the "not recommended for production" caveat — re-litigating language choice
per driver component would be worse than picking one now and revisiting
later if the ecosystem matures. This ADR does not propose rewriting the
sensor's Rust normalization/schema layer in C — only the kernel-mode
minifilter binary itself; everything past the IPC boundary (parsing driver
events into `schema::Event`, rules, sinks) stays Rust, matching the pattern
already used for `sensor-windows-etw` (Rust) attaching to a C++-surfaced ETW
API.

This is marked **proposed**, not **accepted** — same convention as ADR-0008
before #218 formalized it. Given this breaks the repo's Rust-everywhere
convention, it should get explicit team sign-off before code lands, not be
decided unilaterally in a feature branch.

## Consequences

- **A second toolchain to install and maintain**: WDK (separate from the SDK
  already present), Visual Studio driver development workload, `inf`/`cat`
  packaging tools, kernel debugger (WinDbg) for lab validation.
- **A second language in the codebase.** C for the minifilter core only —
  scoped tightly to the IPC boundary, not spreading into detection logic.
- **Lab prerequisites before any code**: enable test-signing on lab VMs
  (`bcdedit /set testsigning on`, reboot required), generate a self-signed
  test certificate for driver package signing, install WDK + VS driver
  workload.
- **First concrete milestone** (before any real telemetry): a minimal
  minifilter that registers with `FltRegisterFilter`, logs load/unload via
  `DbgPrint`/WPP, and can be built, signed with a test cert, loaded via
  `fltmc load`, and unloaded cleanly on a test-signed lab VM — proving the
  pipeline end to end before investing in `IRP_MJ_CREATE`/`IRP_MJ_SET_INFORMATION`
  callback logic.
- **#39's ELAM/PPL scope stays separately blocked** on MVI — this ADR and the
  milestone above deliver #136/#137's telemetry value without touching that
  path, but the driver won't be tamper-resistant or production-signable until
  MVI membership resolves.

## Open questions for the team

- Does the agent already have a kernel-mode IPC precedent to follow (device
  ioctl, named pipe, ALPC), or does this introduce the first one?
- Who owns WDK/driver-signing expertise on the team, or is this the first
  person to ramp up on it? (Affects timeline — kernel driver development has
  a real learning curve independent of language choice.)
- Lab VM readiness: which lab machine(s) get test-signing enabled, and is
  that acceptable given it slightly weakens the VM's own security posture
  (test-signed drivers from anywhere can load)?

## References

- Issue #39 — Windows kernel driver (minifilter, ELAM/PPL) — long term.
- Issue #136 — Windows minifilter file telemetry.
- Issue #137 — Windows handle-access + injection telemetry.
- Issue #138 — Windows WFP network telemetry + inline block.
- `crates/sensors/windows/driver/README.md` — existing placeholder, planned
  capabilities list.
- [microsoft/windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) — status checked 2026-09-18.
- [microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples) — `filesys/miniFilter` samples.
- ADR-0004 — sibling precedent for scoping a Windows telemetry source
  decision explicitly, with options considered and a documented rationale.
