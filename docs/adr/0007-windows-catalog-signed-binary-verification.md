# ADR-0007: Windows catalog-signed binary verification (issue #21's P7 follow-up)

- **Status**: accepted
- **Date**: 2026-09-08

## Context

Issue #21 (Windows ETW provider expansion) closed as completed, but its one
comment carried a scope addition that was explicitly **not** folded into that
work: `enrich`'s `sig.rs` module doc already documented a known limitation —
`WinVerifyTrust` in `WTD_CHOICE_FILE` mode checks only **embedded** Authenticode
signatures, and most Windows System32 binaries are **catalog-signed** instead
(discovered on CI: `notepad.exe` read `Signature::Unsigned`, not `Valid`). The
comment's instruction was explicit: "until then rules must not treat Windows
Unsigned as tampering" — a real detection-accuracy gap, not cosmetic, since any
rule keying off `Signature::Unsigned` as a suspicious-binary signal would
false-positive on a large fraction of stock Windows binaries.

`crates/enrich` deliberately avoids the `windows-sys` crate for its existing
`WinVerifyTrust` binding — "the API surface is one function and two structs,
stable since XP; a manual binding avoids pulling the whole windows-sys surface
into a detection-tier crate" (`sig.rs`'s original doc). The catalog-lookup
chain this ADR adds is a second, separate Win32 API surface
(`CryptCATAdminAcquireContext2` / `CryptCATAdminCalcHashFromFileHandle2` /
`CryptCATAdminEnumCatalogFromHash` / `CryptCATCatalogInfoFromContext` /
`CryptCATAdminReleaseCatalogContext` / `CryptCATAdminReleaseContext`, all
`wintrust.dll`/`mscat.h`, Windows 8+ — below this workspace's floor) with its
own structs (`WINTRUST_CATALOG_INFO`, `CATALOG_INFO`). The same rationale
applies here even more: this crate's whole reason to hand-bind FFI is to avoid
a heavyweight dependency for a small, stable API surface, so the catalog chain
is added as more manual bindings in the same `windows_impl` module, not a new
dependency.

## Decision

`sig::verify` (Windows) now tries two modes, in order:

1. **Embedded** (`WTD_CHOICE_FILE`, unchanged) — `windows_impl::verify_wide`.
2. **Only if (1) returns exactly `Signature::Unsigned`**: a catalog-membership
   check — `windows_impl::catalog_verify`. Not attempted for `Unsupported` (not
   a signable file type — a catalog lookup would not change that) or `Invalid`
   (a broken embedded signature is not "maybe fine via catalog" — it is already
   a concrete verdict).

`catalog_verify`'s flow: acquire a catalog-admin context
(`CryptCATAdminAcquireContext2`, hash algorithm `"SHA256"`) → compute the
file's hash via the documented two-call pattern (`CryptCATAdminCalcHashFromFileHandle2`
with a null buffer to learn the size, then again to fill it) → look the hash up
across installed catalogs (`CryptCATAdminEnumCatalogFromHash`) → if found,
resolve the catalog's file path (`CryptCATCatalogInfoFromContext`) → re-invoke
`WinVerifyTrust`, this time in `WTD_CHOICE_CATALOG` mode, with a
`WINTRUST_CATALOG_INFO` built from the catalog path, the file's own hash
(rendered as an uppercase hex `member_tag`, the documented convention), and the
still-open file handle → tear down the catalog context and then the admin
context, in that order, regardless of verdict.

`WintrustData.file` (previously typed `*mut WintrustFileInfo`) is retyped to
`*mut core::ffi::c_void`: the real C struct is a union between
`WINTRUST_FILE_INFO` and `WINTRUST_CATALOG_INFO` depending on `union_choice`,
and both call sites (embedded and catalog) now live in this module, each
casting its own struct pointer in.

The file handle behind `CryptCATAdminCalcHashFromFileHandle2` and
`WINTRUST_CATALOG_INFO.hMemberFile` comes from `std::fs::File::open` +
`AsRawHandle`, not a manual `CreateFileW` binding — std already owns opening
and closing it correctly, so there was no reason to hand-roll a second way to
get a `HANDLE`.

**Every failure path in `catalog_verify` returns `Signature::Unsigned`** —
context-acquisition failure, hashing failure, no catalog match (a real
"genuinely unsigned" outcome), catalog-info lookup failure. This is
deliberate: a tooling hiccup in the fallback path must never surface as
`Valid` (a false negative on a real Authenticode question) or `Invalid` (a
false positive branding a legitimate binary as tampered) — it must degrade to
exactly the same conservative default this crate already returned before this
ADR.

## Consequences

- The `sig.rs` module doc's "Known limitation" is resolved; a new
  `catalog_signed_system_binary_verifies` test (`lib.rs`, Windows-only, skips
  if `notepad.exe` is absent from the host) pins the exact regression #21's
  comment described.
- Cost: one extra round of Win32 calls (context acquire, two-call hash,
  catalog enum, catalog-info lookup, second `WinVerifyTrust`, two releases),
  but only when the embedded check specifically reports `Unsigned`, and only
  on a cache miss — `Enricher::enrich` already caches the final verdict per
  `(path, mtime, size)`, so this does not run per-event, only per distinct
  file version seen.
- `pStrongHashPolicy` is passed `NULL` (no minimum hash-strength/certificate-chain
  policy beyond `WinVerifyTrust`'s own default checks) — no requirement for
  that has surfaced yet; revisit if one does.
- Rules and detections that previously had to treat Windows `Unsigned` as "no
  embedded signature, not necessarily untrusted" per `sig.rs`'s original
  caveat now see substantially fewer false `Unsigned` verdicts on stock OS
  binaries — but the caveat itself is not deleted, since a file can still
  genuinely be neither embedded- nor catalog-signed (this is exactly what
  `unsigned_scratch_file`'s temp `.ps1` fixture continues to pin: real user
  scripts are never catalog members, so they correctly still read `Unsigned`
  after going through both checks).
