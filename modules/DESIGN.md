# NARF loadable kernel modules — design

NARF historically shipped every driver in-tree. As of Wave 20 the
kernel supports runtime-loadable modules so:

  * Out-of-tree drivers can be developed without rebuilding the
    kernel.
  * Optional features (vendor blobs, experimental subsystems, debug
    tools) load on demand.
  * `rmmod` returns the module's memory and revokes its symbol
    exports cleanly.

The implementation lives in `narf-modules/`. This document explains
the architecture choices.

## Where NARF deviates from Linux

The Linux `.ko` mechanism (in `kernel/module/*.c`) is the closest
prior art. NARF borrows the overall pipeline — parse, relocate,
resolve symbols, call init — but diverges on three load-bearing
points where Linux's choices don't fit the framekernel.

### 1. Cap-typed exports

Linux's `EXPORT_SYMBOL` family has one bit of authorization
(`GPL` / non-GPL). NARF gives each exported symbol an optional
`required_cap`. When the relocator resolves an undefined reference
to a cap-gated export, it checks the module's manifest for a
matching `required_caps=` entry; if absent, load fails with
`-EINVAL` and a diagnostic identifying both the symbol and the
missing cap.

This pushes cap enforcement to *link time* instead of first call.
A buggy out-of-tree driver can't accidentally invoke a privileged
API path because the kernel refuses to wire the pointer in.

### 2. Domain placement

Every NARF module declares a `target_domain=<name>` in its
manifest. The loader maps the module's text + rodata into the
PKS-isolated region for that domain (read-execute from in-domain,
no-access from out-of-domain) and the data + bss into the same
domain's RW region.

The runtime side (PKS PKey assignment, MTE tag, PCID-tagged page
table) is the responsibility of the per-arch HAL — `narf-modules`
allocates with the right `DomainId` and trusts the HAL to enforce
the boundary. On hardware without PKS/MTE, the allocator simply
draws from a domain-tagged frame pool that the scheduler can
honour during context switches.

A buggy module can scribble only its own domain. Linux has no
equivalent; a misbehaving driver can corrupt anything.

### 3. Versioned ABI

Linux's `MODVERSIONS` mechanism is a per-symbol CRC over the
function signature. NARF preserves that idea (the per-export `crc`
field) and adds a coarser whole-kernel `kernel_abi=` hash carried
in every module's manifest.

`kernel_abi` is a 32-bit hash of the running kernel's build
(currently a simple version string; LTO-image hashing is on the
near roadmap). The manifest parser refuses to load a module whose
`kernel_abi` doesn't match. This catches the "wrong kernel
version" case without needing per-symbol CRC bookkeeping for the
common case.

Per-symbol CRCs still apply — they catch the harder case where the
kernel ABI hash matches but a single subsystem's signature
changed.

## Pipeline

```
                 ┌─────────────────┐
                 │ init_module(2)  │
                 │ finit_module(2) │
                 └────────┬────────┘
                          │ image bytes
                          ▼
                  ┌──────────────┐
                  │ sign::verify │  cap-gated; default no-op
                  └──────┬───────┘
                         ▼
                ┌─────────────────┐
                │ elf::parse_*    │  Elf64 + section walk
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ manifest::parse │  .modinfo + kernel_abi check
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ domain::resolve │  target_domain → DomainId
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ W^X invariant   │  reject SHF_EXEC + SHF_WRITE
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ alloc placements│  one Vec<u8> per loadable section
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ relocator       │  walk .rela.* + apply
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ find init/exit  │  narf_module_init + _exit symbols
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ params::parse   │  .narf_kparams k=v lines
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ registry::insert│  + install /sys/module/<name>/
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ invoke_init     │  state Loading → Live
                └─────────────────┘
```

The pipeline is hard-cutover: every error along the way aborts the
load without leaving partial state. We don't support "load with
warnings". The single exception is `Loading` state, which exists
only briefly between layout completion and `invoke_init`.

## Trust model

There are three trust tiers:

  1. **Signature-verified.** A `sign::verify` hook (cap-gated by a
     `ModuleVerify` cap when wired) gates the entire load. Phase 1
     ships a no-op verifier and an `AcceptAll` default. Ed25519
     verification is on the near roadmap — the hook contract is
     stable so the implementation can land without breaking the
     loader.

  2. **Cap-mediated.** Symbols can require caps. A module that
     wants `narf_block::register_block_device` must declare
     `required_caps=BlockDevice:Write` in its manifest. The kernel
     enforces this at link time.

  3. **Admin-only.** `init_module`, `finit_module`, and
     `delete_module` are themselves cap-gated (caller must hold a
     `Cap<Process, Invoke>` with elevated privileges — wired into
     the syscall trap once the syscall plumbing in
     `narf-userspace/handlers` lands). The current Phase 1 wiring
     uses the userspace process's existing privilege model; richer
     per-action caps come later.

## W^X enforcement

Every loadable section is scanned for `SHF_EXECINSTR | SHF_WRITE`.
A section with both is rejected on principle — kernel-mode JIT is
out of scope and a module that wants both is more likely buggy
than principled.

When the PKS HAL hookup lands, text + rodata sections will be
mapped RX-from-domain / no-access-out-of-domain. Data + bss will
be mapped RW-from-domain. The two regions live in distinct PKey
slots so a runtime W^X violation also requires a PKEY-RU MSR
manipulation that the executor refuses.

## Per-export CRC versioning

Each `KernelExport` carries a `crc: u32`. The intent is for the
build system to compute the CRC from the function's signature
(types of args + return) — the same scheme Linux uses for
`MODVERSIONS`. Phase 1 leaves the CRC up to the caller of
`narf_export!(name, addr, crc)`; the build-system integration
that auto-generates CRCs from rustc's type info is deferred.

When a kernel build changes a signature, the export's CRC
changes. A module compiled against the old signature carries the
old CRC; the symbol resolver returns `ResolveError::CrcMismatch`
and the load aborts.

## §6 Per-module symbol ownership and unregister-on-unload

Prior to Wave-29 there was a use-after-free gap: `register_export` added
symbols to KSYMTAB unconditionally at module init time. On
`sys_delete_module` the exports persisted, and a subsequent `resolve` call
could return a dangling address pointing into freed module memory.

This is now fixed. The implementation follows Linux's
`kernel/module/kallsyms.c::module_kallsyms_lookup_name` (per-module symbol
table) and `kernel/module/main.c::free_module` (the sweep point).

### Design choice: Design A — owner-id field on each KSYMTAB entry

Each `KernelExport` carries an `owner: ModuleId` field. In-tree exports
use `KERNEL_MODULE_ID = ModuleId(0)`. LKM exports use a per-module
`ModuleId` assigned at load time from `symbols::alloc_module_id()`.

Design B (side-table of ModuleId → Vec<name>) was considered and rejected:
KSYMTAB is small (tens to low hundreds of entries), so the single-pass
`retain()` sweep in `unregister_exports_of` is cheaper than maintaining a
two-structure invariant.

### API

```rust
/// Permanent kernel export — KERNEL_MODULE_ID owner.
pub const KERNEL_MODULE_ID: ModuleId = ModuleId(0);

/// Allocate a fresh ModuleId for a loading module.
pub fn alloc_module_id() -> ModuleId;

/// Register with explicit owner (for callers that need control).
pub fn register_export_owned_by(owner: ModuleId, export: KernelExport);

/// Register using the current init-attribution context.
/// Outside invoke_init this is KERNEL_MODULE_ID (permanent).
pub fn register_export(export: KernelExport);  // thin wrapper, not a shim

/// Sweep all KSYMTAB entries owned by module_id. Returns count removed.
/// Called from sys_delete_module after invoke_exit, before registry::remove.
pub fn unregister_exports_of(module_id: ModuleId) -> usize;
```

The existing `export(name, addr, crc)` and `export_with_cap(...)` helpers
are unchanged in signature — they route through `register_export` which
reads `current_init_id()` to auto-attribute. Callers outside any init
context (boot code) get `KERNEL_MODULE_ID` automatically.

### Init-attribution context

`loader::invoke_init` brackets the module's `narf_module_init` call with:

```rust
symbols::set_init_context(module.id);   // arm
let rc = init();
symbols::set_init_context(KERNEL_MODULE_ID);  // restore (even on error)
```

This means an LKM's init can call the bare `narf_export!` macro and the
symbol is automatically tagged with the right owner — no API change to
module authoring required. Linux uses `module->init_layout` and
`current->mm` for analogous context tracking.

### Unload sweep

`sys_delete_module` calls `symbols::unregister_exports_of(module.id)`
after `invoke_exit` returns but before `registry::remove` drops the Arc:

```rust
unsafe { loader::invoke_exit(&module) }.map_err(...)?;
let _removed = symbols::unregister_exports_of(module.id);
registry::remove(name);
```

### Verified by e2e smoke 4

`modules/e2e::e2e_unload_cleans_proc_and_sys` (formerly a deferral) now
asserts:
  1. Symbol visible after load (resolve returns Ok).
  2. Symbol gone after unload (resolve returns Err(Unknown)).
  3. Symbol reappears after re-load (idempotency across ModuleId allocation).

### Deferred items

  * **Per-symbol export reference counting.** If module B holds a function
    pointer resolved from module A's export, module A's `unregister_exports_of`
    removes the KSYMTAB entry but doesn't prevent B from calling through the
    stale pointer. Full safety requires refcount-guarded inter-module
    dependencies (like Linux's `try_module_get`/`module_put` pair).
  * **Livepatch.** Symbol ownership interacts with livepatch if a patched
    symbol is later unregistered; deferred until livepatch lands.
  * **`__reset_for_test` resets the MODULE_ID_ALLOC counter.** Tests that
    call `__reset_for_test` between loads get fresh IDs — adequate for
    in-kernel test isolation, but counter exhaustion at 2^64 is theoretical.

## Open questions / future phases

  * **Ed25519 signature verification.** The hook is in place; the
    implementation slots into `sign::install_verifier(...)`.
  * **modprobe userspace daemon.** A userspace tool that walks
    `/lib/modules/`, resolves `depends=`, and submits modules in
    the right order. Currently the kernel exposes the syscalls
    only.
  * **Auto-generated symbol-export pages.** Doc-tool plumbing to
    surface every `narf_export!` site in the rendered API docs.
  * **KASLR-aware fixup.** When the kernel slides at boot, the
    `KSYMTAB` addresses need to be relocated. Phase 1 assumes a
    fixed kernel base.
  * **Livepatch.** Linux's livepatch model leans heavily on the
    module loader. A future NARF livepatch system would reuse
    the relocator + cap-typed exports machinery.
  * **Module dependency graph.** The `depends=` field is parsed
    but not yet enforced — modprobe is expected to order the
    submissions correctly.
  * **Notes / build-id.** Module ELF notes (`.note.gnu.build-id`)
    are present but `/sys/module/<name>/notes/` is a placeholder.

## File layout

```
narf-modules/
  Cargo.toml
  DESIGN.md              ← this file
  MODULE_AUTHORING.md    ← how to write a NARF module
  src/
    lib.rs               ← public API + registry
    elf/                 ← ELF64 parsing
      mod.rs
      header.rs
      reloc.rs
      sections.rs
      symbols.rs
    manifest.rs          ← .modinfo parser + Manifest struct
    loader.rs            ← top-level pipeline
    relocator.rs         ← per-section .rela.* walker
    symbols.rs           ← KSYMTAB + cap-typed exports
    lifecycle.rs         ← state machine + init/exit ABI
    refcount.rs          ← per-module refcount
    domain.rs            ← domain placement
    params.rs            ← .narf_kparams parser
    proc_modules.rs      ← /proc/modules adapter
    sysfs_module.rs      ← /sys/module/<name>/ adapter
    syscalls.rs          ← init_module / finit_module / delete_module
    sign.rs              ← signature-verification hook
    tests.rs             ← module-stub
    tests_smoke.rs       ← in-tree QEMU smokes
```
