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

## What works, and what does not

Working end to end: parse, manifest, layout, mapping into an executable
module VA window with per-region W^X, in-place relocation (with aarch64
veneers), symbol resolution against a real KSYMTAB, link-time provider
pinning, init/exit, `/proc/modules`, `/sys/module/<name>/`, and the
three syscalls.

Known gaps, each expanded where it belongs below:

  * **No test loads a real `.ko` yet.** `cargo xtask build-module` now
    produces one for either architecture — extracting the crate's own
    members from the `staticlib` archive and `ld -r`-ing them into a
    single relocatable object with merged sections. What is still
    missing is a smoke that loads one. `--kernel-abi` stamps the
    running kernel's hash into the built object, so the pieces are
    there; what is not is the plumbing to get a `.ko` in front of the
    kernel under test — either in the initramfs for a smoke to
    `finit_module`, or embedded at build time. Until then every smoke
    still synthesizes its ELF.
  * **Driver domains are named but not enforced.** See §2.
  * **Per-action caps on the three syscalls are not wired.** See the
    trust model, tier 3.
  * **Signatures are accepted unconditionally.** The hook is real, the
    verifier is `AcceptAll`.
  * **A task preempted inside module code can resume on unmapped
    text.** See §6.

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

**Status: the name resolves, the isolation does not exist yet.**
`domain::resolve` maps `target_domain=` to a `DomainId` and the loader
stores it on the `Module`, and nothing reads it. `module_text::alloc`
draws ordinary buddy frames; it does not consult the domain.

What *is* enforced today is W^X (see below), which is a different and
weaker property: a module cannot manufacture executable memory, but it
can still scribble any kernel memory it can address. Getting from here
to the paragraph above needs two things, in order:

  1. A domain-tagged frame pool behind `module_text::alloc`, so a
     module's pages carry its `DomainId`. Cheap, and the enforcement
     machinery (`arch/src/x86_64/pks.rs`,
     `memory/src/domain_state.rs`) already exists.
  2. Call gates. `invoke_init` calls module code directly on the
     kernel stack, so enforcing a PKS domain means switching PKRS in
     *both* directions — kernel→module on entry and module→kernel on
     every export call. That puts a WRMSR on every crossing, which is
     worth building and worth measuring before it is turned on by
     default.

The claim "a buggy module can scribble only its own domain" belongs to
step 2 and should not be read as describing the current kernel.

### 3. Versioned ABI

Linux's `MODVERSIONS` mechanism is a per-symbol CRC over the
function signature. NARF preserves that idea (the per-export `crc`
field) and adds a coarser whole-kernel `kernel_abi=` hash carried
in every module's manifest.

`kernel_abi` is a 32-bit hash **derived from the export table**:
`symbols::compute_abi_hash` folds every registered `(name, crc)` pair,
order-independently. The manifest parser refuses to load a module whose
`kernel_abi` doesn't match. This catches the "wrong kernel" case
without needing per-symbol CRC bookkeeping for the common case.

Earlier drafts of this document planned to hash the LTO image instead.
Hashing the export table is better on the axis that matters: it changes
exactly when the thing modules depend on changes, and not when an
unrelated subsystem is recompiled. An image hash would reject every
module on every kernel rebuild, which trains people to ignore it.

Because the hash is derived, registration has to come first — see the
ordering note on `register_initcalls`. The hash cannot drift from the
surface it describes, because there is nowhere for it to drift to.

Per-symbol CRCs still apply — they catch the harder case where the
kernel ABI hash matches but a single subsystem's signature
changed.

## Where module memory lives

Physical provenance is irrelevant — `module_text::alloc` takes ordinary
buddy frames, no contiguity, no zone. Everything load-bearing is about
the virtual address and the permissions, which is also how Linux does
it (`execmem_alloc_rw` hands back vmalloc'd, scattered frames). Neither
the heap nor the module window is swappable: NARF's `SwapVictim` is
keyed on a user `pml4_phys` plus VA, and nothing enumerates kernel
frames as candidates.

The window placement is the load-bearing choice, and it is forced by
relocation range:

```text
  x86_64   PML4[511] PDPT[510]  0xFFFF_FFFF_8000_0000  kernel image
           PML4[511] PDPT[511]  0xFFFF_FFFF_C000_0000  module images
```

rustc emits calls to exported kernel symbols as `R_X86_64_PLT32` — a
signed 32-bit displacement. A module more than 2 GiB from the kernel
cannot be relocated at all, only rejected. Sitting the window directly
above the kernel image keeps every module within ~1.25 GiB, so PC32 and
PLT32 resolve directly and no GOT or PLT is needed. Linux places
`MODULES_VADDR` the same way for the same reason.

The BPF text window (slot 273, ~131 TiB away) would overflow every such
relocation. `bpf_text` gets away with that placement because the JIT
emits absolute `mov rax, imm64` + `call rax` and does not care about
distance; a module compiled by LLVM as an ordinary relocatable object
does.

PML4[511] already exists in every address space and `new_user_pml4_on`
snapshot-copies PML4[256..512] **by value**, so every root holds the
same PDPT frame by pointer. Populating PDPT[511] inside it propagates
with no reservation step and none of `bpf_text`'s §4.1 boot-ordering
hazard.

Module mappings are deliberately **not** GLOBAL. They are unmapped at
`rmmod`, and several TLB-flush paths retain global entries, which would
leave a stale executable translation on an idle peer. `bpf_text` does
set GLOBAL, and may, because its VA is never recycled.

### aarch64 needs veneers

```text
  aarch64  L0[510] L1[511] 0xFFFF_FF7F_F800_0000  module images
           L0[511] L1[0]   0xFFFF_FF80_0000_0000  linear map: phys 0-1 GiB
           L0[511] L1[1]   0xFFFF_FF80_4000_0000  linear map: phys 1-2 GiB
           L0[511] L1[2]   0xFFFF_FF80_8000_0000  linear map: phys 2-3 GiB
```

aarch64 goes **below** `KERNEL_VIRT_BASE`, and the reason is worth
stating because the obvious placement is wrong.
`PhysAddr::kernel_mut_ptr` is `phys | KERNEL_PHYS_OFFSET` for *every*
physical address, so everything from `KERNEL_VIRT_BASE` upward is the
linear map's image of RAM. The L1 slots `boot.S` leaves empty are not
free address space — they are the images of physical memory the boot
map has not needed to populate. Slot 2 is the image of physical
2–3 GiB, so a window there aliases live frames on any machine with more
than 2 GiB, which QEMU's 2048 MiB default already is. That mistake was
made here and cost a hard fault; the smoke now asserts
`MODULE_VA_BASE + MODULE_VA_USABLE <= KERNEL_VIRT_BASE` rather than
anything about which slots boot.S writes.

Below the base the linear map cannot reach, because it only ever adds.
L0[510] is untouched by boot.S, by the BPF windows (L0[273], L0[275])
and by vmalloc (L0[384]).

Veneers are still required: the window is ~1.1 GiB from kernel text and
`R_AARCH64_CALL26` reaches ±128 MiB. Nowhere is close enough — the GiB
adjacent to the kernel image *is* the linear map.

So `src/plt.rs` emits `adrp x16 / add x16 / br x16` trampolines into an
arena at the end of the module's own text, within branch range of every
call site. x16 is free to clobber: AAPCS64 requires a conforming
program to assume a veneer altering IP0/IP1 may be inserted at any
branch exposed to a long-branch relocation. The arena is sized from a
per-relocation over-count and folded by target at emit time, as Linux's
`count_plts` does.

ADRP reaches ±4 GiB, so with the window 1 GiB out no second-order
veneer is needed. If the window ever moves further, Linux's
`module_emit_veneer_for_adrp` is the piece to add.

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
                │ plan_layout     │  group by permission, page-align each
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ module_text::   │  map RW+NX at the module VA window
                │ alloc           │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ copy sections   │  to their final addresses; zero .bss
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ relocator       │  walk .rela.* + apply IN PLACE
                └────────┬────────┘  (+ aarch64 PLT veneers)
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
                │ module_text::   │  text → RX, rodata → RO, aliases closed
                │ protect         │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ insert_unique   │  + install /sys/module/<name>/
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ pin providers   │  refcount each module linked against
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ invoke_init     │  state Loading → Live
                └─────────────────┘
```

Every failure after `module_text::alloc` unmaps the image before
propagating — `build_image` exists to funnel them through one
`module_text::free`.

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

  3. **Admin-only.** The syscall plumbing exists
     (`userspace/src/handlers/sys_{init,finit,delete}_module.rs`) and
     routes through the process's existing privilege model. The
     per-action `Cap<Process, Invoke>` gate described here is **not**
     wired yet — that is still to do, and is the single largest gap in
     this tier.

## W^X enforcement

Every loadable section is scanned for `SHF_EXECINSTR | SHF_WRITE`.
A section with both is rejected on principle — kernel-mode JIT is
out of scope and a module that wants both is more likely buggy
than principled.

That check is about the *ELF*. The mapping is enforced separately, by
`narf_memory::module_text`:

  * Sections are grouped by permission and each region page-aligned, so
    text, rodata and data can be sealed independently. Linux splits the
    same space seven ways (`enum mod_mem_type`), separating
    `ro_after_init` and giving `.init.*` its own trio so the init region
    can be **freed** once init returns. We have three regions and do not
    reclaim init yet; the layout is a loop over `REGION_ORDER` so both
    are additions rather than a rewrite.
  * Pages are mapped RW+NX, relocated in place, then flipped — text to
    RX, rodata to RO.
  * **The alias matters as much as the mapping.** The frames backing
    module text are also visible through the kernel's linear map, which
    is RW. `protect` closes that via `text_poke::protect_ro` *before*
    publishing the executable mapping, so a failure leaves nothing
    executable. `free` restores it before the frames go back to the
    buddy — skipping that hands the next owner memory it cannot write.
  * On aarch64 `text_poke::can_protect` refuses sub-2-MiB ranges:
    making one 4 KiB frame of a live 2 MiB linear-map block read-only
    needs break-before-make on the kernel's own map. The alias stays
    writable there, which is the same fallback `bpf_text` takes and the
    same refusal Linux arm64 makes.

Prior to this, the loader relocated each section into a `Vec<u8>` on
the kernel heap and used the buffer's own address as the runtime
target. Every kernel window is NX, so a real module faulted on its
first instruction; nothing caught it because the end-to-end smokes
pointed their `SHN_ABS` lifecycle symbols at in-kernel functions and
never executed a relocated byte.

## Per-export CRC versioning

Each `KernelExport` carries a `crc: u32`, computed from the function's
signature — the same scheme Linux uses for `MODVERSIONS`.

This was deferred to "build-system integration"; it turns out none is
needed. The `kernel_abi!` macro in `src/kabi.rs` sees the argument and
return type tokens, so it hashes them at compile time with
`crc_for_signature`. Change a parameter and the CRC changes. This is
MODVERSIONS without genksyms.

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

  * ~~**Per-symbol export reference counting.**~~ **Done.** `Resolution`
    carries the owning `ModuleId`, the relocator records every non-kernel
    owner it resolves against, and `sys_init_module` takes a reference on
    each provider before calling init. A provider with a live consumer
    answers EBUSY. This is `try_module_get` moved from per-call to link
    time, which matches how NARF already handles cap requirements (§1).

  * **A task preempted inside module code.** Still open, and distinct
    from the above. `delete_module` unmaps the image once the refcount is
    zero and the exports are swept, but a task that entered the module
    before `invoke_exit` and was preempted inside it would resume on
    unmapped text. Closing this needs a real grace period between the
    sweep and the free. `rcu::sync()` is *not* it: `qsbr::sync_blocking`
    drives quiescence locally and gives up after 8 rounds, so on SMP it
    would supply the appearance of a grace period without the guarantee.
  * **Livepatch.** Symbol ownership interacts with livepatch if a patched
    symbol is later unregistered; deferred until livepatch lands.
  * **`__reset_for_test` resets the MODULE_ID_ALLOC counter.** Tests that
    call `__reset_for_test` between loads get fresh IDs — adequate for
    in-kernel test isolation, but counter exhaustion at 2^64 is theoretical.

## Open questions / future phases

  * **Ed25519 signature verification.** The hook is in place; the
    implementation slots into `sign::install_verifier(...)`.
  * **Loading a real `.ko` in a test.** The build exists
    (`cargo xtask build-module`, with `--kernel-abi` to stamp the
    running kernel's hash). What is missing is getting the object in
    front of the kernel under test — shipping it in the initramfs for a
    smoke to `finit_module`, which also means the test run has to build
    the module, boot once to read the hash, and rebuild. Until then,
    tests exercise the loader but not rustc's actual relocation output.
    This should be the next thing done.

    Note also that a module using anything from `core` the compiler
    does not inline will come out with undefined references that
    neither KSYMTAB nor the object satisfies. Linux links the needed
    `core` objects into each Rust module; `build_module` does not yet.

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
  * ~~**Module dependency graph.**~~ **Enforced**, though not via
    `depends=`. Edges come from the relocations actually made, which is
    strictly better than a manifest claim: a module cannot outlive
    something it links against regardless of what its `depends=` says.
    `/proc/modules` reports real holders. What modprobe still owns is
    load *ordering* — nothing yet loads a missing provider on demand.
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
    loader.rs            ← top-level pipeline + image layout
    relocator.rs         ← per-section .rela.* walker
    plt.rs               ← aarch64 long-branch veneers
    kabi.rs              ← the C ABI surface modules may call
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
