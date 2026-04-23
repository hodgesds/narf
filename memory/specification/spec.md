# memory — Specification

> Status: **Outline v0.2** (Stage 1 → 2). v0.2 adds PKRS save/restore
> invariants and acknowledges PKS/MTE asymmetry at the arch boundary.

## 1. Purpose & scope

**Owns:** Physical frame allocator (buddy), virtual-memory mappings,
page-table manipulation, slab-style kernel allocator, **domain manager**:
tagging regions with PKS keys (x86_64) / MTE tags (aarch64), switching
the active domain key-rights via the Frame.

**Does NOT own:** Which subsystem gets which domain (policy lives in
`security-model/` + `drivers/`), trap handling on domain faults (`frame/`).

## 2. Assumptions

- `boot/` gave us a memory map with usable regions + reserved regions.
- `arch/` provides MMU and cache ops.
- `frame/` will call `enter_domain` on our behalf.

## 3. Public interface

```rust
pub struct PhysFrame;     // owned 4 KiB physical frame (base page)
pub struct VirtAddr(u64);
pub struct DomainId(u8);  // 0..16

/// Reserved domain IDs. Authoritative assignment table is in
/// `security-model/specification/spec.md` §4.1; the constants below
/// are the code-side mirror. Any spec referencing one of these
/// constants links to the table for rationale.
impl DomainId {
    pub const FRAME:       DomainId = DomainId(0);
    pub const CAPS:        DomainId = DomainId(1);
    pub const MEMORY_MGR:  DomainId = DomainId(2);
    pub const SCHED:       DomainId = DomainId(3);
    pub const IPC:         DomainId = DomainId(4);
    pub const TRACER:      DomainId = DomainId(5);
    pub const KEYS:        DomainId = DomainId(6);
    pub const OBSERVE:     DomainId = DomainId(7);
    pub const USERSPACE_K: DomainId = DomainId(8);
    /// Driver slots 9..14, allocated by the driver framework.
    pub const fn driver(slot: u8) -> DomainId {
        assert!(slot < 6);
        DomainId(9 + slot)
    }
    pub const SCRATCH:     DomainId = DomainId(15);
}

/// A `Folio` is NARF's multi-page allocation unit, borrowed in spirit
/// from Linux's folio API (5.15+). One `Folio` owns `2^order` contiguous
/// frames and carries a single metadata header — far cheaper than
/// tracking per-frame state for large allocations, and the natural
/// currency for a future `filesystem/` page cache.
pub struct Folio { order: u8, head: PhysFrame }
pub struct PageSize(usize);   // base = 4 KiB; see §5 per-arch table

pub fn alloc_frame() -> Option<PhysFrame>;
pub fn alloc_folio(order: u8) -> Option<Folio>;     // 2^order base frames
pub fn map(va: VirtAddr, pf: PhysFrame, flags: MapFlags, domain: DomainId);
pub fn map_folio(va: VirtAddr, folio: Folio, flags: MapFlags, domain: DomainId);
pub fn map_huge(va: VirtAddr, folio: Folio, size: PageSize, flags: MapFlags, domain: DomainId);
pub fn unmap(va: VirtAddr);
pub fn assign_domain(region: VirtRange, domain: DomainId);
pub fn set_domain_rights(domain: DomainId, rights: DomainRights); // PKRS write

// --- Kernel heap (slab-style object allocator) ------------------------

/// Slab API. Shape owes most to Bonwick SLAB (object caches with
/// constructor / destructor), with NARF-specific amendments: every
/// cache is tagged to a `DomainId`, the fast-path avoids locks via
/// per-CPU magazines (tcmalloc/jemalloc idiom), and free objects are
/// zeroised on drop by default (disable via `SlabOpts::no_zeroize`
/// only for auditable use-cases).
pub struct SlabCache<T>;
pub struct SlabOpts {
    pub align:       usize,        // default: align_of::<T>()
    pub domain:      DomainId,     // target domain; default = allocator's
    pub magazine:    MagSize,      // None | Small(16) | Medium(64) | Large(256)
    pub zeroize_on_free: bool,     // default true
}

pub fn slab_new<T>(opts: SlabOpts) -> SlabCache<T>;
impl<T> SlabCache<T> {
    pub fn alloc(&self) -> Option<Box<T, SlabAlloc>>;
    pub fn free(&self, obj: Box<T, SlabAlloc>);
    pub fn reclaim(&self, hint: ReclaimHint); // jemalloc-style purge
}

/// General-purpose allocator for variable-size kernel allocations.
/// Size classes follow a geometric schedule (jemalloc-inspired) with
/// dense small classes (8, 16, 32, 48, 64, 80, 96, 112, 128, ...) and
/// power-of-two large classes from 4 KiB up to the largest huge-page
/// size. Per-(CPU, Domain) magazines on the front; central free lists
/// drain to / refill from the buddy allocator.
pub fn kalloc(size: usize, align: usize, domain: DomainId) -> Option<NonNull<u8>>;
pub fn kfree(ptr: NonNull<u8>, size: usize, domain: DomainId);

// Task-context PKRS state, owned by scheduler/ but defined here
// because memory/ owns domain-rights semantics. See §4.
pub struct DomainSavedState {
    pub pkrs: u64,        // x86_64 IA32_PKRS snapshot
    pub current_domain: DomainId,
    pub mte_tcf: u8,      // aarch64 TCF mode snapshot (sync/async/off)
}
pub fn save_domain_state(out: &mut DomainSavedState);
pub fn restore_domain_state(s: &DomainSavedState);
```

Kernel heap: slab allocator on top of frame allocator; each slab is
itself assigned to a domain (typically the allocating domain's).

**`assign_domain` alignment is arch-asymmetric.** On x86_64 the granule
is a page (4 KiB). On aarch64 the MTE granule is **16 bytes** — an order
of magnitude finer. The allocator slab on aarch64 must align domain
assignments to 16-byte boundaries. Callers passing a `VirtRange` that
is page-aligned satisfy both arches; passing a sub-page range on
x86_64 is rejected at runtime.

## 4. Invariants & safety properties

- Every non-identity kernel mapping has a domain assignment; untagged
  mappings panic in debug, deny-by-default in release.
- `DomainId` 0 is reserved for the Frame's own data; no driver may claim it.
- `PhysFrame` is `!Copy`; dropping it returns to the allocator (Rust
  ownership = leak safety for physical memory).
- Buddy allocator's free lists are per-NUMA-node once NUMA is introduced.
- **A `PhysFrame` returned by `alloc_frame()` is always tagged to
  `DomainId::FRAME` (domain 0) at the point of return.** The caller
  must invoke `assign_domain` before mapping into a non-Frame domain.
  This closes the gap where a freshly-allocated frame has no tag.
- **PKRS / MTE-TCF state is per-task, not per-CPU, from the kernel's
  point of view.** The HAL register is physically per-CPU, but every
  task carries its own `DomainSavedState`. The scheduler saves this
  state on preemption and restores it on resume *before any memory
  access in the new task's domain occurs*. Without this, domain
  isolation has a TOCTOU window at every preemption.
- **On direct context transfer (`scheduler::donate_to`)** the callee's
  `DomainSavedState` must be restored before the first instruction of
  the callee executes. A `WRMSR IA32_PKRS` (x86_64) or the equivalent
  TCF write (aarch64) is therefore part of the transfer sequence's
  critical section, with interrupts disabled.
- **`restore_domain_state` is a compiler-fence pair boundary.**
  The implementation is the `arch/` `DomainPrimitive::restore`
  wrapped in `compiler_fence(SeqCst)` before and after the `asm!`
  that issues the write. Under fat LTO, without the explicit
  fences, LLVM is free to hoist a domain-N memory access past the
  rights change to domain M — a silent domain escape. See
  `build/` §4 and `arch/` §4 for the enforcement discipline.
- **Nested `enter_domain` is forbidden.** `frame/` must save the prior
  domain id + PKRS snapshot in `CpuLocal` on entry and restore on
  exit; a re-entrant call from within the same domain context is a
  bug, caught by an assertion.

## 5. Architecture notes

### x86_64
- Paging: 4-level (possibly 5-level where CPUID says so).
- PKS: `MSR_IA32_PKRS` is the per-CPU rights mask; updated on domain
  enter/exit. Page-table PK field (bits 59..62 of PTE) stores the key.
- SMEP/SMAP mandatory; CET shadow stack desired.
- **Page sizes:**

  | Size   | PTE level | Notes                                           |
  | ------ | --------- | ----------------------------------------------- |
  | 4 KiB  | leaf PTE  | base page; required                             |
  | 2 MiB  | PDE PS=1  | "large page"; required                          |
  | 1 GiB  | PDPTE PS=1 | "huge page"; requires `CPUID.80000001H:EDX[26]` |

  A `Folio` of order *k* backs a 4 KiB × 2^k region. For `map_huge`,
  the folio must be order ≥ 9 (2 MiB) or order ≥ 18 (1 GiB) and the
  head frame must be naturally aligned to the target size.

### aarch64
- Paging: 4-level, 4 KiB granule (default) or 16 KiB / 64 KiB granules
  on platforms that prefer them, 48-bit VA.
- MTE: memory tag is 4 bits, stored in the top byte of the address plus
  tag storage. We assign one tag per domain.
- TBI1/TBI0 enabled; TCR_EL1 configured for MTE.
- **Page sizes (4 KiB granule configuration):**

  | Size    | Level       | Notes                                                |
  | ------- | ----------- | ---------------------------------------------------- |
  | 4 KiB   | L3 leaf     | base page; required                                  |
  | 2 MiB   | L2 block    | required                                             |
  | 1 GiB   | L1 block    | required when VA region is appropriately aligned     |
  | 512 GiB | L0 block    | supported by architecture; not used by NARF pre-1.0  |

  **Contiguous hint (PTE bit 52):** 16 contiguous aligned PTEs at any
  level can share a TLB entry. NARF's `map_folio` sets the contiguous
  hint automatically when the folio order equals 4 (16×4 KiB = 64 KiB),
  7 (16×2 MiB = 32 MiB), or 10 (16×1 GiB = 16 GiB). This halves or
  better the TLB-pressure cost of huge mappings.

- **64 KiB granule option.** On platforms configured for a 64 KiB
  granule, the base page is 64 KiB, and huge-page sizes become 512 MiB
  and 16 GiB. NARF supports the 64 KiB configuration as a build-time
  option for embedded aarch64 SoCs that prefer it; the default is
  4 KiB to match x86_64 closely.

**MTE is NOT symmetric to PKS.** PKS is a per-CPU rights register; a
single `WRMSR` changes which keys are accessible. MTE is
pointer-provenance: the domain identity is embedded in the *tag value
of each pointer* in use. There is no per-CPU "active domain" register
on aarch64. To enforce that code in domain N cannot read domain M's
data, every pointer crossing the domain boundary must be re-tagged.

Consequences NARF accepts:

- `set_domain_rights` on aarch64 has no `WRMSR`-equivalent. It is
  implemented by reconfiguring `SCTLR_EL1.TCF` (sync fault vs. async
  vs. off) and by the pointer-tagging discipline enforced in `ipc/`
  and `capabilities/`.
- Cross-domain pointer transfer on aarch64 requires an explicit
  retag — see `ipc/` §4. On x86_64 a stale pointer to another
  domain's memory is caught by PKS at the access; on aarch64 a
  legitimately-tagged pointer *is* authority to access, so the
  hardware cannot catch a confused-deputy pointer.
- TCF mode is part of `DomainSavedState`. The scheduler restores it
  alongside PKRS on x86_64.

This asymmetry is intentional. The HAL in `arch/` exposes a single
`DomainPrimitive` trait; implementers must understand the two backends
are not performance-equivalent and that the aarch64 backend relies on
discipline at every cross-domain pointer move, not just a register
flip.

## 6. Dependencies

- **Consumes:** `arch/`, `frame/`, `boot/`, `console/` (calls
  `console::remap_to_virtual` during MMU bring-up per `console/` §3.1;
  skipping this call bricks the console at paging-enable time).
- **Provides to:** everything (heap, VM, domains). **`scheduler/` is a
  first-class consumer** for `save_domain_state` / `restore_domain_state`
  on every context switch and on every direct context transfer — the
  PKRS save/restore coupling is load-bearing for correctness, not an
  optimisation.

## 7. Stage assignment

Stage 1: buddy + page tables + identity map for the Frame.
Stage 2: domain manager, PKS/MTE enable, per-domain slab allocator.

## 8. Open questions

- 16 domains is a hard ceiling on x86_64 PKS. **Resolve multiplexing
  policy before Stage 2:** if task-local domain-id remapping is allowed,
  every `DomainId` is meaningful only relative to a task context; if
  not, we are allocating a global static sparse resource. This decision
  couples to the scheduler's PKRS save/restore and to `security-model/`'s
  domain-assignment table.
- MTE tag width is 4 bits (16 values) matching PKS's 16 — coincidence is
  lucky but decide policy when one arch has fewer.
- How aggressive is kernel ASLR, and does it interact with domain tagging?
- **Linux folio API precedent.** Should NARF model multi-page
  allocations as a `Folio`-shaped abstraction (head page + order +
  per-folio metadata) the way Linux 5.15+ does, rather than tracking
  individual `PhysFrame`s for large allocations? Folios would
  compose better with the filesystem page cache once that exists and
  reduce per-page bookkeeping for huge-page slabs. Decide once
  `filesystem/` is being written — the answer depends on whether we
  adopt a unified page cache.
- Per-CPU slab magazines (tcmalloc-style) to avoid global buddy-lock
  contention on SMP — design before Stage 2 or accept the serialisation cost?
