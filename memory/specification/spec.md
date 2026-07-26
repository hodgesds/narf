# memory — Specification

> Status: **v1.0** (Stage 2 design lock). v0.2 covered PKS/MTE
> asymmetry + PKRS save/restore; v1.0 locks the domain
> multiplexing policy, the Folio API as the canonical
> multi-page abstraction, per-CPU slab magazines, and the
> kernel ASLR posture.

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

pub struct Mempolicy {
    pub mode: u32,
    pub nodemask: u64,
    /// Hard boundary supplied by cpuset.mems; allocation never spills out.
    pub allowed: u64,
    /// MPOL_BIND/MPOL_PREFERRED_MANY distance anchor; u32::MAX selects
    /// the policy's default anchor.
    pub home_node: u32,
    /// Task-owned sequence position for interleave policies.
    pub interleave_index: u64,
}
pub fn mempolicy_set(policy: Mempolicy);
pub fn mempolicy_clear();
/// Global Linux MPOL_WEIGHTED_INTERLEAVE ratios (valid weights 1..=255).
pub fn interleave_weight(node: usize) -> Option<u8>;
pub fn set_interleave_weight(node: usize, weight: u8) -> Result<(), ()>;
pub fn interleave_node_at(mask: u64, weighted: bool, index: u64) -> usize;
pub fn interleave_auto() -> bool;
pub fn set_interleave_auto(enabled: bool) -> Result<(), ()>;
pub fn set_interleave_bandwidth(node: usize, bandwidth: u64) -> Result<(), ()>;

/// Runtime memory-hotplug admission. The caller proves the range is real,
/// kernel-mapped RAM that does not overlap boot-reserved or MMIO storage.
pub unsafe fn online_memory_range(
    start: PhysAddr,
    len: u64,
    node: usize,
) -> Result<(), MemoryHotplugError>;
/// Remove an exact previously-hotplugged range only when every frame is free.
pub fn offline_memory_range(
    start: PhysAddr,
    len: u64,
) -> Result<usize, MemoryHotplugError>;
pub fn kernel_ram_range_mapped(start: PhysAddr, len: u64) -> bool;
pub fn online_node_mask() -> u64;
pub fn online_node_count() -> usize;
pub fn hotplug_node_for_phys(addr: PhysAddr) -> Option<usize>;
/// Post-commit observer invoked with no allocator/hotplug lock held.
pub fn install_memory_hotplug_hook(hook: fn());
pub const MEMORY_BLOCK_SIZE: u64;
/// Includes previously discovered offline blocks so memoryN identity persists.
pub fn memory_blocks() -> Vec<MemoryBlock>;

/// Publish local HMAT coordinates and derive Linux-style memory tiers.
pub fn set_node_performance(
    node: usize,
    bandwidth: u64,
    latency: u64,
) -> Result<(), ()>;
pub fn node_tier(node: usize) -> Option<u8>;
pub fn tier_nodes(tier: u8) -> u64;
/// Closest allowed node in the nearest strictly slower tier.
pub fn demotion_target(source: usize, allowed: u64) -> Option<usize>;

/// Temporarily remove an eligible private resident leaf for NUMA sampling.
pub unsafe fn protect_numa_hint_page(vaddr: VirtAddr) -> Result<bool, AddressSpaceError>;
/// Consume the recorded hint before restoring or migrating its backing.
pub fn take_numa_hint(vaddr: VirtAddr) -> bool;

/// Monotonic Linux-compatible allocation-event snapshot for one NUMA node.
pub fn numa_node_stats(node: usize) -> NumaNodeStats;
/// Stable allocator-managed base-page total established at NUMA rebalance.
pub fn node_total(node: usize) -> usize;
/// Free-block counts for buddy orders 0 through 10.
pub fn node_free_blocks(node: usize) -> [usize; BUDDY_ORDER_COUNT];

/// Hugepage allocation is local-first with SLIT-ordered fallback.
pub fn alloc_hugepage_2m() -> Result<HugeFrame, HugeAllocError>;
pub fn alloc_hugepage_1g() -> Result<HugeFrame, HugeAllocError>;
/// Strict node-selection primitives used by NUMA policy consumers.
pub fn alloc_hugepage_2m_on(node: usize) -> Result<HugeFrame, HugeAllocError>;
pub fn alloc_hugepage_1g_on(node: usize) -> Result<HugeFrame, HugeAllocError>;
// Exported from the `hugepage` module.
pub fn node_stats(node: usize) -> HugeNodeStats;

pub struct HugeRegion {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    pub size: HugeSize,
    pub frames: Vec<HugeFrame>,
}

impl AddressSpace {
    /// Install real architecture huge/block leaves and take frame ownership.
    pub unsafe fn map_huge_region(
        &self,
        region: HugeRegion,
    ) -> Result<(), AddressSpaceError>;
    /// Remove an exact huge mapping and return its backing to the pool.
    pub fn unmap_huge_region(&self, base: VirtAddr)
        -> Result<(), AddressSpaceError>;
    /// Test membership across both base-page and hardware huge-page regions.
    pub fn contains_address(&self, vaddr: VirtAddr) -> bool;
    /// Return the registered hardware leaf size (4 KiB, 2 MiB, or 1 GiB).
    pub fn mapped_page_size(&self, vaddr: VirtAddr) -> Option<u64>;
    /// Copy resident bytes through owned physical backing without user faults.
    pub fn copy_user_bytes_nofault(&self, vaddr: VirtAddr, dst: &mut [u8])
        -> usize;
    /// Non-owning per-region resident-page counts grouped by SRAT node.
    pub fn numa_regions_snapshot(&self) -> Vec<NumaRegionSnapshot>;
}

/// Install the external shared-page owner's per-alias lifetime hooks.
/// Every SHARED map retains each non-zero backing frame; unmap, MAP_FIXED
/// replacement, and address-space teardown release only after the
/// corresponding translations have been invalidated.
pub fn install_shared_frame_hooks(retain: fn(u64), release: fn(u64));

impl AddressSpace {
    /// Replace one resident private base page, or the complete hardware leaf
    /// containing a huge-page address, with equivalent backing from a target
    /// NUMA node, preserving bytes and permissions and completing the
    /// required cross-CPU TLB invalidation before releasing old backing.
    pub unsafe fn migrate_page_to_node(
        &self,
        va: VirtAddr,
        target_node: usize,
    ) -> Result<usize, AddressSpaceError>;

    /// Bulk form used by Linux migrate_pages(2); returns pages not moved.
    pub unsafe fn migrate_pages_between(
        &self,
        old_nodes: u64,
        new_nodes: u64,
    ) -> Result<usize, AddressSpaceError>;

    /// Migrate one private base page or complete huge leaf to the nearest
    /// strictly slower memory tier within the caller's allowed-node mask.
    pub unsafe fn demote_page(
        &self,
        va: VirtAddr,
        allowed_nodes: u64,
    ) -> Result<usize, AddressSpaceError>;

    /// Replace all aliases of one externally-owned shared base page in this
    /// address space without releasing either frame.
    pub unsafe fn replace_shared_frame(
        &self,
        old: PhysAddr,
        new: PhysAddr,
    ) -> Result<usize, AddressSpaceError>;

    /// Audit or migrate resident pages in a virtual range to a node mask.
    pub unsafe fn conform_range_to_nodes(
        &self,
        start: VirtAddr,
        len: u64,
        target_nodes: u64,
        do_move: bool,
    ) -> Result<usize, AddressSpaceError>;
}

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
- Runtime memory online is transactional: overlapping/unmapped ranges are
  rejected before donation, and allocator metadata may not grow while the
  frame lock is held. Offline succeeds only for an exact registered range
  whose complete buddy extent is free; a failed removal leaves every free
  list and node counter unchanged.
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

**Status (2026-05-10)** — Stage 1 heap migration largely
done. See `heap-migration.md` for the per-phase / per-acceptance
breakdown. Modules in tree:

- `buddy.rs` — per-NUMA-zone free lists, orders 0..10 (4 KiB
  to 4 MiB), donate / alloc / free / drain_into.
- `slab.rs` — power-of-two size classes 16..4096, per-CPU
  magazines + central per-class lists, `try_alloc_atomic` /
  `try_dealloc_atomic` for IRQ-context callers.
- `heap.rs` — hybrid bootstrap-bump → slab `#[global_allocator]`,
  `BOOTSTRAP_CAPACITY = 8 << 20`.
- `hugepage.rs` — boot-reserved 2 MiB / 1 GiB pool (cmdline
  `hugepages_2m=N` / `hugepages_1g=N`), no buddy fallback.
- `atomic_pool.rs` — driver-side `AtomicPool<T>` fixed-capacity
  pool for IRQ-critical paths that can't tolerate even
  `try_alloc_atomic` failure.
- `context.rs` — `is_sleepable()`, `irqs_enabled()`,
  `AllocContext` enum, debug assert at slab-alloc entry.

Stage 2 / 4 still owe: domain tagging through `SlabOpts`,
shrinker subsystem, per-domain accounting.

## 8. Resolved decisions

### 8.1 Domain multiplexing policy (resolved)

**Decision (was open):** **task-local domain-id remapping**
is the chosen policy. `DomainId::DRIVER(n)` is a logical slot;
the actual PKS key in use depends on which task is currently
polling on this CPU.

Implementation: `CpuLocal` carries a per-task remap table
`[u8; 16]` mapping logical domain → PKS key. The scheduler
restores this table on context switch alongside PKRS. Logical
domain 9 ("first driver") might be PKS key 9 in task A's
context but PKS key 12 in task B's context.

Cost: an extra `[u8; 16]` per task (16 bytes), one
`memcpy_volatile` on context switch (negligible compared to
the existing PKRS save/restore).

Benefit: NARF can support far more concurrent drivers than the
hardware's 16 PKS keys would suggest, because each task's
working set rarely needs more than 4-5 distinct domains active
simultaneously.

This decision is what makes hundreds-of-drivers scaling
possible at the domain level.

### 8.2 MTE tag width policy (resolved)

**Decision (was open):** **NARF assumes ≥16 tags** and gates
booting on the assumption. Currently both PKS (x86_64) and
MTE (aarch64) provide exactly 16; if a future arch had fewer
(e.g. 8), NARF would either:

- Boot with a reduced `DomainId` enum (some drivers refuse
  to load).
- Reject boot and require the platform-specific kernel build
  to opt out of strict isolation.

The choice would be platform-engineering at port time, not a
runtime degradation. For the foreseeable future (x86_64 PKS,
aarch64 MTE) we have 16; lock this assumption.

### 8.3 Kernel ASLR (resolved)

**Decision (was open):** **kernel ASLR is enabled and
randomises 24 bits** of the kernel image base. Page-table
walks and domain-tagging are unaffected — the randomised
offset is applied at boot before any domain assignment.

Per-allocation ASLR (each kalloc result randomly placed) is
**not** done; the cost is too high for the benefit (kernel
heap allocations are typically known to a local attacker via
side channels regardless).

The 24-bit kernel-base entropy interacts with domain tagging
trivially: domain assignment is per-virtual-region, the region
is determined post-randomisation. No coupling.

### 8.4 Folio API (resolved)

**Decision (was open):** **adopt the Folio abstraction**. The
v0.2 spec already includes the Folio types; v1.0 makes them
the canonical multi-page allocation primitive.

Single-page (4 KiB) allocations still go through `alloc_frame`
returning `PhysFrame`. Multi-page allocations go through
`alloc_folio(order)` returning `Folio`. The buddy allocator
internally always works in folios; `PhysFrame` is just `Folio`
of order 0 with a thinner wrapper.

`filesystem/` will use Folios as the page-cache currency
when it adopts a unified page cache. Drivers consuming DMA
buffers see `Cap<DmaBuffer, _>` whose backing is a Folio of
the appropriate order.

### 8.5 Per-CPU slab magazines (resolved)

**Decision (was open):** **per-CPU magazines mandatory** for
hot caches. The slab API in §3 already declares `MagSize`;
v1.0 makes the default non-`None` for any cache used by hot-
path code.

Defaults:

- Allocations < 256 bytes: `MagSize::Small(16)` per-CPU
  magazine.
- Allocations 256 bytes ≤ size < 4 KiB: `MagSize::Medium(64)`.
- Allocations ≥ 4 KiB: `MagSize::Large(256)` for caches with
  > 1 K obj/sec churn, `None` for cold caches.

Cache stats are tracked (`tracing/`) so the magazine size can
be tuned per-cache. The default heuristic above is the v1
contract; the tunable knob is `SlabOpts::magazine`.

## 8a. SPD5 sub-module (`spd5`)

`spd5/` is a clean-room decoder for the JEDEC Serial Presence
Detect EEPROM that DDR5 modules expose over the SMBus / I3C side-
band. References (public-only):

- **JEDEC Standard JESD400-5** — DDR5 SPD Annex L (SPD5 Hub Device
  and SPD5 Memory Module Specifications). Public document.
  §1.2.3 (1024-byte EEPROM map). §1.4 (manufacturer ID = JEP-106
  bank + ID). §1.5 (timing fields stored as 16-bit little-endian
  picosecond values). Annex C (CRC-16/CCITT-XMODEM trailer over
  bytes 0..1021).
- **JEDEC Standard JEP106BJ** — manufacturer's identification code
  registry. Public.
- **JEDEC JESD79-5B** — DDR5 SDRAM core spec. Public. Defines the
  timing parameters whose minimum values the SPD5 region encodes
  (tCKAVGmin / tAAmin / tRCDmin / tRPmin / tRCmin / tRFC1min /
  tRFC2min / tRFCsbmin).

Surfaced:
- `Spd5::parse` — verifies CRC and decodes the SPD revision +
  module type + manufacturer JEP-106 bank/id + module part number
  + 6 picosecond timing minimums + 3 nanosecond refresh minimums.
- `data_rate_mt_per_s` — turns tCKAVGmin into the bus data rate.
- `crc16_ccitt` — the polynomial-0x1021 / init-0 / no-XOR variant.

## 9. ABI versioning

`memory/` exports through SDK at `@v0`:

- `DomainId` enum + driver-slot accessor — frozen (any change
  is `MEMORY_ABI_MAJOR` bump).
- `Folio` / `PhysFrame` types — fields are `pub(crate)`; only
  the trait operations are exported.
- `MapFlags` bitfield — additions are minor bumps,
  reserved-MBZ.

Drivers don't allocate frames or folios directly (the SDK
gate forbids it); they consume `Cap<DmaBuffer, _>` via `io/`.
The exported types are for kernel-internal subsystems only.

`MEMORY_ABI_MAJOR = 1`, `MEMORY_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.2 questions resolved in §8)
