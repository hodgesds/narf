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
/// Return independently owned frames; buddy batches COW shards and bounded
/// per-CPU-cache/NUMA-zone return work, while alternative allocators retain
/// the scalar default.
pub fn free_frame_batch(frames: &[PhysFrame]);
/// Retain every non-zero COW backing while locking each touched refcount
/// shard once; duplicate entries represent distinct owners.
pub fn cow::inc_ref_batch(frames: &[PhysAddr]);
/// Return counts in input order while locking each touched shard once.
pub fn cow::count_batch(frames: &[PhysAddr]) -> Vec<u32>;
/// Drop one owner per input and return frames whose final owner was removed.
pub fn cow::dec_ref_batch(frames: &[PhysAddr]) -> Vec<PhysAddr>;
/// Install scatter backing under one root lock; the callback index preserves
/// alignment with per-page metadata when zero lazy slots are skipped.
pub unsafe fn x86_64::paging::map_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;
/// Rewrite scatter backing under one root lock and one local invalidation
/// phase; peer-active address spaces follow with the remote range/full flush.
pub unsafe fn x86_64::paging::rewrite_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;
/// aarch64 twin: one root lock plus one descriptor-publication barrier for
/// the complete fresh scatter run.
pub unsafe fn aarch64::paging::map_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;
/// Permission/backing rewrite twin: clear the complete span, finish one
/// all-ASID break-before-make invalidation, then publish non-zero replacements.
pub unsafe fn aarch64::paging::rewrite_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;
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

/// Free-memory pressure band and the physical-page deficit to high.
pub fn watermark_min() -> u64;
pub fn watermark_low() -> u64;
pub fn watermark_high() -> u64;
pub fn reclaim_goal_pages() -> usize;

/// Fixed-point proportional-set-size units (one private resident page).
pub const PSS_UNITS_PER_PAGE: u64;
pub struct ReclaimRangeCandidate {
    pub address_space_root: PhysAddr,
    pub base: VirtAddr,
    pub pages: usize,
    pub mapcount: u32,
    /// Conservative rmap-derived physical yield; zero-yield aliases are skipped.
    pub expected_free_pages: usize,
    pub age: u8,
    pub locked: bool,
}
pub struct PlannedReclaimRange { /* root, base, pages, PSS, expected yield */ }
pub struct ReclaimBatchPlan { /* selected ranges + PSS/yield/scan totals */ }
pub fn plan_reclaim_ranges(
    candidates: &[ReclaimRangeCandidate],
    target_free_pages: usize,
    max_selected_pages: usize,
) -> ReclaimBatchPlan;
pub fn plan_watermark_reclaim(
    candidates: &[ReclaimRangeCandidate],
    max_selected_pages: usize,
) -> ReclaimBatchPlan;

/// Swap backends consume vectors as the primary interface. Default methods
/// preserve compatibility for simple backends; block/zram implementations may
/// submit or lock once for the whole vector.
pub trait SwapBackend: Send + Sync {
    fn write_batch(&self, slots: &[SwapSlot], frames: &[PhysAddr])
        -> Result<(), SwapError>;
    fn read_batch_into(&self, slots: &[SwapSlot], frames: &[PhysAddr])
        -> Result<(), SwapError>;
    fn discard_batch(&self, slots: &[SwapSlot]);
}
#[cfg(target_arch = "x86_64")]
pub struct SwapVictim { pub pml4_phys: PhysAddr, pub virt: VirtAddr }
#[cfg(target_arch = "x86_64")]
pub struct SwapInRequest {
    pub pml4_phys: PhysAddr,
    pub virt: VirtAddr,
    pub flags: PtFlags,
}
/// Low-level ownership-sensitive primitive; live VMA reclaim must use the
/// AddressSpace-integrated transaction.
#[cfg(target_arch = "x86_64")]
pub unsafe fn swap_out_batch(victims: &[SwapVictim]) -> Result<usize, SwapError>;
#[cfg(target_arch = "x86_64")]
pub unsafe fn swap_out_plan(plan: &ReclaimBatchPlan) -> SwapBatchReport;
#[cfg(target_arch = "x86_64")]
pub fn swap_in_batch(requests: &[SwapInRequest]) -> Result<Vec<PhysAddr>, SwapError>;

/// Hugepage allocation is local-first with SLIT-ordered fallback.
/// Boot-only reservation skips every protected half-open physical range and
/// returns the additional ranges which the buddy must exclude.
pub unsafe fn reserve_from_regions(
    usable: &[UsableRegion],
    protected: &[(u64, u64)],
    want_2m: usize,
    want_1g: usize,
) -> Vec<(u64, u64)>;
pub fn alloc_hugepage_2m() -> Result<HugeFrame, HugeAllocError>;
pub fn alloc_hugepage_1g() -> Result<HugeFrame, HugeAllocError>;
/// Strict node-selection primitives used by NUMA policy consumers.
pub fn alloc_hugepage_2m_on(node: usize) -> Result<HugeFrame, HugeAllocError>;
pub fn alloc_hugepage_1g_on(node: usize) -> Result<HugeFrame, HugeAllocError>;
/// All-or-nothing vector allocation with one pool-lock transaction.
pub fn alloc_hugepages_with(
    size: HugeSize,
    policies: &[Mempolicy],
    local: usize,
) -> Result<Vec<HugeFrame>, HugeAllocError>;
// Exported from the `hugepage` module.
pub fn node_stats(node: usize) -> HugeNodeStats;

pub struct HugeRegion {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    pub size: HugeSize,
    pub frames: Vec<HugeFrame>,
}

/// POSIX protection bits plus internal address-space state. COW preserves the
/// logical WRITE authority while shared resident leaves remain hardware RO;
/// LOCKED excludes a range from reclaim, including lazy MLOCK_ONFAULT pages.
pub struct RegionPerms(u32);
impl RegionPerms {
    pub const READ: RegionPerms;
    pub const WRITE: RegionPerms;
    pub const EXEC: RegionPerms;
    pub const LOCKED: RegionPerms;
    pub const COW: RegionPerms;
}

impl AddressSpace {
    /// Allocate an architecture user root. On aarch64 this also reserves one
    /// lifetime-scoped process ASID when the hardware pool has capacity.
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError>;
    /// Install this address space's architecture root for the current CPU.
    pub fn activate(&self) -> Result<(), AddressSpaceError>;
    /// One ownership-integrated same-root page-out submission.
    pub unsafe fn swap_out_private_batch(
        &self,
        base: VirtAddr,
        pages: usize,
    ) -> Result<usize, SwapError>;
    /// Execute selected ranges in bounded batches with partial-progress data.
    pub unsafe fn swap_out_reclaim_plan(
        &self,
        plan: &ReclaimBatchPlan,
    ) -> SwapBatchReport;
    /// Materialize every recorded base-page region; used for exec/fork build.
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError>;
    /// Materialize only current regions intersecting a page-aligned user range.
    /// The region lock is held through the page-table walk.
    pub unsafe fn materialize_range(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Result<(), AddressSpaceError>;
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
    /// One mincore-shaped residency byte per rounded base page; holes fail.
    pub fn residency_range(&self, base: VirtAddr, len: u64)
        -> Result<Vec<u8>, AddressSpaceError>;
    /// Move one complete private base-page region without copying resident
    /// bytes; shrink drops tail ownership, growth appends lazy pages.
    pub unsafe fn relocate_region(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
    ) -> Result<(), AddressSpaceError>;
    /// Eagerly populate and pin exactly the rounded mapped range.
    pub fn mlock_range(&self, base: VirtAddr, len: u64)
        -> Result<(), AddressSpaceError>;
    /// Pin exactly the rounded mapped range without populating lazy pages.
    pub fn mlock_range_onfault(&self, base: VirtAddr, len: u64)
        -> Result<(), AddressSpaceError>;
    /// Unpin exactly the rounded mapped range without discarding backing.
    pub fn munlock_range(&self, base: VirtAddr, len: u64)
        -> Result<(), AddressSpaceError>;
}

/// Install the external shared-page owner's per-alias lifetime hooks.
/// Every SHARED map retains each non-zero backing frame; unmap, MAP_FIXED
/// replacement, and address-space teardown release only after the
/// corresponding translations have been invalidated.
pub fn install_shared_frame_hooks(retain: fn(u64), release: fn(u64));

impl AddressSpace {
    /// Remove an exact base-page region.
    pub fn unmap_region(&self, base: VirtAddr)
        -> Result<Region, AddressSpaceError>;
    /// Remove a base-page range while preserving non-overlapping fragments.
    pub fn punch_fixed(&self, base: VirtAddr, len: u64)
        -> Result<(), AddressSpaceError>;
}

/// Clear a contiguous x86_64 leaf range under one per-root mutation-lock hold;
/// each present leaf still receives a local INVLPG and the caller performs the
/// required later cross-CPU range/full invalidation before backing reuse.
pub unsafe fn x86_64::paging::unmap_4kb_local_range(
    root: PhysAddr,
    base: VirtAddr,
    pages: u64,
) -> Result<u64, MapError>;

/// Install a contiguous virtual run from scatter-list backing under one
/// per-root mutation-lock hold; zero entries remain lazy/unmapped.
pub unsafe fn x86_64::paging::map_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;

/// Rewrite resident x86_64 scatter backing under one root-lock hold and one
/// local invalidation phase; zero entries remain lazy/unmapped.
pub unsafe fn x86_64::paging::rewrite_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;

/// aarch64 scatter installation takes the same root lock once and publishes
/// all fresh descriptors with one DSB/ISB sequence.
pub unsafe fn aarch64::paging::map_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;

/// Rewrite a contiguous scatter-backed aarch64 run under one root lock. All
/// old leaves are cleared and invalidated before any replacement is installed;
/// zero backing entries remain lazy holes.
pub unsafe fn aarch64::paging::rewrite_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError>;

/// Clear a contiguous aarch64 leaf run under one root lock, issuing one
/// last-level all-ASID TLBI per VA bracketed by one shared barrier sequence.
pub unsafe fn aarch64::paging::unmap_4kb_range(
    root: PhysAddr,
    base: VirtAddr,
    pages: u64,
) -> Result<u64, MapError>;

Private-region teardown serializes only on the address space's region tables.
Teardown that overlaps an externally owned `SHARED` alias additionally holds
the global shared-mapping transaction through leaf removal, cross-CPU TLB
invalidation, and the external owner's release hook. Classification and table
mutation are one region-lock critical section, so a racing remap cannot switch
a private region to `SHARED` between those steps.

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
- Buddy allocator free lists and their IRQ-safe locks are per-NUMA-node and
  cache-line isolated. Order-0 allocation/free is fronted by a bounded,
  cache-line-aligned per-CPU/per-node cache; refill and spill batch eight pages
  under one zone-lock acquisition, while cached pages remain included in
  free-page and order-0 statistics. Batched final-owner return groups pages by
  physical NUMA node, takes the current CPU cache lock for at most 64 pages at
  a time, and publishes all direct/spilled pages through one buddy-zone lock
  per touched node. A base-page refill or folio allocation holds only one zone
  lock at a time; nearest-node fallback releases the failed zone before trying
  the next, so unrelated NUMA nodes do not serialize on a global frame lock.
  Coordinated draining bypasses new cache insertion before high-order retry;
  runtime-hotplug nodes bypass the cache so exact-range offline admission
  continues to observe every free frame in the buddy.
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
- A private fork preserves each VMA's logical POSIX WRITE bit and marks it
  COW. Hardware leaves remain read-only while their backing-frame refcount is
  greater than one. A write fault is recoverable only when both WRITE and COW
  are present; `mprotect(PROT_READ)` therefore cannot be mistaken for COW.
  Fork retains all resident private backing through one batched operation
  while the parent region transaction is held. The batch groups frames by
  refcount shard, locks each touched shard once, and increments once per input
  occurrence; unbacked zero sentinels and externally owned SHARED mappings are
  excluded. Multi-page materialization and parent permission rewriting snapshot
  COW counts by shard while holding the relevant address-space region lock. A
  concurrent last-owner decrement may conservatively leave a leaf read-only;
  a sole-owner frame cannot become newly shared without that same region
  transaction, so the snapshot cannot incorrectly grant WRITE to shared
  backing. Region teardown, MAP_FIXED punching, and MADV_DONTNEED retire leaves
  and complete the required TLB flush before dropping backing owners through
  the allocator's batch interface.
  The buddy implementation locks each touched COW shard once, performs the
  scalar-equivalent cgroup uncharge and optional scrub for only final-owner or
  unregistered frames, then groups those frames for bounded per-CPU cache and
  per-NUMA-zone return. Allocation-audit transitions and cache-drain bypass
  revalidation are preserved; alternative allocators use the scalar default.
- Base-page relocation installs the disjoint destination before removing the
  source, publishes backing ownership exactly once, invalidates source
  translations before freeing a truncated tail, and leaves the source intact
  when destination installation fails.
- Base-page regions live in an ordered tree keyed by virtual base. The key and
  `Region.base` remain equal after every insertion, removal, split, stack
  growth, and relocation. Because regions never overlap, admission, point
  lookup, random insertion, and empty MAP_FIXED punches are O(log VMA) and
  inspect only the predecessor/successor or intersecting tree range; backing
  ownership and TLB ordering are unchanged by this metadata index invariant.
  The periodic NUMA sampler seeks to the VMA containing or succeeding its
  page-aligned cursor and stops at the first eligible resident slot, rather
  than rescanning all preceding VMAs/pages under the IRQ-safe region lock.
- Anonymous and file-backed demand faults reserve a page-scoped ticket before
  leaving the address-space region lock. Frame allocation, page zeroing, and
  filesystem callbacks run without that IRQ-disabling lock, so faults on
  distinct pages of one shared address space may progress concurrently. The
  winning ticket republishes backing and installs its leaf while holding the
  region lock; structural VMA removal cancels every covered ticket before a
  replacement can appear. A cancelled anonymous allocation remains owned by
  the fault path and returns to the frame allocator; a cancelled file alias is
  released through its backing-owner hook.
- COW write faults use the same page-scoped exclusion principle. The ticket
  owner takes a temporary source-frame reference before releasing the region
  lock, allocates and copies outside that lock, and republishes only if the
  same VMA still owns the same source page with WRITE+COW authority. A
  cancelled copy frees its unpublished destination and drops only the pin; a
  successful copy drops both the old region ownership and the pin after the
  new backing is visible. Faults on unrelated pages therefore do not serialize
  on a 4 KiB allocation/copy, while teardown cannot recycle a source mid-copy.
- Every AS-private x86_64 page-table frame has one live entry in the fixed
  atomic ownership registry. Open-addressed probing never overwrites a live
  entry; deletion leaves a tombstone so colliding ownership remains visible;
  lookup may stop only at a never-used slot. Kernel-shared page tables are not
  registered and therefore are never reclaimed by user-address-space teardown.
- PSS is a range-selection weight, never evidence that physical memory was
  released. Watermark progress advances only by conservative reverse-map
  `expected_free_pages`; locked, malformed, and zero-yield ranges are skipped.
- Boot huge-page reservation never claims the architecture-reserved low-memory
  window or any caller-protected physical range. The loaded kernel image is a
  mandatory protected range, and every successful claim is returned as a buddy
  exclusion before the same usable map is donated. Free 2 MiB and 1 GiB frames
  are partitioned by physical NUMA node, so strict-node allocate, free, and
  per-node statistics are O(1); boot pre-reserves each node stack for its total
  outstanding reservation so a later free cannot grow a vector while holding
  the huge-pool IRQ-safe lock. Multi-frame allocation precomputes each policy
  order before taking that lock, pops the complete vector in one critical
  section, and rolls every pop back to its original node before returning an
  exhaustion error; callers never observe partial batch ownership. On x86_64,
  `map_huge_region` holds one per-root page-table mutation lock across every
  fresh huge leaf in the region; a failed leaf releases that lock before
  ordinary rollback unmaps, and no backing is published to region metadata
  until the complete leaf batch succeeds.
- aarch64 page-table writers are serialized by the same 64-way root-physical
  lock sharding model as x86_64. Base-page scatter installation holds one shard
  across the run and publishes all fresh descriptors with one `DSB ISHST` /
  `ISB`; contiguous teardown clears all leaves before issuing per-VA
  `VAALE1IS` operations bracketed by one `DSB ISHST` / `DSB ISH` / `ISB`.
  MAP_FIXED punching, MADV_DONTNEED, region teardown, and fresh huge-region
  installation use those root transactions, so unrelated address spaces do
  not serialize and a same-root intermediate-table race cannot orphan leaves.
  Permission and COW write-protect rewrites use one break-before-make
  transaction per region: all old leaves are cleared, one batched all-ASID
  invalidation completes, then all non-zero replacements are installed and
  published once. Parent `rematerialize` is a real rewrite on both supported
  architectures; it may not be a no-op after fork while the parent's live leaf
  is still writable.
- x86_64 permission and COW write-protect rewrites hold one root mutation shard
  per region rather than reacquiring it for each unmap/map pair. The helper
  completes one bounded local invalidation phase after the final leaf write;
  `AddressSpace` then issues only the remote half of a range shootdown for a
  peer-active small run, or one full non-global local/remote flush for a large
  multi-region rewrite. No backing becomes reusable in this permission-only
  path, and zero lazy sentinels are never installed as physical address zero.
- A swap-out batch reserves one contiguous slot run, performs one backend
  vector write, validates every same-root leaf before publishing any swap PTE,
  and retires stale translations once before returning any victim frame to the
  allocator. Failure before PTE publication leaves every mapping resident and
  releases the complete slot run.
- A swap-in batch validates and reads every requested slot into unpublished
  frames before atomically replacing the same-root swap leaves. Failure leaves
  all PTEs and slots unchanged. Backend I/O runs without the global swap-device
  lock or a page-table mutation lock held.
- Live anonymous-private x86_64 swap uses region-table transitions
  `Evicting -> Swapped -> Loading -> Resident`. PTE publication transfers the
  corresponding `Region::phys` ownership before TLB invalidation/free; page-in
  republishes Region ownership before retiring slots. A fault on `Swapped`
  collects consecutive leaves ahead of the fault for one vector read/PTE
  commit. Teardown atomically clears all stable swap leaves and discards their
  slots as one backend batch. Shared, COW, file-backed, and locked pages are
  ineligible until reverse-map/slot-sharing semantics are defined.

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
- `AddressSpace::activate` installs the address space's TTBR0 low-half root;
  scheduler polling saves and restores the incoming TTBR0 so kernel tasks never
  inherit a user root. Each live process root receives a unique ASID from the
  hardware-supported namespace after tags 1..=16, which remain reserved for
  domain roots. A switch to a nonzero lifetime tag does not flush; final
  `AddressSpace` teardown broadcasts `TLBI ASIDE1IS` before making that tag
  reusable. Pool exhaustion falls back safely to ASID 0 with a local full
  invalidation on every distinct-root switch.
- Page-table mutation invalidates by VA for every ASID across the
  inner-shareable domain (`VAAE1IS` / `VAALE1IS`). This is required because
  the mutated root need not be the TTBR0 context active on the issuing CPU.
  Mutators take a 64-way root-physical lock; contiguous base-page teardown
  batches the required barrier sequence around the complete run rather than
  paying it once per leaf, while still issuing one last-level TLBI operand per
  page for CPUs that do not implement range TLBI. Permission changes obey
  break-before-make across the whole run: the invalidate barrier sequence
  completes before replacement descriptors are stored, and one publication
  barrier makes the replacement run visible.
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
- `hugepage.rs` — boot-reserved, protected-range-aware, per-NUMA-node 2 MiB /
  1 GiB pools (cmdline `hugepages_2m=N` / `hugepages_1g=N`), no buddy fallback.
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
