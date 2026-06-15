//! Physical frames + per-NUMA-node frame allocator.
//!
//! Wave-2 subset of `memory/` spec §3 with Wave-3 NUMA awareness:
//! per-node free-stack allocators, classified by SRAT memory-range
//! attribution. The allocator stays simple (free-stack, not buddy);
//! the buddy allocator + magazines land later.
//!
//! Layout:
//! - One `Vec<PhysFrame>` per NUMA node (`MAX_NUMA_NODES`). Boot
//!   inits flat (everything goes to bin 0); `rebalance_to_topology`
//!   redistributes the remaining frames to their proper bins once
//!   SRAT data is available.
//! - `alloc_frame()` consults the current CPU's NUMA node first
//!   (looked up via the weak-link `narf_cpu_to_node` hook), then
//!   falls back round-robin to other nodes.
//! - `alloc_frame_on(node)` is the explicit-node entry point.
//! - `free_frame(f)` uses `narf_phys_to_node` to return the frame
//!   to its rightful node bin.
//!
//! Cycle avoidance: this crate cannot depend on `narf-acpi`
//! (narf-acpi pulls in `narf_memory::PhysAddr`). The hooks below are
//! the standard weakly-linked surface — narf-frame provides
//! `#[no_mangle]` definitions calling into narf-acpi at boot.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::buddy::{self, BuddyZone, MAX_ORDER};
use crate::PhysAddr;

/// Page size in bytes. x86_64 / aarch64 both use 4 KiB as the base size.
pub const PAGE_SIZE: u64 = 4096;
/// Log2 of the page size; handy for shifts.
pub const PAGE_SHIFT: u32 = 12;

/// Maximum NUMA nodes we track. Mirrors `narf_acpi::MAX_NUMA_NODES`
/// — kept independent so this crate doesn't pull in narf-acpi.
pub const MAX_NUMA_NODES: usize = 16;

/// A 4 KiB physical frame, identified by its starting physical address.
///
/// The wrapper enforces page alignment at construction time and is
/// `#[repr(transparent)]` so conversion to/from `PhysAddr` is free.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysFrame(PhysAddr);

impl PhysFrame {
    /// Wrap an already-aligned `PhysAddr`. Panics on misaligned input in
    /// debug; truncates in release (callers should use `containing`).
    pub const fn new(addr: PhysAddr) -> Self {
        debug_assert!(
            addr.raw() & (PAGE_SIZE - 1) == 0,
            "PhysFrame::new requires a page-aligned PhysAddr"
        );
        Self(addr)
    }

    /// Round `addr` down to a page boundary and wrap.
    pub const fn containing(addr: PhysAddr) -> Self {
        Self(PhysAddr::new(addr.raw() & !(PAGE_SIZE - 1)))
    }

    /// Starting physical address of this frame.
    #[inline]
    pub const fn start_address(self) -> PhysAddr {
        self.0
    }

    /// Frame number (phys >> PAGE_SHIFT).
    #[inline]
    pub const fn number(self) -> u64 {
        self.0.raw() >> PAGE_SHIFT
    }
}

impl fmt::Debug for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysFrame({:#018x})", self.0.raw())
    }
}

/// Reasons a frame-alloc call can fail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameAllocError {
    /// No free frames remain in any usable region.
    Exhausted,
    /// Allocator not initialised yet (`init_from_map` hasn't run).
    Uninitialised,
    /// The currently-installed `FrameAlloc` impl does not support
    /// this operation (e.g. `BumpFrameAlloc::free_frame`).
    NotSupported,
    /// `install_frame_alloc` was called with an authority cap whose
    /// epoch has been revoked.
    AuthorityRevoked,
}

impl From<CapError> for FrameAllocError {
    fn from(_: CapError) -> Self {
        FrameAllocError::AuthorityRevoked
    }
}

/// Per-node buddy zone. Index 0 holds everything pre-
/// `rebalance_to_topology`; post-rebalance each node has only the
/// frames whose physical addresses map to its proximity domain.
#[derive(Debug)]
pub struct FrameAllocator {
    zones: [BuddyZone; MAX_NUMA_NODES],
    initialised: bool,
    total_frames: usize,
    reserved_frames: usize,
    /// Set after `rebalance_to_topology` completes; alloc + free
    /// honour per-node zones from this point on. Pre-flag, every
    /// allocation comes out of zones[0].
    numa_aware: bool,
}

const NEW_ZONE: BuddyZone = BuddyZone::new();

static ALLOC: IrqSafeSpinLock<FrameAllocator> = IrqSafeSpinLock::new(FrameAllocator {
    zones: [NEW_ZONE; MAX_NUMA_NODES],
    initialised: false,
    total_frames: 0,
    reserved_frames: 0,
    numa_aware: false,
});

/// A subset of the bootloader memory map: just what the allocator needs.
/// Consumers typically pass `BootInfo::memory_map` via `narf_boot`.
#[derive(Copy, Clone, Debug)]
pub struct UsableRegion {
    pub start: PhysAddr,
    pub len: u64,
}

/// Initialise the frame allocator from a slice of usable regions. `exclude`
/// is a list of half-open byte ranges that must NOT be handed out — the
/// kernel image itself, the boot-info structure, the PVH hvm_start_info,
/// and so on.
///
/// Frames go into bin 0 unconditionally — NUMA topology is not yet
/// known at this point in boot. Call `rebalance_to_topology` after
/// SRAT has been parsed to redistribute.
///
/// # Safety
/// - Must be called exactly once, before any `alloc_frame` / `free_frame`.
/// - Each `UsableRegion` must be real, kernel-reachable physical RAM;
///   violating this hands out bogus frames that will fault on first
///   touch.
pub unsafe fn init_from_map(usable: &[UsableRegion], exclude: &[(u64, u64)]) {
    let mut total = 0usize;
    let mut reserved = 0usize;
    let mut guard = ALLOC.lock();
    // First pass: count total + reserved frames for stats.
    for r in usable {
        let start = r.start.raw();
        let end = start + r.len;
        let first = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let last = end & !(PAGE_SIZE - 1);
        let mut a = first;
        while a + PAGE_SIZE <= last {
            total += 1;
            if is_excluded(a, exclude) {
                reserved += 1;
            }
            a += PAGE_SIZE;
        }
    }
    // Second pass: donate sub-ranges that don't overlap any
    // excluded range. Each exclude is (lo_byte, hi_byte) — a
    // half-open byte range. Sub-divide each region accordingly
    // so the buddy gets contiguous sub-ranges to coalesce.
    for r in usable {
        let region_start = (r.start.raw() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let region_end = (r.start.raw() + r.len) & !(PAGE_SIZE - 1);
        if region_start >= region_end {
            continue;
        }
        donate_around_excludes(&mut guard.zones[0], region_start, region_end, exclude);
    }
    guard.initialised = true;
    guard.total_frames = total;
    guard.reserved_frames = reserved;
    guard.numa_aware = false;
    // Drop the guard before installing the default `FrameAlloc` —
    // `install_frame_alloc_default` takes its own lock and we don't
    // want to risk an unrelated future reentrancy regression.
    drop(guard);
    install_frame_alloc_default();
    // NOTE: we deliberately do NOT promote the global allocator to
    // the slab here, and we do not pre-reserve buddy Vec capacity
    // until after `rebalance_to_topology` has redistributed frames
    // to their proper NUMA zones. `reserve_for_slab_promotion()`
    // does the per-zone reservation just before promote_to_slab —
    // sized to the actual zone contents, not the worst-case
    // total. Both are called from bare_main once ACPI is up.
}

/// Pre-reserve buddy Vec capacity in every populated zone so that
/// split / coalesce pushes never realloc-grow at runtime. Critical
/// for deadlock-avoidance once the slab is the global allocator:
/// a Vec growth would route through slab → buddy → `ALLOC.lock()`
/// (already held by the buddy) → recursive deadlock.
///
/// Call this once, AFTER `rebalance_to_topology` has populated
/// each zone, and BEFORE `crate::heap::promote_to_slab()` flips
/// the global allocator. While we're still on bump, the
/// reservation allocations themselves don't recurse.
pub fn reserve_for_slab_promotion() {
    let mut g = ALLOC.lock();
    for zone in g.zones.iter_mut() {
        zone.reserve_growth_capacity();
    }
}

/// Donate the byte range `[start, end)` to `zone`, splitting around
/// any excluded sub-ranges. Aligns each sub-range to page boundaries
/// before donating.
fn donate_around_excludes(zone: &mut BuddyZone, start: u64, end: u64, exclude: &[(u64, u64)]) {
    // Walk left to right, emitting sub-ranges between excludes.
    let mut cursor = start;
    // Collect overlapping excludes, sorted by start.
    let mut hits: Vec<(u64, u64)> = exclude
        .iter()
        .copied()
        .filter(|&(lo, hi)| hi > start && lo < end)
        .map(|(lo, hi)| (lo.max(start), hi.min(end)))
        .collect();
    hits.sort_by_key(|&(lo, _)| lo);
    for (lo, hi) in hits {
        // Round excluded range OUT to page boundaries (anything
        // touching an excluded byte is fully reserved).
        let lo_page = lo & !(PAGE_SIZE - 1);
        let hi_page = (hi + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if cursor < lo_page {
            donate_range(zone, cursor, lo_page);
        }
        cursor = hi_page.max(cursor);
    }
    if cursor < end {
        donate_range(zone, cursor, end);
    }
}

/// Lowest phys address the buddy is allowed to hand out. The first
/// MiB of physical RAM is conventionally reserved on x86 — it
/// contains the BIOS data area, the IVT (real-mode), the EBDA,
/// the SMP AP trampoline (0x8000), VGA framebuffer remnants, and
/// other firmware-owned regions. Even though the bootloader
/// memory map sometimes marks it "Available", handing it out as
/// a real allocation collides with these uses (most painfully:
/// the AP trampoline at 0x8000).
///
/// The previous Vec-based frame allocator masked this because
/// `Vec::pop` returned high frames first; the buddy, splitting
/// from any order, can return low frames early. Skip the first
/// MiB unconditionally.
const LOW_RESERVED_BYTES: u64 = 0x100000;

/// Donate `[start, end)` (page-aligned) to `zone` as a single contiguous run.
/// Skips the first MiB of phys (BIOS / SMP trampoline territory).
fn donate_range(zone: &mut BuddyZone, start: u64, end: u64) {
    debug_assert_eq!(start & (PAGE_SIZE - 1), 0);
    debug_assert_eq!(end & (PAGE_SIZE - 1), 0);
    if end <= start {
        return;
    }
    let start = start.max(LOW_RESERVED_BYTES);
    if end <= start {
        return;
    }
    let first_frame = start >> PAGE_SHIFT;
    let frame_count = (end - start) >> PAGE_SHIFT;
    zone.donate(first_frame, frame_count);
}

fn is_excluded(addr: u64, exclude: &[(u64, u64)]) -> bool {
    exclude.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
}

/// Redistribute frames currently in zones[0] across per-NUMA-node
/// zones according to `narf_phys_to_node`. Call this once after ACPI
/// SRAT has been parsed (`narf_acpi::parse_srat`). Idempotent —
/// repeated calls are no-ops.
///
/// The buddy is per-zone; we move whole free blocks based on the
/// node of their starting frame. (A multi-frame block crossing a
/// node boundary stays with its starting node — rare in practice
/// since SRAT memory ranges are typically aligned to large
/// boundaries.)
pub fn rebalance_to_topology() {
    let mut g = ALLOC.lock();
    if g.numa_aware || !g.initialised {
        return;
    }
    // Move blocks from zones[0] to their proper node zones.
    // Two-pass to avoid borrow-checker issues with simultaneous
    // mutable access to two zone slots.
    for target in 1..MAX_NUMA_NODES {
        let (left, right) = g.zones.split_at_mut(target);
        let dst = &mut right[0];
        let src = &mut left[0];
        src.drain_into(dst, |frame_no| {
            let phys = frame_no << PAGE_SHIFT;
            phys_to_node(phys) == target
        });
    }
    g.numa_aware = true;
}

/// Allocate one 4 KiB frame. NUMA-aware: prefers the current CPU's
/// node, falls back round-robin to other nodes when the local bin
/// is empty. Dispatches through the installed `FrameAlloc`.
pub fn alloc_frame() -> Result<PhysFrame, FrameAllocError> {
    let preferred = current_cpu_node();
    alloc_frame_on(preferred)
}

/// Phys-address ceiling for early boot. While set, alloc_frame*
/// returns only frames whose physical address is strictly below
/// this value. Reason: pre-MMU-init code (per-domain PML4 setup,
/// init_mmu's own page tables, anything that writes through
/// `phys.raw() as *mut T`) only works when phys is in the
/// boot.S identity map (currently 0..4 GiB). On systems with
/// the q35 PCI-hole RAM split (real Zen2 laptops with 16 GiB,
/// QEMU q35 with -m ≥ 4G) usable RAM straddles 4 GiB; an
/// unconstrained allocator would hand out high frames and
/// trigger a #PF on first access.
///
/// Default 4 GiB. Cleared (set to 0 = unlimited) by
/// `release_early_ceiling()` once a kernel direct map covers
/// all RAM — typically after MMU init + a high-mem ioremap pass.
pub(crate) static EARLY_PHYS_CEILING: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(4u64 << 30);

/// Allow the allocator to return frames at any physical address.
/// Call once a kernel direct map covers all installed RAM.
pub fn release_early_ceiling() {
    EARLY_PHYS_CEILING.store(0, core::sync::atomic::Ordering::Release);
}

/// Pop a frame from `zone` whose phys address is below the early
/// ceiling. Returns None if no qualifying block is available at
/// order 0. Uses the buddy zone's `alloc_below` which honors the
/// ceiling at the frame-number level.
fn alloc_below_ceiling(zone: &mut BuddyZone) -> Option<PhysFrame> {
    let ceil_frame = buddy::early_ceiling_frame();
    let frame_no = if ceil_frame == u64::MAX {
        zone.alloc(0)?
    } else {
        zone.alloc_below(0, ceil_frame)?
    };
    Some(buddy::frame_from_no(frame_no))
}

/// Allocate one 4 KiB frame, preferring `node`'s zone. Dispatches
/// through the installed `FrameAlloc` impl — see `install_frame_alloc`.
pub fn alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    // cgroup memory accounting: charge one page to the current task's
    // cgroup chain *before* the allocation commits. A `false` return
    // means a `memory.max` would be exceeded, so the allocation is
    // denied (enforced). This is the order-0 user-facing entry point
    // (`alloc_frame` delegates here), so the charge happens exactly once
    // per page handed out.
    #[cfg(feature = "cgroup")]
    if !crate::cgroup_charge::try_charge(PAGE_SIZE) {
        return Err(FrameAllocError::Exhausted);
    }
    let r = with_installed(|a| a.alloc_frame_on(node));
    #[cfg(feature = "cgroup")]
    if r.is_err() {
        // Allocation failed after charging — refund so accounting stays
        // balanced with the actual page population.
        crate::cgroup_charge::uncharge(PAGE_SIZE);
    }
    r
}

/// Allocate a frame from any node. Useful for boot-time allocations
/// that don't care about locality. Dispatches through the installed
/// `FrameAlloc` impl.
pub fn alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "cgroup")]
    if !crate::cgroup_charge::try_charge(PAGE_SIZE) {
        return Err(FrameAllocError::Exhausted);
    }
    let r = with_installed(|a| a.alloc_frame_anywhere());
    #[cfg(feature = "cgroup")]
    if r.is_err() {
        crate::cgroup_charge::uncharge(PAGE_SIZE);
    }
    r
}

/// Buddy-backed implementation of `alloc_frame_on`. The default
/// `BuddyFrameAlloc::alloc_frame_on` delegates here; alternative
/// `FrameAlloc` impls (e.g. `BumpFrameAlloc`) own their own paths
/// and never touch the buddy.
fn buddy_alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    if !g.initialised {
        return Err(FrameAllocError::Uninitialised);
    }

    if !g.numa_aware {
        // Pre-rebalance: everything's in zones[0].
        return alloc_below_ceiling(&mut g.zones[0]).ok_or(FrameAllocError::Exhausted);
    }

    let preferred = node.min(MAX_NUMA_NODES - 1);
    if let Some(f) = alloc_below_ceiling(&mut g.zones[preferred]) {
        return Ok(f);
    }

    // Fallback: round-robin from the next-highest node, wrapping.
    for offset in 1..MAX_NUMA_NODES {
        let i = (preferred + offset) % MAX_NUMA_NODES;
        if let Some(f) = alloc_below_ceiling(&mut g.zones[i]) {
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Buddy-backed implementation of `alloc_frame_anywhere`.
fn buddy_alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    if !g.initialised {
        return Err(FrameAllocError::Uninitialised);
    }
    for zone in g.zones.iter_mut() {
        if let Some(f) = alloc_below_ceiling(zone) {
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate a contiguous block of `1 << order` frames. `order=0`
/// is one frame (same as `alloc_frame_on`); `order=10` is 4 MiB.
/// Phase-1 buddy allocator entry point.
pub fn alloc_pages_on(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError> {
    if order > MAX_ORDER {
        return Err(FrameAllocError::Exhausted);
    }
    // cgroup memory accounting: charge the whole `1 << order` block up
    // front (enforced — deny if over `memory.max`), refund on failure.
    #[cfg(feature = "cgroup")]
    let charge_bytes = PAGE_SIZE << order;
    #[cfg(feature = "cgroup")]
    if !crate::cgroup_charge::try_charge(charge_bytes) {
        return Err(FrameAllocError::Exhausted);
    }
    let r = alloc_pages_on_inner(node, order);
    #[cfg(feature = "cgroup")]
    if r.is_err() {
        crate::cgroup_charge::uncharge(charge_bytes);
    }
    r
}

fn alloc_pages_on_inner(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    if !g.initialised {
        return Err(FrameAllocError::Uninitialised);
    }
    let preferred = node.min(MAX_NUMA_NODES - 1);
    let zone_idx = if g.numa_aware { preferred } else { 0 };
    let ceil = buddy::early_ceiling_frame();
    let try_alloc = |z: &mut BuddyZone| -> Option<u64> {
        if ceil == u64::MAX {
            z.alloc(order)
        } else {
            z.alloc_below(order, ceil)
        }
    };
    if let Some(no) = try_alloc(&mut g.zones[zone_idx]) {
        return Ok(buddy::frame_from_no(no));
    }
    if !g.numa_aware {
        return Err(FrameAllocError::Exhausted);
    }
    for offset in 1..MAX_NUMA_NODES {
        let i = (preferred + offset) % MAX_NUMA_NODES;
        if let Some(no) = try_alloc(&mut g.zones[i]) {
            return Ok(buddy::frame_from_no(no));
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Free a contiguous block of `1 << order` frames previously
/// returned from `alloc_pages_on`.
pub fn free_pages(frame: PhysFrame, order: u8) {
    if order > MAX_ORDER {
        return;
    }
    // cgroup memory uncharge: mirror the `alloc_pages_on` charge.
    #[cfg(feature = "cgroup")]
    crate::cgroup_charge::uncharge(PAGE_SIZE << order);
    let phys = frame.start_address().raw();
    if phys < LOW_RESERVED_BYTES {
        // Refusing the free is safer than corrupting the buddy by
        // pushing a frame that was never legitimately donated.
        // (donate_range masks below 1 MiB at boot; any lower phys
        // here came from a stale page-table addr or bad pointer.)
        return;
    }
    let node = phys_to_node(phys);
    let mut g = ALLOC.lock();
    if !g.initialised {
        return;
    }
    let zone_idx = if g.numa_aware { node } else { 0 };
    g.zones[zone_idx].free(buddy::frame_no(frame), order);
}

/// Return a previously-allocated frame to the pool. Dispatches
/// through the installed `FrameAlloc`. The default buddy impl
/// routes the frame to its NUMA node's zone; alternative impls
/// (e.g. `BumpFrameAlloc`) may treat this as a no-op or return
/// `NotSupported` via their `try_*` variant.
pub fn free_frame(f: PhysFrame) {
    if let Some(a) = current_alloc() {
        a.free_frame(f);
    }
}

/// Buddy-backed implementation of `free_frame`.
///
/// COW interaction: if the frame has a refcount > 1 (multiple
/// `Arc<AddressSpace>`s share it via `clone_for_fork`), this call
/// only decrements — the actual return-to-bin happens when the
/// last reference drops. Frames that were never refcounted
/// (default for everything outside the COW path) are returned
/// immediately as before.
fn buddy_free_frame(f: PhysFrame) {
    // Refuse low-mem phys before any state mutation. Frames below
    // `LOW_RESERVED_BYTES` are never legitimately donated to the
    // buddy (see `donate_range`), so any caller handing one to
    // `free_frame` has a bad source phys — typically a page-table
    // entry whose `addr()` mask resolved to a sentinel.
    if f.start_address().raw() < LOW_RESERVED_BYTES {
        return;
    }
    if cow::dec_ref(f.start_address()) > 0 {
        // Other ASes still reference this frame; don't return it.
        return;
    }
    // cgroup memory uncharge: only here, where the frame is genuinely
    // returned to the buddy — i.e. the COW refcount has reached 0 — does
    // it balance the single charge taken at `alloc_frame_on`. The
    // intermediate `dec_ref > 0` frees above (fork-shared pages) take no
    // uncharge, matching the fact that `clone_for_fork` `inc_ref`s
    // rather than re-allocating (no second charge was ever taken).
    #[cfg(feature = "cgroup")]
    crate::cgroup_charge::uncharge(PAGE_SIZE);
    // Optional scrub of the frame's contents on its way back to the
    // buddy. The frame's COW refcount just hit 0 and it is NOT yet on
    // any free list, so we hold exclusive access — no lock needed and
    // no allocator can hand it out mid-scrub.
    scrub_freed_frame(f.start_address());
    let node = phys_to_node(f.start_address().raw());
    let mut g = ALLOC.lock();
    if !g.initialised {
        return;
    }
    let zone_idx = if g.numa_aware { node } else { 0 };
    g.zones[zone_idx].free(buddy::frame_no(f), 0);
}

/// Optionally overwrite a frame's bytes as it returns to the buddy
/// allocator. Compiled out (zero cost) unless a scrub feature is set:
///
/// - `frame-zero-on-free`: fill with zeros. Info-leak hardening — a
///   freed frame's stale data (which may be another task's user memory
///   or kernel heap) can't be observed by the next owner of the frame.
/// - `frame-poison-on-free`: fill with a recognizable non-canonical
///   poison word (`0xDEAD_BEEF_DEAD_BEEF`). A use-after-free or
///   uninitialised-pointer read of a recycled frame then faults on an
///   obviously-diagnostic value (`cr2`/registers spell `deadbeef`)
///   instead of whatever stale bytes happened to land there — the
///   "marginal-buddy" execve `#PF` that reads the freed `tcp_congestion`
///   name ("cubic") as a pointer is exactly this class. Poison takes
///   precedence when both features are enabled.
///
/// Both add a 4 KiB write to the genuine-free path (after the COW
/// refcount reaches 0), so they are opt-in debug/hardening aids rather
/// than always-on.
#[inline]
fn scrub_freed_frame(phys: PhysAddr) {
    #[cfg(any(feature = "frame-poison-on-free", feature = "frame-zero-on-free"))]
    {
        #[cfg(feature = "frame-poison-on-free")]
        const FILL: u64 = 0xDEAD_BEEF_DEAD_BEEF;
        #[cfg(all(feature = "frame-zero-on-free", not(feature = "frame-poison-on-free")))]
        const FILL: u64 = 0;
        let dst = phys.kernel_mut_ptr::<u64>();
        // SAFETY: exclusive access per the caller's contract (refcount 0,
        // not yet on a free list). `kernel_mut_ptr` resolves through the
        // kernel direct map (identity low-4-GiB + high-half RAM window),
        // valid for any donated RAM frame. Writes stay within the 4 KiB
        // frame. `write_volatile` keeps the fill from being elided as a
        // dead store into about-to-be-freed memory.
        unsafe {
            for i in 0..(PAGE_SIZE as usize / 8) {
                core::ptr::write_volatile(dst.add(i), FILL);
            }
        }
    }
    let _ = phys;
}

/// Page-table-frame registry. Every PT / PD / PDPT / PML4 page
/// allocated for a user `AddressSpace` is recorded here at alloc
/// time and unregistered when the matching `free_user_pml4_tree`
/// walk reclaims it. `AddressSpace::unmap_region_pages` consults
/// this before handing the leaf phys from `unmap_4kb` to
/// `free_frame`: if the leaf happens to alias a known page-table
/// frame (a corner case in the AS drop teardown where the same
/// phys would otherwise be freed twice — once via the region's
/// data path, once via the page-table walk), the region-side free
/// is skipped and `free_user_pml4_tree` reclaims it.
///
/// 4 K entries is sized generously for the working set of any
/// realistic user task (a 4 KiB-mapped 1 GiB region needs at most
/// ~256 PDs + 256 K PTs; the test suite never reaches that). The
/// registry uses a flat fixed-size atomic array so it can be
/// accessed without taking the buddy lock.
const PT_REGISTRY_LEN: usize = 4096;
static PT_REGISTRY: [core::sync::atomic::AtomicU64; PT_REGISTRY_LEN] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; PT_REGISTRY_LEN]
};
static PT_REGISTRY_HEAD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn __pagetable_register(phys: u64) {
    use core::sync::atomic::Ordering;
    let head = PT_REGISTRY_HEAD.fetch_add(1, Ordering::Relaxed) % PT_REGISTRY_LEN;
    PT_REGISTRY[head].store(phys, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn __pagetable_unregister(phys: u64) {
    use core::sync::atomic::Ordering;
    for slot in PT_REGISTRY.iter() {
        if slot.load(Ordering::Relaxed) == phys {
            slot.store(0, Ordering::Relaxed);
            return;
        }
    }
}

#[doc(hidden)]
pub fn __pagetable_is_registered(phys: u64) -> bool {
    use core::sync::atomic::Ordering;
    PT_REGISTRY
        .iter()
        .any(|s| s.load(Ordering::Relaxed) == phys)
}

/// Per-frame reference counting for the COW-fork path.
///
/// `clone_for_fork` shares the parent's frames with the child by
/// `inc_ref`-ing every frame and marking the PTEs read-only on
/// both sides. The first user-mode write to such a page faults;
/// the page-fault handler invokes `cow_split_on_write` which
/// allocates a fresh frame, memcpys the bytes, repoints the
/// faulting AS's PTE at the new frame, and `dec_ref`s the old
/// shared frame. When the count drops back to 1, the surviving
/// AS is the sole owner and subsequent writes don't fault.
///
/// Frames not registered here behave as if their refcount is 0:
/// `free_frame` returns them immediately, matching the
/// pre-existing single-owner semantics. The map is populated
/// only for frames that go through `inc_ref`.
pub mod cow {
    use alloc::collections::BTreeMap;
    use core::sync::atomic::{AtomicU32, Ordering};

    use narf_lib::sync::IrqSafeSpinLock;

    use crate::PhysAddr;

    static REFCOUNTS: IrqSafeSpinLock<Option<BTreeMap<u64, AtomicU32>>> =
        IrqSafeSpinLock::new(None);

    fn ensure() {
        let mut g = REFCOUNTS.lock();
        if g.is_none() {
            *g = Some(BTreeMap::new());
        }
    }

    /// Increment the refcount on `phys`. Returns the new count.
    /// First call (frame previously had count 0 / unregistered)
    /// inserts a count of 2 — the implicit "1" for the original
    /// owner plus the "1" for the new sharer. Subsequent
    /// `inc_ref`s add one each.
    pub fn inc_ref(phys: PhysAddr) -> u32 {
        ensure();
        let mut g = REFCOUNTS.lock();
        let map = g.as_mut().expect("refcounts initialised above");
        let key = phys.raw();
        let entry = map.entry(key).or_insert_with(|| AtomicU32::new(1));
        // Bump from N to N+1; "first share" promotes the implicit
        // owner from `1` (representing the original sole owner) to
        // `2` (original + new sharer).
        entry.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement the refcount on `phys`. Returns the new count
    /// (post-decrement). If `phys` was never `inc_ref`'d, returns
    /// 0 — `free_frame` then returns the frame to the bin
    /// directly, matching pre-COW semantics.
    pub fn dec_ref(phys: PhysAddr) -> u32 {
        let mut g = REFCOUNTS.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return 0,
        };
        let key = phys.raw();
        let entry = match map.get(&key) {
            Some(e) => e,
            None => return 0,
        };
        // We want the post-decrement value. If the count is
        // already 1, drop the entry entirely so an unregistered
        // frame's next `free_frame` doesn't have to look it up.
        let prev = entry.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            map.remove(&key);
            0
        } else {
            prev - 1
        }
    }

    /// Read-only peek at a frame's refcount. Returns 0 if the
    /// frame was never registered; otherwise the current count.
    pub fn count(phys: PhysAddr) -> u32 {
        let g = REFCOUNTS.lock();
        g.as_ref()
            .and_then(|m| m.get(&phys.raw()))
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Test hook — drop every recorded refcount. Tests that
    /// exercise inc/dec sequences should call this to start from
    /// a clean slate.
    #[doc(hidden)]
    pub fn __test_clear() {
        *REFCOUNTS.lock() = None;
    }
}

/// Snapshot of allocator usage. Dispatches through the installed
/// `FrameAlloc`. Returns a zeroed `FrameStats` if no allocator
/// has been installed yet (pre-init).
pub fn stats() -> FrameStats {
    current_alloc().map(|a| a.stats()).unwrap_or(FrameStats {
        total: 0,
        free: 0,
        reserved: 0,
    })
}

/// Buddy-backed implementation of `stats`.
fn buddy_stats() -> FrameStats {
    let g = ALLOC.lock();
    let free: usize = g.zones.iter().map(|z| z.free_frame_count()).sum();
    FrameStats {
        total: g.total_frames,
        free,
        reserved: g.reserved_frames,
    }
}

/// Per-node free-frame count. Returns 0 when `node` is out of range
/// or the allocator hasn't been initialised.
pub fn node_free(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }
    let g = ALLOC.lock();
    g.zones[node].free_frame_count()
}

/// True once `rebalance_to_topology` has run.
pub fn is_numa_aware() -> bool {
    ALLOC.lock().numa_aware
}

/// Diagnostic: walk every zone's free lists and confirm no frame
/// appears in more than one block. Returns `Ok(())` on success or
/// `Err((zone, frame_no, order_a, order_b))` describing the first
/// overlap found. Intended for smoke-test instrumentation, not hot
/// paths — O(N log N) per zone in total free-block count.
pub fn validate_no_overlap() -> Result<(), (usize, u64, u8, u8)> {
    let g = ALLOC.lock();
    for (i, zone) in g.zones.iter().enumerate() {
        if let Err((f, oa, ob)) = zone.validate_no_overlap() {
            return Err((i, f, oa, ob));
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Debug)]
pub struct FrameStats {
    pub total: usize,
    pub free: usize,
    pub reserved: usize,
}

// ── Weak-link hooks for NUMA topology lookup ────────────────────────
//
// narf-memory cannot depend on narf-acpi (would form a cycle —
// narf-acpi already uses narf_memory::PhysAddr). The kernel binary
// (narf-frame) provides `#[no_mangle]` definitions that call into
// narf-acpi; tests and other binaries that don't care about NUMA
// can provide stubs returning 0.

extern "Rust" {
    /// Look up the NUMA node a physical address belongs to. Returns
    /// `0` when topology is unknown or the address is outside any
    /// SRAT memory range.
    fn narf_phys_to_node(addr: u64) -> u32;
    /// Look up the NUMA node hosting a logical CPU. Returns `0`
    /// when topology is unknown.
    fn narf_cpu_to_node(cpu: u32) -> u32;
}

#[inline]
fn phys_to_node(addr: u64) -> usize {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_phys_to_node(addr) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

#[inline]
fn current_cpu_node() -> usize {
    let cpu = narf_lib::percpu::current_cpu() as u32;
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_cpu_to_node(cpu) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

// ── Pluggable FrameAlloc framework ─────────────────────────────────
//
// Wave-A of the pluggable-policy pass. Mirrors `power::install_governor`
// (`power/src/lib.rs::538`) shape-for-shape, with one principled
// deviation: the frame allocator lives *below* the heap on some
// boot paths (the bootstrap-bump arena is in `.bss`, but a future
// no-bootstrap-heap build would init frames before `Box`). The slot
// therefore stores a `&'static dyn FrameAlloc` rather than a
// `Box<dyn FrameAlloc>`. Installation is cap-gated on
// `Cap<MemAlloc, Grant>`.

/// A pluggable frame allocator. Owns the single-frame allocation
/// surface; multi-frame buddy ops (`alloc_pages_on`, `free_pages`)
/// stay on the concrete buddy and are not part of the trait.
pub trait FrameAlloc: Send + Sync {
    /// Stable identifier (e.g. `"buddy"`, `"bump"`).
    fn name(&self) -> &'static str;
    /// Allocate one 4 KiB frame, preferring `node`'s zone.
    fn alloc_frame_on(&self, node: usize) -> Result<PhysFrame, FrameAllocError>;
    /// Allocate one 4 KiB frame from any node.
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError>;
    /// Return a frame to the pool. Impls that don't support freeing
    /// (e.g. `BumpFrameAlloc`) may treat this as a no-op.
    fn free_frame(&self, frame: PhysFrame);
    /// Snapshot of allocator usage.
    fn stats(&self) -> FrameStats;
}

/// Cap-marker for `install_frame_alloc`. The runtime kind variant
/// is reserved at `CapKind::MemAlloc = 0x0200` (see Wave 0).
#[derive(Copy, Clone, Debug)]
pub struct MemAlloc;
impl CapType for MemAlloc {
    const KIND: CapKind = CapKind::MemAlloc;
}

/// The default, today's per-NUMA buddy allocator wrapped behind the
/// `FrameAlloc` seam. Zero-sized: the actual state lives in the
/// module-private `ALLOC` lock + per-zone `BuddyZone` arrays.
#[derive(Copy, Clone, Debug, Default)]
pub struct BuddyFrameAlloc;

impl FrameAlloc for BuddyFrameAlloc {
    fn name(&self) -> &'static str {
        "buddy"
    }
    fn alloc_frame_on(&self, node: usize) -> Result<PhysFrame, FrameAllocError> {
        buddy_alloc_frame_on(node)
    }
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError> {
        buddy_alloc_frame_anywhere()
    }
    fn free_frame(&self, frame: PhysFrame) {
        buddy_free_frame(frame);
    }
    fn stats(&self) -> FrameStats {
        buddy_stats()
    }
}

/// The shipped `FrameAlloc` default. Installed by
/// `install_frame_alloc_default` during `init_from_map`.
pub static BUDDY_FRAME_ALLOC: BuddyFrameAlloc = BuddyFrameAlloc;

/// Linear-cursor frame allocator over a pre-reserved region. Useful
/// for early-boot diagnostics and as the seam-exercising alternative
/// to `BuddyFrameAlloc`. `free_frame` is unsupported; the cursor
/// advances and never rewinds.
#[derive(Debug)]
pub struct BumpFrameAlloc {
    start: u64,
    end: u64,
    next: AtomicU64,
}

impl BumpFrameAlloc {
    /// Const-construct a bump allocator over `[start, end)`. The
    /// caller is responsible for ensuring the region is genuinely
    /// reserved (e.g. excluded from the buddy donation list) — this
    /// type performs no overlap check with the buddy zones.
    pub const fn new_const(start: PhysAddr, end: PhysAddr) -> Self {
        Self {
            start: start.raw(),
            end: end.raw(),
            next: AtomicU64::new(start.raw()),
        }
    }

    /// Total bytes managed by this bump (`end - start`).
    pub const fn capacity_bytes(&self) -> u64 {
        self.end - self.start
    }

    /// Reset the cursor to `start`. Test/diagnostic hook — there's
    /// no safe way to reset a bump allocator whose frames are still
    /// referenced, so callers must guarantee no live frames exist.
    #[doc(hidden)]
    pub fn __test_reset(&self) {
        self.next.store(self.start, Ordering::SeqCst);
    }
}

impl FrameAlloc for BumpFrameAlloc {
    fn name(&self) -> &'static str {
        "bump"
    }
    fn alloc_frame_on(&self, _node: usize) -> Result<PhysFrame, FrameAllocError> {
        self.alloc_frame_anywhere()
    }
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError> {
        // Bump cursor by PAGE_SIZE, fail when we'd cross `end`.
        let mut cur = self.next.load(Ordering::Acquire);
        loop {
            if cur >= self.end || self.end - cur < PAGE_SIZE {
                return Err(FrameAllocError::Exhausted);
            }
            let next = cur + PAGE_SIZE;
            match self
                .next
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(PhysFrame::new(PhysAddr::new(cur))),
                Err(observed) => cur = observed,
            }
        }
    }
    fn free_frame(&self, _frame: PhysFrame) {
        // Bump allocators don't free. No-op; explicit-failure callers
        // should use a typed wrapper that returns `NotSupported`.
    }
    fn stats(&self) -> FrameStats {
        let used = self.next.load(Ordering::Acquire).saturating_sub(self.start);
        let total = (self.end - self.start) / PAGE_SIZE;
        let used_frames = used / PAGE_SIZE;
        FrameStats {
            total: total as usize,
            free: (total - used_frames) as usize,
            reserved: 0,
        }
    }
}

// `&'static dyn FrameAlloc` is a fat pointer (data + vtable). An
// `AtomicPtr` can only hold one word; we therefore park the trait
// object behind an `IrqSafeSpinLock<Option<…>>`. The lock is taken
// for the entire duration of a dispatched call, which keeps the
// vtable load + the indirect call atomic with respect to a swap.
// The cost is one uncontended lock per frame alloc; on the hot
// alloc path this is the same cost the buddy was already paying
// for `ALLOC.lock()`.
static FRAME_ALLOC_SLOT: IrqSafeSpinLock<Option<&'static dyn FrameAlloc>> =
    IrqSafeSpinLock::new(None);

/// Install a `FrameAlloc` impl. Cap-gated on `Cap<MemAlloc, Grant>`.
/// The previous installed allocator is replaced; callers are
/// responsible for ensuring no frames allocated under the old impl
/// will be freed under the new one (the buddy and the bump don't
/// share a free-list).
pub fn install_frame_alloc(
    cap: &Cap<MemAlloc, Grant>,
    alloc: &'static dyn FrameAlloc,
) -> Result<(), FrameAllocError> {
    cap.check_live()?;
    *FRAME_ALLOC_SLOT.lock() = Some(alloc);
    Ok(())
}

/// Internal: install `BUDDY_FRAME_ALLOC` without a cap check. Called
/// once at the end of `init_from_map` to plant the default before
/// any allocation. There is no public uncap'd install.
fn install_frame_alloc_default() {
    let mut slot = FRAME_ALLOC_SLOT.lock();
    if slot.is_none() {
        *slot = Some(&BUDDY_FRAME_ALLOC);
    }
}

/// Snapshot the active `FrameAlloc`'s `name()`. Returns `"none"`
/// when no allocator has been installed yet (`init_from_map`
/// hasn't run).
pub fn current_frame_alloc_name() -> &'static str {
    FRAME_ALLOC_SLOT
        .lock()
        .as_ref()
        .map(|a| a.name())
        .unwrap_or("none")
}

/// Snapshot the currently-installed `FrameAlloc`. Returns `None`
/// pre-init.
#[inline]
fn current_alloc() -> Option<&'static dyn FrameAlloc> {
    *FRAME_ALLOC_SLOT.lock()
}

/// Dispatch helper: thread the installed allocator into `f` or
/// return `Uninitialised` if none is live.
#[inline]
fn with_installed<R, F>(f: F) -> Result<R, FrameAllocError>
where
    F: FnOnce(&'static dyn FrameAlloc) -> Result<R, FrameAllocError>,
{
    match current_alloc() {
        Some(a) => f(a),
        None => Err(FrameAllocError::Uninitialised),
    }
}
