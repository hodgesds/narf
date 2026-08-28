//! Physical frames + per-NUMA-node frame allocator.
//!
//! Wave-2 subset of `memory/` spec §3 with Wave-3 NUMA awareness:
//! per-node buddy allocators classified by SRAT memory-range attribution.
//!
//! Layout:
//! - One cache-line-aligned buddy-zone lock per NUMA node
//!   (`MAX_NUMA_NODES`). Boot inits flat (everything goes to zone 0);
//!   `rebalance_to_topology` redistributes the remaining frames once SRAT
//!   data is available.
//! - `alloc_frame()` consults the current CPU's NUMA node first
//!   (looked up via the weak-link `narf_cpu_to_node` hook), then falls back
//!   nearest-node-first. Order-0 traffic is batched through a bounded
//!   per-CPU/per-node cache after buddy metadata capacity is frozen.
//! - `alloc_frame_on(node)` is the explicit-node entry point.
//! - `free_frame(f)` uses `narf_phys_to_node` to return the frame
//!   to its rightful node bin.
//!
//! Cycle avoidance: this crate cannot depend on `narf-acpi`
//! (narf-acpi pulls in `narf_memory::PhysAddr`). The hooks below are
//! the standard weakly-linked surface — narf-frame provides
//! `#[no_mangle]` definitions calling into narf-acpi at boot.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
/// Number of buddy orders exposed by `/proc/buddyinfo` (orders 0..=10).
pub const BUDDY_ORDER_COUNT: usize = MAX_ORDER as usize + 1;

/// Linux-compatible per-node NUMA allocation event counters.
///
/// Values count base pages, not allocation calls.  `numa_foreign` is
/// attributed to the intended node; all other fields are attributed to
/// the node that supplied the page.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NumaNodeStats {
    pub numa_hit: u64,
    pub numa_miss: u64,
    pub numa_foreign: u64,
    pub interleave_hit: u64,
    pub local_node: u64,
    pub other_node: u64,
}

struct AtomicNumaNodeStats {
    numa_hit: AtomicU64,
    numa_miss: AtomicU64,
    numa_foreign: AtomicU64,
    interleave_hit: AtomicU64,
    local_node: AtomicU64,
    other_node: AtomicU64,
}

impl AtomicNumaNodeStats {
    const fn new() -> Self {
        Self {
            numa_hit: AtomicU64::new(0),
            numa_miss: AtomicU64::new(0),
            numa_foreign: AtomicU64::new(0),
            interleave_hit: AtomicU64::new(0),
            local_node: AtomicU64::new(0),
            other_node: AtomicU64::new(0),
        }
    }
}

static NUMA_STATS: [AtomicNumaNodeStats; MAX_NUMA_NODES] =
    [const { AtomicNumaNodeStats::new() }; MAX_NUMA_NODES];

/// Return a coherent-enough lock-free snapshot of one node's monotonic
/// allocation counters. Individual fields may advance during the read.
pub fn numa_node_stats(node: usize) -> NumaNodeStats {
    let Some(s) = NUMA_STATS.get(node) else {
        return NumaNodeStats::default();
    };
    NumaNodeStats {
        numa_hit: s.numa_hit.load(Ordering::Relaxed),
        numa_miss: s.numa_miss.load(Ordering::Relaxed),
        numa_foreign: s.numa_foreign.load(Ordering::Relaxed),
        interleave_hit: s.interleave_hit.load(Ordering::Relaxed),
        local_node: s.local_node.load(Ordering::Relaxed),
        other_node: s.other_node.load(Ordering::Relaxed),
    }
}

pub(crate) fn account_numa_allocation(preferred: usize, actual: usize, pages: u64) {
    let preferred = preferred.min(MAX_NUMA_NODES - 1);
    let actual = actual.min(MAX_NUMA_NODES - 1);
    if actual == preferred {
        NUMA_STATS[actual]
            .numa_hit
            .fetch_add(pages, Ordering::Relaxed);
    } else {
        NUMA_STATS[actual]
            .numa_miss
            .fetch_add(pages, Ordering::Relaxed);
        NUMA_STATS[preferred]
            .numa_foreign
            .fetch_add(pages, Ordering::Relaxed);
    }
    if actual == current_cpu_node().min(MAX_NUMA_NODES - 1) {
        NUMA_STATS[actual]
            .local_node
            .fetch_add(pages, Ordering::Relaxed);
    } else {
        NUMA_STATS[actual]
            .other_node
            .fetch_add(pages, Ordering::Relaxed);
    }
}

/// Record an interleave selection that was satisfied by its intended node.
pub(crate) fn account_interleave_hit(node: usize, pages: u64) {
    NUMA_STATS[node.min(MAX_NUMA_NODES - 1)]
        .interleave_hit
        .fetch_add(pages, Ordering::Relaxed);
}

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

/// Global frame-accounting metadata. Buddy free lists are deliberately kept
/// out of this object: each NUMA node has an independent cache-line-aligned
/// lock, so allocations on unrelated nodes do not serialize.
#[derive(Debug)]
pub struct FrameAllocator {
    /// Managed base pages per node, frozen when topology rebalance
    /// completes. Unlike the zone free counts this does not decrease on
    /// allocation, so it is suitable for sysfs MemTotal reporting.
    node_total_frames: [AtomicUsize; MAX_NUMA_NODES],
    initialised: AtomicBool,
    total_frames: AtomicUsize,
    reserved_frames: AtomicUsize,
    /// Set after `rebalance_to_topology` completes; alloc + free
    /// honour per-node zones from this point on. Pre-flag, every
    /// allocation comes out of zones[0].
    numa_aware: AtomicBool,
}

static ALLOC: FrameAllocator = FrameAllocator {
    node_total_frames: [const { AtomicUsize::new(0) }; MAX_NUMA_NODES],
    initialised: AtomicBool::new(false),
    total_frames: AtomicUsize::new(0),
    reserved_frames: AtomicUsize::new(0),
    numa_aware: AtomicBool::new(false),
};

#[repr(align(64))]
struct BuddyZoneLock(IrqSafeSpinLock<BuddyZone>);

impl BuddyZoneLock {
    const fn new() -> Self {
        Self(IrqSafeSpinLock::new(BuddyZone::new()))
    }
}

/// One independently locked buddy free-list per NUMA node. The alignment
/// prevents the lock words for adjacent nodes from sharing a cache line.
static ZONES: [BuddyZoneLock; MAX_NUMA_NODES] = [const { BuddyZoneLock::new() }; MAX_NUMA_NODES];
static REBALANCE_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

const FRAME_CACHE_CAPACITY: usize = 16;
const FRAME_CACHE_BATCH: usize = 8;
/// Maximum final-owner returns published during one cache/zone transaction.
/// The fixed bound keeps IRQ-masked work finite and permits stack-backed spill
/// storage: freeing memory must not allocate memory after ownership reaches 0.
const FRAME_RETURN_CHUNK: usize = 64;

#[derive(Copy, Clone)]
struct NodeFrameCache {
    frames: [u64; FRAME_CACHE_CAPACITY],
    len: usize,
}

impl NodeFrameCache {
    const fn new() -> Self {
        Self {
            frames: [0; FRAME_CACHE_CAPACITY],
            len: 0,
        }
    }
}

struct CpuFrameCache {
    nodes: [NodeFrameCache; MAX_NUMA_NODES],
}

impl CpuFrameCache {
    const fn new() -> Self {
        Self {
            nodes: [NodeFrameCache::new(); MAX_NUMA_NODES],
        }
    }
}

#[repr(align(64))]
struct CpuFrameCacheLock(IrqSafeSpinLock<CpuFrameCache>);

impl CpuFrameCacheLock {
    const fn new() -> Self {
        Self(IrqSafeSpinLock::new(CpuFrameCache::new()))
    }
}

static FRAME_CACHES: [CpuFrameCacheLock; narf_lib::percpu::MAX_CPUS] =
    [const { CpuFrameCacheLock::new() }; narf_lib::percpu::MAX_CPUS];
static FRAME_CACHE_FREE: [AtomicUsize; MAX_NUMA_NODES] =
    [const { AtomicUsize::new(0) }; MAX_NUMA_NODES];
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_REFILLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_SPILLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_BATCH_FREE_LOCKS: AtomicU64 = AtomicU64::new(0);
static FRAME_CACHE_ENABLED: AtomicBool = AtomicBool::new(false);

#[repr(align(64))]
struct FrameCacheDrain {
    lock: IrqSafeSpinLock<()>,
    bypass: AtomicBool,
}

impl FrameCacheDrain {
    const fn new() -> Self {
        Self {
            lock: IrqSafeSpinLock::new(()),
            bypass: AtomicBool::new(false),
        }
    }
}

static FRAME_CACHE_DRAIN: [FrameCacheDrain; MAX_NUMA_NODES] =
    [const { FrameCacheDrain::new() }; MAX_NUMA_NODES];
static FRAME_CACHE_HOTPLUG_BYPASS: [AtomicBool; MAX_NUMA_NODES] =
    [const { AtomicBool::new(false) }; MAX_NUMA_NODES];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct HotplugRange {
    start: u64,
    len: u64,
    node: usize,
    online: bool,
}

static HOTPLUG_RANGES: IrqSafeSpinLock<Vec<HotplugRange>> = IrqSafeSpinLock::new(Vec::new());
static BOOT_MEMORY_RANGES: IrqSafeSpinLock<Vec<(u64, u64)>> = IrqSafeSpinLock::new(Vec::new());
static ONLINE_NODE_MASK: AtomicU64 = AtomicU64::new(1);
static MEMORY_HOTPLUG_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install a post-commit observer for memory-block topology changes.
///
/// The callback runs after allocator and hotplug-registry locks are released,
/// so it may safely query [`memory_blocks`]. Installation is expected once
/// during sysfs initialisation.
pub fn install_memory_hotplug_hook(hook: fn()) {
    MEMORY_HOTPLUG_HOOK.store(hook as usize, Ordering::Release);
}

fn notify_memory_hotplug() {
    let raw = MEMORY_HOTPLUG_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `install_memory_hotplug_hook` stores a function pointer.
        let hook: fn() = unsafe { core::mem::transmute(raw) };
        hook();
    }
}

/// Linux-compatible logical memory-block size. Linux's generic default is
/// 128 MiB; keeping this fixed makes block ids stable across hotplug events.
pub const MEMORY_BLOCK_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemoryBlock {
    pub id: u64,
    pub start: u64,
    pub node: usize,
    pub online: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemoryHotplugError {
    Uninitialised,
    InvalidRange,
    InvalidNode,
    Overlap,
    MetadataCapacity,
    Busy,
    NotOnline,
}

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
    {
        let mut ranges = BOOT_MEMORY_RANGES.lock();
        ranges.clear();
        ranges.extend(usable.iter().filter_map(|region| {
            let start = region.start.raw() & !(PAGE_SIZE - 1);
            let end = region.start.raw().checked_add(region.len)?;
            (start < end).then_some((start, end - start))
        }));
    }
    let mut total = 0usize;
    let mut reserved = 0usize;
    let mut zone0 = ZONES[0].0.lock();
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
        donate_around_excludes(&mut zone0, region_start, region_end, exclude);
    }
    for count in &ALLOC.node_total_frames {
        count.store(0, Ordering::Relaxed);
    }
    ALLOC.node_total_frames[0].store(zone0.free_frame_count(), Ordering::Relaxed);
    ALLOC.total_frames.store(total, Ordering::Relaxed);
    ALLOC.reserved_frames.store(reserved, Ordering::Relaxed);
    ALLOC.numa_aware.store(false, Ordering::Relaxed);
    drop(zone0);
    // Opt the LIVE allocator's zones into frame-alloc-audit (no-op unless
    // the feature is set). Standalone unit-test `BuddyZone`s never call
    // this, so their synthetic frame numbers stay out of the global audit
    // bitmap (which would otherwise false-positive on their fabricated
    // 0x100-style frames).
    #[cfg(feature = "frame-alloc-audit")]
    for zone in &ZONES {
        zone.0.lock().enable_audit();
    }
    // Publish only after every free list and accounting field is complete.
    ALLOC.initialised.store(true, Ordering::Release);
    // Zone locks are released before installing the default `FrameAlloc` —
    // `install_frame_alloc_default` takes its own lock and we don't want to
    // risk an unrelated future reentrancy regression.
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
/// a Vec growth would route through slab → buddy → the same zone lock
/// (already held by the buddy) → recursive deadlock.
///
/// Call this once, AFTER `rebalance_to_topology` has populated
/// each zone, and BEFORE `crate::heap::promote_to_slab()` flips
/// the global allocator. While we're still on bump, the
/// reservation allocations themselves don't recurse.
pub fn reserve_for_slab_promotion() {
    // The reservation below runs one zone at a time and, on a large
    // machine, wants far more than the fixed 12 MiB `.bss` bootstrap
    // arena holds (~16 bytes/frame, so ~3 GiB was the hard ceiling —
    // an 8 GiB boot died right here). Buddy frames are already live, so
    // top the bootstrap arena up from the buddy FIRST, without holding
    // the lock, then reserve.
    let need: usize = ZONES
        .iter()
        .map(|zone| zone.0.lock().reservation_bytes())
        .sum();
    ensure_bootstrap_headroom(need);

    for zone in &ZONES {
        zone.0.lock().reserve_growth_capacity();
    }
    // Free-list Vecs can no longer grow recursively through the slab. This is
    // the safe publication point for order-0 caches even on UMA machines that
    // never publish `numa_aware`.
    FRAME_CACHE_ENABLED.store(true, Ordering::Release);
}

/// Make sure the bootstrap bump arena can satisfy `need` more bytes,
/// donating buddy-allocated RAM to it when the `.bss` array falls short.
///
/// Runs while the global allocator is still the bump arena (pre
/// `promote_to_slab`), so the donated frames' bookkeeping doesn't
/// recurse into the slab. Each donation is one buddy allocation of up
/// to `1 << MAX_ORDER` frames; a handful covers a very large machine.
fn ensure_bootstrap_headroom(need: usize) {
    // A margin over the bare reservation: `reserve_exact` strands the
    // free lists' pre-existing (doubling-grown) buffers, and boot has
    // other bump users still to come (per-CPU init, driver probe).
    let target = need.saturating_add(need / 4).saturating_add(1 << 20);
    let mut have = crate::heap::bootstrap_remaining();
    if have >= target {
        return;
    }

    const MAX_CHUNK_ORDER: u8 = MAX_ORDER; // 1 << 13 frames = 32 MiB
    let mut guard = 0;
    while have < target {
        let deficit = target - have;
        // Smallest order whose block covers the remaining deficit,
        // capped at the buddy's largest allocation.
        let want_frames = deficit.div_ceil(PAGE_SIZE as usize).max(1);
        let mut order = 0u8;
        while order < MAX_CHUNK_ORDER && (1usize << order) < want_frames {
            order += 1;
        }
        // `alloc_pages_on` already falls back across NUMA nodes when
        // node 0 can't satisfy the order.
        let Ok(base) = alloc_pages_on(0, order) else {
            // Can't grow the arena. The reservation may still fit what
            // we already have; if not, the existing OOM panic reports it
            // — no worse than before this path existed.
            return;
        };
        let bytes = (1usize << order) * PAGE_SIZE as usize;
        let vbase = base.start_address().kernel_mut_ptr::<u8>();
        // SAFETY: `base` is `1<<order` contiguous frames just handed out
        // by the buddy (so owned by us, mapped, writable), and `vbase` is
        // its identity or direct-map VA, valid for the kernel's lifetime.
        // The bump arena never frees, matching the donation's
        // leak-forever contract.
        let donated = unsafe { crate::heap::add_bootstrap_spill(vbase, bytes) };
        if !donated {
            // All spill slots full — we've donated as much as the arena
            // can track. Stop; the reservation uses whatever's available.
            return;
        }
        have += bytes;
        guard += 1;
        if guard > 64 {
            break; // defensive: never spin the donation loop
        }
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
pub(crate) const LOW_RESERVED_BYTES: u64 = 0x100000;

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
    let _transition = REBALANCE_LOCK.lock();
    debug_assert!(
        !FRAME_CACHE_ENABLED.load(Ordering::Acquire),
        "NUMA rebalance must precede frame-cache publication"
    );
    if ALLOC.numa_aware.load(Ordering::Acquire) || !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }
    // Move blocks from zones[0] to their proper node zones.
    // Always lock the lower node first. Rebalance is a boot-time,
    // pre-SMP transition; publishing `numa_aware` after every move makes
    // the completed topology visible atomically to later hot paths.
    for (target, target_zone) in ZONES.iter().enumerate().skip(1) {
        let mut src = ZONES[0].0.lock();
        let mut dst = target_zone.0.lock();
        src.drain_into(&mut dst, |frame_no| {
            let phys = frame_no << PAGE_SHIFT;
            phys_to_node(phys) == target
        });
    }
    for (node, zone) in ZONES.iter().enumerate() {
        let total = zone.0.lock().free_frame_count();
        ALLOC.node_total_frames[node].store(total, Ordering::Relaxed);
    }
    let mut online = 0u64;
    for node in 0..MAX_NUMA_NODES {
        if ALLOC.node_total_frames[node].load(Ordering::Relaxed) != 0 {
            online |= 1u64 << node;
        }
    }
    ONLINE_NODE_MASK.store(online.max(1), Ordering::Release);
    ALLOC.numa_aware.store(true, Ordering::Release);
}

/// Dynamically add a real, kernel-addressable RAM range to one NUMA node.
///
/// # Safety
/// The caller must prove the range is RAM, is mapped in the kernel direct
/// map, and does not overlap boot RAM, MMIO, or any previously managed range.
pub unsafe fn online_memory_range(
    start: PhysAddr,
    len: u64,
    node: usize,
) -> Result<(), MemoryHotplugError> {
    if node >= MAX_NUMA_NODES {
        return Err(MemoryHotplugError::InvalidNode);
    }
    if len == 0
        || start.raw() & (PAGE_SIZE - 1) != 0
        || len & (PAGE_SIZE - 1) != 0
        || start.raw().checked_add(len).is_none()
    {
        return Err(MemoryHotplugError::InvalidRange);
    }
    let mut ranges = HOTPLUG_RANGES.lock();
    let end = start.raw() + len;
    let existing = ranges
        .iter()
        .position(|range| range.start < end && start.raw() < range.start + range.len);
    let reused = if let Some(index) = existing {
        let range = ranges[index];
        if range.start != start.raw() || range.len != len || range.node != node || range.online {
            return Err(MemoryHotplugError::Overlap);
        }
        ranges[index].online = true;
        true
    } else {
        ranges.push(HotplugRange {
            start: start.raw(),
            len,
            node,
            online: true,
        });
        false
    };
    // Runtime ranges must remain wholly visible to `remove_free_range`.
    // Disable page caching on this node before the new frames are donated;
    // an in-flight cache operation that began earlier can only see pre-existing
    // boot frames because the range is not in the buddy yet.
    FRAME_CACHE_HOTPLUG_BYPASS[node].store(true, Ordering::Release);
    synchronize_frame_cache_bypass();

    let first_frame = start.raw() >> PAGE_SHIFT;
    let frame_count = len >> PAGE_SHIFT;
    if !ALLOC.initialised.load(Ordering::Acquire) {
        if reused {
            if let Some(range) = ranges
                .iter_mut()
                .find(|range| range.start == start.raw() && range.len == len)
            {
                range.online = false;
            }
        } else {
            ranges.pop();
        }
        let still_online = ranges
            .iter()
            .any(|range| range.node == node && range.online);
        FRAME_CACHE_HOTPLUG_BYPASS[node].store(still_online, Ordering::Release);
        return Err(MemoryHotplugError::Uninitialised);
    }
    let mut zone = ZONES[node].0.lock();
    if !zone.can_donate_without_growth(first_frame, frame_count) {
        if reused {
            if let Some(range) = ranges
                .iter_mut()
                .find(|range| range.start == start.raw() && range.len == len)
            {
                range.online = false;
            }
        } else {
            ranges.pop();
        }
        let still_online = ranges
            .iter()
            .any(|range| range.node == node && range.online);
        FRAME_CACHE_HOTPLUG_BYPASS[node].store(still_online, Ordering::Release);
        return Err(MemoryHotplugError::MetadataCapacity);
    }
    zone.donate(first_frame, frame_count);
    ALLOC.node_total_frames[node].fetch_add(frame_count as usize, Ordering::Relaxed);
    ALLOC
        .total_frames
        .fetch_add(frame_count as usize, Ordering::Relaxed);
    ONLINE_NODE_MASK.fetch_or(1u64 << node, Ordering::AcqRel);
    drop(zone);
    drop(ranges);
    notify_memory_hotplug();
    Ok(())
}

/// Remove an exact hotplug range after proving every frame is free.
///
/// A busy range is left online and returns [`MemoryHotplugError::Busy`].
pub fn offline_memory_range(start: PhysAddr, len: u64) -> Result<usize, MemoryHotplugError> {
    if len == 0 || start.raw() & (PAGE_SIZE - 1) != 0 || len & (PAGE_SIZE - 1) != 0 {
        return Err(MemoryHotplugError::InvalidRange);
    }
    let mut ranges = HOTPLUG_RANGES.lock();
    let Some(index) = ranges
        .iter()
        .position(|range| range.start == start.raw() && range.len == len && range.online)
    else {
        return Err(MemoryHotplugError::NotOnline);
    };
    let range = ranges[index];
    let first_frame = start.raw() >> PAGE_SHIFT;
    let frame_count = len >> PAGE_SHIFT;
    let mut zone = ZONES[range.node].0.lock();
    if !zone.remove_free_range(first_frame, frame_count) {
        return Err(MemoryHotplugError::Busy);
    }
    let remaining = ALLOC.node_total_frames[range.node]
        .fetch_sub(frame_count as usize, Ordering::Relaxed)
        - frame_count as usize;
    ALLOC
        .total_frames
        .fetch_sub(frame_count as usize, Ordering::Relaxed);
    ranges[index].online = false;
    let still_online = ranges
        .iter()
        .any(|candidate| candidate.node == range.node && candidate.online);
    FRAME_CACHE_HOTPLUG_BYPASS[range.node].store(still_online, Ordering::Release);
    if remaining == 0 {
        ONLINE_NODE_MASK.fetch_and(!(1u64 << range.node), Ordering::AcqRel);
    }
    drop(zone);
    drop(ranges);
    notify_memory_hotplug();
    Ok(range.node)
}

pub fn online_node_mask() -> u64 {
    ONLINE_NODE_MASK.load(Ordering::Acquire)
}

pub fn online_node_count() -> u32 {
    let mask = online_node_mask();
    if mask == 0 {
        1
    } else {
        64 - mask.leading_zeros()
    }
}

/// Allocate one 4 KiB frame. NUMA-aware: prefers the current CPU's
/// node, falls back round-robin to other nodes when the local bin
/// is empty. Dispatches through the installed `FrameAlloc`.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn alloc_frame() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    let preferred = current_cpu_node();
    alloc_frame_on_inner(preferred)
}

/// Whether an allocation is servicing the kernel or a userspace mapping.
///
/// The `min` watermark is a reserve the kernel must always be able to draw on:
/// a `Kernel` allocation may take the pool down into it so kernel/atomic work
/// (page tables, slab, fork/teardown metadata) never fails under memory
/// pressure. A `User` allocation (demand fault, COW, stack growth, brk,
/// mmap-populate, page migration) is refused — surfacing as `-ENOMEM` to
/// userspace — once granting it would breach the reserve, so userspace cannot
/// starve the kernel. This is NARF's analogue of Linux's `ALLOC_WMARK_MIN`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AllocContext {
    /// Kernel/atomic allocation — may consume the `min` reserve.
    Kernel,
    /// Userspace-backing allocation — must leave the `min` reserve intact.
    User,
    /// Userspace-backing allocation that MUST succeed to keep a running
    /// process correct, and so may consume the `min` reserve like `Kernel`
    /// while staying `Movable` like `User`. The sole user is a copy-on-write
    /// break (`cow_split_on_write`): the faulting task already owns the shared
    /// page and is performing a legitimate write; refusing the private-copy
    /// frame at the watermark would deliver a spurious SIGSEGV on writable
    /// memory. Linux likewise lets a CoW break dip into reserves rather than
    /// fail the fault. Not a general escape hatch — ordinary demand/mmap/brk
    /// faults stay `User` so userspace still cannot drain the reserve.
    UserReserve,
}

impl AllocContext {
    /// Mobility class for anti-fragmentation grouping. Kernel allocations
    /// are UNMOVABLE (page tables, slab, DMA hold raw physical pointers);
    /// user-backing allocations are MOVABLE (the pages that WOULD be
    /// migratable and that free back in bulk on process teardown). See the
    /// migratetype design note in `buddy.rs`.
    #[inline]
    pub fn migrate_type(self) -> buddy::MigrateType {
        match self {
            AllocContext::Kernel => buddy::MigrateType::Unmovable,
            AllocContext::User | AllocContext::UserReserve => buddy::MigrateType::Movable,
        }
    }
}

/// Central reserve gate. Returns `Exhausted` (and wakes the reclaimer) when a
/// `User` allocation would breach the `min` watermark reserve; `Kernel` and
/// `UserReserve` allocations always pass (the latter is a CoW break that must
/// not fault a writable page — see [`AllocContext::UserReserve`]). Enforced
/// once, here, so every allocation entry inherits the same policy — an ordinary
/// user path cannot silently drain the reserve.
#[inline]
fn reserve_permits(ctx: AllocContext) -> Result<(), FrameAllocError> {
    let node = current_cpu_node();
    // Start background balancing at the low watermark for both kernel and user
    // allocations rather than waiting for either to collide with the protected
    // minimum. Kernel allocations may consume the reserve but must still wake
    // the task-context reclaimer proactively.
    if crate::reclaim::under_low_watermark_node(node) {
        crate::reclaim::wake_kswapd(node);
    }
    if ctx == AllocContext::User {
        if !crate::reclaim::user_alloc_would_breach_reserve() {
            return Ok(());
        }
        // Wake the local node's reclaimer so it can shed clean cache and let
        // the retry succeed. Under an overcommit policy that permits it
        // (Heuristic / Always), also arm the OOM killer so sustained user
        // pressure reclaims a hog rather than only failing the faulting task.
        // Under `Never` (the default) this stays a graceful ENOMEM — no
        // process is killed.
        if crate::reclaim::user_pressure_arms_oom() {
            crate::reclaim::request_reclaim_with_oom(node, 1);
        } else {
            crate::reclaim::request_reclaim(node, 1);
        }
        return Err(FrameAllocError::Exhausted);
    }
    Ok(())
}

/// Allocate one CPU-local frame for a userspace mapping, honouring the `min`
/// watermark reserve. Mirrors [`alloc_frame`] but with `User` context.
pub fn alloc_user_frame() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(current_cpu_node(), AllocContext::User)
}

/// Allocate one CPU-local `Movable` frame for a copy-on-write break, permitted
/// to dip into the `min` reserve. See [`AllocContext::UserReserve`]: a CoW split
/// is a legitimate write to a page the process already owns, so it must not be
/// refused at the watermark and turned into a spurious SIGSEGV. Only
/// `cow_split_on_write` uses this; every other user-backing fault stays on the
/// reserve-respecting [`alloc_user_frame`].
pub fn alloc_user_frame_urgent() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(current_cpu_node(), AllocContext::UserReserve)
}

/// Reserve-respecting `User`-context variant of [`alloc_frame_on`].
pub fn alloc_frame_on_ctx(node: usize, ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(node, ctx)
}

/// Reserve-respecting variant of [`alloc_frame_anywhere`].
pub fn alloc_frame_anywhere_ctx(ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    reserve_permits(ctx)?;
    alloc_frame_anywhere()
}

/// `User`-context strict per-node allocation for a bound mempolicy.
pub fn alloc_user_frame_on_strict(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_for_ctx(node, node, AllocContext::User)
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

#[inline]
fn frame_cache_bypassed(node: usize) -> bool {
    FRAME_CACHE_DRAIN[node].bypass.load(Ordering::Acquire)
        || FRAME_CACHE_HOTPLUG_BYPASS[node].load(Ordering::Acquire)
}

/// Order-0 allocator front-end. Once buddy metadata capacity is stable, each
/// CPU keeps a small cache per node and refills it under one zone-lock
/// acquisition. The per-CPU lock also masks local IRQs, preventing same-CPU
/// re-entry from duplicating a frame.
fn alloc_order0_on(node: usize) -> Option<PhysFrame> {
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return alloc_below_ceiling(&mut ZONES[node].0.lock());
    }

    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    // A drain may have begun between the optimistic check and taking this
    // CPU's lock. Bypass under that transition so the drainer cannot miss a
    // newly cached frame.
    if frame_cache_bypassed(node) {
        drop(cache);
        return alloc_below_ceiling(&mut ZONES[node].0.lock());
    }
    let local = &mut cache.nodes[node];
    if local.len != 0 {
        local.len -= 1;
        let frame = local.frames[local.len];
        FRAME_CACHE_FREE[node].fetch_sub(1, Ordering::Relaxed);
        #[cfg(feature = "kernel-test")]
        FRAME_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        buddy::audit_cached_alloc(frame);
        return Some(buddy::frame_from_no(frame));
    }

    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    let mut zone = ZONES[node].0.lock();
    let first = alloc_below_ceiling(&mut zone)?;
    for _ in 1..FRAME_CACHE_BATCH {
        let Some(extra) = alloc_below_ceiling(&mut zone) else {
            break;
        };
        let frame = buddy::frame_no(extra);
        buddy::audit_cached_free(frame);
        local.frames[local.len] = frame;
        local.len += 1;
        FRAME_CACHE_FREE[node].fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_REFILLS.fetch_add(1, Ordering::Relaxed);
    Some(first)
}

/// Cache an order-0 free. Returns `false` when caching is disabled or a
/// coordinated drain is active; the caller then returns the frame directly to
/// the node buddy.
fn free_order0_to_cache(node: usize, frame: u64) -> bool {
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return false;
    }
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    if frame_cache_bypassed(node) {
        return false;
    }
    let local = &mut cache.nodes[node];
    buddy::audit_cached_free(frame);
    if local.len == FRAME_CACHE_CAPACITY {
        let mut zone = ZONES[node].0.lock();
        for _ in 0..FRAME_CACHE_BATCH {
            local.len -= 1;
            zone.free_cached(local.frames[local.len], 0);
        }
        FRAME_CACHE_FREE[node].fetch_sub(FRAME_CACHE_BATCH, Ordering::Relaxed);
        #[cfg(feature = "kernel-test")]
        FRAME_CACHE_SPILLS.fetch_add(1, Ordering::Relaxed);
    }
    local.frames[local.len] = frame;
    local.len += 1;
    FRAME_CACHE_FREE[node].fetch_add(1, Ordering::Relaxed);
    true
}

/// Publish a bounded set of final-owner order-0 frames for one NUMA node.
///
/// No allocation is permitted here: callers have already removed the final
/// ownership reference, so allocator progress must not depend on obtaining a
/// fresh frame. Cached spills remain covered by the cache lock until they are
/// installed in the buddy zone. That cache -> zone lock coupling is required
/// so a concurrent drain/hot-remove transaction cannot observe the frames in
/// neither location.
fn free_order0_chunk_to_zone(node: usize, frames: &[u64]) {
    debug_assert!(frames.len() <= FRAME_RETURN_CHUNK);
    if frames.is_empty() {
        return;
    }
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        let mut zone = ZONES[node].0.lock();
        for &frame in frames {
            zone.free(frame, 0);
        }
        return;
    }

    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_BATCH_FREE_LOCKS.fetch_add(1, Ordering::Relaxed);
    // A coordinated drain may have published bypass after the optimistic
    // check. Match the scalar path by publishing directly to the zone.
    if frame_cache_bypassed(node) {
        drop(cache);
        let mut zone = ZONES[node].0.lock();
        for &frame in frames {
            zone.free(frame, 0);
        }
        return;
    }

    let local = &mut cache.nodes[node];
    let mut spills = [0u64; FRAME_RETURN_CHUNK];
    let mut spill_len = 0usize;
    for &frame in frames {
        buddy::audit_cached_free(frame);
        if local.len == FRAME_CACHE_CAPACITY {
            debug_assert!(spill_len + FRAME_CACHE_BATCH <= spills.len());
            for _ in 0..FRAME_CACHE_BATCH {
                local.len -= 1;
                spills[spill_len] = local.frames[local.len];
                spill_len += 1;
            }
            FRAME_CACHE_FREE[node].fetch_sub(FRAME_CACHE_BATCH, Ordering::Relaxed);
            #[cfg(feature = "kernel-test")]
            FRAME_CACHE_SPILLS.fetch_add(1, Ordering::Relaxed);
        }
        local.frames[local.len] = frame;
        local.len += 1;
        FRAME_CACHE_FREE[node].fetch_add(1, Ordering::Relaxed);
    }

    if spill_len != 0 {
        // Keep `cache` held until every removed cached frame is visible in the
        // zone. See the drain/hot-remove exclusion argument above.
        let mut zone = ZONES[node].0.lock();
        for &frame in &spills[..spill_len] {
            zone.free_cached(frame, 0);
        }
    }
}

/// Drain every CPU's cache for one node and run `f` while new cache entries
/// are bypassed. Lock order is drain -> per-CPU cache -> zone; ordinary paths
/// take at most one per-CPU cache before the zone and never take a drain lock.
fn with_node_frame_caches_drained<R>(node: usize, f: impl FnOnce(&mut BuddyZone) -> R) -> R {
    let node = node.min(MAX_NUMA_NODES - 1);
    let drain = &FRAME_CACHE_DRAIN[node];
    let _drain_guard = drain.lock.lock();
    drain.bypass.store(true, Ordering::Release);
    for cpu_cache in &FRAME_CACHES {
        let mut cache = cpu_cache.0.lock();
        let local = &mut cache.nodes[node];
        if local.len == 0 {
            continue;
        }
        let mut zone = ZONES[node].0.lock();
        let drained = local.len;
        while local.len != 0 {
            local.len -= 1;
            zone.free_cached(local.frames[local.len], 0);
        }
        FRAME_CACHE_FREE[node].fetch_sub(drained, Ordering::Relaxed);
    }
    let result = f(&mut ZONES[node].0.lock());
    drain.bypass.store(false, Ordering::Release);
    result
}

/// Drain every CPU's cache for `node` into the zone and run `f` with the
/// per-CPU cache BYPASSED — but WITHOUT holding the zone lock across `f`, so `f`
/// may itself allocate / free / reserve frames (which take the zone lock).
///
/// This is what memory compaction needs: draining makes every currently-free
/// frame visible in the zone free lists (so `reserve_frame_range` can hold it),
/// and the bypass routes `f`'s own allocs/frees straight to the zone (so a
/// just-migrated frame is immediately reservable and a destination allocation
/// never comes from the cache). The node's allocations run cache-cold for the
/// duration; keep `f` bounded.
pub fn with_node_cache_bypassed<R>(node: usize, f: impl FnOnce() -> R) -> R {
    let node = node.min(MAX_NUMA_NODES - 1);
    let drain = &FRAME_CACHE_DRAIN[node];
    let _drain_guard = drain.lock.lock();
    drain.bypass.store(true, Ordering::Release);
    for cpu_cache in &FRAME_CACHES {
        let mut cache = cpu_cache.0.lock();
        let local = &mut cache.nodes[node];
        if local.len == 0 {
            continue;
        }
        let mut zone = ZONES[node].0.lock();
        let drained = local.len;
        while local.len != 0 {
            local.len -= 1;
            zone.free_cached(local.frames[local.len], 0);
        }
        FRAME_CACHE_FREE[node].fetch_sub(drained, Ordering::Relaxed);
    }
    // The zone lock is released here; `f` takes it per operation as needed.
    let result = f();
    drain.bypass.store(false, Ordering::Release);
    result
}

/// Wait for every cache operation that may have observed the old bypass value.
/// The caller publishes a persistent bypass first, then calls this before
/// making newly hot-plugged frames visible in the buddy.
fn synchronize_frame_cache_bypass() {
    for cpu_cache in &FRAME_CACHES {
        drop(cpu_cache.0.lock());
    }
}

/// Allocate one 4 KiB frame, preferring `node`'s zone. Dispatches
/// through the installed `FrameAlloc` impl — see `install_frame_alloc`.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner(node)
}

/// Allocate one frame from `node`'s zone ONLY — no cross-node
/// fallback. Returns `Exhausted` if `node` has no free frame.
/// Used by `MPOL_BIND` enforcement, which must never spill outside
/// the bound nodemask. Still applies the cgroup charge.
pub fn alloc_frame_on_strict(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_for(node, node)
}

/// Strict allocation from `node` while attributing hit/miss against
/// `preferred`. Mempolicy uses this when a hard allowed mask requires
/// explicit fallback attempts.
pub(crate) fn alloc_frame_on_strict_for(
    node: usize,
    preferred: usize,
) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_for_ctx(node, preferred, AllocContext::Kernel)
}

/// Reserve-aware core of the strict per-node path. `User` allocations are
/// refused once they would breach the `min` watermark reserve.
pub(crate) fn alloc_frame_on_strict_for_ctx(
    node: usize,
    preferred: usize,
    ctx: AllocContext,
) -> Result<PhysFrame, FrameAllocError> {
    reserve_permits(ctx)?;
    #[cfg(feature = "cgroup")]
    if !crate::cgroup_charge::try_charge(PAGE_SIZE) {
        return Err(FrameAllocError::Exhausted);
    }
    let r = buddy_alloc_frame_on_strict(node, preferred);
    #[cfg(feature = "cgroup")]
    if r.is_err() {
        crate::cgroup_charge::uncharge(PAGE_SIZE);
    }
    if r.is_err() {
        // A strict-node miss may be local fragmentation rather than global
        // exhaustion, so request a background pass without arming OOM.
        crate::reclaim::request_reclaim(node.min(MAX_NUMA_NODES - 1), 1);
    }
    r
}

/// Strict per-node buddy allocation: only `node`'s zone is consulted.
fn buddy_alloc_frame_on_strict(
    node: usize,
    preferred: usize,
) -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let zone = if ALLOC.numa_aware.load(Ordering::Acquire) {
        node.min(MAX_NUMA_NODES - 1)
    } else if node == 0 {
        0
    } else {
        return Err(FrameAllocError::Exhausted);
    };
    let frame = alloc_order0_on(zone).ok_or(FrameAllocError::Exhausted)?;
    account_numa_allocation(preferred, zone, 1);
    Ok(frame)
}

/// Core of `alloc_frame` / `alloc_frame_on` — does the cgroup charge +
/// buddy dispatch. Kept separate (and NOT `#[track_caller]`) so the two
/// public entry points each capture their OWN caller's source location
/// for the `frame-alloc-audit` alloc-site map, instead of one shadowing
/// the other.
fn alloc_frame_on_inner(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_inner_ctx(node, AllocContext::Kernel)
}

/// Reserve-aware core of `alloc_frame` / `alloc_frame_on`. `User` allocations
/// are refused (and the reclaimer woken) once they would breach the `min`
/// watermark reserve; `Kernel` allocations may consume it.
fn alloc_frame_on_inner_ctx(node: usize, ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    reserve_permits(ctx)?;
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
    if r.is_err() {
        if ctx == AllocContext::Kernel {
            // A KERNEL allocation could not be satisfied even into the `min`
            // reserve — genuine, unrecoverable exhaustion (a `User` alloc would
            // have been refused earlier by `reserve_permits`, keeping this reserve
            // intact). Arm the reclaimer's OOM killer. This does NOT fire on the
            // transient below-`min` dips a fork/vmalloc storm produces, only when
            // a kernel request actually fails — so a workload the reserve +
            // vmalloc already carry is never needlessly OOM-killed.
            let reclaim_node = node.min(MAX_NUMA_NODES - 1);
            crate::reclaim::request_reclaim_with_oom(reclaim_node, 1);
        } else {
            // The reserve check passed but the selected buddy/cpuset could not
            // satisfy the allocation (for example fragmentation or strict-node
            // pressure). Give kswapd an opportunity to make progress before a
            // later user fault retries.
            crate::reclaim::request_reclaim(node.min(MAX_NUMA_NODES - 1), 1);
        }
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
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }

    if !ALLOC.numa_aware.load(Ordering::Acquire) {
        // Pre-rebalance: everything's in zones[0].
        let frame = alloc_order0_on(0).ok_or(FrameAllocError::Exhausted)?;
        account_numa_allocation(node, 0, 1);
        return Ok(frame);
    }

    let preferred = node.min(MAX_NUMA_NODES - 1);
    if let Some(f) = alloc_order0_on(preferred) {
        account_numa_allocation(preferred, preferred, 1);
        return Ok(f);
    }

    // Fallback: try the remaining nodes nearest-first by NUMA distance
    // (Linux's local-then-nearest policy) instead of a blind
    // round-robin. On a single node (or no-topology stub) the order is
    // still all other zones, just deterministically index-ordered.
    let mut order = [0usize; MAX_NUMA_NODES];
    let n = fallback_order(preferred, &mut order);
    for &i in &order[..n] {
        if let Some(f) = alloc_order0_on(i) {
            account_numa_allocation(preferred, i, 1);
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Buddy-backed implementation of `alloc_frame_anywhere`.
fn buddy_alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let preferred = current_cpu_node().min(MAX_NUMA_NODES - 1);
    for node in 0..MAX_NUMA_NODES {
        if let Some(f) = alloc_order0_on(node) {
            account_numa_allocation(preferred, node, 1);
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate a contiguous block of `1 << order` frames. `order=0`
/// is one frame (same as `alloc_frame_on`); `order=10` is 4 MiB.
/// Phase-1 buddy allocator entry point.
pub fn alloc_pages_on(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError> {
    // Default higher-order allocations to the kernel/UNMOVABLE class.
    alloc_pages_on_ctx(node, order, AllocContext::Kernel)
}

/// Allocate a contiguous `1 << order` block, classified for
/// anti-fragmentation grouping by `ctx` (Kernel → UNMOVABLE, User →
/// MOVABLE). The multi-frame buddy path files the block — and any
/// split-off buddies — into the matching migratetype partition so
/// unmovable and movable contiguous regions don't fragment each other.
pub fn alloc_pages_on_ctx(
    node: usize,
    order: u8,
    ctx: AllocContext,
) -> Result<PhysFrame, FrameAllocError> {
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
    let r = alloc_pages_on_inner(node, order, ctx.migrate_type());
    // Direct compaction: a higher-order allocation that ran out of contiguous
    // blocks may succeed after migrating movable pages together. Compact this
    // node once and retry before giving up.
    let r = retry_after_direct_compaction(r, node, order, ctx.migrate_type());
    #[cfg(feature = "cgroup")]
    if r.is_err() {
        crate::cgroup_charge::uncharge(charge_bytes);
    }
    r
}

/// If a higher-order allocation failed, run synchronous direct compaction on
/// `node` and retry the allocation once. x86_64 only — migration needs the rmap
/// and accessed-bit machinery that aarch64 lacks; other arches pass the result
/// through unchanged.
#[cfg(target_arch = "x86_64")]
fn retry_after_direct_compaction(
    r: Result<PhysFrame, FrameAllocError>,
    node: usize,
    order: u8,
    mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    if r.is_err()
        && order > 0
        && crate::migrate::direct_compact(node.min(MAX_NUMA_NODES - 1), order as usize) > 0
    {
        return alloc_pages_on_inner(node, order, mt);
    }
    r
}

#[cfg(not(target_arch = "x86_64"))]
fn retry_after_direct_compaction(
    r: Result<PhysFrame, FrameAllocError>,
    _node: usize,
    _order: u8,
    _mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    r
}

fn alloc_pages_on_inner(
    node: usize,
    order: u8,
    mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let preferred = node.min(MAX_NUMA_NODES - 1);
    let numa_aware = ALLOC.numa_aware.load(Ordering::Acquire);
    let zone_idx = if numa_aware { preferred } else { 0 };
    if order == 0 {
        if let Some(frame) = alloc_order0_on(zone_idx) {
            account_numa_allocation(preferred, zone_idx, 1);
            return Ok(frame);
        }
        if !numa_aware {
            return Err(FrameAllocError::Exhausted);
        }
        let mut fallback_nodes = [0usize; MAX_NUMA_NODES];
        let n = fallback_order(preferred, &mut fallback_nodes);
        for &i in &fallback_nodes[..n] {
            if let Some(frame) = alloc_order0_on(i) {
                account_numa_allocation(preferred, i, 1);
                return Ok(frame);
            }
        }
        return Err(FrameAllocError::Exhausted);
    }
    let ceil = buddy::early_ceiling_frame();
    let try_alloc = |z: &mut BuddyZone| -> Option<u64> {
        if ceil == u64::MAX {
            z.alloc_mt(order, mt)
        } else {
            z.alloc_below_mt(order, ceil, mt)
        }
    };
    let first_try = {
        let mut zone = ZONES[zone_idx].0.lock();
        try_alloc(&mut zone)
    };
    if let Some(no) =
        first_try.or_else(|| with_node_frame_caches_drained(zone_idx, |zone| try_alloc(zone)))
    {
        account_numa_allocation(preferred, zone_idx, 1u64 << order);
        return Ok(buddy::frame_from_no(no));
    }
    if !numa_aware {
        return Err(FrameAllocError::Exhausted);
    }
    // Nearest-first cross-node fallback (see buddy_alloc_frame_on).
    let mut fallback_nodes = [0usize; MAX_NUMA_NODES];
    let n = fallback_order(preferred, &mut fallback_nodes);
    for &i in &fallback_nodes[..n] {
        let first_try = {
            let mut zone = ZONES[i].0.lock();
            try_alloc(&mut zone)
        };
        if let Some(no) =
            first_try.or_else(|| with_node_frame_caches_drained(i, |zone| try_alloc(zone)))
        {
            account_numa_allocation(preferred, i, 1u64 << order);
            return Ok(buddy::frame_from_no(no));
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Free a contiguous block of `1 << order` frames previously returned
/// from `alloc_pages_on` (the kernel/UNMOVABLE default).
pub fn free_pages(frame: PhysFrame, order: u8) {
    free_pages_ctx(frame, order, AllocContext::Kernel);
}

/// Free a contiguous block classified by `ctx`, so the block returns to
/// the migratetype partition it was allocated from. A block allocated via
/// [`alloc_pages_on_ctx`] MUST be freed with the matching `ctx`: NARF has
/// no per-frame migratetype record (no pageblock bitmap yet), so the
/// caller supplies the mobility, and a mismatch would misfile the block
/// into the wrong partition (harmless for correctness — the free lists
/// only group, they don't gate reuse — but it would blur the grouping).
pub fn free_pages_ctx(frame: PhysFrame, order: u8, ctx: AllocContext) {
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
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }
    let zone_idx = if ALLOC.numa_aware.load(Ordering::Acquire) {
        node
    } else {
        0
    };
    let frame_no = buddy::frame_no(frame);
    if order == 0 && free_order0_to_cache(zone_idx, frame_no) {
        return;
    }
    ZONES[zone_idx]
        .0
        .lock()
        .free_mt(frame_no, order, ctx.migrate_type());
}

/// Return a previously-allocated frame to the pool. Dispatches
/// through the installed `FrameAlloc`. The default buddy impl
/// routes the frame to its NUMA node's zone; alternative impls
/// (e.g. `BumpFrameAlloc`) may treat this as a no-op or return
/// `NotSupported` via their `try_*` variant.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_frame(f: PhysFrame) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(a) = current_alloc() {
        a.free_frame(f);
    }
}

/// Reserve a fully-free physical frame range: pull it out of the buddy free
/// lists so a later allocation can't hand it out. Returns `false` WITHOUT
/// mutation if any frame in the range is already allocated. The range must lie
/// within a single NUMA node's zone (a buddy block always does).
///
/// Memory compaction uses this to hold migration destinations OUTSIDE the block
/// it is evacuating (and to re-hold each just-migrated frame), so migration
/// never lands a page back in the block being freed. Balance with
/// [`free_movable_range`].
pub fn reserve_frame_range(base: PhysAddr, count: u64) -> bool {
    if count == 0 {
        return false;
    }
    let node = node_for_phys(base.raw());
    let first_frame = base.raw() >> 12;
    ZONES[node].0.lock().remove_free_range(first_frame, count)
}

/// Return a range previously taken with [`reserve_frame_range`] (or a run of
/// freshly-evacuated frames) to the buddy as MOVABLE order-0 frames, coalescing
/// with free buddies. Compaction releases a fully-evacuated block this way so it
/// coalesces up to a higher order. The whole run must lie in one node's zone.
pub fn free_movable_range(base: PhysAddr, count: u64) {
    if count == 0 {
        return;
    }
    let node = node_for_phys(base.raw());
    let first_frame = base.raw() >> 12;
    let mut zone = ZONES[node].0.lock();
    for i in 0..count {
        zone.free_mt(first_frame + i, 0, buddy::MigrateType::Movable);
    }
}

/// Return a vector of independently owned base frames through the installed
/// allocator. Alternative allocators inherit the scalar default; the buddy
/// implementation batches COW-refcount shard acquisition before returning
/// only last-owner frames to its NUMA caches/free lists.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_frame_batch(frames: &[PhysFrame]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(allocator) = current_alloc() {
        allocator.free_frame_batch(frames);
    }
}

/// Free base frames addressed directly as `PhysAddr`, without first collecting
/// a region-sized `Vec<PhysFrame>`. Semantically identical to
/// [`free_frame_batch`] but allocation-free, so address-space teardown can hand
/// its backing list straight in even when memory is exhausted. Zero and
/// low-reserved entries are skipped, matching the `PhysFrame` path.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_phys_batch(phys_list: &[PhysAddr]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if current_alloc().is_some() {
        buddy_free_phys_batch(phys_list);
    }
}

/// Return a batch whose frames are known to have exactly one owner and are not
/// present in the COW registry. Page-table teardown uses this after detaching
/// the final inactive root and removing every table ownership registration.
///
/// # Safety
/// Every input frame must be exclusively owned by the caller. In particular,
/// it must have no COW reference-count entry and no live page-table registry
/// entry. Violating this contract can make a still-owned frame reusable.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub(crate) unsafe fn free_unique_frame_batch(frames: &[PhysFrame]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(allocator) = current_alloc() {
        // SAFETY: forwarded from this function's caller contract.
        unsafe { allocator.free_unique_frame_batch(frames) };
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
    buddy_return_unreferenced_frame(f);
}

/// Return a frame after the caller has established that no COW owner remains.
/// This is the common accounting/scrub/NUMA path for scalar and batched free.
fn buddy_return_unreferenced_frame(f: PhysFrame) {
    buddy_prepare_unreferenced_frame(f.start_address());
    let Some((zone_idx, frame_no)) = buddy_unreferenced_route(f) else {
        return;
    };
    if !free_order0_to_cache(zone_idx, frame_no) {
        ZONES[zone_idx].0.lock().free(frame_no, 0);
    }
}

/// Complete work that must precede publication of a final-owner frame.
fn buddy_prepare_unreferenced_frame(phys: PhysAddr) {
    // DEBUG_VM analogue of Linux `free_pages_prepare`'s "nonzero mapcount"
    // `bad_page` check (mm/page_alloc.c): a frame genuinely returning to the
    // buddy (COW refcount just reached 0) must have no reverse-map owners. A
    // surviving owner means some unmap/teardown path returned the frame without
    // a paired `rmap::remove`, so the next allocation of this frame inherits a
    // stale (root, va) owner and corrupts every reverse-map-driven decision
    // (TLB shootdown, page migration, COW split) — and, in the test suite,
    // makes any rmap-sensitive test later handed the frame flake (the
    // long-standing shared-alias/mremap test flakiness).
    //
    // Perf: this takes the frame's rmap shard lock on every buddy free, so it
    // must NOT run in release. It is the Linux-DEBUG_VM analogue and its
    // intended home is `#[cfg(debug_assertions)]` — on in debug builds, compiled
    // out of release so production pays nothing. It is behind the opt-in
    // `rmap-free-audit` feature FOR NOW (not `debug_assertions`) because it still
    // TRIPS on remaining reclaim/teardown paths that free a frame without a
    // paired `rmap::remove`: the `reap_anonymous` origin is fixed, but a debug
    // sweep shows at least one more, and turning it on in debug before that
    // sweep completes would break every debug build. Run `--features
    // rmap-free-audit` to hunt the remainder; once the suite runs it clean,
    // graduate this to `#[cfg(debug_assertions)]` as the permanent
    // always-on-in-debug regression guard for the whole class.
    #[cfg(feature = "rmap-free-audit")]
    {
        let owners = crate::rmap::owner_count(phys);
        if owners != 0 {
            let mut first_va = u64::MAX;
            let mut first_root = 0u64;
            crate::rmap::for_each_owner(phys, |o| {
                if first_va == u64::MAX {
                    first_va = o.va.as_u64();
                    first_root = o.root.raw();
                }
            });
            panic!(
                "buddy free of {phys:?} with {owners} live rmap owner(s) \
                 (first root={first_root:#x} va={first_va:#x}): a teardown/free \
                 path returned this frame without rmap::remove (Linux bad_page: \
                 nonzero mapcount)"
            );
        }
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
    scrub_freed_frame(phys);
}

/// Resolve the allocator destination after final-owner accounting/scrub.
fn buddy_unreferenced_route(f: PhysFrame) -> Option<(usize, u64)> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return None;
    }
    let zone_idx = if ALLOC.numa_aware.load(Ordering::Acquire) {
        phys_to_node(f.start_address().raw())
    } else {
        0
    };
    Some((zone_idx, buddy::frame_no(f)))
}

/// Window size for the allocation-free batched free path. A whole
/// address-space teardown is processed in fixed windows of this many frames
/// so the transient stack storage is bounded regardless of the region size —
/// freeing memory must never allocate memory proportional to the amount being
/// freed. Each window still amortises COW-shard lock acquisition (one lock per
/// touched shard per window) and publishes through `FRAME_RETURN_CHUNK` spills.
const FREE_BATCH_WINDOW: usize = 256;

/// Return one window (`<= FREE_BATCH_WINDOW`) of already-filtered final-owner
/// candidates. No heap allocation occurs: released frames are collected into a
/// stack buffer, scrubbed, then published through fixed-size cache/zone chunks.
fn free_final_owner_window(valid: &[PhysAddr]) {
    debug_assert!(valid.len() <= FREE_BATCH_WINDOW);
    let mut released = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut released_len = 0usize;
    cow::dec_ref_batch_each(valid, |phys| {
        released[released_len] = phys;
        released_len += 1;
    });
    let released = &released[..released_len];

    // From here no allocation is permitted: every entry has already lost its
    // final owner. Complete scalar-equivalent accounting/scrub with the COW
    // shard locks dropped, then publish through fixed-size stack chunks.
    for &phys in released {
        buddy_prepare_unreferenced_frame(phys);
    }
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }

    let numa_aware = ALLOC.numa_aware.load(Ordering::Acquire);
    let node_count = if numa_aware { MAX_NUMA_NODES } else { 1 };
    for node in 0..node_count {
        let mut chunk = [0u64; FRAME_RETURN_CHUNK];
        let mut chunk_len = 0usize;
        for &phys in released {
            let zone_idx = if numa_aware {
                phys_to_node(phys.raw())
            } else {
                0
            };
            if zone_idx != node {
                continue;
            }
            chunk[chunk_len] = buddy::frame_no(PhysFrame::new(phys));
            chunk_len += 1;
            if chunk_len == FRAME_RETURN_CHUNK {
                free_order0_chunk_to_zone(node, &chunk);
                chunk_len = 0;
            }
        }
        free_order0_chunk_to_zone(node, &chunk[..chunk_len]);
    }
}

fn buddy_free_frame_batch(frames: &[PhysFrame]) {
    let mut valid = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut valid_len = 0usize;
    for frame in frames {
        let phys = frame.start_address();
        if phys.raw() < LOW_RESERVED_BYTES {
            continue;
        }
        valid[valid_len] = phys;
        valid_len += 1;
        if valid_len == FREE_BATCH_WINDOW {
            free_final_owner_window(&valid[..valid_len]);
            valid_len = 0;
        }
    }
    if valid_len != 0 {
        free_final_owner_window(&valid[..valid_len]);
    }
}

/// Free a batch of physical frames addressed directly (no `PhysFrame`
/// wrapper). Shares the allocation-free window machinery so an address-space
/// teardown can hand its backing list straight in without first collecting a
/// region-sized `Vec<PhysFrame>` — that intermediate allocation is exactly
/// what failed under memory pressure.
pub(crate) fn buddy_free_phys_batch(phys_list: &[PhysAddr]) {
    let mut valid = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut valid_len = 0usize;
    for &phys in phys_list {
        if phys.raw() < LOW_RESERVED_BYTES {
            continue;
        }
        valid[valid_len] = phys;
        valid_len += 1;
        if valid_len == FREE_BATCH_WINDOW {
            free_final_owner_window(&valid[..valid_len]);
            valid_len = 0;
        }
    }
    if valid_len != 0 {
        free_final_owner_window(&valid[..valid_len]);
    }
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

/// Page-table-frame registry. Every PT / PD / PDPT / PML4 page allocated for a
/// user `AddressSpace` is recorded here and unregistered when reclaimed.
/// `free_user_pml4_tree` uses membership to distinguish AS-private tables from
/// kernel-shared entries copied into a fresh root; it must never free the
/// latter.
///
/// Sized for the LIVE page-table-frame working set across all
/// concurrently-mapped user address spaces — NOT the cumulative count.
/// Entries are cleared on each AS's teardown (`__pagetable_unregister`
/// via `free_user_pml4_tree`), so a correctly-drained registry only ever
/// holds the page-table pages of currently-live ASes (a handful of
/// processes × their sparse user mappings). The registry is a fixed
/// open-addressed atomic hash table so it can be consulted without allocation
/// or the buddy lock. A flat linear scan made sparse MAP_FIXED/mremap table
/// construction quadratic and overflowed after 16 K live tables.
const PT_REGISTRY_LEN: usize = 131072;
const PT_REGISTRY_TOMBSTONE: u64 = 1;
static PT_REGISTRY: [core::sync::atomic::AtomicU64; PT_REGISTRY_LEN] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; PT_REGISTRY_LEN]
};

#[inline]
fn pagetable_registry_start(phys: u64) -> usize {
    debug_assert!(PT_REGISTRY_LEN.is_power_of_two());
    (((phys >> PAGE_SHIFT).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as usize) & (PT_REGISTRY_LEN - 1)
}

#[doc(hidden)]
pub fn __pagetable_register(phys: u64) {
    use core::sync::atomic::Ordering;
    debug_assert!(phys > PT_REGISTRY_TOMBSTONE && phys & (PAGE_SIZE - 1) == 0);
    let start = pagetable_registry_start(phys);
    'retry: loop {
        let mut first_tombstone = None;
        for distance in 0..PT_REGISTRY_LEN {
            let index = (start + distance) & (PT_REGISTRY_LEN - 1);
            let value = PT_REGISTRY[index].load(Ordering::Acquire);
            if value == phys {
                return;
            }
            if value == PT_REGISTRY_TOMBSTONE {
                first_tombstone.get_or_insert(index);
                continue;
            }
            if value != 0 {
                continue;
            }
            let target = first_tombstone.unwrap_or(index);
            let expected = if target == index {
                0
            } else {
                PT_REGISTRY_TOMBSTONE
            };
            if PT_REGISTRY[target]
                .compare_exchange(expected, phys, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue 'retry;
        }
        if let Some(target) = first_tombstone {
            if PT_REGISTRY[target]
                .compare_exchange(
                    PT_REGISTRY_TOMBSTONE,
                    phys,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
            continue;
        }
        // Full of live entries. Never evict another root's ownership marker.
        PT_REGISTRY_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
        return;
    }
}

/// Count of `__pagetable_register` calls that found no free slot. Stays
/// 0 in healthy operation; a non-zero value means address spaces are
/// leaking page tables faster than they're reclaimed.
pub static PT_REGISTRY_OVERFLOWS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn __pagetable_unregister(phys: u64) {
    use core::sync::atomic::Ordering;
    let start = pagetable_registry_start(phys);
    for distance in 0..PT_REGISTRY_LEN {
        let slot = &PT_REGISTRY[(start + distance) & (PT_REGISTRY_LEN - 1)];
        let value = slot.load(Ordering::Acquire);
        if value == 0 {
            return;
        }
        if value == phys {
            let _ = slot.compare_exchange(
                phys,
                PT_REGISTRY_TOMBSTONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
    }
}

#[doc(hidden)]
pub fn __pagetable_is_registered(phys: u64) -> bool {
    use core::sync::atomic::Ordering;
    let start = pagetable_registry_start(phys);
    for distance in 0..PT_REGISTRY_LEN {
        let value = PT_REGISTRY[(start + distance) & (PT_REGISTRY_LEN - 1)].load(Ordering::Acquire);
        if value == phys {
            return true;
        }
        if value == 0 {
            return false;
        }
    }
    false
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
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    use narf_lib::sync::IrqSafeSpinLock;

    use crate::PhysAddr;

    // COW refcounts are consulted on EVERY frame free (`dec_ref`) and every
    // fork'd shared page (`inc_ref`), so a single global lock bounced one cache
    // line between every CPU freeing memory. Shard 64-way by phys page number
    // (same transform as the signal / futex tables); a frame always maps to one
    // shard, but unrelated frames on other CPUs no longer contend.
    const REFCOUNT_SHARDS: usize = 64;

    #[repr(align(64))]
    struct RefShard {
        map: IrqSafeSpinLock<Option<BTreeMap<u64, AtomicU32>>>,
    }

    impl RefShard {
        const fn new() -> Self {
            Self {
                map: IrqSafeSpinLock::new(None),
            }
        }
    }

    static REFCOUNTS: [RefShard; REFCOUNT_SHARDS] = [const { RefShard::new() }; REFCOUNT_SHARDS];

    #[inline]
    fn ref_shard(phys: u64) -> usize {
        // Frames are page-aligned; the low 12 bits are always zero.
        ((phys >> 12) as usize) & (REFCOUNT_SHARDS - 1)
    }

    /// Increment the refcount on `phys`. Returns the new count.
    /// First call (frame previously had count 0 / unregistered)
    /// inserts a count of 2 — the implicit "1" for the original
    /// owner plus the "1" for the new sharer. Subsequent
    /// `inc_ref`s add one each.
    pub fn inc_ref(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        let mut g = REFCOUNTS[ref_shard(key)].map.lock();
        let map = g.get_or_insert_with(BTreeMap::new);
        let entry = map.entry(key).or_insert_with(|| AtomicU32::new(1));
        // Bump from N to N+1; "first share" promotes the implicit
        // owner from `1` (representing the original sole owner) to
        // `2` (original + new sharer).
        entry.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Increment the COW reference for every non-zero frame in `frames`.
    ///
    /// Frames are grouped by refcount shard before any lock is taken, so a
    /// fork of an N-page address space acquires each touched shard once rather
    /// than disabling IRQs around N independent lock acquisitions. Duplicate
    /// addresses are intentional: each occurrence represents another owner
    /// and therefore contributes one reference.
    pub fn inc_ref_batch(frames: &[PhysAddr]) {
        let mut by_shard: [Vec<u64>; REFCOUNT_SHARDS] = core::array::from_fn(|_| Vec::new());
        for phys in frames {
            let key = phys.raw();
            if key != 0 {
                by_shard[ref_shard(key)].push(key);
            }
        }

        for (shard, keys) in by_shard.into_iter().enumerate() {
            if keys.is_empty() {
                continue;
            }
            let mut guard = REFCOUNTS[shard].map.lock();
            let map = guard.get_or_insert_with(BTreeMap::new);
            for key in keys {
                let entry = map.entry(key).or_insert_with(|| AtomicU32::new(1));
                entry.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// Undo speculative retains previously added by [`inc_ref_batch`].
    ///
    /// Fork uses this only for the suffix of private frames whose child VMAs
    /// were never published.  The original owner is therefore still live: a
    /// count that falls from two to one is removed from the table, restoring
    /// the implicit sole-owner representation, and no frame is released.
    /// Duplicate inputs remain distinct retains and are rolled back in full.
    /// This path allocates nothing and takes each touched shard at most once.
    pub(crate) fn rollback_inc_ref_batch(frames: &[PhysAddr]) {
        for (shard, refcounts) in REFCOUNTS.iter().enumerate() {
            let mut guard = None;
            for &phys in frames {
                let key = phys.raw();
                if key == 0 || ref_shard(key) != shard {
                    continue;
                }
                let g = guard.get_or_insert_with(|| refcounts.map.lock());
                let map = g
                    .as_mut()
                    .expect("speculative COW retain must have a refcount table");
                let entry = map
                    .get(&key)
                    .expect("speculative COW retain must remain registered");
                let previous = entry.fetch_sub(1, Ordering::AcqRel);
                assert!(previous > 1, "cannot roll back the original COW owner");
                if previous == 2 {
                    map.remove(&key);
                }
            }
        }
    }

    /// Decrement the refcount on `phys`. Returns the new count
    /// (post-decrement). If `phys` was never `inc_ref`'d, returns
    /// 0 — `free_frame` then returns the frame to the bin
    /// directly, matching pre-COW semantics.
    pub fn dec_ref(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        let mut g = REFCOUNTS[ref_shard(key)].map.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return 0,
        };
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

    /// Drop one owner for every non-zero input and return exactly the frames
    /// whose final COW owner was removed (or which were never registered).
    ///
    /// Results preserve input order within each shard only; callers must treat
    /// them as an ownership set, not as a positional mask. Duplicate inputs
    /// are processed as distinct owner drops. Each touched shard is locked
    /// once, eliminating per-page IRQ disable/restore cycles during teardown.
    pub fn dec_ref_batch(frames: &[PhysAddr]) -> Vec<PhysAddr> {
        let mut by_shard: [Vec<usize>; REFCOUNT_SHARDS] = core::array::from_fn(|_| Vec::new());
        for (index, phys) in frames.iter().enumerate() {
            let key = phys.raw();
            if key != 0 {
                by_shard[ref_shard(key)].push(index);
            }
        }

        // Reserve before any refcount reaches zero. Growing this vector while
        // holding a COW shard after final-owner removal would make teardown's
        // forward progress depend on a recursive frame allocation.
        let mut releasable = Vec::with_capacity(frames.len());
        for (shard, indices) in by_shard.into_iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let mut guard = REFCOUNTS[shard].map.lock();
            for index in indices {
                let phys = frames[index];
                let Some(map) = guard.as_mut() else {
                    releasable.push(phys);
                    continue;
                };
                let key = phys.raw();
                let Some(entry) = map.get(&key) else {
                    releasable.push(phys);
                    continue;
                };
                let previous = entry.fetch_sub(1, Ordering::AcqRel);
                if previous <= 1 {
                    map.remove(&key);
                    releasable.push(phys);
                }
            }
        }
        releasable
    }

    /// Drop one owner for every non-zero input, invoking `on_release(phys)`
    /// for each frame whose final COW owner was removed (or which was never
    /// registered). Unlike [`dec_ref_batch`] this allocates nothing: the
    /// caller supplies the sink, so freeing memory never depends on a
    /// recursive allocation. That is a hard requirement for the teardown and
    /// OOM-reaper paths, which run precisely when memory is exhausted.
    ///
    /// Each touched shard is locked at most once: the outer loop walks the
    /// shard space and, for each shard, scans the input for the frames that
    /// map to it. `on_release` runs while the shard lock is held, so it must
    /// only record the address (e.g. into a stack buffer) — it must not take
    /// the zone/cache locks, which would invert the established lock order.
    /// Callers scrub/publish released frames after this returns.
    pub fn dec_ref_batch_each(frames: &[PhysAddr], mut on_release: impl FnMut(PhysAddr)) {
        for (shard, refcounts) in REFCOUNTS.iter().enumerate() {
            let mut guard = None;
            for &phys in frames {
                let key = phys.raw();
                if key == 0 || ref_shard(key) != shard {
                    continue;
                }
                let g = guard.get_or_insert_with(|| refcounts.map.lock());
                let Some(map) = g.as_mut() else {
                    on_release(phys);
                    continue;
                };
                let Some(entry) = map.get(&key) else {
                    on_release(phys);
                    continue;
                };
                if entry.fetch_sub(1, Ordering::AcqRel) <= 1 {
                    map.remove(&key);
                    on_release(phys);
                }
            }
        }
    }

    /// Read-only peek at a frame's refcount. Returns 0 if the
    /// frame was never registered; otherwise the current count.
    pub fn count(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        REFCOUNTS[ref_shard(key)]
            .map
            .lock()
            .as_ref()
            .and_then(|m| m.get(&key))
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Snapshot COW counts in the same order as `frames`.
    ///
    /// Each touched shard is locked once, so page-table construction can
    /// derive permissions for a complete region without one IRQ-disabling
    /// lock acquisition per leaf. Zero/unregistered frames report zero and
    /// duplicate inputs receive identical snapshots.
    pub fn count_batch(frames: &[PhysAddr]) -> Vec<u32> {
        let mut counts = alloc::vec![0; frames.len()];
        let mut by_shard: [Vec<usize>; REFCOUNT_SHARDS] = core::array::from_fn(|_| Vec::new());
        for (index, phys) in frames.iter().enumerate() {
            let key = phys.raw();
            if key != 0 {
                by_shard[ref_shard(key)].push(index);
            }
        }

        for (shard, indices) in by_shard.into_iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let guard = REFCOUNTS[shard].map.lock();
            let Some(map) = guard.as_ref() else {
                continue;
            };
            for index in indices {
                let key = frames[index].raw();
                counts[index] = map
                    .get(&key)
                    .map(|count| count.load(Ordering::Acquire))
                    .unwrap_or(0);
            }
        }
        counts
    }

    /// Test hook — drop every recorded refcount. Tests that
    /// exercise inc/dec sequences should call this to start from
    /// a clean slate.
    #[doc(hidden)]
    pub fn __test_clear() {
        for s in &REFCOUNTS {
            *s.map.lock() = None;
        }
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
    let free: usize = ZONES
        .iter()
        .enumerate()
        .map(|(node, zone)| {
            zone.0.lock().free_frame_count() + FRAME_CACHE_FREE[node].load(Ordering::Relaxed)
        })
        .sum();
    FrameStats {
        total: ALLOC.total_frames.load(Ordering::Relaxed),
        free,
        reserved: ALLOC.reserved_frames.load(Ordering::Relaxed),
    }
}

/// Per-node free-frame count. Returns 0 when `node` is out of range
/// or the allocator hasn't been initialised.
pub fn node_free(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }
    ZONES[node].0.lock().free_frame_count() + FRAME_CACHE_FREE[node].load(Ordering::Relaxed)
}

/// Stable number of allocator-managed base pages assigned to `node`.
///
/// The snapshot is established at SRAT-driven rebalance, after early
/// reserved/boot allocations have been removed from the buddy pool.
pub fn node_total(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }
    ALLOC.node_total_frames[node].load(Ordering::Relaxed)
}

/// Snapshot the number of free buddy blocks at every order for `node`.
pub fn node_free_blocks(node: usize) -> [usize; BUDDY_ORDER_COUNT] {
    let mut counts = [0usize; BUDDY_ORDER_COUNT];
    if node >= MAX_NUMA_NODES {
        return counts;
    }
    let zone = ZONES[node].0.lock();
    for (order, count) in counts.iter_mut().enumerate() {
        *count = zone.free_block_count(order as u8);
    }
    counts[0] += FRAME_CACHE_FREE[node].load(Ordering::Relaxed);
    counts
}

/// True once `rebalance_to_topology` has run.
pub fn is_numa_aware() -> bool {
    ALLOC.numa_aware.load(Ordering::Acquire)
}

/// Diagnostic: walk every zone's free lists and confirm no frame
/// appears in more than one block. Returns `Ok(())` on success or
/// `Err((zone, frame_no, order_a, order_b))` describing the first
/// overlap found. Intended for smoke-test instrumentation, not hot
/// paths — O(N log N) per zone in total free-block count.
pub fn validate_no_overlap() -> Result<(), (usize, u64, u8, u8)> {
    for (i, zone) in ZONES.iter().enumerate() {
        if let Err((f, oa, ob)) = zone.0.lock().validate_no_overlap() {
            return Err((i, f, oa, ob));
        }
    }
    Ok(())
}

fn smoke_buddy_zone_locks_are_independent() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    let first = core::ptr::addr_of!(ZONES[0]) as usize;
    let second = core::ptr::addr_of!(ZONES[1]) as usize;
    if first & 63 != 0 || second.saturating_sub(first) < 64 {
        return TestResult::Fail("buddy zone locks share a cache line");
    }
    let _held = ZONES[0].0.lock();
    if ZONES[1].0.try_lock().is_none() {
        return TestResult::Fail("locking one buddy zone blocks another zone");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("memory/frame", smoke_buddy_zone_locks_are_independent);

#[cfg(feature = "kernel-test")]
fn smoke_order0_frame_cache_round_trip() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    let node = current_cpu_node();
    if FRAME_CACHE_HOTPLUG_BYPASS[node].load(Ordering::Acquire) {
        return TestResult::Skip("runtime hotplug intentionally bypasses frame cache");
    }
    let free_before = node_free(node);
    let hits_before = FRAME_CACHE_HITS.load(Ordering::Relaxed);
    let first = match alloc_pages_on(node, 0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("no order-0 frame available"),
    };
    free_pages(first, 0);
    let second = match alloc_pages_on(node, 0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("cached order-0 frame was not reusable"),
    };
    free_pages(second, 0);
    if FRAME_CACHE_HITS.load(Ordering::Relaxed) <= hits_before {
        return TestResult::Fail("order-0 round trip missed the per-CPU cache");
    }
    if node_free(node) != free_before {
        return TestResult::Fail("frame cache changed free-page accounting");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("memory/frame", smoke_order0_frame_cache_round_trip);

#[cfg(feature = "kernel-test")]
fn smoke_order0_frame_cache_batch_free_is_bounded() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
        current_cpu_node().min(MAX_NUMA_NODES - 1)
    } else {
        0
    };
    if frame_cache_bypassed(node) {
        return TestResult::Skip("frame cache drain/hotplug bypass is active");
    }

    const FRAMES: usize = FRAME_RETURN_CHUNK + 1;
    let free_before = node_free(node);
    let mut frames = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        let frame = match alloc_pages_on(node, 0) {
            Ok(frame) => frame,
            Err(_) => {
                buddy_free_frame_batch(&frames);
                return TestResult::Skip("not enough order-0 frames for batch-free smoke");
            }
        };
        let release_node = if ALLOC.numa_aware.load(Ordering::Acquire) {
            phys_to_node(frame.start_address().raw())
        } else {
            0
        };
        if release_node != node {
            frames.push(frame);
            buddy_free_frame_batch(&frames);
            return TestResult::Skip("allocation fell back to another NUMA node");
        }
        frames.push(frame);
    }

    let locks_before = FRAME_CACHE_BATCH_FREE_LOCKS.load(Ordering::Relaxed);
    buddy_free_frame_batch(&frames);
    let locks = FRAME_CACHE_BATCH_FREE_LOCKS
        .load(Ordering::Relaxed)
        .saturating_sub(locks_before);
    if locks != 2 {
        return TestResult::Fail("batch free did not use bounded cache transactions");
    }
    if node_free(node) != free_before {
        return TestResult::Fail("batch free changed free-page accounting");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_order0_frame_cache_batch_free_is_bounded
);

/// A teardown larger than one `FREE_BATCH_WINDOW` must free every frame with
/// no allocation proportional to the batch size (the region-sized `Vec` that
/// used to sit on this path panicked the kernel under memory pressure). This
/// exercises the multi-window `free_phys_batch` entry across the window
/// boundary and asserts free-page accounting is fully restored and the frames
/// are reusable — a leak or a stranded window would fail both.
#[cfg(feature = "kernel-test")]
fn smoke_free_phys_batch_spans_windows_without_leak() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !ALLOC.initialised.load(Ordering::Acquire) {
        return TestResult::Skip("allocator not initialised");
    }
    let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
        current_cpu_node().min(MAX_NUMA_NODES - 1)
    } else {
        0
    };

    const FRAMES: usize = FREE_BATCH_WINDOW + 8;
    let free_before = node_free(node);
    let mut phys = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        match alloc_pages_on(node, 0) {
            Ok(frame) => {
                if ALLOC.numa_aware.load(Ordering::Acquire)
                    && phys_to_node(frame.start_address().raw()) != node
                {
                    phys.push(frame.start_address());
                    free_phys_batch(&phys);
                    return TestResult::Skip("allocation fell back to another NUMA node");
                }
                phys.push(frame.start_address());
            }
            Err(_) => {
                free_phys_batch(&phys);
                return TestResult::Skip("not enough order-0 frames for windowed free smoke");
            }
        }
    }

    free_phys_batch(&phys);
    if node_free(node) != free_before {
        return TestResult::Fail("windowed free_phys_batch changed free-page accounting");
    }
    // A stranded window would leak frames; confirm the pool handed them back.
    match alloc_pages_on(node, 0) {
        Ok(frame) => free_pages(frame, 0),
        Err(_) => return TestResult::Fail("frames not reusable after windowed free"),
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_free_phys_batch_spans_windows_without_leak
);

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

#[cfg(target_os = "none")]
extern "Rust" {
    /// Look up the NUMA node a physical address belongs to. Returns
    /// `0` when topology is unknown or the address is outside any
    /// SRAT memory range.
    fn narf_phys_to_node(addr: u64) -> u32;
    /// Look up the NUMA node hosting a logical CPU. Returns `0`
    /// when topology is unknown.
    fn narf_cpu_to_node(cpu: u32) -> u32;
    /// NUMA distance from node `from` to node `to` (Linux's
    /// `node_distance`, scaled so local == 10). Returns the SLIT
    /// matrix entry when available, else 10 (same node) / 20
    /// (cross-node). Used to order the allocator's cross-node
    /// fallback nearest-first.
    fn narf_node_distance(from: u32, to: u32) -> u32;
}

// Host-side crate tests do not link the kernel binary that owns the ACPI
// bridge above. Give them the documented no-topology behavior so every crate
// that transitively links narf-memory gets the same deterministic fallback.
// These definitions are excluded from kernel targets, where silently
// replacing firmware topology would be incorrect.
#[cfg(not(target_os = "none"))]
unsafe fn narf_phys_to_node(_addr: u64) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe fn narf_cpu_to_node(_cpu: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe fn narf_node_distance(from: u32, to: u32) -> u32 {
    if from == to {
        10
    } else {
        20
    }
}

/// Resolve a physical address to an allocator NUMA-node index.
///
/// Kept crate-visible for address-space page migration; external consumers
/// should use higher-level allocation and policy APIs.
#[inline]
pub(crate) unsafe fn narf_phys_node(addr: u64) -> usize {
    // SAFETY: narf-frame provides the topology hook in kernel binaries.
    unsafe { narf_phys_to_node(addr) as usize }.min(MAX_NUMA_NODES - 1)
}

/// Distance from node `from` to node `to`, via the weak ACPI hook.
/// Clamps to a sane non-zero default (10 local / 20 remote) when the
/// hook is the no-topology stub.
#[inline]
pub(crate) fn node_distance(from: usize, to: usize) -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let d = unsafe { narf_node_distance(from as u32, to as u32) };
    if d == 0 {
        if from == to {
            10
        } else {
            20
        }
    } else {
        d
    }
}

/// Build the cross-node fallback search order for `preferred`: every
/// *other* node, sorted nearest-first by NUMA distance, ties broken by
/// ascending node index for determinism. Returns the count written into
/// `out` (always `MAX_NUMA_NODES - 1`).
fn fallback_order(preferred: usize, out: &mut [usize; MAX_NUMA_NODES]) -> usize {
    let mut n = 0;
    for i in 0..MAX_NUMA_NODES {
        if i != preferred {
            out[n] = i;
            n += 1;
        }
    }
    // Insertion sort by (distance, index); n <= 15 so this is cheap and
    // avoids any alloc on the hot path.
    for a in 1..n {
        let mut b = a;
        while b > 0 {
            let cur = out[b];
            let prev = out[b - 1];
            let dc = node_distance(preferred, cur);
            let dp = node_distance(preferred, prev);
            if dc < dp || (dc == dp && cur < prev) {
                out.swap(b, b - 1);
                b -= 1;
            } else {
                break;
            }
        }
    }
    n
}

#[inline]
fn phys_to_node(addr: u64) -> usize {
    if let Some(node) = hotplug_node_for_phys(addr) {
        return node;
    }
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_phys_to_node(addr) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

pub fn node_for_phys(addr: u64) -> usize {
    phys_to_node(addr)
}

pub fn hotplug_node_for_phys(addr: u64) -> Option<usize> {
    HOTPLUG_RANGES
        .lock()
        .iter()
        .find(|range| addr >= range.start && addr < range.start + range.len)
        .map(|range| range.node)
}

/// Inclusive `[lo, hi]` frame-number span containing all of `node`'s managed
/// frames, or `None` if the node has none. This is the physical range the
/// compaction dual-scanner sweeps between.
///
/// The span is an OUTER bound, not an exact membership test: where firmware /
/// hotplug ranges interleave nodes it may include holes or foreign-node frames.
/// Callers step frame-by-frame and re-check [`node_for_phys`] (and free /
/// movable state), so an over-approximate span only costs a few skipped frames.
pub fn node_frame_bounds(node: usize) -> Option<(u64, u64)> {
    // Snapshot the range registries first: `phys_to_node` locks `HOTPLUG_RANGES`,
    // so we must not hold it (or `BOOT_MEMORY_RANGES`) across the sample.
    let boot = BOOT_MEMORY_RANGES.lock().clone();
    let hotplug = HOTPLUG_RANGES.lock().clone();

    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut seen = false;
    let mut consider = |start: u64, len: u64| {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        // SRAT- and hotplug-derived ranges are node-homogeneous; sample the node
        // at the range start rather than per frame.
        if phys_to_node(start) != node {
            return;
        }
        let first = (start + PAGE_SIZE - 1) >> 12; // first fully-contained frame
        let last = (end >> 12).saturating_sub(1); // last fully-contained frame
        if last < first {
            return;
        }
        lo = lo.min(first);
        hi = hi.max(last);
        seen = true;
    };

    for (start, len) in &boot {
        consider(*start, *len);
    }
    for range in &hotplug {
        if range.online {
            consider(range.start, range.len);
        }
    }
    seen.then_some((lo, hi))
}

/// Snapshot Linux-style logical memory blocks from authoritative boot RAM and
/// currently-online hotplug ranges. A block is listed once even when adjacent
/// firmware ranges overlap it.
pub fn memory_blocks() -> Vec<MemoryBlock> {
    let boot = BOOT_MEMORY_RANGES.lock().clone();
    let hotplug = HOTPLUG_RANGES.lock().clone();
    memory_blocks_from_ranges(&boot, &hotplug)
}

fn memory_blocks_from_ranges(boot: &[(u64, u64)], hotplug: &[HotplugRange]) -> Vec<MemoryBlock> {
    let mut ids = Vec::new();
    for &(start, len) in boot {
        let first = start / MEMORY_BLOCK_SIZE;
        let last = start.saturating_add(len).saturating_sub(1) / MEMORY_BLOCK_SIZE;
        for id in first..=last {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    for range in hotplug {
        let first = range.start / MEMORY_BLOCK_SIZE;
        let last = range.start.saturating_add(range.len).saturating_sub(1) / MEMORY_BLOCK_SIZE;
        for id in first..=last {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.into_iter()
        .map(|id| {
            let start = id * MEMORY_BLOCK_SIZE;
            let sample = boot
                .iter()
                .filter_map(|&(base, len)| {
                    (start < base + len && base < start + MEMORY_BLOCK_SIZE)
                        .then_some(start.max(base))
                })
                .chain(hotplug.iter().filter_map(|range| {
                    (start < range.start + range.len && range.start < start + MEMORY_BLOCK_SIZE)
                        .then_some(start.max(range.start))
                }))
                .min()
                .unwrap_or(start);
            let node = hotplug
                .iter()
                .find(|range| {
                    start < range.start + range.len && range.start < start + MEMORY_BLOCK_SIZE
                })
                .map(|range| range.node)
                .unwrap_or_else(|| phys_to_node(sample));
            MemoryBlock {
                id,
                start,
                node,
                online: boot
                    .iter()
                    .any(|&(base, len)| start < base + len && base < start + MEMORY_BLOCK_SIZE)
                    || hotplug.iter().any(|range| {
                        range.online
                            && start < range.start + range.len
                            && range.start < start + MEMORY_BLOCK_SIZE
                    }),
            }
        })
        .collect()
}

fn smoke_memory_blocks_persist_offline_topology() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    let base = 8 * MEMORY_BLOCK_SIZE;
    let ranges = [
        HotplugRange {
            start: base,
            len: MEMORY_BLOCK_SIZE / 2,
            node: 3,
            online: false,
        },
        HotplugRange {
            start: base + MEMORY_BLOCK_SIZE,
            len: MEMORY_BLOCK_SIZE,
            node: 4,
            online: true,
        },
    ];
    let blocks = memory_blocks_from_ranges(&[], &ranges);
    let offline = blocks.iter().find(|block| block.id == 8);
    let online = blocks.iter().find(|block| block.id == 9);
    if offline.is_none_or(|block| block.online || block.node != 3)
        || online.is_none_or(|block| !block.online || block.node != 4)
    {
        TestResult::Fail("offline identity or live state was not preserved")
    } else {
        TestResult::Pass
    }
}
narf_kernel_test::kernel_test_in!("memory/numa", smoke_memory_blocks_persist_offline_topology);

#[inline]
pub(crate) fn current_cpu_node() -> usize {
    let cpu = narf_lib::percpu::current_cpu() as u32;
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_cpu_to_node(cpu) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

/// The NUMA node hosting the current CPU (the "local" node for
/// locality-first allocation). Public wrapper over `current_cpu_node`
/// so the mempolicy + fault paths can resolve their `local` argument.
#[inline]
pub fn local_node() -> usize {
    current_cpu_node()
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
    /// Return multiple independently owned base frames. The default preserves
    /// compatibility for simple allocators; implementations may coalesce
    /// metadata locking while retaining scalar ownership semantics.
    fn free_frame_batch(&self, frames: &[PhysFrame]) {
        for frame in frames {
            self.free_frame(*frame);
        }
    }
    /// Return frames for which the caller has already proved unique ownership.
    /// Simple allocators retain their ordinary batch semantics; allocators with
    /// separate shared-owner metadata may bypass those lookups.
    ///
    /// # Safety
    /// Every frame must be exclusively owned by the caller and absent from any
    /// allocator-specific shared-owner registry.
    unsafe fn free_unique_frame_batch(&self, frames: &[PhysFrame]) {
        self.free_frame_batch(frames);
    }
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
/// module-private cache-line-aligned per-zone `BuddyZone` locks.
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
    fn free_frame_batch(&self, frames: &[PhysFrame]) {
        buddy_free_frame_batch(frames);
    }
    unsafe fn free_unique_frame_batch(&self, frames: &[PhysFrame]) {
        for frame in frames {
            buddy_return_unreferenced_frame(*frame);
        }
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
// object behind an `IrqSafeSpinLock<Option<…>>`. Dispatch copies the
// `'static` fat pointer and releases this lock before invoking it, so
// buddy work is serialized only by the selected NUMA-zone lock.
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
