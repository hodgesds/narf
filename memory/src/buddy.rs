// Clean-room buddy allocator.
//
// Algorithm references:
//   - Knuth, "The Art of Computer Programming", Vol 1 §2.5
//     "Dynamic Storage Allocation" — buddy system per Knowlton.
//     <https://www.informit.com/store/art-of-computer-programming-volume-1-fundamental-9780201896831>
//   - Knowlton, K. C. (1965). "A fast storage allocator." Comm. ACM
//     8(10): 623-625.
//     <https://dl.acm.org/doi/10.1145/365628.365655>
//   - Intel SDM Vol 3A §4 — paging granularity / page sizes.
//     <https://www.intel.com/sdm>
//
// No GPL source consulted. See `memory/specification/heap-migration.md` §0.
//
// Design summary (per `heap-migration.md` §3.1):
// - Per-NUMA-node, per-order free lists.
// - Orders 0..=10 (4 KiB to 4 MiB).
// - Coalesce on free by checking the buddy frame's free state.
// - Honors `EARLY_PHYS_CEILING` (4 GiB cap pre-direct-map).
//
// Buddy invariants:
// 1. A block of order N covers `1 << N` contiguous frames starting
//    at a frame number that is a multiple of `1 << N`.
// 2. The "buddy" of a block at frame number F, order N is the block
//    starting at frame number `F XOR (1 << N)`.
// 3. Two buddies can coalesce iff both are free and both are blocks
//    of the SAME order N (i.e., neither has been further split) AND
//    both belong to the SAME migratetype partition (see below).
//
// ── Anti-fragmentation: migratetype partitioning ────────────────────
//
// Free blocks are grouped by mobility class (`MigrateType`: UNMOVABLE
// vs MOVABLE), mirroring Linux's per-migratetype free lists. Grouping
// keeps long-lived UNMOVABLE allocations (page tables, slab pages, DMA)
// out of the contiguous regions that bulk-freed MOVABLE user pages live
// in, so a fork/exec/exit storm frees its user pages back into a few
// large coalescible runs instead of a checkerboard of unmovable holes.
// This raises higher-order allocation success under fragmentation with
// NO page migration required — it only changes WHERE a free block is
// filed, never moves live data.
//
// When a migratetype's own partition can't serve a request, the
// allocator STEALS a higher-order block from the fallback migratetype
// (`FALLBACK_ORDER`) and converts the whole split block to the
// requesting type (Linux's whole-block steal), so a single steal
// doesn't permanently scatter the donor pool.
//
// ── Design note: the eventual MIGRATION step (NOT yet implemented) ───
//
// Linux compaction goes further: it MIGRATES movable pages — copies a
// page's contents to a new frame and rewrites every PTE that mapped the
// old frame — to actively assemble higher-order free blocks on demand.
// NARF CANNOT do this soundly today because it has NO reverse map
// (rmap): there is no per-frame descriptor recording which
// address-space PTEs (and COW/shmem aliases) reference a given physical
// frame. Frame state is only the buddy free-list plus the COW refcount
// shards; nothing maps frame -> mappings. Blindly copying a movable
// page and repointing one caller would leave every other alias dangling.
//
// The migration step becomes implementable once a per-frame rmap exists
// (frame -> list of (address_space, virtual_page) referrers). At that
// point a compaction pass would, for a target movable block: (1) allocate
// a replacement movable frame, (2) copy contents, (3) walk the rmap
// updating every referrer PTE under the relevant AS locks with a TLB
// shootdown, (4) free the old frame — coalescing it with its now-free
// buddies. Until rmap lands, the partitioning above is the honest,
// migration-free anti-fragmentation slice; `MigrateType::Movable` names
// the pages that WOULD be migratable so the accounting is already in
// place for that future work.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::frame::{PhysFrame, EARLY_PHYS_CEILING, PAGE_SHIFT, PAGE_SIZE};
use crate::PhysAddr;

/// Smallest block order. Order 0 = 4 KiB.
pub const MIN_ORDER: u8 = 0;

/// Largest block order in the buddy. Order 13 = 32 MiB.
/// Hugepages (2 MiB / 1 GiB) live in a separate pool — see §3.1.2.
pub const MAX_ORDER: u8 = 13;

/// Number of orders inclusive (0..=MAX_ORDER).
pub const NUM_ORDERS: usize = (MAX_ORDER as usize) + 1;

/// Mobility class of an allocation — Linux's "migratetype", minus the
/// migration machinery (see the anti-fragmentation design note below).
///
/// Free blocks are partitioned by migratetype so that long-lived
/// UNMOVABLE allocations (page tables, slab pages, kernel objects) do
/// not fragment the contiguous regions that MOVABLE allocations (user
/// anonymous/file pages — freed in bulk on process exit) live in, and
/// vice versa. Keeping the two classes clustered means a movable region
/// tends to free back into one large coalescible block instead of a
/// checkerboard of unmovable holes, which is what starves higher-order
/// allocations under fragmentation.
///
/// Ordering is deliberate: `UNMOVABLE` first so it is the natural
/// `Default` and index 0. The fallback preference order in
/// `FALLBACK_ORDER` is derived from these indices.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MigrateType {
    /// Kernel-internal allocations that can never be relocated because
    /// something holds a raw physical/direct-map pointer to them: page
    /// tables, slab backing pages, DMA buffers, per-CPU data.
    Unmovable = 0,
    /// User-backing pages (anonymous, file, shmem). In Linux these are
    /// migratable; in NARF they are merely *grouped* (no migration yet),
    /// so that a fork/exec/exit storm frees them back into large
    /// contiguous runs rather than peppering the unmovable pool.
    Movable = 1,
}

/// Number of migratetypes tracked.
pub const NUM_MIGRATE_TYPES: usize = 2;

impl MigrateType {
    /// Free-list partition index for this migratetype.
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Reconstruct a migratetype from its partition index. Any
    /// out-of-range value maps to `Unmovable`, the conservative default
    /// (an unmovable block is never wrongly relocated).
    #[inline]
    pub const fn from_index(idx: usize) -> Self {
        match idx {
            1 => MigrateType::Movable,
            _ => MigrateType::Unmovable,
        }
    }
}

impl Default for MigrateType {
    #[inline]
    fn default() -> Self {
        MigrateType::Unmovable
    }
}

/// Fallback search order per requested migratetype. When a request
/// cannot be served from its own partition, the allocator steals from
/// the next migratetype in this list (Linux's `fallbacks[]`). The
/// requested type always appears first. With only two types the table is
/// trivial, but it is expressed as data so adding RECLAIMABLE later is a
/// one-line change.
const FALLBACK_ORDER: [[MigrateType; NUM_MIGRATE_TYPES]; NUM_MIGRATE_TYPES] = [
    // Unmovable request: prefer unmovable, else steal movable.
    [MigrateType::Unmovable, MigrateType::Movable],
    // Movable request: prefer movable, else steal unmovable.
    [MigrateType::Movable, MigrateType::Unmovable],
];

/// Returns the size in bytes of a block at `order`.
#[inline]
pub const fn order_bytes(order: u8) -> u64 {
    PAGE_SIZE << (order as u32)
}

/// Returns the size in frames of a block at `order`.
#[inline]
pub const fn order_frames(order: u8) -> u64 {
    1u64 << (order as u32)
}

/// Buddy frame number for `frame_no` at `order`.
/// Per invariant 2 in the file header.
#[inline]
const fn buddy_of(frame_no: u64, order: u8) -> u64 {
    frame_no ^ (1u64 << (order as u32))
}

// ── Per-frame allocation audit (frame-alloc-audit feature) ──────────────
//
// A global 1-bit-per-frame map: set when the buddy hands a block out,
// cleared when the buddy takes it back. A double-alloc (the buddy
// returning a frame it already handed out — the "marginal-buddy"
// signature) or a double-free panics AT THE SOURCE, so the bad caller's
// backtrace is printed at the offending alloc/free rather than later, in
// some unrelated consumer that read the aliased frame.
//
// Hooked at the BuddyZone alloc/free primitives (`alloc`, `alloc_below`,
// `free`); `donate` (initial population) and `drain_into` (NUMA
// rebalance) move blocks via the free lists directly without changing
// allocation state, so they intentionally bypass the audit.
#[cfg(feature = "frame-alloc-audit")]
mod audit {
    use core::panic::Location;
    use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

    /// Source location of the most recent `free_frame` call, captured via
    /// `#[track_caller]` (the kernel is `-fomit-frame-pointer`, so the
    /// panic backtrace is empty — this names the bad free's call site).
    static LAST_FREE_LOC: AtomicPtr<Location<'static>> = AtomicPtr::new(core::ptr::null_mut());

    pub fn set_free_loc(loc: &'static Location<'static>) {
        LAST_FREE_LOC.store(loc as *const _ as *mut _, Ordering::Relaxed);
    }

    // Per-frame alloc-site tracking (covers the first 1 GiB of phys =
    // 256 Ki frames; the doubly-freed frame is always very low). Lets the
    // double-free panic say WHERE the frame was allocated — the missing
    // datum that distinguishes "this frame is a PML4/page-table page"
    // (alloc site in paging.rs) from "this frame is region data" (alloc
    // site in the loader / stack path).
    const ALLOC_LOC_FRAMES: usize = 256 * 1024;
    static LAST_ALLOC_LOC: AtomicPtr<Location<'static>> = AtomicPtr::new(core::ptr::null_mut());
    static ALLOC_LOC: [AtomicPtr<Location<'static>>; ALLOC_LOC_FRAMES] = {
        const Z: AtomicPtr<Location<'static>> = AtomicPtr::new(core::ptr::null_mut());
        [Z; ALLOC_LOC_FRAMES]
    };

    pub fn set_alloc_loc(loc: &'static Location<'static>) {
        LAST_ALLOC_LOC.store(loc as *const _ as *mut _, Ordering::Relaxed);
    }

    fn record_alloc_loc(frame: u64) {
        let f = frame as usize;
        if f < ALLOC_LOC_FRAMES {
            ALLOC_LOC[f].store(LAST_ALLOC_LOC.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }

    fn alloc_site(frame: u64) -> (&'static str, u32) {
        let f = frame as usize;
        if f < ALLOC_LOC_FRAMES {
            let p = ALLOC_LOC[f].load(Ordering::Relaxed);
            if !p.is_null() {
                // SAFETY: only `&'static Location` pointers stored.
                return unsafe { ((*p).file(), (*p).line()) };
            }
        }
        ("<unknown>", 0)
    }

    // Small ring of recent frees so a double-free can name the FIRST
    // free's site too, not just the offending second one.
    const RING: usize = 1024;
    static RING_FRAME: [AtomicU64; RING] = {
        const Z: AtomicU64 = AtomicU64::new(u64::MAX);
        [Z; RING]
    };
    static RING_LOC: [AtomicPtr<Location<'static>>; RING] = {
        const Z: AtomicPtr<Location<'static>> = AtomicPtr::new(core::ptr::null_mut());
        [Z; RING]
    };
    static RING_POS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    fn ring_record(frame: u64) {
        let pos = RING_POS.fetch_add(1, Ordering::Relaxed) % RING;
        RING_FRAME[pos].store(frame, Ordering::Relaxed);
        RING_LOC[pos].store(LAST_FREE_LOC.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Find the file:line of the MOST RECENT prior free of `frame` (the
    /// one that makes the current free a double-free), or
    /// `("<not-in-ring>", 0)` if it scrolled out. Scans newest-first from
    /// the ring write cursor.
    fn ring_prior_free(frame: u64) -> (&'static str, u32) {
        let head = RING_POS.load(Ordering::Relaxed);
        for back in 1..=RING {
            let i = (head + RING - back) % RING;
            if RING_FRAME[i].load(Ordering::Relaxed) == frame {
                let p = RING_LOC[i].load(Ordering::Relaxed);
                if !p.is_null() {
                    // SAFETY: only `&'static Location` pointers stored.
                    return unsafe { ((*p).file(), (*p).line()) };
                }
            }
        }
        ("<not-in-ring>", 0)
    }

    fn free_loc() -> &'static str {
        let p = LAST_FREE_LOC.load(Ordering::Relaxed);
        if p.is_null() {
            "<unknown>"
        } else {
            // SAFETY: only ever stored a `&'static Location` pointer.
            unsafe { (*p).file() }
        }
    }

    fn free_line() -> u32 {
        let p = LAST_FREE_LOC.load(Ordering::Relaxed);
        if p.is_null() {
            0
        } else {
            // SAFETY: only ever stored a `&'static Location` pointer.
            unsafe { (*p).line() }
        }
    }

    /// Frame-number ceiling the bitmap covers (4 Mi frames = 16 GiB of
    /// physical RAM). Frames above this are not tracked (the test
    /// configs sit well under 4 GiB).
    const AUDIT_FRAMES: usize = 4 * 1024 * 1024;
    const WORDS: usize = AUDIT_FRAMES / 64;
    static BITS: [AtomicU64; WORDS] = {
        const Z: AtomicU64 = AtomicU64::new(0);
        [Z; WORDS]
    };

    pub fn mark_alloc(frame: u64, order: u8) {
        for f in frame..frame + super::order_frames(order) {
            let idx = (f / 64) as usize;
            if idx >= WORDS {
                continue;
            }
            let bit = 1u64 << (f % 64);
            if BITS[idx].fetch_or(bit, Ordering::Relaxed) & bit != 0 {
                panic!(
                    "frame-alloc-audit: DOUBLE-ALLOC of frame {:#x} (phys {:#x}), block order {}",
                    f,
                    f << 12,
                    order
                );
            }
            record_alloc_loc(f);
        }
    }

    pub fn mark_free(frame: u64, order: u8) {
        for f in frame..frame + super::order_frames(order) {
            let idx = (f / 64) as usize;
            if idx >= WORDS {
                continue;
            }
            let bit = 1u64 << (f % 64);
            if BITS[idx].fetch_and(!bit, Ordering::Relaxed) & bit == 0 {
                let (pf, pl) = ring_prior_free(f);
                let (af, al) = alloc_site(f);
                panic!(
                    "frame-alloc-audit: DOUBLE-FREE of frame {:#x} (phys {:#x}) order {}; \
                     alloc'd @ {}:{}; this free @ {}:{}; first free @ {}:{}",
                    f,
                    f << 12,
                    order,
                    af,
                    al,
                    free_loc(),
                    free_line(),
                    pf,
                    pl,
                );
            }
            ring_record(f);
        }
    }
}

/// Record a buddy hand-out. Only compiled with `frame-alloc-audit`; the
/// zone-gated `note_alloc` calls it solely inside its own feature cfg.
#[cfg(feature = "frame-alloc-audit")]
#[inline]
fn audit_alloc(frame: u64, order: u8) {
    audit::mark_alloc(frame, order);
}

/// Record a buddy return. Only compiled with `frame-alloc-audit`.
#[cfg(feature = "frame-alloc-audit")]
#[inline]
fn audit_free(frame: u64, order: u8) {
    audit::mark_free(frame, order);
}

/// Transition one live-allocator frame from owned to per-CPU-cache free.
/// The cache is outside `BuddyZone`, so it must feed the same audit bitmap
/// explicitly. No-op when frame auditing is disabled.
#[inline]
pub(crate) fn audit_cached_free(frame: u64) {
    #[cfg(feature = "frame-alloc-audit")]
    audit_free(frame, 0);
    #[cfg(not(feature = "frame-alloc-audit"))]
    let _ = frame;
}

/// Transition one frame from a per-CPU free cache back to caller ownership.
#[inline]
pub(crate) fn audit_cached_alloc(frame: u64) {
    #[cfg(feature = "frame-alloc-audit")]
    audit_alloc(frame, 0);
    #[cfg(not(feature = "frame-alloc-audit"))]
    let _ = frame;
}

/// Stash the `free_frame` caller's source location for the audit's
/// double-free panic message. No-op unless `frame-alloc-audit` is set.
#[inline]
pub fn audit_note_free_caller(loc: &'static core::panic::Location<'static>) {
    #[cfg(feature = "frame-alloc-audit")]
    audit::set_free_loc(loc);
    #[cfg(not(feature = "frame-alloc-audit"))]
    let _ = loc;
}

/// Stash the allocating caller's source location so the audit can report
/// where a doubly-freed frame was allocated. No-op unless
/// `frame-alloc-audit` is set.
#[inline]
pub fn audit_note_alloc_caller(loc: &'static core::panic::Location<'static>) {
    #[cfg(feature = "frame-alloc-audit")]
    audit::set_alloc_loc(loc);
    #[cfg(not(feature = "frame-alloc-audit"))]
    let _ = loc;
}

/// Per-NUMA-node buddy zone. Stores 11 free lists (orders 0..=MAX_ORDER)
/// of frame numbers (block heads).
///
/// We index free blocks by their FRAME NUMBER (not byte address) so the
/// XOR-based buddy lookup is straightforward shifts.
#[derive(Debug)]
pub struct BuddyZone {
    /// `free_lists[M][N]` holds frame numbers of free order-N blocks
    /// belonging to migratetype `M` (see `MigrateType`). Partitioning by
    /// mobility is the anti-fragmentation mechanism: unmovable and
    /// movable free blocks are kept in separate pools so they don't
    /// checkerboard each other's contiguous regions.
    free_lists: [[Vec<u64>; NUM_ORDERS]; NUM_MIGRATE_TYPES],
    /// Total frames in this zone (free + allocated). For stats.
    total_frames: usize,
    /// Free frames in this zone (sum of `(order_frames(N) * len)` across
    /// all order-N free lists). Maintained incrementally.
    free_frames: usize,
    /// When set, this zone's alloc/free feed the global `frame-alloc-audit`
    /// map. Only the live allocator's NUMA zones opt in (via
    /// `enable_audit`); standalone unit-test zones (`BuddyZone::new` +
    /// synthetic `donate`) must NOT, since their fabricated frame numbers
    /// (e.g. 0x100) collide with the global per-frame bitmap and would
    /// false-positive as double-alloc/double-free.
    #[cfg(feature = "frame-alloc-audit")]
    audit: bool,
}

impl BuddyZone {
    pub const fn new() -> Self {
        const NEW_VEC: Vec<u64> = Vec::new();
        const NEW_ORDERS: [Vec<u64>; NUM_ORDERS] = [NEW_VEC; NUM_ORDERS];
        Self {
            free_lists: [NEW_ORDERS; NUM_MIGRATE_TYPES],
            #[cfg(feature = "frame-alloc-audit")]
            audit: false,
            total_frames: 0,
            free_frames: 0,
        }
    }

    /// Opt this zone into `frame-alloc-audit`. Called only on the live
    /// allocator's NUMA zones (see `frame::init_from_map`), never on the
    /// synthetic zones the buddy unit tests build.
    #[cfg(feature = "frame-alloc-audit")]
    #[inline]
    pub fn enable_audit(&mut self) {
        self.audit = true;
    }

    /// Record a buddy hand-out in the audit, iff this zone opted in.
    #[inline]
    fn note_alloc(&self, frame: u64, order: u8) {
        #[cfg(feature = "frame-alloc-audit")]
        if self.audit {
            audit_alloc(frame, order);
        }
        #[cfg(not(feature = "frame-alloc-audit"))]
        let _ = (frame, order);
    }

    /// Record a buddy return in the audit, iff this zone opted in.
    #[inline]
    fn note_free(&self, frame: u64, order: u8) {
        #[cfg(feature = "frame-alloc-audit")]
        if self.audit {
            audit_free(frame, order);
        }
        #[cfg(not(feature = "frame-alloc-audit"))]
        let _ = (frame, order);
    }

    /// Pre-allocate Vec capacity in every order's free list. Critical
    /// for deadlock-avoidance once the slab is the global allocator:
    /// without pre-reservation, a buddy `alloc()` that splits blocks
    /// into lower orders does `Vec::push` which may need to grow the
    /// Vec, which routes to the global allocator (now slab), which
    /// itself calls back into the buddy (`alloc_frame` for slab page
    /// growth) — and the outer caller is holding `frame::ALLOC.lock()`.
    /// Recursive lock acquisition deadlocks.
    ///
    /// Pre-allocating capacity up-front means `Vec::push` never has
    /// to grow during runtime. Total entries across all orders is
    /// bounded by `total_frames` (worst case: every frame is its own
    /// order-0 block), so reserving that much in order 0 is the
    /// pessimistic bound. Higher orders need progressively less.
    /// Cost: ~2x `total_frames * 8` bytes of capacity.
    ///
    /// MUST be called while the global allocator is still bump (i.e.
    /// before `promote_to_slab`).
    /// Bytes `reserve_growth_capacity` is about to demand from the
    /// allocator for this zone: the pessimistic per-order free-list
    /// capacity, `Σ over orders of cap * size_of::<u64>()`.
    ///
    /// The caller uses this to make sure the bootstrap arena can cover
    /// the reservation BEFORE it takes `frame::ALLOC.lock()`, since the
    /// reservation runs under that lock and must not have to go find
    /// memory while holding it. Deliberately ignores the capacity the
    /// free lists already have — over-estimating only costs a little
    /// extra headroom, whereas under-estimating reintroduces the
    /// out-of-bootstrap-memory panic this exists to prevent.
    pub fn reservation_bytes(&self) -> usize {
        if self.total_frames == 0 {
            return 0;
        }
        let mut bytes = 0usize;
        for order in 0..NUM_ORDERS {
            let cap = (self.total_frames >> order).max(64) + 64;
            // Reserved once per migratetype partition: a block may live
            // in either partition, and stealing moves it between them
            // (all under `frame::ALLOC.lock()`), so every partition needs
            // the pessimistic per-order bound to stay Vec-growth-free.
            bytes = bytes.saturating_add(cap * core::mem::size_of::<u64>() * NUM_MIGRATE_TYPES);
        }
        bytes
    }

    pub fn reserve_growth_capacity(&mut self) {
        // Empty zone: nothing donated, so nothing will ever come
        // back via free either. Skip the reservation entirely so
        // unused NUMA slots don't burn bootstrap memory.
        if self.total_frames == 0 {
            return;
        }
        for order in 0..NUM_ORDERS {
            // Pessimistic worst-case bound: every frame is its own
            // order-0 block at this order. Caps each order at the
            // natural physical maximum.
            // Reserve the PESSIMISTIC physical bound (every frame its own
            // order-N block), NOT a fixed headroom. A `Vec::push` in
            // alloc()/free() runs under `frame::ALLOC.lock()`, and if it has to
            // grow it routes to the global slab → `alloc_frame` → the same lock
            // → a recursive-lock DEADLOCK (observed: under systemd's heavy
            // fork/exec/exit churn a low-order free list outgrew a fixed 16 K
            // headroom, and the reallocation hung the CPU spinning on its own
            // lock). Reserving `physical_max` guarantees the free list can never
            // reallocate at runtime. Cost is bounded: Σ(total_frames >> order) ≈
            // 2·total_frames·8 bytes of capacity, reserved once at boot while the
            // allocator is still bump.
            let cap = (self.total_frames >> order).max(64) + 64;
            // Every migratetype partition gets the full pessimistic bound
            // so that stealing a block between partitions (which pushes to
            // the destination list under the frame lock) can never trigger
            // a `Vec` growth → slab → recursive-lock deadlock.
            for mt in 0..NUM_MIGRATE_TYPES {
                let need = cap.saturating_sub(self.free_lists[mt][order].capacity());
                if need > 0 {
                    self.free_lists[mt][order].reserve_exact(need);
                }
            }
        }
    }

    /// Donate a contiguous range of frames `[first_frame .. first_frame + frame_count)`
    /// to this zone. Splits into the largest naturally-aligned blocks
    /// the range can support.
    ///
    /// Caller must guarantee:
    ///   - The range is real, kernel-reachable RAM.
    ///   - Every frame in the range is in this zone (no boundary
    ///     crossing into another node's region).
    ///   - The range doesn't overlap any already-donated frames.
    pub fn donate(&mut self, first_frame: u64, frame_count: u64) {
        self.donate_as(first_frame, frame_count, MigrateType::Movable);
    }

    /// Donate a range, seeding it into a specific migratetype partition.
    /// Boot/hotplug RAM is seeded `Movable` (Linux marks fresh pageblocks
    /// movable) so the bulk user allocations inherit the large contiguous
    /// runs; unmovable kernel allocations steal from it on demand.
    pub fn donate_as(&mut self, first_frame: u64, frame_count: u64, mt: MigrateType) {
        let mut start = first_frame;
        let end = first_frame + frame_count;
        self.total_frames += frame_count as usize;
        self.free_frames += frame_count as usize;
        while start < end {
            // Largest order N such that:
            //   - start is aligned to (1 << N) frames
            //   - start + (1 << N) <= end
            //   - N <= MAX_ORDER
            let mut order = MAX_ORDER;
            while order > 0 {
                let block_frames = order_frames(order);
                if (start & (block_frames - 1)) == 0 && start + block_frames <= end {
                    break;
                }
                order -= 1;
            }
            self.free_lists[mt.index()][order as usize].push(start);
            start += order_frames(order);
        }
    }

    /// Whether donating this range can use the already-reserved free-list
    /// capacity. Runtime hotplug must not grow a `Vec` while the global frame
    /// lock is held because the slab allocator recurses into that lock.
    pub fn can_donate_without_growth(&self, first_frame: u64, frame_count: u64) -> bool {
        let mut needed = [0usize; NUM_ORDERS];
        let mut start = first_frame;
        let end = first_frame.saturating_add(frame_count);
        while start < end {
            let mut order = MAX_ORDER;
            while order > 0 {
                let block_frames = order_frames(order);
                if (start & (block_frames - 1)) == 0 && start + block_frames <= end {
                    break;
                }
                order -= 1;
            }
            needed[order as usize] += 1;
            start += order_frames(order);
        }
        // `donate`/`donate_as(Movable)` push into the Movable partition,
        // so that is the partition whose capacity headroom must cover the
        // range.
        let mt = MigrateType::Movable.index();
        needed.iter().enumerate().all(|(order, need)| {
            self.free_lists[mt][order].len().saturating_add(*need)
                <= self.free_lists[mt][order].capacity()
        })
    }

    /// Remove a fully-free frame range from this zone.
    ///
    /// Returns false without mutation if any frame is allocated. Free blocks
    /// crossing a range boundary are split in place; only outside fragments
    /// are returned to the lists.
    pub fn remove_free_range(&mut self, first_frame: u64, frame_count: u64) -> bool {
        if frame_count == 0 {
            return false;
        }
        let end = first_frame.saturating_add(frame_count);
        if end <= first_frame {
            return false;
        }
        let mut covered = 0u64;
        for partition in self.free_lists.iter() {
            for (order, list) in partition.iter().enumerate() {
                let span = order_frames(order as u8);
                for &block in list {
                    let overlap_lo = block.max(first_frame);
                    let overlap_hi = block.saturating_add(span).min(end);
                    if overlap_lo < overlap_hi {
                        covered = covered.saturating_add(overlap_hi - overlap_lo);
                    }
                }
            }
        }
        if covered != frame_count {
            return false;
        }

        // A block crossing the range boundary is split in place; its
        // outside fragments are returned to the SAME migratetype partition
        // they were removed from, preserving the mobility grouping.
        for mt in 0..NUM_MIGRATE_TYPES {
            for order in (0..NUM_ORDERS).rev() {
                let span = order_frames(order as u8);
                let mut index = 0;
                while index < self.free_lists[mt][order].len() {
                    let block = self.free_lists[mt][order][index];
                    let block_end = block + span;
                    if block >= end || block_end <= first_frame {
                        index += 1;
                        continue;
                    }
                    self.free_lists[mt][order].swap_remove(index);
                    Self::retain_outside_range(
                        &mut self.free_lists[mt],
                        block,
                        order as u8,
                        first_frame,
                        end,
                    );
                }
            }
        }
        self.free_frames -= frame_count as usize;
        self.total_frames -= frame_count as usize;
        true
    }

    fn retain_outside_range(
        lists: &mut [Vec<u64>; NUM_ORDERS],
        block: u64,
        order: u8,
        remove_lo: u64,
        remove_hi: u64,
    ) {
        let end = block + order_frames(order);
        if block >= remove_lo && end <= remove_hi {
            return;
        }
        if end <= remove_lo || block >= remove_hi {
            lists[order as usize].push(block);
            return;
        }
        debug_assert!(order > 0);
        let child_order = order - 1;
        let half = order_frames(child_order);
        Self::retain_outside_range(lists, block, child_order, remove_lo, remove_hi);
        Self::retain_outside_range(lists, block + half, child_order, remove_lo, remove_hi);
    }

    /// Allocate a block of `order` frames for the default (`Unmovable`)
    /// migratetype. Splits a higher-order block if necessary; pushes the
    /// unused half back to the next-lower order's list. Returns `None` on
    /// exhaustion.
    ///
    /// Most kernel call sites want unmovable memory (page tables, slab,
    /// DMA), so this is the conservative default. User-backing allocations
    /// should call [`BuddyZone::alloc_mt`] with `MigrateType::Movable` to
    /// keep those pages clustered away from the unmovable pool.
    pub fn alloc(&mut self, order: u8) -> Option<u64> {
        self.alloc_mt(order, MigrateType::Unmovable)
    }

    /// Allocate a block of `order` frames of migratetype `mt`.
    ///
    /// Serves the request from `mt`'s own partition first. If that
    /// partition has no block at or above `order`, it steals from the next
    /// migratetype in `FALLBACK_ORDER` — the whole higher-order block is
    /// migrated into `mt`'s partition as it is split down, so future frees
    /// of the returned block land back in `mt` (Linux's steal-the-whole-
    /// block heuristic, which prevents a single steal from permanently
    /// scattering the donor pool).
    pub fn alloc_mt(&mut self, order: u8, mt: MigrateType) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        for &src_mt in &FALLBACK_ORDER[mt.index()] {
            if let Some(frame) = self.alloc_within(order, src_mt, mt) {
                return Some(frame);
            }
        }
        None
    }

    /// Try to satisfy an order-`order` request by splitting a block from
    /// the `src_mt` partition, placing all split-off buddies (and the
    /// returned block's accounting) into the `dst_mt` partition. When
    /// `src_mt == dst_mt` this is the ordinary same-partition split; when
    /// they differ it is a cross-migratetype steal.
    fn alloc_within(&mut self, order: u8, src_mt: MigrateType, dst_mt: MigrateType) -> Option<u64> {
        // Walk up to find a non-empty list at order >= requested in the
        // source partition.
        let mut found_order = order;
        while found_order <= MAX_ORDER {
            if !self.free_lists[src_mt.index()][found_order as usize].is_empty() {
                break;
            }
            found_order += 1;
        }
        if found_order > MAX_ORDER {
            return None;
        }
        let frame = self.free_lists[src_mt.index()][found_order as usize].pop()?;
        // Split down to the requested order. Each split halves a block:
        // keep the lower half for the caller, push the upper half onto the
        // DESTINATION partition's lower-order free list so the entire
        // stolen block converts to `dst_mt`.
        while found_order > order {
            found_order -= 1;
            let buddy = frame + order_frames(found_order);
            self.free_lists[dst_mt.index()][found_order as usize].push(buddy);
        }
        self.free_frames -= order_frames(order) as usize;
        self.note_alloc(frame, order);
        Some(frame)
    }

    /// Allocate from this zone subject to a frame-number ceiling.
    /// `max_frame_no_excl` is the first frame number we WON'T return.
    /// Used to honor `EARLY_PHYS_CEILING` (e.g., 4 GiB during early
    /// boot). Walks the order-N free list looking for a block whose
    /// END frame fits below the ceiling.
    pub fn alloc_below(&mut self, order: u8, max_frame_no_excl: u64) -> Option<u64> {
        self.alloc_below_mt(order, max_frame_no_excl, MigrateType::Unmovable)
    }

    /// Ceiling-constrained allocation of migratetype `mt`. Searches `mt`'s
    /// own partition first, then steals from the fallback migratetype; a
    /// stolen block's split-off buddies are placed into `mt`'s partition,
    /// mirroring [`BuddyZone::alloc_mt`].
    pub fn alloc_below_mt(
        &mut self,
        order: u8,
        max_frame_no_excl: u64,
        mt: MigrateType,
    ) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        let need = order_frames(order);
        for &src_mt in &FALLBACK_ORDER[mt.index()] {
            // Try the exact-order list first (fast path).
            if let Some(idx) = self.find_below(order, max_frame_no_excl, src_mt) {
                let frame = self.free_lists[src_mt.index()][order as usize].swap_remove(idx);
                self.free_frames -= need as usize;
                self.note_alloc(frame, order);
                return Some(frame);
            }
            // Fallback: walk higher orders for a block whose lower half
            // fits under the ceiling, then split repeatedly, converting the
            // block to `mt`.
            for src in (order + 1)..=MAX_ORDER {
                if let Some(idx) = self.find_below(src, max_frame_no_excl, src_mt) {
                    let frame = self.free_lists[src_mt.index()][src as usize].swap_remove(idx);
                    let mut cur = src;
                    while cur > order {
                        cur -= 1;
                        let buddy = frame + order_frames(cur);
                        self.free_lists[mt.index()][cur as usize].push(buddy);
                    }
                    self.free_frames -= need as usize;
                    self.note_alloc(frame, order);
                    return Some(frame);
                }
            }
        }
        None
    }

    /// Find the index of a block at `order` in the `mt` partition whose
    /// END falls below `max_frame_no_excl`. Linear scan of the order's
    /// free list.
    fn find_below(&self, order: u8, max_frame_no_excl: u64, mt: MigrateType) -> Option<usize> {
        let blk = order_frames(order);
        self.free_lists[mt.index()][order as usize]
            .iter()
            .position(|&f| f + blk <= max_frame_no_excl)
    }

    /// Free a block at `frame` of `order` into the default (`Unmovable`)
    /// partition, coalescing with its buddy upward as long as the buddy is
    /// also free WITHIN THE SAME PARTITION.
    pub fn free(&mut self, frame: u64, order: u8) {
        self.free_mt(frame, order, MigrateType::Unmovable);
    }

    /// Free a block at `frame` of `order` into migratetype `mt`'s
    /// partition. Coalescing only merges a buddy that is free in the same
    /// partition, so unmovable and movable blocks never merge across the
    /// mobility boundary — that is what keeps each class's contiguous
    /// regions intact.
    pub fn free_mt(&mut self, frame: u64, order: u8, mt: MigrateType) {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        self.note_free(frame, order);
        self.free_inner(frame, order, mt);
    }

    /// Return a block that was already recorded free while resident in a
    /// per-CPU cache. This updates/coalesces buddy metadata without emitting a
    /// second audit transition. Cached frames are order-0 base pages fed by
    /// the order-0 fast path; they rejoin the `Unmovable` partition.
    pub(crate) fn free_cached(&mut self, frame: u64, order: u8) {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        self.free_inner(frame, order, MigrateType::Unmovable);
    }

    fn free_inner(&mut self, frame: u64, order: u8, mt: MigrateType) {
        self.free_frames += order_frames(order) as usize;
        let mt = mt.index();
        let mut cur_order = order;
        let mut cur_frame = frame;
        while cur_order < MAX_ORDER {
            let buddy = buddy_of(cur_frame, cur_order);
            // Look for buddy in the same-order free list of the SAME
            // migratetype partition. A buddy of a different migratetype is
            // deliberately not merged.
            if let Some(idx) = self.free_lists[mt][cur_order as usize]
                .iter()
                .position(|&f| f == buddy)
            {
                self.free_lists[mt][cur_order as usize].swap_remove(idx);
                // Coalesced block starts at min(cur_frame, buddy).
                cur_frame = cur_frame.min(buddy);
                cur_order += 1;
                continue;
            }
            break;
        }
        self.free_lists[mt][cur_order as usize].push(cur_frame);
    }

    /// Number of free frames in this zone (sum across all orders).
    pub fn free_frame_count(&self) -> usize {
        self.free_frames
    }

    /// Number of free buddy blocks at `order` (not base pages), summed
    /// across every migratetype partition.
    pub fn free_block_count(&self, order: u8) -> usize {
        (0..NUM_MIGRATE_TYPES)
            .map(|mt| self.free_block_count_mt(order, MigrateType::from_index(mt)))
            .sum()
    }

    /// Number of free buddy blocks at `order` in migratetype `mt`'s
    /// partition. Used by `/proc/pagetypeinfo` and the anti-fragmentation
    /// tests.
    pub fn free_block_count_mt(&self, order: u8, mt: MigrateType) -> usize {
        self.free_lists[mt.index()]
            .get(order as usize)
            .map_or(0, alloc::vec::Vec::len)
    }

    /// Diagnostic: walk every free-list entry and confirm no frame
    /// is covered by more than one block (across all orders).
    ///
    /// Returns `Ok(())` if the buddy state is internally consistent,
    /// or `Err((frame_no, order_a, order_b))` describing the first
    /// overlap found.
    ///
    /// No-alloc O(N²) so it can run from inside the buddy lock
    /// without deadlocking through the slab. Used by the smoke-test
    /// runner to pinpoint corruption.
    /// Overlap-check spans every migratetype partition: a frame covered by
    /// both an unmovable and a movable free block would be a real
    /// double-free bug, so the two pools are compared against each other,
    /// not just within a partition.
    pub fn validate_no_overlap(&self) -> Result<(), (u64, u8, u8)> {
        // Compare every (partition_a, order_a, block_a) against every
        // strictly-later (partition_b, order_b, block_b) in a single flat
        // ordering keyed by (mt, order, index). No allocation.
        for mta in 0..NUM_MIGRATE_TYPES {
            for oa in 0..NUM_ORDERS {
                let span_a = order_frames(oa as u8);
                for (ia, &sa) in self.free_lists[mta][oa].iter().enumerate() {
                    let ea = sa + span_a;
                    // Remaining entries in the SAME (mt, order) list.
                    for &sb in self.free_lists[mta][oa][ia + 1..].iter() {
                        let eb = sb + span_a;
                        if sa < eb && sb < ea {
                            return Err((sa.max(sb), oa as u8, oa as u8));
                        }
                    }
                    // Higher orders in the SAME partition.
                    for ob in (oa + 1)..NUM_ORDERS {
                        let span_b = order_frames(ob as u8);
                        for &sb in self.free_lists[mta][ob].iter() {
                            let eb = sb + span_b;
                            if sa < eb && sb < ea {
                                return Err((sa.max(sb), oa as u8, ob as u8));
                            }
                        }
                    }
                    // Every order in every LATER partition.
                    for mtb in (mta + 1)..NUM_MIGRATE_TYPES {
                        for ob in 0..NUM_ORDERS {
                            let span_b = order_frames(ob as u8);
                            for &sb in self.free_lists[mtb][ob].iter() {
                                let eb = sb + span_b;
                                if sa < eb && sb < ea {
                                    return Err((sa.max(sb), oa as u8, ob as u8));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Number of total frames donated to this zone.
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }

    /// Move every free block to another zone where `predicate` is
    /// true. Used by `rebalance_to_topology` to reassign zone 0
    /// across NUMA nodes.
    ///
    /// Implemented as in-place swap-removal so we don't allocate
    /// temporary Vecs — the global allocator may itself call back
    /// into the buddy (slab refill), and we're holding the
    /// frame-allocator lock for the duration. Allocating here
    /// would recurse and deadlock.
    pub fn drain_into(&mut self, dest: &mut BuddyZone, predicate: impl Fn(u64) -> bool) {
        for mt in 0..NUM_MIGRATE_TYPES {
            for order in 0..NUM_ORDERS {
                let mut i = 0;
                while i < self.free_lists[mt][order].len() {
                    let frame = self.free_lists[mt][order][i];
                    if predicate(frame) {
                        self.free_lists[mt][order].swap_remove(i);
                        let block_frames = order_frames(order as u8) as usize;
                        self.free_frames -= block_frames;
                        self.total_frames -= block_frames;
                        // Preserve the migratetype grouping across the move.
                        dest.free_lists[mt][order].push(frame);
                        dest.free_frames += block_frames;
                        dest.total_frames += block_frames;
                        // Don't increment i — swap_remove pulled a
                        // new element into position i.
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }
}

impl Default for BuddyZone {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a `PhysFrame` to its frame number for buddy lookup.
#[inline]
pub fn frame_no(f: PhysFrame) -> u64 {
    f.start_address().raw() >> PAGE_SHIFT
}

/// Convert a frame number back to a `PhysFrame`.
#[inline]
pub fn frame_from_no(no: u64) -> PhysFrame {
    PhysFrame::new(PhysAddr::new(no << PAGE_SHIFT))
}

/// Returns the `EARLY_PHYS_CEILING` interpreted as a frame-number
/// limit. Returns `u64::MAX` (no limit) when the ceiling is 0.
#[inline]
pub(crate) fn early_ceiling_frame() -> u64 {
    let bytes = EARLY_PHYS_CEILING.load(Ordering::Acquire);
    if bytes == 0 {
        u64::MAX
    } else {
        bytes >> PAGE_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_bytes_grows_geometrically() {
        assert_eq!(order_bytes(0), 4096);
        assert_eq!(order_bytes(1), 8192);
        assert_eq!(order_bytes(10), 4 * 1024 * 1024);
    }

    #[test]
    fn remove_free_range_splits_boundary_blocks() {
        let mut zone = BuddyZone::new();
        zone.donate(0x1000, 16);
        assert!(zone.remove_free_range(0x1004, 4));
        assert_eq!(zone.total_frame_count(), 12);
        assert_eq!(zone.free_frame_count(), 12);
        for _ in 0..12 {
            let frame = zone.alloc(0).expect("outside frame");
            assert!(!(0x1004..0x1008).contains(&frame));
        }
        assert!(zone.alloc(0).is_none());
    }

    #[test]
    fn remove_free_range_rejects_allocated_frame_without_mutation() {
        let mut zone = BuddyZone::new();
        zone.donate(0x2000, 8);
        let allocated = zone.alloc(0).expect("allocation");
        assert!(!zone.remove_free_range(0x2000, 8));
        assert_eq!(zone.total_frame_count(), 8);
        assert_eq!(zone.free_frame_count(), 7);
        zone.free(allocated, 0);
        assert!(zone.remove_free_range(0x2000, 8));
    }

    #[test]
    fn buddy_xor_property() {
        // Frame 0 + frame 1 are buddies at order 0.
        assert_eq!(buddy_of(0, 0), 1);
        assert_eq!(buddy_of(1, 0), 0);
        // Frames 0 + 2 are buddies at order 1.
        assert_eq!(buddy_of(0, 1), 2);
        assert_eq!(buddy_of(2, 1), 0);
        // Frames 0 + 1024 are buddies at order 10.
        assert_eq!(buddy_of(0, 10), 1024);
        assert_eq!(buddy_of(1024, 10), 0);
    }

    #[test]
    fn donate_carves_largest_aligned_blocks() {
        let mut z = BuddyZone::new();
        // 1024 frames starting at frame 0 = single order-10 block.
        // `donate` seeds the Movable partition (fresh RAM is movable).
        z.donate(0, 1024);
        assert_eq!(z.free_lists[MigrateType::Movable.index()][10].len(), 1);
        assert_eq!(z.free_lists[MigrateType::Movable.index()][10][0], 0);
        for o in 0..10 {
            assert!(z.free_lists[MigrateType::Movable.index()][o].is_empty());
        }
        assert_eq!(z.free_frame_count(), 1024);
    }

    #[test]
    fn donate_misaligned_splits_into_smaller_blocks() {
        let mut z = BuddyZone::new();
        // 6 frames at frame 1: forced to use smaller orders.
        z.donate(1, 6);
        // Frame 1: order-0 (1 frame) → frame 1
        // Frame 2: order-1 (2 frames) → frames 2..4
        // Frame 4: order-1 (2 frames) → frames 4..6
        // Frame 6: order-0 (1 frame) → frame 6
        let mv = MigrateType::Movable.index();
        assert_eq!(z.free_lists[mv][0].len(), 2); // frames 1 and 6
        assert_eq!(z.free_lists[mv][1].len(), 2); // frames 2 and 4
        assert_eq!(z.free_frame_count(), 6);
    }

    #[test]
    fn alloc_then_free_round_trip() {
        let mut z = BuddyZone::new();
        z.donate(0, 1024);
        let f = z.alloc(0).unwrap();
        assert_eq!(z.free_frame_count(), 1023);
        z.free(f, 0);
        assert_eq!(z.free_frame_count(), 1024);
        // After full coalesce, we should be back to 1 order-10 block.
        // `alloc(0)` (Unmovable) stole and converted the whole block to
        // Unmovable, so it coalesces back there — sum across partitions.
        assert_eq!(z.free_block_count(10), 1);
    }

    #[test]
    fn alloc_higher_order_succeeds_and_splits() {
        let mut z = BuddyZone::new();
        z.donate(0, 1024);
        // Ask for order 0; should split the order-10 block all the
        // way down, returning frame 0 and pushing buddies back.
        let f = z.alloc(0).unwrap();
        assert_eq!(f, 0);
        // After this, we should have a free block at every order
        // from 0 to 9 (the buddies that were pushed back). They live in
        // the Unmovable partition since `alloc(0)` stole the block there.
        for o in 0..=9 {
            assert_eq!(z.free_block_count(o), 1, "order {} should have 1 block", o);
        }
        assert_eq!(z.free_block_count(10), 0);
        assert_eq!(z.free_frame_count(), 1023);
    }

    #[test]
    fn alloc_exhaustion_returns_none() {
        let mut z = BuddyZone::new();
        z.donate(0, 4);
        // Two order-1 blocks (4 frames). Alloc both at order 1.
        assert!(z.alloc(1).is_some());
        assert!(z.alloc(1).is_some());
        assert!(z.alloc(1).is_none());
        // But we can still alloc smaller... wait, no, we exhausted everything.
        assert!(z.alloc(0).is_none());
    }

    #[test]
    fn coalesce_after_free_buddy() {
        let mut z = BuddyZone::new();
        z.donate(0, 4); // 1 order-2 block (frames 0..4)
                        // Allocate two order-0 blocks (frames 0 and 1 should be
                        // siblings after splitting all the way down).
        let a = z.alloc(0).unwrap();
        let b = z.alloc(0).unwrap();
        // Free both; they should coalesce back up.
        z.free(a, 0);
        z.free(b, 0);
        assert_eq!(z.free_frame_count(), 4);
        // After full coalesce, only the order-2 block remains.
        assert_eq!(z.free_block_count(2), 1);
        for o in [0, 1] {
            assert_eq!(z.free_block_count(o), 0);
        }
    }

    #[test]
    fn alloc_below_ceiling_picks_low_block() {
        let mut z = BuddyZone::new();
        // Two order-10 blocks: one at frame 0 (low), one at frame
        // 1_000_000 (above any 4-GiB-equivalent ceiling).
        z.donate(0, 1024);
        z.donate(1_000_000, 1024);
        // Ceiling at frame 2048 (just above the low block).
        let f = z.alloc_below(0, 2048).unwrap();
        assert!(f < 2048);
    }
}
