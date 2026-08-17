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
//    of the SAME order N (i.e., neither has been further split).

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
    /// `free_lists[N]` holds frame numbers of free blocks of order N.
    free_lists: [Vec<u64>; NUM_ORDERS],
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
        Self {
            free_lists: [NEW_VEC; NUM_ORDERS],
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
            bytes = bytes.saturating_add(cap * core::mem::size_of::<u64>());
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
            let need = cap.saturating_sub(self.free_lists[order].capacity());
            if need > 0 {
                self.free_lists[order].reserve_exact(need);
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
            self.free_lists[order as usize].push(start);
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
        needed.iter().enumerate().all(|(order, need)| {
            self.free_lists[order].len().saturating_add(*need) <= self.free_lists[order].capacity()
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
        for (order, list) in self.free_lists.iter().enumerate() {
            let span = order_frames(order as u8);
            for &block in list {
                let overlap_lo = block.max(first_frame);
                let overlap_hi = block.saturating_add(span).min(end);
                if overlap_lo < overlap_hi {
                    covered = covered.saturating_add(overlap_hi - overlap_lo);
                }
            }
        }
        if covered != frame_count {
            return false;
        }

        for order in (0..NUM_ORDERS).rev() {
            let span = order_frames(order as u8);
            let mut index = 0;
            while index < self.free_lists[order].len() {
                let block = self.free_lists[order][index];
                let block_end = block + span;
                if block >= end || block_end <= first_frame {
                    index += 1;
                    continue;
                }
                self.free_lists[order].swap_remove(index);
                Self::retain_outside_range(
                    &mut self.free_lists,
                    block,
                    order as u8,
                    first_frame,
                    end,
                );
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

    /// Allocate a block of `order` frames. Splits a higher-order
    /// block if necessary; pushes the unused half back to the
    /// next-lower order's list. Returns `None` on exhaustion.
    pub fn alloc(&mut self, order: u8) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        // Walk up to find a non-empty list at order >= requested.
        let mut found_order = order;
        while found_order <= MAX_ORDER {
            if !self.free_lists[found_order as usize].is_empty() {
                break;
            }
            found_order += 1;
        }
        if found_order > MAX_ORDER {
            return None;
        }
        let frame = self.free_lists[found_order as usize].pop()?;
        // Split down to the requested order. Each split halves a
        // block: keep the lower half for the caller, push the
        // upper half onto the lower order's free list.
        while found_order > order {
            found_order -= 1;
            let buddy = frame + order_frames(found_order);
            self.free_lists[found_order as usize].push(buddy);
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
        if order > MAX_ORDER {
            return None;
        }
        let need = order_frames(order);
        // Try the exact-order list first (fast path).
        if let Some(idx) = self.find_below(order, max_frame_no_excl) {
            let frame = self.free_lists[order as usize].swap_remove(idx);
            self.free_frames -= need as usize;
            self.note_alloc(frame, order);
            return Some(frame);
        }
        // Fallback: walk higher orders for a block whose lower half
        // fits under the ceiling, then split repeatedly.
        for src in (order + 1)..=MAX_ORDER {
            if let Some(idx) = self.find_below(src, max_frame_no_excl) {
                let frame = self.free_lists[src as usize].swap_remove(idx);
                let mut cur = src;
                while cur > order {
                    cur -= 1;
                    let buddy = frame + order_frames(cur);
                    self.free_lists[cur as usize].push(buddy);
                }
                self.free_frames -= need as usize;
                self.note_alloc(frame, order);
                return Some(frame);
            }
        }
        None
    }

    /// Find the index of a block at `order` whose END falls below
    /// `max_frame_no_excl`. Linear scan of the order's free list.
    fn find_below(&self, order: u8, max_frame_no_excl: u64) -> Option<usize> {
        let blk = order_frames(order);
        self.free_lists[order as usize]
            .iter()
            .position(|&f| f + blk <= max_frame_no_excl)
    }

    /// Free a block at `frame` of `order`, attempting to coalesce
    /// with its buddy upward as long as the buddy is also free.
    pub fn free(&mut self, frame: u64, order: u8) {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        self.note_free(frame, order);
        self.free_inner(frame, order);
    }

    /// Return a block that was already recorded free while resident in a
    /// per-CPU cache. This updates/coalesces buddy metadata without emitting a
    /// second audit transition.
    pub(crate) fn free_cached(&mut self, frame: u64, order: u8) {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        self.free_inner(frame, order);
    }

    fn free_inner(&mut self, frame: u64, order: u8) {
        self.free_frames += order_frames(order) as usize;
        let mut cur_order = order;
        let mut cur_frame = frame;
        while cur_order < MAX_ORDER {
            let buddy = buddy_of(cur_frame, cur_order);
            // Look for buddy in the same-order free list.
            if let Some(idx) = self.free_lists[cur_order as usize]
                .iter()
                .position(|&f| f == buddy)
            {
                self.free_lists[cur_order as usize].swap_remove(idx);
                // Coalesced block starts at min(cur_frame, buddy).
                cur_frame = cur_frame.min(buddy);
                cur_order += 1;
                continue;
            }
            break;
        }
        self.free_lists[cur_order as usize].push(cur_frame);
    }

    /// Number of free frames in this zone (sum across all orders).
    pub fn free_frame_count(&self) -> usize {
        self.free_frames
    }

    /// Number of free buddy blocks at `order` (not base pages).
    pub fn free_block_count(&self, order: u8) -> usize {
        self.free_lists
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
    pub fn validate_no_overlap(&self) -> Result<(), (u64, u8, u8)> {
        for oa in 0..NUM_ORDERS {
            let span_a = order_frames(oa as u8);
            for (ia, &sa) in self.free_lists[oa].iter().enumerate() {
                let ea = sa + span_a;
                // Other entries at the same order, after index ia.
                for &sb in self.free_lists[oa][ia + 1..].iter() {
                    let eb = sb + span_a;
                    if sa < eb && sb < ea {
                        return Err((sa.max(sb), oa as u8, oa as u8));
                    }
                }
                // Entries at any higher order.
                for ob in (oa + 1)..NUM_ORDERS {
                    let span_b = order_frames(ob as u8);
                    for &sb in self.free_lists[ob].iter() {
                        let eb = sb + span_b;
                        if sa < eb && sb < ea {
                            return Err((sa.max(sb), oa as u8, ob as u8));
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
        for order in 0..NUM_ORDERS {
            let mut i = 0;
            while i < self.free_lists[order].len() {
                let frame = self.free_lists[order][i];
                if predicate(frame) {
                    self.free_lists[order].swap_remove(i);
                    let block_frames = order_frames(order as u8) as usize;
                    self.free_frames -= block_frames;
                    self.total_frames -= block_frames;
                    dest.free_lists[order].push(frame);
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
        z.donate(0, 1024);
        assert_eq!(z.free_lists[10].len(), 1);
        assert_eq!(z.free_lists[10][0], 0);
        for o in 0..10 {
            assert!(z.free_lists[o].is_empty());
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
        assert_eq!(z.free_lists[0].len(), 2); // frames 1 and 6
        assert_eq!(z.free_lists[1].len(), 2); // frames 2 and 4
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
        assert_eq!(z.free_lists[10].len(), 1);
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
        // from 0 to 9 (the buddies that were pushed back).
        for o in 0..=9 {
            assert_eq!(z.free_lists[o].len(), 1, "order {} should have 1 block", o);
        }
        assert_eq!(z.free_lists[10].len(), 0);
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
        assert_eq!(z.free_lists[2].len(), 1);
        for o in [0, 1] {
            assert!(z.free_lists[o].is_empty());
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
