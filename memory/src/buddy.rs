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
// Provenance of later additions: the per-frame free-state index (the
// `FrameStateIndex` section below and the `list_*` helpers that keep it in
// step with the free lists) was added after the GPL-2.0-or-later relicense,
// by an author who had read Linux `mm/page_alloc.c` while reshaping the
// per-CPU frame caches in `frame.rs`. It is not a port — Linux links free
// pages through `struct page`, this indexes positions in the existing lists —
// but the clean-room statement above describes the original allocator only.
//
// Design summary (per `heap-migration.md` §3.1):
// - Per-NUMA-node, per-order free lists.
// - Orders 0..=10 (4 KiB to 4 MiB).
// - Coalesce on free by checking the buddy frame's free state: one load of
//   the buddy's state word once the zone is indexed (see "Per-frame free
//   state"), a scan of the order's free list before that.
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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::OnceLock;

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

// ── Per-frame free state ────────────────────────────────────────────────
//
// One word per managed frame recording where the frame is while it is FREE —
// NARF's counterpart of the buddy fields of Linux's `struct page`
// (`PageBuddy` + `buddy_order` + the free-list linkage, and `pcp_list`):
//
//   0                    not a free-block head and not cached: the frame is
//                        allocated, or it is an interior frame of a free block.
//   block(node, mt, k, i) head of a free order-`k` block, entry `i` of
//                        `free_lists[mt][k]` in node `node`'s zone.
//   cached(next)         resident in a per-CPU frame cache; `next` is the next
//                        frame on that cache's list.
//
// With it, "is this block's buddy free, and where is it on its list" is one
// load instead of a search of the list, so returning a block costs O(orders)
// however many blocks are free. Before the index existed every free scanned
// its order's free list for the buddy; with a few hundred thousand order-0
// blocks listed, one large `munmap` spent tens of seconds there with
// interrupts off.
//
// Ownership: a word is written only by whoever currently holds the frame's
// free state — the zone that lists the block, under that zone's lock, or the
// per-CPU cache that holds the frame, under that cache's lock. A zone also
// READS the word of a block's buddy, which another zone or a cache may own;
// that is why the words are atomics, and why a block word carries its node: a
// word some other owner wrote can never compare equal to the reader's own
// `block(node, ..)` tag, so it reads as "not free here" and nothing is merged.
// An allocated frame's word is 0 and nobody writes it, which is also what
// makes a second free of the same frame detectable.
//
// Storage is sparse, like Linux's SPARSEMEM sections: a fixed root table
// covering the whole 52-bit physical space, second-level tables allocated per
// 512 GiB that holds RAM, and 128 MiB sections of words installed only for
// ranges the allocator manages. Tables and sections are published through
// `OnceLock`s and never removed, so a lookup takes no lock. A frame with no
// section has no word; the zone then falls back to scanning its list for that
// frame (the pre-index behaviour), and the frame cache declines to hold it.

/// log2 of the frames one index section covers (128 MiB of RAM — also the
/// logical memory-block size, so a hot-plugged block maps to whole sections).
pub(crate) const STATE_SECTION_SHIFT: u32 = 15;
/// Frames (and state words) per index section.
pub(crate) const STATE_SECTION_FRAMES: usize = 1 << STATE_SECTION_SHIFT;
/// log2 of the sections one second-level table covers (512 GiB of RAM).
const STATE_TABLE_SHIFT: u32 = 12;
const STATE_TABLE_LEN: usize = 1 << STATE_TABLE_SHIFT;
/// Root entries: `2^13` tables of `2^12` sections of `2^15` frames is `2^40`
/// frames, every frame a 52-bit physical address can name.
const STATE_ROOT_LEN: usize = 1 << 13;

/// Low bits of a state word: 0 = none, `order + 1` = free-block head,
/// `STATE_KIND_CACHED` = in a per-CPU cache.
const STATE_KIND_MASK: u64 = 0xF;
const STATE_KIND_CACHED: u64 = 0xF;
const STATE_MT_SHIFT: u32 = 4;
const STATE_NODE_SHIFT: u32 = 6;
/// Bits above the tag: the list position (block) or the next frame (cached).
const STATE_PAYLOAD_SHIFT: u32 = 12;

// A free block never crosses a section, so a block head and every frame of the
// block share one section (and so share whether they have state words).
const _: () = assert!((MAX_ORDER as u32) <= STATE_SECTION_SHIFT);
const _: () = assert!((MAX_ORDER as u64) + 1 < STATE_KIND_CACHED);
const _: () = assert!(NUM_MIGRATE_TYPES <= 1 << (STATE_NODE_SHIFT - STATE_MT_SHIFT));
const _: () =
    assert!(crate::frame::MAX_NUMA_NODES <= 1 << (STATE_PAYLOAD_SHIFT - STATE_NODE_SHIFT));

// ── Allocated frames (Linux page flags / compound head-tail state) ─────
//
// A frame handed out also carries a word, with kind bits 0: the head of a
// live order-N block (`STATE_ALLOC`, N in bits 6..12) or a tail frame of one
// (`STATE_TAIL`). The free of a block must name its head with its order. A
// free of a tail ("tail of a live order-N block"), of a frame whose word is
// 0 ("not allocated" — inside a free buddy block, or never handed out), or
// of a head with another order, is refused and reported, as Linux's
// `free_pages_prepare` reports a `bad_page`. Frames that were already
// allocated when the index was enabled at boot carry `STATE_LEGACY`: their
// order is unknown, so any order is accepted for them.
const STATE_ALLOC: u64 = 1 << 4;
const STATE_TAIL: u64 = 1 << 5;
const ALLOC_ORDER_SHIFT: u32 = 6;
const ALLOC_ORDER_UNKNOWN: u64 = 0x3F;
/// Word of a frame allocated before the index existed (order unknown).
pub(crate) const STATE_LEGACY: u64 = STATE_ALLOC | (ALLOC_ORDER_UNKNOWN << ALLOC_ORDER_SHIFT);

/// Word of the head of a live order-`order` block.
#[inline]
pub(crate) const fn alloc_head_state(order: u8) -> u64 {
    STATE_ALLOC | ((order as u64) << ALLOC_ORDER_SHIFT)
}

/// Why a free was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum FreeRefusal {
    /// The frame heads a free block or sits in a per-CPU cache.
    AlreadyFree,
    /// The frame is a tail of a live block; only its head may be freed.
    TailOfLiveBlock,
    /// The frame is not allocated: inside a free block, or never handed out.
    NotAllocated,
    /// The frame heads a live block of another order.
    OrderMismatch(u8),
}

impl FreeRefusal {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            FreeRefusal::AlreadyFree => "already free (free-block head or cached)",
            FreeRefusal::TailOfLiveBlock => "tail of a live block",
            FreeRefusal::NotAllocated => "not allocated (inside a free block, or never handed out)",
            FreeRefusal::OrderMismatch(_) => "head of a live block of another order",
        }
    }
}

/// Judge freeing an order-`order` block whose head word is `state`.
#[inline]
pub(crate) const fn judge_free(state: u64, order: u8) -> Result<(), FreeRefusal> {
    if state & STATE_KIND_MASK != 0 {
        return Err(FreeRefusal::AlreadyFree);
    }
    if state & STATE_TAIL != 0 {
        return Err(FreeRefusal::TailOfLiveBlock);
    }
    if state & STATE_ALLOC == 0 {
        return Err(FreeRefusal::NotAllocated);
    }
    let held = (state >> ALLOC_ORDER_SHIFT) & ALLOC_ORDER_UNKNOWN;
    if held != ALLOC_ORDER_UNKNOWN && held != order as u64 {
        return Err(FreeRefusal::OrderMismatch(held as u8));
    }
    Ok(())
}

/// End-of-list marker for a per-CPU cache's frame list.
pub(crate) const NO_FRAME: u64 = u64::MAX;

/// State word of a frame resident in a per-CPU cache whose list continues at
/// `next` (`NO_FRAME` for the last frame).
#[inline]
pub(crate) const fn cached_state(next: u64) -> u64 {
    STATE_KIND_CACHED | (next.wrapping_add(1) << STATE_PAYLOAD_SHIFT)
}

/// The next frame on a cache list, or `None` when `state` is not a cached
/// frame's word at all — the list has been corrupted.
#[inline]
pub(crate) const fn cached_next(state: u64) -> Option<u64> {
    if state & STATE_KIND_MASK != STATE_KIND_CACHED {
        return None;
    }
    Some((state >> STATE_PAYLOAD_SHIFT).wrapping_sub(1))
}

type StateSection = &'static [AtomicU64];
type StateTable = &'static [OnceLock<StateSection>];

/// Sparse table of per-frame free-state words. See the section comment above.
pub(crate) struct FrameStateIndex {
    root: [OnceLock<StateTable>; STATE_ROOT_LEN],
    /// `frame-poison-check`: free frames hold the poison pattern; a frame is
    /// poisoned as its word turns free and verified as it turns allocated.
    #[cfg(feature = "frame-poison-check")]
    check_contents: core::sync::atomic::AtomicBool,
}

impl FrameStateIndex {
    pub(crate) const fn new() -> Self {
        Self {
            root: [const { OnceLock::new() }; STATE_ROOT_LEN],
            #[cfg(feature = "frame-poison-check")]
            check_contents: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// `frame-poison-check`: from now on poison every block whose word turns
    /// free and verify it as it turns allocated. The caller has poisoned every
    /// block that is free at this point ([`BuddyZone::poison_free_blocks`]).
    #[cfg(feature = "frame-poison-check")]
    pub(crate) fn enable_content_check(&self) {
        self.check_contents.store(true, Ordering::Release);
    }

    /// Whether free blocks of this index must hold the poison pattern.
    #[cfg(feature = "frame-poison-check")]
    #[inline]
    fn checks_contents(&self) -> bool {
        self.check_contents.load(Ordering::Acquire)
    }

    /// The state word of `frame`, or `None` when no section covers it.
    #[inline]
    pub(crate) fn slot(&self, frame: u64) -> Option<&'static AtomicU64> {
        let section = frame >> STATE_SECTION_SHIFT;
        let table: StateTable = self
            .root
            .get((section >> STATE_TABLE_SHIFT) as usize)?
            .get()
            .copied()?;
        let words: StateSection = table[(section as usize) & (STATE_TABLE_LEN - 1)]
            .get()
            .copied()?;
        Some(&words[(frame as usize) & (STATE_SECTION_FRAMES - 1)])
    }

    /// Mark `[frame, frame + 2^order)` as a live block: head and tails. The
    /// caller owns the block (it was just taken off a free list or cache).
    #[inline]
    pub(crate) fn mark_allocated(&self, frame: u64, order: u8) {
        let Some(head) = self.slot(frame) else {
            return;
        };
        #[cfg(feature = "frame-poison-check")]
        if self.checks_contents() {
            poison::verify(frame, order, head.load(Ordering::Acquire));
        }
        head.store(alloc_head_state(order), Ordering::Release);
        for tail in frame + 1..frame + order_frames(order) {
            if let Some(word) = self.slot(tail) {
                word.store(STATE_TAIL, Ordering::Relaxed);
            }
        }
    }

    /// Validate and claim the free of the order-`order` block at `frame`:
    /// on success its head and tail words are 0 (the caller now holds the
    /// block as free). A frame without a word is accepted unchecked. The head
    /// is claimed with one compare-exchange, so two racing frees of the same
    /// block cannot both succeed.
    #[inline]
    pub(crate) fn claim_free(&self, frame: u64, order: u8) -> Result<(), FreeRefusal> {
        let Some(head) = self.slot(frame) else {
            return Ok(());
        };
        let state = head.load(Ordering::Acquire);
        judge_free(state, order)?;
        if head
            .compare_exchange(state, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(FreeRefusal::AlreadyFree);
        }
        for tail in frame + 1..frame + order_frames(order) {
            if let Some(word) = self.slot(tail) {
                word.store(0, Ordering::Relaxed);
            }
        }
        // The block is free from here on: nothing may write it until it is
        // handed out again.
        #[cfg(feature = "frame-poison-check")]
        if self.checks_contents() {
            poison::fill(frame, order_frames(order));
        }
        Ok(())
    }

    /// Turn a live order-`order` block into `2^order` live order-0 frames
    /// (Linux `split_page`), so they can be freed one by one. `false` when
    /// `frame` does not head a live block of that order.
    pub(crate) fn split_allocated(&self, frame: u64, order: u8) -> bool {
        let Some(head) = self.slot(frame) else {
            return true;
        };
        let state = head.load(Ordering::Acquire);
        if judge_free(state, order).is_err() {
            return false;
        }
        for each in frame..frame + order_frames(order) {
            if let Some(word) = self.slot(each) {
                word.store(alloc_head_state(0), Ordering::Release);
            }
        }
        true
    }

    /// Set every word of every installed section to `value`. Boot-only: run
    /// before any zone is indexed, with nothing else using the words.
    pub(crate) fn fill(&self, value: u64) {
        for table in self.root.iter().filter_map(|table| table.get()) {
            for section in table.iter().filter_map(|section| section.get()) {
                for word in section.iter() {
                    word.store(value, Ordering::Relaxed);
                }
            }
        }
    }

    /// Whether section number `section` (`frame >> STATE_SECTION_SHIFT`) has
    /// state words.
    pub(crate) fn has_section(&self, section: u64) -> bool {
        self.slot(section << STATE_SECTION_SHIFT).is_some()
    }

    /// Give section `section` its state words. `words` must hold exactly
    /// [`STATE_SECTION_FRAMES`] zeroed entries and is kept for the kernel's
    /// lifetime. Returns `false` — leaving `words` unused — when the section
    /// already has words, lies outside the addressable range, or the
    /// second-level table could not be allocated.
    ///
    /// May allocate (the second-level table): never call it under a zone or
    /// frame-cache lock. Publishing a section does not by itself change any
    /// frame's state; a zone that may already list frames of the section must
    /// run [`BuddyZone::sync_index`] afterwards.
    pub(crate) fn install_section(&self, section: u64, words: &'static [AtomicU64]) -> bool {
        if words.len() != STATE_SECTION_FRAMES {
            return false;
        }
        debug_assert!(words.iter().all(|word| word.load(Ordering::Relaxed) == 0));
        let Some(root) = self.root.get((section >> STATE_TABLE_SHIFT) as usize) else {
            return false;
        };
        if root.get().is_none() {
            let mut entries: Vec<OnceLock<StateSection>> = Vec::new();
            if entries.try_reserve_exact(STATE_TABLE_LEN).is_err() {
                return false;
            }
            entries.resize_with(STATE_TABLE_LEN, OnceLock::new);
            // A racing installer may publish its table first; this one then
            // stays leaked and theirs is used below. Callers serialize section
            // installation (boot is single-threaded, hot-add holds the
            // hot-plug registry lock), so that is a theoretical 98 KiB.
            let table: StateTable = Box::leak(entries.into_boxed_slice());
            let _ = root.set(table);
        }
        let Some(table) = root.get().copied() else {
            return false;
        };
        table[(section as usize) & (STATE_TABLE_LEN - 1)]
            .set(words)
            .is_ok()
    }
}

// ── Free-frame poison check (frame-poison-check feature) ─────────────────
//
// Linux `CONFIG_PAGE_POISONING` / `init_on_free` + `check_poison_mem`: every
// frame is filled with a poison word as it becomes free (its state word
// leaves the allocated kinds) and verified as it is handed out again (its
// state word becomes allocated). A store into a free frame — a stale pointer
// writing after the frame's free, or a write through a frame freed while
// still in use — is reported at the hand-out with the frame, the offset and
// value of the first changed word and the words around it, then panics.
// Covers every frame with a state word: all boot RAM and hot-added RAM.
#[cfg(feature = "frame-poison-check")]
mod poison {
    use super::order_frames;

    /// The word every free frame holds (non-canonical as a pointer).
    pub(super) const WORD: u64 = 0xDEAD_BEEF_DEAD_BEEF;
    const WORDS_PER_FRAME: usize = (crate::PAGE_SIZE / 8) as usize;

    #[inline]
    fn words(frame: u64) -> *mut u64 {
        crate::PhysAddr::new(frame << 12).kernel_mut_ptr::<u64>()
    }

    /// Poison `frames` frames from `frame`. The caller owns them as free.
    pub(super) fn fill(frame: u64, frames: u64) {
        for each in frame..frame + frames {
            let dst = words(each);
            // SAFETY: a free RAM frame the caller owns (its state word was
            // just claimed free, or it sits on a free list under the zone
            // lock), reached through the kernel direct map, which covers all
            // managed RAM once the index is enabled. Writes stay in the frame.
            unsafe {
                for i in 0..WORDS_PER_FRAME {
                    core::ptr::write_volatile(dst.add(i), WORD);
                }
            }
        }
    }

    /// Verify that the free order-`order` block at `frame`, about to be
    /// handed out, still holds the poison. Panics naming the first changed
    /// word otherwise. `state` is the head's state word before the hand-out.
    pub(super) fn verify(frame: u64, order: u8, state: u64) {
        for each in frame..frame + order_frames(order) {
            let src = words(each);
            let mut changed = 0usize;
            let mut first = usize::MAX;
            let mut last = 0usize;
            for i in 0..WORDS_PER_FRAME {
                // SAFETY: as in `fill`; the block is still free, owned by the
                // allocator handing it out.
                let value = unsafe { core::ptr::read_volatile(src.add(i)) };
                if value != WORD {
                    changed += 1;
                    first = first.min(i);
                    last = i;
                }
            }
            if changed != 0 {
                report(frame, order, state, each, changed, first, last);
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn report(
        head: u64,
        order: u8,
        state: u64,
        frame: u64,
        changed: usize,
        first: usize,
        last: usize,
    ) -> ! {
        let src = words(frame);
        let start = first.saturating_sub(2);
        let mut around = [0u64; 8];
        for (k, slot) in around.iter_mut().enumerate() {
            if start + k < WORDS_PER_FRAME {
                // SAFETY: as in `verify`.
                *slot = unsafe { core::ptr::read_volatile(src.add(start + k)) };
            }
        }
        #[cfg(feature = "frame-alloc-audit")]
        let (alloc_site, free_site) = (
            super::audit::alloc_site_of(frame),
            super::audit::prior_free_site(frame),
        );
        #[cfg(not(feature = "frame-alloc-audit"))]
        let (alloc_site, free_site) = (
            ("<frame-alloc-audit off>", 0u32),
            ("<frame-alloc-audit off>", 0u32),
        );
        panic!(
            "frame-poison-check: free frame phys {:#x} (block phys {:#x} order {}, word {:#x}) \
             was written while free: {} of {} words changed, first at +{:#x} = {:#x}, last at \
             +{:#x}; words from +{:#x}: {:x?}; last alloc @ {}:{}, last free @ {}:{}",
            frame << 12,
            head << 12,
            order,
            state,
            changed,
            WORDS_PER_FRAME,
            first * 8,
            around[first - start],
            last * 8,
            start * 8,
            around,
            alloc_site.0,
            alloc_site.1,
            free_site.0,
            free_site.1,
        );
    }
}

impl core::fmt::Debug for FrameStateIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameStateIndex").finish_non_exhaustive()
    }
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

    /// Frame-number ceiling the bitmap covers (16 Mi frames = 64 GiB of
    /// physical address space, a 2 MiB bitmap). Frames above this are not
    /// tracked. A 16 GiB guest's RAM already ends past 17 GiB (the PCI hole
    /// pushes it up), beyond the 16 GiB this covered before.
    const AUDIT_FRAMES: usize = 16 * 1024 * 1024;
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

    /// True if `frame` is currently marked allocated. The demand-fault
    /// self-heal uses this to refuse re-mapping a `phys[idx]` that a racing
    /// teardown already returned to the buddy (stale-backing use-after-free).
    pub fn is_allocated(frame: u64) -> bool {
        let idx = (frame / 64) as usize;
        if idx >= WORDS {
            // Untracked high frame: assume allocated so a legit mapping outside
            // the audited window is never wrongly rejected.
            return true;
        }
        BITS[idx].load(Ordering::Relaxed) & (1u64 << (frame % 64)) != 0
    }

    /// file:line of the most recent prior free of `frame` — the op that leaked
    /// it while a region kept `phys[idx]` pointing at it.
    pub fn prior_free_site(frame: u64) -> (&'static str, u32) {
        ring_prior_free(frame)
    }

    /// file:line where `frame` was last allocated (low window only).
    pub fn alloc_site_of(frame: u64) -> (&'static str, u32) {
        alloc_site(frame)
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

/// Audit view of one physical frame: `(is_allocated, prior_free_site,
/// alloc_site)`. `None` unless `frame-alloc-audit` is compiled in. The
/// demand-fault self-heal consults this to refuse re-mapping a `phys[idx]`
/// that a racing teardown already freed, and to name the leaking free.
/// `(allocated, alloc_site, prior_free_site)` for one frame, each site a
/// `(file, line)` pair. Named so the tuple does not have to be spelled out at
/// every use — `clippy::type_complexity` rejects the inline form.
pub type FrameAuditState = Option<(bool, (&'static str, u32), (&'static str, u32))>;

#[inline]
pub fn frame_audit_state(phys: crate::PhysAddr) -> FrameAuditState {
    #[cfg(feature = "frame-alloc-audit")]
    {
        let frame = phys.raw() >> 12;
        Some((
            audit::is_allocated(frame),
            audit::prior_free_site(frame),
            audit::alloc_site_of(frame),
        ))
    }
    #[cfg(not(feature = "frame-alloc-audit"))]
    {
        let _ = phys;
        None
    }
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

/// Transition one frame from an external free pool (a per-CPU cache or an
/// exact-range reservation) back to caller ownership.
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

/// Per-zone operation counters for the allocator scale tests. Plain fields
/// behind the zone lock, so a caller holding the lock reads an exact delta for
/// its own hold. Compiled only into the kernel-test build.
#[cfg(feature = "kernel-test")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ZoneOpStats {
    /// Blocks returned to the zone (one per `free`/`free_mt`/`free_cached`).
    pub frees: u64,
    /// Blocks handed out by the zone.
    pub allocs: u64,
    /// Free-list entries examined while looking for a block's buddy.
    pub find_steps: u64,
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
    #[cfg(feature = "kernel-test")]
    op_stats: ZoneOpStats,
    /// Per-frame free-state words this zone mirrors its free lists into, once
    /// [`BuddyZone::enable_index`] has run. `None` for the live zones during
    /// early boot and for standalone test zones, which find a buddy by
    /// scanning its list instead.
    index: Option<&'static FrameStateIndex>,
    /// Node tag this zone writes into its block words (see the index notes).
    index_node: u8,
}

impl BuddyZone {
    pub const fn new() -> Self {
        const NEW_VEC: Vec<u64> = Vec::new();
        const NEW_ORDERS: [Vec<u64>; NUM_ORDERS] = [NEW_VEC; NUM_ORDERS];
        Self {
            index: None,
            index_node: 0,
            free_lists: [NEW_ORDERS; NUM_MIGRATE_TYPES],
            #[cfg(feature = "frame-alloc-audit")]
            audit: false,
            #[cfg(feature = "kernel-test")]
            op_stats: ZoneOpStats {
                frees: 0,
                allocs: 0,
                find_steps: 0,
            },
            total_frames: 0,
            free_frames: 0,
        }
    }

    /// Snapshot of this zone's operation counters (scale tests only).
    #[cfg(feature = "kernel-test")]
    #[inline]
    pub(crate) fn op_stats(&self) -> ZoneOpStats {
        self.op_stats
    }

    // ── Free lists and their index ──────────────────────────────────────
    //
    // Every change to a free list goes through `list_push`, `list_pop` or
    // `list_swap_remove`, which keep the per-frame state words in step with
    // the lists: for every listed block whose head has a state word, the word
    // is `block(node, mt, order, position)`, and no other word carries this
    // zone's node tag. `list_find` relies on exactly that.

    /// Mirror this zone's free lists into `index`, tagging its blocks with
    /// `node`. From here on a buddy lookup is one load for every frame the
    /// index covers. Must run under the zone's lock (it takes `&mut self`),
    /// after the sections for the zone's RAM have been installed.
    pub(crate) fn enable_index(&mut self, index: &'static FrameStateIndex, node: usize) {
        debug_assert!(node < crate::frame::MAX_NUMA_NODES);
        self.index = Some(index);
        self.index_node = node as u8;
        self.sync_index();
    }

    /// Rewrite the state word of every listed block. Needed once when the
    /// index is enabled, and again after a section is installed for a range
    /// this zone may already list frames of (they were pushed with no word to
    /// write). O(free blocks); no allocation.
    pub(crate) fn sync_index(&mut self) {
        let Some(index) = self.index else {
            return;
        };
        for mt in 0..NUM_MIGRATE_TYPES {
            for order in 0..NUM_ORDERS {
                for (pos, &frame) in self.free_lists[mt][order].iter().enumerate() {
                    if let Some(slot) = index.slot(frame) {
                        slot.store(self.block_state(mt, order, pos), Ordering::Relaxed);
                    }
                    // A free block's other frames carry no state: a free of
                    // one of them is a free of memory nobody owns.
                    for interior in frame + 1..frame + order_frames(order as u8) {
                        if let Some(slot) = index.slot(interior) {
                            slot.store(0, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// `frame-poison-check`: poison every listed free block that has a state
    /// word, before [`FrameStateIndex::enable_content_check`]. Under the zone
    /// lock, with the direct map covering the zone's RAM.
    #[cfg(feature = "frame-poison-check")]
    pub(crate) fn poison_free_blocks(&self) {
        let Some(index) = self.index else {
            return;
        };
        for lists in &self.free_lists {
            for (order, list) in lists.iter().enumerate() {
                for &frame in list {
                    if index.slot(frame).is_some() {
                        poison::fill(frame, order_frames(order as u8));
                    }
                }
            }
        }
    }

    /// The state word of `frame`, when this zone is indexed and a section
    /// covers the frame.
    #[inline]
    fn slot(&self, frame: u64) -> Option<&'static AtomicU64> {
        self.index?.slot(frame)
    }

    /// State word of this zone's free block at `free_lists[mt][order][pos]`.
    #[inline]
    fn block_state(&self, mt: usize, order: usize, pos: usize) -> u64 {
        (order as u64 + 1)
            | ((mt as u64) << STATE_MT_SHIFT)
            | (u64::from(self.index_node) << STATE_NODE_SHIFT)
            | ((pos as u64) << STATE_PAYLOAD_SHIFT)
    }

    /// Decode `state` as one of THIS zone's block words: `(mt, order, pos)`.
    /// `None` for an empty word, a cached frame, or another node's block.
    #[inline]
    fn own_block(&self, state: u64) -> Option<(usize, usize, usize)> {
        let kind = state & STATE_KIND_MASK;
        if kind == 0 || kind == STATE_KIND_CACHED {
            return None;
        }
        let node =
            (state >> STATE_NODE_SHIFT) & ((1 << (STATE_PAYLOAD_SHIFT - STATE_NODE_SHIFT)) - 1);
        if node != u64::from(self.index_node) {
            return None;
        }
        let mt =
            ((state >> STATE_MT_SHIFT) & ((1 << (STATE_NODE_SHIFT - STATE_MT_SHIFT)) - 1)) as usize;
        let order = (kind - 1) as usize;
        let pos = (state >> STATE_PAYLOAD_SHIFT) as usize;
        // The word is only a hint until the list agrees: a stale or foreign
        // value must never be used to index a list.
        (mt < NUM_MIGRATE_TYPES
            && order < NUM_ORDERS
            && self.free_lists[mt][order].get(pos).is_some())
        .then_some((mt, order, pos))
    }

    /// True when `frame` has a state word and it is non-zero: the frame is
    /// already the head of a free block or resident in a per-CPU cache, so
    /// freeing it now would be a double free.
    #[inline]
    fn already_free(&self, frame: u64) -> bool {
        self.slot(frame)
            .is_some_and(|slot| slot.load(Ordering::Relaxed) & STATE_KIND_MASK != 0)
    }

    #[inline]
    fn list_push(&mut self, mt: usize, order: usize, frame: u64) {
        let pos = self.free_lists[mt][order].len();
        self.free_lists[mt][order].push(frame);
        if let Some(slot) = self.slot(frame) {
            slot.store(self.block_state(mt, order, pos), Ordering::Relaxed);
        }
    }

    #[inline]
    fn list_pop(&mut self, mt: usize, order: usize) -> Option<u64> {
        let frame = self.free_lists[mt][order].pop()?;
        if let Some(slot) = self.slot(frame) {
            slot.store(0, Ordering::Relaxed);
        }
        Some(frame)
    }

    /// Remove entry `pos` of a free list in O(1): the last entry takes its
    /// place, and that entry's state word is updated to its new position.
    #[inline]
    fn list_swap_remove(&mut self, mt: usize, order: usize, pos: usize) -> u64 {
        let frame = self.free_lists[mt][order].swap_remove(pos);
        if let Some(slot) = self.slot(frame) {
            slot.store(0, Ordering::Relaxed);
        }
        if let Some(&moved) = self.free_lists[mt][order].get(pos) {
            if let Some(slot) = self.slot(moved) {
                slot.store(self.block_state(mt, order, pos), Ordering::Relaxed);
            }
        }
        frame
    }

    /// Position of `frame` on `free_lists[mt][order]`, if it is listed there.
    ///
    /// One load when the frame has a state word. Otherwise — a zone that is
    /// not indexed, or a frame no section covers — a scan of the list, which
    /// is what every lookup used to be.
    #[inline]
    fn list_find(&mut self, mt: usize, order: usize, frame: u64) -> Option<usize> {
        if let Some(slot) = self.slot(frame) {
            #[cfg(feature = "kernel-test")]
            {
                self.op_stats.find_steps += 1;
            }
            let found = self.own_block(slot.load(Ordering::Relaxed))?;
            return (found.0 == mt
                && found.1 == order
                && self.free_lists[mt][order][found.2] == frame)
                .then_some(found.2);
        }
        let found = self.free_lists[mt][order]
            .iter()
            .position(|&listed| listed == frame);
        #[cfg(feature = "kernel-test")]
        {
            let examined = found.map_or(self.free_lists[mt][order].len(), |pos| pos + 1);
            self.op_stats.find_steps += examined as u64;
        }
        found
    }

    /// Check the index against the lists: every listed block whose head has
    /// a state word must carry exactly its own `block(..)` word. Returns the
    /// first `(frame, order)` that does not. O(free blocks); no allocation.
    pub(crate) fn validate_index(&self) -> Result<(), (u64, u8)> {
        for mt in 0..NUM_MIGRATE_TYPES {
            for order in 0..NUM_ORDERS {
                for (pos, &frame) in self.free_lists[mt][order].iter().enumerate() {
                    if let Some(slot) = self.slot(frame) {
                        if slot.load(Ordering::Relaxed) != self.block_state(mt, order, pos) {
                            return Err((frame, order as u8));
                        }
                    }
                }
            }
        }
        Ok(())
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
        if let Some(index) = self.index {
            index.mark_allocated(frame, order);
        }
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
            // RAM donated once free frames are checked (hot-add) must hold
            // the poison like every other free block.
            #[cfg(feature = "frame-poison-check")]
            if self
                .index
                .is_some_and(|index| index.checks_contents() && index.slot(start).is_some())
            {
                poison::fill(start, order_frames(order));
            }
            self.list_push(mt.index(), order as usize, start);
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
        if let Some(removed) = self.remove_free_range_indexed(first_frame, end) {
            return removed;
        }
        self.remove_free_range_scan(first_frame, end)
    }

    /// The free block of this zone that contains `frame`, as
    /// `(head, order, mt, pos)`, read from the state words: a block of order
    /// `k` containing the frame can only start at the frame rounded down to
    /// `2^k`, so at most one probe per order. The outer `None` means the
    /// frame has no state word and only a list scan could answer.
    fn indexed_block_containing(&self, frame: u64) -> Option<Option<(u64, u8, usize, usize)>> {
        self.slot(frame)?;
        for order in 0..=MAX_ORDER {
            let head = frame & !(order_frames(order) - 1);
            // Same section as `frame` (see the compile-time assertion on
            // `MAX_ORDER`), so the head has a word whenever the frame does.
            let state = self.slot(head)?.load(Ordering::Relaxed);
            if let Some((mt, found_order, pos)) = self.own_block(state) {
                if found_order == order as usize && self.free_lists[mt][found_order][pos] == head {
                    return Some(Some((head, order, mt, pos)));
                }
            }
        }
        Some(None)
    }

    /// [`Self::remove_free_range`] in O(blocks in the range × orders), from
    /// the state words. `None` — with nothing changed — when part of the range
    /// has no state words; the caller then falls back to scanning the lists.
    fn remove_free_range_indexed(&mut self, first_frame: u64, end: u64) -> Option<bool> {
        // Pass 1: every frame must lie in a free block of this zone. Nothing
        // is modified until that is known, so a busy range leaves the lists
        // exactly as they were.
        let mut cursor = first_frame;
        while cursor < end {
            match self.indexed_block_containing(cursor)? {
                Some((head, order, _, _)) => cursor = head + order_frames(order),
                None => return Some(false),
            }
        }
        // Pass 2: take each block off its list; the parts of a boundary block
        // that lie outside the range go back to the same migratetype.
        let mut cursor = first_frame;
        while cursor < end {
            let Some(Some((head, order, mt, pos))) = self.indexed_block_containing(cursor) else {
                unreachable!("free block vanished under the zone lock");
            };
            self.list_swap_remove(mt, order as usize, pos);
            self.retain_outside_range(mt, head, order, first_frame, end);
            cursor = head + order_frames(order);
        }
        let frame_count = (end - first_frame) as usize;
        self.free_frames -= frame_count;
        self.total_frames -= frame_count;
        Some(true)
    }

    /// [`Self::remove_free_range`] by scanning every free list: the form for
    /// a zone that is not indexed, or a range no index section covers.
    fn remove_free_range_scan(&mut self, first_frame: u64, end: u64) -> bool {
        let frame_count = end - first_frame;
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
                    self.list_swap_remove(mt, order, index);
                    self.retain_outside_range(mt, block, order as u8, first_frame, end);
                }
            }
        }
        self.free_frames -= frame_count as usize;
        self.total_frames -= frame_count as usize;
        true
    }

    /// Return to `free_lists[mt]` the parts of the removed block
    /// `[block, block + 2^order)` that lie outside `[remove_lo, remove_hi)`,
    /// as the largest aligned sub-blocks. Recursion depth is at most `order`.
    fn retain_outside_range(
        &mut self,
        mt: usize,
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
            self.list_push(mt, order as usize, block);
            return;
        }
        debug_assert!(order > 0);
        let child_order = order - 1;
        let half = order_frames(child_order);
        self.retain_outside_range(mt, block, child_order, remove_lo, remove_hi);
        self.retain_outside_range(mt, block + half, child_order, remove_lo, remove_hi);
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
        let frame = self.list_pop(src_mt.index(), found_order as usize)?;
        // Split down to the requested order. Each split halves a block:
        // keep the lower half for the caller, push the upper half onto the
        // DESTINATION partition's lower-order free list so the entire
        // stolen block converts to `dst_mt`.
        while found_order > order {
            found_order -= 1;
            let buddy = frame + order_frames(found_order);
            self.list_push(dst_mt.index(), found_order as usize, buddy);
        }
        self.free_frames -= order_frames(order) as usize;
        self.note_alloc(frame, order);
        #[cfg(feature = "kernel-test")]
        {
            self.op_stats.allocs += 1;
        }
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
                let frame = self.list_swap_remove(src_mt.index(), order as usize, idx);
                self.free_frames -= need as usize;
                self.note_alloc(frame, order);
                #[cfg(feature = "kernel-test")]
                {
                    self.op_stats.allocs += 1;
                }
                return Some(frame);
            }
            // Fallback: walk higher orders for a block whose lower half
            // fits under the ceiling, then split repeatedly, converting the
            // block to `mt`.
            for src in (order + 1)..=MAX_ORDER {
                if let Some(idx) = self.find_below(src, max_frame_no_excl, src_mt) {
                    let frame = self.list_swap_remove(src_mt.index(), src as usize, idx);
                    let mut cur = src;
                    while cur > order {
                        cur -= 1;
                        let buddy = frame + order_frames(cur);
                        self.list_push(mt.index(), cur as usize, buddy);
                    }
                    self.free_frames -= need as usize;
                    self.note_alloc(frame, order);
                    #[cfg(feature = "kernel-test")]
                    {
                        self.op_stats.allocs += 1;
                    }
                    return Some(frame);
                }
            }
        }
        None
    }

    /// Find the index of a block at `order` in the `mt` partition whose
    /// END falls below `max_frame_no_excl`. Linear scan of the order's
    /// free list: the lists are not ordered by address, and a ceiling is
    /// only in force during early boot (before the direct map covers all
    /// RAM) and for a device's coherent-DMA mask — neither is a path that
    /// runs per page under load.
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
        let _ = self.try_free_mt(frame, order, mt);
    }

    /// [`Self::free_mt`], reporting whether the block was taken. `false`
    /// means the frame's state word says it is ALREADY free — the head of a
    /// free block, or resident in a per-CPU cache — so this is a double free:
    /// the zone is left untouched and the caller must not count the block as
    /// freed. Only frames with a state word can be refused; a zone that is not
    /// indexed accepts every free, as before.
    pub(crate) fn try_free_mt(&mut self, frame: u64, order: u8, mt: MigrateType) -> bool {
        self.try_free_checked(frame, order, mt).is_ok()
    }

    /// [`Self::try_free_mt`], saying why a free was refused: the frame is
    /// already free, is a tail of a live block, is not allocated at all
    /// (inside a free block), or heads a block of another order.
    pub(crate) fn try_free_checked(
        &mut self,
        frame: u64,
        order: u8,
        mt: MigrateType,
    ) -> Result<(), FreeRefusal> {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        // The audit (when compiled in) names a double free at its source
        // before the refusal below can hide it.
        self.note_free(frame, order);
        if let Some(index) = self.index {
            index.claim_free(frame, order)?;
        }
        self.free_inner(frame, order, mt);
        Ok(())
    }

    /// Return a block that was already recorded free while resident in a
    /// per-CPU cache. This updates/coalesces buddy metadata without emitting a
    /// second audit transition. Cached base pages and complete order-1 pairs
    /// have already emitted one transition per page and rejoin `Unmovable`.
    /// The cache has cleared the frame's state word before handing it over.
    pub(crate) fn free_cached(&mut self, frame: u64, order: u8) {
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (order_frames(order) - 1), 0);
        debug_assert!(!self.already_free(frame));
        self.free_inner(frame, order, MigrateType::Unmovable);
    }

    /// Put a block on its free list, merging with its buddy for as long as
    /// the buddy is free at the same order in the same migratetype. Each
    /// order costs one [`Self::list_find`] and at most one O(1) list removal,
    /// so the whole free is O(orders) for every frame the index covers.
    fn free_inner(&mut self, frame: u64, order: u8, mt: MigrateType) {
        self.free_frames += order_frames(order) as usize;
        #[cfg(feature = "kernel-test")]
        {
            self.op_stats.frees += 1;
        }
        let mt = mt.index();
        let mut cur_order = order;
        let mut cur_frame = frame;
        while cur_order < MAX_ORDER {
            let buddy = buddy_of(cur_frame, cur_order);
            // The buddy must be free in the SAME migratetype partition. A
            // buddy of a different migratetype is deliberately not merged.
            let Some(pos) = self.list_find(mt, cur_order as usize, buddy) else {
                break;
            };
            self.list_swap_remove(mt, cur_order as usize, pos);
            // Coalesced block starts at min(cur_frame, buddy).
            cur_frame = cur_frame.min(buddy);
            cur_order += 1;
        }
        self.list_push(mt, cur_order as usize, cur_frame);
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
        // The per-frame state words must agree with the lists they index: a
        // disagreement is reported as the block against itself.
        if let Err((frame, order)) = self.validate_index() {
            return Err((frame, order, order));
        }
        match self.validate_no_overlap_indexed() {
            Some(result) => result,
            None => self.validate_no_overlap_scan(),
        }
    }

    /// Overlap check from the state words, O(free blocks × orders): with the
    /// words known to match the lists (`validate_index`), two entries cannot
    /// name the same head, so the only possible overlap is a block lying
    /// inside a LARGER free block — and that block could only start at this
    /// block's head rounded down to the larger order. `None` when some listed
    /// head has no state word; the pairwise scan then covers the zone.
    fn validate_no_overlap_indexed(&self) -> Option<Result<(), (u64, u8, u8)>> {
        self.index?;
        for lists in &self.free_lists {
            for (order, list) in lists.iter().enumerate() {
                for &frame in list {
                    self.slot(frame)?;
                    for larger in (order + 1)..NUM_ORDERS {
                        let head = frame & !(order_frames(larger as u8) - 1);
                        let state = self.slot(head)?.load(Ordering::Relaxed);
                        if let Some((other_mt, other_order, pos)) = self.own_block(state) {
                            if other_order == larger
                                && self.free_lists[other_mt][other_order][pos] == head
                            {
                                return Some(Err((frame, order as u8, larger as u8)));
                            }
                        }
                    }
                }
            }
        }
        Some(Ok(()))
    }

    /// Pairwise overlap check, O(N²) in free blocks: the form for a zone
    /// that is not indexed (early boot, standalone test zones).
    fn validate_no_overlap_scan(&self) -> Result<(), (u64, u8, u8)> {
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
                        self.list_swap_remove(mt, order, i);
                        let block_frames = order_frames(order as u8) as usize;
                        self.free_frames -= block_frames;
                        self.total_frames -= block_frames;
                        // Preserve the migratetype grouping across the move.
                        dest.list_push(mt, order, frame);
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

/// Kernel tests of the free-state index, on synthetic zones.
///
/// They live in the kernel-test harness rather than in the `#[cfg(test)]`
/// module above because the crate's host test binary does not link (the crate
/// references kernel linker symbols), so nothing in that module ever runs.
#[cfg(feature = "kernel-test")]
mod index_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, kt_assert_ne, TestResult};

    /// Index for the synthetic zones below — separate from the live
    /// allocator's, so fabricated frame numbers never meet real ones. Words
    /// outlive the zones that wrote them, so every test keeps to its own
    /// frame range and starts by clearing it.
    static TEST_INDEX: FrameStateIndex = FrameStateIndex::new();

    /// Give `[first, first + count)` zeroed state words in the test index.
    fn cover(first: u64, count: u64) -> bool {
        let last = (first + count - 1) >> STATE_SECTION_SHIFT;
        for section in (first >> STATE_SECTION_SHIFT)..=last {
            if TEST_INDEX.has_section(section) {
                continue;
            }
            let mut words = Vec::new();
            if words.try_reserve_exact(STATE_SECTION_FRAMES).is_err() {
                return false;
            }
            words.resize_with(STATE_SECTION_FRAMES, || AtomicU64::new(0));
            if !TEST_INDEX.install_section(section, Box::leak(words.into_boxed_slice())) {
                return false;
            }
        }
        for frame in first..first + count {
            match TEST_INDEX.slot(frame) {
                Some(word) => word.store(0, Ordering::Relaxed),
                None => return false,
            }
        }
        true
    }

    fn indexed_zone(node: usize) -> BuddyZone {
        let mut zone = BuddyZone::new();
        zone.enable_index(&TEST_INDEX, node);
        zone
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    const OUT_OF_MEMORY: TestResult = TestResult::Skip("no memory for test index sections");

    /// The indexed zone must make exactly the decisions the scanning zone
    /// makes: the same frame for every allocation, the same lists after every
    /// free. Drive both with one pseudo-random alloc/free stream.
    fn smoke_buddy_index_matches_scanning_zone() -> TestResult {
        const FIRST: u64 = 0x10_0000;
        const FRAMES: u64 = 2 * 8192 + 1000;
        if !cover(FIRST, FRAMES) {
            return OUT_OF_MEMORY;
        }
        let mut plain = BuddyZone::new();
        let mut indexed = indexed_zone(1);
        plain.donate(FIRST, FRAMES);
        indexed.donate(FIRST, FRAMES);
        let mut live: Vec<(u64, u8, MigrateType)> = Vec::new();
        let mut rng = 0x1234_5678_9ABC_DEF1u64;
        for step in 0..20_000u32 {
            let roll = xorshift(&mut rng);
            if live.is_empty() || roll % 5 < 3 {
                let order = ((roll >> 8) % 4) as u8;
                let mt = MigrateType::from_index(((roll >> 16) & 1) as usize);
                let scanned = plain.alloc_mt(order, mt);
                kt_assert_eq!(scanned, indexed.alloc_mt(order, mt));
                if let Some(frame) = scanned {
                    live.push((frame, order, mt));
                }
            } else {
                let (frame, order, mt) = live.swap_remove((roll >> 8) as usize % live.len());
                plain.free_mt(frame, order, mt);
                kt_assert!(indexed.try_free_mt(frame, order, mt));
            }
            if step % 257 == 0 {
                kt_assert!(indexed.validate_index().is_ok());
                kt_assert!(indexed.validate_no_overlap().is_ok());
            }
        }
        for (frame, order, mt) in live.drain(..) {
            plain.free_mt(frame, order, mt);
            indexed.free_mt(frame, order, mt);
        }
        kt_assert!(plain.free_lists == indexed.free_lists);
        kt_assert_eq!(indexed.free_frame_count(), FRAMES as usize);
        kt_assert!(indexed.validate_index().is_ok());
        kt_assert!(indexed.validate_no_overlap().is_ok());
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_matches_scanning_zone);

    /// A buddy lookup on an indexed zone is one probe however long the list
    /// is; on a scanning zone it is the list. Build a long order-0 list (one
    /// frame of every pair) and count what freeing the partners costs.
    fn smoke_buddy_index_lookup_is_one_step() -> TestResult {
        const FIRST: u64 = 0x10_D000;
        const FRAMES: u64 = 4096;
        if !cover(FIRST, FRAMES) {
            return OUT_OF_MEMORY;
        }
        let mut steps = [0u64; 2];
        for (which, mut zone) in [BuddyZone::new(), indexed_zone(2)].into_iter().enumerate() {
            let mut frames = Vec::new();
            zone.donate(FIRST, FRAMES);
            while let Some(frame) = zone.alloc(0) {
                frames.push(frame);
            }
            kt_assert_eq!(frames.len(), FRAMES as usize);
            for &frame in frames.iter().filter(|frame| *frame & 1 == 0) {
                zone.free(frame, 0);
            }
            let before = zone.op_stats();
            for &frame in frames.iter().filter(|frame| *frame & 1 == 1) {
                zone.free(frame, 0);
            }
            let after = zone.op_stats();
            kt_assert_eq!(zone.free_frame_count(), FRAMES as usize);
            steps[which] = (after.find_steps - before.find_steps) / (after.frees - before.frees);
        }
        // The scanning zone walks a list of up to 2048 entries per free; the
        // indexed one makes at most one probe per order.
        kt_assert!(steps[0] > 64);
        kt_assert!(steps[1] <= u64::from(MAX_ORDER) + 1);
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_lookup_is_one_step);

    fn smoke_buddy_index_refuses_a_double_free() -> TestResult {
        const FIRST: u64 = 0x10_8000;
        if !cover(FIRST, 16) {
            return OUT_OF_MEMORY;
        }
        let mut zone = indexed_zone(0);
        zone.donate(FIRST, 16);
        let (Some(a), Some(_held)) = (zone.alloc(0), zone.alloc(0)) else {
            return TestResult::Fail("synthetic zone could not supply two frames");
        };
        kt_assert!(zone.try_free_mt(a, 0, MigrateType::Unmovable));
        let free = zone.free_frame_count();
        // `a` is now the head of a free order-0 block (its buddy is held).
        kt_assert!(!zone.try_free_mt(a, 0, MigrateType::Unmovable));
        kt_assert!(!zone.try_free_mt(a, 0, MigrateType::Movable));
        kt_assert_eq!(zone.free_frame_count(), free);
        kt_assert!(zone.validate_index().is_ok());
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_refuses_a_double_free);

    /// Two zones sharing one index must never merge each other's blocks,
    /// even for frames that are buddies: the node tag keeps a word written by
    /// one zone from matching in the other.
    fn smoke_buddy_index_keeps_nodes_apart() -> TestResult {
        const FIRST: u64 = 0x10_8400;
        if !cover(FIRST, 2) {
            return OUT_OF_MEMORY;
        }
        let mut a = indexed_zone(0);
        let mut b = indexed_zone(1);
        // Both frames are live order-0 frames before they are freed.
        TEST_INDEX.mark_allocated(FIRST, 0);
        TEST_INDEX.mark_allocated(FIRST + 1, 0);
        a.free_mt(FIRST, 0, MigrateType::Movable);
        b.free_mt(FIRST + 1, 0, MigrateType::Movable);
        kt_assert_eq!(a.free_block_count(0), 1);
        kt_assert_eq!(b.free_block_count(0), 1);
        kt_assert_eq!(a.free_block_count(1) + b.free_block_count(1), 0);
        kt_assert!(a.validate_index().is_ok());
        kt_assert!(b.validate_index().is_ok());
        // The frame zone `a` lists is free there, so `b` refuses it too.
        kt_assert!(!b.try_free_mt(FIRST, 0, MigrateType::Movable));
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_keeps_nodes_apart);

    /// Removing an exact range from the words must leave what removing it by
    /// scanning leaves: same counts, same surviving frames.
    fn smoke_buddy_index_remove_range_matches_scan() -> TestResult {
        const FIRST: u64 = 0x10_A000;
        const FRAMES: u64 = 8192;
        let cases: [(u64, u64); 6] = [
            (FIRST, FRAMES),
            (FIRST + 5, 3),
            (FIRST + 1000, 4096),
            (FIRST + 8191, 1),
            (FIRST, 1),
            (FIRST + 4095, 2),
        ];
        for (start, count) in cases {
            if !cover(FIRST, FRAMES) {
                return OUT_OF_MEMORY;
            }
            let mut plain = BuddyZone::new();
            let mut indexed = indexed_zone(2);
            plain.donate(FIRST, FRAMES);
            indexed.donate(FIRST, FRAMES);
            kt_assert!(plain.remove_free_range(start, count));
            kt_assert!(indexed.remove_free_range(start, count));
            kt_assert_eq!(indexed.free_frame_count(), plain.free_frame_count());
            kt_assert_eq!(indexed.total_frame_count(), plain.total_frame_count());
            kt_assert!(indexed.validate_index().is_ok());
            kt_assert!(indexed.validate_no_overlap().is_ok());
            let mut left_plain = Vec::new();
            let mut left_indexed = Vec::new();
            while let Some(frame) = plain.alloc(0) {
                left_plain.push(frame);
            }
            while let Some(frame) = indexed.alloc(0) {
                left_indexed.push(frame);
            }
            left_plain.sort_unstable();
            left_indexed.sort_unstable();
            kt_assert!(left_plain == left_indexed);
            kt_assert!(left_indexed
                .iter()
                .all(|frame| !(start..start + count).contains(frame)));
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_remove_range_matches_scan);

    fn smoke_buddy_index_remove_range_rejects_busy_without_mutation() -> TestResult {
        const FIRST: u64 = 0x10_C000;
        if !cover(FIRST, 64) {
            return OUT_OF_MEMORY;
        }
        let mut zone = indexed_zone(0);
        zone.donate(FIRST, 64);
        let Some(held) = zone.alloc(0) else {
            return TestResult::Fail("synthetic zone could not supply a frame");
        };
        let lists = zone.free_lists.clone();
        kt_assert!(!zone.remove_free_range(FIRST, 64));
        kt_assert!(!zone.remove_free_range(held, 1));
        kt_assert!(zone.free_lists == lists);
        kt_assert!(zone.validate_index().is_ok());
        zone.free(held, 0);
        kt_assert!(zone.remove_free_range(FIRST, 64));
        kt_assert_eq!(zone.free_frame_count(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/buddy",
        smoke_buddy_index_remove_range_rejects_busy_without_mutation
    );

    /// A zone may list frames no section covers (their words do not exist).
    /// Those keep the scanning behaviour and must still coalesce; installing
    /// the section later and syncing brings them into the index. Sections are
    /// also only ever installed whole, and once.
    fn smoke_buddy_index_uncovered_frames_fall_back_to_the_scan() -> TestResult {
        const FIRST: u64 = 0x90_0000;
        let section = FIRST >> STATE_SECTION_SHIFT;
        if TEST_INDEX.has_section(section) {
            return TestResult::Skip("test index section already installed");
        }
        let mut zone = indexed_zone(3);
        zone.donate(FIRST, 8);
        let (Some(a), Some(b)) = (zone.alloc(0), zone.alloc(0)) else {
            return TestResult::Fail("synthetic zone could not supply two frames");
        };
        zone.free(a, 0);
        zone.free(b, 0);
        kt_assert_eq!(zone.free_frame_count(), 8);
        kt_assert_eq!(zone.free_block_count(3), 1);
        kt_assert!(zone.validate_no_overlap().is_ok());

        let words = |len: usize| -> Option<&'static [AtomicU64]> {
            let mut words = Vec::new();
            words.try_reserve_exact(len).ok()?;
            words.resize_with(len, || AtomicU64::new(0));
            Some(Box::leak(words.into_boxed_slice()))
        };
        let (Some(short), Some(whole), Some(again)) = (
            words(STATE_SECTION_FRAMES - 1),
            words(STATE_SECTION_FRAMES),
            words(STATE_SECTION_FRAMES),
        ) else {
            return OUT_OF_MEMORY;
        };
        kt_assert!(!TEST_INDEX.install_section(section, short));
        kt_assert!(TEST_INDEX.install_section(section, whole));
        kt_assert!(!TEST_INDEX.install_section(section, again));
        kt_assert!(TEST_INDEX.slot(FIRST).is_some());
        kt_assert!(TEST_INDEX
            .slot(FIRST + STATE_SECTION_FRAMES as u64 - 1)
            .is_some());
        kt_assert!(TEST_INDEX
            .slot(FIRST + STATE_SECTION_FRAMES as u64)
            .is_none());
        // Beyond the 52-bit physical space there is no root entry at all.
        kt_assert!(TEST_INDEX.slot(u64::MAX).is_none());
        kt_assert!(!TEST_INDEX.install_section(u64::MAX >> STATE_SECTION_SHIFT, again));

        // The block listed before its section existed has no word yet.
        kt_assert!(zone.validate_index().is_err());
        zone.sync_index();
        kt_assert!(zone.validate_index().is_ok());
        kt_assert!(zone.remove_free_range(FIRST + 2, 2));
        kt_assert_eq!(zone.free_frame_count(), 6);
        kt_assert!(zone.validate_no_overlap().is_ok());
        kt_assert_ne!(zone.free_block_count(1) + zone.free_block_count(2), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/buddy",
        smoke_buddy_index_uncovered_frames_fall_back_to_the_scan
    );

    /// Linux `bad_page` cases a free must refuse: a tail of a live block, a
    /// head freed with the wrong order, a frame inside a free block. A live
    /// block split with `split_allocated` frees frame by frame.
    fn smoke_buddy_index_refuses_bad_frees() -> TestResult {
        const FIRST: u64 = 0x10_E000;
        if !cover(FIRST, 16) {
            return OUT_OF_MEMORY;
        }
        let mut zone = indexed_zone(4);
        zone.donate(FIRST, 16);
        let mt = MigrateType::Unmovable;
        let Some(block) = zone.alloc(2) else {
            return TestResult::Fail("synthetic zone could not supply an order-2 block");
        };
        kt_assert_eq!(
            zone.try_free_checked(block + 1, 0, mt),
            Err(FreeRefusal::TailOfLiveBlock)
        );
        kt_assert_eq!(
            zone.try_free_checked(block, 1, mt),
            Err(FreeRefusal::OrderMismatch(2))
        );
        kt_assert!(zone.try_free_checked(block, 2, mt).is_ok());
        kt_assert_eq!(zone.free_frame_count(), 16);
        // Everything is one free order-4 block again; its frames are free.
        kt_assert_eq!(
            zone.try_free_checked(FIRST + 3, 0, mt),
            Err(FreeRefusal::NotAllocated)
        );
        kt_assert_eq!(
            zone.try_free_checked(FIRST, 4, mt),
            Err(FreeRefusal::AlreadyFree)
        );
        // A split block frees one frame at a time.
        let Some(block) = zone.alloc(2) else {
            return TestResult::Fail("synthetic zone could not supply an order-2 block");
        };
        kt_assert!(TEST_INDEX.split_allocated(block, 2));
        for frame in block..block + 4 {
            kt_assert!(zone.try_free_checked(frame, 0, mt).is_ok());
        }
        kt_assert_eq!(zone.free_frame_count(), 16);
        kt_assert!(zone.validate_index().is_ok());
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_refuses_bad_frees);

    /// A cache link round-trips, and is neither an empty word nor any zone's
    /// block word; a frame carrying one is refused by a zone like any other
    /// frame that is already free.
    fn smoke_buddy_index_cached_words_are_distinct() -> TestResult {
        const FIRST: u64 = 0x10_8800;
        kt_assert_eq!(cached_next(cached_state(NO_FRAME)), Some(NO_FRAME));
        kt_assert_eq!(cached_next(cached_state(0)), Some(0));
        kt_assert_eq!(
            cached_next(cached_state(0xF_FFFF_FFFF)),
            Some(0xF_FFFF_FFFF)
        );
        kt_assert_eq!(cached_next(0), None);
        if !cover(FIRST, 16) {
            return OUT_OF_MEMORY;
        }
        let mut zone = indexed_zone(5);
        kt_assert_eq!(
            cached_next(zone.block_state(1, MAX_ORDER as usize, 7)),
            None
        );
        kt_assert!(zone.own_block(cached_state(3)).is_none());
        zone.donate(FIRST, 16);
        let Some(frame) = zone.alloc(0) else {
            return TestResult::Fail("synthetic zone could not supply a frame");
        };
        let Some(word) = zone.slot(frame) else {
            return TestResult::Fail("covered frame has no state word");
        };
        word.store(cached_state(NO_FRAME), Ordering::Relaxed);
        kt_assert!(!zone.try_free_mt(frame, 0, MigrateType::Unmovable));
        word.store(alloc_head_state(0), Ordering::Relaxed);
        kt_assert!(zone.try_free_mt(frame, 0, MigrateType::Unmovable));
        TestResult::Pass
    }
    kernel_test_in!("memory/buddy", smoke_buddy_index_cached_words_are_distinct);
}
