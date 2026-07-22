//! Size-class slab allocator over the page-frame buddy.
//!
//! # Clean-room provenance
//!
//! Algorithm references:
//!   - Bonwick, J. (1994). "The Slab Allocator: An Object-Caching
//!     Kernel Memory Allocator." USENIX Summer 1994.
//!     <https://www.usenix.org/legacy/publications/library/proceedings/bos94/full_papers/bonwick.ps>
//!   - Bonwick, J. & Adams, J. (2001). "Magazines and Vmem:
//!     Extending the Slab Allocator to Many CPUs and Arbitrary
//!     Resources." USENIX 2001.
//!     <https://www.usenix.org/legacy/event/usenix01/full_papers/bonwick/bonwick.pdf>
//!
//! No GPL source consulted. See `memory/specification/heap-migration.md` §0.
//!
//! # Shape
//!
//! Single-CPU today; the per-CPU magazine layer slots on top once
//! SMP brings up application processors. The shape:
//!
//!   * Nine power-of-2 size classes from 16 B to 4 KiB.
//!   * Each class owns a singly-linked free list of blocks the same
//!     size as the class. Pop on `alloc`, push on `dealloc`.
//!   * When a class's free list is empty, the slab grabs a fresh
//!     page frame from `alloc_frame` and slabs it into N blocks of
//!     class size, pushing all N onto the list before popping the
//!     first.
//!   * Allocations larger than the largest class fall through to
//!     `alloc_frame` directly (one or more contiguous frames).
//!     `dealloc` symmetrically returns those frames.
//!
//! `dealloc` consults `Layout::size()` to recover the size class —
//! the standard `GlobalAlloc` contract. No header is stored ahead
//! of each block.
//!
//! **What's missing for SMP** (Stage-5+):
//!   * Per-CPU magazines. Each CPU has a small array of free blocks
//!     per size class; alloc pops local, dealloc pushes local. Magazine
//!     overflow / underflow batch-flushes to / pulls from the
//!     central slab here. That removes all CAS / lock contention
//!     from the fast path.
//!   * `get_cpu()` primitive (`RDPID` / `MPIDR_EL1`).
//!   * Cross-CPU dealloc routing (the freeing CPU's magazine isn't
//!     necessarily the allocating CPU's — solved with a per-CPU
//!     "remote free queue").
//!
//! The trait surface here is intentionally minimal — `alloc(layout)`
//! and `dealloc(ptr, layout)` — so the SMP layer can wrap the
//! central slab with a magazine pair without changing call sites.

use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::kernel_test_in;
use narf_lib::percpu::{current_cpu, MAX_CPUS};
use narf_lib::sync::IrqSafeSpinLock;

use crate::buddy::MAX_ORDER;
use crate::frame::{alloc_frame, alloc_pages_on, free_pages, PhysFrame};
use crate::PAGE_SIZE;

/// Local `usize` view of `PAGE_SIZE` (which the rest of the crate
/// exposes as `u64` because it doubles as a physical-address
/// stride). `usize` is what `Layout` traffics in.
const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Smallest block size — also the alignment all blocks satisfy.
/// Must hold the free-list link (word 0) plus the free-state canary
/// (word 1) — see the canary section below.
const MIN_BLOCK: usize = 16;
const _: () = assert!(MIN_BLOCK >= 2 * core::mem::size_of::<u64>());
/// Number of size classes: 16, 32, 64, ..., 4096.
const N_CLASSES: usize = 9;

/// Power-of-2 size that class `i` serves. `i = 0..N_CLASSES`.
#[inline]
const fn class_size(i: usize) -> usize {
    MIN_BLOCK << i
}

/// Pick the class for `size`. Returns `None` if size > largest class.
#[inline]
fn class_for(size: usize) -> Option<usize> {
    if size == 0 {
        return Some(0);
    }
    let s = core::cmp::max(size, MIN_BLOCK);
    // ceil(log2(s)) - log2(MIN_BLOCK).
    let log = (s.next_power_of_two().trailing_zeros() as usize)
        .saturating_sub(MIN_BLOCK.trailing_zeros() as usize);
    if log < N_CLASSES {
        Some(log)
    } else {
        None
    }
}

#[repr(C)]
struct FreeBlock {
    next: Option<NonNull<FreeBlock>>,
}

// ── Free-block canary ───────────────────────────────────────────────
//
// Every block that sits in the free state (on a per-CPU magazine or
// the central free list) carries a per-block canary in its SECOND
// word (bytes 8..16): `block_address ^ FREE_CANARY_SALT`. Word 0 is
// the `FreeBlock::next` link; `MIN_BLOCK` is 16 bytes, so both words
// fit in every size class.
//
// Protocol:
//   * Entering the free state (`canary_on_free`): first CHECK the
//     word — if it already holds this block's canary, the caller is
//     freeing a block that is already free → panic naming the block
//     (double-free caught at the second free, not later as silent
//     heap corruption). Then write the canary.
//   * Leaving the free state (`canary_on_alloc`): CHECK the word
//     still holds the canary — a mismatch means something wrote
//     through a stale pointer while the block sat on a free list
//     (use-after-free) → panic naming the block. Then zero the word
//     so a caller that never touches bytes 8..16 can't trip the
//     double-free check on its own legitimate free.
//   * Blocks freshly carved out of a new frame (grow path) get the
//     canary written UNCONDITIONALLY (`canary_set_fresh`) — the
//     frame's previous life may have left a stale canary — and the
//     one block the grow path hands to its caller gets the word
//     zeroed (`canary_clear_fresh`) for the same reason.
//
// The per-block XOR keeps a canary copied byte-for-byte into a
// different block (memcpy of freed data) from validating there. The
// only false-positive path is an owner storing exactly
// `addr ^ SALT` at offset 8 of its own block — a 2⁻⁶⁴ coincidence.

/// Salt for the free-state canary. Recognisable in raw memory dumps.
const FREE_CANARY_SALT: u64 = 0xF7EE_B10C_5AB5_1AB5;

/// The canary value for `blk` while it is free.
#[inline]
fn free_canary_value(blk: NonNull<FreeBlock>) -> u64 {
    (blk.as_ptr() as u64) ^ FREE_CANARY_SALT
}

/// Pointer to `blk`'s canary word (bytes 8..16).
///
/// # Safety
/// `blk` must point at a slab block of at least `MIN_BLOCK` bytes.
#[inline]
unsafe fn canary_word(blk: NonNull<FreeBlock>) -> *mut u64 {
    // SAFETY: every size class is ≥ MIN_BLOCK = 16 bytes, so word 1
    // is in bounds; caller owns the block.
    unsafe { blk.as_ptr().cast::<u64>().add(1) }
}

/// Block enters the free state: reject a double free, then arm the
/// canary.
///
/// # Safety
/// `blk` must be a block of size class `class_idx` that the caller
/// is returning to this slab (exclusive access).
#[inline]
unsafe fn canary_on_free(blk: NonNull<FreeBlock>, class_idx: usize) {
    // SAFETY: caller owns the block being freed; see `canary_word`.
    unsafe {
        let w = canary_word(blk);
        let w1 = w.read();
        // Capture the block's live shape BEFORE overwriting word 1 with
        // the canary: for a `{data, vtable}` object word 1 is the vtable
        // pointer that names the type if this block is later clobbered.
        #[cfg(feature = "slab-free-audit")]
        free_audit::note_free(blk, blk.as_ptr().cast::<u64>().read(), w1);
        if w1 == free_canary_value(blk) {
            panic!(
                "slab: double free of block {:p} (class {} B) — the block is already on a free list{}",
                blk.as_ptr(),
                class_size(class_idx),
                free_site_note(blk),
            );
        }
        w.write(free_canary_value(blk));
    }
}

/// Block leaves the free state: verify it wasn't scribbled while
/// free, then disarm the canary.
///
/// # Safety
/// `blk` must be a free block of size class `class_idx` just popped
/// from a magazine or the central list (exclusive access).
#[inline]
unsafe fn canary_on_alloc(blk: NonNull<FreeBlock>, class_idx: usize) {
    // SAFETY: caller owns the just-popped block; see `canary_word`.
    unsafe {
        let w = canary_word(blk);
        let got = w.read();
        if got != free_canary_value(blk) {
            panic!(
                "slab: free-block canary clobbered on block {:p} (class {} B): {:#x} != {:#x} — \
                 write-after-free while the block sat on a free list{}",
                blk.as_ptr(),
                class_size(class_idx),
                got,
                free_canary_value(blk),
                free_site_note(blk),
            );
        }
        w.write(0);
    }
}

/// Verify a block that stays free (magazine ↔ central transfer)
/// still carries its canary.
///
/// # Safety
/// `blk` must be a free block of size class `class_idx` reachable
/// only by the caller (magazine slot or central list under lock).
#[inline]
unsafe fn canary_check_free(blk: NonNull<FreeBlock>, class_idx: usize) {
    // SAFETY: caller has exclusive reach to the free block.
    unsafe {
        let got = canary_word(blk).read();
        if got != free_canary_value(blk) {
            panic!(
                "slab: free-block canary clobbered on block {:p} (class {} B): {:#x} != {:#x} — \
                 write-after-free while the block sat on a free list{}",
                blk.as_ptr(),
                class_size(class_idx),
                got,
                free_canary_value(blk),
                free_site_note(blk),
            );
        }
    }
}

/// Arm the canary on a block carved from a fresh frame — no
/// double-free check, since the frame's previous life may have left
/// a stale canary at offset 8.
///
/// # Safety
/// `blk` must be a block inside a frame this grow path exclusively
/// owns.
#[inline]
unsafe fn canary_set_fresh(blk: NonNull<FreeBlock>) {
    // SAFETY: the grow path owns the whole fresh frame.
    unsafe {
        canary_word(blk).write(free_canary_value(blk));
    }
}

/// Zero the canary word of a fresh-frame block being handed straight
/// to the caller (never entered the free state in this life).
///
/// # Safety
/// Same contract as `canary_set_fresh`.
#[inline]
unsafe fn canary_clear_fresh(blk: NonNull<FreeBlock>) {
    // SAFETY: the grow path owns the whole fresh frame.
    unsafe {
        canary_word(blk).write(0);
    }
}

// ── Free-site audit ─────────────────────────────────────────────────
//
// When the canary trips (write-after-free / double-free of a slab
// block), the block address alone doesn't say WHAT was corrupted. For
// the long-standing rip=0x3 crash the offending object is 16 bytes
// shaped {data_ptr@0, vtable@8} — a `Box<dyn Trait>`, `Arc<T>` inner,
// or `RawWaker`. The vtable pointer at offset 8 uniquely identifies
// the concrete Rust type, but `canary_on_free` overwrites offset 8
// with the canary before the trip is detected.
//
// This ring captures each freed block's first two words at the moment
// of free, BEFORE the canary write, keyed by block address. On a trip
// the tripping block's captured words are recalled and printed; the
// operator runs `addr2line` on the word-1 value to name the type. A
// ring (not a direct map) survives collisions: an entry lives until
// `RING` later frees scroll it out, and the trip normally follows the
// bad free closely.
#[cfg(feature = "slab-free-audit")]
mod free_audit {
    use super::FreeBlock;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicU64, Ordering};

    // Direct-mapped free-site table, indexed by `(block_addr >> 4) %
    // SLOTS`. Unlike a ring (which retains only the last N frees
    // globally), a direct-mapped slot survives until a DIFFERENT block
    // that hashes to the same slot is freed. That is what the rip=0x3
    // UAF needs: the offending object is long-lived — freed once,
    // never freed again (a dangling reference writes it) — so its free
    // must be retained across the millions of unrelated frees between
    // then and the eventual canary trip. 1 Mi slots × 3 words = 24 MiB
    // static; affordable for an off-by-default diagnostic build.
    const SLOTS: usize = 1 << 20;
    const SLOT_MASK: usize = SLOTS - 1;

    #[inline]
    fn idx(addr: u64) -> usize {
        ((addr >> 4) as usize) & SLOT_MASK
    }

    static SLOT_ADDR: [AtomicU64; SLOTS] = {
        const Z: AtomicU64 = AtomicU64::new(0);
        [Z; SLOTS]
    };
    static SLOT_W0: [AtomicU64; SLOTS] = {
        const Z: AtomicU64 = AtomicU64::new(0);
        [Z; SLOTS]
    };
    static SLOT_W1: [AtomicU64; SLOTS] = {
        const Z: AtomicU64 = AtomicU64::new(0);
        [Z; SLOTS]
    };

    /// Record a block's first two words at free time. `w0`/`w1` are
    /// read by the caller BEFORE the canary overwrites word 1, so `w1`
    /// still holds the freed object's live bytes (its vtable, for a
    /// `{data, vtable}` fat pointer).
    #[inline]
    pub(super) fn note_free(blk: NonNull<FreeBlock>, w0: u64, w1: u64) {
        let addr = blk.as_ptr() as u64;
        let i = idx(addr);
        SLOT_ADDR[i].store(addr, Ordering::Relaxed);
        SLOT_W0[i].store(w0, Ordering::Relaxed);
        SLOT_W1[i].store(w1, Ordering::Relaxed);
    }

    /// Recall the captured `(word0, word1)` for `blk`, or `None` if a
    /// colliding free evicted it. Only runs on the (rare) canary-trip
    /// panic path.
    #[inline]
    pub(super) fn recall(blk: NonNull<FreeBlock>) -> Option<(u64, u64)> {
        let addr = blk.as_ptr() as u64;
        let i = idx(addr);
        if SLOT_ADDR[i].load(Ordering::Relaxed) == addr {
            Some((
                SLOT_W0[i].load(Ordering::Relaxed),
                SLOT_W1[i].load(Ordering::Relaxed),
            ))
        } else {
            None
        }
    }
}

/// On a canary trip, format the freed block's captured shape (a
/// `{data, vtable}` fat pointer's word 1 is a vtable pointer —
/// `addr2line` it to name the concrete type). Empty when the audit
/// feature is off or the block scrolled out of the ring.
#[inline]
fn free_site_note(blk: NonNull<FreeBlock>) -> FreeSiteNote {
    #[cfg(feature = "slab-free-audit")]
    {
        match free_audit::recall(blk) {
            Some((w0, w1)) => FreeSiteNote {
                words: Some((w0, w1)),
            },
            None => FreeSiteNote { words: None },
        }
    }
    #[cfg(not(feature = "slab-free-audit"))]
    {
        let _ = blk;
        FreeSiteNote {}
    }
}

/// Displays as ` [freed as data=.. vtable=.. (addr2line vtable → type)]`
/// when the audit feature captured the block, otherwise empty.
struct FreeSiteNote {
    #[cfg(feature = "slab-free-audit")]
    words: Option<(u64, u64)>,
}

impl core::fmt::Display for FreeSiteNote {
    #[cfg_attr(not(feature = "slab-free-audit"), allow(unused_variables))]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "slab-free-audit")]
        if let Some((w0, w1)) = self.words {
            return write!(
                f,
                " [freed as data={:#x} vtable={:#x} — addr2line vtable → concrete type]",
                w0, w1
            );
        }
        Ok(())
    }
}

/// Per-CPU magazine size — number of pre-cached free blocks per
/// (CPU, class). 16 keeps the working set small while amortising
/// the central-list lock cost across many alloc/free pairs. Tune
/// once contention measurements arrive on real SMP hardware.
const MAG_SIZE: usize = 16;

/// One per-CPU magazine. The stack lives in an `UnsafeCell` so the
/// owning CPU can mutate without an atomic; cross-CPU access is
/// forbidden by construction (the slab dispatcher consults
/// `current_cpu()` before touching the cell).
#[repr(align(64))] // cache-line-pad to avoid false sharing
struct Magazine {
    inner: UnsafeCell<MagazineInner>,
}

struct MagazineInner {
    stack: [Option<NonNull<FreeBlock>>; MAG_SIZE],
    top: usize,
}

impl Magazine {
    const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(MagazineInner {
                stack: [None; MAG_SIZE],
                top: 0,
            }),
        }
    }
}

// SAFETY: per-CPU access pattern. The dispatcher only reads/writes
// the magazine for the active CPU, so the `UnsafeCell` is never
// shared across CPUs in flight. The `Sync` bound is what lets us
// store a `[Magazine; MAX_CPUS]` in a `static`.
unsafe impl Sync for Magazine {}

/// Per-size-class state. Central free-list head is behind a
/// spin-lock; the magazine array gives each CPU a fast path that
/// doesn't touch the lock until the magazine empties or fills.
///
/// The `mag_hit_count` / `mag_miss_count` counters are the
/// observability surface Bonwick & Adams (2001) §4 ("Object
/// Caching with Per-CPU Magazines") describes as essential for
/// validating that the magazine layer is actually pulling its
/// weight: contention only matters when misses dominate, so
/// the ratio is what tuning runs key on.
struct SizeClass {
    head: IrqSafeSpinLock<Option<NonNull<FreeBlock>>>,
    /// Total blocks ever produced by this class (alloc-backed).
    grown: AtomicUsize,
    /// Currently-allocated block count.
    in_use: AtomicUsize,
    /// Per-CPU magazines. Indexed by `current_cpu()`.
    magazines: [Magazine; MAX_CPUS],
    /// Number of alloc / free operations served entirely from a
    /// per-CPU magazine (the lock-free fast path). Summed across
    /// CPUs via `Relaxed` — readers don't need a coherent snapshot,
    /// just a monotonic counter that survives wraparound at the
    /// 64-bit horizon.
    mag_hit_count: AtomicU64,
    /// Number of alloc / free operations that missed the magazine
    /// and had to touch the central lock (or grow a fresh frame).
    mag_miss_count: AtomicU64,
}

impl SizeClass {
    const fn new() -> Self {
        Self {
            head: IrqSafeSpinLock::new(None),
            grown: AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
            magazines: [const { Magazine::new() }; MAX_CPUS],
            mag_hit_count: AtomicU64::new(0),
            mag_miss_count: AtomicU64::new(0),
        }
    }
}

// SAFETY: the IrqSafeSpinLock guards the free list; the NonNull
// pointers it holds reference DMA-mapped frames the allocator owns
// for the lifetime of the kernel.
unsafe impl Sync for SizeClass {}

static CLASSES: [SizeClass; N_CLASSES] = [
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
    SizeClass::new(),
];

/// Allocations larger than the largest size class go straight to
/// the page-frame buddy. We track the count so observers can spot
/// leak patterns without instrumenting every caller.
static LARGE_IN_USE: AtomicUsize = AtomicUsize::new(0);

/// Why an allocation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlabError {
    /// Frame allocator out of pages — class growth couldn't proceed.
    NoMemory,
    /// `Layout` size + align combination the slab can't satisfy
    /// (e.g. align > PAGE_SIZE_USIZE).
    LayoutUnsupported,
}

impl From<crate::FrameAllocError> for SlabError {
    fn from(_: crate::FrameAllocError) -> Self {
        SlabError::NoMemory
    }
}

/// Allocate `layout` bytes. Pointer is aligned to at least
/// `MIN_BLOCK` for size-class allocations and to `PAGE_SIZE_USIZE` for
/// large allocations.
///
/// Returns `Err(SlabError::LayoutUnsupported)` when the alignment
/// exceeds `PAGE_SIZE_USIZE`.
pub fn alloc(layout: Layout) -> Result<NonNull<u8>, SlabError> {
    // Sleepable is the implicit context for `slab::alloc`. In
    // debug builds the assertion panics if we got here from an
    // IRQ handler or with IRQs masked — a class of bug that
    // would otherwise show up as a latency spike on hardware.
    crate::context::AllocContext::Sleepable.debug_assert_consistent();

    if layout.align() > PAGE_SIZE_USIZE {
        return Err(SlabError::LayoutUnsupported);
    }

    let need = layout.size().max(layout.align()).max(MIN_BLOCK);
    let class = class_for(need);
    match class {
        Some(c) => alloc_class(c),
        None => alloc_large(layout),
    }
}

/// Free a previously-allocated pointer.
///
/// # Safety
/// `ptr` must have been returned by an `alloc(layout)` call with the
/// *same* layout (or one whose size + align resolved to the same
/// size class / large-alloc path). This is the standard
/// `GlobalAlloc::dealloc` contract.
pub unsafe fn dealloc(ptr: NonNull<u8>, layout: Layout) {
    let need = layout.size().max(layout.align()).max(MIN_BLOCK);
    match class_for(need) {
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        Some(c) => unsafe { dealloc_class(c, ptr) },
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        None => unsafe { dealloc_large(ptr, layout) },
    }
}

/// Atomic-context allocation: magazine-only fast path. Never
/// touches the central free list, never grows a fresh page,
/// never invokes reclaim. Returns `None` immediately if the
/// per-CPU magazine for the requested size class is empty.
///
/// Targeted at IRQ handlers and other sections that hold an
/// `IrqSafeSpinLock` — anywhere going to the central lock could
/// deadlock or block longer than the caller can tolerate. Pair
/// with `try_dealloc_atomic` so frees in the same context don't
/// bounce off the central lock either.
///
/// O(1) hot path, no atomics beyond the per-class `in_use`
/// counter. Spec acceptance criterion #6 targets this at < 100 ns
/// (success) / < 200 ns (failure) on the bring-up CPU.
///
/// Allocations beyond the largest size class always return
/// `None` — large allocs go through the buddy, which the atomic
/// path won't touch.
pub fn try_alloc_atomic(layout: Layout) -> Option<NonNull<u8>> {
    if layout.align() > PAGE_SIZE_USIZE {
        return None;
    }
    let need = layout.size().max(layout.align()).max(MIN_BLOCK);
    let c = class_for(need)?;
    let class = &CLASSES[c];
    // Mask IRQs across the whole magazine pop, exactly like
    // `alloc_class` / `dealloc_class`: the per-CPU magazine is a
    // plain (non-atomic) read-modify-write, so a nested IRQ that
    // allocs/frees the same size class between our `top` read and
    // write would lose or duplicate a block (a duplicated pop hands
    // one block to two owners — heap corruption). Masking also pins
    // `current_cpu()` for the duration: a caller running with IRQs
    // enabled cannot be preempted+migrated mid-update and mutate
    // CPU A's magazine from CPU B. When the caller already has IRQs
    // masked (IRQ handler, IrqSafeSpinLock held) the save/restore
    // nests to a no-op.
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();
        // SAFETY: per-CPU access invariant — only the active CPU
        // touches its own magazine cell, and IRQs are masked above so
        // no same-CPU re-entry can alias this borrow.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        if mag.top == 0 {
            // Atomic path never touches the central lock, so an empty
            // magazine is a permanent miss for this caller.
            class.mag_miss_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        mag.top -= 1;
        let blk = mag.stack[mag.top].take().expect("magazine top non-null");
        // SAFETY: `blk` was just popped; we hold the only reference.
        unsafe { canary_on_alloc(blk, c) };
        class.in_use.fetch_add(1, Ordering::Relaxed);
        class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
        Some(blk.cast())
    })
}

/// Atomic-context dealloc: push to the per-CPU magazine if it
/// has room. If the magazine is full, returns
/// `Err(AtomicDeallocFull)` rather than draining to the central
/// list (which would take the central lock). Caller is expected
/// to defer the free to a sleepable context, or arrange for
/// magazine drain ahead of the IRQ-critical section.
///
/// # Safety
/// Same contract as `dealloc`: `ptr` must have come from a
/// matching `alloc` / `try_alloc_atomic` call with the same
/// effective size class.
pub unsafe fn try_dealloc_atomic(
    ptr: NonNull<u8>,
    layout: Layout,
) -> Result<(), AtomicDeallocFull> {
    let need = layout.size().max(layout.align()).max(MIN_BLOCK);
    let c = match class_for(need) {
        Some(c) => c,
        None => return Err(AtomicDeallocFull),
    };
    let class = &CLASSES[c];
    // Mask IRQs across the whole magazine push — same reasoning as
    // `try_alloc_atomic`: the non-atomic `top`/`stack` update must
    // not interleave with a nested IRQ or a preempt+migrate, and
    // `current_cpu()` must be read under the mask so the push lands
    // in the executing CPU's own cell.
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();
        // SAFETY: per-CPU access invariant, IRQs masked above.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        if mag.top >= MAG_SIZE {
            // Full magazine in atomic context — we can't drain to the
            // central lock here, so count this as a miss for the caller.
            class.mag_miss_count.fetch_add(1, Ordering::Relaxed);
            return Err(AtomicDeallocFull);
        }
        let blk = ptr.cast::<FreeBlock>();
        // SAFETY: caller hands us ownership of the block; the push
        // below is what publishes it as free.
        unsafe { canary_on_free(blk, c) };
        mag.stack[mag.top] = Some(blk);
        mag.top += 1;
        class.in_use.fetch_sub(1, Ordering::Relaxed);
        class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
}

/// Returned by `try_dealloc_atomic` when the per-CPU magazine
/// is full. Caller defers the free to a sleepable context.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AtomicDeallocFull;

fn alloc_class(c: usize) -> Result<NonNull<u8>, SlabError> {
    let class = &CLASSES[c];
    // Mask IRQs for the whole magazine manipulation: the per-CPU
    // magazine is also touched by IRQ-context slab calls
    // (`try_*_atomic`), so without masking an IRQ that allocs/frees the
    // same size class mid-update corrupts it (a `None` below `top`,
    // which surfaces as the `dealloc_class` "magazine full" panic). The
    // central free list is separately IrqSafeSpinLock-guarded; the
    // nested save/restore composes (its restore returns to "masked",
    // this call's restore returns to the caller's original IRQ state).
    //
    // Reentrancy discipline: a `&mut MagazineInner` is only ever held
    // across straight-line, non-allocating code. `alloc_frame()` (the
    // grow path) can re-enter this allocator synchronously on the SAME
    // CPU — the buddy's free-list `Vec::push` growth, the cgroup charge
    // hook, and the NUMA rebalance path all route back through the
    // global slab (`without_interrupts` masks IRQ preemption but does
    // NOT stop a synchronous nested call). Holding a magazine borrow
    // across that call would alias a second `&mut` to the same cell
    // (UB) and let the compiler cache `mag.top` while the nested call
    // mutates it — the observed `top == MAG_SIZE` index panic and the
    // garbage-`next` `#GP`. So the frame is pulled with NO borrow live,
    // then a fresh short-lived borrow does the bounded push.
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();

        // FAST PATH: pop from the per-CPU magazine. No atomics, no
        // lock — only the active CPU touches its own magazine cell.
        // SAFETY: per-CPU access invariant, IRQs masked above.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        if mag.top > 0 {
            mag.top -= 1;
            let blk = mag.stack[mag.top].take().expect("magazine top non-null");
            // SAFETY: `blk` was just popped; we hold the only reference.
            unsafe { canary_on_alloc(blk, c) };
            class.in_use.fetch_add(1, Ordering::Relaxed);
            class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
            return Ok(blk.cast());
        }
        // Magazine empty — every path from here touches the central
        // lock (refill) or the buddy (grow). Count once per miss event,
        // not per block batched-in.
        class.mag_miss_count.fetch_add(1, Ordering::Relaxed);

        // SLOW PATH 1: refill the magazine from the central free list.
        // Take up to MAG_SIZE/2 blocks under one lock acquisition so
        // the lock cost amortises across the next ~8 allocs. Locking the
        // central head doesn't allocate (the buddy isn't touched), so
        // holding the magazine borrow here is safe.
        {
            let mut g = class.head.lock();
            let take = MAG_SIZE / 2;
            let mut taken = 0;
            // Bound every push to MAG_SIZE regardless of `taken`: a
            // slipped invariant (a stale `top`) must flush/return, never
            // index off the end of the fixed 16-slot stack.
            while taken < take && mag.top < MAG_SIZE {
                match *g {
                    Some(head) => {
                        // Verify the block wasn't scribbled while free
                        // BEFORE trusting its `next` link — a clobbered
                        // block would otherwise splice garbage into the
                        // central list.
                        // SAFETY: `head` is on the central list we hold
                        // the lock for.
                        unsafe { canary_check_free(head, c) };
                        // SAFETY: central blocks were inserted by this slab.
                        let next = unsafe { head.as_ref().next };
                        *g = next;
                        mag.stack[mag.top] = Some(head);
                        mag.top += 1;
                        taken += 1;
                    }
                    None => break,
                }
            }
            if taken > 0 {
                mag.top -= 1;
                let blk = mag.stack[mag.top].take().expect("just pushed");
                // SAFETY: `blk` was just popped; we hold the only reference.
                unsafe { canary_on_alloc(blk, c) };
                class.in_use.fetch_add(1, Ordering::Relaxed);
                return Ok(blk.cast());
            }
        }

        // SLOW PATH 2: grow. Pull a fresh page, slab it into N blocks,
        // push half into the magazine + the rest onto central, return
        // the last block in the page.
        //
        // CRITICAL: drop the magazine borrow before `alloc_frame()`.
        // The call can synchronously re-enter this allocator on this
        // CPU (see the module-level reentrancy note), so no `&mut` to
        // the cell may be live across it.
        let _ = mag;
        let frame: PhysFrame = alloc_frame()?;
        let base = frame.start_address().kernel_mut_ptr::<u8>();
        let block_size = class_size(c);
        let n_blocks = PAGE_SIZE_USIZE / block_size;
        // Re-borrow the magazine AFTER the (possibly reentrant) frame
        // allocation. `top` may have moved if a nested alloc/free for
        // this class ran during `alloc_frame`, so read it fresh and
        // bound every push to the remaining capacity.
        // SAFETY: per-CPU access invariant; no other borrow is live and
        // IRQs are masked, so this is the sole reference to the cell.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        let room = MAG_SIZE.saturating_sub(mag.top);
        let to_mag = (MAG_SIZE / 2).min(n_blocks - 1).min(room);
        // SAFETY: `base..base+PAGE_SIZE_USIZE` is a fresh frame
        // accessed via the per-arch kernel mapping (identity on
        // x86_64, TTBR1 high-half on aarch64) so the write stays
        // valid across user-task page-table swaps.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            for i in 0..to_mag {
                // Defensive: never index past the fixed stack. `to_mag`
                // is already clamped to `room`, but re-check so a future
                // refactor can't reintroduce the off-the-end write.
                if mag.top >= MAG_SIZE {
                    break;
                }
                let blk = NonNull::new_unchecked(base.add(i * block_size) as *mut FreeBlock);
                canary_set_fresh(blk);
                mag.stack[mag.top] = Some(blk);
                mag.top += 1;
            }
            // Everything not parked in the magazine (including any
            // blocks skipped because the magazine was already full)
            // goes onto the central free list.
            let mut g = class.head.lock();
            for i in to_mag..(n_blocks - 1) {
                let blk = base.add(i * block_size) as *mut FreeBlock;
                (*blk).next = *g;
                canary_set_fresh(NonNull::new_unchecked(blk));
                *g = NonNull::new(blk);
            }
            drop(g);
        }
        class.grown.fetch_add(n_blocks, Ordering::Relaxed);
        class.in_use.fetch_add(1, Ordering::Relaxed);
        // Last block is the one we return.
        // SAFETY: identity-mapped frame.
        Ok(unsafe {
            let ret =
                NonNull::new_unchecked(base.add((n_blocks - 1) * block_size) as *mut FreeBlock);
            // Fresh frame — its previous life may have left a stale
            // canary at offset 8; clear so this block's first free
            // doesn't false-positive the double-free check.
            canary_clear_fresh(ret);
            ret.cast()
        })
    })
}

unsafe fn dealloc_class(c: usize, ptr: NonNull<u8>) {
    let class = &CLASSES[c];
    // Mask IRQs for the whole magazine manipulation — see `alloc_class`.
    // Without this, an IRQ-context free of the same size class that
    // pre-empts the slow path below leaves a `None` below `top`, which
    // the next flush hits as the "magazine full" panic.
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();

        // The block enters the free state exactly once, whichever
        // path below parks it: reject a double free + arm the canary.
        // SAFETY: caller hands us ownership of the block.
        unsafe { canary_on_free(ptr.cast::<FreeBlock>(), c) };

        // FAST PATH: push onto the per-CPU magazine.
        // SAFETY: per-CPU access invariant, IRQs masked above.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        if mag.top < MAG_SIZE {
            mag.stack[mag.top] = Some(ptr.cast::<FreeBlock>());
            mag.top += 1;
            class.in_use.fetch_sub(1, Ordering::Relaxed);
            class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Magazine full — we have to spill to the central list.
        class.mag_miss_count.fetch_add(1, Ordering::Relaxed);

        // SLOW PATH: magazine full. Flush the bottom half back to the
        // central free list, compact the top half down, then push the
        // freshly-freed block.
        let flush = MAG_SIZE / 2;
        let mut g = class.head.lock();
        for i in 0..flush {
            let mut blk = mag.stack[i].expect("magazine full");
            // The block stays free across the magazine → central
            // move; its canary must still be intact.
            // SAFETY: `blk` is a free block only we can reach.
            unsafe { canary_check_free(blk, c) };
            // SAFETY: blocks were originally allocated from this slab,
            // so overwriting `next` re-links them onto the central head.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                blk.as_mut().next = *g;
            }
            *g = Some(blk);
        }
        drop(g);
        // Compact: shift the surviving half down to slots 0..flush.
        for i in 0..(MAG_SIZE - flush) {
            mag.stack[i] = mag.stack[i + flush].take();
        }
        mag.top = MAG_SIZE - flush;
        mag.stack[mag.top] = Some(ptr.cast::<FreeBlock>());
        mag.top += 1;
        class.in_use.fetch_sub(1, Ordering::Relaxed);
    });
}

fn alloc_large(layout: Layout) -> Result<NonNull<u8>, SlabError> {
    let n_pages = layout.size().div_ceil(PAGE_SIZE_USIZE);
    if n_pages == 0 {
        return Err(SlabError::LayoutUnsupported);
    }
    // Find the smallest buddy order that fits n_pages.
    // order N covers 1 << N pages.
    let order = pages_to_order(n_pages)?;
    let frame = alloc_pages_on(0, order)?;
    LARGE_IN_USE.fetch_add(1, Ordering::Relaxed);
    let p = frame.start_address().kernel_mut_ptr::<u8>();
    // SAFETY: `p` is reachable through the per-arch kernel
    // mapping + page-aligned to its order.
    // SAFETY: Valid memory or trusted environment
    Ok(unsafe { NonNull::new_unchecked(p) })
}

unsafe fn dealloc_large(ptr: NonNull<u8>, layout: Layout) {
    // `alloc_large` handed out `frame.start_address().kernel_mut_ptr()`,
    // so invert that mapping to recover the frame — a plain
    // `PhysAddr::new(ptr)` would treat the direct-map VA as a physical
    // address and free the wrong frame (buddy double-alloc) once the
    // high-half direct map is live.
    let phys = crate::PhysAddr::from_kernel_ptr(ptr.as_ptr());
    let frame = PhysFrame::new(phys);
    let n_pages = layout.size().div_ceil(PAGE_SIZE_USIZE);
    let order = pages_to_order(n_pages).unwrap_or(0);
    free_pages(frame, order);
    LARGE_IN_USE.fetch_sub(1, Ordering::Relaxed);
}

/// Smallest buddy order that fits `n_pages`. Returns Err when the
/// requested page count exceeds MAX_ORDER (1 << 10 = 4 MiB).
fn pages_to_order(n_pages: usize) -> Result<u8, SlabError> {
    if n_pages == 0 {
        return Ok(0);
    }
    let order = (n_pages.next_power_of_two().trailing_zeros()) as u8;
    if order > MAX_ORDER {
        return Err(SlabError::LayoutUnsupported);
    }
    Ok(order)
}

/// Per-class diagnostic snapshot.
#[derive(Copy, Clone, Debug)]
pub struct ClassStats {
    pub block_size: usize,
    pub grown: usize,
    pub in_use: usize,
    /// Alloc / free operations served from a per-CPU magazine.
    /// Bonwick & Adams (2001) §4: the magazine layer's value
    /// proposition is hit-count / (hit + miss); read this through
    /// `MagazineStats` for the cross-class total.
    pub mag_hit_count: u64,
    /// Alloc / free operations that had to touch the central lock.
    pub mag_miss_count: u64,
}

/// Cross-class magazine totals. Folded out of `ClassStats` for the
/// common observability case (hit-rate dashboards don't care which
/// size class a hit came from).
#[derive(Copy, Clone, Debug)]
pub struct MagazineStats {
    pub mag_hit_count: u64,
    pub mag_miss_count: u64,
}

/// Snapshot of all size classes + the large-alloc counter.
#[derive(Copy, Clone, Debug)]
pub struct SlabStats {
    pub classes: [ClassStats; N_CLASSES],
    pub large_in_use: usize,
}

pub fn stats() -> SlabStats {
    let mut classes = [ClassStats {
        block_size: 0,
        grown: 0,
        in_use: 0,
        mag_hit_count: 0,
        mag_miss_count: 0,
    }; N_CLASSES];
    for (i, c) in CLASSES.iter().enumerate() {
        classes[i] = ClassStats {
            block_size: class_size(i),
            grown: c.grown.load(Ordering::Relaxed),
            in_use: c.in_use.load(Ordering::Relaxed),
            mag_hit_count: c.mag_hit_count.load(Ordering::Relaxed),
            mag_miss_count: c.mag_miss_count.load(Ordering::Relaxed),
        };
    }
    SlabStats {
        classes,
        large_in_use: LARGE_IN_USE.load(Ordering::Relaxed),
    }
}

/// Magazine hit / miss totals summed across every size class.
/// O(N_CLASSES); cheap enough for periodic observability scrapes.
pub fn magazine_stats() -> MagazineStats {
    let mut hits: u64 = 0;
    let mut misses: u64 = 0;
    for c in CLASSES.iter() {
        hits = hits.wrapping_add(c.mag_hit_count.load(Ordering::Relaxed));
        misses = misses.wrapping_add(c.mag_miss_count.load(Ordering::Relaxed));
    }
    MagazineStats {
        mag_hit_count: hits,
        mag_miss_count: misses,
    }
}

/// Number of distinct size classes the allocator supports.
pub const fn num_classes() -> usize {
    N_CLASSES
}

/// Largest size class's block size. Allocations strictly larger
/// fall through to the page-frame buddy.
pub const fn max_class_size() -> usize {
    class_size(N_CLASSES - 1)
}

// ───────────────────────────────────────────────────────────────────
// Per-CPU magazine smokes.
//
// Tests live alongside the implementation rather than in
// `memory/src/tests.rs` so the magazine-isolation cases can reach
// `CLASSES[c].magazines[cpu]` directly — `current_cpu()` is the
// only public entry point and Stage-2 hard-pins it to CPU 0, so
// validating isolation at the `current_cpu()` level alone wouldn't
// actually exercise the per-CPU split. Touching `magazines[other]`
// directly here proves the data structure itself isolates state.
// ───────────────────────────────────────────────────────────────────

/// Test helper: peek at the magazine occupancy for `(class, cpu)`.
/// Reads under the per-CPU access invariant — only safe to call
/// from a single-threaded test harness or with external evidence
/// that `cpu` is quiesced.
#[doc(hidden)]
pub fn _test_magazine_top(class_idx: usize, cpu: usize) -> usize {
    assert!(class_idx < N_CLASSES);
    assert!(cpu < MAX_CPUS);
    // SAFETY: the test harness runs single-threaded with
    // current_cpu() == 0, so peeking another CPU's slot is not
    // concurrent with any other reader / writer.
    // SAFETY: Valid memory or trusted environment
    let mag = unsafe { &*CLASSES[class_idx].magazines[cpu].inner.get() };
    mag.top
}

/// Test helper: forcibly push a block into the magazine for
/// `(class_idx, cpu)`. Used by the isolation smoke to confirm
/// state planted on CPU N stays put while allocs flow through
/// CPU 0's slot.
///
/// # Safety
/// `ptr` must reference a free block previously vended by the same
/// size class. Caller is responsible for not double-pushing the
/// same block and for ensuring the slot has room (`top < MAG_SIZE`).
#[doc(hidden)]
pub unsafe fn _test_magazine_push(class_idx: usize, cpu: usize, ptr: NonNull<u8>) {
    assert!(class_idx < N_CLASSES);
    assert!(cpu < MAX_CPUS);
    // SAFETY: per-CPU access invariant — caller guarantees the
    // target slot is quiesced; tests run single-threaded.
    // SAFETY: Valid memory or trusted environment
    let mag = unsafe { &mut *CLASSES[class_idx].magazines[cpu].inner.get() };
    assert!(mag.top < MAG_SIZE);
    // The planted block enters the free state — arm its canary like
    // every other free-list entry so the eventual pop verifies clean.
    // SAFETY: caller hands us ownership of the block.
    unsafe { canary_on_free(ptr.cast::<FreeBlock>(), class_idx) };
    mag.stack[mag.top] = Some(ptr.cast::<FreeBlock>());
    mag.top += 1;
    // Mirror the accounting that `dealloc_class` would have done
    // if this push had come through the public path.
    CLASSES[class_idx].in_use.fetch_sub(1, Ordering::Relaxed);
}

/// Test: per-CPU isolation. After parking a freed block in CPU 1's
/// magazine slot, allocations driven through the active CPU
/// (CPU 0) must NOT pop that block — the active CPU's magazine
/// is empty, so it has to refill from the central list. Verifies
/// the data-structure split actually keeps state segregated.
fn smoke_slab_magazine_per_cpu_isolation() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(64, 16).expect("layout");
    let class_idx = class_for(64).expect("class");

    // Allocate, then plant the resulting block into CPU 1's
    // magazine slot. CPU 0's magazine stays untouched.
    let stolen = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("seed alloc failed"),
    };
    let cpu1_top_before = _test_magazine_top(class_idx, 1);
    if cpu1_top_before >= MAG_SIZE {
        // Pre-existing test from this run already filled CPU 1's
        // slot; skip cleanly rather than scribble over it.
        // SAFETY: matching layout.
        unsafe { dealloc(stolen, layout) };
        return TestResult::Pass;
    }
    // SAFETY: just allocated from the same class.
    unsafe { _test_magazine_push(class_idx, 1, stolen) };
    let cpu1_top_after = _test_magazine_top(class_idx, 1);
    if cpu1_top_after != cpu1_top_before + 1 {
        return TestResult::Fail("planted block didn't land in CPU 1 slot");
    }

    // Now drain CPU 0's magazine so the next alloc is forced to
    // touch the central list — if CPU 1's slot leaked into the
    // active path, the planted block would come back.
    let mut drained: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::new();
    while _test_magazine_top(class_idx, 0) > 0 {
        match alloc(layout) {
            Ok(p) => drained.push(p),
            Err(_) => return TestResult::Fail("drain alloc failed"),
        }
    }

    // Allocate a fresh block. It must NOT be the one we planted
    // in CPU 1's slot.
    let fresh = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("fresh alloc failed"),
    };
    if fresh.as_ptr() == stolen.as_ptr() {
        return TestResult::Fail("CPU 1's magazine bled into CPU 0's alloc path");
    }
    if _test_magazine_top(class_idx, 1) != cpu1_top_after {
        return TestResult::Fail("CPU 1 slot mutated by CPU 0 alloc");
    }

    // Cleanup: free the fresh block + drained blocks.
    // SAFETY: blocks just returned from alloc with matching layout.
    unsafe {
        dealloc(fresh, layout);
        for p in drained {
            dealloc(p, layout);
        }
    }
    // Manually pop the planted block from CPU 1's slot and re-park
    // it on the central free list. The `_test_magazine_push` helper
    // already decremented in_use, so the block is in "free,
    // available" accounting state — just move it from CPU 1's
    // magazine to central.
    // SAFETY: single-threaded test harness; CPU 1 is quiesced.
    let class = &CLASSES[class_idx];
    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
    let mag = unsafe { &mut *class.magazines[1].inner.get() };
    mag.top -= 1;
    let blk = mag.stack[mag.top].take().expect("planted block present");
    let mut g = class.head.lock();
    // SAFETY: `blk` came from this slab's class; we own its bytes
    // until pushed onto the central list.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        blk.as_ptr()
            .cast::<FreeBlock>()
            .write(FreeBlock { next: *g })
    };
    *g = Some(blk);
    drop(g);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_magazine_per_cpu_isolation);

/// Test: magazine spill to global. Push more than `MAG_SIZE`
/// blocks back into the per-CPU magazine in quick succession;
/// the dealloc path must spill half to the central list and the
/// `mag_miss_count` must advance for the spill event.
fn smoke_slab_magazine_spill_to_global() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(128, 16).expect("layout");
    let class_idx = class_for(128).expect("class");
    let class = &CLASSES[class_idx];

    // Drain CPU 0's magazine first so we know exactly how many
    // free-side pushes it takes to fill + spill.
    let mut drained: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::new();
    while _test_magazine_top(class_idx, 0) > 0 {
        match alloc(layout) {
            Ok(p) => drained.push(p),
            Err(_) => return TestResult::Fail("drain alloc failed"),
        }
    }

    // Allocate more than MAG_SIZE blocks so freeing them all in
    // a row forces at least one spill.
    let n = MAG_SIZE + 4;
    let mut ptrs: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n {
        match alloc(layout) {
            Ok(p) => ptrs.push(p),
            Err(_) => return TestResult::Fail("alloc failed"),
        }
    }

    let misses_before = class.mag_miss_count.load(Ordering::Relaxed);
    // SAFETY: layout matches the alloc.
    unsafe {
        for p in ptrs {
            dealloc(p, layout);
        }
    }
    let misses_after = class.mag_miss_count.load(Ordering::Relaxed);

    if misses_after <= misses_before {
        return TestResult::Fail("spill didn't bump mag_miss_count");
    }
    // After spill + push, CPU 0's magazine is bounded by MAG_SIZE.
    if _test_magazine_top(class_idx, 0) > MAG_SIZE {
        return TestResult::Fail("magazine top exceeded MAG_SIZE");
    }
    // SAFETY: drained vec entries are matching layout.
    unsafe {
        for p in drained {
            dealloc(p, layout);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_magazine_spill_to_global);

/// Test: magazine refill from global. After deliberately draining
/// the magazine + flushing some blocks to the central list, the
/// next alloc on an empty magazine must refill from central
/// (not grow a fresh frame) and bump `mag_miss_count` exactly
/// once for the refill event.
fn smoke_slab_magazine_refill_from_global() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(256, 16).expect("layout");
    let class_idx = class_for(256).expect("class");
    let class = &CLASSES[class_idx];

    // Step 1: produce many blocks so the central list has stock.
    // 32 * 256 B > one page worth (16 blocks/page), so the class
    // grows and the central list accumulates spillover.
    let n_prime = 32;
    let mut prime: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::with_capacity(n_prime);
    for _ in 0..n_prime {
        match alloc(layout) {
            Ok(p) => prime.push(p),
            Err(_) => return TestResult::Fail("prime alloc failed"),
        }
    }
    // SAFETY: same layout.
    unsafe {
        for p in prime {
            dealloc(p, layout);
        }
    }

    // Step 2: drain the magazine so the next alloc forces a refill.
    let mut drained: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::new();
    while _test_magazine_top(class_idx, 0) > 0 {
        match alloc(layout) {
            Ok(p) => drained.push(p),
            Err(_) => return TestResult::Fail("drain alloc failed"),
        }
    }

    let grown_before = class.grown.load(Ordering::Relaxed);
    let misses_before = class.mag_miss_count.load(Ordering::Relaxed);

    // Step 3: one alloc on an empty magazine — must refill.
    let p = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("refill alloc failed"),
    };

    let grown_after = class.grown.load(Ordering::Relaxed);
    let misses_after = class.mag_miss_count.load(Ordering::Relaxed);

    if grown_after != grown_before {
        return TestResult::Fail("refill grew a fresh frame instead of using central stock");
    }
    if misses_after != misses_before + 1 {
        return TestResult::Fail("refill should bump mag_miss_count exactly once");
    }

    // SAFETY: matching layout.
    unsafe {
        dealloc(p, layout);
        for q in drained {
            dealloc(q, layout);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_magazine_refill_from_global);

/// Test: hit-rate counters advance under steady-state churn. With
/// the magazine warm, ≥ `MAG_SIZE` consecutive alloc/free pairs of
/// the same class should produce zero new misses and many hits.
/// Also confirms `magazine_stats()` aggregates across classes.
fn smoke_slab_magazine_stats_counters() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(32, 16).expect("layout");
    let class_idx = class_for(32).expect("class");
    let class = &CLASSES[class_idx];

    // Warm the magazine: one round-trip ensures CPU 0's magazine
    // has stock so the steady-state loop never misses.
    let warm = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("warm alloc failed"),
    };
    // SAFETY: matching layout.
    unsafe { dealloc(warm, layout) };

    let hits_before = class.mag_hit_count.load(Ordering::Relaxed);
    let misses_before = class.mag_miss_count.load(Ordering::Relaxed);
    let agg_before = magazine_stats();

    // Steady-state loop: alloc + free in lockstep so the magazine
    // top oscillates between K and K+1; every operation should
    // be a magazine hit.
    let iters = 256;
    for _ in 0..iters {
        let p = match alloc(layout) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("hot alloc failed"),
        };
        // SAFETY: matching layout.
        unsafe { dealloc(p, layout) };
    }

    let hits_after = class.mag_hit_count.load(Ordering::Relaxed);
    let misses_after = class.mag_miss_count.load(Ordering::Relaxed);
    let agg_after = magazine_stats();

    let hits_delta = hits_after - hits_before;
    let misses_delta = misses_after - misses_before;
    if hits_delta < (iters as u64) * 2 {
        // 2 hits per iteration (alloc + free) when steady.
        return TestResult::Fail("hit-count didn't track steady-state churn");
    }
    if misses_delta != 0 {
        return TestResult::Fail("steady-state churn produced unexpected misses");
    }
    // Aggregate must monotonically advance and reflect the delta.
    if agg_after.mag_hit_count < agg_before.mag_hit_count + hits_delta {
        return TestResult::Fail("magazine_stats() didn't aggregate per-class hits");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_magazine_stats_counters);

/// Test: grow-path magazine invariant under repeated grow events. A
/// tight alloc/free hammer that keeps forcing the slow (grow / spill)
/// paths must never drive a magazine `top` past `MAG_SIZE`, and every
/// returned pointer must be distinct + correctly aligned while live.
///
/// This asserts the single-thread invariant the SMP corruption bug
/// violated: the grow path (`alloc_class` SLOW PATH 2) used to hold a
/// `&mut MagazineInner` across `alloc_frame()` — a call that can
/// re-enter the slab on the same CPU — and then push into the
/// magazine assuming `top` was unchanged, which under load ran `top`
/// off the end of the 16-slot stack (`index out of bounds: len is 16
/// but index is 16`). Only SMP + heavy service load reproduces the
/// reentrancy in the field; here we at least pin the invariant that
/// no path leaves `top > MAG_SIZE` and no live block aliases another.
fn smoke_slab_grow_path_top_bounded() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(64, 16).expect("layout");
    let class_idx = class_for(64).expect("class");

    // Hold a large batch live so the class is repeatedly forced to
    // grow fresh frames (magazine + central both drained), exercising
    // SLOW PATH 2 many times over. 512 * 64 B spans dozens of frames.
    let n = 512usize;
    let mut live: alloc::vec::Vec<NonNull<u8>> = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n {
        match alloc(layout) {
            Ok(p) => live.push(p),
            Err(_) => {
                // Clean up whatever we did get before bailing.
                // SAFETY: matching layout.
                unsafe {
                    for q in live.drain(..) {
                        dealloc(q, layout);
                    }
                }
                return TestResult::Fail("grow-hammer alloc failed");
            }
        }
        // Invariant: no per-CPU magazine slot for this class may ever
        // exceed MAG_SIZE. `_test_magazine_top` reads the raw `top`.
        if _test_magazine_top(class_idx, 0) > MAG_SIZE {
            return TestResult::Fail("magazine top exceeded MAG_SIZE during grow hammer");
        }
    }

    // Distinctness: no two live blocks alias. O(n^2) but n is small
    // and this is a smoke, not a hot path. Aliasing would mean the
    // grow path handed the same block out twice (the corruption
    // signature).
    for i in 0..live.len() {
        for j in (i + 1)..live.len() {
            if live[i].as_ptr() == live[j].as_ptr() {
                return TestResult::Fail("grow path returned an aliased block");
            }
        }
    }

    // Free everything, re-checking the bound as the spill path runs.
    // SAFETY: matching layout for every entry.
    unsafe {
        for p in live.drain(..) {
            dealloc(p, layout);
            if _test_magazine_top(class_idx, 0) > MAG_SIZE {
                return TestResult::Fail("magazine top exceeded MAG_SIZE during free hammer");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_grow_path_top_bounded);

/// Test: free-block canary lifecycle. A handed-out block's canary
/// word (offset 8) is zero; freeing arms it (`addr ^ SALT`); an
/// immediate re-alloc (LIFO magazine top) returns the same block with
/// the word cleared again. This is the observable half of the canary
/// protocol — the panic halves (double free, write-after-free) can't
/// be asserted in-kernel without dying, so we pin the arm/disarm
/// transitions they key on.
fn smoke_slab_free_block_canary_lifecycle() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(64, 16).expect("layout");

    let p = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("alloc failed"),
    };
    let word = |ptr: NonNull<u8>| -> u64 {
        // SAFETY: every slab block is ≥ MIN_BLOCK = 16 bytes; reading
        // word 1 of a block this test controls is in bounds.
        unsafe { ptr.as_ptr().cast::<u64>().add(1).read() }
    };
    let canary = (p.as_ptr() as u64) ^ FREE_CANARY_SALT;
    if word(p) != 0 {
        return TestResult::Fail("handed-out block's canary word not cleared");
    }
    // Simulate an owner that scribbles the canary slot, then frees —
    // the free must overwrite the owner bytes with the armed canary.
    // SAFETY: we own the block; writing inside its 64 bytes is fine.
    unsafe { p.as_ptr().cast::<u64>().add(1).write(0xDEAD_BEEF) };
    // SAFETY: matching layout.
    unsafe { dealloc(p, layout) };
    if word(p) != canary {
        return TestResult::Fail("freed block's canary not armed");
    }
    // LIFO: the next alloc of this class pops the same block.
    let q = match alloc(layout) {
        Ok(q) => q,
        Err(_) => return TestResult::Fail("re-alloc failed"),
    };
    if q.as_ptr() != p.as_ptr() {
        // Another slot won the LIFO race (shouldn't happen in the
        // single-threaded harness, but don't fail spuriously) — just
        // clean up.
        // SAFETY: matching layout.
        unsafe { dealloc(q, layout) };
        return TestResult::Pass;
    }
    if word(q) != 0 {
        return TestResult::Fail("re-allocated block's canary not cleared");
    }
    // SAFETY: matching layout.
    unsafe { dealloc(q, layout) };
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_free_block_canary_lifecycle);

/// Test: the atomic magazine paths mask IRQs for their critical
/// section and restore the caller's IRQ state, and they follow the
/// same canary protocol as the sleepable paths (disarm on pop, arm
/// on push).
fn smoke_slab_atomic_paths_masked_and_canaried() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let layout = Layout::from_size_align(128, 16).expect("layout");
    let irq_before = crate::context::irqs_enabled();

    // Warm the magazine so the atomic pop has stock.
    let warm = match alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("warm alloc failed"),
    };
    // SAFETY: matching layout.
    unsafe { dealloc(warm, layout) };

    let p = match try_alloc_atomic(layout) {
        Some(p) => p,
        None => return TestResult::Fail("atomic alloc missed a warm magazine"),
    };
    if crate::context::irqs_enabled() != irq_before {
        return TestResult::Fail("try_alloc_atomic changed the caller's IRQ state");
    }
    let word = |ptr: NonNull<u8>| -> u64 {
        // SAFETY: block is ≥ MIN_BLOCK bytes and controlled by this test.
        unsafe { ptr.as_ptr().cast::<u64>().add(1).read() }
    };
    if word(p) != 0 {
        return TestResult::Fail("atomic pop left the canary armed");
    }
    // SAFETY: matching layout, block just came from try_alloc_atomic.
    if unsafe { try_dealloc_atomic(p, layout) }.is_err() {
        return TestResult::Fail("atomic dealloc rejected a non-full magazine");
    }
    if crate::context::irqs_enabled() != irq_before {
        return TestResult::Fail("try_dealloc_atomic changed the caller's IRQ state");
    }
    if word(p) != (p.as_ptr() as u64) ^ FREE_CANARY_SALT {
        return TestResult::Fail("atomic push didn't arm the canary");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_atomic_paths_masked_and_canaried);

/// Stress: multi-class alloc/free churn asserting the no-double-issue
/// invariants. Every live block carries an ownership tag (its own
/// address ⊕ salt) in word 0; if the slab ever hands one block to two
/// owners, the second owner's tag write clobbers the first owner's,
/// and the first owner's free-side verification fails loudly. The
/// churn is sized to force every slow path — grow (fresh frames),
/// spill (magazine → central), refill (central → magazine) — many
/// times over, with the buddy's free-list overlap validator run
/// periodically ("no frame in two free lists"). In a single-task
/// harness this exercises the full path mix; under an SMP boot the
/// same invariants are enforced at every alloc/free by the always-on
/// canary checks, which is where the cross-CPU protection lives.
fn smoke_slab_churn_no_double_issue() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    const TAG_SALT: u64 = 0xA5A5_5A5A_C3C3_3C3C;
    const SIZES: [usize; 4] = [16, 64, 256, 512];
    const ROUNDS: usize = 4096;
    const LIVE_CAP: usize = 1024;

    let mut rng: u64 = 0x1234_5678_9abc_def0;
    let mut lcg = move || {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        rng
    };
    let mut live: alloc::vec::Vec<(NonNull<u8>, usize)> = alloc::vec::Vec::with_capacity(LIVE_CAP);

    let free_one = |(p, sz): (NonNull<u8>, usize)| -> Result<(), &'static str> {
        // SAFETY: word 0 of a live block we own.
        let got = unsafe { p.as_ptr().cast::<u64>().read() };
        if got != (p.as_ptr() as u64) ^ TAG_SALT {
            return Err("live block's ownership tag clobbered — block issued to two owners");
        }
        let layout = Layout::from_size_align(sz, 16).expect("layout");
        // SAFETY: `p` came from `alloc` with this layout.
        unsafe { dealloc(p, layout) };
        Ok(())
    };

    for round in 0..ROUNDS {
        let r = lcg();
        let sz = SIZES[(r >> 33) as usize % SIZES.len()];
        let do_alloc = (r >> 62) & 1 == 0;
        if (do_alloc && live.len() < LIVE_CAP) || live.len() < 8 {
            let layout = Layout::from_size_align(sz, 16).expect("layout");
            let p = match alloc(layout) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("churn alloc failed"),
            };
            // SAFETY: word 0 of a block we just got handed.
            unsafe {
                p.as_ptr()
                    .cast::<u64>()
                    .write((p.as_ptr() as u64) ^ TAG_SALT)
            };
            live.push((p, sz));
        } else {
            let idx = (r >> 8) as usize % live.len();
            if let Err(msg) = free_one(live.swap_remove(idx)) {
                return TestResult::Fail(msg);
            }
        }
        if round % 512 == 0 {
            // Buddy invariant: no frame covered by two free blocks.
            if crate::frame::validate_no_overlap().is_err() {
                return TestResult::Fail("buddy free lists overlap during churn");
            }
            // Magazine invariant: `top` never exceeds the fixed stack.
            let cpu = current_cpu();
            for cls in 0..N_CLASSES {
                if _test_magazine_top(cls, cpu) > MAG_SIZE {
                    return TestResult::Fail("magazine top exceeded MAG_SIZE during churn");
                }
            }
        }
    }
    // Drain: every surviving block must still carry its own tag.
    while let Some(entry) = live.pop() {
        if let Err(msg) = free_one(entry) {
            return TestResult::Fail(msg);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_churn_no_double_issue);
