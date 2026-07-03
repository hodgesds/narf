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
const MIN_BLOCK: usize = 16;
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
    let cpu = current_cpu();
    // SAFETY: per-CPU access invariant — only the active CPU
    // touches its own magazine cell.
    // SAFETY: Valid memory or trusted environment
    let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
    if mag.top == 0 {
        // Atomic path never touches the central lock, so an empty
        // magazine is a permanent miss for this caller.
        class.mag_miss_count.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    mag.top -= 1;
    let blk = mag.stack[mag.top].take().expect("magazine top non-null");
    class.in_use.fetch_add(1, Ordering::Relaxed);
    class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
    Some(blk.cast())
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
    let cpu = current_cpu();
    // SAFETY: per-CPU access invariant.
    let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
    if mag.top >= MAG_SIZE {
        // Full magazine in atomic context — we can't drain to the
        // central lock here, so count this as a miss for the caller.
        class.mag_miss_count.fetch_add(1, Ordering::Relaxed);
        return Err(AtomicDeallocFull);
    }
    mag.stack[mag.top] = Some(ptr.cast::<FreeBlock>());
    mag.top += 1;
    class.in_use.fetch_sub(1, Ordering::Relaxed);
    class.mag_hit_count.fetch_add(1, Ordering::Relaxed);
    Ok(())
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
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();

        // FAST PATH: pop from the per-CPU magazine. No atomics, no
        // lock — only the active CPU touches its own magazine cell.
        // SAFETY: per-CPU access invariant, IRQs masked above.
        let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
        if mag.top > 0 {
            mag.top -= 1;
            let blk = mag.stack[mag.top].take().expect("magazine top non-null");
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
        // the lock cost amortises across the next ~8 allocs.
        {
            let mut g = class.head.lock();
            let take = MAG_SIZE / 2;
            let mut taken = 0;
            while taken < take {
                match *g {
                    Some(head) => {
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
                class.in_use.fetch_add(1, Ordering::Relaxed);
                return Ok(blk.cast());
            }
        }

        // SLOW PATH 2: grow. Pull a fresh page, slab it into N blocks,
        // push half into the magazine + the rest onto central, return
        // the last block in the page.
        let frame: PhysFrame = alloc_frame()?;
        let base = frame.start_address().kernel_mut_ptr::<u8>();
        let block_size = class_size(c);
        let n_blocks = PAGE_SIZE_USIZE / block_size;
        let to_mag = (MAG_SIZE / 2).min(n_blocks - 1);
        // SAFETY: `base..base+PAGE_SIZE_USIZE` is a fresh frame
        // accessed via the per-arch kernel mapping (identity on
        // x86_64, TTBR1 high-half on aarch64) so the write stays
        // valid across user-task page-table swaps.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            for i in 0..to_mag {
                let blk = NonNull::new_unchecked(base.add(i * block_size) as *mut FreeBlock);
                mag.stack[mag.top] = Some(blk);
                mag.top += 1;
            }
            let mut g = class.head.lock();
            for i in to_mag..(n_blocks - 1) {
                let blk = base.add(i * block_size) as *mut FreeBlock;
                (*blk).next = *g;
                *g = NonNull::new(blk);
            }
            drop(g);
        }
        class.grown.fetch_add(n_blocks, Ordering::Relaxed);
        class.in_use.fetch_add(1, Ordering::Relaxed);
        // Last block is the one we return.
        // SAFETY: identity-mapped frame.
        Ok(unsafe { NonNull::new_unchecked(base.add((n_blocks - 1) * block_size)) })
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
