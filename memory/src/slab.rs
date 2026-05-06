//! Size-class slab allocator over the page-frame buddy.
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
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::percpu::{current_cpu, MAX_CPUS};
use narf_lib::sync::IrqSafeSpinLock;

use crate::frame::{alloc_frame, free_frame, PhysFrame};
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
struct SizeClass {
    head: IrqSafeSpinLock<Option<NonNull<FreeBlock>>>,
    /// Total blocks ever produced by this class (alloc-backed).
    grown: AtomicUsize,
    /// Currently-allocated block count.
    in_use: AtomicUsize,
    /// Per-CPU magazines. Indexed by `current_cpu()`.
    magazines: [Magazine; MAX_CPUS],
}

impl SizeClass {
    const fn new() -> Self {
        Self {
            head: IrqSafeSpinLock::new(None),
            grown: AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
            magazines: [const { Magazine::new() }; MAX_CPUS],
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
        Some(c) => unsafe { dealloc_class(c, ptr) },
        None => unsafe { dealloc_large(ptr, layout) },
    }
}

fn alloc_class(c: usize) -> Result<NonNull<u8>, SlabError> {
    let class = &CLASSES[c];
    let cpu = current_cpu();

    // FAST PATH: pop from the per-CPU magazine. No atomics, no
    // lock — only the active CPU touches its own magazine cell.
    // SAFETY: per-CPU access invariant.
    let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
    if mag.top > 0 {
        mag.top -= 1;
        let blk = mag.stack[mag.top].take().expect("magazine top non-null");
        class.in_use.fetch_add(1, Ordering::Relaxed);
        return Ok(blk.cast());
    }

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
    let base = frame.start_address().raw() as *mut u8;
    let block_size = class_size(c);
    let n_blocks = PAGE_SIZE_USIZE / block_size;
    let to_mag = (MAG_SIZE / 2).min(n_blocks - 1);
    // SAFETY: `base..base+PAGE_SIZE_USIZE` is a fresh identity-mapped
    // frame.
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
}

unsafe fn dealloc_class(c: usize, ptr: NonNull<u8>) {
    let class = &CLASSES[c];
    let cpu = current_cpu();

    // FAST PATH: push onto the per-CPU magazine.
    // SAFETY: per-CPU access invariant.
    let mag = unsafe { &mut *class.magazines[cpu].inner.get() };
    if mag.top < MAG_SIZE {
        mag.stack[mag.top] = Some(ptr.cast::<FreeBlock>());
        mag.top += 1;
        class.in_use.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    // SLOW PATH: magazine full. Flush the bottom half back to the
    // central free list, compact the top half down, then push the
    // freshly-freed block.
    let flush = MAG_SIZE / 2;
    let mut g = class.head.lock();
    for i in 0..flush {
        let mut blk = mag.stack[i].expect("magazine full");
        // SAFETY: blocks were originally allocated from this slab,
        // so overwriting `next` re-links them onto the central head.
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
}

fn alloc_large(layout: Layout) -> Result<NonNull<u8>, SlabError> {
    let n_pages = (layout.size() + PAGE_SIZE_USIZE - 1) / PAGE_SIZE_USIZE;
    if n_pages == 0 {
        return Err(SlabError::LayoutUnsupported);
    }
    if n_pages > 1 {
        // Multi-page contiguous allocations need a buddy / region
        // allocator that we don't yet expose. Stage-5 follow-up.
        return Err(SlabError::LayoutUnsupported);
    }
    let frame = alloc_frame()?;
    LARGE_IN_USE.fetch_add(1, Ordering::Relaxed);
    let p = frame.start_address().raw() as *mut u8;
    // SAFETY: `p` is identity-mapped + page-aligned.
    Ok(unsafe { NonNull::new_unchecked(p) })
}

unsafe fn dealloc_large(ptr: NonNull<u8>, _layout: Layout) {
    let phys = crate::PhysAddr::new(ptr.as_ptr() as u64);
    let frame = PhysFrame::new(phys);
    free_frame(frame);
    LARGE_IN_USE.fetch_sub(1, Ordering::Relaxed);
}

/// Per-class diagnostic snapshot.
#[derive(Copy, Clone, Debug)]
pub struct ClassStats {
    pub block_size: usize,
    pub grown: usize,
    pub in_use: usize,
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
    }; N_CLASSES];
    for (i, c) in CLASSES.iter().enumerate() {
        classes[i] = ClassStats {
            block_size: class_size(i),
            grown: c.grown.load(Ordering::Relaxed),
            in_use: c.in_use.load(Ordering::Relaxed),
        };
    }
    SlabStats {
        classes,
        large_in_use: LARGE_IN_USE.load(Ordering::Relaxed),
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
