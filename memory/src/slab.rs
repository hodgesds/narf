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
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

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
const fn class_size(i: usize) -> usize { MIN_BLOCK << i }

/// Pick the class for `size`. Returns `None` if size > largest class.
#[inline]
fn class_for(size: usize) -> Option<usize> {
    if size == 0 { return Some(0); }
    let s = core::cmp::max(size, MIN_BLOCK);
    // ceil(log2(s)) - log2(MIN_BLOCK).
    let log = (s.next_power_of_two().trailing_zeros() as usize)
        .saturating_sub(MIN_BLOCK.trailing_zeros() as usize);
    if log < N_CLASSES { Some(log) } else { None }
}

#[repr(C)]
struct FreeBlock {
    next: Option<NonNull<FreeBlock>>,
}

/// Per-size-class state. Free-list head is behind a spin-lock; the
/// stat counters are atomics so observers can read them lock-free.
struct SizeClass {
    head:        IrqSafeSpinLock<Option<NonNull<FreeBlock>>>,
    /// Total blocks ever produced by this class (alloc-backed).
    grown:       AtomicUsize,
    /// Currently-allocated block count.
    in_use:      AtomicUsize,
}

impl SizeClass {
    const fn new() -> Self {
        Self {
            head:   IrqSafeSpinLock::new(None),
            grown:  AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
        }
    }
}

// SAFETY: the IrqSafeSpinLock guards the free list; the NonNull
// pointers it holds reference DMA-mapped frames the allocator owns
// for the lifetime of the kernel.
unsafe impl Sync for SizeClass {}

static CLASSES: [SizeClass; N_CLASSES] = [
    SizeClass::new(), SizeClass::new(), SizeClass::new(),
    SizeClass::new(), SizeClass::new(), SizeClass::new(),
    SizeClass::new(), SizeClass::new(), SizeClass::new(),
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
    fn from(_: crate::FrameAllocError) -> Self { SlabError::NoMemory }
}

/// Allocate `layout` bytes. Pointer is aligned to at least
/// `MIN_BLOCK` for size-class allocations and to `PAGE_SIZE_USIZE` for
/// large allocations.
///
/// Returns `Err(SlabError::LayoutUnsupported)` when the alignment
/// exceeds `PAGE_SIZE_USIZE`.
pub fn alloc(layout: Layout) -> Result<NonNull<u8>, SlabError> {
    if layout.align() > PAGE_SIZE_USIZE { return Err(SlabError::LayoutUnsupported); }

    let need = layout.size().max(layout.align()).max(MIN_BLOCK);
    let class = class_for(need);
    match class {
        Some(c) => alloc_class(c),
        None    => alloc_large(layout),
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
        None    => unsafe { dealloc_large(ptr, layout) },
    }
}

fn alloc_class(c: usize) -> Result<NonNull<u8>, SlabError> {
    let class = &CLASSES[c];
    // Fast path: pop the head.
    let mut g = class.head.lock();
    if let Some(head) = *g {
        // SAFETY: head was a previously-pushed block in this class;
        // its `next` field is the slab-managed link.
        let next = unsafe { head.as_ref().next };
        *g = next;
        drop(g);
        class.in_use.fetch_add(1, Ordering::Relaxed);
        return Ok(head.cast());
    }
    drop(g);

    // Slow path: grow. Pull a fresh page, slab it into N blocks,
    // push all-but-one onto the free list, return the last.
    let frame: PhysFrame = alloc_frame()?;
    let base = frame.start_address().raw() as *mut u8;
    let block_size = class_size(c);
    let n_blocks   = PAGE_SIZE_USIZE / block_size;
    // SAFETY: `base..base+PAGE_SIZE_USIZE` is a fresh frame mapped 1:1
    // (low-4-GiB identity map on x86_64 / lo_L1[1] Normal block on
    // aarch64). We carve N adjacent blocks each `block_size` bytes.
    unsafe {
        let mut g2 = class.head.lock();
        // Push blocks 1..n in reverse so the first pop returns
        // block 0 (purely cosmetic — keeps allocator output predictable
        // in dumps).
        for i in (1..n_blocks).rev() {
            let blk = base.add(i * block_size) as *mut FreeBlock;
            (*blk).next = *g2;
            *g2 = NonNull::new(blk);
        }
        drop(g2);
    }
    class.grown.fetch_add(n_blocks, Ordering::Relaxed);
    class.in_use.fetch_add(1, Ordering::Relaxed);
    // Block 0 is the one we return.
    // SAFETY: same identity-mapped frame.
    Ok(unsafe { NonNull::new_unchecked(base) })
}

unsafe fn dealloc_class(c: usize, ptr: NonNull<u8>) {
    let class = &CLASSES[c];
    let blk = ptr.cast::<FreeBlock>();
    let mut g = class.head.lock();
    // SAFETY: caller asserts ptr was allocated from this class; we
    // overwrite the block's `next` field with the current head and
    // push.
    unsafe {
        let mut blk_mut = blk;
        blk_mut.as_mut().next = *g;
    }
    *g = Some(blk);
    drop(g);
    class.in_use.fetch_sub(1, Ordering::Relaxed);
}

fn alloc_large(layout: Layout) -> Result<NonNull<u8>, SlabError> {
    let n_pages = (layout.size() + PAGE_SIZE_USIZE - 1) / PAGE_SIZE_USIZE;
    if n_pages == 0 { return Err(SlabError::LayoutUnsupported); }
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
    pub grown:      usize,
    pub in_use:     usize,
}

/// Snapshot of all size classes + the large-alloc counter.
#[derive(Copy, Clone, Debug)]
pub struct SlabStats {
    pub classes:        [ClassStats; N_CLASSES],
    pub large_in_use:   usize,
}

pub fn stats() -> SlabStats {
    let mut classes = [ClassStats { block_size: 0, grown: 0, in_use: 0 }; N_CLASSES];
    for (i, c) in CLASSES.iter().enumerate() {
        classes[i] = ClassStats {
            block_size: class_size(i),
            grown:      c.grown.load(Ordering::Relaxed),
            in_use:     c.in_use.load(Ordering::Relaxed),
        };
    }
    SlabStats {
        classes,
        large_in_use: LARGE_IN_USE.load(Ordering::Relaxed),
    }
}

/// Number of distinct size classes the allocator supports.
pub const fn num_classes() -> usize { N_CLASSES }

/// Largest size class's block size. Allocations strictly larger
/// fall through to the page-frame buddy.
pub const fn max_class_size() -> usize { class_size(N_CLASSES - 1) }
