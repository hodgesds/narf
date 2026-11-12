//! Retention smokes: the heap must give back what a burst of allocations
//! took, measured in frames per size class rather than in time.
//!
//! A class that holds more frames after its objects are freed than before
//! they were allocated either leaks (its live-object count stays up) or
//! retains freed memory (live count back at baseline, frames not). These
//! smokes drive both halves of that distinction through the same public
//! counters `/proc/slabinfo` and `/proc/narf/slab` print.

use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{alloc, blocks_per_frame, class_detail, class_size, dealloc, N_CLASSES};

/// Frames each class grows by in the churn smoke: enough that keeping them
/// all is unmistakable next to the bounded per-class cache.
const CHURN_FRAMES: usize = 128;

/// Noise allowance per class, in frames: this CPU's magazine can pin one
/// frame per cached block, and other CPUs keep allocating while the smoke
/// runs.
const NOISE_FRAMES: usize = super::MAG_SIZE + 8;

/// SLUB keeps at most `min_partial` (5..=10) empty slabs per node; the
/// retained empty-frame cache must be no larger.
const MAX_EMPTY_CACHE: usize = 10;

fn layout(c: usize) -> Layout {
    Layout::from_size_align(class_size(c), 16).expect("power-of-two class layout")
}

/// Park–Miller style LCG step; deterministic across runs and arches.
fn next(seed: &mut u64) -> usize {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (*seed >> 33) as usize
}

/// Free every recorded object.
fn free_all(ptrs: &mut Vec<(usize, NonNull<u8>)>) {
    for (c, p) in ptrs.drain(..) {
        // SAFETY: each entry was returned by `alloc(layout(c))` and is freed
        // exactly once here.
        unsafe { dealloc(p, layout(c)) };
    }
}

/// Allocate `CHURN_FRAMES` frames' worth of objects in every class, in an
/// interleaved class order; return them in a shuffled order. Errors skip
/// (memory-starved runner), never leak.
fn churn_every_class() -> Result<(), TestResult> {
    let mut want = [0usize; N_CLASSES];
    for (c, slot) in want.iter_mut().enumerate() {
        *slot = CHURN_FRAMES * blocks_per_frame(c);
    }
    let total: usize = want.iter().sum();
    // One large (buddy-backed) vector: recording the pointers must not itself
    // grow the classes under test.
    let mut ptrs: Vec<(usize, NonNull<u8>)> = Vec::new();
    if ptrs.try_reserve_exact(total).is_err() {
        return Err(TestResult::Skip("pointer table allocation failed"));
    }
    let mut seed = 0x5EED_51AB_C0FF_EE01u64;
    while ptrs.len() < total {
        let mut c = next(&mut seed) % N_CLASSES;
        while want[c] == 0 {
            c = (c + 1) % N_CLASSES;
        }
        want[c] -= 1;
        match alloc(layout(c)) {
            Ok(p) => ptrs.push((c, p)),
            Err(_) => {
                free_all(&mut ptrs);
                return Err(TestResult::Skip("frame allocator drained"));
            }
        }
    }
    // Fisher–Yates: frees arrive in no particular frame order, so frames go
    // partial → empty in a mixed sequence, as they do under real churn.
    for i in (1..ptrs.len()).rev() {
        let j = next(&mut seed) % (i + 1);
        ptrs.swap(i, j);
    }
    free_all(&mut ptrs);
    Ok(())
}

/// Mixed-class, mixed-order churn returns its frames: once the executor's
/// maintenance hook has run, every class is back at its baseline frame count
/// plus at most a SLUB-sized empty-frame cache. Fails while freed frames are
/// parked until a class's whole free pool passes a large watermark.
fn smoke_slab_mixed_churn_returns_empty_frames() -> TestResult {
    let mut base = [0usize; N_CLASSES];
    for (c, slot) in base.iter_mut().enumerate() {
        *slot = class_detail(c).frames;
    }
    if let Err(r) = churn_every_class() {
        return r;
    }
    // The executor runs this between dispatches on every CPU; a few rounds
    // stand in for a few ticks (each round has a bounded per-class budget).
    for _ in 0..8 {
        super::drain_over_watermark();
    }
    for (c, &before) in base.iter().enumerate() {
        let d = class_detail(c);
        if d.frames > before + MAX_EMPTY_CACHE + NOISE_FRAMES {
            return TestResult::Fail(match c {
                0 => "kmalloc-16 kept the churn's freed frames",
                1 => "kmalloc-32 kept the churn's freed frames",
                2 => "kmalloc-64 kept the churn's freed frames",
                3 => "kmalloc-128 kept the churn's freed frames",
                4 => "kmalloc-256 kept the churn's freed frames",
                5 => "kmalloc-512 kept the churn's freed frames",
                6 => "kmalloc-1024 kept the churn's freed frames",
                7 => "kmalloc-2048 kept the churn's freed frames",
                _ => "kmalloc-4096 kept the churn's freed frames",
            });
        }
        if d.empty_frames > MAX_EMPTY_CACHE + NOISE_FRAMES {
            return TestResult::Fail("a class's empty-frame cache exceeds the SLUB bound");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/slab_retention",
    smoke_slab_mixed_churn_returns_empty_frames
);
