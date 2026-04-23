//! Physical frames + Stage-1 frame allocator.
//!
//! Wave-2 subset of `memory/` spec §3: a `PhysFrame` newtype, a simple
//! free-stack frame allocator built from the bootloader memory map, and
//! typed alloc/free entry points. The full buddy allocator + magazines
//! land later — this is the bridge from "no physical-memory management"
//! to "kernel code can grab a 4 KiB page."
//!
//! Free-stack design (not buddy):
//!
//! - Frames are 4 KiB. Higher-order requests are rejected — Wave-2 full
//!   buddy lands them.
//! - Each `MemRegionKind::Usable` region is split into 4 KiB aligned
//!   frames and pushed onto a `Vec<PhysFrame>`. Alloc pops; free pushes.
//! - O(1) alloc/free. Fragmentation is irrelevant at 4 KiB granularity.
//!
//! The allocator is guarded by an `IrqSafeSpinLock`; Stage 1 is BSP-only
//! but the lock is future-proof for AP bring-up in Wave 2.

use core::fmt;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::PhysAddr;

/// Page size in bytes. x86_64 / aarch64 both use 4 KiB as the base size.
pub const PAGE_SIZE: u64 = 4096;
/// Log2 of the page size; handy for shifts.
pub const PAGE_SHIFT: u32 = 12;

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
        debug_assert!(addr.raw() & (PAGE_SIZE - 1) == 0,
                      "PhysFrame::new requires a page-aligned PhysAddr");
        Self(addr)
    }

    /// Round `addr` down to a page boundary and wrap.
    pub const fn containing(addr: PhysAddr) -> Self {
        Self(PhysAddr::new(addr.raw() & !(PAGE_SIZE - 1)))
    }

    /// Starting physical address of this frame.
    #[inline]
    pub const fn start_address(self) -> PhysAddr { self.0 }

    /// Frame number (phys >> PAGE_SHIFT).
    #[inline]
    pub const fn number(self) -> u64 { self.0.raw() >> PAGE_SHIFT }
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
}

/// The Stage-1 free-stack frame allocator.
#[derive(Debug)]
pub struct FrameAllocator {
    free: Option<Vec<PhysFrame>>,
    total_frames:  usize,
    reserved_frames: usize,   // never added to `free`; diagnostics only
}

static ALLOC: IrqSafeSpinLock<FrameAllocator> = IrqSafeSpinLock::new(
    FrameAllocator {
        free: None,
        total_frames:    0,
        reserved_frames: 0,
    });

/// A subset of the bootloader memory map: just what the allocator needs.
/// Consumers typically pass `BootInfo::memory_map` via `narf_boot`.
#[derive(Copy, Clone, Debug)]
pub struct UsableRegion {
    pub start: PhysAddr,
    pub len:   u64,
}

/// Initialise the frame allocator from a slice of usable regions. `exclude`
/// is a list of half-open byte ranges that must NOT be handed out — the
/// kernel image itself, the boot-info structure, the PVH hvm_start_info,
/// and so on.
///
/// # Safety
/// - Must be called exactly once, before any `alloc_frame` / `free_frame`.
/// - Each `UsableRegion` must be real, kernel-reachable physical RAM;
///   violating this hands out bogus frames that will fault on first
///   touch.
pub unsafe fn init_from_map(usable: &[UsableRegion], exclude: &[(u64, u64)]) {
    // Two-pass to avoid Vec growth thrashing: the Stage-1 bump heap never
    // reclaims, so a doubling Vec<PhysFrame> leaves each superseded buffer
    // pinned — for 256 MiB of RAM (64K frames × 8 B = 512 KiB final Vec)
    // the growth trail burns ~1 MiB, blowing the 1 MiB heap.
    //
    // Pass 1: count pageable frames exactly. Pass 2: Vec::with_capacity(n)
    // and fill in a single allocation.
    let mut total = 0usize;
    let mut reserved = 0usize;
    let mut pageable = 0usize;
    for r in usable {
        let start = r.start.raw();
        let end   = start + r.len;
        let first = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let last  = end & !(PAGE_SIZE - 1);
        let mut a = first;
        while a + PAGE_SIZE <= last {
            total += 1;
            if is_excluded(a, exclude) { reserved += 1; }
            else                        { pageable += 1; }
            a += PAGE_SIZE;
        }
    }

    let mut free: Vec<PhysFrame> = Vec::with_capacity(pageable);
    for r in usable {
        let start = r.start.raw();
        let end   = start + r.len;
        let first = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let last  = end & !(PAGE_SIZE - 1);
        let mut a = first;
        while a + PAGE_SIZE <= last {
            if !is_excluded(a, exclude) {
                free.push(PhysFrame::new(PhysAddr::new(a)));
            }
            a += PAGE_SIZE;
        }
    }

    let mut guard = ALLOC.lock();
    guard.free = Some(free);
    guard.total_frames    = total;
    guard.reserved_frames = reserved;
}

fn is_excluded(addr: u64, exclude: &[(u64, u64)]) -> bool {
    exclude.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
}

/// Allocate one 4 KiB frame. Returns `Err(Exhausted)` when the free
/// stack is empty.
pub fn alloc_frame() -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    let Some(free) = g.free.as_mut() else { return Err(FrameAllocError::Uninitialised); };
    free.pop().ok_or(FrameAllocError::Exhausted)
}

/// Return a previously-allocated frame to the pool. `free`-ing a frame
/// that was never allocated is undefined — the allocator trusts the
/// caller. Wave-2 full allocator adds a bitmap guard.
pub fn free_frame(f: PhysFrame) {
    let mut g = ALLOC.lock();
    if let Some(free) = g.free.as_mut() {
        free.push(f);
    }
}

/// Snapshot of allocator usage. Panics if `init_from_map` hasn't run.
pub fn stats() -> FrameStats {
    let g = ALLOC.lock();
    let free = g.free.as_ref().map(|v| v.len()).unwrap_or(0);
    FrameStats {
        total:    g.total_frames,
        free,
        reserved: g.reserved_frames,
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FrameStats {
    pub total:    usize,
    pub free:     usize,
    pub reserved: usize,
}
