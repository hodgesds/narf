//! Physical frames + per-NUMA-node frame allocator.
//!
//! Wave-2 subset of `memory/` spec §3 with Wave-3 NUMA awareness:
//! per-node free-stack allocators, classified by SRAT memory-range
//! attribution. The allocator stays simple (free-stack, not buddy);
//! the buddy allocator + magazines land later.
//!
//! Layout:
//! - One `Vec<PhysFrame>` per NUMA node (`MAX_NUMA_NODES`). Boot
//!   inits flat (everything goes to bin 0); `rebalance_to_topology`
//!   redistributes the remaining frames to their proper bins once
//!   SRAT data is available.
//! - `alloc_frame()` consults the current CPU's NUMA node first
//!   (looked up via the weak-link `narf_cpu_to_node` hook), then
//!   falls back round-robin to other nodes.
//! - `alloc_frame_on(node)` is the explicit-node entry point.
//! - `free_frame(f)` uses `narf_phys_to_node` to return the frame
//!   to its rightful node bin.
//!
//! Cycle avoidance: this crate cannot depend on `narf-acpi`
//! (narf-acpi pulls in `narf_memory::PhysAddr`). The hooks below are
//! the standard weakly-linked surface — narf-frame provides
//! `#[no_mangle]` definitions calling into narf-acpi at boot.

use core::fmt;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::PhysAddr;

/// Page size in bytes. x86_64 / aarch64 both use 4 KiB as the base size.
pub const PAGE_SIZE: u64 = 4096;
/// Log2 of the page size; handy for shifts.
pub const PAGE_SHIFT: u32 = 12;

/// Maximum NUMA nodes we track. Mirrors `narf_acpi::MAX_NUMA_NODES`
/// — kept independent so this crate doesn't pull in narf-acpi.
pub const MAX_NUMA_NODES: usize = 16;

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

/// Per-node free-stack allocator. Index 0 holds everything pre-
/// `rebalance_to_topology`; post-rebalance each node has only the
/// frames whose physical addresses map to its proximity domain.
#[derive(Debug)]
pub struct FrameAllocator {
    bins:            [Vec<PhysFrame>; MAX_NUMA_NODES],
    initialised:     bool,
    total_frames:    usize,
    reserved_frames: usize,
    /// Set after `rebalance_to_topology` completes; alloc + free
    /// honour per-node bins from this point on. Pre-flag, every
    /// allocation comes out of bin 0.
    numa_aware:      bool,
}

const NEW_VEC: Vec<PhysFrame> = Vec::new();

static ALLOC: IrqSafeSpinLock<FrameAllocator> = IrqSafeSpinLock::new(
    FrameAllocator {
        bins:            [NEW_VEC; MAX_NUMA_NODES],
        initialised:     false,
        total_frames:    0,
        reserved_frames: 0,
        numa_aware:      false,
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
    // Two-pass to avoid Vec growth thrashing.
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

    let mut bin0: Vec<PhysFrame> = Vec::with_capacity(pageable);
    for r in usable {
        let start = r.start.raw();
        let end   = start + r.len;
        let first = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let last  = end & !(PAGE_SIZE - 1);
        let mut a = first;
        while a + PAGE_SIZE <= last {
            if !is_excluded(a, exclude) {
                bin0.push(PhysFrame::new(PhysAddr::new(a)));
            }
            a += PAGE_SIZE;
        }
    }

    let mut guard = ALLOC.lock();
    guard.bins[0] = bin0;
    guard.initialised     = true;
    guard.total_frames    = total;
    guard.reserved_frames = reserved;
    guard.numa_aware      = false;
}

fn is_excluded(addr: u64, exclude: &[(u64, u64)]) -> bool {
    exclude.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
}

/// Redistribute frames currently in bin 0 across per-NUMA-node bins
/// according to `narf_phys_to_node`. Call this once after ACPI SRAT
/// has been parsed (`narf_acpi::parse_srat`). Idempotent — repeated
/// calls are no-ops.
pub fn rebalance_to_topology() {
    let mut g = ALLOC.lock();
    if g.numa_aware || !g.initialised { return; }

    // Drain bin 0 into a temporary, then redistribute.
    let drained: Vec<PhysFrame> =
        core::mem::replace(&mut g.bins[0], Vec::new());

    for f in drained {
        let node = phys_to_node(f.start_address().raw());
        g.bins[node].push(f);
    }
    g.numa_aware = true;
}

/// Allocate one 4 KiB frame. NUMA-aware: prefers the current CPU's
/// node, falls back round-robin to other nodes when the local bin
/// is empty.
pub fn alloc_frame() -> Result<PhysFrame, FrameAllocError> {
    let preferred = current_cpu_node();
    alloc_frame_on(preferred)
}

/// Allocate one 4 KiB frame, preferring `node`'s bin. Falls back to
/// other nodes when `node`'s bin is empty.
pub fn alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    if !g.initialised { return Err(FrameAllocError::Uninitialised); }

    if !g.numa_aware {
        // Pre-rebalance: everything's in bin 0.
        return g.bins[0].pop().ok_or(FrameAllocError::Exhausted);
    }

    let preferred = node.min(MAX_NUMA_NODES - 1);
    if let Some(f) = g.bins[preferred].pop() { return Ok(f); }

    // Fallback: round-robin from the next-highest node, wrapping.
    for offset in 1..MAX_NUMA_NODES {
        let i = (preferred + offset) % MAX_NUMA_NODES;
        if let Some(f) = g.bins[i].pop() { return Ok(f); }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate a frame from any node. Useful for boot-time allocations
/// that don't care about locality.
pub fn alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    let mut g = ALLOC.lock();
    if !g.initialised { return Err(FrameAllocError::Uninitialised); }
    for bin in g.bins.iter_mut() {
        if let Some(f) = bin.pop() { return Ok(f); }
    }
    Err(FrameAllocError::Exhausted)
}

/// Return a previously-allocated frame to the pool. The frame's
/// physical address selects which node bin it goes back into.
pub fn free_frame(f: PhysFrame) {
    let node = phys_to_node(f.start_address().raw());
    let mut g = ALLOC.lock();
    if !g.initialised { return; }
    if g.numa_aware {
        g.bins[node].push(f);
    } else {
        g.bins[0].push(f);
    }
}

/// Snapshot of allocator usage (aggregate across nodes).
pub fn stats() -> FrameStats {
    let g = ALLOC.lock();
    let free: usize = g.bins.iter().map(|b| b.len()).sum();
    FrameStats {
        total:    g.total_frames,
        free,
        reserved: g.reserved_frames,
    }
}

/// Per-node free-frame count. Returns 0 when `node` is out of range
/// or the allocator hasn't been initialised.
pub fn node_free(node: usize) -> usize {
    if node >= MAX_NUMA_NODES { return 0; }
    let g = ALLOC.lock();
    g.bins[node].len()
}

/// True once `rebalance_to_topology` has run.
pub fn is_numa_aware() -> bool {
    ALLOC.lock().numa_aware
}

#[derive(Copy, Clone, Debug)]
pub struct FrameStats {
    pub total:    usize,
    pub free:     usize,
    pub reserved: usize,
}

// ── Weak-link hooks for NUMA topology lookup ────────────────────────
//
// narf-memory cannot depend on narf-acpi (would form a cycle —
// narf-acpi already uses narf_memory::PhysAddr). The kernel binary
// (narf-frame) provides `#[no_mangle]` definitions that call into
// narf-acpi; tests and other binaries that don't care about NUMA
// can provide stubs returning 0.

extern "Rust" {
    /// Look up the NUMA node a physical address belongs to. Returns
    /// `0` when topology is unknown or the address is outside any
    /// SRAT memory range.
    fn narf_phys_to_node(addr: u64) -> u32;
    /// Look up the NUMA node hosting a logical CPU. Returns `0`
    /// when topology is unknown.
    fn narf_cpu_to_node(cpu: u32) -> u32;
}

#[inline]
fn phys_to_node(addr: u64) -> usize {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_phys_to_node(addr) } as usize;
    if n < MAX_NUMA_NODES { n } else { 0 }
}

#[inline]
fn current_cpu_node() -> usize {
    let cpu = narf_lib::percpu::current_cpu() as u32;
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_cpu_to_node(cpu) } as usize;
    if n < MAX_NUMA_NODES { n } else { 0 }
}
