//! Hugepage pool — 2 MiB and 1 GiB pages, separate from the buddy.
//!
//! The buddy's `MAX_ORDER = 10` caps it at 4 MiB blocks. Workloads
//! that legitimately want larger naturally-aligned pages —
//! virtualization guest backing, large DMA buffers, kernel
//! direct-map extensions — use this module instead.
//!
//! Reservation policy (see `memory/specification/heap-migration.md`
//! §3.1.2 / §4.6): at boot, `reserve_from_regions()` walks the
//! usable memory map and carves leading naturally-aligned 1 GiB
//! and 2 MiB chunks out of each region, up to the cmdline-bounded
//! targets. Whatever leading misalignment + tail remains is
//! handed to the buddy via the normal `init_from_map` path,
//! reported as a list of byte-range excludes.
//!
//! Hugepage allocations DO NOT fall back to coalescing buddy
//! blocks. If the boot reservation didn't capture enough,
//! `alloc_hugepage_*` returns `Err(Empty)` and the caller has
//! to either retry with smaller pages or arrange to start
//! before fragmentation eats the contiguous regions. This is
//! the explicit Linux model (`hugepages=` boot param).
//!
//! Provenance: clean-room. Pool layout patterned on Bonwick's
//! observation (USENIX 1994 §4) that fixed-class object pools
//! collapse into trivial stack-pop / stack-push when no
//! coalescing is needed. No Linux mm/hugetlb sources consulted.

extern crate alloc as alloc_crate;

use alloc_crate::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::frame::{self, UsableRegion, MAX_NUMA_NODES};
use crate::mempolicy::{Mempolicy, MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED};

/// 2 MiB hugepage size in bytes.
pub const HUGEPAGE_2M_BYTES: u64 = 2 * 1024 * 1024;
/// 1 GiB hugepage size in bytes.
pub const HUGEPAGE_1G_BYTES: u64 = 1024 * 1024 * 1024;

/// Hugepage size discriminator. `M2` = 2 MiB, `G1` = 1 GiB.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HugeSize {
    M2,
    G1,
}

/// A reserved hugepage. The phys address is naturally aligned to
/// the corresponding size. Returned by `alloc_hugepage_*`, freed
/// via `free_hugepage`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugeFrame {
    phys: u64,
    size: HugeSize,
}

impl HugeFrame {
    /// Physical base address of the hugepage. Naturally aligned to
    /// `size_bytes()`.
    #[inline]
    pub fn phys(&self) -> u64 {
        self.phys
    }
    /// Hugepage size class.
    #[inline]
    pub fn size(&self) -> HugeSize {
        self.size
    }
    /// Hugepage size in bytes.
    #[inline]
    pub fn size_bytes(&self) -> u64 {
        match self.size {
            HugeSize::M2 => HUGEPAGE_2M_BYTES,
            HugeSize::G1 => HUGEPAGE_1G_BYTES,
        }
    }

    /// SRAT proximity node containing this hugepage.
    #[inline]
    pub fn node(&self) -> usize {
        // SAFETY: the frame was carved from a usable physical-memory region.
        unsafe { frame::narf_phys_node(self.phys) }
    }
}

/// Hugepage allocator error. Only failure mode is pool exhaustion —
/// hugepages don't fall back to the buddy (see module docs).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HugeAllocError {
    Empty,
}

struct HugePool {
    free_2m: Vec<u64>,
    free_1g: Vec<u64>,
    reserved_2m: usize,
    reserved_1g: usize,
}

impl HugePool {
    const fn new() -> Self {
        Self {
            free_2m: Vec::new(),
            free_1g: Vec::new(),
            reserved_2m: 0,
            reserved_1g: 0,
        }
    }
}

static POOL: IrqSafeSpinLock<HugePool> = IrqSafeSpinLock::new(HugePool::new());

/// Carve naturally-aligned hugepages out of `usable` regions, up
/// to the requested counts, and stash them in the pool. Returns
/// the byte-range excludes that the buddy must skip when it
/// donates the same regions.
///
/// Algorithm (per region, processed in order):
///   1. Skip head bytes until 1 GiB-aligned. While we still want
///      1 GiB pages and the region has ≥ 1 GiB remaining, claim
///      a 1 GiB chunk and advance.
///   2. Then, while we still want 2 MiB pages and the region has
///      ≥ 2 MiB remaining (with 2 MiB-aligned cursor), claim a
///      2 MiB chunk and advance.
///   3. The leading misalignment + trailing remainder stay with
///      the region; the buddy will pick those up.
///
/// Each successful claim adds a `(start_byte, end_byte)` exclude
/// so init_from_map's donate path skips that range.
///
/// Idempotency: this is a one-shot boot call. Calling twice
/// would push duplicate phys addresses into the pool and is a
/// caller bug.
pub fn reserve_from_regions(
    usable: &[UsableRegion],
    want_2m: usize,
    want_1g: usize,
) -> Vec<(u64, u64)> {
    let mut excludes: Vec<(u64, u64)> = Vec::new();
    let mut pool = POOL.lock();
    let cap_2m = pool.free_2m.capacity();
    let cap_1g = pool.free_1g.capacity();
    pool.free_2m.reserve_exact(want_2m.saturating_sub(cap_2m));
    pool.free_1g.reserve_exact(want_1g.saturating_sub(cap_1g));
    let mut left_2m = want_2m;
    let mut left_1g = want_1g;

    for r in usable {
        let region_start = r.start.raw();
        let region_end = region_start + r.len;
        let mut cursor = region_start;

        // Phase 1: claim 1 GiB chunks while available + wanted.
        while left_1g > 0 {
            let aligned = (cursor + HUGEPAGE_1G_BYTES - 1) & !(HUGEPAGE_1G_BYTES - 1);
            let chunk_end = aligned + HUGEPAGE_1G_BYTES;
            if chunk_end > region_end {
                break;
            }
            pool.free_1g.push(aligned);
            pool.reserved_1g += 1;
            excludes.push((aligned, chunk_end));
            cursor = chunk_end;
            left_1g -= 1;
        }

        // Phase 2: claim 2 MiB chunks while available + wanted.
        while left_2m > 0 {
            let aligned = (cursor + HUGEPAGE_2M_BYTES - 1) & !(HUGEPAGE_2M_BYTES - 1);
            let chunk_end = aligned + HUGEPAGE_2M_BYTES;
            if chunk_end > region_end {
                break;
            }
            pool.free_2m.push(aligned);
            pool.reserved_2m += 1;
            excludes.push((aligned, chunk_end));
            cursor = chunk_end;
            left_2m -= 1;
        }

        if left_2m == 0 && left_1g == 0 {
            break;
        }
    }
    excludes
}

/// Allocate one 2 MiB hugepage from the boot-reserved pool.
/// Returns `Err(Empty)` if the pool is exhausted — does NOT fall
/// back to coalescing buddy blocks.
pub fn alloc_hugepage_2m() -> Result<HugeFrame, HugeAllocError> {
    alloc_hugepage_local(HugeSize::M2)
}

/// Allocate one 1 GiB hugepage from the boot-reserved pool.
/// Returns `Err(Empty)` if the pool is exhausted.
pub fn alloc_hugepage_1g() -> Result<HugeFrame, HugeAllocError> {
    alloc_hugepage_local(HugeSize::G1)
}

/// Allocate a 2 MiB hugepage strictly from `node`.
///
/// Unlike the local-first convenience allocator, this never spills to
/// another node. It is the primitive used by NUMA memory-policy callers.
pub fn alloc_hugepage_2m_on(node: usize) -> Result<HugeFrame, HugeAllocError> {
    alloc_hugepage_on(HugeSize::M2, node)
}

/// Allocate a 1 GiB hugepage strictly from `node`.
pub fn alloc_hugepage_1g_on(node: usize) -> Result<HugeFrame, HugeAllocError> {
    alloc_hugepage_on(HugeSize::G1, node)
}

/// Allocate a hardware hugepage under the same NUMA policy semantics used by
/// demand-paged base frames.
pub fn alloc_hugepage_with(
    size: HugeSize,
    policy: Mempolicy,
    local: usize,
) -> Result<HugeFrame, HugeAllocError> {
    let all_nodes = (1u64 << MAX_NUMA_NODES) - 1;
    let allowed = policy.allowed & all_nodes;
    if allowed == 0 {
        return Err(HugeAllocError::Empty);
    }
    let requested = policy.nodemask & allowed;
    let preferred = match policy.mode {
        MPOL_BIND | MPOL_PREFERRED if requested != 0 => requested.trailing_zeros() as usize,
        MPOL_INTERLEAVE if requested != 0 => crate::mempolicy::next_interleave_node(requested),
        _ => local.min(MAX_NUMA_NODES - 1),
    };
    let candidates =
        if policy.mode == MPOL_BIND || (policy.mode == MPOL_INTERLEAVE && requested != 0) {
            requested
        } else {
            allowed
        };
    if candidates == 0 {
        return Err(HugeAllocError::Empty);
    }

    let mut order = [0usize; MAX_NUMA_NODES];
    let mut count = 0usize;
    for node in 0..MAX_NUMA_NODES {
        if (candidates >> node) & 1 != 0 {
            order[count] = node;
            count += 1;
        }
    }
    order[..count].sort_unstable_by_key(|&node| (frame::node_distance(preferred, node), node));
    if let Some(pos) = order[..count].iter().position(|&node| node == preferred) {
        order[..count].swap(0, pos);
    }
    for &node in &order[..count] {
        if let Ok(allocated) = alloc_hugepage_on(size, node) {
            let pages = allocated.size_bytes() >> 12;
            frame::account_numa_allocation(preferred, node, pages);
            if policy.mode == MPOL_INTERLEAVE && node == preferred {
                frame::account_interleave_hit(node, pages);
            }
            return Ok(allocated);
        }
    }
    Err(HugeAllocError::Empty)
}

fn alloc_hugepage_local(size: HugeSize) -> Result<HugeFrame, HugeAllocError> {
    let local = frame::current_cpu_node();
    if let Ok(frame) = alloc_hugepage_on(size, local) {
        return Ok(frame);
    }

    let mut candidates = [0usize; MAX_NUMA_NODES];
    let mut count = 0usize;
    for node in 0..MAX_NUMA_NODES {
        if node != local {
            candidates[count] = node;
            count += 1;
        }
    }
    candidates[..count].sort_unstable_by_key(|&node| (frame::node_distance(local, node), node));
    for &node in &candidates[..count] {
        if let Ok(frame) = alloc_hugepage_on(size, node) {
            return Ok(frame);
        }
    }
    Err(HugeAllocError::Empty)
}

pub(crate) fn alloc_hugepage_on(size: HugeSize, node: usize) -> Result<HugeFrame, HugeAllocError> {
    if node >= MAX_NUMA_NODES {
        return Err(HugeAllocError::Empty);
    }
    let mut pool = POOL.lock();
    let free = match size {
        HugeSize::M2 => &mut pool.free_2m,
        HugeSize::G1 => &mut pool.free_1g,
    };
    let Some(index) = free.iter().rposition(|&phys| {
        // SAFETY: every pool entry was carved from a usable region.
        unsafe { frame::narf_phys_node(phys) == node }
    }) else {
        return Err(HugeAllocError::Empty);
    };
    let phys = free.swap_remove(index);
    Ok(HugeFrame { phys, size })
}

/// Return a hugepage to the pool. Caller asserts the frame came
/// from a prior `alloc_hugepage_*` of the matching size.
pub fn free_hugepage(frame: HugeFrame) {
    let mut pool = POOL.lock();
    match frame.size {
        HugeSize::M2 => pool.free_2m.push(frame.phys),
        HugeSize::G1 => pool.free_1g.push(frame.phys),
    }
}

/// Snapshot of pool state for diagnostics + tests.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugeStats {
    pub reserved_2m: usize,
    pub reserved_1g: usize,
    pub free_2m: usize,
    pub free_1g: usize,
}

/// Per-node free hugepage counts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugeNodeStats {
    pub free_2m: usize,
    pub free_1g: usize,
}

/// Snapshot of pool state. Lock-acquiring; do not call from IRQ.
pub fn stats() -> HugeStats {
    let pool = POOL.lock();
    HugeStats {
        reserved_2m: pool.reserved_2m,
        reserved_1g: pool.reserved_1g,
        free_2m: pool.free_2m.len(),
        free_1g: pool.free_1g.len(),
    }
}

/// Snapshot the free hugepages physically located on `node`.
pub fn node_stats(node: usize) -> HugeNodeStats {
    if node >= MAX_NUMA_NODES {
        return HugeNodeStats {
            free_2m: 0,
            free_1g: 0,
        };
    }
    let pool = POOL.lock();
    HugeNodeStats {
        free_2m: pool
            .free_2m
            .iter()
            .filter(|&&phys| {
                // SAFETY: every pool entry was carved from usable memory.
                unsafe { frame::narf_phys_node(phys) == node }
            })
            .count(),
        free_1g: pool
            .free_1g
            .iter()
            .filter(|&&phys| {
                // SAFETY: every pool entry was carved from usable memory.
                unsafe { frame::narf_phys_node(phys) == node }
            })
            .count(),
    }
}
