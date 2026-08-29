//! Hugepage pool — 2 MiB and 1 GiB pages, separate from the buddy.
//!
//! The buddy's `MAX_ORDER = 10` caps it at 4 MiB blocks. Workloads
//! that legitimately want larger naturally-aligned pages —
//! virtualization guest backing, large DMA buffers, kernel
//! direct-map extensions — use this module instead.
//!
//! Reservation policy (see `memory/specification/heap-migration.md`
//! §3.1.2 / §4.6): at boot, `reserve_from_regions()` walks the
//! usable memory map and carves naturally-aligned 1 GiB and 2 MiB
//! chunks out of each region, up to the cmdline-bounded targets.
//! Caller-protected ranges (most importantly the loaded kernel image)
//! and the architecture-reserved low-memory window are skipped. Whatever
//! leading misalignment + protected holes + tail remains is handed to the
//! buddy via the normal `init_from_map` path, reported as a list of
//! byte-range excludes.
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
use crate::mempolicy::{
    Mempolicy, MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED, MPOL_PREFERRED_MANY,
    MPOL_WEIGHTED_INTERLEAVE,
};

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
    /// Free pages are partitioned by physical NUMA node. Strict-node
    /// allocation is therefore one stack pop instead of a reverse scan over
    /// every reserved huge page (and one SRAT lookup per candidate).
    free_2m: [Vec<u64>; MAX_NUMA_NODES],
    free_1g: [Vec<u64>; MAX_NUMA_NODES],
    /// Per-node reservation totals include allocated pages. Besides
    /// diagnostics, these let a later reservation pre-grow each stack for all
    /// outstanding frames so `free_hugepage` never reallocates while holding
    /// `POOL`.
    reserved_2m_by_node: [usize; MAX_NUMA_NODES],
    reserved_1g_by_node: [usize; MAX_NUMA_NODES],
    reserved_2m: usize,
    reserved_1g: usize,
}

impl HugePool {
    const fn new() -> Self {
        const NEW_VEC: Vec<u64> = Vec::new();
        Self {
            free_2m: [NEW_VEC; MAX_NUMA_NODES],
            free_1g: [NEW_VEC; MAX_NUMA_NODES],
            reserved_2m_by_node: [0; MAX_NUMA_NODES],
            reserved_1g_by_node: [0; MAX_NUMA_NODES],
            reserved_2m: 0,
            reserved_1g: 0,
        }
    }

    #[inline]
    fn free_mut(&mut self, size: HugeSize, node: usize) -> &mut Vec<u64> {
        match size {
            HugeSize::M2 => &mut self.free_2m[node],
            HugeSize::G1 => &mut self.free_1g[node],
        }
    }
}

static POOL: IrqSafeSpinLock<HugePool> = IrqSafeSpinLock::new(HugePool::new());

/// References to a hugepage BEYOND the one its allocation created.
///
/// Linux refcounts the hugetlb folio, so a `MAP_SHARED | MAP_HUGETLB` mapping
/// inherited across fork maps the same pages in both processes: the child must
/// not copy them, and the parent's exit must not free them while the child
/// still has them mapped.
///
/// Only the EXCESS is stored. A frame absent from this map has exactly one
/// owner, which is every private mapping — so the ordinary alloc/free path
/// stays a plain pool operation with no map traffic, and the table only ever
/// holds entries for genuinely shared frames.
static EXTRA_REFS: IrqSafeSpinLock<alloc_crate::collections::BTreeMap<u64, u32>> =
    IrqSafeSpinLock::new(alloc_crate::collections::BTreeMap::new());

/// Take another reference to `frame`, so the next [`free_hugepage`] returns it
/// to a sharer rather than to the pool.
pub fn retain_hugepage(frame: HugeFrame) {
    *EXTRA_REFS.lock().entry(frame.phys).or_insert(0) += 1;
}

/// How many owners `frame` has. 1 unless it is shared; used by tests to prove
/// a fork aliased rather than copied, and that an exit released rather than
/// freed.
pub fn hugepage_refs(frame: HugeFrame) -> u32 {
    1 + EXTRA_REFS.lock().get(&frame.phys).copied().unwrap_or(0)
}

/// Carve naturally-aligned hugepages out of `usable` regions, up to the
/// requested counts, and stash them in the pool. `protected` contains
/// half-open byte ranges which may be inside otherwise-usable memory but must
/// never enter either allocator, such as the loaded kernel image. Returns the
/// byte-range excludes that the buddy must skip when it donates the same
/// regions.
///
/// Algorithm (per region, processed in order):
///   1. Skip head bytes until 1 GiB-aligned. While we still want
///      1 GiB pages and the region has ≥ 1 GiB remaining, skip any
///      candidate intersecting `protected`, otherwise claim it and advance.
///   2. Then, while we still want 2 MiB pages and the region has
///      ≥ 2 MiB remaining (with 2 MiB-aligned cursor), apply the same
///      protected-range check, claim a 2 MiB chunk, and advance.
///   3. The leading misalignment + trailing remainder stay with
///      the region; the buddy will pick those up.
///
/// Each successful claim adds a `(start_byte, end_byte)` exclude
/// so init_from_map's donate path skips that range.
///
/// Idempotency: this is a one-shot boot call. Calling twice
/// would push duplicate phys addresses into the pool and is a
/// caller bug.
///
/// # Safety
///
/// Every unprotected byte in `usable` must be real, kernel-reachable RAM which
/// is not owned by firmware, the loaded kernel, boot metadata, or another
/// allocator. The caller must include every live subrange in `protected` and
/// call this exactly once before the buddy allocator accepts the same regions.
pub unsafe fn reserve_from_regions(
    usable: &[UsableRegion],
    protected: &[(u64, u64)],
    want_2m: usize,
    want_1g: usize,
) -> Vec<(u64, u64)> {
    let mut excludes: Vec<(u64, u64)> = Vec::new();
    let mut claims: Vec<(u64, HugeSize, usize)> = Vec::new();
    claims.reserve_exact(want_2m.saturating_add(want_1g));
    let mut left_2m = want_2m;
    let mut left_1g = want_1g;

    for r in usable {
        let region_start = r.start.raw();
        let Some(region_end) = region_start.checked_add(r.len) else {
            continue;
        };
        // Keep the same low-memory reservation policy as the buddy. Without
        // this, a bootloader map which calls 0..1 MiB usable could let the
        // huge pool capture the BIOS data area or SMP trampoline.
        let mut cursor = region_start.max(frame::LOW_RESERVED_BYTES);

        // Phase 1: claim 1 GiB chunks while available + wanted.
        while left_1g > 0 {
            let Some(aligned) = next_unprotected(cursor, region_end, HUGEPAGE_1G_BYTES, protected)
            else {
                break;
            };
            let chunk_end = aligned + HUGEPAGE_1G_BYTES;
            // SAFETY: `aligned` lies within a caller-supplied usable region.
            let node = unsafe { frame::narf_phys_node(aligned) }.min(MAX_NUMA_NODES - 1);
            claims.push((aligned, HugeSize::G1, node));
            excludes.push((aligned, chunk_end));
            cursor = chunk_end;
            left_1g -= 1;
        }

        // Phase 2: claim 2 MiB chunks while available + wanted.
        while left_2m > 0 {
            let Some(aligned) = next_unprotected(cursor, region_end, HUGEPAGE_2M_BYTES, protected)
            else {
                break;
            };
            let chunk_end = aligned + HUGEPAGE_2M_BYTES;
            // SAFETY: `aligned` lies within a caller-supplied usable region.
            let node = unsafe { frame::narf_phys_node(aligned) }.min(MAX_NUMA_NODES - 1);
            claims.push((aligned, HugeSize::M2, node));
            excludes.push((aligned, chunk_end));
            cursor = chunk_end;
            left_2m -= 1;
        }

        if left_2m == 0 && left_1g == 0 {
            break;
        }
    }

    let mut added_2m = [0usize; MAX_NUMA_NODES];
    let mut added_1g = [0usize; MAX_NUMA_NODES];
    for &(_, size, node) in &claims {
        match size {
            HugeSize::M2 => added_2m[node] += 1,
            HugeSize::G1 => added_1g[node] += 1,
        }
    }

    let mut pool = POOL.lock();
    for node in 0..MAX_NUMA_NODES {
        let target_2m = pool.reserved_2m_by_node[node].saturating_add(added_2m[node]);
        let target_1g = pool.reserved_1g_by_node[node].saturating_add(added_1g[node]);
        let len_2m = pool.free_2m[node].len();
        let len_1g = pool.free_1g[node].len();
        pool.free_2m[node].reserve_exact(target_2m.saturating_sub(len_2m));
        pool.free_1g[node].reserve_exact(target_1g.saturating_sub(len_1g));
        pool.reserved_2m_by_node[node] = target_2m;
        pool.reserved_1g_by_node[node] = target_1g;
    }
    for (phys, size, node) in claims {
        pool.free_mut(size, node).push(phys);
        match size {
            HugeSize::M2 => pool.reserved_2m += 1,
            HugeSize::G1 => pool.reserved_1g += 1,
        }
    }
    excludes
}

/// Find the first naturally aligned `size` chunk at or after `cursor` which
/// fits below `region_end` and does not intersect a protected range.
fn next_unprotected(
    mut cursor: u64,
    region_end: u64,
    size: u64,
    protected: &[(u64, u64)],
) -> Option<u64> {
    debug_assert!(size.is_power_of_two());
    loop {
        let aligned = cursor.checked_add(size - 1)? & !(size - 1);
        let chunk_end = aligned.checked_add(size)?;
        if chunk_end > region_end {
            return None;
        }
        let overlap_end = protected
            .iter()
            .filter(|&&(lo, hi)| lo < chunk_end && aligned < hi)
            .map(|&(_, hi)| hi)
            .max();
        match overlap_end {
            Some(end) if end > cursor => cursor = end,
            Some(_) => cursor = chunk_end,
            None => return Some(aligned),
        }
    }
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
    let plan = plan_policy(policy, local)?;
    let mut pool = POOL.lock();
    let (frame, node) = alloc_from_pool(&mut pool, size, &plan)?;
    drop(pool);
    account_policy_allocation(&plan, node, frame.size_bytes() >> 12);
    Ok(frame)
}

/// Allocate a complete hugepage vector under precomputed NUMA policies.
///
/// The operation takes the pool lock once and is all-or-nothing: exhaustion
/// returns every frame popped by this call before exposing an error. Callers
/// can therefore build a multi-leaf mapping without lock/unlock and policy
/// ordering work once per leaf or a partial-allocation cleanup path.
pub fn alloc_hugepages_with(
    size: HugeSize,
    policies: &[Mempolicy],
    local: usize,
) -> Result<Vec<HugeFrame>, HugeAllocError> {
    let mut plans = Vec::with_capacity(policies.len());
    for &policy in policies {
        plans.push(plan_policy(policy, local)?);
    }
    let mut frames: Vec<HugeFrame> = Vec::with_capacity(plans.len());

    let mut pool = POOL.lock();
    for plan in &mut plans {
        let Some((frame, node)) = alloc_from_pool(&mut pool, size, plan).ok() else {
            // Each pop created at least one free slot in its original node
            // stack, so rollback cannot grow a vector under the pool lock.
            for (frame, completed) in frames.drain(..).zip(plans.iter()) {
                pool.free_mut(size, completed.selected_node)
                    .push(frame.phys);
            }
            return Err(HugeAllocError::Empty);
        };
        plan.selected_node = node;
        frames.push(frame);
    }
    drop(pool);

    let pages = match size {
        HugeSize::M2 => HUGEPAGE_2M_BYTES >> 12,
        HugeSize::G1 => HUGEPAGE_1G_BYTES >> 12,
    };
    for plan in &plans {
        account_policy_allocation(plan, plan.selected_node, pages);
    }
    Ok(frames)
}

struct HugePolicyPlan {
    order: [usize; MAX_NUMA_NODES],
    count: usize,
    preferred: usize,
    interleave: bool,
    selected_node: usize,
}

fn plan_policy(policy: Mempolicy, local: usize) -> Result<HugePolicyPlan, HugeAllocError> {
    let all_nodes = (1u64 << MAX_NUMA_NODES) - 1;
    let allowed = policy.allowed & all_nodes;
    if allowed == 0 {
        return Err(HugeAllocError::Empty);
    }
    let requested = policy.nodemask & allowed;
    let anchor = if policy.home_node == u32::MAX {
        local.min(MAX_NUMA_NODES - 1)
    } else {
        policy.home_node as usize
    };
    let preferred = match policy.mode {
        MPOL_BIND | MPOL_PREFERRED if requested != 0 => requested.trailing_zeros() as usize,
        MPOL_PREFERRED_MANY if requested != 0 => anchor,
        MPOL_INTERLEAVE if requested != 0 => {
            crate::mempolicy::next_interleave_node(requested, policy.interleave_index)
        }
        MPOL_WEIGHTED_INTERLEAVE if requested != 0 => {
            crate::mempolicy::next_weighted_interleave_node(requested, policy.interleave_index)
        }
        _ => anchor,
    };
    let candidates = if policy.mode == MPOL_BIND
        || (matches!(policy.mode, MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE) && requested != 0)
    {
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
    order[..count].sort_unstable_by_key(|&node| {
        let preference_class =
            u8::from(policy.mode == MPOL_PREFERRED_MANY && (requested >> node) & 1 == 0);
        (
            preference_class,
            frame::node_distance(preferred, node),
            node,
        )
    });
    if let Some(pos) = order[..count].iter().position(|&node| node == preferred) {
        order[..count].swap(0, pos);
    }
    Ok(HugePolicyPlan {
        order,
        count,
        preferred,
        interleave: matches!(policy.mode, MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE),
        selected_node: MAX_NUMA_NODES,
    })
}

fn alloc_from_pool(
    pool: &mut HugePool,
    size: HugeSize,
    plan: &HugePolicyPlan,
) -> Result<(HugeFrame, usize), HugeAllocError> {
    for &node in &plan.order[..plan.count] {
        if let Some(phys) = pool.free_mut(size, node).pop() {
            return Ok((HugeFrame { phys, size }, node));
        }
    }
    Err(HugeAllocError::Empty)
}

fn account_policy_allocation(plan: &HugePolicyPlan, node: usize, pages: u64) {
    frame::account_numa_allocation(plan.preferred, node, pages);
    if plan.interleave && node == plan.preferred {
        frame::account_interleave_hit(node, pages);
    }
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
    let phys = pool
        .free_mut(size, node)
        .pop()
        .ok_or(HugeAllocError::Empty)?;
    Ok(HugeFrame { phys, size })
}

/// Return a hugepage to the pool. Caller asserts the frame came
/// from a prior `alloc_hugepage_*` of the matching size.
pub fn free_hugepage(frame: HugeFrame) {
    // Drop a shared reference rather than the frame itself. The guard is
    // released before POOL is taken so the two locks are never held together
    // — every other path takes POOL alone, so there is one order, not two.
    {
        let mut refs = EXTRA_REFS.lock();
        if let Some(remaining) = refs.get_mut(&frame.phys) {
            *remaining -= 1;
            if *remaining == 0 {
                refs.remove(&frame.phys);
            }
            return;
        }
    }
    let node = frame.node().min(MAX_NUMA_NODES - 1);
    let mut pool = POOL.lock();
    pool.free_mut(frame.size, node).push(frame.phys);
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
        free_2m: pool.free_2m.iter().map(Vec::len).sum(),
        free_1g: pool.free_1g.iter().map(Vec::len).sum(),
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
        free_2m: pool.free_2m[node].len(),
        free_1g: pool.free_1g[node].len(),
    }
}
