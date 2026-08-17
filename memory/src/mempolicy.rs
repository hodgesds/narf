//! NUMA memory-policy steering for the frame allocator.
//!
//! Linux's `set_mempolicy(2)` / `mbind(2)` choose which NUMA node a
//! fresh page is allocated from. NARF resolves that policy here and
//! feeds a target node into the per-node buddy allocator
//! (`frame::alloc_frame_on`), so the policy is actually *enforced*,
//! not merely round-tripped.
//!
//! ## Model
//! The policy in force for a fault is a small value (mode + nodemask +
//! hard allowed-node mask)
//! published to a **per-CPU active slot** by the page-fault path right
//! before it demand-allocates. The allocator then resolves:
//!
//! - `MPOL_DEFAULT` / `MPOL_LOCAL` → the faulting CPU's local node
//!   (then nearest-by-distance fallback, the allocator's default).
//! - `MPOL_PREFERRED` → the first node in the nodemask (or local when
//!   the mask is empty), with nearest-by-distance fallback.
//! - `MPOL_PREFERRED_MANY` → the nearest node in the nodemask relative
//!   to the policy home node (or faulting CPU), then allowed fallbacks.
//! - `MPOL_BIND` → restrict strictly to the nodemask, nearest-first;
//!   only nodes in the mask are tried.
//! - `MPOL_INTERLEAVE` → round-robin across the nodemask, advancing a
//!   per-CPU counter each allocation.
//!
//! The active slot is **per-CPU** rather than per-task so the memory
//! crate stays decoupled from the task/scheduler crates: the fault
//! path (which knows the current task's policy) installs it, the
//! allocator consumes it, and it is cleared after the fault. A task
//! that never sets a policy leaves the slot at `MPOL_DEFAULT`, which
//! reproduces today's local-first behavior exactly.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::frame::{self, AllocContext, FrameAllocError, PhysFrame, MAX_NUMA_NODES};

// Every allocation in this module backs a userspace page — mempolicy is a
// userspace NUMA policy applied on the demand-fault / mlock path — so all of
// them honour the `min` watermark reserve (`AllocContext::User`). Routing
// through these thin wrappers keeps that guarantee in one place instead of
// tagging each of the many per-node attempts below.
#[inline]
fn u_alloc_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    frame::alloc_frame_on_ctx(node, AllocContext::User)
}
#[inline]
fn u_alloc_strict(node: usize, preferred: usize) -> Result<PhysFrame, FrameAllocError> {
    frame::alloc_frame_on_strict_for_ctx(node, preferred, AllocContext::User)
}
#[inline]
fn u_alloc_anywhere() -> Result<PhysFrame, FrameAllocError> {
    frame::alloc_frame_anywhere_ctx(AllocContext::User)
}

/// Linux `MPOL_*` mode values (the low bits of the mode word).
pub const MPOL_DEFAULT: u32 = 0;
pub const MPOL_PREFERRED: u32 = 1;
pub const MPOL_BIND: u32 = 2;
pub const MPOL_INTERLEAVE: u32 = 3;
pub const MPOL_LOCAL: u32 = 4;
pub const MPOL_PREFERRED_MANY: u32 = 5;
pub const MPOL_WEIGHTED_INTERLEAVE: u32 = 6;

/// Max CPUs whose active policy we track. A CPU index at or above this
/// falls back to slot 0 (correctness-preserving).
const MAX_TRACKED_CPUS: usize = 256;

/// Per-CPU active policy: packed `(mode << 32) | nodemask_low`.
/// `u64::MAX` sentinel = "no policy installed" (treat as DEFAULT).
static ACTIVE: [AtomicU64; MAX_TRACKED_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; MAX_TRACKED_CPUS];

/// Per-CPU hard node constraint, normally supplied by `cpuset.mems`.
static ACTIVE_ALLOWED: [AtomicU64; MAX_TRACKED_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; MAX_TRACKED_CPUS];

/// Per-CPU BIND home node (`u32::MAX` means no override).
static ACTIVE_HOME: [AtomicU32; MAX_TRACKED_CPUS] =
    [const { AtomicU32::new(u32::MAX) }; MAX_TRACKED_CPUS];

/// Linux-compatible global weighted-interleave ratios. A weight is never
/// zero; the sysfs ABI accepts the inclusive range 1..=255.
static INTERLEAVE_WEIGHTS: [AtomicU8; MAX_NUMA_NODES] =
    [const { AtomicU8::new(1) }; MAX_NUMA_NODES];

/// HMAT-derived node bandwidth values used by automatic weighting.
static INTERLEAVE_BANDWIDTH: [AtomicU64; MAX_NUMA_NODES] =
    [const { AtomicU64::new(0) }; MAX_NUMA_NODES];

/// Linux defaults weighted interleave to automatic mode.
static INTERLEAVE_AUTO: AtomicBool = AtomicBool::new(true);

static INTERLEAVE_CONFIG_LOCK: narf_lib::sync::IrqSafeSpinLock<()> =
    narf_lib::sync::IrqSafeSpinLock::new(());

/// Task-owned interleave sequence position published for the active fault.
static ACTIVE_INTERLEAVE_INDEX: [AtomicU64; MAX_TRACKED_CPUS] =
    [const { AtomicU64::new(0) }; MAX_TRACKED_CPUS];

#[inline]
fn cpu_slot() -> usize {
    let c = narf_lib::percpu::current_cpu();
    if c < MAX_TRACKED_CPUS {
        c
    } else {
        0
    }
}

/// A resolved NUMA policy: the low bits of `set_mempolicy`'s mode and
/// the first 64-bit word of the nodemask.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mempolicy {
    pub mode: u32,
    pub nodemask: u64,
    /// Hard allocation boundary (for example `cpuset.mems.effective`).
    pub allowed: u64,
    /// Distance anchor for MPOL_BIND (`u32::MAX` = lowest masked node).
    pub home_node: u32,
    /// Task-owned sequence position for ordinary and weighted interleave.
    pub interleave_index: u64,
}

impl Mempolicy {
    pub const DEFAULT: Self = Self {
        mode: MPOL_DEFAULT,
        nodemask: 0,
        allowed: u64::MAX,
        home_node: u32::MAX,
        interleave_index: 0,
    };

    fn pack(self) -> u64 {
        ((self.mode as u64) << 32) | (self.nodemask & 0xFFFF_FFFF)
    }

    fn unpack(v: u64) -> Self {
        if v == u64::MAX {
            return Self::DEFAULT;
        }
        Self {
            mode: (v >> 32) as u32,
            nodemask: v & 0xFFFF_FFFF,
            allowed: u64::MAX,
            home_node: u32::MAX,
            interleave_index: 0,
        }
    }
}

/// Publish `policy` as the active mempolicy for the current CPU.
pub fn set_active(policy: Mempolicy) {
    let slot = cpu_slot();
    ACTIVE_ALLOWED[slot].store(policy.allowed, Ordering::Release);
    ACTIVE_HOME[slot].store(policy.home_node, Ordering::Release);
    ACTIVE_INTERLEAVE_INDEX[slot].store(policy.interleave_index, Ordering::Release);
    ACTIVE[slot].store(policy.pack(), Ordering::Release);
}

/// Reset the current CPU's active policy to `MPOL_DEFAULT`.
pub fn clear_active() {
    let slot = cpu_slot();
    ACTIVE[slot].store(u64::MAX, Ordering::Release);
    ACTIVE_ALLOWED[slot].store(u64::MAX, Ordering::Release);
    ACTIVE_HOME[slot].store(u32::MAX, Ordering::Release);
    ACTIVE_INTERLEAVE_INDEX[slot].store(0, Ordering::Release);
}

/// The current CPU's active policy (DEFAULT when none installed).
pub fn active() -> Mempolicy {
    let slot = cpu_slot();
    let mut policy = Mempolicy::unpack(ACTIVE[slot].load(Ordering::Acquire));
    policy.allowed = ACTIVE_ALLOWED[slot].load(Ordering::Acquire);
    policy.home_node = ACTIVE_HOME[slot].load(Ordering::Acquire);
    policy.interleave_index = ACTIVE_INTERLEAVE_INDEX[slot].load(Ordering::Acquire);
    policy
}

/// Lowest set node index in `mask`, or `None` for an empty mask.
fn first_node(mask: u64) -> Option<usize> {
    if mask == 0 {
        None
    } else {
        Some(mask.trailing_zeros() as usize)
    }
}

/// Resolve an ordinary interleave sequence position.
fn interleave_pick(mask: u64, index: u64) -> usize {
    if mask == 0 {
        return 0;
    }
    let popcount = mask.count_ones();
    let idx = index % popcount as u64;
    let mut seen = 0u32;
    for bit in 0..MAX_NUMA_NODES as u32 {
        if (mask >> bit) & 1 != 0 {
            if seen as u64 == idx {
                return bit as usize;
            }
            seen += 1;
        }
    }
    0
}

pub(crate) fn next_interleave_node(mask: u64, index: u64) -> usize {
    interleave_pick(mask, index)
}

/// Return the configured global weighted-interleave weight for `node`.
pub fn interleave_weight(node: usize) -> Option<u8> {
    INTERLEAVE_WEIGHTS
        .get(node)
        .map(|weight| weight.load(Ordering::Acquire))
}

/// Set one node's global weighted-interleave weight.
pub fn set_interleave_weight(node: usize, weight: u8) -> Result<(), ()> {
    if weight == 0 {
        return Err(());
    }
    let Some(slot) = INTERLEAVE_WEIGHTS.get(node) else {
        return Err(());
    };
    let _guard = INTERLEAVE_CONFIG_LOCK.lock();
    slot.store(weight, Ordering::Release);
    INTERLEAVE_AUTO.store(false, Ordering::Release);
    Ok(())
}

/// Whether HMAT-derived automatic weighting is enabled.
pub fn interleave_auto() -> bool {
    INTERLEAVE_AUTO.load(Ordering::Acquire)
}

/// Publish a node's real HMAT bandwidth coordinate. Zero means unknown.
pub fn set_interleave_bandwidth(node: usize, bandwidth: u64) -> Result<(), ()> {
    let Some(slot) = INTERLEAVE_BANDWIDTH.get(node) else {
        return Err(());
    };
    let _guard = INTERLEAVE_CONFIG_LOCK.lock();
    slot.store(bandwidth, Ordering::Release);
    if interleave_auto() {
        recompute_auto_weights()?;
    }
    Ok(())
}

/// Enable or disable HMAT-derived weights. Enabling fails when no node has
/// a usable bandwidth coordinate; disabling preserves the current weights.
pub fn set_interleave_auto(enabled: bool) -> Result<(), ()> {
    let _guard = INTERLEAVE_CONFIG_LOCK.lock();
    if enabled {
        recompute_auto_weights()?;
    }
    INTERLEAVE_AUTO.store(enabled, Ordering::Release);
    Ok(())
}

fn recompute_auto_weights() -> Result<(), ()> {
    const WEIGHTINESS: u64 = 32;
    let mut bandwidth = [0u64; MAX_NUMA_NODES];
    let mut sum = 0u64;
    for (node, value) in INTERLEAVE_BANDWIDTH.iter().enumerate() {
        bandwidth[node] = value.load(Ordering::Acquire);
        sum = sum.saturating_add(bandwidth[node]);
    }
    if sum == 0 {
        return Err(());
    }

    let mut weights = [1u8; MAX_NUMA_NODES];
    let mut gcd = 0u8;
    for node in 0..MAX_NUMA_NODES {
        if bandwidth[node] == 0 {
            continue;
        }
        let scaled = WEIGHTINESS.saturating_mul(bandwidth[node]);
        let weight = scaled.checked_div(sum).unwrap_or(0).clamp(1, 255) as u8;
        weights[node] = weight;
        gcd = if gcd == 0 {
            weight
        } else {
            gcd_u8(gcd, weight)
        };
    }
    if gcd > 1 {
        for node in 0..MAX_NUMA_NODES {
            if bandwidth[node] != 0 {
                weights[node] /= gcd;
            }
        }
    }
    for (slot, weight) in INTERLEAVE_WEIGHTS.iter().zip(weights) {
        slot.store(weight, Ordering::Release);
    }
    Ok(())
}

fn gcd_u8(mut a: u8, mut b: u8) -> u8 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn weighted_interleave_pick(mask: u64, index: u64) -> usize {
    let mut total = 0u32;
    for (node, weight) in INTERLEAVE_WEIGHTS.iter().enumerate() {
        if (mask >> node) & 1 != 0 {
            total += weight.load(Ordering::Acquire) as u32;
        }
    }
    if total == 0 {
        return 0;
    }
    let mut target = (index % total as u64) as u32;
    for (node, weight) in INTERLEAVE_WEIGHTS.iter().enumerate() {
        if (mask >> node) & 1 == 0 {
            continue;
        }
        let weight = weight.load(Ordering::Acquire) as u32;
        if target < weight {
            return node;
        }
        target -= weight;
    }
    mask.trailing_zeros() as usize
}

pub(crate) fn next_weighted_interleave_node(mask: u64, index: u64) -> usize {
    weighted_interleave_pick(mask, index)
}

/// Resolve a task-owned interleave sequence position without mutation.
pub fn interleave_node_at(mask: u64, weighted: bool, index: u64) -> usize {
    if mask == 0 {
        return 0;
    }
    if !weighted {
        let idx = index % mask.count_ones() as u64;
        let mut seen = 0u32;
        for node in 0..MAX_NUMA_NODES {
            if (mask >> node) & 1 != 0 {
                if seen as u64 == idx {
                    return node;
                }
                seen += 1;
            }
        }
        return mask.trailing_zeros() as usize;
    }
    let total: u32 = INTERLEAVE_WEIGHTS
        .iter()
        .enumerate()
        .filter(|(node, _)| (mask >> node) & 1 != 0)
        .map(|(_, weight)| weight.load(Ordering::Acquire) as u32)
        .sum();
    let mut target = (index % total as u64) as u32;
    for (node, weight) in INTERLEAVE_WEIGHTS.iter().enumerate() {
        if (mask >> node) & 1 == 0 {
            continue;
        }
        let weight = weight.load(Ordering::Acquire) as u32;
        if target < weight {
            return node;
        }
        target -= weight;
    }
    mask.trailing_zeros() as usize
}

/// Allocate one frame honoring `policy`, with `local` as the faulting
/// CPU's node (used by DEFAULT/LOCAL/PREFERRED-empty).
///
/// `policy.allowed` is always a hard boundary. MPOL_BIND further narrows
/// it to the policy nodemask; the other modes choose their preferred order
/// within the allowed set.
pub fn alloc_frame_with(policy: Mempolicy, local: usize) -> Result<PhysFrame, FrameAllocError> {
    let unconstrained = policy.allowed == u64::MAX;
    let all_nodes = if MAX_NUMA_NODES == 64 {
        u64::MAX
    } else {
        (1u64 << MAX_NUMA_NODES) - 1
    };
    let allowed = policy.allowed & all_nodes;
    if allowed == 0 {
        return Err(FrameAllocError::Exhausted);
    }
    match policy.mode {
        MPOL_BIND => alloc_bind(policy.nodemask & allowed, policy.home_node),
        MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE => {
            let mask = if policy.nodemask == 0 {
                allowed
            } else {
                policy.nodemask & allowed
            };
            let node = if policy.mode == MPOL_WEIGHTED_INTERLEAVE {
                weighted_interleave_pick(mask, policy.interleave_index)
            } else {
                interleave_pick(mask, policy.interleave_index)
            };
            let result = if unconstrained {
                u_alloc_on(node)
            } else {
                alloc_preferred_within(node, mask)
            };
            if let Ok(allocated) = result {
                // SAFETY: the topology hook is provided by the kernel and
                // allocation returned a valid physical frame.
                if unsafe { frame::narf_phys_node(allocated.start_address().raw()) } == node {
                    frame::account_interleave_hit(node, 1);
                }
            }
            result
        }
        MPOL_PREFERRED => {
            let preferred = policy.nodemask & allowed;
            let node = first_node(preferred).unwrap_or(local);
            if unconstrained {
                u_alloc_on(node)
            } else {
                alloc_preferred_within(node, allowed)
            }
        }
        MPOL_PREFERRED_MANY => {
            let preferred = policy.nodemask & allowed;
            let anchor = if policy.home_node == u32::MAX {
                local
            } else {
                policy.home_node as usize
            };
            alloc_preferred_many(preferred, allowed, anchor)
        }
        // DEFAULT and LOCAL mean local-first, but never outside cpuset.mems.
        _ if unconstrained => u_alloc_on(local),
        _ => alloc_preferred_within(local, allowed),
    }
}

fn alloc_preferred_many(
    preferred: u64,
    allowed: u64,
    anchor: usize,
) -> Result<PhysFrame, FrameAllocError> {
    let mut candidates = [0usize; MAX_NUMA_NODES];
    let mut count = 0usize;
    for node in 0..MAX_NUMA_NODES {
        if (preferred >> node) & 1 != 0 {
            candidates[count] = node;
            count += 1;
        }
    }
    candidates[..count].sort_unstable_by_key(|&node| (frame::node_distance(anchor, node), node));
    for &node in &candidates[..count] {
        if let Ok(frame) = u_alloc_strict(node, node) {
            return Ok(frame);
        }
    }
    for node in 0..MAX_NUMA_NODES {
        if (allowed >> node) & 1 != 0 && (preferred >> node) & 1 == 0 {
            if let Ok(frame) = u_alloc_strict(node, anchor) {
                return Ok(frame);
            }
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate on `preferred` when allowed, then try the remaining allowed
/// nodes. Every attempt is strict so a cgroup hard boundary cannot spill.
fn alloc_preferred_within(preferred: usize, allowed: u64) -> Result<PhysFrame, FrameAllocError> {
    if preferred < MAX_NUMA_NODES && (allowed >> preferred) & 1 != 0 {
        if let Ok(frame) = u_alloc_strict(preferred, preferred) {
            return Ok(frame);
        }
    }
    for node in 0..MAX_NUMA_NODES {
        if node != preferred && (allowed >> node) & 1 != 0 {
            if let Ok(frame) = u_alloc_strict(node, preferred) {
                return Ok(frame);
            }
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// MPOL_BIND: try only nodes set in `mask`, nearest-first by distance
/// from the lowest masked node. Never spills outside the mask.
fn alloc_bind(mask: u64, home_node: u32) -> Result<PhysFrame, FrameAllocError> {
    let Some(first) = first_node(mask) else {
        return u_alloc_anywhere();
    };
    let anchor = if home_node == u32::MAX {
        first
    } else {
        (home_node as usize).min(MAX_NUMA_NODES - 1)
    };
    let mut candidates = [0usize; MAX_NUMA_NODES];
    let mut count = 0usize;
    for node in 0..MAX_NUMA_NODES {
        if (mask >> node) & 1 != 0 {
            candidates[count] = node;
            count += 1;
        }
    }
    for i in 1..count {
        let mut j = i;
        while j > 0 {
            let a = candidates[j - 1];
            let b = candidates[j];
            let da = frame::node_distance(anchor, a);
            let db = frame::node_distance(anchor, b);
            if db < da || (db == da && b < a) {
                candidates.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }
    let preferred = candidates[0];
    for &node in &candidates[..count] {
        if let Ok(f) = u_alloc_strict(node, preferred) {
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate honoring the **current CPU's active policy**. This is the
/// entry point the demand-paging fault path uses.
pub fn alloc_frame_policied(local: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_with(active(), local)
}
