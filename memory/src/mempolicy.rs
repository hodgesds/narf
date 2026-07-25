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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::frame::{self, FrameAllocError, PhysFrame, MAX_NUMA_NODES};

/// Linux `MPOL_*` mode values (the low bits of the mode word).
pub const MPOL_DEFAULT: u32 = 0;
pub const MPOL_PREFERRED: u32 = 1;
pub const MPOL_BIND: u32 = 2;
pub const MPOL_INTERLEAVE: u32 = 3;
pub const MPOL_LOCAL: u32 = 4;

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

/// Per-CPU interleave rotor for `MPOL_INTERLEAVE`.
static INTERLEAVE_NEXT: [AtomicU32; MAX_TRACKED_CPUS] =
    [const { AtomicU32::new(0) }; MAX_TRACKED_CPUS];

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
}

impl Mempolicy {
    pub const DEFAULT: Self = Self {
        mode: MPOL_DEFAULT,
        nodemask: 0,
        allowed: u64::MAX,
        home_node: u32::MAX,
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
        }
    }
}

/// Publish `policy` as the active mempolicy for the current CPU.
pub fn set_active(policy: Mempolicy) {
    let slot = cpu_slot();
    ACTIVE_ALLOWED[slot].store(policy.allowed, Ordering::Release);
    ACTIVE_HOME[slot].store(policy.home_node, Ordering::Release);
    ACTIVE[slot].store(policy.pack(), Ordering::Release);
}

/// Reset the current CPU's active policy to `MPOL_DEFAULT`.
pub fn clear_active() {
    let slot = cpu_slot();
    ACTIVE[slot].store(u64::MAX, Ordering::Release);
    ACTIVE_ALLOWED[slot].store(u64::MAX, Ordering::Release);
    ACTIVE_HOME[slot].store(u32::MAX, Ordering::Release);
}

/// The current CPU's active policy (DEFAULT when none installed).
pub fn active() -> Mempolicy {
    let slot = cpu_slot();
    let mut policy = Mempolicy::unpack(ACTIVE[slot].load(Ordering::Acquire));
    policy.allowed = ACTIVE_ALLOWED[slot].load(Ordering::Acquire);
    policy.home_node = ACTIVE_HOME[slot].load(Ordering::Acquire);
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

/// Pick the next interleave target from `mask` for this CPU, advancing
/// the rotor. Falls back to node 0 for an empty mask.
fn interleave_pick(mask: u64) -> usize {
    if mask == 0 {
        return 0;
    }
    let popcount = mask.count_ones();
    let slot = cpu_slot();
    let idx = INTERLEAVE_NEXT[slot].fetch_add(1, Ordering::Relaxed) % popcount;
    let mut seen = 0u32;
    for bit in 0..MAX_NUMA_NODES as u32 {
        if (mask >> bit) & 1 != 0 {
            if seen == idx {
                return bit as usize;
            }
            seen += 1;
        }
    }
    0
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
        MPOL_INTERLEAVE => {
            let mask = if policy.nodemask == 0 {
                allowed
            } else {
                policy.nodemask & allowed
            };
            let node = interleave_pick(mask);
            let result = if unconstrained {
                frame::alloc_frame_on(node)
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
                frame::alloc_frame_on(node)
            } else {
                alloc_preferred_within(node, allowed)
            }
        }
        // DEFAULT and LOCAL mean local-first, but never outside cpuset.mems.
        _ if unconstrained => frame::alloc_frame_on(local),
        _ => alloc_preferred_within(local, allowed),
    }
}

/// Allocate on `preferred` when allowed, then try the remaining allowed
/// nodes. Every attempt is strict so a cgroup hard boundary cannot spill.
fn alloc_preferred_within(preferred: usize, allowed: u64) -> Result<PhysFrame, FrameAllocError> {
    if preferred < MAX_NUMA_NODES && (allowed >> preferred) & 1 != 0 {
        if let Ok(frame) = frame::alloc_frame_on_strict_for(preferred, preferred) {
            return Ok(frame);
        }
    }
    for node in 0..MAX_NUMA_NODES {
        if node != preferred && (allowed >> node) & 1 != 0 {
            if let Ok(frame) = frame::alloc_frame_on_strict_for(node, preferred) {
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
        return frame::alloc_frame_anywhere();
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
        if let Ok(f) = frame::alloc_frame_on_strict_for(node, preferred) {
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
