//! NUMA memory-policy steering for the frame allocator.
//!
//! Linux's `set_mempolicy(2)` / `mbind(2)` choose which NUMA node a
//! fresh page is allocated from. NARF resolves that policy here and
//! feeds a target node into the per-node buddy allocator
//! (`frame::alloc_frame_on`), so the policy is actually *enforced*,
//! not merely round-tripped.
//!
//! ## Model
//! The policy in force for a fault is a small value (mode + nodemask)
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
}

impl Mempolicy {
    pub const DEFAULT: Self = Self {
        mode: MPOL_DEFAULT,
        nodemask: 0,
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
        }
    }
}

/// Publish `policy` as the active mempolicy for the current CPU.
pub fn set_active(policy: Mempolicy) {
    ACTIVE[cpu_slot()].store(policy.pack(), Ordering::Release);
}

/// Reset the current CPU's active policy to `MPOL_DEFAULT`.
pub fn clear_active() {
    ACTIVE[cpu_slot()].store(u64::MAX, Ordering::Release);
}

/// The current CPU's active policy (DEFAULT when none installed).
pub fn active() -> Mempolicy {
    Mempolicy::unpack(ACTIVE[cpu_slot()].load(Ordering::Acquire))
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
/// MPOL_BIND is the only *restrictive* mode: it confines the
/// allocation to the nodemask and fails if every masked node is
/// exhausted. The other modes are *preferences* — they pick a starting
/// node and let the allocator's nearest-by-distance fallback spill
/// over, exactly like Linux.
pub fn alloc_frame_with(policy: Mempolicy, local: usize) -> Result<PhysFrame, FrameAllocError> {
    match policy.mode {
        MPOL_BIND => alloc_bind(policy.nodemask),
        MPOL_INTERLEAVE => {
            let node = interleave_pick(policy.nodemask);
            frame::alloc_frame_on(node)
        }
        MPOL_PREFERRED => {
            let node = first_node(policy.nodemask).unwrap_or(local);
            frame::alloc_frame_on(node)
        }
        // DEFAULT and LOCAL both mean "local node, then nearest".
        _ => frame::alloc_frame_on(local),
    }
}

/// MPOL_BIND: try only nodes set in `mask`, nearest-first by distance
/// from the lowest masked node. Never spills outside the mask.
fn alloc_bind(mask: u64) -> Result<PhysFrame, FrameAllocError> {
    let Some(anchor) = first_node(mask) else {
        return frame::alloc_frame_anywhere();
    };
    if (mask >> anchor) & 1 != 0 {
        if let Ok(f) = frame::alloc_frame_on_strict(anchor) {
            return Ok(f);
        }
    }
    for bit in 0..MAX_NUMA_NODES {
        if bit == anchor {
            continue;
        }
        if (mask >> bit) & 1 != 0 {
            if let Ok(f) = frame::alloc_frame_on_strict(bit) {
                return Ok(f);
            }
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate honoring the **current CPU's active policy**. This is the
/// entry point the demand-paging fault path uses.
pub fn alloc_frame_policied(local: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_with(active(), local)
}
