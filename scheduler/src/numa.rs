//! Per-task NUMA-node constraints.
//!
//! The scheduler owns task identity, so it also owns the small policy seam
//! used by cgroup-v2 `cpuset.mems`. The filesystem controller publishes an
//! effective node mask here; the userspace page-fault bridge reads it when
//! resolving `set_mempolicy` / `mbind`.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// No cgroup constraint: all node bits accepted by the memory layer.
pub const ALL_NUMA_NODES: u64 = u64::MAX;

const NEW_MEMS_SHARD: IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> = IrqSafeSpinLock::new(None);
static TASK_MEMS_ALLOWED: [IrqSafeSpinLock<Option<BTreeMap<u64, u64>>>;
    narf_lib::percpu::MAX_CPUS] = [NEW_MEMS_SHARD; narf_lib::percpu::MAX_CPUS];
/// Monotonic fast-path gate. A false value proves no restrictive task mask has
/// ever been published, so the default lookup cannot find anything but
/// [`ALL_NUMA_NODES`] and need not disable IRQs or enter a shard.
static TASK_MEMS_RESTRICTION_POSSIBLE: AtomicBool = AtomicBool::new(false);

#[inline]
fn shard(task: u64) -> usize {
    task as usize % narf_lib::percpu::MAX_CPUS
}

/// Set the hard NUMA-node mask for `task`.
///
/// An empty mask means unconstrained/inherit and is normalized to all nodes.
pub fn set_task_mems_allowed(task: u64, mask: u64) {
    let allowed = if mask == 0 { ALL_NUMA_NODES } else { mask };
    if allowed != ALL_NUMA_NODES {
        // Publish possibility before the table mutation. A racing reader may
        // conservatively take the lock before insertion completes, but can
        // never skip a completed restrictive publication.
        TASK_MEMS_RESTRICTION_POSSIBLE.store(true, Ordering::Release);
    }
    TASK_MEMS_ALLOWED[shard(task)]
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task, allowed);
}

/// Return the hard NUMA-node mask for `task`.
pub fn task_mems_allowed(task: u64) -> u64 {
    if !TASK_MEMS_RESTRICTION_POSSIBLE.load(Ordering::Acquire) {
        return ALL_NUMA_NODES;
    }
    TASK_MEMS_ALLOWED[shard(task)]
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(ALL_NUMA_NODES)
}

/// Remove a task's stored NUMA constraint at detach/exit.
pub fn clear_task_mems_allowed(task: u64) {
    if let Some(m) = TASK_MEMS_ALLOWED[shard(task)].lock().as_mut() {
        m.remove(&task);
    }
}
