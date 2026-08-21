//! Per-task NUMA-node constraints.
//!
//! The scheduler owns task identity, so it also owns the small policy seam
//! used by cgroup-v2 `cpuset.mems`. The filesystem controller publishes an
//! effective node mask here; the userspace page-fault bridge reads it when
//! resolving `set_mempolicy` / `mbind`.

use alloc::collections::BTreeMap;

use narf_lib::sync::IrqSafeSpinLock;

/// No cgroup constraint: all node bits accepted by the memory layer.
pub const ALL_NUMA_NODES: u64 = u64::MAX;

const NEW_MEMS_SHARD: IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> = IrqSafeSpinLock::new(None);
static TASK_MEMS_ALLOWED: [IrqSafeSpinLock<Option<BTreeMap<u64, u64>>>;
    narf_lib::percpu::MAX_CPUS] = [NEW_MEMS_SHARD; narf_lib::percpu::MAX_CPUS];

#[inline]
fn shard(task: u64) -> usize {
    task as usize % narf_lib::percpu::MAX_CPUS
}

/// Set the hard NUMA-node mask for `task`.
///
/// An empty mask means unconstrained/inherit and is normalized to all nodes.
pub fn set_task_mems_allowed(task: u64, mask: u64) {
    let allowed = if mask == 0 { ALL_NUMA_NODES } else { mask };
    TASK_MEMS_ALLOWED[shard(task)]
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task, allowed);
}

/// Return the hard NUMA-node mask for `task`.
pub fn task_mems_allowed(task: u64) -> u64 {
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
