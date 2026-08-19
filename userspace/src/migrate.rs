//! Root → `AddressSpace` resolver — the task-layer half of
//! [`narf_memory::migrate::AddressSpaceResolver`].
//!
//! `memory` defines the migration seam but cannot enumerate address spaces. This
//! resolves a page-table root by scanning resident tasks for the one whose
//! address-space root matches, and installs it at boot. (A `root → AS` index is
//! a follow-up; a linear scan is fine for the low frequency of migration, and it
//! runs in kthread context so the `snapshot_identities` allocation is safe.)

use alloc::sync::Arc;

use narf_memory::address_space::AddressSpace;
use narf_memory::migrate::AddressSpaceResolver;
use narf_memory::PhysAddr;
use narf_scheduler::TaskId;

/// The default resolver: match a page-table root against every resident task's
/// address space.
struct TaskAddressSpaceResolver;

static TASK_ADDRESS_SPACE_RESOLVER: TaskAddressSpaceResolver = TaskAddressSpaceResolver;

impl AddressSpaceResolver for TaskAddressSpaceResolver {
    fn resolve(&self, root: PhysAddr) -> Option<Arc<AddressSpace>> {
        for (tid, pid) in crate::task::snapshot_identities() {
            // Kernel identities (pid 0) have no user address space.
            if pid == 0 {
                continue;
            }
            if let Some(aspace) = narf_scheduler::address_space_of(TaskId(tid)) {
                if aspace.root == root {
                    return Some(aspace);
                }
            }
        }
        None
    }
}

/// Install the default root→AddressSpace resolver into the memory crate. Call
/// once at boot, before migration runs.
pub fn install() {
    narf_memory::migrate::register_address_space_resolver(&TASK_ADDRESS_SPACE_RESOLVER);
}
