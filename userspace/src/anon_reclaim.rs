//! Anonymous-memory swap reclaim policy — the userspace half of
//! [`narf_memory::reclaim::AnonReclaimer`].
//!
//! `memory` owns the swap machinery (per-address-space page-out via
//! [`AddressSpace::swap_out_reclaim_plan`](narf_memory::address_space::AddressSpace::swap_out_reclaim_plan),
//! the cold-range planner, the watermarks) but cannot enumerate resident user
//! tasks without a dependency cycle. This module supplies a policy that scans
//! resident address spaces for cold private-anonymous ranges and swaps them out
//! toward a page target, and installs it with [`install`]. An out-of-tree crate
//! could register a different policy the same way.

use narf_memory::reclaim::AnonReclaimer;

/// The default NARF anon-reclaim policy: walk resident user address spaces,
/// swap out their coldest private-anonymous ranges until the target is met.
struct TaskAnonReclaimer;

static TASK_ANON_RECLAIMER: TaskAnonReclaimer = TaskAnonReclaimer;

#[cfg(target_arch = "x86_64")]
impl AnonReclaimer for TaskAnonReclaimer {
    fn reclaim_anon(&self, target_pages: usize) -> usize {
        use narf_memory::reclaim::plan_reclaim_ranges;
        use narf_scheduler::TaskId;

        let mut freed = 0usize;
        for (tid, pid) in crate::task::snapshot_identities() {
            if freed >= target_pages {
                break;
            }
            // Never swap init (pid 1) or kernel identities (pid 0).
            if pid <= 1 {
                continue;
            }
            // Only user processes have an address space; a kernel task or an
            // already-reaped zombie resolves to None and is skipped.
            let Some(aspace) = narf_scheduler::address_space_of(TaskId(tid)) else {
                continue;
            };
            let remaining = target_pages - freed;
            // Collect this space's cold private-anon runs (bounded to what we
            // still need), plan a bounded batch, and execute it. Holding the
            // `Arc` pins the address space so its `Drop` teardown cannot free
            // the same frames concurrently, and the executor validates every
            // range's root against this space.
            let mut candidates = alloc::vec::Vec::new();
            aspace.collect_anon_reclaim_candidates(&mut candidates, remaining);
            if candidates.is_empty() {
                continue;
            }
            let plan = plan_reclaim_ranges(&candidates, remaining, remaining);
            if plan.ranges.is_empty() {
                continue;
            }
            // SAFETY: `aspace` is a live identity-reachable root pinned by the
            // `Arc`; the swap executor's per-page transition table keeps each
            // selected page owned by this space for the transaction even under
            // a concurrent fault on a sibling thread.
            let report = unsafe { aspace.swap_out_reclaim_plan(&plan) };
            freed = freed.saturating_add(report.swapped_pages);
        }
        freed
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl AnonReclaimer for TaskAnonReclaimer {
    fn reclaim_anon(&self, _target_pages: usize) -> usize {
        // Swap is x86_64-only today; nothing to reclaim elsewhere.
        0
    }
}

/// Install the default anon-reclaim policy into the memory crate. Call once at
/// boot, before kswapd runs.
pub fn install() {
    narf_memory::reclaim::register_anon_reclaimer(&TASK_ANON_RECLAIMER);
}
