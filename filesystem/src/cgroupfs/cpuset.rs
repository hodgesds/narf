//! `cpuset` controller — pin a cgroup to a set of CPUs / memory nodes.
//!
//! Stores `cpuset.cpus` / `cpuset.mems` (requested) and computes
//! `cpuset.cpus.effective` / `cpuset.mems.effective` as
//! `parent.effective ∩ requested` (root effective = all online CPUs).
//! Applies the effective CPU set as task affinity to member tasks via
//! the `narf-scheduler` cgroup affinity hook.
//!
//! ## REAL vs best-effort
//!
//! - **`cpuset.cpus.effective`**: REAL — the effective mask is pushed
//!   to member tasks as `Affinity.allowed` via
//!   `narf_scheduler::cgroup_set_affinity`, and the executor honours
//!   `allowed` as a hard dispatch constraint (see
//!   `scheduler/src/cgroup.rs`).
//! - **Live re-propagation to descendant cgroups**: LIMITED. A
//!   `ControllerState` only sees its *parent* (handed in via
//!   `new_state` for inheritance); it has no back-reference to its
//!   children. So a write to a parent's `cpuset.cpus` recomputes and
//!   re-applies *this* level's effective set to *this* level's
//!   members, but does not walk down to recompute children that were
//!   created earlier. Children compute the correct intersection at
//!   *their* creation time (they downcast the parent at `new_state`);
//!   a later parent narrowing is not retro-pushed into existing
//!   children. Documented rather than worked around — the
//!   `Controller`/`ControllerState` trait surface (which this task may
//!   not modify) does not expose a child list.
//! - **`cpuset.mems` / `.effective`**: REAL — the effective mask is
//!   published as a hard per-task constraint through `narf-scheduler`.
//!   The fault-time mempolicy resolver intersects placement policy
//!   with this mask before asking the buddy allocator.
//! - Linux's legacy-v1 `cpuset.memory_migrate` is deliberately absent from
//!   this cgroup-v2 surface.
//!
//! Linux ref: `kernel/cgroup/cpuset.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"Cpuset".

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "cpuset.cpus",
    "cpuset.cpus.effective",
    "cpuset.mems",
    "cpuset.mems.effective",
    "cpuset.cpus.partition",
];

/// Width of the inline CPU mask. Matches `narf_scheduler::CpuSet`'s
/// 64-bit inline representation.
const MASK_BITS: u32 = 64;

/// Ensure the scheduler-side affinity hook is installed exactly once.
#[cfg(feature = "cgroup")]
fn ensure_hooks() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        narf_scheduler::install_cgroup_affinity_hook(narf_scheduler::apply_affinity);
    }
}

#[cfg(not(feature = "cgroup"))]
fn ensure_hooks() {}

/// Bitmask of all online CPUs (root cgroup's effective set).
#[cfg(feature = "cgroup")]
fn all_online_mask() -> u64 {
    mask_lo_bits(narf_scheduler::online_count())
}

#[cfg(not(feature = "cgroup"))]
fn all_online_mask() -> u64 {
    // Default to a single CPU when the scheduler seam is absent.
    1
}

/// Memory nodes backed by a populated allocator zone.
fn all_memory_mask() -> u64 {
    let mut mask = 0u64;
    for node in 0..narf_memory::FRAME_MAX_NUMA_NODES {
        if narf_memory::node_free(node) != 0 {
            mask |= 1u64 << node;
        }
    }
    if mask == 0 {
        1
    } else {
        mask
    }
}

/// Mask with the low `n` bits set, clamped to the inline width.
fn mask_lo_bits(n: u32) -> u64 {
    let n = n.min(MASK_BITS);
    if n == 0 {
        0
    } else if n == MASK_BITS {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

/// Parse Linux cpulist syntax ("0-3,5,7-9") into a bitmask. An empty
/// string parses to `0` (meaning "inherit parent" at the policy
/// layer). Out-of-range or malformed input is rejected with
/// `InvalidData`.
fn parse_cpulist(s: &str) -> Result<u64, FsError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let mut mask: u64 = 0;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(FsError::InvalidData);
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo.trim().parse().map_err(|_| FsError::InvalidData)?;
            let hi: u32 = hi.trim().parse().map_err(|_| FsError::InvalidData)?;
            if lo > hi || hi >= MASK_BITS {
                return Err(FsError::InvalidData);
            }
            for c in lo..=hi {
                mask |= 1u64 << c;
            }
        } else {
            let c: u32 = part.parse().map_err(|_| FsError::InvalidData)?;
            if c >= MASK_BITS {
                return Err(FsError::InvalidData);
            }
            mask |= 1u64 << c;
        }
    }
    Ok(mask)
}

/// Render a bitmask back to Linux cpulist syntax ("0-3,5"). Empty mask
/// renders to the empty string.
fn format_cpulist(mut mask: u64) -> String {
    let mut out = String::new();
    let mut bit: u32 = 0;
    let mut first = true;
    while mask != 0 {
        // Advance to the next set bit.
        let tz = mask.trailing_zeros();
        bit += tz;
        mask >>= tz;
        // Find the run length.
        let run = mask.trailing_ones();
        let lo = bit;
        let hi = bit + run - 1;
        if !first {
            out.push(',');
        }
        first = false;
        if lo == hi {
            out.push_str(&alloc::format!("{lo}"));
        } else {
            out.push_str(&alloc::format!("{lo}-{hi}"));
        }
        bit += run;
        mask >>= run;
    }
    out
}

#[derive(Debug)]
pub struct CpuSetController;

impl Controller for CpuSetController {
    fn name(&self) -> &'static str {
        "cpuset"
    }

    fn new_state(&self, parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        ensure_hooks();
        // Inheritance: the effective mask we may grant is bounded by
        // the parent's effective mask; the root's effective mask is
        // every online CPU.
        let parent_effective = parent
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<CpuSetState>())
            .map(|ps| *ps.effective_cpus.lock())
            .unwrap_or_else(all_online_mask);
        let parent_effective_mems = parent
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<CpuSetState>())
            .map(|ps| *ps.effective_mems.lock())
            .unwrap_or_else(all_memory_mask);
        Arc::new(CpuSetState {
            cpus: IrqSafeSpinLock::new(String::new()),
            mems: IrqSafeSpinLock::new(String::new()),
            partition: IrqSafeSpinLock::new(String::from("member")),
            // Requested mask 0 ("inherit") ⇒ effective == parent's.
            effective_cpus: IrqSafeSpinLock::new(parent_effective),
            effective_mems: IrqSafeSpinLock::new(parent_effective_mems),
            parent_effective_cpus: IrqSafeSpinLock::new(parent_effective),
            parent_effective_mems: IrqSafeSpinLock::new(parent_effective_mems),
            members: IrqSafeSpinLock::new(alloc::collections::BTreeSet::new()),
        })
    }
}

#[derive(Debug)]
pub struct CpuSetState {
    /// Requested cpu list, e.g. "0-3" (empty = inherit parent).
    cpus: IrqSafeSpinLock<String>,
    mems: IrqSafeSpinLock<String>,
    partition: IrqSafeSpinLock<String>,
    /// Effective cpu mask = `parent.effective ∩ requested` (or the
    /// parent's effective when the request is empty/"inherit").
    effective_cpus: IrqSafeSpinLock<u64>,
    /// Effective memory-node mask, enforced at page-fault allocation.
    effective_mems: IrqSafeSpinLock<u64>,
    /// Snapshot of the parent's effective cpu mask captured at
    /// `new_state`. Used to recompute our effective set on a local
    /// `cpuset.cpus` write without a parent back-reference.
    parent_effective_cpus: IrqSafeSpinLock<u64>,
    /// Snapshot of the parent's effective memory-node mask.
    parent_effective_mems: IrqSafeSpinLock<u64>,
    /// Pids attached at this cgroup level.
    members: IrqSafeSpinLock<alloc::collections::BTreeSet<u64>>,
}

impl CpuSetState {
    /// Recompute `effective_cpus` from the requested list and the
    /// captured parent effective mask, then re-apply to members.
    fn recompute_and_apply_cpus(&self) -> Result<(), FsError> {
        let requested = parse_cpulist(&self.cpus.lock())?;
        let parent = *self.parent_effective_cpus.lock();
        // Empty request ⇒ inherit the parent's effective set.
        let effective = if requested == 0 {
            parent
        } else {
            requested & parent
        };
        *self.effective_cpus.lock() = effective;
        let members: Vec<u64> = self.members.lock().iter().copied().collect();
        for pid in members {
            push_affinity(pid, effective);
        }
        Ok(())
    }

    fn recompute_and_apply_mems(&self, requested: u64) -> Result<(), FsError> {
        let parent = *self.parent_effective_mems.lock();
        let effective = if requested == 0 {
            parent
        } else {
            requested & parent
        };
        if effective == 0 {
            return Err(FsError::InvalidData);
        }
        *self.effective_mems.lock() = effective;
        let members: Vec<u64> = self.members.lock().iter().copied().collect();
        for pid in members {
            narf_scheduler::set_task_mems_allowed(pid, effective);
        }
        Ok(())
    }
}

#[cfg(feature = "cgroup")]
fn push_affinity(pid: u64, mask: u64) {
    let _ = narf_scheduler::cgroup_set_affinity(pid, mask);
}

#[cfg(not(feature = "cgroup"))]
fn push_affinity(_pid: u64, _mask: u64) {}

impl ControllerState for CpuSetState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        let line = |s: &str| {
            let mut o = String::from(s);
            o.push('\n');
            o
        };
        match file {
            "cpuset.cpus" => line(&self.cpus.lock()),
            "cpuset.cpus.effective" => line(&format_cpulist(*self.effective_cpus.lock())),
            "cpuset.mems" => line(&self.mems.lock()),
            "cpuset.mems.effective" => line(&format_cpulist(*self.effective_mems.lock())),
            "cpuset.cpus.partition" => line(&self.partition.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "cpuset.cpus" => {
                // Validate before storing so a malformed list leaves
                // state untouched.
                let _ = parse_cpulist(text)?;
                *self.cpus.lock() = String::from(text);
                self.recompute_and_apply_cpus()
            }
            "cpuset.mems" => {
                let m = parse_cpulist(text)?;
                self.recompute_and_apply_mems(m)?;
                *self.mems.lock() = String::from(text);
                Ok(())
            }
            "cpuset.cpus.partition" => {
                // v2 accepts "member" | "root" | "isolated". We store
                // the string verbatim; partition semantics (exclusive
                // CPU ownership) are not enforced on the cooperative
                // executor.
                if !matches!(text, "member" | "root" | "isolated") {
                    return Err(FsError::InvalidData);
                }
                *self.partition.lock() = String::from(text);
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "cpuset.cpus" | "cpuset.mems" | "cpuset.cpus.partition"
        )
    }

    fn on_attach(&self, pid: u64) {
        self.members.lock().insert(pid);
        // Apply this cgroup's current effective CPU set to the
        // joining task.
        let effective = *self.effective_cpus.lock();
        push_affinity(pid, effective);
        let effective_mems = *self.effective_mems.lock();
        narf_scheduler::set_task_mems_allowed(pid, effective_mems);
    }

    fn on_detach(&self, pid: u64) {
        self.members.lock().remove(&pid);
        narf_scheduler::clear_task_mems_allowed(pid);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn smoke_cpuset_mems_propagates_to_task() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    const TASK: u64 = 0x4350_5553_4554;
    let state = CpuSetController.new_state(None);
    if state.files().contains(&"cpuset.memory_migrate")
        || state.write("cpuset.memory_migrate", b"1").is_ok()
    {
        return TestResult::Fail("legacy cpuset.memory_migrate leaked into cgroup2");
    }
    if state.write("cpuset.mems", b"0").is_err() {
        return TestResult::Fail("cpuset.mems rejected online node 0");
    }
    state.on_attach(TASK);
    if narf_scheduler::task_mems_allowed(TASK) != 1 {
        state.on_detach(TASK);
        return TestResult::Fail("cpuset.mems did not reach scheduler task policy");
    }
    state.on_detach(TASK);
    if narf_scheduler::task_mems_allowed(TASK) != u64::MAX {
        return TestResult::Fail("cpuset detach did not clear task memory mask");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("filesystem/cgroupfs", smoke_cpuset_mems_propagates_to_task);
