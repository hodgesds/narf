//! cgroup-v2 `cpu` / `cpuset` seam (feature `cgroup`).
//!
//! The cgroupfs controllers (`filesystem/src/cgroupfs/cpu.rs`,
//! `cpuset.rs`) own the policy — parsing `cpu.weight`, `cpu.max`,
//! `cpuset.cpus`, computing effective masks — and need a way to push
//! the resulting per-task `Priority` / affinity `CpuSet` onto the
//! tasks that currently belong to a cgroup. This module is that push
//! seam.
//!
//! # Hook-install pattern (matches `filesystem/src/devfs.rs`)
//!
//! Rather than have the cgroupfs crate reach into the scheduler's
//! private `READY` queues directly (it can't — `TaskSlot`/`account`
//! are private), the scheduler exposes two real apply functions
//! ([`apply_priority`], [`apply_affinity`]) and an indirection layer:
//! the controllers call [`install_cgroup_cpu_hook`] /
//! [`install_cgroup_affinity_hook`] once at first-`new_state` time
//! (guarded by an atomic), wiring the scheduler's own apply functions
//! in as the live hooks, then dispatch through
//! [`cgroup_set_priority`] / [`cgroup_set_affinity`]. Installing the
//! *scheduler's own* functions keeps the indirection honest: the hook
//! is a real, working seam, not a stub, and the install point exists
//! so an alternate scheduler policy could override it without a
//! surface break.
//!
//! # What is REAL vs best-effort on the cooperative executor
//!
//! - **Affinity (`cpuset.cpus.effective`)**: REAL. The executor's
//!   per-CPU dispatch and work-stealing honour `TaskSpec.affinity`
//!   (`allowed` is a hard constraint, `preferred` a hint), so
//!   rewriting a parked task's `spec.affinity` changes where it is
//!   eligible to run from its next dispatch onward.
//! - **Priority (`cpu.weight` → nice → `Priority`)**: applied to the
//!   slot's `TaskSpec.priority`, which the Stage-4 `PriorityScheduler`
//!   policy consumes for in-class ordering. On the single-CPU FIFO
//!   default policy this is carried-but-not-acted-on (same caveat the
//!   `priority` module documents) — it becomes live when a
//!   priority-ordered `RunQueue` policy is installed.
//! - **Bandwidth (`cpu.max` quota/period)**: NOT plumbed here. The
//!   executor is cooperative with no preemptive throttle seam; the
//!   `cpu` controller accepts `cpu.max` and reports it but cannot
//!   enforce it. See the comment in `cpu.rs`.
//!
//! All apply functions scan the per-CPU ready queues and rewrite the
//! matching parked task's `spec`. A task that is *mid-poll* (popped
//! onto the executor stack) is not in any queue; it picks up the new
//! value when it returns `Poll::Pending` and is re-enqueued, i.e.
//! after its current poll completes. This is the natural granularity
//! for a cooperative scheduler and is documented rather than worked
//! around.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::affinity::{Affinity, CpuId, CpuSet};
use crate::priority::Priority;
use crate::{TaskId, READY};

/// Apply a nice-style priority to the task whose raw id equals `pid`.
///
/// In NARF the cgroup membership pid and the scheduler [`TaskId`] raw
/// value are the same namespace (see `sys_sched_setattr` in
/// `userspace/src/handlers.rs`, which treats the syscall pid directly
/// as the task id). `nice` is the cgroup's `cpu.weight.nice`
/// equivalent; it is wrapped into [`Priority`] verbatim. Returns
/// `true` if a matching parked task was found and updated.
///
/// Signature matches [`CpuPriorityHook`] so the controller can install
/// it directly. REAL effect is policy-dependent: the
/// `PriorityScheduler` acts on `spec.priority`; the default FIFO
/// policy carries it forward without reordering (see module docs).
pub fn apply_priority(pid: u64, nice: i8) -> bool {
    let priority = Priority(nice);
    let want = TaskId(pid);
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(slot) = dq.iter_mut().find(|s| s.id == want) {
                slot.spec.priority = priority;
                return true;
            }
        }
    }
    false
}

/// Apply a CPU affinity mask to the task whose raw id equals `pid`.
///
/// The mask becomes the task's hard `allowed` constraint; the
/// `preferred` hint is set to the lowest-numbered CPU in the mask (or
/// cleared if the mask is empty). REAL: the executor honours
/// `allowed` for dispatch and work-stealing from the next dispatch
/// onward. Returns `true` if a matching parked task was updated.
///
/// `mask_bits` are the raw `CpuSet` bits (signature matches
/// [`AffinityHook`] so the controller can install this directly). An
/// all-zero mask is treated as "no constraint" (`CpuSet::ALL`) rather
/// than "never runnable" — an empty `cpuset.cpus` in v2 means
/// "inherit", and the controller resolves inheritance before calling
/// here, so a zero mask reaching this point means the effective set is
/// unconstrained.
pub fn apply_affinity(pid: u64, mask_bits: u64) -> bool {
    let cpus = cpu_set_from_bits(mask_bits);
    let allowed = if cpus.is_empty() { CpuSet::ALL } else { cpus };
    let preferred = lowest_cpu(allowed);
    let aff = Affinity { allowed, preferred };
    let want = TaskId(pid);
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(slot) = dq.iter_mut().find(|s| s.id == want) {
                slot.spec.affinity = aff;
                return true;
            }
        }
    }
    false
}

/// Lowest-numbered CPU present in `set`, as the `preferred` hint.
fn lowest_cpu(set: CpuSet) -> Option<CpuId> {
    (0u32..(narf_lib::percpu::MAX_CPUS as u32)).find_map(|c| {
        let id = CpuId(c);
        set.contains(id).then_some(id)
    })
}

/// Sum of measured CPU cycles spent by the parked tasks whose raw ids
/// appear in `pids`. Used by the `cpu` controller's `cpu.stat`
/// `usage_usec` line so it reports *real* per-cgroup usage rather than
/// a zero stub.
///
/// Best-effort by construction: a task that is mid-poll (off-queue) or
/// has already exited (drained from every queue) contributes nothing
/// to the snapshot, so the figure is a lower bound that lags the live
/// total — the same stale-but-consistent semantic `all_task_ids`
/// documents. Returns raw cycles; the controller converts to µs.
pub fn cgroup_cycles_for(pids: &[u64]) -> u64 {
    let mut total: u64 = 0;
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            for slot in dq.iter() {
                if pids.contains(&slot.id.0) {
                    total = total.saturating_add(slot.account.cycles_spent);
                }
            }
        }
    }
    total
}

// ── Hook indirection ────────────────────────────────────────────────
//
// `fn(u64, <payload>) -> bool` pointers stored as `usize`, mirroring
// the devfs `install_*_hook` pattern. The controllers install the
// scheduler's own apply functions lazily from `new_state` so no boot
// wiring is needed; an alternate policy could install different
// behaviour through the same point.

/// Priority hook signature: `(pid, raw_nice_priority) -> updated`.
pub type CpuPriorityHook = fn(u64, i8) -> bool;
/// Affinity hook signature: `(pid, raw_cpu_mask_bits) -> updated`.
pub type AffinityHook = fn(u64, u64) -> bool;

static CPU_PRIORITY_HOOK: AtomicUsize = AtomicUsize::new(0);
static AFFINITY_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the cpu-controller priority hook. Idempotent: a second
/// install of the same pointer is a no-op; a different pointer
/// replaces it. Boot-time / first-`new_state`-time call.
pub fn install_cgroup_cpu_hook(hook: CpuPriorityHook) {
    CPU_PRIORITY_HOOK.store(hook as usize, Ordering::Release);
}

/// Install the cpuset-controller affinity hook. Same semantics as
/// [`install_cgroup_cpu_hook`].
pub fn install_cgroup_affinity_hook(hook: AffinityHook) {
    AFFINITY_HOOK.store(hook as usize, Ordering::Release);
}

/// Dispatch a priority change through the installed cpu hook. The
/// `nice` value is the cgroup's `cpu.weight.nice`-equivalent, clamped
/// to `Priority`'s `i8` range by the caller. Returns `false` if no
/// hook is installed or the task was not found.
pub fn cgroup_set_priority(pid: u64, nice: i8) -> bool {
    let p = CPU_PRIORITY_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return false;
    }
    // SAFETY: `p` was stored by `install_cgroup_cpu_hook` from a valid
    // `CpuPriorityHook` (`fn(u64, i8) -> bool`); identical size and
    // ABI, static lifetime.
    let f: CpuPriorityHook = unsafe { core::mem::transmute::<usize, CpuPriorityHook>(p) };
    f(pid, nice)
}

/// Dispatch an affinity change through the installed cpuset hook.
/// `mask_bits` are the raw `CpuSet` bits. Returns `false` if no hook
/// is installed or the task was not found.
pub fn cgroup_set_affinity(pid: u64, mask_bits: u64) -> bool {
    let p = AFFINITY_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return false;
    }
    // SAFETY: `p` was stored by `install_cgroup_affinity_hook` from a
    // valid `AffinityHook` (`fn(u64, u64) -> bool`); identical size and
    // ABI, static lifetime.
    let f: AffinityHook = unsafe { core::mem::transmute::<usize, AffinityHook>(p) };
    f(pid, mask_bits)
}

/// Construct a `CpuSet` from raw bits. Exposed so the cpuset
/// controller (which speaks Linux cpulist syntax) can hand the
/// scheduler a mask without depending on `CpuSet`'s private
/// representation.
pub fn cpu_set_from_bits(bits: u64) -> CpuSet {
    let mut set = CpuSet::EMPTY;
    for c in 0u32..(narf_lib::percpu::MAX_CPUS as u32) {
        if bits & (1u64 << (c & 0x3F)) != 0 {
            set.insert(CpuId(c));
        }
    }
    set
}

#[doc(hidden)]
pub fn __reset_hooks_for_test() {
    CPU_PRIORITY_HOOK.store(0, Ordering::Release);
    AFFINITY_HOOK.store(0, Ordering::Release);
}
