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
//! Affinity updates use the scheduler's task-identity registry. A task
//! that is *mid-poll* (popped onto the executor stack) observes the new
//! mask immediately through queries and is re-homed when it returns
//! `Poll::Pending`. Priority updates remain parked-slot updates.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::affinity::{CpuId, CpuSet};
use crate::priority::Priority;
use crate::{current_task_id, set_task_affinity, TaskId, READY};

// ── memory-controller charge-PID provider ───────────────────────────
//
// The page/frame allocator (`narf-memory`) has no per-task identity of
// its own; the `memory` cgroup controller's charge hook needs "which
// task is allocating right now". The scheduler owns that register
// (`current_task_id`), and `narf-memory` is a dependency, so the
// scheduler is the natural — and only — place that can answer it. The
// `memory` controller calls [`install_memory_pid_provider`] from its
// first-`new_state` lazy-install (the same indirection the cpu/cpuset
// hooks use, just in the opposite direction), wiring the provider below
// into the allocator. See `filesystem/src/cgroupfs/memory.rs`.

/// Function-pointer seam from the userspace process table. The scheduler
/// deliberately does not depend on `narf-userspace`; frame installs this hook
/// once userspace's TaskId-to-ProcessId map is ready.
static MEMORY_PID_RESOLVER: AtomicUsize = AtomicUsize::new(0);
static PROCESS_TASK_RESOLVER: AtomicUsize = AtomicUsize::new(0);

/// Install the resolver which maps a scheduler task id to the outer userspace
/// process id used by cgroup membership. A missing mapping means the task is
/// kernel-internal and its allocation remains unattributed.
///
/// Calling this replaces the prior resolver, which is useful during bootstrap
/// when the userspace process table becomes available after the scheduler.
pub fn install_memory_pid_resolver(resolver: fn(u64) -> Option<u64>) {
    MEMORY_PID_RESOLVER.store(resolver as usize, Ordering::Release);
    // A new resolver can map the same task id to a different pid (bootstrap
    // hand-off; test resolver swaps), so drop every per-CPU memo entry.
    for memo in CHARGE_PID_MEMO.iter() {
        memo.task.store(CHARGE_MEMO_EMPTY, Ordering::Relaxed);
    }
}

/// Install the reverse ProcessId-to-TaskId resolver used by cgroup controller
/// updates. Cgroup membership is keyed by outer ProcessId, while READY slots
/// are keyed by executor-private TaskId.
pub fn install_process_task_resolver(resolver: fn(u64) -> Option<u64>) {
    PROCESS_TASK_RESOLVER.store(resolver as usize, Ordering::Release);
}

fn process_task(pid: u64) -> Option<TaskId> {
    let ptr = PROCESS_TASK_RESOLVER.load(Ordering::Acquire);
    if ptr == 0 {
        return Some(TaskId(pid));
    }
    // SAFETY: installed from the exact `fn(u64) -> Option<u64>` type above.
    let resolve: fn(u64) -> Option<u64> = unsafe { core::mem::transmute(ptr) };
    resolve(pid).map(TaskId)
}

/// Temporarily install a process-to-task resolver while an in-kernel
/// regression test exercises the cgroup seam, then restore the boot-time
/// resolver. Kernel tests share one address space, so leaving a synthetic
/// resolver installed would make later tests order-dependent.
pub(crate) fn with_process_task_resolver_for_test<R>(
    resolver: fn(u64) -> Option<u64>,
    test: impl FnOnce() -> R,
) -> R {
    let previous = PROCESS_TASK_RESOLVER.swap(resolver as usize, Ordering::AcqRel);
    let result = test();
    PROCESS_TASK_RESOLVER.store(previous, Ordering::Release);
    result
}

/// Resolve the PID to charge for the in-flight allocation. The current task
/// id is an executor-private identity; cgroup membership is keyed by the
/// userspace ProcessId, so translate it through the installed resolver.
/// Outside a task poll (early boot, between rounds, kernel-internal work), or
/// without a process mapping, allocations stay unattributed rather than being
/// charged to an unrelated cgroup with the same raw numeric id.
fn current_charge_pid() -> Option<u64> {
    let id = current_task_id();
    if id == TaskId::NONE {
        return None;
    }
    let ptr = MEMORY_PID_RESOLVER.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    // Per-CPU memo of the last task->charge-pid resolution. This runs on EVERY
    // heap allocation, and the resolver (`task_to_pid_raw`) takes a GLOBAL
    // spinlock + BTreeMap lookup — so without this, the per-CPU slab's fast
    // path is serialised behind one lock on every alloc (it dominated the CPU
    // when a Wayland compositor faulted in its DSOs, and would collapse under
    // SMP as every CPU contends the same lock). Allocations come in long bursts
    // within a single task, so a per-CPU (task,pid) cache hits almost always,
    // reducing the hot path to two relaxed loads + a compare. A task's pid is
    // stable for its lifetime; a rare stale hit after task-id reuse only
    // mis-attributes accounting (never unsafe).
    let raw = id.raw();
    let cpu = narf_lib::percpu::current_cpu();
    let memo = &CHARGE_PID_MEMO[if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    }];
    if memo.task.load(Ordering::Relaxed) == raw {
        let p = memo.pid.load(Ordering::Relaxed);
        return if p == CHARGE_MEMO_NONE { None } else { Some(p) };
    }
    // SAFETY: `ptr` is non-zero (checked) and was produced by
    // `install_memory_pid_resolver` from the exact function-pointer type.
    let resolve: fn(u64) -> Option<u64> = unsafe { core::mem::transmute(ptr) };
    let pid = resolve(raw);
    // Publish pid before task so a same-CPU IRQ allocation that sees the new
    // task also sees the matching pid (a miss before both stores just
    // re-resolves — safe).
    memo.pid
        .store(pid.unwrap_or(CHARGE_MEMO_NONE), Ordering::Relaxed);
    memo.task.store(raw, Ordering::Relaxed);
    pid
}

/// A resolver returned `None` (kernel-internal task, no process mapping) — a
/// real sentinel stored in the memo so the miss isn't re-resolved every alloc.
const CHARGE_MEMO_NONE: u64 = u64::MAX;
/// Task slot that has never been populated. Distinct from any real task id
/// (a small monotonic counter) and from `CHARGE_MEMO_NONE`.
const CHARGE_MEMO_EMPTY: u64 = u64::MAX - 1;

#[repr(align(64))]
struct ChargePidMemo {
    task: AtomicU64,
    pid: AtomicU64,
}

/// Per-CPU cache of `current_charge_pid`, cache-line padded to avoid false
/// sharing between CPUs.
static CHARGE_PID_MEMO: [ChargePidMemo; narf_lib::percpu::MAX_CPUS] = [const {
    ChargePidMemo {
        task: AtomicU64::new(CHARGE_MEMO_EMPTY),
        pid: AtomicU64::new(CHARGE_MEMO_NONE),
    }
};
    narf_lib::percpu::MAX_CPUS];

/// Install the `memory`-controller charge-PID provider into
/// `narf-memory`. Idempotent at the allocator side (a second install
/// just re-stores the same fn pointer). Called by the cgroupfs `memory`
/// controller's lazy hook-install so no boot wiring is required; until
/// it runs, the allocator's charge hook has no PID to attribute and
/// memory accounting is simply inactive.
pub fn install_memory_pid_provider() {
    narf_memory::install_cgroup_pid_provider(current_charge_pid);
}

/// Apply a nice-style priority to the task mapped from outer ProcessId `pid`.
/// `nice` is the cgroup's `cpu.weight.nice` equivalent; it is wrapped into
/// [`Priority`] verbatim. Returns `true` if a matching parked task was found
/// and updated.
///
/// Signature matches [`CpuPriorityHook`] so the controller can install
/// it directly. REAL effect is policy-dependent: the
/// `PriorityScheduler` acts on `spec.priority`; the default FIFO
/// policy carries it forward without reordering (see module docs).
pub fn apply_priority(pid: u64, nice: i8) -> bool {
    let priority = Priority(nice);
    let Some(want) = process_task(pid) else {
        return false;
    };
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

/// Apply a CPU affinity mask to the task mapped from outer ProcessId `pid`.
///
/// The mask becomes the task's hard `allowed` constraint; the
/// `preferred` hint is set to the lowest-numbered CPU in the mask (or
/// cleared if the mask is empty). REAL: the executor honours
/// `allowed` for dispatch and work-stealing from the next dispatch
/// onward. Returns `true` if a matching live task was updated.
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
    process_task(pid).is_some_and(|task| set_task_affinity(task, allowed).is_ok())
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
