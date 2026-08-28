//! narf-scheduler — cooperative async executor.
//!
//! Spec: `scheduler/specification/spec.md`. Stage-1 subset per STAGE1.md
//! #10: single-CPU cooperative executor, intrusive-esque ready queue,
//! `spawn`, `yield_now`, `block_on`, no preemption.
//!
//! Stage 2 adds real per-task wakers (see ── Waker plumbing ──): a
//! Pending task whose waker has not fired since its last poll is
//! skipped on the next round, so futures driven by external signals
//! (IRQ handlers, IPC events) no longer cost a poll per loop iteration.
//! The halt-on-no-progress backstop is kept so self-waking futures
//! (today's `SleepUntil`, `yield_now`) still idle the CPU between
//! rounds until a hardware tick resumes us.
//!
//! Stage 3 adds CPU budgets, affinity types, and the scaffolding for
//! direct context transfer. Single-CPU reality keeps the work-stealing
//! and SMP pieces structural; what the executor *does* act on:
//! - `TaskSpec { affinity, budget, budget_cap }` on every spawn.
//! - A live `Cap<CpuBudget, Spend>`, when attached, is
//!   `check_live`-gated on every poll — revoke → task dropped next
//!   round.
//! - Per-task `BudgetAccount` accumulates measured poll cycles and
//!   ticks `overruns` when a poll blows the burst allowance.
//!
//! Stage 4 adds per-CPU run queues + opt-in work stealing. Each CPU
//! owns one slot of `READY: [_; MAX_CPUS]`; `spawn` routes by the
//! task's `affinity.preferred` (when online) or the current CPU. APs
//! enter `run_forever` after bring-up and drain their own queue;
//! `enable_work_stealing()` lets idle CPUs steal from siblings.
//! Off by default so the BSP-only test harness sees stable single-
//! CPU FIFO ordering.
//!
//! Stage 5 lands the spec's post-Stage-4 features in three waves:
//! budget-credit donation with head enqueue, domain-state save/restore at
//! cooperative yield points, and fair-share enforcement + NUMA-aware steal.
//!
//! Donation fast path (spec §3.3): `donate_to(target, &Cap<Task,
//! Invoke>)` deducts the donor's remaining burst quantum from its
//! `BudgetAccount`, credits it to the target, and head-enqueues
//! the target so the next dispatch services it first. Revoking
//! the donation cap before the donee polls refunds both sides
//! atomically at the donee's next pop (`settle_donation`).
//!
//! Architecture-neutral domain state is saved around every poll. On x86_64
//! this preserves PKRS (or the PCID fallback); on aarch64 it preserves the MTE
//! tag-check mode. The representation and switching mechanics remain private
//! to `narf_memory`, so scheduling policies cannot bypass this boundary.
//!
//! Burst-overrun handling + NUMA-aware steal (spec §3.4 / §3.2):
//! `BudgetAccount::charge` compares each completed poll with the configured
//! burst and returns a `ChargeOutcome` the executor acts on — `Throttle`
//! clears the awake flag until an external wake,
//! `Demote` reclassifies the slot as `SchedClass::Idle`, `Kill`
//! drops the slot O(1). `PeriodBudget` adds core-owned replenishment, strict
//! throttling, and bounded idle borrowing with debt repayment. `share_ppm`
//! remains descriptive unless a consistent period contract is attached.
//! `try_steal_one` prefers same-NUMA-node
//! victims (`narf_acpi::cpu_node`) before crossing nodes; design
//! follows Vyukov's CPPCON work-stealing notes
//! (https://www.1024cores.net/).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod accounting;
pub mod admission;
pub mod affinity;
pub mod budget;
#[cfg(feature = "cgroup")]
pub mod cgroup;
pub mod cpu_lifecycle;
pub mod donation;
pub mod numa;
pub mod policy;
pub mod priority;
pub mod stackful;
pub mod steal;

mod tests;

pub use accounting::{
    hardirq_cycles, interrupt_account_enter, nmi_cycles, InterruptAccountGuard, InterruptKind,
};
pub use admission::{realtime_bandwidth, AdmissionError, RealtimeBandwidth, RT_CPU_LIMIT_PPM};
pub use affinity::{Affinity, CpuId, CpuSet};
pub use budget::{
    BudgetAccount, BudgetEligibility, BudgetView, ChargeOutcome, CpuBudget, ExhaustionPolicy,
    OverrunPolicy, PeriodBudget, ResourceBudget,
};
#[cfg(feature = "cgroup")]
pub use cgroup::{
    apply_affinity, apply_priority, cgroup_cycles_for, cgroup_set_affinity, cgroup_set_priority,
    cpu_set_from_bits, install_cgroup_affinity_hook, install_cgroup_cpu_hook,
    install_memory_pid_provider, install_memory_pid_resolver, install_process_task_resolver,
    AffinityHook, CpuPriorityHook,
};
pub use cpu_lifecycle::{
    cpu_bring_up, cpu_online, cpu_take_offline, online_count, CpuLifecycle, HotPlugError,
};
pub use donation::{
    current_donation_policy_name, install_donation_policy, BackQueueDonation, Donation,
    DonationError, DonationPolicy, EnqueueDonee, HeadQueueDonation,
};
pub use numa::{clear_task_mems_allowed, set_task_mems_allowed, task_mems_allowed, ALL_NUMA_NODES};
pub use policy::{
    cpu_state, current_scheduler_name, install_scheduler, ClassScheduler, CpuIdleMeta, CpuState,
    CpuStateChange, FifoScheduler, PriorityScheduler, RunQueue, SchedPolicy, Scheduler,
    SchedulerError, TaskDequeueReason, TaskEnqueueReason, TaskHandle, TaskMeta, TaskQueueEvent,
};
pub use priority::{Priority, SchedClass, SmtSharePolicy, WorkKind};
pub use stackful::{preempt_count, preempt_disable, PreemptGuard};
pub use steal::{
    current_steal_strategy_name, install_steal_strategy, NumaAwareSteal, RandomSteal, Steal,
    StealError, StealStrategy,
};

// re-export the Invoke rights marker for callers who need to type a
// donation cap — saves one import line at every call site.
pub use narf_capabilities::Invoke;

// Re-export user-mode primitives so downstream crates that already
// depend on `narf-scheduler` (notably `narf-userspace`, where user
// tasks live as scheduler futures) can name them without taking a
// fresh direct dep on `narf-arch` — adding a fresh direct dep
// perturbs link-time test-registration ordering enough to expose
// latent flakes in the e2e suite. The transitive dep already
// exists (`narf-scheduler` → `narf-arch`); this just exposes it.
#[cfg(target_arch = "x86_64")]
pub use narf_arch::x86_64::{
    enter_user_mode, enter_user_mode_at_top, enter_user_mode_resume, enter_user_mode_resume_at_top,
    enter_user_mode_with_arg, enter_user_mode_with_arg_at_top, longjmp, set_user_fs_base, setjmp,
    JmpBuf, UserState, USER_RFLAGS,
};

#[cfg(target_arch = "aarch64")]
pub use narf_arch::aarch64::{
    enter_user_mode, enter_user_mode_at_top, enter_user_mode_resume, enter_user_mode_resume_at_top,
    enter_user_mode_with_arg, enter_user_mode_with_arg_at_top, longjmp, set_user_tls_base, setjmp,
    JmpBuf, UserFpState, UserState, USER_SPSR,
};

// `halt_forever` is the right "I should never reach here" sink for
// the user-task hook fast-paths in `narf-userspace`. Re-exported
// for the same reason the user-mode primitives are: avoids a fresh
// direct `narf-arch` dep on `narf-userspace` that re-perturbs link
// ordering.
pub use narf_arch::halt_forever;

// Re-export the time crate so `narf-userspace` (already a downstream
// of `narf-scheduler`) can read the monotonic clock without taking a
// direct `narf-time` dep — same dep-cycle / link-ordering rationale
// as the `narf-arch` re-export above.
pub use narf_time;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;

use narf_capabilities::{Cap, CapKind, CapType, Spend};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;
use narf_time::Instant;

/// A pinned boxed future representing one kernel task.
type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Per-CPU ready queues. Each CPU owns its own `VecDeque<TaskSlot>`;
/// `spawn` enqueues onto the CPU named by the task's affinity hint
/// (or the current CPU if no hint). `run_until_empty` drains the
/// caller's queue then attempts to steal one task from another CPU's
/// queue. With single-CPU configurations only index 0 is exercised,
/// matching pre-SMP behaviour byte-for-byte.
const NEW_QUEUE: IrqSafeSpinLock<Option<VecDeque<TaskSlot>>> = IrqSafeSpinLock::new(None);
static READY: [IrqSafeSpinLock<Option<VecDeque<TaskSlot>>>; narf_lib::percpu::MAX_CPUS] =
    [NEW_QUEUE; narf_lib::percpu::MAX_CPUS];

/// Monotonic task identifier. Minted at `spawn` time. `0` is reserved
/// as "no task"; the first spawn gets `TaskId(1)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    pub const NONE: TaskId = TaskId(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Read-only, per-CPU demand sample for the separately capability-gated power
/// governor. This is observation only: scheduler policies cannot set
/// frequencies and power governors cannot mutate a run queue.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuDemand {
    pub state: CpuState,
    pub runnable: usize,
    pub realtime_runnable: usize,
    pub softirq_runnable: usize,
    pub kernel_threads_runnable: usize,
    pub user_threads_runnable: usize,
    pub next_deadline_cycles: Option<u64>,
    pub realtime_reserved_ppm: u64,
    pub hardirq_cycles: u64,
    pub nmi_cycles: u64,
}

/// Snapshot scheduler demand without calling policy code or taking any
/// cross-CPU/global scheduler lock.
pub fn cpu_demand(cpu: CpuId) -> CpuDemand {
    let index = cpu.0 as usize;
    let mut sample = CpuDemand {
        state: policy::cpu_state(cpu),
        realtime_reserved_ppm: admission::realtime_bandwidth(cpu).cpu_reserved_ppm,
        hardirq_cycles: accounting::hardirq_cycles(cpu),
        nmi_cycles: accounting::nmi_cycles(cpu),
        ..CpuDemand::default()
    };
    let Some(ready) = READY.get(index) else {
        return sample;
    };
    let queue = ready.lock();
    let Some(queue) = queue.as_ref() else {
        return sample;
    };
    let now = narf_time::now_cycles();
    for slot in queue {
        if !slot.awake.flag.load(Ordering::Acquire) {
            continue;
        }
        let view = slot.account.view(now, &slot.spec.budget);
        if view.eligibility == BudgetEligibility::Throttled {
            sample.next_deadline_cycles =
                min_deadline(sample.next_deadline_cycles, view.replenish_at_cycles);
            continue;
        }
        sample.runnable += 1;
        sample.realtime_runnable += usize::from(slot.spec.class == SchedClass::Realtime);
        sample.softirq_runnable += usize::from(slot.spec.work_kind == WorkKind::SoftIrq);
        sample.kernel_threads_runnable +=
            usize::from(slot.spec.work_kind == WorkKind::KernelThread);
        sample.user_threads_runnable += usize::from(slot.spec.work_kind == WorkKind::UserThread);
        sample.next_deadline_cycles = min_deadline(
            sample.next_deadline_cycles,
            min_deadline(slot.spec.budget.deadline_cycles, view.replenish_at_cycles),
        );
    }
    sample
}

#[inline]
fn min_deadline(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Cap-type marker for `Cap<Task, R>`. `Cap<Task, Invoke>` is the
/// `scheduler/` spec §3.3 donation-authority type: the caller proves
/// prior permission to donate its time slice to the target.
#[derive(Copy, Clone, Debug)]
pub struct Task;

impl CapType for Task {
    const KIND: CapKind = CapKind::Task;
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Live user-task count (processes + threads) for the fork-bomb guard.
static LIVE_USER_TASKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Hard cap on concurrent user tasks. `fork`/`clone` return `EAGAIN` at the
/// cap, containing a fork bomb before it exhausts kernel memory and the
/// per-CPU ready queues (unbounded `VecDeque`s). Generous for real workloads;
/// far below where that many forked address spaces would OOM. SMP makes an
/// uncapped bomb worse — more cores to flood and more concurrent shootdowns.
pub const MAX_USER_TASKS: usize = 1024;

/// RAII decrement for a live user task, stored in the slot by `spawn_user`.
/// Fires on the slot's final drop (completion / kill / budget-drop), so the
/// count stays balanced no matter which removal path ran. Moving the slot
/// between queues does not drop it, so the count tracks task lifetime.
struct NprocGuard;
impl NprocGuard {
    #[inline]
    fn new() -> Self {
        LIVE_USER_TASKS.fetch_add(1, Ordering::Relaxed);
        NprocGuard
    }
}
impl Drop for NprocGuard {
    #[inline]
    fn drop(&mut self) {
        LIVE_USER_TASKS.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for TaskSlot {
    fn drop(&mut self) {
        unregister_task_affinity(self.id);
    }
}

/// Current number of live user tasks (processes + threads).
pub fn live_user_task_count() -> usize {
    LIVE_USER_TASKS.load(Ordering::Relaxed)
}

/// Whether another user task may be spawned under [`MAX_USER_TASKS`]. `fork`
/// and `clone` consult this and return `EAGAIN` when it is false — the
/// fork-bomb guard. A slight TOCTOU overshoot (bounded by concurrent forks)
/// is harmless: this contains a runaway, it isn't a hard security boundary.
pub fn user_nproc_available() -> bool {
    live_user_task_count() < MAX_USER_TASKS
}

/// Master switch for cross-CPU work stealing. Off by default so the
/// BSP-only test harness sees stable single-CPU FIFO semantics. Boot
/// code (or a runtime toggle) flips it on once the system is past
/// the sequential setup phase, after which APs in `run_forever`
/// drain their own queue first and steal from siblings only when
/// idle.
static STEAL_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable cross-CPU work stealing on this kernel. Callable from boot
/// once the BSP has finished publishing its initial spawn batch and
/// is ready to share work with online APs.
pub fn enable_work_stealing() {
    STEAL_ENABLED.store(true, Ordering::Release);
}

/// Disable work stealing. The toggle is process-wide; useful for
/// tests that need the single-CPU FIFO invariant back.
pub fn disable_work_stealing() {
    STEAL_ENABLED.store(false, Ordering::Release);
}

/// Master switch for running *user* tasks on multiple CPUs. Off by
/// default. Boot flips it on ONLY when cross-CPU TLB shootdown is
/// wired (x2APIC active → the `invlpg_global` broadcast hook is
/// installed), which is the soundness prerequisite: a thread group
/// sharing an address space across cores needs every munmap /
/// mprotect / madvise / COW-resolve to invalidate peer TLBs. Under
/// xAPIC fallback the hook is absent, so this stays off and user
/// tasks remain BOOT-pinned (see [`TaskSpec::user_task`] and the
/// `addr_space` floor in `steal::StealStrategy::allow_steal`).
static USER_SMP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable user-task SMP (migration + AP initial placement). Call once
/// at boot, after confirming the TLB-shootdown broadcast hook is
/// installed (x2APIC) and APs are online. Idempotent.
pub fn enable_user_task_smp() {
    USER_SMP_ENABLED.store(true, Ordering::Release);
}

/// Whether user tasks may run on application processors. Consulted by
/// [`TaskSpec::user_task`] (initial affinity) and the steal floor.
#[inline]
pub fn user_task_smp_enabled() -> bool {
    USER_SMP_ENABLED.load(Ordering::Acquire)
}

/// Id of the task currently being polled by the executor on each CPU,
/// or `0` when that CPU is between polls. Syscall handlers read THIS
/// CPU's slot to identify the caller — the syscall trap runs on the
/// same CPU as the task that issued it. Per-CPU is required once user
/// tasks run on multiple CPUs concurrently; a single global would
/// report the wrong task to a syscall on a different core.
static CURRENT_TASK: [AtomicU64; narf_lib::percpu::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; narf_lib::percpu::MAX_CPUS]
};

/// This CPU's current-task cell.
#[inline]
fn current_task_slot() -> &'static AtomicU64 {
    &CURRENT_TASK[narf_lib::percpu::current_cpu()]
}

pub(crate) fn cpu_running_task(cpu: CpuId) -> bool {
    CURRENT_TASK
        .get(cpu.0 as usize)
        .map(|task| task.load(Ordering::Acquire) != TaskId::NONE.raw())
        .unwrap_or(false)
}

/// Address space of the currently-polling task on each CPU — published
/// before `poll` so syscall handlers can resolve it without searching
/// the run-queue (the slot has been popped and isn't visible to
/// `address_space_of` during the poll body). Cleared on the way out.
/// Per-CPU for the same reason as `CURRENT_TASK`.
static ACTIVE_USER_AS: [narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>>;
    narf_lib::percpu::MAX_CPUS] = {
    const EMPTY: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    [EMPTY; narf_lib::percpu::MAX_CPUS]
};

/// This CPU's active-user-AS cell.
#[inline]
fn active_user_as_slot() -> &'static narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> {
    &ACTIVE_USER_AS[narf_lib::percpu::current_cpu()]
}

/// Read the currently-polling task's id on this CPU. Returns
/// `TaskId::NONE` when called outside any `poll` context (e.g. from
/// boot or between rounds).
#[inline]
pub fn current_task_id() -> TaskId {
    TaskId(current_task_slot().load(Ordering::Acquire))
}

fn publish_budget_window(cpu: usize, started: u64, view: BudgetView, budget: &ResourceBudget) {
    let Some(period) = budget.period else {
        CURRENT_BUDGET_SOFT_END[cpu].store(0, Ordering::Release);
        CURRENT_BUDGET_HARD_END[cpu].store(0, Ordering::Release);
        CURRENT_BUDGET_BORROWING[cpu].store(false, Ordering::Release);
        return;
    };
    let borrow_available = if period.exhaustion == ExhaustionPolicy::IdleBorrow {
        period
            .max_borrow_cycles
            .saturating_sub(view.borrowed_cycles)
    } else {
        0
    };
    let soft_end = started.saturating_add(view.remaining_cycles);
    let hard_end = soft_end
        .saturating_add(borrow_available)
        .min(view.replenish_at_cycles.unwrap_or(u64::MAX));
    CURRENT_BUDGET_SOFT_END[cpu].store(soft_end, Ordering::Release);
    CURRENT_BUDGET_HARD_END[cpu].store(hard_end, Ordering::Release);
    arm_scheduler_deadline(soft_end.min(hard_end));
    CURRENT_BUDGET_BORROWING[cpu].store(
        view.eligibility == BudgetEligibility::Borrowable,
        Ordering::Release,
    );
}

fn clear_budget_window(cpu: usize) -> bool {
    CURRENT_BUDGET_SOFT_END[cpu].store(0, Ordering::Release);
    CURRENT_BUDGET_HARD_END[cpu].store(0, Ordering::Release);
    CURRENT_BUDGET_BORROWING[cpu].swap(false, Ordering::AcqRel)
}

/// Timer-trap decision for a currently running stackful task. A strict budget
/// forces a switch at its soft boundary. Idle-borrow work keeps the current
/// continuation running—with no idle-thread round trip—until regular work
/// appears or its bounded hard limit is reached.
pub(crate) fn tick_preemption_required(current: u64, now: u64, slice_expired: bool) -> bool {
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let soft_end = CURRENT_BUDGET_SOFT_END[cpu].load(Ordering::Acquire);
    let hard_end = CURRENT_BUDGET_HARD_END[cpu].load(Ordering::Acquire);
    if hard_end != 0 && now >= hard_end {
        return true;
    }
    if soft_end != 0 && now >= soft_end {
        if has_other_runnable_work(current) {
            return true;
        }
        CURRENT_BUDGET_BORROWING[cpu].store(true, Ordering::Release);
        return false;
    }
    slice_expired && has_other_runnable_work(current)
}

/// Resolve the address space of the currently-polling task. This
/// is the syscall-side companion to `address_space_of` that works
/// during a poll body (when the slot has been popped from the
/// run-queue and is no longer findable by id). Returns `None`
/// when the active task is kernel-only (no AS) or the executor
/// isn't currently polling.
pub fn current_address_space() -> Option<Arc<AddressSpace>> {
    active_user_as_slot().lock().clone()
}

/// A task's wake state, shared between its ready-queue slot and every
/// `Waker` it has handed out. `flag` is the "needs-repoll" bit; `cpu` is
/// the CPU whose ready queue currently holds the slot — the reschedule-
/// IPI target so a cross-core wake un-halts an idle owner immediately
/// instead of leaving it to wake at its next timer tick.
pub(crate) struct WakeCell {
    flag: AtomicBool,
    cpu: AtomicU32,
}

/// Per-CPU "about to halt / halted" flag, used to gate the reschedule
/// IPI: only kick a CPU that is actually idle (a running CPU sees the
/// awake flag on its next round, no IPI needed). The wake side and the
/// idle side fence around this (Dekker) so a wake racing a halt is never
/// both un-IPI'd AND unobserved.
static CPU_HALTED: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

/// Per-CPU periodic-budget boundaries for the currently polling slot. Zero
/// means no period budget. The timer trap reads these without touching the
/// private task slot or accounting object.
static CURRENT_BUDGET_SOFT_END: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static CURRENT_BUDGET_HARD_END: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static CURRENT_BUDGET_BORROWING: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

/// Installed at boot: sends a fixed reschedule IPI to `cpu`. A hook (not
/// a direct call) keeps `narf-scheduler` free of an `narf-interrupts`
/// dependency. `0` = not installed (single-CPU / pre-boot) → no IPI.
static RESCHED_IPI_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the reschedule-IPI sender (boot installs the x2APIC ICR write).
pub fn set_resched_ipi_hook(f: fn(u32)) {
    RESCHED_IPI_HOOK.store(f as usize, Ordering::Release);
}

/// Hook to arm a one-shot architecture clockevent at the given cycle value
/// (x86 boot wires `apic::arm_tsc_deadline_if_earlier`). Used for periodic
/// budget boundaries and by the idle path as a LOST-WAKEUP BACKSTOP: an AP
/// that HLTs with no wheel deadline otherwise
/// relies entirely on an external wake (cross-core IPI / device IRQ) plus
/// the periodic tick. The stall watchdog caught a runnable task stranded
/// on a HALTED AP — a wake that was neither observed nor IPI-delivered.
/// Arming a short fallback before every idle HLT guarantees the AP
/// re-scans within a bounded time, so a lost/late wake self-heals (a
/// permanent wedge becomes a sub-tick latency blip) regardless of any
/// subtle wake-delivery race. `0` = not installed (single-CPU / pre-boot).
static IDLE_BACKSTOP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the scheduler deadline arm (boot installs the LAPIC TSC-deadline
/// write). The historical name is retained for API compatibility.
pub fn set_idle_backstop_hook(f: fn(u64)) {
    IDLE_BACKSTOP_HOOK.store(f as usize, Ordering::Release);
}

/// Installed at boot: retarget the running CPU's kernel-entry stack (TSS.rsp0
/// and the SYSCALL `gs:[8]` kernel_stack_top) to `top`, so a trap/syscall from
/// the currently-running user task lands on THAT task's own kernel stack
/// (Linux `update_task_stack` model). `top == 0` restores the per-CPU baseline
/// (the boot-time rsp0 stack). A hook keeps `narf-scheduler` free of an
/// `narf-frame` dependency (frame owns the TSS / PerCpu). `0`-ptr = not
/// installed (single-CPU / pre-boot) → no-op.
#[cfg(target_arch = "x86_64")]
static SET_KERNEL_STACK_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the per-task kernel-stack retargeting (boot installs the TSS.rsp0 +
/// `gs:[8]` write + lazy per-CPU baseline capture).
#[cfg(target_arch = "x86_64")]
pub fn set_kernel_stack_hook(f: fn(u64)) {
    SET_KERNEL_STACK_HOOK.store(f as usize, Ordering::Release);
}

/// Reads the running CPU's current SYSCALL kernel-stack top (`gs:[8]`). Boot
/// installs `percpu::kernel_stack_top`. Used by `poll_to_yield` to snapshot the
/// rsp0 that was live on entry so a NESTED poll (a stackful task pumping
/// `poll_one_round` from a sync wait) restores the OUTER task's stack top on
/// switch-back instead of blindly resetting to the executor baseline — which
/// would leave the outer user task's subsequent syscalls landing on the
/// executor stack and corrupting its saved switch context.
#[cfg(target_arch = "x86_64")]
static GET_KERNEL_STACK_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the kernel-stack-top reader (boot installs `percpu::kernel_stack_top`).
#[cfg(target_arch = "x86_64")]
pub fn set_get_kernel_stack_hook(f: fn() -> u64) {
    GET_KERNEL_STACK_HOOK.store(f as usize, Ordering::Release);
}

/// Current rsp0 / `gs:[8]` top, or 0 if no reader is installed.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn current_kernel_stack_top() -> u64 {
    let p = GET_KERNEL_STACK_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return 0;
    }
    // SAFETY: `p` was stored by `set_get_kernel_stack_hook` from a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(p) };
    f()
}

/// Point the running CPU's kernel-entry stack at `top` (or, when `top == 0`,
/// restore the per-CPU baseline). No-op if no hook is installed.
///
/// Wired into the stackful switch-in/out path (`poll_to_yield`) for the
/// per-task-own-stack model.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn retarget_kernel_stack(top: u64) {
    let p = SET_KERNEL_STACK_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    // SAFETY: `p` was stored by `set_kernel_stack_hook` from a real `fn(u64)`.
    let f: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(p) };
    f(top);
}

/// Arm the architecture clockevent no later than `deadline`.
fn arm_scheduler_deadline(deadline: u64) {
    let p = IDLE_BACKSTOP_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    // SAFETY: `p` was set by `set_idle_backstop_hook` from a `fn(u64)`.
    let f: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(p) };
    f(deadline);
}

/// Arm the idle backstop ~`ms` milliseconds out, if a hook is installed.
fn arm_idle_backstop_ms(ms: u64) {
    let deadline = narf_time::now_cycles().wrapping_add(narf_time::ns_to_cycles(ms * 1_000_000));
    arm_scheduler_deadline(deadline);
}

/// Cache-line-isolated read-only telemetry written by the executing CPU.
/// Watchdog and test readers aggregate all CPUs only when they need a snapshot,
/// keeping remote-wake and bounded-completion paths off shared counter lines.
#[repr(C, align(64))]
struct SchedulerTelemetry {
    resched_sent: AtomicU64,
    resched_skip: AtomicU64,
    forward_progress: AtomicU64,
    _pad: [u8; 40],
}

impl SchedulerTelemetry {
    const fn new() -> Self {
        Self {
            resched_sent: AtomicU64::new(0),
            resched_skip: AtomicU64::new(0),
            forward_progress: AtomicU64::new(0),
            _pad: [0; 40],
        }
    }
}

const _: () = assert!(core::mem::size_of::<SchedulerTelemetry>() == 64);

static SCHEDULER_TELEMETRY: [SchedulerTelemetry; narf_lib::percpu::MAX_CPUS] =
    [const { SchedulerTelemetry::new() }; narf_lib::percpu::MAX_CPUS];

#[inline]
fn local_scheduler_telemetry() -> &'static SchedulerTelemetry {
    &SCHEDULER_TELEMETRY[narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1)]
}

fn sum_scheduler_telemetry(select: fn(&SchedulerTelemetry) -> &AtomicU64) -> u64 {
    SCHEDULER_TELEMETRY.iter().fold(0u64, |total, cpu| {
        total.wrapping_add(select(cpu).load(Ordering::Relaxed))
    })
}

/// Publish a completed unit of kernel work to fatal-path watchdogs.
///
/// Long operations can legitimately remain inside one syscall for seconds
/// (for example, faulting a desktop's DSOs from a block device). Callers mark
/// bounded completions so watchdogs distinguish that work from a true stall.
#[inline]
pub fn note_forward_progress() {
    local_scheduler_telemetry()
        .forward_progress
        .fetch_add(1, Ordering::Relaxed);
}

/// Monotonic completed-work counter used by fatal-path watchdogs.
pub fn forward_progress_count() -> u64 {
    sum_scheduler_telemetry(|cpu| &cpu.forward_progress)
}

/// `(resched_ipis_sent, cross_core_wakes_skipped_not_halted)`.
pub fn dbg_resched_counts() -> (u64, u64) {
    (
        sum_scheduler_telemetry(|cpu| &cpu.resched_sent),
        sum_scheduler_telemetry(|cpu| &cpu.resched_skip),
    )
}

/// Test-only: force a CPU's published halted flag, so the kernel-test
/// suite can pin the cross-core wake/spawn kick protocol (`enqueue_on` →
/// `resched_remote`) without a second physical CPU. Never call outside
/// tests — the flag is owned by that CPU's idle path.
#[doc(hidden)]
pub fn __test_set_cpu_halted(cpu: usize, halted: bool) {
    if cpu < narf_lib::percpu::MAX_CPUS {
        CPU_HALTED[cpu].store(halted, Ordering::SeqCst);
    }
}

#[inline]
fn resched_remote(target_cpu: u32) {
    let me = narf_lib::percpu::current_cpu() as u32;
    if target_cpu == me || target_cpu as usize >= narf_lib::percpu::MAX_CPUS {
        return;
    }
    // Pair with the idle side's `mark_halted(true); fence; final-scan`.
    core::sync::atomic::fence(Ordering::SeqCst);
    if !CPU_HALTED[target_cpu as usize].load(Ordering::SeqCst) {
        local_scheduler_telemetry()
            .resched_skip
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    local_scheduler_telemetry()
        .resched_sent
        .fetch_add(1, Ordering::Relaxed);
    let p = RESCHED_IPI_HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` was set by `set_resched_ipi_hook` from a `fn(u32)`.
        let f: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(p) };
        f(target_cpu);
    }
}

pub(crate) struct TaskSlot {
    task: BoxedTask,
    // Per-task wake state. The slot owns one `Arc<WakeCell>`; each
    // handed-out `Waker` owns another clone, so it outlives the slot if
    // the future stashed its waker. The scheduler swaps `flag` to
    // `false` before polling; if the poll returns `Pending` and nothing
    // re-set it, the slot is skipped until a waker flips it back.
    awake: Arc<WakeCell>,
    /// Monotonic identifier stamped at spawn time so `donate_to` has
    /// a stable handle into the ready queue. `pub(crate)` so the
    /// `policy` module's `RunQueue` projection can read it.
    pub(crate) id: TaskId,
    /// Stage-3 §3.3/§3.4 per-task metadata: affinity, CPU budget, the
    /// `Cap<CpuBudget, Spend>` that gates scheduling, and the running
    /// `BudgetAccount`. `pub(crate)` so the `policy` module's
    /// `RunQueue` projection can read its `priority`/`class`/
    /// `affinity` fields.
    pub(crate) spec: TaskSpec,
    account: BudgetAccount,
    /// Optional per-process address space (Stage 4). `None` for
    /// kernel-only tasks; `Some` for a user-mode task that shares
    /// the AS with its process peers. Held as `Arc` so tasks within
    /// one process share one AS without copying.
    addr_space: Option<Arc<AddressSpace>>,
    /// Pending time-slice donation (§3.3). Set by `donate_to` so the
    /// next pop either consumes the credit (cap live) or refunds
    /// the donor (cap revoked). `None` outside an active donation.
    donation: Option<DonationClaim>,
    /// Architecture-neutral PKRS / PCID / MTE-TCF task state. `None` before
    /// first dispatch means the task inherits the executor's neutral state;
    /// every later dispatch restores the captured value before polling.
    domain_saved: Option<narf_memory::DomainSavedState>,
    /// Present only for tasks admitted through `spawn_realtime`. Its `Drop`
    /// releases per-CPU, system, and authority-domain bandwidth atomically.
    rt_reservation: Option<admission::RealtimeReservation>,
    /// RAII fork-bomb counter. `Some` for user tasks (decrements
    /// `LIVE_USER_TASKS` on the slot's final drop), `None` for kernel tasks.
    /// Held purely for its `Drop` side-effect — never read, hence the allow.
    #[allow(dead_code)]
    nproc_guard: Option<NprocGuard>,
}

/// One in-flight time-slice donation handed to a task by
/// `donate_to`. The donee carries the claim until its next
/// dispatch round; `settle_donation` then either keeps the credit
/// (cap still live) or reverts both sides (cap revoked → refund
/// donor + revert donee's credit). Stored on the donee so the
/// executor resolves revocation O(1) at pop time.
struct DonationClaim {
    donor: TaskId,
    /// Snapshot of the donor's `TaskMeta` at donation time. Passed
    /// to `DonationPolicy::on_revoke` if the donation is cancelled
    /// between donate and settle, so the policy can attribute the
    /// refund without re-walking the ready queues.
    donor_meta: crate::policy::TaskMeta,
    cycles: u64,
    cap: Cap<Task, Invoke>,
}

impl core::fmt::Debug for DonationClaim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DonationClaim")
            .field("donor", &self.donor)
            .field("cycles", &self.cycles)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for TaskSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskSlot")
            .field("id", &self.id)
            .field("awake", &self.awake.flag.load(Ordering::Relaxed))
            .field("spec", &self.spec)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// Poll one task with domain state treated as task context rather than CPU
/// context. Capture of the returned task state is the first operation after
/// `poll`; the executor state is restored before accounting, queue mutation,
/// or any other scheduler-owned data is touched.
#[inline]
fn poll_with_domain(slot: &mut TaskSlot, ctx: &mut Context<'_>) -> Poll<()> {
    let executor_domain = narf_memory::save_domain_state();
    let task_domain = slot.domain_saved.unwrap_or(executor_domain);
    narf_memory::restore_domain_state(&task_domain);

    let result = slot.task.as_mut().poll(ctx);

    let returned_task_domain = narf_memory::save_domain_state();
    narf_memory::restore_domain_state(&executor_domain);
    slot.domain_saved = Some(returned_task_domain);
    result
}

/// Per-task scheduling metadata — spec §3.3 + §3.4.
///
/// A `TaskSpec` with `budget_cap = None` behaves like a Stage-2 task:
/// always runnable, no accounting. Attaching a live
/// `Cap<CpuBudget, Spend>` makes the executor `check_live`-gate every
/// poll; revoking the cap takes the task off the scheduler in O(1) on
/// the next round.
#[derive(Copy, Clone, Debug, Default)]
pub struct TaskSpec {
    pub affinity: Affinity,
    pub budget: ResourceBudget,
    pub budget_cap: Option<Cap<CpuBudget, Spend>>,
    /// Kind of execution requested for this task. This is visible to policy,
    /// but the core retains ownership of accounting and attribution and this
    /// value grants no authority by itself.
    pub work_kind: WorkKind,
    /// Scheduling class used by the default strict-class dispatcher.
    pub class: SchedClass,
    /// Nice-style priority within `class`.
    pub priority: Priority,
    /// SMT-sibling co-scheduling preference.
    pub smt: SmtSharePolicy,
}

impl TaskSpec {
    /// Return this spec with descriptive work classification changed. The
    /// value affects policy selection only; it does not change the task's
    /// capability, domain, or accounting identity.
    pub const fn with_work_kind(mut self, work_kind: WorkKind) -> Self {
        self.work_kind = work_kind;
        self
    }

    /// Default: BSP-pinned, unthrottled, no cap gate. Pinning to
    /// the boot CPU is a load-bearing safety property today —
    /// most spawn-and-forget tasks (FB drain, USB-HID supervisor,
    /// virtio-input pump, …) were written assuming single-CPU
    /// execution and reach into shared state without locks. Until
    /// each is audited for SMP safety, the default keeps them on
    /// CPU0 even when work-stealing is enabled and APs are alive.
    /// Tasks that have been verified SMP-safe can opt into
    /// migration with `Affinity::any()` via spawn_with_spec.
    pub const fn unthrottled() -> Self {
        Self {
            affinity: Affinity::pinned(crate::affinity::CpuId::BOOT),
            budget: ResourceBudget::unthrottled(),
            budget_cap: None,
            work_kind: WorkKind::AsyncTask,
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Like `unthrottled()` but eligible to run on ANY online CPU
    /// (`Affinity::any()`) instead of BOOT-pinned. Use this ONLY for
    /// kernel-side tasks that have been audited SMP-safe: leaf tasks
    /// touching only `IrqSafeSpinLock`-guarded state, no per-CPU MMIO,
    /// and never on the serial/console/framebuffer/USB path (whose
    /// output ordering the boot-smoke / musl-demo gates assert on).
    /// A task spawned with this spec can be work-stolen onto an AP.
    /// `unthrottled()` intentionally stays BOOT-pinned — that pin is a
    /// load-bearing safety property for the un-audited spawn-and-forget
    /// tasks and for user tasks; do not collapse the two.
    pub const fn kernel_any() -> Self {
        Self {
            affinity: Affinity::any(),
            budget: ResourceBudget::unthrottled(),
            budget_cap: None,
            work_kind: WorkKind::KernelThread,
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Spec for a USER task (one carrying an address space, spawned
    /// via [`spawn_user`]). Eligible to run on any online CPU when
    /// user-task SMP is enabled ([`enable_user_task_smp`] — set at
    /// boot iff cross-CPU TLB shootdown is wired), otherwise BOOT-
    /// pinned exactly like [`unthrottled`](Self::unthrottled). Unlike
    /// `unthrottled()` (which stays pinned to protect un-audited
    /// kernel spawn-and-forget tasks), user tasks are SMP-safe to
    /// migrate: their per-in-flight state is per-CPU (`CURRENT`,
    /// `CURRENT_TASK`, `ACTIVE_USER_AS`, the executor jmpbuf) and the
    /// rest is per-task-keyed; the shared-AS TLB hazard is covered by
    /// the broadcast shootdown that gates the enable flag.
    ///
    /// Not `const`: the affinity depends on the runtime enable flag.
    pub fn user_task() -> Self {
        let affinity = if user_task_smp_enabled() {
            // Prefer APs so the RX forwarder (BSP) and request processing
            // pipeline across cores. On a two-CPU topology the placement
            // policy includes both CPUs: excluding the BSP there would put
            // every user process on the sole AP and serialize fork bursts.
            // See `user_ap_affinity`.
            user_ap_affinity()
        } else {
            Affinity::pinned(crate::affinity::CpuId::BOOT)
        };
        Self {
            affinity,
            budget: ResourceBudget::unthrottled(),
            budget_cap: None,
            work_kind: WorkKind::UserThread,
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Budgeted spec: charge every poll against `budget`, and
    /// `check_live` the cap each round.
    pub const fn budgeted(budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> Self {
        Self {
            affinity: Affinity::pinned(crate::affinity::CpuId::BOOT),
            budget,
            budget_cap: Some(cap),
            work_kind: WorkKind::AsyncTask,
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Shorthand: realtime task with an absolute cycle deadline.
    pub const fn realtime(deadline_cycles: u64) -> Self {
        Self {
            affinity: Affinity::any(),
            budget: ResourceBudget {
                share_ppm: 1_000_000,
                burst_cycles: u64::MAX,
                deadline_cycles: Some(deadline_cycles),
                policy: OverrunPolicy::Ignore,
                period: None,
            },
            budget_cap: None,
            work_kind: WorkKind::KernelThread,
            class: SchedClass::RealTime,
            priority: Priority::HIGH,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Realtime task with a strict core-enforced runtime/period reservation.
    /// The scheduling policy sees the deadline and budget snapshot, but only
    /// the executor replenishes or throttles this contract.
    pub const fn realtime_periodic(
        runtime_cycles: u64,
        period_cycles: u64,
        deadline_cycles: u64,
    ) -> Self {
        let mut spec = Self::realtime(deadline_cycles);
        let share = if period_cycles == 0 {
            0
        } else {
            let raw = ((runtime_cycles as u128) * 1_000_000u128) / (period_cycles as u128);
            if raw > 1_000_000 {
                1_000_000
            } else {
                raw as u32
            }
        };
        spec.budget.share_ppm = share;
        spec.budget.period = Some(PeriodBudget::strict(runtime_cycles, period_cycles));
        spec
    }
}

/// Call once at boot before spawning anything. Initialises every
/// per-CPU ready queue. Idempotent within a test run: re-init drops
/// any tasks left over from a prior round, which is what test setup
/// wants.
///
/// **Smoke tests using `spawn` + `run_until_empty` MUST call
/// `init()` first.** The boot-time queue carries long-lived
/// kernel async tasks (USB HID supervisor, FB drain, scheduler
/// step pump, etc.) that are parked indefinitely on
/// `sleep_cycles` / `wait_for_irq`. Without re-initialising the
/// queue, a smoke's `run_until_empty` would try to drive those
/// zombies too — round 1 polls them all (each returns Pending),
/// `ready_this_round = 0`, `local_empty = false` → executor
/// hits `halt_until_irq` and waits forever for an IRQ that
/// would only re-arm one of the zombies (typically a timer tick
/// that satisfies a sleep deadline far in the future).
pub fn init() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Double-init is a *bug*. Pre-fix this path
        // unconditionally re-built every per-CPU VecDeque, silently
        // dropping any task spawned in between (cursor pump + USB
        // HID supervisor were historic victims — both spawned
        // during Stage::Late initcalls and disappeared when
        // bare_main re-init'd before run_async_demo). Panic now so
        // the mistake surfaces at the call site instead of becoming
        // a silent kill weeks later. Tests that need a fresh queue
        // call `__reset_queues_for_test` explicitly.
        panic!("narf_scheduler::init() called twice — would wipe spawned tasks; use __reset_queues_for_test in tests");
    }
    for q in READY.iter() {
        *q.lock() = Some(VecDeque::new());
    }
    // Wire the default `ClassScheduler` into the policy slot
    // before any `run_until_empty` call dispatches. Idempotent — if a
    // smoke installed an alternative impl ahead of init, leave it.
    policy::install_default_if_unset();
    policy::notify_cpu_state(CpuId::BOOT, CpuState::Active, None);
    // Wave E: wire the default `HeadQueueDonation` so `donate_to`'s
    // policy-driven placement and cycle-ceiling lookups return the
    // pre-Wave-E hardcoded behaviour byte-for-byte. Idempotent for the
    // same reason `policy::install_default_if_unset` is.
    donation::install_default_if_unset();
    // Wave F: wire the default `NumaAwareSteal` so `try_steal_one`'s
    // policy-driven victim-ordering and per-task allow_steal checks
    // return the pre-Wave-F two-phase same-node-first behaviour
    // byte-for-byte. Idempotent for the same reason the wave D/E
    // installs are.
    steal::install_default_if_unset();
}

/// Test-only hook: clear every ready queue without re-running
/// `init()`. Hermetic isolation between verification smokes that
/// build their own task graph and need an empty queue without
/// touching the one-shot `INITIALIZED` flag in `init`.
#[doc(hidden)]
pub fn __reset_queues_for_test() {
    for q in READY.iter() {
        if let Some(d) = q.lock().as_mut() {
            d.clear();
        }
    }
    // Reclaim any nodes left on the per-CPU wake lists so tasks don't leak or
    // carry over between tests. Swapping to null then boxing each node back
    // frees it (and drops the carried `TaskSlot`).
    for head in WAKE_LIST.iter() {
        let mut cur = head.swap(core::ptr::null_mut(), Ordering::AcqRel);
        while !cur.is_null() {
            // SAFETY: nodes were `Box::into_raw`'d in `wake_list_push`; after the
            // swap we exclusively own the detached list and free each once.
            let node = unsafe { Box::from_raw(cur) };
            cur = node.next.load(Ordering::Relaxed);
        }
    }
}

/// Authoritative affinity for every live scheduler task.
///
/// A slot is absent from all ready queues while its future is being polled.
/// Keeping the mask independently makes `sched_getaffinity(2)` exact during
/// that interval and lets a concurrent setter publish an update that the slot
/// consumes at the next cooperative poll boundary.
#[derive(Copy, Clone)]
struct TaskAffinityEntry {
    id: TaskId,
    affinity: Affinity,
    realtime_pinned: bool,
}

const NEW_TASK_AFFINITY_SHARD: IrqSafeSpinLock<alloc::vec::Vec<TaskAffinityEntry>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());
static TASK_AFFINITY: [IrqSafeSpinLock<alloc::vec::Vec<TaskAffinityEntry>>;
    narf_lib::percpu::MAX_CPUS] = [NEW_TASK_AFFINITY_SHARD; narf_lib::percpu::MAX_CPUS];

#[inline]
fn task_affinity_shard(id: TaskId) -> usize {
    id.raw() as usize % narf_lib::percpu::MAX_CPUS
}

fn register_task_affinity(id: TaskId, affinity: Affinity, realtime_pinned: bool) {
    let mut entries = TASK_AFFINITY[task_affinity_shard(id)].lock();
    entries.retain(|entry| entry.id != id);
    entries.push(TaskAffinityEntry {
        id,
        affinity,
        realtime_pinned,
    });
}

fn unregister_task_affinity(id: TaskId) {
    TASK_AFFINITY[task_affinity_shard(id)]
        .lock()
        .retain(|entry| entry.id != id);
}

/// Snapshot the online CPU set used by Linux affinity syscalls and cgroups.
pub fn online_cpu_set() -> CpuSet {
    CpuSet::from_bits(narf_lib::smp::online_bitmap())
}

/// Return a live task's hard affinity mask.
pub fn task_affinity(id: TaskId) -> Option<CpuSet> {
    TASK_AFFINITY[task_affinity_shard(id)]
        .lock()
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.affinity.allowed)
}

/// Failure from [`set_task_affinity`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SetAffinityError {
    /// The requested task has already exited or never existed.
    TaskNotFound,
    /// The supplied set has no online CPU.
    NoOnlineCpu,
    /// Admitted realtime reservations remain pinned to their admission CPU.
    RealtimePinned,
}

/// Change a task's hard affinity and migrate a queued slot when necessary.
///
/// A currently-polled task observes the registry update immediately through
/// [`task_affinity`] and is re-homed when that poll returns `Pending`. This is
/// the cooperative equivalent of Linux's `__set_cpus_allowed_ptr()` boundary:
/// never move a live kernel continuation, and never dispatch the next slice
/// outside the new mask.
pub fn set_task_affinity(id: TaskId, requested: CpuSet) -> Result<(), SetAffinityError> {
    let allowed = requested.intersection(online_cpu_set());
    if allowed.is_empty() {
        return Err(SetAffinityError::NoOnlineCpu);
    }
    let affinity = Affinity {
        allowed,
        preferred: lowest_allowed_cpu(allowed),
    };
    {
        let mut entries = TASK_AFFINITY[task_affinity_shard(id)].lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) else {
            return Err(SetAffinityError::TaskNotFound);
        };
        if entry.realtime_pinned && entry.affinity != affinity {
            return Err(SetAffinityError::RealtimePinned);
        }
        entry.affinity = affinity;
    }

    // If the task is parked, update and (when its old queue is no longer
    // allowed) move it before it can dispatch again. At most one READY lock is
    // held at a time; enqueue_on acquires the destination only after removal.
    for (cpu, ready) in READY.iter().enumerate() {
        let cpu_id = CpuId(cpu as u32);
        let found = policy::with_scheduler(cpu_id, |scheduler| {
            let mut queue = ready.lock();
            let queue = queue.as_mut()?;
            let pos = queue.iter().position(|slot| slot.id == id)?;
            if allowed.contains(CpuId(cpu as u32)) {
                queue[pos].spec.affinity = affinity;
                return Some(None);
            }
            let mut slot = queue.remove(pos).expect("affinity slot disappeared");
            slot.spec.affinity = affinity;
            if let Some(scheduler) = scheduler {
                scheduler.on_task_queue_event(
                    cpu_id,
                    policy::TaskQueueEvent::Dequeued {
                        task: policy::TaskMeta::from_slot(&slot),
                        reason: policy::TaskDequeueReason::Migrated,
                    },
                );
            }
            Some(Some(slot))
        });
        let Some(moved) = found else {
            continue;
        };
        let Some(moved) = moved else {
            return Ok(());
        };
        let target = target_cpu_for_affinity(affinity, cpu);
        enqueue_on(target, moved, policy::TaskEnqueueReason::Migrated);
        return Ok(());
    }

    // The live slot is currently being polled (or is in the tiny
    // poll-return→requeue interval). Its requeue path reads TASK_AFFINITY.
    Ok(())
}

fn registered_affinity(id: TaskId) -> Option<Affinity> {
    TASK_AFFINITY[task_affinity_shard(id)]
        .lock()
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.affinity)
}

fn refresh_slot_affinity(slot: &mut TaskSlot) {
    if let Some(affinity) = registered_affinity(slot.id) {
        slot.spec.affinity = affinity;
    }
}

fn lowest_allowed_cpu(set: CpuSet) -> Option<CpuId> {
    (0..narf_lib::percpu::MAX_CPUS as u32)
        .find(|cpu| narf_lib::smp::is_online(*cpu) && set.contains(CpuId(*cpu)))
        .map(CpuId)
}

fn target_cpu_for_affinity(affinity: Affinity, fallback: usize) -> usize {
    if let Some(preferred) = affinity.preferred {
        let cpu = preferred.0 as usize;
        if cpu < narf_lib::percpu::MAX_CPUS
            && narf_lib::smp::is_online(preferred.0)
            && affinity.allowed.contains(preferred)
        {
            return cpu;
        }
    }
    if fallback < narf_lib::percpu::MAX_CPUS
        && narf_lib::smp::is_online(fallback as u32)
        && affinity.allowed.contains(CpuId(fallback as u32))
    {
        return fallback;
    }
    lowest_allowed_cpu(affinity.allowed)
        .map(|cpu| cpu.0 as usize)
        .unwrap_or(0)
}

fn requeue_cpu_for_affinity(affinity: Affinity, current: usize) -> usize {
    if current < narf_lib::percpu::MAX_CPUS
        && narf_lib::smp::is_online(current as u32)
        && affinity.allowed.contains(CpuId(current as u32))
    {
        return current;
    }
    target_cpu_for_affinity(affinity, current)
}

/// Make an infallible spawn request runnable on the current online topology.
///
/// Unlike `set_task_affinity`, the historic spawn API cannot return
/// `NoOnlineCpu`. Internal callers can nevertheless construct a stale
/// `TaskSpec` while CPUs are being hot-unplugged. Retaining an empty
/// `allowed ∩ online` set would make the new slot bounce between dispatch and
/// requeue forever, so an impossible initial mask falls back to the caller's
/// online CPU. A valid mask remains a hard constraint.
fn normalize_spawn_affinity(affinity: Affinity) -> Affinity {
    let eligible = affinity.allowed.intersection(online_cpu_set());
    if eligible.is_empty() {
        let here = narf_lib::percpu::current_cpu();
        let fallback = if here < narf_lib::percpu::MAX_CPUS && narf_lib::smp::is_online(here as u32)
        {
            CpuId(here as u32)
        } else {
            CpuId::BOOT
        };
        return Affinity::pinned(fallback);
    }
    let preferred = affinity
        .preferred
        .filter(|cpu| narf_lib::smp::is_online(cpu.0) && eligible.contains(*cpu));
    Affinity {
        allowed: affinity.allowed,
        preferred,
    }
}

fn enqueue_after_poll(cpu: usize, mut slot: TaskSlot) {
    refresh_slot_affinity(&mut slot);
    let target = requeue_cpu_for_affinity(slot.spec.affinity, cpu);
    enqueue_on(target, slot, policy::TaskEnqueueReason::Requeued);
}

fn offline_migration_target(slot: &TaskSlot, source: usize) -> Option<usize> {
    if slot.rt_reservation.is_some() {
        return None;
    }
    let preferred = slot.spec.affinity.preferred.map(|cpu| cpu.0 as usize);
    preferred
        .filter(|cpu| {
            *cpu != source
                && *cpu < narf_lib::percpu::MAX_CPUS
                && narf_lib::smp::is_online(*cpu as u32)
                && cpu_lifecycle::cpu_online(CpuId(*cpu as u32))
                && slot.spec.affinity.allowed.contains(CpuId(*cpu as u32))
        })
        .or_else(|| {
            (0..narf_lib::percpu::MAX_CPUS).find(|cpu| {
                *cpu != source
                    && narf_lib::smp::is_online(*cpu as u32)
                    && cpu_lifecycle::cpu_online(CpuId(*cpu as u32))
                    && slot.spec.affinity.allowed.contains(CpuId(*cpu as u32))
            })
        })
}

/// Drain one quiesced CPU without holding its queue lock while taking a
/// destination lock. Returns false if any queued task is pinned there.
pub(crate) fn drain_cpu_queue(cpu: CpuId) -> bool {
    let source = cpu.0 as usize;
    let Some(ready) = READY.get(source) else {
        return false;
    };
    // Fold any cross-core wakes staged for this CPU into READY first, so a task
    // a remote waker pushed onto the offlining CPU's wake list is migrated with
    // the rest rather than stranded (the CPU is quiesced and won't drain itself).
    drain_wake_list(source);
    let mut moved: alloc::vec::Vec<(usize, TaskSlot)> = alloc::vec::Vec::new();
    let drained = policy::with_scheduler(cpu, |scheduler| {
        let mut queue = ready.lock();
        let Some(queue) = queue.as_mut() else {
            return false;
        };
        let mut destinations = alloc::vec::Vec::with_capacity(queue.len());
        for slot in queue.iter() {
            let Some(target) = offline_migration_target(slot, source) else {
                return false;
            };
            destinations.push(target);
        }
        for (slot, target) in queue.drain(..).zip(destinations) {
            if let Some(scheduler) = scheduler {
                scheduler.on_task_queue_event(
                    cpu,
                    policy::TaskQueueEvent::Dequeued {
                        task: policy::TaskMeta::from_slot(&slot),
                        reason: policy::TaskDequeueReason::Migrated,
                    },
                );
            }
            moved.push((target, slot));
        }
        true
    });
    if !drained {
        return false;
    }
    for (target, slot) in moved {
        enqueue_on(target, slot, policy::TaskEnqueueReason::Migrated);
    }
    true
}

/// Pick the CPU index a task with `spec` should land on. Honours
/// `affinity.preferred` when the named CPU is online; otherwise spawns
/// on the current CPU. Falls back to CPU 0 if the current CPU is
/// somehow not online (shouldn't happen — current_cpu() returning a
/// CPU implies that CPU is executing).
fn target_cpu(spec: &TaskSpec) -> usize {
    let here = narf_lib::percpu::current_cpu();
    target_cpu_for_affinity(spec.affinity, here)
}

/// Round-robin cursor for spreading user tasks across application
/// processors (see [`user_ap_affinity`]).
static NEXT_USER_AP: AtomicU32 = AtomicU32::new(0);

/// Count of low CPUs (0..N) reserved for kernel RX-forwarder tasks, so
/// `user_ap_affinity` steers user tasks (the server workers) to the
/// REMAINING cores. Set by the virtio-net driver when it places one
/// per-queue RX forwarder per core under multi-queue. 0 = no
/// reservation (default; single-queue / nosmp), which keeps the prior
/// "workers on any AP" behaviour. Partitioning forwarders and workers
/// onto disjoint cores keeps multi-queue RX dispatch from contending the
/// workers; it's throughput-neutral until the binding bottleneck (the
/// workers don't yet scale — see `docs/redis-perf-plan.md`) is lifted,
/// but is the correct MQ core layout, so it's kept.
static RX_FORWARDER_CORES: AtomicU32 = AtomicU32::new(0);

/// Convert the online AP candidate list into a user-task affinity.
///
/// The sole-AP topology is special only in the mathematical sense: an
/// AP-only round robin has one element and therefore performs no balancing.
/// Include the BSP in that degenerate case so consecutive user-task spawns
/// alternate across both allowed CPUs. Larger topologies retain the AP-only
/// pipeline that keeps ordinary user work away from BSP housekeeping.
fn user_affinity_from_aps(mut aps: [u32; 64], mut n: usize, sequence: u32) -> Affinity {
    if n == 0 {
        return Affinity::any();
    }
    if n == 1 && aps[0] != crate::affinity::CpuId::BOOT.0 {
        aps[1] = aps[0];
        aps[0] = crate::affinity::CpuId::BOOT.0;
        n = 2;
    }
    let idx = (sequence as usize) % n;
    Affinity {
        allowed: crate::affinity::CpuSet::ALL,
        preferred: Some(crate::affinity::CpuId(aps[idx])),
    }
}

/// Reserve CPUs `0..n` for RX forwarders (see [`RX_FORWARDER_CORES`]).
/// Idempotent; the driver calls this once it knows the queue count.
pub fn reserve_rx_forwarder_cores(n: u32) {
    RX_FORWARDER_CORES.store(n, Ordering::Relaxed);
}

/// Affinity for a user task when user-task SMP is live: **`preferred`
/// biased to round-robin online application processors (or BSP+AP on
/// a two-CPU system), `allowed` left wide open** (every CPU). A soft
/// initial-placement hint, not a pin.
///
/// Rationale (redis SMP scaling — see `docs/redis-perf-plan.md`): the
/// virtio RX forwarder and the other kernel housekeeping tasks are
/// BSP-pinned. A user task spawned with `Affinity::any()` lands on the
/// spawning CPU (the BSP) and, because the forwarder wakes it into
/// `READY[bsp]` and the BSP re-polls it before an idle AP can steal it,
/// effectively stays there — so the forwarder(BSP)↔app(AP) pipeline
/// never forms across cores and the 2nd vCPU adds almost nothing.
/// Steering the *initial* placement to an AP spawns the task off the
/// BSP, where it is woken and re-enqueued, forming the pipeline —
/// measured: SMP PING p99 254→222µs, p50 69→65µs (20k samples).
///
/// `allowed` stays `CpuSet::ALL` deliberately. On a topology with only one
/// AP, initial placement also alternates over the BSP: relying on later
/// stealing left every short-lived fork/exec child serialized on the AP
/// while BSP housekeeping prevented timely steals. With two or more APs,
/// initial placement remains AP-only to keep the common forwarder(BSP) ↔
/// application(AP) pipeline.
///
/// Falls back to `Affinity::any()` if — against the
/// `user_task_smp_enabled()` precondition — no AP is online, so a task
/// is never left unrunnable. CPUs ≥ 64 aren't scanned (the round-robin
/// list is a fixed 64-wide buffer); NARF tops out well below that.
fn user_ap_affinity() -> Affinity {
    // SOFT bias, not a hard pin: `allowed` stays ALL so a user task can
    // still fall back to the BSP under load. `preferred` steers initial
    // placement over APs on larger systems and over BSP+AP on a two-CPU
    // system. A hard "APs only" mask exiled every user task to the single
    // AP on a 2-vCPU box, starving co-resident user tasks (observed:
    // net-smoke's netserve never reached `listen`) while the BSP sat
    // kernel-idle. Larger systems keep the forwarder(BSP)↔app(AP) pipeline
    // for hot servers without that degenerate-topology starvation.
    let cap = narf_lib::percpu::MAX_CPUS.min(64) as u32;
    // Skip CPUs reserved for RX forwarders so workers land on disjoint
    // cores (start at least at 1 — the BSP is never a worker target).
    let base = RX_FORWARDER_CORES.load(Ordering::Relaxed).max(1);
    let mut aps = [0u32; 64];
    let mut n = 0usize;
    for cpu in base..cap {
        if narf_lib::smp::is_online(cpu) {
            aps[n] = cpu;
            n += 1;
        }
    }
    // If the reservation left no worker cores (too few vCPUs), fall back
    // to every AP so workers are never starved of a runnable CPU.
    if n == 0 {
        for cpu in 1..cap {
            if narf_lib::smp::is_online(cpu) {
                aps[n] = cpu;
                n += 1;
            }
        }
    }
    user_affinity_from_aps(aps, n, NEXT_USER_AP.fetch_add(1, Ordering::Relaxed))
}

/// ── Cross-core wake list (Linux `ttwu_queue_wakelist` analogue) ──
///
/// One node in a CPU's lock-free wake list. Boxed and CAS-pushed by a remote
/// waker (`wake_list_push`), reclaimed by the target CPU when it folds the list
/// into its own run queue (`drain_wake_list`).
struct WakeNode {
    /// Treiber-stack link (Linux `llist_node`). Only the pushing producer (via
    /// CAS) and the single draining consumer (after an exclusive swap) touch it.
    next: AtomicPtr<WakeNode>,
    slot: TaskSlot,
    reason: policy::TaskEnqueueReason,
}

/// Per-CPU lock-free MPSC wake list (Linux `rq->wake_list` of `llist_node`s). A
/// *remote* waker CAS-pushes a task here and sends a reschedule IPI instead of
/// taking the target's `CPU_SCHEDULERS[target]` policy slot; the target folds
/// the list into its own `READY[target]` under its own slot in
/// `drain_wake_list` (Linux `sched_ttwu_pending`). Off-loading the enqueue to
/// the target keeps a herd of cross-core wakers from spinning on — and starving
/// — a queue-rich target's own dispatch of that slot lock.
static WAKE_LIST: [AtomicPtr<WakeNode>; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; narf_lib::percpu::MAX_CPUS];

/// CAS-push `slot` onto `cpu`'s wake list (Linux `llist_add`). Lock-free, so it
/// is safe from IRQ context and never masks IRQs across a remote lock — it
/// upholds the same "don't spin IRQ-off on a cross-core lock" invariant the
/// steal path documents (a spin there stalls inbound TLB-shootdown IPIs).
/// Returns `true` when the list was empty before this push, mirroring
/// `llist_add`'s "first entry" return.
fn wake_list_push(cpu: usize, slot: TaskSlot, reason: policy::TaskEnqueueReason) -> bool {
    let node = Box::into_raw(Box::new(WakeNode {
        next: AtomicPtr::new(core::ptr::null_mut()),
        slot,
        reason,
    }));
    let head = &WAKE_LIST[cpu];
    let mut cur = head.load(Ordering::Relaxed);
    loop {
        // SAFETY: `node` is our freshly-allocated, not-yet-published box; we are
        // its sole owner until the CAS below links it, so this store is a plain
        // write to memory we exclusively own.
        unsafe {
            (*node).next.store(cur, Ordering::Relaxed);
        }
        match head.compare_exchange_weak(cur, node, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return cur.is_null(),
            Err(observed) => cur = observed,
        }
    }
}

/// True when `cpu`'s wake list has at least one pending task. The idle-halt
/// Dekker final-scan consults this so a CPU never commits to HLT with a wake
/// already queued; a push that races *after* the commit is covered by the
/// reschedule IPI (`resched_remote`).
#[inline]
fn wake_list_pending(cpu: usize) -> bool {
    !WAKE_LIST[cpu].load(Ordering::Acquire).is_null()
}

/// Fold `cpu`'s wake list into `READY[cpu]` (Linux `llist_del_all` +
/// `sched_ttwu_pending`). MUST run on `cpu` itself: the whole list is claimed
/// with one exclusive swap, then each task is enqueued under this CPU's OWN
/// policy slot, running the `Enqueued` policy callback locally (the activate
/// happens on the target, as in Linux). The list is a LIFO stack; it is
/// reversed to arrival order so wakes dispatch roughly FIFO.
fn drain_wake_list(cpu: usize) {
    let head = WAKE_LIST[cpu].swap(core::ptr::null_mut(), Ordering::AcqRel);
    if head.is_null() {
        return;
    }
    // Claim + free every node exactly once; collect (slot, reason) in stack
    // (LIFO) order.
    let mut items: alloc::vec::Vec<(TaskSlot, policy::TaskEnqueueReason)> = alloc::vec::Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: every node was `Box::into_raw`'d in `wake_list_push` and is
        // reachable exactly once from the list we now exclusively own (post
        // swap). We reconstitute the box to move its fields out and free it.
        let node = unsafe { Box::from_raw(cur) };
        let WakeNode { next, slot, reason } = *node;
        cur = next.load(Ordering::Relaxed);
        items.push((slot, reason));
    }
    for (slot, reason) in items.into_iter().rev() {
        // Local enqueue: `cpu` is us, so `with_scheduler` takes only our own
        // slot lock (the dispatch path already owns the round on this CPU) and
        // attributes the Enqueued event to this CPU.
        slot.awake.cpu.store(cpu as u32, Ordering::Relaxed);
        let meta = policy::TaskMeta::from_slot(&slot);
        policy::with_scheduler(CpuId(cpu as u32), |scheduler| {
            let mut q = READY[cpu].lock();
            q.as_mut()
                .expect("scheduler: wake-list drain before init")
                .push_back(slot);
            if let Some(scheduler) = scheduler {
                scheduler.on_task_queue_event(
                    CpuId(cpu as u32),
                    policy::TaskQueueEvent::Enqueued { task: meta, reason },
                );
            }
        });
    }
}

/// Push `slot` onto `cpu`'s ready queue. Panics if `init()` hasn't run.
fn enqueue_on(cpu: usize, slot: TaskSlot, reason: policy::TaskEnqueueReason) {
    // Record the slot's home CPU so a cross-core waker knows where to
    // send the reschedule IPI. Updated again each time the slot is
    // polled (it may have been work-stolen onto a different CPU).
    slot.awake.cpu.store(cpu as u32, Ordering::Relaxed);
    let awake = slot.awake.flag.load(Ordering::Acquire);
    let me = narf_lib::percpu::current_cpu();

    // REMOTE target: off-load onto the target's lock-free wake list (Linux
    // `ttwu_queue_wakelist`) and kick it, rather than reaching across to take
    // its `CPU_SCHEDULERS[target]` policy slot. The target folds the task into
    // its run queue under its own slot in `drain_wake_list`. This is the
    // cross-core-contention fix: a queue-rich target's dispatch is no longer
    // starved of its slot by a herd of remote wakers.
    if cpu != me && cpu < narf_lib::percpu::MAX_CPUS {
        wake_list_push(cpu, slot, reason);
        // A spawn IS a wake: a freshly-enqueued runnable slot on a REMOTE CPU
        // needs a reschedule kick, or an idle-halted target only notices it at
        // its next timer tick (~10 ms spawn-to-first-poll latency for every
        // pthread_create landing on an idle AP — the round-robin
        // `user_ap_affinity` placement makes that the COMMON case for thread
        // spawns). `resched_remote` pairs with the idle side's Dekker handshake:
        // `run_until_empty`'s commit-to-halt publishes CPU_HALTED and re-scans
        // both READY and `wake_list_pending`; the push above is the "set the
        // wake" half, the fence + halted-check + IPI live in resched_remote.
        if awake {
            resched_remote(cpu as u32);
        }
        return;
    }

    // LOCAL target: we are executing on `cpu`, so it is not halted and its slot
    // is on the current dispatch path — enqueue directly. No cross-core IPI is
    // needed (`resched_remote` no-ops for the current CPU anyway).
    let meta = policy::TaskMeta::from_slot(&slot);
    policy::with_scheduler(CpuId(cpu as u32), |scheduler| {
        let mut q = READY[cpu].lock();
        q.as_mut()
            .expect("scheduler: spawn before init")
            .push_back(slot);
        if let Some(scheduler) = scheduler {
            scheduler.on_task_queue_event(
                CpuId(cpu as u32),
                policy::TaskQueueEvent::Enqueued { task: meta, reason },
            );
        }
    });
}

#[inline]
fn slot_is_dispatchable(slot: &TaskSlot, now: u64) -> bool {
    if !slot.awake.flag.load(Ordering::Acquire) {
        return false;
    }
    slot.account.view(now, &slot.spec.budget).eligibility != BudgetEligibility::Throttled
}

fn next_budget_replenishment(cpu: usize, now: u64) -> Option<u64> {
    let q = READY[cpu].lock();
    q.as_ref().and_then(|ready| {
        ready
            .iter()
            .filter(|slot| slot.awake.flag.load(Ordering::Acquire))
            .filter_map(|slot| {
                let view = slot.account.view(now, &slot.spec.budget);
                (view.eligibility == BudgetEligibility::Throttled)
                    .then_some(view.replenish_at_cycles)
                    .flatten()
            })
            .min()
    })
}

fn notify_cpu_idle(cpu: usize) {
    let now = narf_time::now_cycles();
    let state = {
        let q = READY[cpu].lock();
        let Some(ready) = q.as_ref() else {
            return;
        };
        let mut parked = 0usize;
        let mut throttled = 0usize;
        let mut borrowable = 0usize;
        let mut next_budget_replenishment = None;
        for slot in ready {
            if !slot.awake.flag.load(Ordering::Acquire) {
                parked += 1;
                continue;
            }
            let view = slot.account.view(now, &slot.spec.budget);
            match view.eligibility {
                BudgetEligibility::Eligible => {}
                BudgetEligibility::Borrowable => borrowable += 1,
                BudgetEligibility::Throttled => {
                    throttled += 1;
                    if let Some(deadline) = view.replenish_at_cycles {
                        next_budget_replenishment = Some(
                            next_budget_replenishment
                                .map(|current: u64| current.min(deadline))
                                .unwrap_or(deadline),
                        );
                    }
                }
            }
        }
        CpuIdleMeta {
            queued: ready.len(),
            parked,
            throttled,
            borrowable,
            next_budget_replenishment,
        }
    };
    policy::notify_cpu_executor_state(CpuId(cpu as u32), CpuState::Idle, Some(state));
}

#[inline]
fn notify_cpu_active(cpu: usize) {
    policy::notify_cpu_executor_state(CpuId(cpu as u32), CpuState::Active, None);
}

/// Queue a new task on the ready queue. Requires `init()` to have run.
///
/// Returns the `TaskId` stamped on the newly-created task — `donate_to`
/// and future `cancel`/`join` primitives name the task by this id.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) -> TaskId {
    spawn_with_spec(f, TaskSpec::unthrottled())
}

/// Queue a new task with a Stage-3 `TaskSpec` attached. A `None`
/// `budget_cap` makes the task always-runnable; a live cap is
/// epoch-checked on every round and the task drops when the cap is
/// revoked.
pub fn spawn_with_spec<F>(f: F, spec: TaskSpec) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut spec = spec;
    assert!(
        spec.budget.is_valid(),
        "scheduler: invalid periodic resource budget"
    );
    // A class label is policy metadata, not authority. The infallible legacy
    // spawn surface cannot prove admission, so an RT request through it is
    // safely demoted. `spawn_realtime*` is the sole admission path.
    if spec.class == SchedClass::Realtime {
        spec.class = SchedClass::Default;
    }
    spec.affinity = normalize_spawn_affinity(spec.affinity);
    let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
    let slot = TaskSlot {
        task: Box::pin(f),
        awake: Arc::new(WakeCell {
            flag: AtomicBool::new(true),
            cpu: AtomicU32::new(0),
        }),
        id,
        spec,
        addr_space: None,
        account: BudgetAccount::new(),
        donation: None,
        domain_saved: None,
        rt_reservation: None,
        nproc_guard: None,
    };
    let cpu = target_cpu(&spec);
    register_task_affinity(id, spec.affinity, false);
    enqueue_on(cpu, slot, policy::TaskEnqueueReason::Admitted);
    id
}

/// Admit and spawn a preemptible realtime kernel thread.
///
/// Realtime service requires all three of: a live CPU-budget authority, a
/// strict `PeriodBudget` with an absolute deadline, and available per-CPU,
/// system, and authority-domain bandwidth. The resulting task is pinned to
/// the CPU on which its reservation was admitted.
pub fn spawn_realtime<F>(
    f: F,
    spec: TaskSpec,
    authority: &Cap<CpuBudget, Spend>,
) -> Result<TaskId, AdmissionError>
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_realtime_with_options(f, spec, authority, StackfulOptions::default())
}

/// [`spawn_realtime`] with explicit own-stack/preemption options.
pub fn spawn_realtime_with_options<F>(
    f: F,
    mut spec: TaskSpec,
    authority: &Cap<CpuBudget, Spend>,
    opts: StackfulOptions,
) -> Result<TaskId, AdmissionError>
where
    F: Future<Output = ()> + Send + 'static,
{
    if spec.class != SchedClass::Realtime || !spec.budget.is_valid() || opts.no_preempt {
        return Err(AdmissionError::InvalidContract);
    }
    spec.affinity = normalize_spawn_affinity(spec.affinity);
    let cpu = target_cpu(&spec);
    let reservation = admission::reserve(authority, CpuId(cpu as u32), &spec.budget)?;
    spec.affinity = Affinity::pinned(reservation.cpu());
    spec.budget_cap = Some(*authority);
    spec.work_kind = WorkKind::KernelThread;
    let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
    let slot = TaskSlot {
        task: Box::pin(stackful::StackfulAdapter::with_options(f, opts)),
        awake: Arc::new(WakeCell {
            flag: AtomicBool::new(true),
            cpu: AtomicU32::new(cpu as u32),
        }),
        id,
        spec,
        addr_space: None,
        account: BudgetAccount::new(),
        donation: None,
        domain_saved: None,
        rt_reservation: Some(reservation),
        nproc_guard: None,
    };
    register_task_affinity(id, spec.affinity, true);
    enqueue_on(cpu, slot, policy::TaskEnqueueReason::Admitted);
    Ok(id)
}

/// Spawn a task that runs on its own dedicated kernel stack
/// (16 KiB default). The future's `poll` is driven via
/// `kernel_switch` so the LAPIC timer ISR can preempt it on
/// slice expiry — see `scheduler/specification/preemption.md`.
///
/// Phase 2 lossy preemption is now active: a kernel async task
/// that busy-loops inside its `poll()` body gets preempted at
/// the per-task TSC slice (default 10 ms ≈ 33 M cycles on a
/// 3.3 GHz CPU) and the executor regains control. The future
/// re-polls from its current heap state on next dispatch — its
/// progress isn't lost, only the intermediate stack frames of
/// the abandoned poll.
///
/// Migrate suspect-busy-loop kernel tasks (FB cursor pump,
/// drain task, USB HID supervisor, etc.) from `spawn()` to this
/// to immunise the executor against their wedges.
///
/// Same return + queueing semantics as `spawn()` — caller gets
/// back a TaskId. For per-task preemption tuning (slice size,
/// opt-out via `no_preempt`), use `spawn_stackful_with_options`.
pub fn spawn_stackful<F>(f: F) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_with_spec(
        stackful::StackfulAdapter::new(f),
        TaskSpec::unthrottled().with_work_kind(WorkKind::KernelThread),
    )
}

/// Options for tuning a stackful task's preemption behaviour.
#[derive(Copy, Clone, Debug)]
pub struct StackfulOptions {
    /// Per-task TSC slice in cycles. Default
    /// `stackful::DEFAULT_SLICE_CYCLES` (~10 ms on 3.3 GHz Zen2).
    pub slice_cycles: u64,
    /// When true, the trap-handler hook skips preempting this
    /// task. Use for drivers that hold hardware locks across an
    /// `.await`-free region.
    pub no_preempt: bool,
    /// Allow timer slicing when this task is interrupted in CPL3. This is
    /// independent of `no_preempt`: user tasks keep arbitrary CPL0 kernel
    /// continuations non-preemptible until the scheduler has a preempt-disable
    /// counter, while still time-slicing syscall-free userspace.
    pub user_preempt: bool,
    /// Per-task kernel stack size. Must be ≥ 4 KiB and 16-byte
    /// aligned. Default `stackful::DEFAULT_KERNEL_STACK_BYTES`
    /// (16 KiB).
    pub stack_bytes: usize,
}

impl Default for StackfulOptions {
    fn default() -> Self {
        Self {
            slice_cycles: stackful::DEFAULT_SLICE_CYCLES,
            no_preempt: false,
            user_preempt: false,
            stack_bytes: stackful::DEFAULT_KERNEL_STACK_BYTES,
        }
    }
}

/// Spawn a stackful task with explicit preemption options.
/// Wraps `spawn_stackful` but configures the per-task slice +
/// preempt opt-out + stack size before queuing.
pub fn spawn_stackful_with_options<F>(f: F, opts: StackfulOptions) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_stackful_with_spec(
        f,
        TaskSpec::unthrottled().with_work_kind(WorkKind::KernelThread),
        opts,
    )
}

/// Spawn a preemptible stackful task with explicit scheduling metadata and
/// preemption options. This is the public bridge used by realtime/kernel
/// thread front-ends: policy can inspect the spec, while stack switching and
/// domain restoration remain private to the executor.
pub fn spawn_stackful_with_spec<F>(f: F, spec: TaskSpec, opts: StackfulOptions) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut adapter = stackful::StackfulAdapter::with_options(f, opts);
    adapter.apply_options();
    spawn_with_spec(adapter, spec)
}

/// Spawn a stackful task HARD-pinned to `cpu` (otherwise default
/// preemption options). Used by the virtio-net per-queue RX forwarders
/// to spread RX dispatch across cores instead of funneling every queue
/// through the boot CPU. The task MUST be SMP-safe — touch only
/// `IrqSafeSpinLock`-guarded state — since it runs off the BSP (see
/// `TaskSpec::unthrottled`'s note on why spawn-and-forget tasks are
/// BSP-pinned by default). `cpu == 0` pins to the BSP, i.e. identical to
/// `spawn_stackful`.
pub fn spawn_stackful_pinned<F>(f: F, cpu: u32) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let spec = TaskSpec {
        affinity: Affinity::pinned(crate::affinity::CpuId(cpu)),
        work_kind: WorkKind::KernelThread,
        ..TaskSpec::unthrottled()
    };
    spawn_with_spec(stackful::StackfulAdapter::new(f), spec)
}

/// Shorthand: spawn a task with a budget cap + the default everywhere-
/// affinity.
pub fn spawn_budgeted<F>(f: F, budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_with_spec(f, TaskSpec::budgeted(budget, cap))
}

/// Reserve a fresh `TaskId` without enqueuing anything. User-task
/// spawns allocate the id FIRST so the caller can register the task's
/// refcounted `Task` object (keyed by this id) BEFORE the task becomes
/// runnable — otherwise the task could run, syscall, and look itself up
/// in the registry before the spawner finished registering it.
pub fn alloc_task_id() -> TaskId {
    TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed))
}

/// Hook invoked whenever the executor DROPS a task slot through a path
/// that is not the task's own `Poll::Ready` completion — budget-cap
/// revocation and `ChargeOutcome::Kill`. Without this, an abnormally
/// dropped USER task would bypass the entire exit teardown (task
/// registry, exit observers, fd tables, SIGCHLD), leaving its
/// refcounted `Task` stranded as RUNNING forever. Installed once at
/// boot by `narf_userspace`.
static SLOT_REAP_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_slot_reap_hook(f: fn(TaskId)) {
    SLOT_REAP_HOOK.store(f as usize, Ordering::Release);
}

fn notify_slot_reaped(id: TaskId) {
    let p = SLOT_REAP_HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` was stored by `set_slot_reap_hook` from a real
        // `fn(TaskId)`; fn pointers are 'static.
        let f: fn(TaskId) = unsafe { core::mem::transmute::<usize, fn(TaskId)>(p) };
        f(id);
    }
}

/// Spawn a user-mode task carrying its own address space. Every
/// poll of the task's future is preceded by `addr_space.activate()`,
/// which on x86_64 issues a `MOV CR3` (with the right `compiler_fence`
/// discipline) and on aarch64 issues the architected
/// `MSR TTBR0_EL1 + DSB + TLBI VMALLE1 + DSB + ISB` sequence. Both
/// paths are live; the only `NotImplemented` returns now come from
/// arches outside the {x86_64, aarch64} matrix (they log + proceed).
///
/// `id` MUST come from [`alloc_task_id`]; the caller registers its
/// task object under that id before calling this, so the task is
/// resolvable from its very first instruction.
pub fn spawn_user<F>(id: TaskId, f: F, spec: TaskSpec, addr_space: Arc<AddressSpace>) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut spec = spec;
    assert!(
        spec.budget.is_valid(),
        "scheduler: invalid periodic resource budget"
    );
    spec.work_kind = WorkKind::UserThread;
    if spec.class == SchedClass::Realtime {
        spec.class = SchedClass::Default;
    }
    spec.affinity = normalize_spawn_affinity(spec.affinity);
    // Run user tasks on their OWN kernel stack via the stackful
    // adapter. The cooperative executor polls a slot ON THE EXECUTOR STACK; a
    // *plain* UserTaskFuture would therefore run `enter_user_mode_resume` —
    // whose synthetic iretq frame pushes the user CS/SS selectors — onto the
    // shared executor stack, where a stale pushed selector can survive at a
    // slot a later executor `ret` pops (→ #UD jumping to a selector value).
    // Giving the user task its own stack confines those pushes. User tasks
    // remain timer-preemptible ONLY at CPL3: the own-stack path
    // (`try_preempt_user`) preserves the complete trap continuation and FPU
    // state, so a syscall-free loop yields its CPU. Arbitrary CPL0 preemption
    // stays disabled until NARF has Linux-style preempt-disable accounting;
    // otherwise a suspended syscall can strand a lock needed by every sibling
    // in its shared address space. Both supported architectures use the same
    // executor-private continuation model.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let task: BoxedTask = Box::pin(stackful::StackfulAdapter::with_options(
        f,
        crate::StackfulOptions {
            no_preempt: true,
            user_preempt: true,
            ..Default::default()
        },
    ));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let task: BoxedTask = Box::pin(f);
    let slot = TaskSlot {
        task,
        awake: Arc::new(WakeCell {
            flag: AtomicBool::new(true),
            cpu: AtomicU32::new(0),
        }),
        id,
        spec,
        addr_space: Some(addr_space),
        account: BudgetAccount::new(),
        donation: None,
        domain_saved: None,
        rt_reservation: None,
        nproc_guard: Some(NprocGuard::new()),
    };
    let cpu = target_cpu(&spec);
    register_task_affinity(id, spec.affinity, false);
    enqueue_on(cpu, slot, policy::TaskEnqueueReason::Admitted);
    id
}

/// Look up the address space attached to `id`, if any. The returned
/// `Arc` keeps the AS alive even if the task drops immediately —
/// callers holding it observe a consistent snapshot.
///
/// Searches every per-CPU queue. The lock on each CPU's queue is held
/// for the duration of its scan; no two CPUs' queues are held at once.
pub fn address_space_of(id: TaskId) -> Option<Arc<AddressSpace>> {
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            if let Some(slot) = dq.iter().find(|s| s.id == id) {
                return slot.addr_space.clone();
            }
        }
    }
    None
}

/// Snapshot of every task currently sitting on a per-CPU ready
/// queue. Used by /proc to enumerate `[pid]` subdirectories and
/// by debug surfaces (`ps`-style introspection).
///
/// Intentionally returns owned Vec rather than an iterator: the
/// per-CPU lock is dropped before any caller code runs, so the
/// snapshot can become stale immediately. Stale-but-consistent is
/// the right semantic for /proc — Linux reports the same shape.
pub fn all_task_ids() -> alloc::vec::Vec<TaskId> {
    let mut out = alloc::vec::Vec::new();
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            for slot in dq.iter() {
                out.push(slot.id);
            }
        }
    }
    out
}

/// Snapshot every distinct live user address space, including tasks currently
/// being polled and therefore temporarily absent from the ready queues.
pub fn all_address_spaces() -> alloc::vec::Vec<Arc<AddressSpace>> {
    let mut out: alloc::vec::Vec<Arc<AddressSpace>> = alloc::vec::Vec::new();
    let mut push_unique = |candidate: Arc<AddressSpace>| {
        if !out.iter().any(|existing| Arc::ptr_eq(existing, &candidate)) {
            out.push(candidate);
        }
    };
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            for slot in dq.iter() {
                if let Some(ref addr_space) = slot.addr_space {
                    push_unique(addr_space.clone());
                }
            }
        }
    }
    for slot in ACTIVE_USER_AS.iter() {
        if let Some(addr_space) = slot.lock().clone() {
            push_unique(addr_space);
        }
    }
    out
}

/// Replace the address space attached to `id`. Returns the
/// previous Arc so the caller can decide what to do with it
/// (e.g. drop immediately to free the old AS's frames + page-
/// table pages, or hold it briefly to continue running on the
/// old AS until the trap-return swap takes effect).
///
/// Used by `execve` to swap the current task's AS to the freshly-
/// loaded program AS without re-spawning the task — the task id,
/// its place in the ready queue, and any in-flight syscall
/// bookkeeping (fd table, brk, sigaction handlers) all stay
/// keyed to the same id.
///
/// Returns None if no slot with that id is on any ready queue.
pub fn replace_address_space(id: TaskId, new_arc: Arc<AddressSpace>) -> Option<Arc<AddressSpace>> {
    // Wave-49fu: when execve fires from inside a user task's poll
    // body (the normal case), the slot has been popped from the
    // ready queue and lives on the executor's stack — the queue
    // scan below won't find it. Two updates are needed for the
    // mismatch-free outcome:
    //
    //   1. ACTIVE_USER_AS — the trap path / sys_* handlers read
    //      this immediately for any further #PF / mmap / brk in the
    //      same poll round (e.g. demand-paging the new image's
    //      stack writes during the bytes-walk of init_sysv_stack).
    //   2. PENDING_SLOT_AS map — the slot will be pushed back to
    //      the queue on Poll::Pending; on the NEXT round the
    //      scheduler must publish the NEW AS, not the slot's stale
    //      addr_space field. The map is checked after the slot is
    //      popped; the override takes precedence over the slot's
    //      own field.
    let id_now = current_task_slot().load(Ordering::Acquire);
    if id_now == id.raw() {
        {
            let mut g = active_user_as_slot().lock();
            let _ = g.take();
            *g = Some(new_arc.clone());
        }
        let mut p = PENDING_SLOT_AS[task_affinity_shard(id)].lock();
        let prev = p
            .iter()
            .find(|(k, _)| *k == id.raw())
            .map(|(_, v)| v.clone());
        p.retain(|(k, _)| *k != id.raw());
        p.push((id.raw(), new_arc));
        return prev;
    }
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(slot) = dq.iter_mut().find(|s| s.id == id) {
                let prev = slot.addr_space.take();
                slot.addr_space = Some(new_arc);
                return prev;
            }
        }
    }
    None
}

/// Wave-49fu: pending slot AS updates queued by `replace_address_
/// space` when the target slot is the currently-polling task. The
/// scheduler's per-poll prelude drains this on pop and applies the
/// override to the slot's `addr_space` before activate. Vec instead
/// of BTreeMap to avoid an alloc-only dependency on `alloc::collections`
/// for one-or-two-entry workloads. Wave-49+ may swap this to a
/// `BTreeMap` if the post-fork burst pattern needs it.
type PendingAddressSpaces = alloc::vec::Vec<(u64, Arc<AddressSpace>)>;
type PendingAddressSpaceShard = IrqSafeSpinLock<PendingAddressSpaces>;
const NEW_PENDING_SLOT_AS_SHARD: PendingAddressSpaceShard =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());
static PENDING_SLOT_AS: [PendingAddressSpaceShard; narf_lib::percpu::MAX_CPUS] =
    [NEW_PENDING_SLOT_AS_SHARD; narf_lib::percpu::MAX_CPUS];

/// Drain `PENDING_SLOT_AS` for the given task id, returning the
/// pending AS if any. Called by `poll_one_round` after popping a
/// slot — the caller assigns the override into `slot.addr_space`
/// so the activate + ACTIVE_USER_AS publication see the new AS.
fn take_pending_slot_as(id: TaskId) -> Option<Arc<AddressSpace>> {
    let mut p = PENDING_SLOT_AS[task_affinity_shard(id)].lock();
    let pos = p.iter().position(|(k, _)| *k == id.raw())?;
    let (_, v) = p.swap_remove(pos);
    Some(v)
}

/// Errors `donate_to` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DonateError {
    /// Caller's donation authority was revoked.
    AuthorityRevoked,
    /// No task with the named id is currently on the ready queue.
    /// Target may have completed or never existed.
    TargetNotFound,
    /// Scheduler is not initialised.
    NotReady,
    /// The installed donation policy returned
    /// `EnqueueDonee::Refuse`. The donor's budget has been
    /// restored; the donee is unchanged.
    PolicyRefused,
}

/// Pending donor-side debit table for donations whose donor is
/// off-queue (currently being polled). Each entry is `(donor,
/// cycles)`; the executor drains matching entries when the donor's
/// slot is re-enqueued and applies them via `add_debit`.
///
/// 16 slots covers the realistic in-flight donation graph; an
/// overflow panics so the misuse surfaces at the call site.
const MAX_PENDING_DONATIONS: usize = 16;
const NEW_PENDING_DONOR_SHARD: IrqSafeSpinLock<[(TaskId, u64); MAX_PENDING_DONATIONS]> =
    IrqSafeSpinLock::new([(TaskId::NONE, 0); MAX_PENDING_DONATIONS]);
static PENDING_DONOR_DEBITS: [IrqSafeSpinLock<[(TaskId, u64); MAX_PENDING_DONATIONS]>;
    narf_lib::percpu::MAX_CPUS] = [NEW_PENDING_DONOR_SHARD; narf_lib::percpu::MAX_CPUS];

#[inline]
fn donor_shard(donor: TaskId) -> usize {
    donor.raw() as usize % narf_lib::percpu::MAX_CPUS
}

fn stage_donor_debit(donor: TaskId, cycles: u64) {
    let mut t = PENDING_DONOR_DEBITS[donor_shard(donor)].lock();
    for slot in t.iter_mut() {
        if slot.0 == TaskId::NONE {
            *slot = (donor, cycles);
            return;
        }
    }
    panic!("donate_to: pending-debit table full");
}

fn drain_donor_debit(donor: TaskId) -> u64 {
    if donor == TaskId::NONE {
        return 0;
    }
    let mut t = PENDING_DONOR_DEBITS[donor_shard(donor)].lock();
    let mut total = 0u64;
    for slot in t.iter_mut() {
        if slot.0 == donor {
            total = total.saturating_add(slot.1);
            *slot = (TaskId::NONE, 0);
        }
    }
    total
}

fn cancel_donor_debit(donor: TaskId, cycles: u64) {
    let mut t = PENDING_DONOR_DEBITS[donor_shard(donor)].lock();
    for slot in t.iter_mut() {
        if slot.0 == donor {
            let new = slot.1.saturating_sub(cycles);
            if new == 0 {
                *slot = (TaskId::NONE, 0);
            } else {
                slot.1 = new;
            }
            return;
        }
    }
}

fn refund_donor(donor: TaskId, cycles: u64) {
    if cycles == 0 || donor == TaskId::NONE {
        return;
    }
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(s) = dq.iter_mut().find(|s| s.id == donor) {
                s.account.revert_debit(cycles);
                return;
            }
        }
    }
    cancel_donor_debit(donor, cycles);
}

#[doc(hidden)]
pub fn __reset_donations_for_test() {
    for shard in &PENDING_DONOR_DEBITS {
        *shard.lock() = [(TaskId::NONE, 0); MAX_PENDING_DONATIONS];
    }
}

/// Direct time-slice donation fast path (spec §3.3).
///
/// On success the scheduler:
/// 1. Deducts the donor's remaining burst quantum (capped at
///    `MAX_DONATION_CYCLES` so an unthrottled donor can't transfer
///    `u64::MAX`) from the donor's `BudgetAccount`. If the donor
///    is currently being polled (off-queue), the debit is staged
///    in `PENDING_DONOR_DEBITS` and applied at the donor's next
///    `push_back`.
/// 2. Credits the same cycle count to the target via
///    `BudgetAccount::add_credit`, extending its effective
///    quantum.
/// 3. Stamps a `Donation` claim on the target's slot.
/// 4. Forces the donee awake and moves the slot to the head of
///    its ready queue so the next dispatch round polls it first
///    (ahead of normal FIFO order).
///
/// Revocation: if `cap.revoke()` is called before the donee
/// consumes the donation, the executor's `settle_donation` at
/// the donee's next pop calls `account.revert_credit` on the
/// donee and `refund_donor` on the donor (refunds via
/// `revert_debit` if findable, otherwise cancels the pending
/// debit). The donee continues without the boost.
pub fn donate_to(target: TaskId, cap: &Cap<Task, Invoke>) -> Result<(), DonateError> {
    cap.check_live()
        .map_err(|_| DonateError::AuthorityRevoked)?;

    let donor_id = current_task_id();
    let mut any_initialised = false;

    for q in READY.iter() {
        let mut g = q.lock();
        let ready = match g.as_mut() {
            Some(r) => r,
            None => continue,
        };
        any_initialised = true;
        if let Some(pos) = ready.iter().position(|s| s.id == target) {
            // Build a donor-meta snapshot. If the donor is on the
            // same queue, lift its real `TaskMeta`; if not, synthesise
            // a placeholder carrying just the donor id so the policy
            // can still log/decide. Either way `donor_meta` is what
            // the policy sees for both `cycle_ceiling` and
            // `enqueue_donee`.
            let (donor_meta, donor_on_queue) = if donor_id != TaskId::NONE {
                if let Some(d) = ready.iter().find(|s| s.id == donor_id) {
                    (
                        crate::policy::TaskMeta {
                            id: d.id,
                            work_kind: d.spec.work_kind,
                            priority: d.spec.priority,
                            class: d.spec.class,
                            deadline_cycles: d.spec.budget.deadline_cycles,
                            budget: d.spec.budget,
                            account: d.account,
                            budget_state: d.account.view(narf_time::now_cycles(), &d.spec.budget),
                            runnable: d.awake.flag.load(Ordering::Acquire),
                            affinity: d.spec.affinity,
                            addr_space: d.addr_space.is_some(),
                        },
                        true,
                    )
                } else {
                    (
                        crate::policy::TaskMeta {
                            id: donor_id,
                            work_kind: crate::priority::WorkKind::AsyncTask,
                            priority: crate::priority::Priority::NORMAL,
                            class: crate::priority::SchedClass::Normal,
                            deadline_cycles: None,
                            budget: crate::budget::ResourceBudget::unthrottled(),
                            account: crate::budget::BudgetAccount::new(),
                            budget_state: crate::budget::BudgetAccount::new().view(
                                narf_time::now_cycles(),
                                &crate::budget::ResourceBudget::unthrottled(),
                            ),
                            runnable: false,
                            affinity: crate::affinity::Affinity::any(),
                            addr_space: false,
                        },
                        false,
                    )
                }
            } else {
                (
                    crate::policy::TaskMeta {
                        id: TaskId::NONE,
                        work_kind: crate::priority::WorkKind::AsyncTask,
                        priority: crate::priority::Priority::NORMAL,
                        class: crate::priority::SchedClass::Normal,
                        deadline_cycles: None,
                        budget: crate::budget::ResourceBudget::unthrottled(),
                        account: crate::budget::BudgetAccount::new(),
                        budget_state: crate::budget::BudgetAccount::new().view(
                            narf_time::now_cycles(),
                            &crate::budget::ResourceBudget::unthrottled(),
                        ),
                        runnable: false,
                        affinity: crate::affinity::Affinity::any(),
                        addr_space: false,
                    },
                    false,
                )
            };

            // Consult the donation policy for placement intent and
            // cycle ceiling. The helper acquires `DONATION`, reads,
            // and drops the lock before returning so the queue lock
            // we still hold here is never nested under it.
            let donee_handle = crate::policy::TaskHandle::from_id(target);
            let (placement, ceiling) = {
                let rq = crate::policy::RunQueue::projected(ready);
                crate::donation::placement_and_ceiling(&rq, &donor_meta, donee_handle)
            };

            // Refuse short-circuit: no budget changes, no enqueue
            // mutation; donee stays where it is.
            if matches!(placement, crate::donation::EnqueueDonee::Refuse) {
                return Err(DonateError::PolicyRefused);
            }

            // Compute the actual cycles to transfer. When the donor
            // is on-queue we cap by its remaining burst quantum (the
            // pre-Wave-E behaviour); otherwise the ceiling is the
            // full policy budget (debit staged for next pop).
            let mut donor_remaining: u64 = 0;
            let mut donor_debited_inline = false;
            if donor_id != TaskId::NONE {
                if donor_on_queue {
                    if let Some(d) = ready.iter_mut().find(|s| s.id == donor_id) {
                        let rem = d
                            .spec
                            .budget
                            .burst_cycles
                            .saturating_sub(d.account.cycles_spent);
                        donor_remaining = rem.min(ceiling);
                        if donor_remaining > 0 {
                            d.account.add_debit(donor_remaining);
                            donor_debited_inline = true;
                        }
                    }
                } else {
                    donor_remaining = ceiling;
                }
            }

            let mut slot = ready.remove(pos).unwrap();
            if donor_remaining > 0 {
                slot.account.add_credit(donor_remaining);
                slot.donation = Some(DonationClaim {
                    donor: donor_id,
                    donor_meta,
                    cycles: donor_remaining,
                    cap: *cap,
                });
                if !donor_debited_inline {
                    stage_donor_debit(donor_id, donor_remaining);
                }
            }
            slot.awake.flag.store(true, Ordering::Release);
            match placement {
                crate::donation::EnqueueDonee::HeadOfQueue => ready.push_front(slot),
                crate::donation::EnqueueDonee::BackOfQueue => ready.push_back(slot),
                // Refuse handled above.
                crate::donation::EnqueueDonee::Refuse => unreachable!(),
            }
            return Ok(());
        }
    }

    if !any_initialised {
        return Err(DonateError::NotReady);
    }
    Err(DonateError::TargetNotFound)
}

/// Settle the slot's pending donation claim before polling. Live
/// cap → consume the claim (credit was already applied at
/// `donate_to` time); revoked cap → refund both sides so the
/// donor and donee end up as they would have without the
/// donation.
fn settle_donation(slot: &mut TaskSlot) {
    if let Some(d) = slot.donation.take() {
        if d.cap.check_live().is_err() {
            slot.account.revert_credit(d.cycles);
            refund_donor(d.donor, d.cycles);
            // Inform the active donation policy that the donation
            // was revoked. The structural refund above is the
            // load-bearing side effect; this hook is informational
            // for policy-level accounting / telemetry. Done after
            // the structural work so an impl that re-enters
            // `current_donation_policy_name`-style observers sees
            // consistent state.
            crate::donation::notify_revoke(&d.donor_meta, d.cycles);
        }
    }
}

// ── Waker plumbing ──────────────────────────────────────────────────
//
// Each task owns an `Arc<AtomicBool>` awake flag. A `Waker` is just an
// `Arc<AtomicBool>` whose `wake`/`wake_by_ref` store `true` into the
// flag. The vtable's `clone`/`drop` operate the Arc refcount, so a
// future is free to stash its waker (as IRQ-driven drivers will want
// to) and have it outlive the original `TaskSlot` view.

const TASK_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

unsafe fn clone_raw(data: *const ()) -> RawWaker {
    // Reconstitute, clone, restore the original — net +1 refcount.
    // SAFETY: `data` was produced by `Arc::into_raw` in `make_waker`
    // or a prior `clone_raw`, and the Arc is still live.
    // SAFETY: Valid memory or trusted environment
    let arc = unsafe { Arc::<WakeCell>::from_raw(data as *const WakeCell) };
    let cloned = arc.clone();
    let _ = Arc::into_raw(arc);
    RawWaker::new(Arc::into_raw(cloned) as *const (), &TASK_VTABLE)
}

// The cooperative executor idles a CPU exactly when no task is RUNNABLE,
// matching Linux (`schedule()` picks the idle task iff `nr_running == 0`).
// "Runnable" is encoded by a task's `awake` flag: a `wake` (self-wake
// heartbeat, or a cross-task / IRQ readiness wake) stores `true` into it.
// `run_until_empty` polls every awake slot each round and, before
// committing to `halt_until_irq`, SCANS the ready queue for any slot whose
// flag is still set — i.e. a wake that landed after the slot was polled
// this round (inbound TCP data waking the epoll-parked redis task, a
// driver completion). Any such slot is runnable, so it re-polls instead of
// halting. This is what keeps off-box request/response latency event-paced
// rather than gated at the 10 ms tick. No separate external-wake flag is
// needed: the awake bit IS the runnable bit, and the scan reads it
// directly.

unsafe fn wake_raw(data: *const ()) {
    // wake-by-value: consume the Arc.
    // SAFETY: same as clone_raw; we own the refcount handed to us.
    let arc = unsafe { Arc::<WakeCell>::from_raw(data as *const WakeCell) };
    arc.flag.store(true, Ordering::Release);
    // Kick the owner's CPU if it's idle on another core (else the awake
    // bit waits until that CPU's next timer tick — the cross-core wake
    // tail). `resched_remote` no-ops for same-CPU / running targets.
    resched_remote(arc.cpu.load(Ordering::Acquire));
}

unsafe fn wake_by_ref_raw(data: *const ()) {
    let ptr = data as *const WakeCell;
    // SAFETY: caller still holds a live Waker (hence a live Arc), so
    // the WakeCell behind `data` is valid for the duration of this call.
    // SAFETY: Valid memory or trusted environment
    let cpu = unsafe {
        (*ptr).flag.store(true, Ordering::Release);
        (*ptr).cpu.load(Ordering::Acquire)
    };
    resched_remote(cpu);
}

unsafe fn drop_raw(data: *const ()) {
    // SAFETY: reconstructing consumes the refcount owned by this waker.
    unsafe {
        drop(Arc::<WakeCell>::from_raw(data as *const WakeCell));
    }
}

fn make_waker(cell: Arc<WakeCell>) -> Waker {
    let raw = Arc::into_raw(cell) as *const ();
    // SAFETY: vtable functions are matched to the `Arc<WakeCell>`
    // representation encoded in `raw`.
    // SAFETY: Valid memory or trusted environment
    unsafe { Waker::from_raw(RawWaker::new(raw, &TASK_VTABLE)) }
}

/// Run the ready queue until it's empty.
///
/// Drives the *current CPU's* per-CPU queue. Each round visits every
/// task currently on the queue at most once; each slot is polled iff
/// its awake flag is set. The flag is cleared (`swap(false)`) before
/// the poll so a waker that fires *during* the poll leaves the task
/// marked for re-poll on the next round.
///
/// After a local round produces no `Ready` tasks, the executor tries
/// to steal one task from another CPU's queue (round-robin starting
/// at `cpu+1`). If every queue is empty *and* nothing made progress,
/// halt the CPU via `arch::halt_until_irq`. An external interrupt
/// (timer or otherwise) will wake us, and the next round either makes
/// progress (a deadline met, waker fired) or we halt again. The halt
/// is kept even though wakers are now per-task because today's self-
/// waking futures (`SleepUntil`, `yield_now`) would otherwise spin
/// the CPU between clock ticks — they re-set their own awake flag
/// before returning Pending, so the "any awake?" check would always
/// pass.
///
/// Termination: returns when both this CPU's queue and every other
/// CPU's queue are empty. Workers (APs) call this in a loop with no
/// expectation of return; tests call it from BSP and rely on it
/// returning once their spawned tasks complete.
/// Drive one round of the local CPU's run-queue, polling **only
/// kernel-side tasks** (`addr_space.is_none()`), and return.
///
/// Designed to be called from inside a syscall trap — most
/// notably the `sys_sleep` busy-wait in
/// `narf_userspace::handlers::sleep_pumps` — to keep kernel async
/// work (FB drain, USB HID supervisor, the boot-time async demo,
/// future device pumps) advancing while a user task is parked.
///
/// User-mode (AS-bearing) tasks are intentionally skipped:
/// polling one of them inside a syscall handler would call
/// `enter_user_mode` from a trap context whose `iretq` frame is
/// still on the kernel stack, re-entering user code while another
/// trap is in flight — the kernel stack would corrupt and the
/// CR3 swap would race. User tasks resume normally on the
/// outermost `run_until_empty` after the syscall returns.
///
/// Each kernel task is visited at most once. The function never
/// `halt_until_irq`s. Returns the number of tasks that completed
/// this round (`Ready` returns), purely as a diagnostic.
pub fn poll_one_round() -> usize {
    let cpu = narf_lib::percpu::current_cpu();
    let cpu = if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    };

    // Fold any cross-core wakes into READY first (Linux `sched_ttwu_pending`)
    // so a remote-pushed task is visited this round.
    drain_wake_list(cpu);
    let round_len = {
        let q = READY[cpu].lock();
        match q.as_ref() {
            Some(d) => d.len(),
            None => return 0,
        }
    };
    let mut ready_this_round = 0usize;

    for _ in 0..round_len {
        // Policy publication is CPU-local on the hot path. The callback sees
        // a read-only queue projection; the core validates and detaches the
        // returned opaque handle while retaining queue ownership.
        let cpu_id = CpuId(cpu as u32);
        let Some((_handle, mut slot)) = policy::with_scheduler(cpu_id, |scheduler| {
            let mut q = READY[cpu].lock();
            q.as_mut()
                .and_then(|d| policy::pick_next_slot(scheduler, cpu_id, d))
        }) else {
            break;
        };
        refresh_slot_affinity(&mut slot);
        if !slot.spec.affinity.allowed.contains(CpuId(cpu as u32)) {
            enqueue_after_poll(cpu, slot);
            continue;
        }
        // Skip user-mode tasks — see fn-level comment. Re-push so
        // the outer run loop still sees them when this returns.
        if slot.addr_space.is_some() {
            enqueue_after_poll(cpu, slot);
            continue;
        }
        // Settle any pending donation claim before deciding to
        // drop. A revoked donation cap rolls back both sides; the
        // donee still polls (donation never happened semantics).
        settle_donation(&mut slot);
        if let Some(ref cap) = slot.spec.budget_cap {
            if cap.check_live().is_err() {
                // Abnormal drop (not the task's own Ready) — let the
                // task-lifetime layer run exit teardown for the slot.
                notify_slot_reaped(slot.id);
                continue;
            }
        }
        if slot
            .account
            .view(narf_time::now_cycles(), &slot.spec.budget)
            .eligibility
            == BudgetEligibility::Throttled
        {
            enqueue_after_poll(cpu, slot);
            continue;
        }
        if !slot.awake.flag.swap(false, Ordering::Acquire) {
            enqueue_after_poll(cpu, slot);
            continue;
        }
        // Running on this CPU now — aim future wakes' reschedule IPI here
        // (the slot may have been work-stolen since it was enqueued).
        slot.awake.cpu.store(cpu as u32, Ordering::Relaxed);
        let waker = make_waker(slot.awake.clone());
        let mut ctx = Context::from_waker(&waker);
        let start = Instant::now();
        let interrupt_start = accounting::interrupt_cycles(cpu);
        let budget_dispatch = slot.account.prepare(start.as_cycles(), &slot.spec.budget);
        publish_budget_window(cpu, start.as_cycles(), budget_dispatch, &slot.spec.budget);
        // Save + restore identity around the inner poll. We're
        // running INSIDE another task's poll (the user-mode
        // syscall handler that called sleep_pumps); a blunt
        // clear on exit would strip the outer task's
        // CURRENT_TASK + ACTIVE_USER_AS publication and break
        // its next syscall lookup. Pumps only ever poll
        // kernel-only tasks (the user-task skip above), so the
        // ACTIVE_USER_AS clear is unconditional — kernel tasks
        // don't carry their own AS publication.
        let outer_task = current_task_slot().load(Ordering::Acquire);
        let outer_as = active_user_as_slot().lock().clone();
        current_task_slot().store(slot.id.raw(), Ordering::Release);
        // No `*active_user_as_slot().lock() = ...` here because kernel
        // tasks have `addr_space.is_none()` (we filtered above).
        let poll_result = poll_with_domain(&mut slot, &mut ctx);
        let borrowed = clear_budget_window(cpu)
            || budget_dispatch.eligibility == BudgetEligibility::Borrowable;
        current_task_slot().store(outer_task, Ordering::Release);
        *active_user_as_slot().lock() = outer_as;
        let interrupt_elapsed = accounting::interrupt_cycles(cpu).saturating_sub(interrupt_start);
        let elapsed = Instant::now()
            .cycles_since(start)
            .saturating_sub(interrupt_elapsed);
        let burst_outcome = slot.account.charge(elapsed, &slot.spec.budget);
        let period_outcome = slot
            .account
            .charge_period(elapsed, &slot.spec.budget, borrowed);
        let outcome = if burst_outcome == crate::budget::ChargeOutcome::Continue {
            period_outcome
        } else {
            burst_outcome
        };
        // Apply any donor-side debit that `donate_to` staged
        // while this task was off-queue (currently polling).
        let pending = drain_donor_debit(slot.id);
        if pending > 0 {
            slot.account.add_debit(pending);
        }
        // Announce a QSBR quiescent state — UNLESS the task returned Pending
        // because it was involuntarily preempted (a preemption is an
        // arbitrary-PC context switch, not a quiescent point; its suspended
        // continuation may still hold raw RCU references). `take_preempted_return`
        // reads-and-clears the per-CPU flag `poll_to_yield` set at switch-back.
        if !stackful::take_preempted_return() {
            narf_rcu::report_quiescent();
        }
        match poll_result {
            Poll::Ready(()) => ready_this_round += 1,
            Poll::Pending => {
                // Stage-5 fair-share enforcement (§3.4).
                use crate::budget::ChargeOutcome;
                match outcome {
                    ChargeOutcome::Kill => {
                        notify_slot_reaped(slot.id);
                        continue;
                    }
                    ChargeOutcome::Demote => slot.spec.class = SchedClass::Idle,
                    ChargeOutcome::Throttle => {
                        slot.awake.flag.store(false, Ordering::Release);
                    }
                    ChargeOutcome::Continue | ChargeOutcome::PeriodExhausted => {}
                }
                enqueue_after_poll(cpu, slot);
            }
        }
    }
    ready_this_round
}

/// Idle the current CPU until there may be new work, honouring the
/// reliability of the clock-event tick.
///
/// On a dependable tick (TSC-deadline self-rearming one-shot) we HLT and
/// trust the periodic IRQ — or any device IRQ — to wake us; `next_deadline`
/// lets us skip the halt when a wheel deadline has already passed.
///
/// On the uncalibrated InitialCount periodic fallback (CPUID reports no
/// TSC-deadline, e.g. QEMU `qemu64` under TCG) a tick can be dropped or
/// arrive late. Halting there risks stranding a CPU past a parked sleeper's
/// deadline and — worse — stops the sleep-pumps from re-running, so a parked
/// interval-timer owner's SIGALRM never fires (it's the pump, not the wheel,
/// that raises it; see `frame`'s timer trap). We instead busy-wait a short
/// bounded slice so the executor loop re-evaluates and re-pumps promptly,
/// independent of IRQ delivery. Costs 100% CPU while idle on such hosts —
/// the price of an undependable tick, paid only where TSC-deadline is
/// unavailable. `narf_time::set_tick_reliable` publishes which case we're in.
/// Per-CPU accumulated idle time (ns) — the real data behind
/// /proc/stat's per-cpu idle column. Folded around `idle_wait`'s
/// actual sleep (HLT or the tick-unreliable pump slice); the adaptive
/// halt-poll spin windows (bounded ~60µs, see run_until_empty) are
/// deliberately NOT counted — they're latency polling, and at their
/// scale the distinction is noise for a 100Hz-tick consumer.
static PERCPU_IDLE_NS: [core::sync::atomic::AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Accumulated idle ns for `cpu` since boot (0 for an out-of-range id).
pub fn cpu_idle_ns(cpu: usize) -> u64 {
    PERCPU_IDLE_NS
        .get(cpu)
        .map(|a| a.load(Ordering::Relaxed))
        .unwrap_or(0)
}

fn idle_wait(next_deadline: Option<u64>) {
    let t0 = narf_time::now_cycles();
    idle_wait_inner(next_deadline);
    let dt_cycles = narf_time::now_cycles().wrapping_sub(t0);
    let ns = narf_time::cycles_to_ns(dt_cycles);
    let cpu = narf_lib::percpu::current_cpu();
    if let Some(slot) = PERCPU_IDLE_NS.get(cpu) {
        slot.fetch_add(ns, Ordering::Relaxed);
    }
}

#[inline]
fn idle_wait_inner(next_deadline: Option<u64>) {
    if narf_time::tick_reliable() {
        if let Some(deadline) = next_deadline {
            if narf_time::now_cycles() >= deadline {
                return;
            }
        }
        narf_arch::halt_until_irq();
        return;
    }
    // ~1 ms re-pump cadence: fast enough that interval timers / short
    // sleeps fire on time, slow enough not to pin the loop body tighter
    // than necessary. Capped at the deadline so we never overshoot a wake.
    const IDLE_POLL_SLICE_NS: u64 = 1_000_000;
    let mut slice = narf_time::ns_to_cycles(IDLE_POLL_SLICE_NS);
    if let Some(deadline) = next_deadline {
        let now = narf_time::now_cycles();
        if now >= deadline {
            return;
        }
        slice = slice.min(deadline - now);
    }
    narf_time::busy_wait_cycles(slice);
}

/// Mark a between-polls CPU inactive before the scheduler's internal
/// parked-queue halt.
///
/// `run_until_empty` may retain sleeping slots in its local queue and wait
/// here indefinitely, so it does not necessarily return to `run_forever`'s
/// outer `report_idle` call. Leaving the last active QSBR timestamp published
/// while halted makes the RCU watchdog diagnose an idle CPU as stalled.
#[inline]
fn report_parked_queue_idle() {
    narf_rcu::report_idle();
}

pub fn run_until_empty() {
    let cpu = narf_lib::percpu::current_cpu();
    let cpu = if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    };

    // Forced-pump fallback: when a runnable slot lets us skip the per-round
    // sleep_pumps on the wake→repoll fast path (below), a *perpetual*
    // self-waker would otherwise starve the pumps forever. Bound that by
    // forcing a pump if one hasn't run in ~1 ms of wall time regardless of
    // how busy the queue stays. Normal request/response idles between rounds,
    // so the all-parked branch pumps every cycle and this never trips.
    let pump_interval_cycles = narf_time::ns_to_cycles(1_000_000); // ~1 ms
    let mut last_pump_cycles = narf_time::now_cycles();
    // Adaptive halt-poll window (cycles), per the KVM `halt_poll_ns`
    // model. Grows when an idle spin catches a quick wake (a busy
    // request/response workload), shrinks toward 0 when spins miss (a
    // genuinely idle CPU), so latency-sensitive load gets the spin win
    // while a truly idle CPU still HLTs and preserves power. Persists
    // across rounds as an executor-local — no static, no layout churn.
    let mut halt_poll_cycles: u64 = 0;

    loop {
        // Logical hot-unplug publishes Draining before inspecting/migrating
        // the queue. Stop dispatching new slots so the control CPU observes a
        // stable quiescent queue; an already-running slot makes the operation
        // return Busy and restores Active.
        if policy::cpu_state(CpuId(cpu as u32)) == CpuState::Draining {
            return;
        }
        // Per-round drain of IRQ-deferred wakers. Must run every
        // round (not gated on ready_this_round == 0), because a
        // perpetually self-waking task (supervisor with
        // YieldTimeout) keeps ready > 0 and would otherwise
        // starve deferred wakes forever.
        let _ = narf_lib::deferred_wake::drain_and_wake();
        // Fold any cross-core wakes (Linux `sched_ttwu_pending`) into READY
        // before snapshotting the round so a task a remote CPU pushed onto our
        // wake list dispatches THIS round rather than waiting for the next one.
        drain_wake_list(cpu);
        // Snapshot queue length. We'll visit each task at most once per
        // round; spawns during the round land at the back and get
        // visited on the NEXT round.
        let round_len = {
            let q = READY[cpu].lock();
            q.as_ref()
                .expect("scheduler::run_until_empty before init")
                .len()
        };

        for _ in 0..round_len {
            // The pluggable policy sees only a read-only candidate view and
            // returns an opaque handle. Policy publication is CPU-local on
            // this hot path; the core validates and removes the selected slot.
            let cpu_id = crate::affinity::CpuId(cpu as u32);
            let Some((_handle, mut slot)) = policy::with_scheduler(cpu_id, |scheduler| {
                let mut q = READY[cpu].lock();
                let dq = q.as_mut().unwrap();
                policy::pick_next_slot(scheduler, cpu_id, dq)
            }) else {
                break;
            };

            // Wave-49fu: apply any deferred AS update that
            // `replace_address_space` queued while this slot was
            // off-queue (currently polling). Without this, an
            // execve-driven AS swap that fired during the prior
            // poll body only updated ACTIVE_USER_AS for the rest of
            // that round — the slot's own `addr_space` stayed at the
            // pre-execve value, and the next round's activate() +
            // ACTIVE_USER_AS publication would resurrect the stale
            // AS, mis-routing demand-paging into the wrong PML4 and
            // looping the user task on its first write to any
            // post-execve heap page.
            if let Some(new_as) = take_pending_slot_as(slot.id) {
                slot.addr_space = Some(new_as);
            }
            refresh_slot_affinity(&mut slot);
            if !slot.spec.affinity.allowed.contains(CpuId(cpu as u32)) {
                enqueue_after_poll(cpu, slot);
                continue;
            }

            // Settle any pending donation claim before deciding to
            // drop. A revoked donation cap rolls back both sides;
            // the donee still polls (donation never happened
            // semantics).
            settle_donation(&mut slot);

            // Budget cap check — a revoked Cap<CpuBudget, Spend>
            // drops the task O(1). No cap attached → skip the check.
            if let Some(ref cap) = slot.spec.budget_cap {
                if cap.check_live().is_err() {
                    // Task is off the scheduler: drop the slot. Abnormal
                    // drop — run the task-lifetime exit teardown so a user
                    // task can't bypass observers/registry cleanup.
                    notify_slot_reaped(slot.id);
                    continue;
                }
            }

            if slot
                .account
                .view(narf_time::now_cycles(), &slot.spec.budget)
                .eligibility
                == BudgetEligibility::Throttled
            {
                enqueue_after_poll(cpu, slot);
                continue;
            }

            // Skip if no waker has fired since the last poll. The slot
            // stays in the queue, waiting for an external signal.
            if !slot.awake.flag.swap(false, Ordering::Acquire) {
                enqueue_after_poll(cpu, slot);
                continue;
            }
            // This is the first point at which idle has become execution:
            // merely receiving an IRQ or running maintenance does not make a
            // CPU active from a scheduling-policy perspective.
            notify_cpu_active(cpu);
            // Running on this CPU now — aim future wakes' reschedule IPI
            // here (the slot may have been work-stolen since enqueue).
            slot.awake.cpu.store(cpu as u32, Ordering::Relaxed);

            // Save the kernel per-AS register before activating
            // the user AS so we can swap back after `poll()`
            // returns. Without this, the next kernel task to be
            // polled runs with the stale user mapping register
            // active — any low-half access (FB phys, identity-
            // mapped MMIO, beacon paint) page-faults on x86_64.
            //
            // x86_64: the single CR3 holds both halves; leaving
            // it on the user AS is the actual bug we hit on Zen2
            // (init's user AS lacked the FB phys low-half map,
            // every subsequent kernel task faulted silently).
            //
            // aarch64: split TTBR0/TTBR1. Kernel always resolves
            // via TTBR1, so kernel tasks following a user task
            // are fine even without this restore. But two user
            // tasks back-to-back would inherit the previous one's
            // TTBR0 until their own activate() runs — same
            // save/restore shape prevents the user-vs-user leak
            // pre-emptively.
            #[cfg(target_arch = "x86_64")]
            let saved_cr3: u64 = if slot.addr_space.is_some() {
                let raw: u64;
                // SAFETY: Reading CR3 is an unprivileged-of-side-effects
                // ring-0 instruction with no memory operand; `nomem`/`nostack`
                // accurately describe it and `raw` receives the value.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    core::arch::asm!(
                        "mov {0}, cr3",
                        out(reg) raw,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                raw
            } else {
                0
            };
            #[cfg(target_arch = "aarch64")]
            let saved_ttbr0: u64 = if slot.addr_space.is_some() {
                let raw: u64;
                // SAFETY: `mrs ttbr0_el1` reads the EL1 translation-table
                // base register; the scheduler runs at EL1 where this read
                // is unconditionally permitted. It has no memory operand,
                // so `nomem`/`nostack`/`preserves_flags` hold, and `raw`
                // receives the register value.
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                // SAFETY: EL1 system-register asm; operands as documented above.
                unsafe {
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        out(reg) raw,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                raw
            } else {
                0
            };

            // If the task owns an address space, activate it before
            // polling so user-mode accesses land in the right low-half
            // mappings. Live on x86_64 (CR3 swap) and aarch64 (TTBR0
            // swap). The error path remains so kernel-only tasks on
            // unsupported arches keep running unchanged.
            if let Some(ref a) = slot.addr_space {
                let _ = a.activate();
            }

            let waker = make_waker(slot.awake.clone());
            let mut ctx = Context::from_waker(&waker);
            let start = Instant::now();
            let interrupt_start = accounting::interrupt_cycles(cpu);
            let budget_dispatch = slot.account.prepare(start.as_cycles(), &slot.spec.budget);
            publish_budget_window(cpu, start.as_cycles(), budget_dispatch, &slot.spec.budget);
            // Publish this slot's id + AS as the currently-polling
            // task so syscall handlers + introspection can identify
            // the caller and resolve its mappings. Cleared after the
            // poll so async code that defers via `.await` doesn't
            // leak identity across yield points (the next round's
            // task will re-publish). The AS publication makes
            // `current_address_space()` work during the poll body —
            // by the time we'd otherwise look the slot up via
            // `address_space_of(id)` it's already been popped from
            // the queue and thus invisible to that scan.
            current_task_slot().store(slot.id.raw(), Ordering::Release);
            *active_user_as_slot().lock() = slot.addr_space.clone();
            let poll_result = poll_with_domain(&mut slot, &mut ctx);
            let borrowed = clear_budget_window(cpu)
                || budget_dispatch.eligibility == BudgetEligibility::Borrowable;
            current_task_slot().store(0, Ordering::Release);
            *active_user_as_slot().lock() = None;
            // Restore kernel per-AS register — see save comment
            // above. Without this, every kernel task polled after
            // a user task runs with stale user-AS CR3 (x86_64)
            // and faults on any low-half access; on aarch64 two
            // back-to-back user tasks would inherit each other's
            // TTBR0 until their own activate() runs.
            #[cfg(target_arch = "x86_64")]
            if saved_cr3 != 0 {
                // SAFETY: `saved_cr3` was just read from CR3 in
                // kernel context above; writing it back is
                // identity-safe.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {0}",
                        in(reg) saved_cr3,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                // The plain kernel-root CR3 restore flushes PCID 0 on this
                // CPU. Clear residency only after that flush, so a concurrent
                // shared-AS mutation can never omit a CPU retaining a stale
                // user translation.
                narf_memory::tlb_shootdown::clear_active_as(cpu as u32, 0);
            }
            #[cfg(target_arch = "aarch64")]
            if saved_ttbr0 != 0 {
                // SAFETY: `saved_ttbr0` was just read from
                // TTBR0_EL1 in kernel context above. Process ASIDs are unique
                // for the AddressSpace lifetime and are invalidated before
                // reuse, so restoring the saved `(root, ASID)` context needs
                // only the architected DSB + MSR + ISB sequence. Flushing here
                // would discard the translations that ASIDs exist to retain.
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                // SAFETY: EL1 TLBI/ASID asm; operands as documented above.
                unsafe {
                    core::arch::asm!(
                        "dsb ish",
                        "msr ttbr0_el1, {0}",
                        "isb",
                        in(reg) saved_ttbr0,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
            let interrupt_elapsed =
                accounting::interrupt_cycles(cpu).saturating_sub(interrupt_start);
            let elapsed = Instant::now()
                .cycles_since(start)
                .saturating_sub(interrupt_elapsed);
            let burst_outcome = slot.account.charge(elapsed, &slot.spec.budget);
            let period_outcome = slot
                .account
                .charge_period(elapsed, &slot.spec.budget, borrowed);
            let outcome = if burst_outcome == crate::budget::ChargeOutcome::Continue {
                period_outcome
            } else {
                burst_outcome
            };

            // Apply any donor-side debit that `donate_to` staged
            // while this task was off-queue (currently polling).
            let pending = drain_donor_debit(slot.id);
            if pending > 0 {
                slot.account.add_debit(pending);
            }

            // Announce a QSBR quiescent state: the task has yielded
            // back to the executor and holds no RCU read-guards across
            // the poll boundary (per rcu/ §3.7, read-guards may not
            // span awaits). Every cooperative poll return is therefore
            // a grace-period tick for this CPU — but a task that
            // returned Pending because it was involuntarily PREEMPTED
            // is NOT at a quiescent point (its suspended continuation,
            // saved in task.ctx and re-polled later, may still hold raw
            // RCU references that never went through pin()). Suppress
            // the announcement on a preemption return.
            if !stackful::take_preempted_return() {
                narf_rcu::report_quiescent();
            }

            match poll_result {
                Poll::Ready(()) => { /* completed — drop slot */ }
                Poll::Pending => {
                    // Stage-5 fair-share enforcement (§3.4): act on
                    // the `BudgetAccount::charge` outcome before
                    // re-enqueue.
                    use crate::budget::ChargeOutcome;
                    match outcome {
                        ChargeOutcome::Kill => {
                            // Drop the slot. `overruns` already
                            // ticked; no refund. Abnormal drop — run
                            // the task-lifetime exit teardown.
                            notify_slot_reaped(slot.id);
                            continue;
                        }
                        ChargeOutcome::Demote => {
                            // Hot cutover: mutate the slot's class
                            // to Idle so it only polls when no
                            // Default/Interactive/Realtime peer is runnable.
                            slot.spec.class = SchedClass::Idle;
                        }
                        ChargeOutcome::Throttle => {
                            // Clear awake so the next round skips
                            // this slot; only an external wake
                            // (timer, IRQ, peer-wake) revives it.
                            slot.awake.flag.store(false, Ordering::Release);
                            enqueue_after_poll(cpu, slot);
                            continue;
                        }
                        ChargeOutcome::Continue | ChargeOutcome::PeriodExhausted => {}
                    }
                    // A self-wake during the poll (`yield_now`, the
                    // SleepUntil busy-poll fallback) leaves `slot.awake`
                    // set; the pre-halt runnable scan below sees it and
                    // re-polls, so a self-waking future keeps making
                    // progress (and an idle CPU still halts once nothing
                    // is awake) without a separate progress counter.
                    enqueue_after_poll(cpu, slot);
                }
            }
        }

        // RCU maintenance: if this CPU holds deferred reclamations (e.g. a
        // retired `Box<KernelTask>` from a completed slot's drop), publish
        // the next grace-period epoch so the per-CPU quiescent reports above
        // can actually release them. Near-free when nothing is pending.
        narf_rcu::advance_epoch_if_pending();

        // Local queue done for this round. If empty, try to steal one
        // task from another CPU's queue; if that fails, we have
        // nothing to do — return so the caller decides whether to
        // park (worker APs via `run_forever`) or proceed (BSP-side
        // test callers).
        let now = narf_time::now_cycles();
        let (local_empty, local_dispatchable) = {
            let q = READY[cpu].lock();
            q.as_ref()
                .map(|d| {
                    (
                        d.is_empty(),
                        d.iter().any(|slot| slot_is_dispatchable(slot, now)),
                    )
                })
                .unwrap_or((true, false))
        };
        if !local_dispatchable {
            if try_steal_one(cpu) {
                continue;
            }
            if local_empty {
                notify_cpu_idle(cpu);
                return;
            }
        }

        // Drain any wakers that IRQ handlers stashed for deferred
        // execution — EVERY round, not just when all tasks parked.
        // The IRQ paths (dispatch::on_irq's vector-waker chain,
        // timer_pump's pump_irq → wheel wakers) can't call
        // `Waker::wake()` directly — the drop of the inner Arc can hit
        // a Sleepable slab dealloc, which the allocator's IRQ-context
        // check refuses. They push to the per-CPU deferred queue; we
        // drain + wake here, in non-IRQ context. This is the
        // load-bearing wake path for everything that depends on IRQ
        // delivery (virtio-net RX completions, xHCI completions,
        // keyboard IRQ1, HPET-driven wheel wakes).
        //
        // This MUST run every round, not only in the `ready==0`
        // branch below: a perpetually self-waking task (the FB cursor
        // pump, the diagnostic heartbeat, any `yield_now` busy-poll)
        // keeps `ready_this_round > 0` forever, so gating the drain on
        // the all-parked branch starves it. The deferred queue is a
        // bounded 64-slot stash that silently drops on overflow; left
        // undrained it fills over a few dozen IRQs and then drops
        // load-bearing wakes permanently (the "next tick re-fires"
        // recovery the queue assumes ALSO can't be queued once full).
        // That manifested as an off-box TCP stream wedging mid-flight
        // after ~25-34 round-trips: the parked virtio-net RX pump's
        // completion wake was dropped and never re-delivered, so
        // inbound frames piled up unprocessed while the host
        // retransmitted into silence. Draining unconditionally is
        // cheap when the queue is empty (one lock + scan) and bounds
        // wake latency to a single poll-round.
        //
        // Tick the sleep pumps EVERY round for the same reason — NOT only
        // in the `ready_this_round == 0` branch below. The pumps raise the
        // POSIX interval-timer SIGALRM for a parked task, drain serial
        // input to a blocked console reader, and step kernel async work.
        // Gating them on the all-parked branch lets a perpetually
        // self-waking peer (FB cursor pump, diagnostic heartbeat) keep
        // `ready_this_round > 0` forever and starve them — which manifested
        // as `itimer_smoke` hanging (the alarm never fires) once the
        // infinite park stopped busy-spinning the pumps itself. Their wakes
        // land in the deferred queue / signal wakers and are picked up by
        // the drain immediately below.
        // Halt iff NO task is runnable — Linux idles a CPU exactly when
        // nr_running == 0. Scan the ready queue for any slot whose `awake`
        // flag is set: a wake that landed after the slot was polled this
        // round (the virtio-net RX pump making a socket readable and waking
        // the epoll-parked redis task; a driver completion; a self-wake).
        // Any such slot is runnable, so re-poll instead of sleeping out the
        // next 10 ms tick — this is what keeps off-box round-trips
        // event-paced. A wake that lands AFTER this scan but before the HLT
        // is not lost: it pushes to the deferred-wake queue (drained next
        // round) and the HLT itself wakes on the delivering IRQ.
        //
        // This scan runs BEFORE sleep_pumps so a freshly-woken task is
        // re-polled WITHOUT first paying a full sleep_pumps::run() (fb drain,
        // smoltcp timer poll, serial drain, posix timers). When the FIFO
        // order put the woken task (e.g. epoll-parked redis) ahead of its
        // waker (the virtio-net forwarder) in this round, that per-round pump
        // cost was injecting ~tens-of-µs into the wake→repoll hop on roughly
        // half of off-box round-trips — a bimodal request latency. The pumps
        // still run on the all-parked branch below (every idle cycle, i.e.
        // once per request/response since the loop idles between them), plus
        // a ~1 ms forced fallback so a perpetual self-waker can't starve them.
        let runnable_now = narf_time::now_cycles();
        let any_runnable = {
            let q = READY[cpu].lock();
            q.as_ref()
                .map(|d| d.iter().any(|s| slot_is_dispatchable(s, runnable_now)))
                .unwrap_or(false)
        };
        if any_runnable {
            let now = runnable_now;
            // Drain due timer-wheel wakers EVERY round while a task is
            // runnable — the idle-path `fire_due` below only runs when nothing
            // is runnable, and the timer ISR can't fire the wheel itself (the
            // Waker drop hits a Sleepable dealloc, illegal in IRQ context). A
            // CPU-bound task keeps the executor perpetually non-idle, so an
            // expired wheel deadline would otherwise never be serviced. That
            // matters because `apic::on_timer_tick`/`next_arm_target` floors
            // the next TSC-deadline to `now + MIN_DELTA` (~4µs) whenever the
            // wheel's earliest deadline is already past — re-arming an
            // ~250 kHz timer-IRQ storm that preempts the CPU-bound task before
            // a single user instruction retires. Observed as a `stress-ng`
            // worker frozen exactly at its `alarm()` SIGALRM-handler entry
            // (zero forward progress), so its parent's `wait4` hung forever.
            // `fire_due` is cheap when nothing is due (one wheel-lock + a
            // deadline compare), so it's safe to call unthrottled here; this
            // context already drops Wakers via `drain_and_wake` below, so the
            // alloc is permitted. Servicing the entry clears the past-due
            // deadline, so the next arm reverts to a full `now + period` slice.
            let _ = narf_time::timer_wheel::fire_due(now);
            if now.wrapping_sub(last_pump_cycles) >= pump_interval_cycles {
                last_pump_cycles = now;
                sleep_pumps::run();
                let _ = narf_lib::deferred_wake::drain_and_wake();
            }
            continue;
        }
        last_pump_cycles = narf_time::now_cycles();
        notify_cpu_idle(cpu);

        {
            // All tasks parked this round. Tick the sleep pumps so the work
            // that USED to ride the per-task 1ms sleep busy-wait still makes
            // progress now that finite sleeps truly park on the timer wheel:
            // POSIX interval timers (raise SIGALRM for a sleeping task),
            // serial-input drain (push bytes → wake a blocked console
            // reader), and kernel async stepping. Their wakes land in the
            // deferred queue / signal wakers and are picked up by the
            // drain + the next round.
            sleep_pumps::run();
            // sleep_pumps may itself have stashed wakers (signal
            // wakers, freshly-due wheel slots) — drain them before
            // committing to a halt.
            let n_drained = narf_lib::deferred_wake::drain_and_wake();
            if n_drained > 0 {
                // A drained wake may have flipped a slot's
                // awake flag — continue to the top of the outer
                // loop so we re-evaluate ready_this_round on the
                // updated state instead of falling into the
                // halt/spin idle path.
                continue;
            }
            // Service the timer wheel before committing to a halt. This is
            // the ONE place a fully-idle executor reaches, and `fire_due`
            // otherwise runs only in the `any_runnable` branch above (which
            // needs a task ALREADY awake). The LAPIC TSC-deadline ISR
            // (`apic::on_timer_tick`) re-arms the timer but deliberately
            // never drops Wakers from IRQ context, so a wheel deadline whose
            // IRQ just woke this HLT — or one that already passed — is only
            // ACTUALLY fired here. Without this, a fully-parked executor
            // halts on the armed deadline, wakes on its IRQ, finds nothing
            // awake (the sleeper was never fired), and re-halts: the timer
            // wheel stalls and every wheel-backed sleeper strands (the
            // virtio-net RX forwarder's 2 ms backstop, redis epoll timeouts,
            // nanosleep). The longjmp model masked this because its user-task
            // adapters self-wake every round, keeping `any_runnable` true;
            // the own-stack model lets a parked user task genuinely clear its
            // awake flag, so the executor actually reaches this branch.
            // Non-IRQ context here, so the expired Waker's `Sleepable`
            // dealloc on drop is legal (same as the `any_runnable` fire_due).
            if narf_time::timer_wheel::fire_due(narf_time::now_cycles()) > 0 {
                continue;
            }
            // Idle path. Nothing is runnable — HLT the CPU until an
            // interrupt instead of spinning a core hot. Linux does the
            // same: an idle CPU halts and the timer tick (or any device
            // IRQ) wakes it.
            //
            // Wheel deadline pending: a sleeper is parked on the timer
            // wheel. The LAPIC TSC-deadline tick is re-armed every period
            // (`apic::on_timer_tick`) and the wheel's arm callback programs
            // a timer at the earliest deadline, so a HLT is woken within
            // (at worst) one tick; `fire_due` then fires the due waker and
            // the next round runs the task. We re-check `now < deadline`
            // first so a deadline that already passed fires immediately
            // without a needless halt.
            //
            // (History: an earlier revision TSC-busy-polled here to defend
            // against a tick source that silently dropped its IRQ — observed
            // on AMD Renoir 4700U. The TSC-deadline tick now reliably drives
            // preemption + interval timers, and a HLT also wakes on ANY
            // other device IRQ, the same assumption the wheel-empty halt
            // already makes — so we trust it and let the CPU idle.)
            // When user tasks run on APs (user-task SMP), an AP that
            // reaches idle right after parking a user task inherits the
            // IF=0 left by the pre-iretq `cli` discipline. With IF=0,
            // `halt_until_irq` only `spin_loop()`s — it never enables
            // interrupts — so the AP can't wake to service a peer's TLB
            // shootdown IPI, and a BSP spinning on its shootdown ack
            // deadlocks against it. Re-enable IRQs here so the halt
            // actually halts-and-wakes on the IPI. Gated on user-task
            // SMP: feature-off / kernel-test deliberately keep the IF=0
            // spin (their executor wakes come from synchronous code, not
            // IRQs, and a hlt there would wedge with no IRQ to wake it).
            //
            if user_task_smp_enabled() {
                // SAFETY: enabling IRQs between polls is the executor's
                // natural state; nothing here holds an IRQ-unsafe lock.
                unsafe {
                    narf_arch::enable_interrupts();
                }
                // Adaptive halt-poll (KVM `halt_poll_ns` analogue). Before
                // paying the HLT VM-exit + host-vcpu-deschedule wakeup cost,
                // spin a short bounded window re-checking for a wake. A virtio
                // RX IRQ that lands during the spin keeps the vcpu hot and is
                // serviced here in µs instead of after the next 1 ms timer tick
                // — measured to cut redis off-box PING p50 from ~300-400µs to
                // ~200µs. Spins ONLY when otherwise fully idle and bails to the
                // HLT below once the budget expires, so a truly idle system
                // still halts (Phase A power behaviour preserved). Gated on a
                // reliable tick (KVM / TSC-deadline); the InitialCount fallback
                // already busy-spins inside `idle_wait`.
                if narf_time::tick_reliable() {
                    // Window bounds: cap at 60µs (the measured PING-wake
                    // sweet spot), seed a grown window at 8µs.
                    let max_poll = narf_time::ns_to_cycles(60_000);
                    let grow_start = narf_time::ns_to_cycles(8_000);
                    let mut woke = false;
                    if halt_poll_cycles > 0 {
                        let spin_start = narf_time::now_cycles();
                        while narf_time::now_cycles().wrapping_sub(spin_start) < halt_poll_cycles {
                            // A wake arrives either as an IRQ-deferred waker or
                            // as a directly-set awake flag on a ready slot.
                            if narf_lib::deferred_wake::drain_and_wake() > 0 {
                                woke = true;
                                break;
                            }
                            let any = {
                                let now = narf_time::now_cycles();
                                let q = READY[cpu].lock();
                                q.as_ref()
                                    .map(|d| d.iter().any(|s| slot_is_dispatchable(s, now)))
                                    .unwrap_or(false)
                            };
                            if any {
                                woke = true;
                                break;
                            }
                            core::hint::spin_loop();
                        }
                    } else {
                        // Window collapsed (idle CPU): one cheap probe before
                        // committing to the spin-grow cycle, so a lone wake
                        // that already landed skips the HLT.
                        woke = narf_lib::deferred_wake::drain_and_wake() > 0;
                    }
                    if woke {
                        // Hit: grow the window (seed if collapsed, else ×2).
                        halt_poll_cycles = if halt_poll_cycles == 0 {
                            grow_start
                        } else {
                            halt_poll_cycles.saturating_mul(2).min(max_poll)
                        };
                        continue;
                    }
                    // Miss: shrink toward 0 so a genuinely idle CPU stops
                    // spinning and just HLTs.
                    halt_poll_cycles /= 2;
                }
            }
            let now = narf_time::now_cycles();
            let wheel_deadline = narf_time::timer_wheel::next_deadline_cycles();
            let budget_deadline = next_budget_replenishment(cpu, now);
            let next_deadline = match (wheel_deadline, budget_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            if let Some(deadline) = budget_deadline {
                arm_scheduler_deadline(deadline);
            }
            // We are between task polls and hold no RCU read guard. This halt
            // can be indefinite when the queue contains only parked slots, so
            // remove this CPU from the active QSBR census before publishing
            // CPU_HALTED. The next completed poll re-adopts the live epoch via
            // report_quiescent().
            report_parked_queue_idle();
            // Publish "this CPU is about to halt" so a concurrent cross-core
            // waker sends us a reschedule IPI instead of leaving the awake
            // bit to wake us at the next timer tick. Dekker ordering: store
            // HALTED=true, full fence, then RE-SCAN the ready queue. The
            // waker does the mirror: set the awake flag, full fence, load
            // HALTED. If the waker's flag-set precedes our scan we see it
            // (and skip the halt); otherwise our HALTED store precedes the
            // waker's load and it IPIs us. Either way the wake is never both
            // un-IPI'd AND unobserved.
            //
            // ── BUG FIX (intermittent permanent SMP wedge) ──
            // The Dekker handshake only guarantees the waker SENDS the IPI;
            // it does NOT by itself guarantee we don't HALT through it. With
            // IRQs ENABLED (the user-task-SMP idle state — see the
            // enable_interrupts() above the halt-poll), a reschedule IPI that
            // arrives in the window AFTER the re-scan but BEFORE the HLT is
            // serviced immediately by the (no-op) resched handler and thereby
            // CONSUMED — then the HLT waits for the *next* IRQ. There is NO
            // periodic timer on an idle AP whose timer-wheel has no armed
            // deadline (`next_deadline == None`), so that "next IRQ" may never
            // come: the AP HLTs forever while the woken task strands in
            // READY[cpu] with awake=true, and any connection that task serves
            // stalls — the ~50%-of-200-conn-runs permanent livelock.
            //
            // Fix: run the re-scan AND the HLT with IRQs MASKED, and halt via
            // the atomic `sti;hlt;cli` (`idle_halt_then_disable`, Linux
            // `safe_halt`). A resched IPI sent during the commit-to-halt
            // window now stays PENDING in the LAPIC IRR (IF=0) and is taken
            // by the `sti;hlt` pair, which wakes the HLT — no lost wakeup.
            // Only applies on a reliable tick with IRQs currently enabled
            // (i.e. the KVM / user-task-SMP path where the race exists); the
            // InitialCount-fallback / IF=0-spin cases keep the old `idle_wait`.
            let race_free_halt = narf_time::tick_reliable() && narf_arch::interrupts_enabled();
            if race_free_halt {
                // SAFETY: re-enabled below (or by the sti;hlt;cli halt).
                // Masking IRQs across the Dekker re-scan + HLT is what closes
                // the IPI-before-HLT race described above.
                unsafe {
                    narf_arch::disable_interrupts();
                }
            }
            narf_memory::tlb_shootdown::mark_idle(cpu as u32);
            CPU_HALTED[cpu].store(true, Ordering::SeqCst);
            core::sync::atomic::fence(Ordering::SeqCst);
            let woke_late = wake_list_pending(cpu) || {
                let now = narf_time::now_cycles();
                let q = READY[cpu].lock();
                q.as_ref()
                    .map(|d| d.iter().any(|s| slot_is_dispatchable(s, now)))
                    .unwrap_or(false)
            };
            if woke_late {
                CPU_HALTED[cpu].store(false, Ordering::SeqCst);
                narf_memory::tlb_shootdown::mark_busy(cpu as u32);
                if race_free_halt {
                    // SAFETY: restore the IRQ state we masked above; a wake is
                    // already pending so we loop straight back to polling.
                    unsafe {
                        narf_arch::enable_interrupts();
                    }
                }
                continue;
            }
            // Idle until a wake is plausible.
            if race_free_halt {
                // IRQs are masked here. Skip the HLT if the deadline already
                // passed; otherwise sti;hlt;cli — atomic enable+halt so a
                // resched/shootdown IPI (or the armed TSC-deadline timer, or
                // any device IRQ) wakes us, INCLUDING one that raced into the
                // commit-to-halt window above. Returns with IRQs masked.
                let deadline_passed = next_deadline
                    .map(|d| narf_time::now_cycles() >= d)
                    .unwrap_or(false);
                if !deadline_passed {
                    // LOST-WAKEUP BACKSTOP: arm a ~2 ms fallback so this AP
                    // re-scans soon even if a cross-core wake is lost and
                    // the periodic tick stalls (see `IDLE_BACKSTOP_HOOK`).
                    // The watchdog observed a runnable task stranded on a
                    // halted AP; this bounds the strand to ~2 ms. Armed with
                    // IRQs masked so it can't fire-and-be-consumed before
                    // the sti;hlt below.
                    arm_idle_backstop_ms(2);
                    // SAFETY: CPL=0, IF=0 on entry (we masked above); the
                    // arch primitive is the Linux safe_halt sti;hlt;cli.
                    unsafe {
                        narf_arch::idle_halt_then_disable();
                    }
                }
                CPU_HALTED[cpu].store(false, Ordering::SeqCst);
                narf_memory::tlb_shootdown::mark_busy(cpu as u32);
                // SAFETY: restore the IRQ state to the idle path's natural
                // enabled state (it was enabled before we masked it).
                unsafe {
                    narf_arch::enable_interrupts();
                }
            } else {
                // Unreliable-tick (InitialCount) bounded-spin or the
                // IF=0 (no user-task-SMP) spin — both handled by `idle_wait`,
                // which doesn't HLT-through-an-IPI, so the race doesn't apply.
                idle_wait(next_deadline);
                CPU_HALTED[cpu].store(false, Ordering::SeqCst);
                narf_memory::tlb_shootdown::mark_busy(cpu as u32);
            }
            if next_deadline.is_some() {
                // After the wake (or if the deadline already passed),
                // fire any due wakers in this non-IRQ context.
                let _ = narf_time::timer_wheel::fire_due(narf_time::now_cycles());
            }
        }
    }
}

/// Is there runnable work on this CPU OTHER than task `current`? Used by the
/// timer-preempt path to decide whether yielding a CPU-bound task to the
/// cooperative executor would accomplish anything — if nothing else needs the
/// CPU, the round-trip (yield -> executor round -> resume the same task) is
/// pure overhead, so the caller should just let the task keep running.
///
/// Ordered cheapest-first: two lock-free atomic checks (pending IRQ-deferred
/// wakes, an already-due timer-wheel deadline), then a `try_lock` scan of the
/// ready queue for another awake task. `try_lock` (never `lock`) so the IRQ
/// path can't spin; a momentarily-contended queue conservatively reports
/// "yes, preempt".
pub fn has_other_runnable_work(current: u64) -> bool {
    // A device/IRQ completion is waiting to wake some task.
    if narf_lib::deferred_wake::has_pending() {
        return true;
    }
    // A parked sleeper's deadline has already passed.
    if let Some(d) = narf_time::timer_wheel::next_deadline_cycles_try() {
        if narf_time::now_cycles() >= d {
            return true;
        }
    }
    // A cross-core wake is staged for this CPU (Linux `rq->wake_list`).
    let cpu = narf_lib::percpu::current_cpu();
    if wake_list_pending(cpu) {
        return true;
    }
    // Another awake task is queued and ready to run.
    let now = narf_time::now_cycles();
    match READY[cpu].try_lock() {
        Some(q) => q
            .as_ref()
            .map(|d| {
                d.iter()
                    .any(|s| s.id.raw() != current && slot_is_dispatchable(s, now))
            })
            .unwrap_or(false),
        None => true,
    }
}

/// Snapshot per-CPU ready-queue depths. Returns one entry per
/// online CPU as `(cpu_id, len)`. Diagnostic surface — the FB
/// status panel renders this so a wedged executor is visible
/// at a glance (`sched: c0=42 c1=0 c2=0 …` means BSP is hoarding
/// while APs idle).
pub fn cpu_queue_depths() -> alloc::vec::Vec<(u32, usize)> {
    let mut out = alloc::vec::Vec::new();
    for (cpu, ready) in READY.iter().enumerate().take(narf_lib::percpu::MAX_CPUS) {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let len = ready.lock().as_ref().map(|d| d.len()).unwrap_or(0);
        out.push((cpu as u32, len));
    }
    out
}

/// Count of RUNNABLE tasks across online CPUs — ready-queue slots whose
/// awake flag is set (parked sleepers stay queued but not awake). The
/// /proc/loadavg sample source: Linux's calc_load counts running +
/// uninterruptible, and awake-in-queue is NARF's equivalent. try_lock
/// like the stall watchdog — a contended queue is skipped for one
/// sample rather than deadlocking a procfs read against the executor.
pub fn runnable_task_count() -> usize {
    let mut n = 0;
    for (cpu, ready) in READY.iter().enumerate().take(narf_lib::percpu::MAX_CPUS) {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        if let Some(g) = ready.try_lock() {
            if let Some(d) = g.as_ref() {
                let now = narf_time::now_cycles();
                n += d.iter().filter(|s| slot_is_dispatchable(s, now)).count();
            }
        }
    }
    n
}

/// Stall-watchdog diagnostic for one CPU: `(ready_depth, awake_count,
/// halted, locked)`.
///
/// `halted` is the CPU's published `CPU_HALTED` flag (true ⇒ the CPU has
/// committed to / is in HLT). `locked` is true when `try_lock` on the
/// CPU's ready queue FAILED — i.e. some context holds the per-CPU queue
/// lock right now (mid-mutation, or wedged holding it). Uses `try_lock`
/// throughout so the watchdog can never itself deadlock on a wedged queue.
///
/// Decision table for a confirmed scheduler stall:
/// - `halted && awake > 0`  ⇒ LOST WAKEUP (a runnable task on a halted CPU).
/// - `!halted && awake > 0` ⇒ the CPU is spinning but not polling — a
///   data-path/lock issue keeping it off the poll, OR a busy-loop bug.
/// - `locked`               ⇒ a holder is stuck inside the queue lock.
///
/// Scheduler-side state of the slot owning `task_id`, if it is queued:
/// `(awake_flag, home_cpu, queue_len, affinity_bits, queued_cpu, allowed)`.
/// This is sampled only when the stall watchdog reports a stranded waiter;
/// collecting it requires no counters on the normal scheduling path.
pub fn dbg_slot_state(task_id: u64) -> Option<(bool, u32, usize, u64, u32, bool)> {
    for (cpu, ready) in READY.iter().enumerate() {
        if cpu != 0 && !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        // try_lock: this runs from a timer tick, and blocking on a queue
        // lock held by the very CPU under investigation would deadlock the
        // reporter.
        let Some(g) = ready.try_lock() else {
            continue;
        };
        let Some(d) = g.as_ref() else { continue };
        if let Some(slot) = d.iter().find(|s| s.id.raw() == task_id) {
            let home = slot.awake.cpu.load(Ordering::Relaxed);
            let allowed = slot.spec.affinity.allowed;
            // `run_until_empty` pops a slot, and BEFORE consuming its awake
            // flag re-queues it when its affinity excludes the CPU it is
            // queued on. If that holds, the slot bounces on this queue
            // forever with `awake` never cleared — so report whether this
            // queue's CPU is even permitted to run it.
            return Some((
                slot.awake.flag.load(Ordering::Acquire),
                home,
                d.len(),
                allowed.bits(),
                cpu as u32,
                allowed.contains(CpuId(cpu as u32)),
            ));
        }
    }
    None
}

/// Per-slot snapshot of `cpu`'s ready queue, newest-first, for the stall
/// watchdog: `(tid, awake, home_cpu, affinity_bits, allowed_here)`.
///
/// [`dbg_cpu_stall`] reports that a halted CPU has runnable work, but not
/// WHICH work or why it is not running, and the stall dump's summary counts
/// are compatible with different bugs. `allowed_here == false` directly
/// identifies an affinity bounce without maintaining per-slot counters.
///
/// Capped at [`DBG_READY_SLOTS_MAX`]: this runs from a timer trap onto a
/// synchronous serial console, where dumping an unbounded queue would itself
/// become the stall. `try_lock`, for the same reason [`dbg_slot_state`] uses
/// it — blocking on the queue lock held by the CPU under investigation would
/// deadlock the reporter.
pub fn dbg_ready_slots(cpu: usize) -> alloc::vec::Vec<(u64, bool, u32, u64, bool)> {
    let mut out = alloc::vec::Vec::new();
    if cpu >= narf_lib::percpu::MAX_CPUS {
        return out;
    }
    let Some(g) = READY[cpu].try_lock() else {
        return out;
    };
    let Some(d) = g.as_ref() else { return out };
    for slot in d.iter().take(DBG_READY_SLOTS_MAX) {
        let allowed = slot.spec.affinity.allowed;
        out.push((
            slot.id.raw(),
            slot.awake.flag.load(Ordering::Acquire),
            slot.awake.cpu.load(Ordering::Relaxed),
            allowed.bits(),
            allowed.contains(CpuId(cpu as u32)),
        ));
    }
    out
}

/// Upper bound on [`dbg_ready_slots`] output — see its note on trap context.
pub const DBG_READY_SLOTS_MAX: usize = 24;

pub fn dbg_cpu_stall(cpu: usize) -> (usize, usize, bool, bool) {
    if cpu >= narf_lib::percpu::MAX_CPUS {
        return (0, 0, false, false);
    }
    let halted = CPU_HALTED[cpu].load(Ordering::SeqCst);
    match READY[cpu].try_lock() {
        Some(g) => match g.as_ref() {
            Some(d) => {
                let awake = d
                    .iter()
                    .filter(|s| s.awake.flag.load(Ordering::Acquire))
                    .count();
                (d.len(), awake, halted, false)
            }
            None => (0, 0, halted, false),
        },
        None => (0, 0, halted, true),
    }
}

/// NUMA node ID of the executing CPU, or `None` when SRAT
/// topology wasn't published. Thin wrapper over
/// `narf_acpi::cpu_node(current_cpu())` so callers in this crate
/// (and downstream introspection) name the concept once. The
/// work-stealing search uses this to prefer same-node victims —
/// see `arch/specification/smp-topology.md` for the topology API.
pub fn local_node() -> Option<u32> {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= narf_lib::percpu::MAX_CPUS {
        return None;
    }
    narf_acpi::cpu_node(cpu as u32)
}

/// Try to steal one task from another CPU's queue. Returns `true` if
/// a slot was moved onto `cpu`'s queue.
///
/// Victim ordering and per-task eligibility are delegated to the
/// installed `steal::StealStrategy` (Wave F). The default
/// `NumaAwareSteal` reproduces the pre-Wave-F two-phase
/// same-NUMA-node-first / cross-node round-robin scan byte-for-byte;
/// alternative strategies (e.g. `RandomSteal`) can be installed under
/// a `Cap<Steal, Grant>`.
///
/// **Lock order**: snapshot the `Arc<dyn StealStrategy>` out of
/// `steal::STEAL` first, drop that lock, then walk victims. Calling
/// the strategy is allowed while the `READY[victim]` lock is held
/// (for the `allow_steal` check) because the strategy is a *cloned-
/// out* Arc — STEAL itself is not held during the queue walk, so
/// there is no STEAL → READY[victim] inversion.
///
/// No-op when `STEAL_ENABLED` is false (boot default). Callers in the
/// idle path treat a `false` return as "nothing to do, return".
fn try_steal_one(cpu: usize) -> bool {
    if !STEAL_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let strategy = match crate::steal::snapshot() {
        Some(s) => s,
        // No strategy installed (pre-`init` very early boot). The
        // idle path treats this as "no steal", same as STEAL_ENABLED
        // being false.
        None => return false,
    };

    // Build the online-minus-thief set the strategy will permute.
    let max = narf_lib::percpu::MAX_CPUS;
    let mut online: alloc::vec::Vec<crate::affinity::CpuId> = alloc::vec::Vec::with_capacity(max);
    for v in 0..max {
        if v == cpu {
            continue;
        }
        if !narf_lib::smp::is_online(v as u32) {
            continue;
        }
        online.push(crate::affinity::CpuId(v as u32));
    }

    let thief = crate::affinity::CpuId(cpu as u32);
    let victims = strategy.order_victims(thief, &online);
    for v in victims {
        if try_steal_from(v.0 as usize, cpu, strategy.as_ref()) {
            return true;
        }
    }
    false
}

/// Inner helper: try to move one strategy-permitted slot from
/// `victim`'s queue onto `cpu`'s queue. Returns `true` on success.
/// The `strategy` reference is the snapshot-out Arc from
/// `try_steal_one`; it's safe to call `allow_steal` here because the
/// STEAL slot lock is no longer held.
fn try_steal_from(victim: usize, cpu: usize, strategy: &dyn crate::steal::StealStrategy) -> bool {
    let thief = crate::affinity::CpuId(cpu as u32);
    let victim_id = crate::affinity::CpuId(victim as u32);
    // Non-blocking on BOTH the victim's policy slot and its run queue. A
    // blocking `with_scheduler(victim, ..)` here lets idle thieves pile onto a
    // queue-rich victim's `CPU_SCHEDULERS[victim]` lock and starve its own
    // dispatch of the slot (the SPIN-NOT-POLLING stall). Best-effort stealing
    // makes "skip a contended victim" correct: the slot stays for the lock
    // holder or another thief. `None` (slot contended) => this victim yields
    // nothing, same as an empty/contended queue.
    let stolen = policy::try_with_scheduler(victim_id, |scheduler| {
        // Non-blocking: a contended victim queue is skipped, never spun
        // on. Spinning here holds IRQs masked (IrqSafeSpinLock), which on
        // x86_64 stalls inbound TLB-shootdown IPIs — the sender then spins
        // to its 10M ack cap, livelocking dynamically-linked user tasks
        // under user-task-smp. Best-effort stealing makes "skip" correct:
        // the slot stays for the lock holder or another thief.
        let mut g = match READY[victim].try_lock() {
            Some(g) => g,
            None => return None,
        };
        let q = match g.as_mut() {
            Some(q) => q,
            None => return None,
        };
        // Linear scan for the first slot the strategy permits. The
        // default impl respects `affinity.allowed`; custom impls may
        // refuse on class/priority/id.
        let now = narf_time::now_cycles();
        let pos = q.iter().position(|s| {
            if !slot_is_dispatchable(s, now) {
                return false;
            }
            let meta = crate::policy::TaskMeta::from_slot(s);
            strategy.allow_steal(thief, &meta)
        });
        match pos {
            Some(p) => {
                let slot = q.remove(p);
                if let (Some(scheduler), Some(slot)) = (scheduler, slot.as_ref()) {
                    scheduler.on_task_queue_event(
                        victim_id,
                        policy::TaskQueueEvent::Dequeued {
                            task: policy::TaskMeta::from_slot(slot),
                            reason: policy::TaskDequeueReason::Migrated,
                        },
                    );
                }
                slot
            }
            None => None,
        }
    });
    // `try_with_scheduler` -> None means the victim's policy slot was contended
    // (skip it); the inner closure -> None means no dispatchable slot to steal.
    // Both collapse to "this victim yielded nothing".
    if let Some(slot) = stolen.flatten() {
        // ── BUG FIX (intermittent permanent SMP wedge) ──
        // Re-home the stolen slot to the THIEF before it lands on the
        // thief's queue. `awake.cpu` is the CPU a cross-core waker will
        // resched-IPI (see `resched_remote` / `enqueue_on`'s comment),
        // and it is otherwise only refreshed when the slot is POLLED. The
        // steal moved the slot from `victim`'s queue to `cpu`'s queue but
        // left `awake.cpu == victim` (stale). A waker that fires before the
        // thief first polls the slot would then read the stale victim id,
        // check `CPU_HALTED[victim]`, and IPI VICTIM — while the slot
        // actually sits in `READY[thief]` and the thief is the CPU that
        // needs waking. If the thief has halted, that wake is lost and the
        // task strands with awake=true → the connection it serves stalls
        // (the intermittent 200-conn livelock; worse under affinity
        // restriction, which forces more cross-core placement/stealing).
        // Route the steal through `enqueue_on` as well so re-homing, policy
        // lifecycle notification, and the remote reschedule handshake remain
        // one ordered operation.
        enqueue_on(cpu, slot, policy::TaskEnqueueReason::Migrated);
        return true;
    }
    false
}

/// Worker-AP entry: the per-CPU run loop that an AP enters after
/// bring-up. Equivalent to `run_until_empty` but never returns —
/// when both this CPU's queue and every steal target are empty,
/// halts until an IRQ delivers a wake.
///
/// Reports a QSBR quiescent state immediately before the halt so
/// `narf_rcu::sync` can advance even when this CPU has gone idle.
/// Without this, an AP that polled one task and then halted would
/// leave its `last_quiescent` stuck below the current epoch and
/// stall every subsequent grace period kernel-wide.
fn park_for_cpu_lifecycle(cpu: usize) -> bool {
    let cpu_id = CpuId(cpu as u32);
    let state = policy::cpu_state(cpu_id);
    if matches!(state, CpuState::Active | CpuState::Idle) {
        return false;
    }
    if state == CpuState::Draining {
        cpu_lifecycle::acknowledge_drain(cpu);
    }
    narf_rcu::report_idle();
    narf_memory::tlb_shootdown::mark_idle(cpu as u32);

    let interrupts_were_enabled = narf_arch::interrupts_enabled();
    if interrupts_were_enabled {
        // SAFETY: between polls with no scheduler lock held. The matching
        // enable below restores the executor's normal IRQ state.
        unsafe { narf_arch::disable_interrupts() };
    }
    CPU_HALTED[cpu].store(true, Ordering::SeqCst);
    core::sync::atomic::fence(Ordering::SeqCst);

    let state_after_publish = policy::cpu_state(cpu_id);
    if state_after_publish == CpuState::Draining {
        cpu_lifecycle::acknowledge_drain(cpu);
    }
    if matches!(state_after_publish, CpuState::Active | CpuState::Idle) {
        CPU_HALTED[cpu].store(false, Ordering::SeqCst);
        narf_memory::tlb_shootdown::mark_busy(cpu as u32);
        if interrupts_were_enabled {
            // SAFETY: restores the state masked above.
            unsafe { narf_arch::enable_interrupts() };
        }
        return false;
    }

    if interrupts_were_enabled {
        // SAFETY: IRQs were disabled above. This is the architecture's atomic
        // enable/halt/disable sequence, so a bring-up IPI cannot be lost in
        // the final state-check-to-halt window.
        unsafe { narf_arch::idle_halt_then_disable() };
    } else {
        core::hint::spin_loop();
    }
    CPU_HALTED[cpu].store(false, Ordering::SeqCst);
    narf_memory::tlb_shootdown::mark_busy(cpu as u32);
    if interrupts_were_enabled {
        // SAFETY: restores the state masked above.
        unsafe { narf_arch::enable_interrupts() };
    }
    true
}

pub fn run_forever() -> ! {
    let cpu = narf_lib::percpu::current_cpu();
    let cpu = if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    };
    // APs enter the scheduler here after architecture bring-up. Publish
    // execution availability even if the first queue is empty; the first
    // run_until_empty pass then emits the matching Idle edge before halt.
    policy::notify_cpu_state(CpuId(cpu as u32), CpuState::Active, None);
    loop {
        if park_for_cpu_lifecycle(cpu) {
            continue;
        }
        run_until_empty();
        if park_for_cpu_lifecycle(cpu) {
            continue;
        }
        // RCU maintenance before idling: open the next grace-period epoch
        // if this CPU still holds deferred reclamations, so peers' reports
        // can release them while we halt.
        narf_rcu::advance_epoch_if_pending();
        // Idle path: declare ourselves out of RCU consideration so
        // `sync()` doesn't block on an asleep CPU. We re-adopt the
        // live epoch on our first `report_quiescent` after wake.
        // Safe at this point because `run_until_empty` only returns
        // between polls, and read guards may not span awaits per
        // rcu/ §3.7.
        narf_rcu::report_idle();
        // See run_until_empty's idle path: under user-task SMP an AP
        // must re-enable IRQs before halting so it can wake to service
        // a peer's TLB-shootdown IPI (a parked user task left IF=0).
        if user_task_smp_enabled() {
            // SAFETY: between-polls idle; no IRQ-unsafe lock held.
            unsafe {
                narf_arch::enable_interrupts();
            }
        }
        // ── Dekker-participating empty-queue halt ──
        // This is the OTHER idle halt (run_until_empty's covers a CPU whose
        // queue still holds parked slots; this one covers a CPU whose queue
        // is EMPTY — exactly where a fresh spawn lands). It used to be a
        // bare `halt_until_irq()` OUTSIDE the CPU_HALTED protocol, which
        // broke the spawn kick twice over: `enqueue_on`'s `resched_remote`
        // saw halted=false and SKIPPED the IPI, and even a sent IPI could
        // be consumed in the check→HLT window (the documented
        // `halt_until_irq` race). Publish HALTED, fence, RE-CHECK the
        // queue + pending deferred wakes, and commit with the atomic
        // `sti;hlt;cli` — the same handshake as run_until_empty's idle
        // path, minus the wheel/backstop machinery (an empty CPU has no
        // sleepers to serve; the periodic tick still bounds any residual
        // miss).
        let race_free_halt = narf_time::tick_reliable() && narf_arch::interrupts_enabled();
        if race_free_halt {
            // SAFETY: re-enabled below (or by the sti;hlt;cli halt).
            // Masking IRQs across the halted-publish + re-scan + HLT is
            // what closes the IPI-before-HLT race.
            unsafe {
                narf_arch::disable_interrupts();
            }
        }
        narf_memory::tlb_shootdown::mark_idle(cpu as u32);
        CPU_HALTED[cpu].store(true, Ordering::SeqCst);
        core::sync::atomic::fence(Ordering::SeqCst);
        let work_arrived = {
            let nonempty = READY[cpu]
                .lock()
                .as_ref()
                .map(|d| !d.is_empty())
                .unwrap_or(false);
            nonempty || narf_lib::deferred_wake::has_pending()
        };
        if work_arrived {
            CPU_HALTED[cpu].store(false, Ordering::SeqCst);
            narf_memory::tlb_shootdown::mark_busy(cpu as u32);
            if race_free_halt {
                // SAFETY: restore the IRQ state we masked above; work is
                // already queued so we loop straight back to polling.
                unsafe {
                    narf_arch::enable_interrupts();
                }
            }
            continue;
        }
        if race_free_halt {
            // SAFETY: CPL=0, IF=0 on entry (masked above); the arch
            // primitive is the Linux safe_halt sti;hlt;cli, so an IPI (or
            // any IRQ) that raced into the commit window still wakes it.
            unsafe {
                narf_arch::idle_halt_then_disable();
            }
            CPU_HALTED[cpu].store(false, Ordering::SeqCst);
            narf_memory::tlb_shootdown::mark_busy(cpu as u32);
            // SAFETY: restore the enabled state this idle path runs with.
            unsafe {
                narf_arch::enable_interrupts();
            }
        } else {
            // Unreliable-tick / IF=0 contexts (kernel-test, InitialCount
            // fallback): the bounded `halt_until_irq` (spin when IF=0)
            // keeps the pre-existing behaviour.
            narf_arch::halt_until_irq();
            CPU_HALTED[cpu].store(false, Ordering::SeqCst);
            narf_memory::tlb_shootdown::mark_busy(cpu as u32);
        }
    }
}

/// Tiny convenience: Future that returns Pending once, then Ready.
/// `block_on`-equivalent `yield` point for cooperative tasks that just
/// want to give the executor a chance to run peers.
#[derive(Debug)]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded {
            Poll::Ready(())
        } else {
            this.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Background-pump registry — fn-pointer hooks that scheduler-blocking
/// busy-waits should tick periodically so subsystems whose forward
/// progress depends on regular polling (FB drain, cursor renderer,
/// future audio drain) don't freeze while a sync caller spins on
/// hardware.
///
/// Shape: fixed-size lock-free static array of `usize` (transmuted
/// `fn()` pointers). Registration is boot-only + idempotent on the
/// same fn pointer (registering twice fills two slots — callers
/// register exactly once per subsystem).
///
/// Used by:
/// - `userspace::handlers::sys_sleep`'s busy-wait
/// - Driver sync spin loops (NVMe, AHCI, NIC TX poll) — added so
///   a stuck device doesn't freeze the cursor / FB / serial
pub mod sleep_pumps {
    use core::sync::atomic::{AtomicUsize, Ordering};

    const MAX_PUMPS: usize = 8;
    pub type Pump = fn();

    static SLOTS: [AtomicUsize; MAX_PUMPS] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    pub fn register(p: Pump) {
        let p_addr = p as usize;
        for slot in SLOTS.iter() {
            if slot
                .compare_exchange(0, p_addr, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
        panic!("sleep_pumps: registry full ({} slots)", MAX_PUMPS);
    }

    pub fn run() {
        for slot in SLOTS.iter() {
            let p = slot.load(Ordering::Acquire);
            if p == 0 {
                return;
            }
            // SAFETY: slot was populated by `register` with a
            // valid `Pump` (`fn()`), and the static lifetime is
            // the kernel's.
            // SAFETY: Valid memory or trusted environment
            let f: Pump = unsafe { core::mem::transmute(p) };
            f();
        }
    }

    #[doc(hidden)]
    pub fn __reset_for_test() {
        for slot in SLOTS.iter() {
            slot.store(0, Ordering::Release);
        }
    }
}

/// Bounded busy-poll that ticks `sleep_pumps` periodically so the
/// FB cursor / serial drain / audio pump stay alive during driver
/// reset/init busy-waits. Returns true if `done` returned true
/// before `max_iters`, false on timeout.
///
/// The right primitive for "wait for an MMIO bit to flip" loops in
/// hardware drivers: pre-fix every NIC + USB controller hand-
/// rolled the spin loop, none ticked sleep_pumps, and a slow
/// device init froze the visible system for the duration. Default
/// every-4096-iters tick is invisible at MMIO read speeds and
/// pump cost is trivial (a few atomic loads + indirect calls).
#[inline]
pub fn responsive_spin<F: FnMut() -> bool>(mut done: F, max_iters: u32) -> bool {
    for i in 0..max_iters {
        if done() {
            note_forward_progress();
            return true;
        }
        if i & 0xFFF == 0 {
            sleep_pumps::run();
        }
        core::hint::spin_loop();
    }
    false
}

/// Arch-agnostic cooperative yield for contended in-kernel spin-waits whose
/// lock holder may be a descheduled stackful task homed on THIS CPU (see
/// [`stackful::cooperative_yield`]). Returns `true` if a yield happened,
/// `false` when there is nothing to yield to (no stackful task, or an arch
/// without the own-stack model) — the caller should then plain-spin.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
pub fn cooperative_yield() -> bool {
    stackful::cooperative_yield()
}

/// Unsupported-architecture stub: no own-stack scheduler, so the caller spins.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn cooperative_yield() -> bool {
    false
}

/// Deadline-driven counterpart to `responsive_spin`. Polls
/// `done()` until it returns true or the wall-clock `deadline`
/// passes; same `sleep_pumps`-tick cadence in between. Use this
/// when the wait should be bounded by real wall time rather than
/// an arbitrary iteration count that varies with CPU clock —
/// e.g. spec-defined "controller must respond within 100 ms" or
/// "hub reset takes max 50 ms".
///
/// Returns true if `done` succeeded before the deadline, false
/// on timeout.
#[inline]
pub fn responsive_spin_until<F: FnMut() -> bool>(
    mut done: F,
    deadline: narf_time::Deadline,
) -> bool {
    let mut i: u32 = 0;
    loop {
        if done() {
            note_forward_progress();
            return true;
        }
        if deadline.expired() {
            return false;
        }
        if i & 0xFFF == 0 {
            sleep_pumps::run();
        }
        core::hint::spin_loop();
        i = i.wrapping_add(1);
    }
}

/// Drive a future to completion synchronously from outside the
/// async executor. Polls the future; on Pending, runs the
/// registered `sleep_pumps` (so cursor/FB/serial keep moving) and
/// **idles to `halt_until_irq`** until something delivers a wake.
/// Returns the future's output.
///
/// The right primitive for **sync→async bridges in normal kernel
/// context**: any sync subsystem (BlockDeviceSync, FsOps' sync
/// wrappers, the eventual VFS sync paths) that wants to call into
/// an already-async driver path. Drivers should expose async
/// functions (e.g. NVMe's submit_io_irq_async) and let block_on
/// bridge instead of every driver hand-rolling spin loops.
///
/// **Constraints:**
/// - Caller MUST NOT hold any `IrqSafeSpinLock`. Those locks
///   disable IRQs while held, and `halt_until_irq` waits for an
///   IRQ — would deadlock forever. Use [`block_on_spin`] for the
///   IRQ-disabled / lock-held variant.
/// - Caller MUST NOT be inside an executor poll. block_on doesn't
///   yield to the executor; nested invocation deadlocks the
///   polling loop. (No runtime check; callers are expected to
///   know which context they're in.)
/// - The awaited future must be IRQ-driven or self-waking. A
///   future that depends on another scheduler task to make
///   progress will hang because block_on doesn't run the executor.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    block_on_inner(fut, /* allow_halt = */ true)
}

/// Spin-only sync→async bridge. Same shape as [`block_on`] but
/// never calls `halt_until_irq`, so safe to call with IRQs
/// disabled (any caller holding an `IrqSafeSpinLock`, panic
/// dump path, IRQ handler, SMP startup before the BSP timer is
/// armed). Trade-off: 100% CPU during the wait. Sleep-pumps
/// still tick so cursor/FB/serial don't freeze under the spin.
///
/// Same async-task and IRQ-driven-future constraints as
/// [`block_on`].
pub fn block_on_spin<F: Future>(fut: F) -> F::Output {
    block_on_inner(fut, /* allow_halt = */ false)
}

#[inline]
fn block_on_inner<F: Future>(mut fut: F, allow_halt: bool) -> F::Output {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    // Defensive: refuse to run the halting variant from inside an
    // executor poll. The executor publishes CURRENT_TASK before
    // polling and clears after; if it's non-zero we're inside
    // someone else's poll body, and recursing into block_on with
    // halt would deadlock the polling loop. The spinning variant
    // (block_on_spin) cannot deadlock the executor since it
    // busy-polls instead of calling halt_until_irq, and its
    // documented callers (panic dump, IRQ handlers, lock holders,
    // SMP startup, sleep_pump re-entry) may legitimately observe
    // CURRENT_TASK != 0.
    if allow_halt && current_task_slot().load(Ordering::Acquire) != 0 {
        panic!(
            "narf_scheduler::block_on called from inside executor poll \
             (CURRENT_TASK != 0) — would deadlock the polling loop. \
             Use yield_now().await or restructure the caller as async."
        );
    }
    // Pin the future on the stack. Sound because `fut` is owned
    // by this function's stack frame and Rust prevents moving it
    // out from under our `&mut` for the function's lifetime.
    // SAFETY: `fut` is a unique mutable binding we never move
    // again until the future completes.
    // SAFETY: Valid memory or trusted environment
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    let awake = Arc::new(WakeCell {
        flag: AtomicBool::new(true),
        cpu: AtomicU32::new(narf_lib::percpu::current_cpu() as u32),
    });
    let waker = make_waker(awake.clone());
    let mut ctx = Context::from_waker(&waker);
    loop {
        // Reset awake before polling so a wake landing during
        // the poll body is observable on the next iteration.
        awake.flag.store(false, Ordering::Release);
        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // Tick the sleep pumps so cursor/FB/serial stay
                // alive while we wait for an IRQ wake or self-
                // wake from the future's busy-poll.
                sleep_pumps::run();
                if allow_halt && !awake.flag.load(Ordering::Acquire) {
                    // Cooperative path: idle until something
                    // fires an IRQ. IRQ handler (or the future's
                    // own wake_by_ref) flips awake, then we return.
                    // `idle_wait` HLTs on a reliable tick and
                    // bounded-spins on the InitialCount fallback, so
                    // a dropped tick can't wedge a blocked caller.
                    idle_wait(None);
                } else {
                    // Spin path: re-poll immediately. Cheap
                    // back-off via spin_loop hint.
                    core::hint::spin_loop();
                }
            }
        }
    }
}
