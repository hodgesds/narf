//! ClassScheduler's CPU-time-bounded blocking-I/O preference.

use super::{CpuId, DispatchReason, RunQueue, TaskHandle, TaskRuntime, WakeReason};
use crate::{BudgetEligibility, Priority, ResourceBudget, SchedClass};
use core::sync::atomic::{AtomicI64, Ordering};

// Bound bursts to one existing fair-share quantum (a quarter of a default
// task slice), with ordinary charged CPU time repaying every spent cycle.
const CREDIT: i64 = (crate::EEVDF_BASE_SLICE * 4) as i64;

#[repr(align(64))]
struct Credit(AtomicI64);
static CREDITS: [Credit; narf_lib::percpu::MAX_CPUS] =
    [const { Credit(AtomicI64::new(CREDIT)) }; narf_lib::percpu::MAX_CPUS];

pub(super) fn reset(cpu: usize) {
    if let Some(credit) = CREDITS.get(cpu) {
        credit.0.store(CREDIT, Ordering::Relaxed);
    }
}

pub(super) fn pick(cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
    if CREDITS.get(cpu.0 as usize)?.0.load(Ordering::Relaxed) <= 0 {
        return None;
    }
    for task in queue.iter_sched() {
        if !task.runnable || task.eligibility != BudgetEligibility::Eligible {
            continue;
        }
        // Keep class ordering here too: a delegating scheduler must not need
        // the core's native-ClassScheduler fast-path checks for correctness.
        if task.class.rank() > SchedClass::Default.rank()
            || (task.class == SchedClass::Default && task.priority < Priority::NORMAL)
        {
            return None;
        }
    }
    // Only the candidate search needs full budget metadata. In particular,
    // don't copy every helper's BudgetAccount to check class ordering above.
    queue.iter_meta().find_map(|(handle, task)| {
        (task.runnable
            && task.wake_reason == Some(WakeReason::BlockingIo)
            && task.class == SchedClass::Default
            && task.priority == Priority::NORMAL
            && task.budget == ResourceBudget::unthrottled()
            && task.budget_state.eligibility == BudgetEligibility::Eligible)
            .then_some(handle)
    })
}

pub(super) fn charge(cpu: usize, runtime: TaskRuntime) {
    let Some(credit) = CREDITS.get(cpu) else {
        return;
    };
    let old = credit.0.load(Ordering::Relaxed);
    if runtime.reason == DispatchReason::Policy && old >= CREDIT {
        return;
    }
    let cycles = runtime.cycles.min(i64::MAX as u64) as i64;
    let new = if runtime.reason == DispatchReason::Wakeup {
        old.saturating_sub(cycles)
    } else {
        old.saturating_add(cycles).min(CREDIT)
    };
    // CPU-local executor callbacks are serialized, including nested polls.
    // Overshoot remains debt; ordinary CPU time repays it, capped at one fair
    // quantum. Neither repeated wakes nor short dispatches manufacture credit.
    credit.0.store(new, Ordering::Relaxed);
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::policy::{ClassScheduler, Scheduler};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_class_wake_metadata_and_cpu_debt() -> TestResult {
        crate::__reset_queues_for_test();
        let cpu = CpuId(narf_lib::percpu::current_cpu() as u32);
        let policy = ClassScheduler;
        let helper = crate::spawn(async {});
        let first = crate::spawn(async {});
        let second = crate::spawn(async {});
        let mut ready = crate::READY[cpu.0 as usize].lock();
        let queue = ready.as_mut().unwrap();
        for slot in queue.iter().filter(|s| s.id == first || s.id == second) {
            slot.awake.blocking_wake.store(true, Ordering::Release);
        }
        crate::blocking::mark_possible(cpu.0 as usize);
        let (_, mut selected) = super::super::pick_next_slot(Some(&policy), cpu, queue).unwrap();
        let both_retained =
            selected.id == first && selected.dispatch_reason == DispatchReason::Wakeup;
        selected.awake.blocking_wake.store(false, Ordering::Release);
        selected.dispatch_reason = DispatchReason::Policy;
        queue.push_back(selected);
        let (_, mut selected) = super::super::pick_next_slot(Some(&policy), cpu, queue).unwrap();
        let both_retained = both_retained && selected.id == second;
        selected.awake.blocking_wake.store(false, Ordering::Release);
        selected.dispatch_reason = DispatchReason::Policy;
        queue.push_back(selected);
        let event = |cycles, reason| TaskRuntime {
            task: TaskHandle::from_id(first),
            cycles,
            reason,
        };
        queue
            .front()
            .unwrap()
            .awake
            .blocking_wake
            .store(true, Ordering::Release);
        let (_, mut selected) = super::super::pick_next_slot(Some(&policy), cpu, queue).unwrap();
        let ordinary_charged =
            selected.id == helper && selected.dispatch_reason == DispatchReason::Wakeup;
        selected.awake.blocking_wake.store(false, Ordering::Release);
        selected.dispatch_reason = DispatchReason::Policy;
        queue.push_front(selected);
        policy.on_task_runtime(cpu, event((CREDIT * 2) as u64, DispatchReason::Wakeup));
        queue
            .iter()
            .find(|s| s.id == first)
            .unwrap()
            .awake
            .blocking_wake
            .store(true, Ordering::Release);
        let debt_blocks = policy
            .pick_wakeup(cpu, &RunQueue::projected(queue))
            .is_none();
        policy.on_task_runtime(cpu, event(CREDIT as u64, DispatchReason::Policy));
        let zero_blocks = policy
            .pick_wakeup(cpu, &RunQueue::projected(queue))
            .is_none();
        policy.on_task_runtime(cpu, event(1, DispatchReason::Policy));
        let paid = policy.pick_wakeup(cpu, &RunQueue::projected(queue))
            == Some(TaskHandle::from_id(first));
        policy.on_task_runtime(cpu, event(i64::MAX as u64, DispatchReason::Policy));
        policy.on_task_runtime(cpu, event(CREDIT as u64, DispatchReason::Wakeup));
        let capped = policy
            .pick_wakeup(cpu, &RunQueue::projected(queue))
            .is_none();
        let (_, selected) = super::super::pick_next_slot(Some(&policy), cpu, queue).unwrap();
        let helper_runs = selected.id == helper;
        drop(ready);
        crate::__reset_queues_for_test();
        if !both_retained
            || !ordinary_charged
            || !debt_blocks
            || !zero_blocks
            || !paid
            || !capped
            || !helper_runs
        {
            return TestResult::Fail(
                "class wake preference lost metadata, debt, or ordinary progress",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!("scheduler", smoke_class_wake_metadata_and_cpu_debt);
}
