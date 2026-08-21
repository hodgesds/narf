#![no_std]

//! Compile proof that scheduling policy can live in a separate crate.
//!
//! This crate intentionally depends only on `narf-scheduler`'s public API.
//! It cannot name `TaskSlot`, run-queue locks, stack/domain switch state, or
//! architecture context-switch functions.

use narf_scheduler::{
    BudgetEligibility, CpuId, RunQueue, SchedClass, Scheduler, TaskHandle, TaskMeta,
    TaskQueueEvent, WorkKind,
};

/// Example budget-aware strict-class policy.
#[derive(Copy, Clone, Debug, Default)]
pub struct BudgetAwareClassPolicy;

impl Scheduler for BudgetAwareClassPolicy {
    fn name(&self) -> &'static str {
        "example-budget-aware-class"
    }

    fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        let mut best: Option<(TaskHandle, TaskMeta)> = None;

        for (handle, meta) in queue.iter_meta() {
            if !meta.runnable || meta.budget_state.eligibility == BudgetEligibility::Throttled {
                continue;
            }

            // Policy can inspect work kind and immutable budget/accounting
            // snapshots. The core remains the only component that can charge,
            // throttle, remove a queue slot, or switch its execution context.
            let candidate_rank = effective_rank(&meta);

            let replace = match best {
                None => true,
                Some((_, incumbent)) => {
                    let incumbent_rank = effective_rank(&incumbent);
                    if candidate_rank != incumbent_rank {
                        candidate_rank > incumbent_rank
                    } else if meta.priority != incumbent.priority {
                        meta.priority.raw() < incumbent.priority.raw()
                    } else if meta.class == SchedClass::Realtime
                        && incumbent.class == SchedClass::Realtime
                    {
                        match (meta.deadline_cycles, incumbent.deadline_cycles) {
                            (Some(candidate), Some(current)) => candidate < current,
                            (Some(_), None) => true,
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
            };
            if replace {
                best = Some((handle, meta));
            }
        }

        best.map(|(handle, _)| handle)
    }

    fn on_task_queue_event(&self, _cpu: CpuId, _event: TaskQueueEvent) {
        // A stateful external policy can maintain its own per-CPU index here.
        // The executor's RunQueue snapshot remains authoritative.
    }
}

fn effective_rank(meta: &TaskMeta) -> u8 {
    let budgeted_softirq_overrun = meta.work_kind == WorkKind::SoftIrq
        && meta.budget.share_ppm < 1_000_000
        && meta.account.overruns != 0;
    meta.class
        .rank()
        .saturating_sub(u8::from(budgeted_softirq_overrun))
}
