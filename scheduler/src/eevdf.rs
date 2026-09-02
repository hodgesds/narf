//! EEVDF-lite scheduler policy — NARF's default.
//!
//! An equal-weight approximation of Linux's EEVDF fair class
//! (`/usr/src/linux/kernel/sched/fair.c`). Uses the core-owned per-task
//! `vruntime` and per-CPU `VFLOOR` (see
//! `specification/scheduling-policies.md` §4-5), so this policy holds NO
//! per-task state of its own — every decision is a pure function of the lean
//! [`SchedRow`] projection plus the CPU's virtual-time floor. The hot paths
//! (`pick_next` per dispatch, `wakeup_preempt` per wake) are single O(n) scans
//! over `Copy` rows with no allocation and no `TaskMeta` materialisation.
//!
//! Key quantities (all TSC cycles), mirroring Linux:
//! - `v_eff = max(vruntime, VFLOOR - BASE)` — effective virtual runtime with a
//!   bounded sleeper credit: a long-parked task's negative lag is clamped to one
//!   base slice (Linux `place_entity()`'s lag clamp), so it cannot preempt
//!   everything forever.
//! - `d_eff = v_eff + BASE` — the task's virtual deadline (Linux
//!   `se->deadline = vruntime + slice`). With uniform slices, "min deadline"
//!   picks equal "min `v_eff`".
//! - The runner's protected `vdeadline = vruntime_at_dispatch + BASE` (Linux
//!   `RUN_TO_PARITY` slice protection), published in `CurrentTask`.
//!
//! `wakeup_preempt` cedes iff the best runnable sibling outranks the runner's
//! class, or (same class) its `d_eff` is strictly earlier than the runner's
//! protected `vdeadline`. A just-slept, starved task has an early `d_eff` and
//! preempts (fast futex wait/wake handoff); a balanced peer's `d_eff` is not
//! earlier than the protected deadline, so the runner batches out its slice (no
//! de-batch of pipe/msg/redis-pipeline throughput). One rule, both behaviours —
//! no wall-clock threshold.

use crate::affinity::CpuId;
use crate::budget::BudgetEligibility;
use crate::policy::{CpuSchedContext, RunQueue, Scheduler, SchedRow, TaskHandle};
use crate::priority::SchedClass;
use crate::EEVDF_BASE_SLICE;

/// EEVDF-lite policy. Zero-sized: all state is core-owned.
#[derive(Copy, Clone, Debug, Default)]
pub struct EevdfScheduler;

/// Effective virtual runtime with the bounded sleeper-credit clamp.
#[inline]
fn v_eff(vruntime: u64, vfloor: u64) -> u64 {
    vruntime.max(vfloor.saturating_sub(EEVDF_BASE_SLICE))
}

/// Effective virtual deadline `= v_eff + BASE`.
#[inline]
fn d_eff(vruntime: u64, vfloor: u64) -> u64 {
    v_eff(vruntime, vfloor).saturating_add(EEVDF_BASE_SLICE)
}

/// Eligibility tier order for a pick: `Eligible` (2) beats `Borrowable` (1);
/// `Throttled` (0) is never dispatchable. Higher is better.
#[inline]
fn tier(e: BudgetEligibility) -> u8 {
    match e {
        BudgetEligibility::Eligible => 2,
        BudgetEligibility::Borrowable => 1,
        BudgetEligibility::Throttled => 0,
    }
}

/// Is `a` a strictly better *pick* than `b`? Ordering: higher eligibility tier,
/// then higher class rank, then earlier `d_eff`, then lower nice priority. Pure
/// so the pick order is unit-testable without a live executor.
#[inline]
fn better_pick(
    a_tier: u8,
    a_class: SchedClass,
    a_deadline: u64,
    a_prio: i8,
    b_tier: u8,
    b_class: SchedClass,
    b_deadline: u64,
    b_prio: i8,
) -> bool {
    if a_tier != b_tier {
        return a_tier > b_tier;
    }
    if a_class.rank() != b_class.rank() {
        return a_class.rank() > b_class.rank();
    }
    if a_deadline != b_deadline {
        return a_deadline < b_deadline;
    }
    a_prio < b_prio
}

/// The wake-preemption rule (Linux `check_preempt_wakeup_fair`), pulled out as a
/// pure function: cede iff the wakee outranks the runner's class, or (same
/// class) the wakee's `d_eff` is strictly earlier than the runner's CURRENT
/// virtual runtime `runner_now` (= vruntime-at-dispatch + what it has run since).
///
/// Comparing against the runner's *growing* clock — not a fixed dispatch
/// deadline — is what distinguishes the two workloads with ONE rule:
/// - a deeply-starved sleeper (a futex parent parked across many waker slices)
///   has `d_eff ≪ runner_now`, so it preempts immediately → fast wait/wake
///   handoff;
/// - a briefly-blocked peer (a pipe/msg reader) has `d_eff ≈ dispatch + BASE`,
///   which exceeds `runner_now` until the runner has actually run ~a base slice,
///   so the runner keeps batching (and if it blocks first, no forced switch at
///   all) → no de-batch.
///
/// Strict `<` so an exactly-caught-up peer does not preempt.
#[inline]
pub(crate) fn eevdf_should_preempt(
    runner_class: SchedClass,
    runner_now: u64,
    wakee_class: SchedClass,
    wakee_d_eff: u64,
) -> bool {
    if wakee_class.rank() != runner_class.rank() {
        return wakee_class.rank() > runner_class.rank();
    }
    wakee_d_eff < runner_now
}

/// True if `row` is a dispatchable candidate (runnable, not throttled).
#[inline]
fn candidate(row: &SchedRow) -> bool {
    row.runnable && row.eligibility != BudgetEligibility::Throttled
}

impl Scheduler for EevdfScheduler {
    fn name(&self) -> &'static str {
        "eevdf"
    }

    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        let vfloor = crate::vfloor(cpu.0 as usize);
        let mut best: Option<(TaskHandle, u8, SchedClass, u64, i8)> = None;
        for row in queue.iter_sched() {
            if !candidate(&row) {
                continue;
            }
            let t = tier(row.eligibility);
            let dl = d_eff(row.vruntime, vfloor);
            let p = row.priority.0;
            let take = match best {
                None => true,
                Some((_, bt, bc, bd, bp)) => {
                    better_pick(t, row.class, dl, p, bt, bc, bd, bp)
                }
            };
            if take {
                best = Some((row.handle, t, row.class, dl, p));
            }
        }
        // Core validates the handle and falls back to the top tier if we somehow
        // returned nothing while runnable work exists.
        best.map(|(h, ..)| h).or_else(|| queue.front())
    }

    fn wakeup_preempt(&self, ctx: &CpuSchedContext, queue: &RunQueue<'_>) -> bool {
        let vfloor = ctx.vfloor;
        let current = &ctx.current;
        // Best runnable sibling (highest class, then earliest d_eff). The runner
        // is detached during its poll, so the queue holds only waiters; the id
        // guard is belt-and-suspenders.
        let mut best: Option<(SchedClass, u64)> = None;
        for row in queue.iter_sched() {
            if !candidate(&row) || row.handle.task_id() == current.id {
                continue;
            }
            let dl = d_eff(row.vruntime, vfloor);
            let take = match best {
                None => true,
                Some((bc, bd)) => {
                    row.class.rank() > bc.rank() || (row.class.rank() == bc.rank() && dl < bd)
                }
            };
            if take {
                best = Some((row.class, dl));
            }
        }
        match best {
            None => false,
            // `current.vruntime` here is the runner's CURRENT effective virtual
            // runtime (dispatch + elapsed), assembled by the core in
            // `wake_preempt_policy_check`.
            Some((wclass, wd)) => {
                eevdf_should_preempt(current.class, current.vruntime, wclass, wd)
            }
        }
    }
}
