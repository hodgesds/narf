//! Equal-weight EEVDF policy and shared fair wake-preemption decision.
//!
//! Linux 7.0-rc3 `kernel/sched/fair.c` (`vruntime_eligible`, `__pick_eevdf`,
//! `wakeup_preempt_fair`) checks current eligibility BEFORE slice protection.
//! The Class policy shares that wake decision within its class/priority tier.
//! NARF uses equal-weight runtime, uniform virtual request sizes, and its
//! existing bounded sleeper credit. This is not Linux's weighted/group runqueue
//! or its persistent per-entity request/deadline implementation.

use crate::affinity::CpuId;
use crate::budget::BudgetEligibility;
use crate::policy::{CpuSchedContext, RunQueue, SchedRow, Scheduler, TaskHandle, WakePreemption};
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

/// Comparison key for a pick candidate: eligibility tier, class, virtual
/// deadline, and nice priority — the fields `better_pick` orders by.
#[derive(Copy, Clone)]
struct PickKey {
    tier: u8,
    class: SchedClass,
    deadline: u64,
    prio: i8,
}

/// Is `a` a strictly better *pick* than `b`? Ordering: higher eligibility tier,
/// then higher class rank, then earlier `d_eff`, then lower nice priority. Pure
/// so the pick order is unit-testable without a live executor.
#[inline]
fn better_pick(a: PickKey, b: PickKey) -> bool {
    if a.tier != b.tier {
        return a.tier > b.tier;
    }
    if a.class.rank() != b.class.rank() {
        return a.class.rank() > b.class.rank();
    }
    if a.deadline != b.deadline {
        return a.deadline < b.deadline;
    }
    a.prio < b.prio
}

/// Equal-weight adaptation of Linux's eligibility-before-protection ordering.
/// The runner is detached from RunQueue, so include its live runtime explicitly.
/// Uniform request sizes make the minimum-vruntime peer the earliest deadline;
/// collecting it and the exact runtime sum needs one allocation-free scan.
/// All runtime comparisons use the same bounded-credit view as EEVDF picks.
#[derive(Debug)]
pub(crate) struct FairWake {
    start: u64,
    now: u64,
    deadline: u64,
    elapsed: u64,
    floor: u64,
    peer_sum: u128,
    peers: u64,
    first: u64,
}

impl FairWake {
    pub(crate) fn new(ctx: &CpuSchedContext) -> Self {
        let start = v_eff(ctx.current.vruntime, ctx.vfloor);
        Self {
            start,
            now: start.saturating_add(ctx.elapsed),
            deadline: start
                .saturating_add(ctx.current.vdeadline.saturating_sub(ctx.current.vruntime)),
            elapsed: ctx.elapsed,
            floor: ctx.vfloor,
            peer_sum: 0,
            peers: 0,
            first: u64::MAX,
        }
    }

    pub(crate) fn observe(&mut self, vruntime: u64) {
        let v = v_eff(vruntime, self.floor);
        self.peer_sum += u128::from(v);
        self.peers += 1;
        self.first = self.first.min(v);
    }

    pub(crate) fn decision(self) -> WakePreemption {
        if self.peers == 0 {
            return WakePreemption::KeepRunning;
        }
        let peers = u128::from(self.peers);
        let now = u128::from(self.now);
        let single = self.peers == 1;
        // Linux vruntime_eligible(): compare sums, without a rounded average.
        // current <= (sum(peers) + current)/(nr_peers + 1) reduces to this.
        let ineligible = if single {
            self.now > self.first
        } else {
            now * peers > self.peer_sum
        };
        if ineligible {
            // __pick_eevdf drops an ineligible current before protect_slice().
            // The earliest peer is necessarily eligible in this case.
            return WakePreemption::Now;
        }
        let first_eligible = if single {
            self.first <= self.now
        } else {
            u128::from(self.first) * (peers + 1) <= self.peer_sum + now
        };
        let protected = self.now < self.deadline;
        if !protected
            && first_eligible
            && self.first.saturating_add(EEVDF_BASE_SLICE) <= self.deadline
        {
            return WakePreemption::Now;
        }

        // With peers stationary, current first becomes ineligible one cycle
        // past their average. Protection may end sooner when an eligible peer
        // already has an earlier/equal deadline. Keep this exact boundary for
        // the core's existing deferred check instead of a fixed grace period.
        // A single peer's average is its runtime. Keep this common ping-pong
        // case off the wide divide while retaining exact sums for larger queues.
        let average = if single {
            u128::from(self.first)
        } else {
            self.peer_sum / peers
        };
        let mut next = (average + 1).saturating_sub(u128::from(self.start));
        if protected && first_eligible {
            next = next.min(u128::from(self.deadline.saturating_sub(self.start)));
        }
        if next > u128::from(self.elapsed) && next <= u128::from(u64::MAX) {
            WakePreemption::After(next as u64)
        } else {
            WakePreemption::KeepRunning
        }
    }
}

/// True if `row` is a dispatchable candidate (runnable, not throttled).
#[inline]
fn candidate(row: &SchedRow) -> bool {
    row.runnable && row.eligibility != BudgetEligibility::Throttled
}

impl Scheduler for EevdfScheduler {
    fn wakeup_preemption(&self, ctx: &CpuSchedContext, queue: &RunQueue<'_>) -> WakePreemption {
        let mut fair = FairWake::new(ctx);
        for row in queue.iter_sched() {
            if !candidate(&row) || row.handle.task_id() == ctx.current.id {
                continue;
            }
            if row.class != ctx.current.class {
                if row.class.rank() > ctx.current.class.rank() {
                    return WakePreemption::Now;
                }
                continue;
            }
            if row.class == SchedClass::Realtime {
                if row.priority.raw() < ctx.current.priority.raw() {
                    return WakePreemption::Now;
                }
                continue; // Equal-priority FIFO/RR ordering is core-owned.
            }
            if matches!(row.class, SchedClass::Default | SchedClass::Interactive) {
                fair.observe(row.vruntime);
            }
        }
        fair.decision()
    }

    fn name(&self) -> &'static str {
        "eevdf"
    }

    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        let vfloor = crate::vfloor(cpu.0 as usize);
        let mut best: Option<(TaskHandle, PickKey)> = None;
        for row in queue.iter_sched() {
            if !candidate(&row) {
                continue;
            }
            let key = PickKey {
                tier: tier(row.eligibility),
                class: row.class,
                deadline: d_eff(row.vruntime, vfloor),
                prio: row.priority.0,
            };
            let take = match best {
                None => true,
                Some((_, bkey)) => better_pick(key, bkey),
            };
            if take {
                best = Some((row.handle, key));
            }
        }
        // Core validates the handle and falls back to the top tier if we somehow
        // returned nothing while runnable work exists.
        best.map(|(h, ..)| h).or_else(|| queue.front())
    }

    fn select_task_rq(
        &self,
        prev_cpu: CpuId,
        waker_cpu: CpuId,
        is_online: &dyn Fn(CpuId) -> bool,
        is_idle: &dyn Fn(CpuId) -> bool,
        allowed: &dyn Fn(CpuId) -> bool,
    ) -> Option<CpuId> {
        // Shared with the Class policy — see `policy::select_idle_sibling`.
        crate::policy::select_idle_sibling(prev_cpu, waker_cpu, is_online, is_idle, allowed)
    }

    fn wakeup_preempt(&self, ctx: &CpuSchedContext, queue: &RunQueue<'_>) -> bool {
        self.wakeup_preemption(ctx, queue) == WakePreemption::Now
    }
}
