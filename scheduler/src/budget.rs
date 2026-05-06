//! CPU budget types + accounting.
//!
//! Spec: `scheduler/specification/spec.md` §3.4. A `ResourceBudget`
//! caps the CPU share a task may consume; the scheduler deducts
//! elapsed cycles from the per-task `BudgetAccount` on every poll and
//! records an overrun if the task runs past its burst allowance. A
//! live `Cap<CpuBudget, Spend>` is required for the task to be picked
//! for polling at all — revoking the cap stops the task O(1).
//!
//! Stage-3 scope (single-CPU):
//! - `ResourceBudget` + `OverrunPolicy` + `CpuBudget` cap type.
//! - `BudgetAccount`: per-task running total of cycles spent + overrun
//!   counter. No hard-kill on exhaustion — that's Stage-4 policy work.
//! - Executor integration: cap `check_live` before poll; on revoked →
//!   drop the slot; on live → time the poll, charge the account.
//!
//! Deferred to Stage 4:
//! - Fair-share enforcement (today's account is diagnostic only).
//! - `deadline: Option<Deadline>` — the field exists but the scheduler
//!   does not yet promote deadline-backed tasks over peers.
//! - Domain-root budget inheritance (§3.4 last bullet).

use narf_capabilities::{CapKind, CapType};

/// Policy for what the scheduler does when a task blows its budget.
///
/// Default is `Block`: the scheduler parks the task until its budget
/// refills at the next epoch. `Degrade` keeps it running but emits a
/// `tracing/` event so operators see the over-run. `Ignore` is
/// diagnostic-only — the accounting still happens but nothing changes
/// on the scheduling path. Today every policy behaves like `Ignore`
/// in the executor; the enum is here so Stage 4 can flip behaviour
/// without changing the public spawn API.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum OverrunPolicy {
    #[default]
    Block,
    Degrade,
    Ignore,
}

/// CPU-share budget for a task.
///
/// `share_ppm` is parts-per-million of a single CPU (1_000_000 = one
/// full CPU, 500_000 = half a CPU). `burst_cycles` is how many
/// *contiguous* cycles a task may exceed its share before the
/// overrun counter ticks. `deadline_cycles` is an absolute wake
/// deadline (in `narf_time` cycles); `None` for non-realtime tasks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceBudget {
    pub share_ppm: u32,
    pub burst_cycles: u64,
    pub deadline_cycles: Option<u64>,
    pub policy: OverrunPolicy,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::unthrottled()
    }
}

impl ResourceBudget {
    /// Unthrottled budget — the common case for kernel drivers.
    pub const fn unthrottled() -> Self {
        Self {
            share_ppm: 1_000_000,
            burst_cycles: u64::MAX,
            deadline_cycles: None,
            policy: OverrunPolicy::Ignore,
        }
    }

    /// Fair-share at `share_ppm` with a `burst_cycles` allowance.
    pub const fn fair_share(share_ppm: u32, burst_cycles: u64) -> Self {
        Self {
            share_ppm,
            burst_cycles,
            deadline_cycles: None,
            policy: OverrunPolicy::Block,
        }
    }
}

/// `CapType` marker gating CPU-budget debit. Held as
/// `Cap<CpuBudget, Spend>` by a task so the scheduler can revoke CPU
/// time with a single epoch bump.
#[derive(Copy, Clone, Debug)]
pub struct CpuBudget;

impl CapType for CpuBudget {
    const KIND: CapKind = CapKind::CpuBudget;
}

/// Per-task running account. `cycles_spent` is the sum of measured
/// poll durations; `overruns` ticks once per poll that exceeded
/// `burst_cycles`. The scheduler updates both fields; `ResourceBudget`
/// itself is immutable after spawn.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetAccount {
    pub cycles_spent: u64,
    pub overruns: u64,
    pub polls: u64,
}

impl BudgetAccount {
    pub const fn new() -> Self {
        Self {
            cycles_spent: 0,
            overruns: 0,
            polls: 0,
        }
    }

    /// Charge `cycles` to this account against `budget`. Returns
    /// `true` if the charge crossed the burst allowance.
    #[inline]
    pub fn charge(&mut self, cycles: u64, budget: &ResourceBudget) -> bool {
        self.polls = self.polls.saturating_add(1);
        self.cycles_spent = self.cycles_spent.saturating_add(cycles);
        let over = cycles > budget.burst_cycles;
        if over {
            self.overruns = self.overruns.saturating_add(1);
        }
        over
    }
}
