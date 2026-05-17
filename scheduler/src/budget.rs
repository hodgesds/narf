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

/// Policy for what the scheduler does when a task blows its
/// burst quantum.
///
/// `Throttle` (default): clear the awake flag and push the slot
/// to the back of the queue without polling next round; only an
/// external waker revives it. `Demote`: reclassify the task as
/// `SchedClass::Idle` so peers in `Normal` / `RealTime` outrun
/// it. `Kill`: drop the slot O(1) — the future's `Drop` runs
/// from the executor. `Ignore`: accounting only.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum OverrunPolicy {
    #[default]
    Throttle,
    Demote,
    Kill,
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
            policy: OverrunPolicy::Throttle,
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

/// Per-task running account. `cycles_spent` sums measured poll
/// durations; `overruns` ticks once per poll that exceeded
/// `burst_cycles`. `donated_in` / `donated_out` track time-slice
/// donation flow per §3.3 — `add_credit` boosts the donee's
/// quantum by reducing `cycles_spent`; `add_debit` charges the
/// donor symmetrically. Both are reversible via `revert_*` so a
/// revoked donation cap rolls back cleanly.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetAccount {
    pub cycles_spent: u64,
    pub overruns: u64,
    pub polls: u64,
    pub donated_in: u64,
    pub donated_out: u64,
}

/// Outcome of `BudgetAccount::charge`. `Continue` is the common
/// in-budget path; `Throttle` parks the task without polling next
/// round; `Demote` shifts it to `SchedClass::Idle`; `Kill` drops
/// the slot. The executor branches on this value in
/// `run_until_empty`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ChargeOutcome {
    #[default]
    Continue,
    Throttle,
    Demote,
    Kill,
}

impl BudgetAccount {
    pub const fn new() -> Self {
        Self {
            cycles_spent: 0,
            overruns: 0,
            polls: 0,
            donated_in: 0,
            donated_out: 0,
        }
    }

    /// Charge `cycles` to this account against `budget`. The
    /// returned `ChargeOutcome` tells the executor what to do
    /// with the slot. Bookkeeping (`polls`, `cycles_spent`,
    /// `overruns`) updates regardless of `policy`.
    #[inline]
    pub fn charge(&mut self, cycles: u64, budget: &ResourceBudget) -> ChargeOutcome {
        self.polls = self.polls.saturating_add(1);
        self.cycles_spent = self.cycles_spent.saturating_add(cycles);
        let over = cycles > budget.burst_cycles;
        if over {
            self.overruns = self.overruns.saturating_add(1);
        }
        if !over {
            return ChargeOutcome::Continue;
        }
        match budget.policy {
            OverrunPolicy::Ignore => ChargeOutcome::Continue,
            OverrunPolicy::Throttle => ChargeOutcome::Throttle,
            OverrunPolicy::Demote => ChargeOutcome::Demote,
            OverrunPolicy::Kill => ChargeOutcome::Kill,
        }
    }

    /// Apply a donation credit: bump `donated_in` and reduce
    /// `cycles_spent` by `cycles` (saturating at 0). Called by the
    /// executor when stamping a `donate_to` claim on the donee.
    #[inline]
    pub fn add_credit(&mut self, cycles: u64) {
        self.donated_in = self.donated_in.saturating_add(cycles);
        self.cycles_spent = self.cycles_spent.saturating_sub(cycles);
    }

    /// Apply a donation debit on the donor side.
    #[inline]
    pub fn add_debit(&mut self, cycles: u64) {
        self.donated_out = self.donated_out.saturating_add(cycles);
        self.cycles_spent = self.cycles_spent.saturating_add(cycles);
    }

    /// Reverse `add_credit`. Used when the donation cap is revoked
    /// before the donee consumed the credit.
    #[inline]
    pub fn revert_credit(&mut self, cycles: u64) {
        self.donated_in = self.donated_in.saturating_sub(cycles);
        self.cycles_spent = self.cycles_spent.saturating_add(cycles);
    }

    /// Reverse `add_debit` on the donor side.
    #[inline]
    pub fn revert_debit(&mut self, cycles: u64) {
        self.donated_out = self.donated_out.saturating_sub(cycles);
        self.cycles_spent = self.cycles_spent.saturating_sub(cycles);
    }
}
