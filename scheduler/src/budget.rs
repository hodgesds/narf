//! CPU budget types + accounting.
//!
//! Spec: `scheduler/specification/spec.md` §3.4. A `ResourceBudget`
//! caps the CPU share a task may consume; the scheduler deducts
//! elapsed cycles from the per-task `BudgetAccount` on every poll,
//! replenishes periodic runtime in the core, and records an overrun if a
//! task runs past its per-dispatch burst allowance. A
//! live `Cap<CpuBudget, Spend>` is required for the task to be picked
//! for polling at all — revoking the cap stops the task O(1).
//!
//! Implemented scope:
//! - `ResourceBudget` + `OverrunPolicy` + `CpuBudget` cap type.
//! - `BudgetAccount`: per-task running total of cycles spent + overrun
//!   counter. The executor applies the configured overrun action.
//! - Executor integration: cap `check_live` before poll; on revoked →
//!   drop the slot; on live → time the poll, charge the account.
//!
//! Domain-root budget inheritance (§3.4 last bullet) remains deferred.

use narf_capabilities::{CapKind, CapType};

/// Policy for what the scheduler does when a task blows its
/// burst quantum.
///
/// `Throttle` (default): clear the awake flag and push the slot
/// to the back of the queue without polling again; only an external
/// waker revives it. `Demote`: reclassify the task as
/// `SchedClass::Idle` so peers in higher classes outrun
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

/// What the core does after a periodic runtime allocation is exhausted.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ExhaustionPolicy {
    /// Ineligible until the next period even when the CPU would otherwise idle.
    #[default]
    Strict,
    /// May consume bounded borrowed runtime only while no regular work is
    /// eligible. A wake makes the borrower preemptible at the next tick.
    IdleBorrow,
}

/// Core-owned periodic bandwidth contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PeriodBudget {
    /// Runtime replenished at each period boundary.
    pub runtime_cycles: u64,
    /// Distance between replenishment boundaries.
    pub period_cycles: u64,
    /// Maximum idle time that may be borrowed within one period.
    pub max_borrow_cycles: u64,
    pub exhaustion: ExhaustionPolicy,
}

impl PeriodBudget {
    pub const fn strict(runtime_cycles: u64, period_cycles: u64) -> Self {
        Self {
            runtime_cycles,
            period_cycles,
            max_borrow_cycles: 0,
            exhaustion: ExhaustionPolicy::Strict,
        }
    }

    pub const fn idle_borrow(
        runtime_cycles: u64,
        period_cycles: u64,
        max_borrow_cycles: u64,
    ) -> Self {
        Self {
            runtime_cycles,
            period_cycles,
            max_borrow_cycles,
            exhaustion: ExhaustionPolicy::IdleBorrow,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.runtime_cycles > 0
            && self.period_cycles > 0
            && self.runtime_cycles <= self.period_cycles
            && (matches!(self.exhaustion, ExhaustionPolicy::IdleBorrow)
                || self.max_borrow_cycles == 0)
    }
}

/// Eligibility computed by the core from the current period account.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum BudgetEligibility {
    #[default]
    Eligible,
    Borrowable,
    Throttled,
}

/// Read-only period snapshot passed to scheduling policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BudgetView {
    pub eligibility: BudgetEligibility,
    pub remaining_cycles: u64,
    pub replenish_at_cycles: Option<u64>,
    pub borrowed_cycles: u64,
    pub debt_cycles: u64,
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
    /// `None` means no period-based bandwidth limit.
    pub period: Option<PeriodBudget>,
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
            period: None,
        }
    }

    /// Fair-share at `share_ppm` with a `burst_cycles` allowance.
    pub const fn fair_share(share_ppm: u32, burst_cycles: u64) -> Self {
        Self {
            share_ppm,
            burst_cycles,
            deadline_cycles: None,
            policy: OverrunPolicy::Throttle,
            period: None,
        }
    }

    /// Attach a validated period contract. Invalid contracts are rejected at
    /// spawn even if callers construct `PeriodBudget` with public fields.
    pub const fn with_period(mut self, period: PeriodBudget) -> Self {
        self.period = Some(period);
        self
    }

    pub const fn is_valid(self) -> bool {
        self.share_ppm <= 1_000_000
            && match self.period {
                Some(period) => period.is_valid(),
                None => true,
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
    /// Start of the active replenishment period. Zero until first dispatch.
    pub period_start_cycles: u64,
    /// Next core-owned replenishment boundary. Zero when uninitialised or
    /// unthrottled.
    pub replenish_at_cycles: u64,
    pub runtime_remaining_cycles: u64,
    pub borrowed_cycles: u64,
    /// Borrowed idle capacity deducted from future replenishments.
    pub debt_cycles: u64,
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
    /// Period runtime (including any bounded idle borrowing) is exhausted.
    PeriodExhausted,
}

impl BudgetAccount {
    pub const fn new() -> Self {
        Self {
            cycles_spent: 0,
            overruns: 0,
            polls: 0,
            donated_in: 0,
            donated_out: 0,
            period_start_cycles: 0,
            replenish_at_cycles: 0,
            runtime_remaining_cycles: 0,
            borrowed_cycles: 0,
            debt_cycles: 0,
        }
    }

    /// Pure snapshot for policy. Replenishment that is due is reflected in the
    /// returned value without mutating the core-owned account.
    pub fn view(&self, now: u64, budget: &ResourceBudget) -> BudgetView {
        let Some(period) = budget.period else {
            return BudgetView {
                eligibility: BudgetEligibility::Eligible,
                remaining_cycles: u64::MAX,
                replenish_at_cycles: None,
                borrowed_cycles: 0,
                debt_cycles: self.debt_cycles,
            };
        };

        let uninitialised = self.replenish_at_cycles == 0;
        let due = !uninitialised && now >= self.replenish_at_cycles;
        let (remaining, replenish_at, borrowed, debt) = if uninitialised {
            (
                period.runtime_cycles,
                now.saturating_add(period.period_cycles),
                0,
                self.debt_cycles,
            )
        } else if due {
            let periods = now
                .saturating_sub(self.replenish_at_cycles)
                .checked_div(period.period_cycles)
                .unwrap_or(0)
                .saturating_add(1);
            let prior_capacity = period
                .runtime_cycles
                .saturating_mul(periods.saturating_sub(1));
            let debt_at_current = self.debt_cycles.saturating_sub(prior_capacity);
            let payment = period.runtime_cycles.min(debt_at_current);
            (
                period.runtime_cycles - payment,
                self.replenish_at_cycles
                    .saturating_add(period.period_cycles.saturating_mul(periods)),
                0,
                debt_at_current - payment,
            )
        } else {
            (
                self.runtime_remaining_cycles,
                self.replenish_at_cycles,
                self.borrowed_cycles,
                self.debt_cycles,
            )
        };

        let eligibility = if remaining > 0 {
            BudgetEligibility::Eligible
        } else if period.exhaustion == ExhaustionPolicy::IdleBorrow
            && borrowed < period.max_borrow_cycles
        {
            BudgetEligibility::Borrowable
        } else {
            BudgetEligibility::Throttled
        };
        BudgetView {
            eligibility,
            remaining_cycles: remaining,
            replenish_at_cycles: Some(replenish_at),
            borrowed_cycles: borrowed,
            debt_cycles: debt,
        }
    }

    /// Apply a due replenishment and return the dispatch-time view.
    pub fn prepare(&mut self, now: u64, budget: &ResourceBudget) -> BudgetView {
        let view = self.view(now, budget);
        if budget.period.is_some() {
            let replenish_at = view.replenish_at_cycles.unwrap_or(0);
            if self.replenish_at_cycles == 0 || now >= self.replenish_at_cycles {
                let period = budget.period.expect("period checked above");
                self.period_start_cycles = replenish_at.saturating_sub(period.period_cycles);
                self.replenish_at_cycles = replenish_at;
                self.runtime_remaining_cycles = view.remaining_cycles;
                self.borrowed_cycles = view.borrowed_cycles;
                self.debt_cycles = view.debt_cycles;
            }
        }
        view
    }

    /// Charge elapsed runtime to the active period. `allow_borrow` is decided
    /// by the core after proving that no regular candidate was eligible.
    pub fn charge_period(
        &mut self,
        cycles: u64,
        budget: &ResourceBudget,
        allow_borrow: bool,
    ) -> ChargeOutcome {
        let Some(period) = budget.period else {
            return ChargeOutcome::Continue;
        };
        let regular = cycles.min(self.runtime_remaining_cycles);
        self.runtime_remaining_cycles -= regular;
        let excess = cycles - regular;
        if excess == 0 {
            return ChargeOutcome::Continue;
        }
        if allow_borrow && period.exhaustion == ExhaustionPolicy::IdleBorrow {
            let available = period
                .max_borrow_cycles
                .saturating_sub(self.borrowed_cycles);
            let borrowed = excess.min(available);
            self.borrowed_cycles = self.borrowed_cycles.saturating_add(borrowed);
            self.debt_cycles = self.debt_cycles.saturating_add(borrowed);
            if borrowed == excess {
                return ChargeOutcome::Continue;
            }
            self.debt_cycles = self
                .debt_cycles
                .saturating_add(excess.saturating_sub(borrowed));
        } else {
            // Cooperative/non-preemptible work can overshoot a hard boundary.
            // Preserve the consumed CPU as debt so the next replenishment pays
            // it back instead of silently minting runtime.
            self.debt_cycles = self.debt_cycles.saturating_add(excess);
        }
        ChargeOutcome::PeriodExhausted
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
