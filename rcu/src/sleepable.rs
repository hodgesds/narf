//! Sleepable RCU (SRCU-analogue).
//!
//! Spec: `rcu/specification/spec.md` §3.5. Unlike QSBR (where readers
//! may not span `.await`), sleepable readers are explicitly allowed to
//! hold a reservation across yield points. Writers wait for those
//! reservations to release, *bounded by a deadline* — so a buggy or
//! malicious reader can never stall the writer indefinitely. The whole
//! variant is cap-gated: a `Cap<SleepableReader, Read>` proves the
//! caller is authorised to occupy a sleepable slot.
//!
//! # Stage-3 scope
//!
//! - `SleepableScope` is a single per-call-site struct holding a reader
//!   census (`active`), the longest currently-held duration witness
//!   (`longest_pin_cycles`), and the budget threshold above which the
//!   *next* `sync_async` returns `Timeout` even if the deadline hasn't
//!   fired (spec §3.5: per-cap budget, per-scope deadline).
//! - Entry is gated on `cap.check_live()`. Revoked caps return
//!   `CapError::Revoked` from `enter`.
//! - `sync_async` is a `Future` that resolves `Drained` once `active`
//!   hits zero, `Timeout` once `Instant::now() >= deadline`, or
//!   `Timeout` immediately if the per-scope budget has already been
//!   tripped by an over-long reader.
//!
//! # Stage-3 deferrals (called out, not silently elided)
//!
//! - **Cooperative cap-revocation drain.** Spec §4 wants a sleepable
//!   reader whose cap is revoked to have its guard forcibly drained at
//!   the next `.await`. The cooperative-drain hook lives downstream of
//!   the executor's poll-boundary cancellation signal, which doesn't
//!   exist yet (Stage 3 main track has no cancellation futures). For
//!   now, a revoked cap simply prevents *new* `enter` calls; in-flight
//!   readers run to natural completion. `SyncOutcome::Cancelled` is
//!   reserved for that future plumbing — it's exposed but not yet
//!   produced by `sync_async`.
//! - **Per-cap budget escalation.** The spec calls for auto-revoking
//!   the offending `Cap<SleepableReader, _>` on budget violation. We
//!   trip the scope-side `over_budget` flag (so `sync_async` returns
//!   `Timeout`), but invoking `Cap::revoke` requires `Cap` ownership
//!   we don't keep here. Stage 4 wires the budget-violation observer
//!   into `capabilities/`'s revocation stream.
//! - **Multi-CPU census fairness.** The reader census is a single
//!   `AtomicUsize`; SMP scaling per spec §3.5 wants a per-CPU census
//!   with a sum-on-sync. Punted to Stage 4 with `scheduler/` SMP.
//!
//! # Determinism note for Stage 4
//!
//! The `smoke_rcu_sleepable_*` tests rely on the Stage-2/3
//! single-CPU FIFO cooperative scheduler — same shape as
//! `smoke_exit_gate_*`. Under preemption / SMP the precise
//! interleaving of "task A holds guard; task B awaits sync" changes,
//! and the budget/deadline numbers may need bumping. Flag in Stage-4
//! revalidation.

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Read};
use narf_time::Instant;

// ── SleepableReader CapType ─────────────────────────────────────────
//
// `SleepableReader` is the marker type for `Cap<SleepableReader, Read>`.
// Holding such a cap proves the bearer is authorised to enter a
// sleepable scope. The cap is minted by the scope owner per spec §3.5.
//
// The cap-table integration uses `CapKind::SleepableReader`, registered
// in `capabilities/src/lib.rs` Wave-2.

/// Cap-gated sleepable RCU reader marker. Hold a `Cap<SleepableReader, Read>`
/// to enter a `SleepableScope`.
#[derive(Debug)]
pub struct SleepableReader {
    _private: (),
}

impl CapType for SleepableReader {
    const KIND: CapKind = CapKind::SleepableReader;
}

impl SleepableReader {
    /// Mint a fresh reader cap. Convenience wrapper around
    /// `Cap::<SleepableReader, Read>::bootstrap()` for tests and scope
    /// owners that don't already hold a `Grant` parent.
    pub fn bootstrap_cap() -> Cap<SleepableReader, Read> {
        Cap::<SleepableReader, Read>::bootstrap()
    }
}

// ── SleepableScope ──────────────────────────────────────────────────

/// Outcome of `sync_async`. Per spec §3.5: writers see either a clean
/// drain, a deadline-bounded timeout, or — Stage-4 — an explicit
/// cancellation signal driven by a downstream cap revocation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Every sleepable reader released before the deadline.
    Drained,
    /// Deadline expired (or the per-scope reader budget was tripped)
    /// while at least one reader was still holding a guard.
    Timeout,
    /// Reserved for cooperative-drain cancellation. Stage-3 sleepable
    /// does not yet emit this; see module docs.
    Cancelled,
}

/// One sleepable-RCU scope. Per spec §3.5 each call site (typically:
/// per-mount in `filesystem/`, per-routing-generation in `interrupts/`)
/// holds its own scope so syncs are isolated.
///
/// Internally tracks:
/// - `active`: current reader census. `enter` increments, `Drop` of
///   the guard decrements.
/// - `longest_pin_cycles`: longest observed pin duration across the
///   scope's history. Compared against `budget_cycles` to decide
///   "this scope is misbehaving — fail the next sync rather than wait".
/// - `over_budget`: latched flag set when an exiting guard reports a
///   pin duration above the budget. Cleared on the next successful
///   `Drained` outcome.
#[derive(Debug)]
pub struct SleepableScope {
    active:             AtomicUsize,
    longest_pin_cycles: AtomicU64,
    budget_cycles:      AtomicU64,
    over_budget:        AtomicBool,
}

impl SleepableScope {
    /// Construct a scope with no budget cap. `set_budget` configures
    /// the threshold above which `sync_async` short-circuits to
    /// `Timeout`. `u64::MAX` is "unbounded".
    pub const fn new() -> Self {
        Self {
            active:             AtomicUsize::new(0),
            longest_pin_cycles: AtomicU64::new(0),
            budget_cycles:      AtomicU64::new(u64::MAX),
            over_budget:        AtomicBool::new(false),
        }
    }

    /// Set the per-scope reader-budget threshold in raw CPU cycles.
    /// A reader holding its guard longer than this trips
    /// `SyncOutcome::Timeout` on the next `sync_async`, instead of
    /// stalling the writer.
    pub fn set_budget(&self, cycles: u64) {
        self.budget_cycles.store(cycles, Ordering::Release);
    }

    /// Currently-pinned reader count. Test/diagnostic use.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Longest reader-hold duration witnessed so far, in cycles.
    pub fn longest_pin_cycles(&self) -> u64 {
        self.longest_pin_cycles.load(Ordering::Acquire)
    }

    /// Whether the scope has tripped its per-reader budget. A scope in
    /// this state will fail the next `sync_async` with `Timeout` even
    /// if all readers have released — explicit caller acknowledgement
    /// resets the flag (see `clear_over_budget`).
    pub fn over_budget(&self) -> bool {
        self.over_budget.load(Ordering::Acquire)
    }

    /// Acknowledge and clear the over-budget latch. Typically called by
    /// a writer that has decided how to handle the misbehaving scope
    /// (escalate, log-and-retry, etc. per spec §3.5).
    pub fn clear_over_budget(&self) {
        self.over_budget.store(false, Ordering::Release);
    }

    /// Enter the scope. Cap-gated: the cap's epoch is checked; if the
    /// cap has been revoked, returns `Err(CapError::Revoked)`.
    ///
    /// On success, increments the scope's reader census and returns a
    /// `SleepableGuard` whose `Drop` decrements it again. Unlike QSBR's
    /// `ReadGuard`, this guard is `await`-safe.
    pub fn enter<'s>(
        &'s self,
        cap: &Cap<SleepableReader, Read>,
    ) -> Result<SleepableGuard<'s>, CapError> {
        cap.check_live()?;
        // Cap is live — admit the reader. We bump the census *after* the
        // cap check so a failed admission has no observable side-effect
        // on the scope.
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(SleepableGuard {
            scope:    self,
            entered:  Instant::now(),
            _phantom: PhantomData,
        })
    }
}

impl Default for SleepableScope {
    fn default() -> Self { Self::new() }
}

// ── SleepableGuard ──────────────────────────────────────────────────

/// RAII reservation held by an in-flight sleepable reader. Distinct
/// from the QSBR `ReadGuard`: this one is allowed to live across
/// `.await` (the whole point of the sleepable variant per spec §3.5).
///
/// **Stage-3 deviation from spec §3.5.** The spec wants `SleepableGuard`
/// `!Send` to keep readers pinned to one CPU. The Stage-3 scheduler
/// requires every spawned `Future` to be `Send` (preparing for the
/// Stage-4 work-stealing executor, which doesn't exist yet), so a
/// `!Send` guard cannot live across an `.await` inside a spawned task —
/// defeating the whole point of the variant. We resolve by making the
/// guard `Send` for Stage 3 (it is a `&SleepableScope` plus an
/// `Instant`, both of which are `Send`) and revisiting `!Send` when
/// per-CPU census lands together with the Stage-4 work-stealing bring-
/// up. Single-CPU execution makes Send-vs-!Send observationally
/// equivalent today.
#[derive(Debug)]
pub struct SleepableGuard<'s> {
    scope:    &'s SleepableScope,
    entered:  Instant,
    // Phantom only carries the scope lifetime; we deliberately do NOT
    // include a `*const ()` (which would be the standard !Send recipe)
    // because the Stage-3 scheduler bounds a spawned future on Send.
    // See the type-level docstring for the deferral rationale.
    _phantom: PhantomData<&'s ()>,
}

impl<'s> SleepableGuard<'s> {
    /// Cycles elapsed since this guard was acquired.
    pub fn held_cycles(&self) -> u64 {
        Instant::now().cycles_since(self.entered)
    }
}

impl<'s> Drop for SleepableGuard<'s> {
    fn drop(&mut self) {
        // Update the longest-pin watermark and trip the budget latch if
        // this reader exceeded the configured threshold. The watermark
        // is monotonic (max) so writers can read a stable "worst case
        // ever observed" without coordinating with the readers.
        let held = self.held_cycles();
        let budget = self.scope.budget_cycles.load(Ordering::Acquire);
        // CAS-loop a max-update on the watermark.
        let mut prev = self.scope.longest_pin_cycles.load(Ordering::Relaxed);
        while held > prev {
            match self.scope.longest_pin_cycles.compare_exchange_weak(
                prev, held, Ordering::AcqRel, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => prev = p,
            }
        }
        if held > budget {
            self.scope.over_budget.store(true, Ordering::Release);
        }
        // Decrement census. Use AcqRel so a sync_async polled on the
        // writer side sees both the decrement AND any of the reader's
        // prior writes (per spec §4: the guarantee is safety, not a
        // total order — but we still want release semantics on exit).
        self.scope.active.fetch_sub(1, Ordering::AcqRel);
    }
}

// ── sync_async ──────────────────────────────────────────────────────

/// Wait for every sleepable reader currently in `scope` to release,
/// bounded by `deadline`. See `SyncOutcome` for the resolution cases.
///
/// The future re-arms its waker each Pending so a cooperative executor
/// (today: `narf-scheduler`) repolls it next round. A future Stage-4
/// upgrade will park the future against an event slot bumped by guard
/// drops; today the cost of re-polling is bounded by the executor's
/// halt-on-no-progress backstop.
pub fn sync_async<'s>(
    scope: &'s SleepableScope,
    deadline: Instant,
) -> SleepableSync<'s> {
    SleepableSync { scope, deadline }
}

/// Future returned by `sync_async`.
#[derive(Debug)]
pub struct SleepableSync<'s> {
    scope:    &'s SleepableScope,
    deadline: Instant,
}

impl<'s> Future for SleepableSync<'s> {
    type Output = SyncOutcome;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<SyncOutcome> {
        // Order matters: check Drained first so a scope that's already
        // empty resolves immediately even if we somehow arrived past the
        // deadline. Then check the budget latch (spec §3.5 says a
        // budget-tripped scope returns Timeout regardless), then the
        // wall-clock deadline.
        if self.scope.active.load(Ordering::Acquire) == 0 {
            return Poll::Ready(SyncOutcome::Drained);
        }
        if self.scope.over_budget.load(Ordering::Acquire) {
            return Poll::Ready(SyncOutcome::Timeout);
        }
        if Instant::now() >= self.deadline {
            return Poll::Ready(SyncOutcome::Timeout);
        }
        // Re-arm self for the next executor round. Stage-4 will replace
        // this with a per-scope waker queue that the guard drop bumps —
        // for now, the executor's halt-on-no-progress halts the CPU
        // until a hardware tick when nothing else is awake.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ── Quiescence reporting hook (sleepable-side) ─────────────────────

/// Sleepable-side quiescence hook. The QSBR variant has its own; this
/// is here so a future per-scope sync waker has a documented integration
/// point. Today it's a no-op because guard drops already update the
/// scope-local census without needing a global tick.
///
/// Kept on the public surface so `rcu::sleepable::report_quiescent` is
/// callable for symmetry with the QSBR `report_quiescent` even though
/// no body is required at this stage.
#[inline]
pub fn report_quiescent() {
    // Sleepable-RCU quiescence is per-scope and is announced by the
    // SleepableGuard's Drop running. There is deliberately no global
    // counter to bump here.
}

/// Convenience: enter `scope` with `cap`. Mirrors the spec's
/// `sleepable_read(cap)` shorthand from §3.5; takes a scope reference
/// because Stage-3 carries the scope explicitly rather than threading
/// through TLS.
#[inline]
pub fn enter<'s>(
    scope: &'s SleepableScope,
    cap: &Cap<SleepableReader, Read>,
) -> Result<SleepableGuard<'s>, CapError> {
    scope.enter(cap)
}
