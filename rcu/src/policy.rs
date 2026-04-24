//! Reclamation-policy selection.
//!
//! Spec: `rcu/specification/spec.md` §3.2. Consumers pick a variant per
//! call site; NARF's defaults are tabulated in the spec. The concrete
//! collector per policy is a Stage-4 tuning target — Stage-2 wires QSBR
//! as the global default and exposes Epoch as an opt-in.

/// Which reclamation strategy a data structure uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReclamationPolicy {
    /// Quiescent-state-based — readers are free, writers wait for every
    /// CPU to pass a poll boundary. The default hot-path variant.
    Qsbr,
    /// crossbeam-style per-reader epoch snapshot. Used where the poll-
    /// boundary assumption doesn't hold (e.g. IRQ-handler context).
    Epoch,
    /// Hazard-pointer — bounded reclamation latency, higher read-side
    /// cost. Stage-3 stub in this crate.
    Hazard,
    /// Sleepable (SRCU-analogue) — readers may `await`. Cap-gated;
    /// Stage-3 stub in this crate.
    Sleepable,
}

impl ReclamationPolicy {
    /// Whether readers under this policy may hold a guard across an
    /// `.await`. Only `Sleepable` permits it — consult `rcu/` §3.3.
    pub const fn allows_await(&self) -> bool {
        matches!(self, ReclamationPolicy::Sleepable)
    }
}
