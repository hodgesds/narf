//! Task priority + scheduling class.
//!
//! Spec: `scheduler/specification/spec.md` §3.3 + §3.4.
//! Stage-4 structural surface — the single-CPU executor does not yet
//! act on priority, but the type discipline means task specs can
//! carry their policy forward so the SMP dispatcher has a stable
//! interface when it lands.

/// Scheduling class for a task. A `RealTime` task with a
/// `ResourceBudget::deadline_cycles` receives strict earliest-deadline-
/// first service from the Stage-4 dispatcher; `Normal` is work-preserving
/// fair-share; `Idle` runs only when no other class has a runnable task.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SchedClass {
    #[default]
    Normal,
    RealTime,
    Idle,
}

/// Nice-style priority within a scheduling class. `0` is the default;
/// negative values increase priority, positive values decrease it.
/// Stage-4 uses this to break ties inside a class.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub i8);

impl Priority {
    pub const HIGH: Priority = Priority(-10);
    pub const NORMAL: Priority = Priority(0);
    pub const LOW: Priority = Priority(10);

    #[inline]
    pub const fn raw(self) -> i8 {
        self.0
    }
}

/// SMT-sharing policy (spec §3.3). Stage-4 governor consults this
/// when placing tasks on SMT-sibling cores. Kept here so `TaskSpec`
/// can carry a policy that will be acted on later without a surface
/// break.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SmtSharePolicy {
    /// Don't co-schedule with sibling threads — the classic avoid
    /// path when LLC contention would hurt p99 latency.
    #[default]
    Avoid,
    /// Ambivalent — placer decides.
    Allow,
    /// Opt-in to sibling co-scheduling (latency-sensitive driver
    /// pairs that benefit from sharing the LLC).
    Require,
}
