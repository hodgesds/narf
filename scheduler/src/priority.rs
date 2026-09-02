//! Task priority + scheduling class.
//!
//! Spec: `scheduler/specification/spec.md` §3.3 + §3.4.
//! The default `ClassScheduler` applies strict inter-class order and uses
//! `Priority` within a class. Alternative policies receive these values as
//! read-only metadata through the public policy interface.

/// Linux-like scheduling-class order. Inter-class dispatch is strict:
/// `Realtime` outranks `Interactive`, then `Default`, `Batch`, and `Idle`.
/// Policy implementations may replace the ordering algorithm, but the core
/// retains task ownership, eligibility checks, and context switching.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SchedClass {
    Idle,
    Batch,
    #[default]
    Default,
    Interactive,
    Realtime,
}

/// Kind of execution being accounted. This is descriptive scheduling
/// metadata, not authority: the core assigns/validates attribution and charges
/// hard-IRQ time outside the schedulable task model.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum WorkKind {
    UserThread,
    KernelThread,
    #[default]
    AsyncTask,
    SoftIrq,
    Idle,
}

impl SchedClass {
    /// Compatibility spelling retained for existing callers.
    #[allow(non_upper_case_globals)]
    pub const Normal: Self = Self::Default;
    /// Compatibility spelling retained for existing callers.
    #[allow(non_upper_case_globals)]
    pub const RealTime: Self = Self::Realtime;

    /// Strict inter-class ordering used by [`crate::ClassScheduler`].
    #[inline]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Batch => 1,
            Self::Default => 2,
            Self::Interactive => 3,
            Self::Realtime => 4,
        }
    }

    /// Inverse of [`rank`](Self::rank): reconstruct a class from its rank. Used
    /// to rehydrate a class published as a compact rank in the per-CPU running
    /// snapshot (`CurrentTask`). An out-of-range rank maps to `Default`.
    #[inline]
    pub const fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Self::Idle,
            1 => Self::Batch,
            3 => Self::Interactive,
            4 => Self::Realtime,
            _ => Self::Default,
        }
    }
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
