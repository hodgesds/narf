//! CPU affinity types.
//!
//! Spec: `scheduler/specification/spec.md` §3.3. Stage-3 scope on the
//! single-CPU executor is purely structural: the types are real, but
//! the executor has only one CPU so every `CpuSet` trivially contains
//! the running CPU. Stage-4's SMP-capable run loop will use
//! `Affinity.allowed` as a hard constraint and `Affinity.preferred`
//! as a hint during work-stealing.

/// Single-CPU stand-in for `CpuId`. Stage 4 will widen this to match
/// the platform's topology ID space.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuId(pub u32);

impl CpuId {
    pub const BOOT: CpuId = CpuId(0);
}

/// Bit-set of permitted CPUs. Up to 64 CPUs fit inline without an
/// allocation; that covers every current NARF target.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuSet(u64);

impl CpuSet {
    /// Empty set — no CPU is permitted.
    pub const EMPTY: CpuSet = CpuSet(0);
    /// Every CPU permitted.
    pub const ALL: CpuSet = CpuSet(!0);

    /// Single-CPU set.
    #[inline]
    pub const fn single(cpu: CpuId) -> Self {
        CpuSet(1u64 << (cpu.0 & 0x3F))
    }

    #[inline]
    pub const fn contains(&self, cpu: CpuId) -> bool {
        self.0 & (1u64 << (cpu.0 & 0x3F)) != 0
    }

    #[inline]
    pub fn insert(&mut self, cpu: CpuId) {
        self.0 |= 1u64 << (cpu.0 & 0x3F);
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Count of CPUs in the set.
    #[inline]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }
}

/// Affinity hint. `allowed` is a hard constraint (work-stealing
/// respects it); `preferred` is a soft hint the executor honours when
/// possible.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Affinity {
    pub allowed: CpuSet,
    pub preferred: Option<CpuId>,
}

impl Affinity {
    /// Any CPU is OK.
    pub const fn any() -> Self {
        Self {
            allowed: CpuSet::ALL,
            preferred: None,
        }
    }

    /// Pin to a single CPU. Stage 4 enforces this through
    /// `Cap<CpuAffinity, Pin>` per spec §3.3 — the type here is
    /// permissive and the cap gate will land with the spawn-site
    /// integration.
    pub const fn pinned(cpu: CpuId) -> Self {
        Self {
            allowed: CpuSet::single(cpu),
            preferred: Some(cpu),
        }
    }
}

impl Default for Affinity {
    fn default() -> Self {
        Self::any()
    }
}
