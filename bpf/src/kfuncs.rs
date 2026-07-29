//! The starter kfunc set.
//!
//! Deliberately tiny. Every kfunc is reachable from a probe site, which per
//! `bpf/specification/spec.md` §4.7 means it runs with IRQs masked and
//! `tracing::dispatch`'s `TABLE.inner` held — so the closed, audited list is
//! the safety property, not a convenience. In particular **nothing here may
//! call into `narf_tracing::dispatch::*`**: that is an instant self-deadlock.
//!
//! Invariant §4.6 applies to every one of them: no global allocator, no
//! `alloc_frame`, no lock a caller might already hold.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::types::fnv1a32_nonzero;

/// The `call` immediate for [`narf_yield`].
///
/// The interpreter intercepts this id rather than calling the shim, because
/// the uniform kfunc ABI returns a `u64` and a kfunc that awaits cannot go
/// through it. Computed here from the same hash the registry uses, so the two
/// cannot drift.
pub const YIELD_ID: i32 = fnv1a32_nonzero("narf_yield") as i32;

/// Scratch counters programs can bump before maps land in Phase 3.
///
/// Sixteen `AtomicU64`s, no allocation, no locking — which is exactly the
/// property `PerCpuArray` will need to preserve when it replaces this. Kept
/// deliberately small and boring so that "maps are Phase 3" stays true: this
/// is a counter array, not a map implementation in disguise.
const COUNTER_SLOTS: usize = 16;
static COUNTERS: [AtomicU64; COUNTER_SLOTS] = [const { AtomicU64::new(0) }; COUNTER_SLOTS];

/// Read one of the scratch counters from kernel code.
#[must_use]
pub fn counter(slot: usize) -> u64 {
    COUNTERS.get(slot).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// Zero one of the scratch counters. Used by the smokes to get a clean start.
pub fn reset_counter(slot: usize) {
    if let Some(c) = COUNTERS.get(slot) {
        c.store(0, Ordering::Relaxed);
    }
}

crate::kfunc! {
    /// Add `delta` to scratch counter `slot`, returning the pre-add value.
    ///
    /// Out-of-range slots return `u64::MAX` rather than trapping: a kfunc
    /// reports failure through its return value, because trapping the whole
    /// program for a bad argument would make every kfunc a potential
    /// termination point and the verifier's job correspondingly harder.
    #[context(Atomic)]
    pub fn narf_counter_add(slot: u32, delta: u64) -> u64 {
        match COUNTERS.get(slot as usize) {
            Some(c) => c.fetch_add(delta, Ordering::Relaxed),
            None => u64::MAX,
        }
    }

    /// Read scratch counter `slot`. Out-of-range slots read as `u64::MAX`.
    #[context(Atomic)]
    pub fn narf_counter_read(slot: u32) -> u64 {
        COUNTERS
            .get(slot as usize)
            .map_or(u64::MAX, |c| c.load(Ordering::Relaxed))
    }

    /// Yield to the scheduler. Sleepable programs only.
    ///
    /// Yielding does **not** refill fuel (§4.9): fuel bounds total work, and
    /// yielding only lets other tasks interleave. Keeping them orthogonal is
    /// what makes a long iterator walk cooperative rather than either
    /// CPU-hogging or fuel-fatal.
    ///
    /// The body here is never executed — the interpreter recognises
    /// [`YIELD_ID`] and awaits instead. It exists so the descriptor carries a
    /// real shim address (`KfuncDesc::validate` rejects a null one) and so the
    /// signature and context live in the same place as every other kfunc's.
    #[context(Sleepable)]
    pub fn narf_yield() -> u64 {
        0
    }
}
