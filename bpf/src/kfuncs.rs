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

/// Scratch counters, kept after `crate::map` landed.
///
/// Sixteen `AtomicU64`s, no allocation, no locking. `PerCpuArray` supersedes
/// them for anything a program wants to *keep* — it is created by userspace,
/// read back through `bpf(2)`, and sized by the caller — but these need no map
/// to exist, so they stay as what the interpreter and probe-attach smokes
/// observe an effect through. Deliberately still a counter array and not a map
/// implementation in disguise.
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

}

// ── test-only kfuncs ────────────────────────────────────────────────
//
// Compiled only under `kernel-test`, so a production kernel cannot name them.
// They exist because no *production* kfunc makes a calling convention
// observable from a BPF program: `narf_counter_add` and `narf_counter_read`
// take two arguments and one respectively, so neither the R4/R5 shuffle nor
// the callee's stack alignment shows up in any comparison against the
// interpreter — and `narf_counter_add` has a side effect, so running the same
// program twice (once JITed, once interpreted) does not even return the same
// value. Both of these are pure, which is what a differential comparison
// requires; one is five arguments wide and the other reports the callee's own
// stack alignment.
#[cfg(feature = "kernel-test")]
crate::kfunc! {
    /// Combine all five argument registers, distinguishably.
    ///
    /// Distinct odd multipliers, so *any* permutation of distinct arguments
    /// gives a different answer. That is the property that makes the
    /// interpreter a real oracle for the JIT's argument shuffling: swapping R4
    /// and R5, or dropping one and passing another twice, changes the result
    /// rather than happening to agree. Wrapping arithmetic, so no input traps.
    #[context(Atomic)]
    pub fn narf_test_arg_mix(a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
        a.wrapping_add(b.wrapping_mul(3))
            .wrapping_add(c.wrapping_mul(5))
            .wrapping_add(d.wrapping_mul(7))
            .wrapping_add(e.wrapping_mul(11))
    }

    /// This shim's own stack alignment, as a residue mod 16.
    ///
    /// A local's address is a fixed offset from the stack pointer the shim was
    /// entered with, so the residue is a pure function of the *caller's*
    /// alignment at the call instruction. It means nothing on its own — nobody
    /// knows what that fixed offset is — and everything when compared between
    /// callers: the interpreter enters the shim from ordinary Rust, where the
    /// ABI's alignment rule holds by construction, so a JIT whose `call` is
    /// eight bytes out returns a different residue and the differential harness
    /// says so.
    ///
    /// Worth the indirection because the failure it catches is otherwise
    /// invisible from BPF: a misaligned SysV call does not fault at the call,
    /// it faults on the first aligned SSE spill somewhere inside a callee that
    /// has nothing to do with BPF.
    #[context(Atomic)]
    pub fn narf_test_stack_residue() -> u64 {
        let probe: u64 = 0;
        (core::ptr::addr_of!(probe) as u64) & 0xF
    }
}

// A separate `kfunc!` invocation: every item in one invocation must match the
// same rule, and this one is the sleepable (`async fn`) form.
crate::kfunc! {
    /// Yield to the scheduler. Sleepable programs only.
    ///
    /// Yielding does **not** refill fuel (§4.9): fuel bounds total work, and
    /// yielding only lets other tasks interleave. Keeping them orthogonal is
    /// what makes a long iterator walk cooperative rather than either
    /// CPU-hogging or fuel-fatal.
    ///
    /// Unlike every other kfunc here this one is `async`, which is the whole
    /// declaration: `kfunc!`'s sleepable rule derives
    /// [`Context::Sleepable`](narf_bpf_verifier::kfunc::Context) from the
    /// keyword, so there is no attribute to forget and no way to declare an
    /// awaiting kfunc as atomic.
    ///
    /// It was previously an interpreter intrinsic with a dead body, because a
    /// uniform `u64`-returning shim had nowhere to put a suspension. Now it is
    /// an ordinary kfunc, and so can any other sleepable one be.
    pub async fn narf_yield() -> u64 {
        crate::interp::yield_now().await;
        0
    }

    /// Yield `n` times, returning the number of yields performed.
    ///
    /// Exists to prove the sleepable ABI generalises: `narf_yield` suspends at
    /// most once, so on its own it could be satisfied by a shim that returned
    /// `Pending` a single time. This one suspends an argument-dependent number
    /// of times, which only a real future can do — and it is the shape a
    /// blocking kfunc (a filesystem walk, an iterator drain) would take.
    ///
    /// Capped so a program cannot turn one call into an unbounded stall; the
    /// caller's fuel is not consumed by the suspension itself, so the cap is
    /// the only bound here.
    pub async fn narf_yield_n(n: u32) -> u64 {
        let count = n.min(64);
        for _ in 0..count {
            crate::interp::yield_now().await;
        }
        u64::from(count)
    }
}
