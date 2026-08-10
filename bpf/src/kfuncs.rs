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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::percpu::{current_cpu, MAX_CPUS};

use crate::types::{fnv1a32_nonzero, TraceFieldOffset, TraceSource};

/// XDP redirect target, one slot per CPU.
///
/// `bpf_redirect` has no writable context word to convey the target ifindex
/// through — the XDP frame is read-only (see `attach_xdp.rs`). Instead it
/// stashes the ifindex here and the classifier reads it back when the program
/// returns `XDP_REDIRECT` (4). A per-CPU slot rather than one global cell
/// because an XDP program runs with IRQs masked (`run_xdp` holds `XDP_PROGS`,
/// an `IrqSafeSpinLock`), so between the `bpf_redirect` call and the
/// classifier's read the running CPU cannot change and no other frame on this
/// CPU can overwrite the slot. `+1` biasing distinguishes "no redirect
/// requested" (0) from "redirect to ifindex 0"; the classifier only consults
/// the slot on a return of 4, so a stale value from a prior frame is never
/// mistaken for a live request.
static XDP_REDIRECT_TARGET: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Read and clear the current CPU's pending XDP redirect target.
///
/// Returns the ifindex a `bpf_redirect` on this CPU stashed, or `None` if the
/// program requested no redirect. Called by the classifier immediately after
/// an XDP program returns 4, on the same CPU with IRQs still masked, so the
/// read pairs with the store the program made a few instructions earlier.
#[must_use]
pub fn take_xdp_redirect_target() -> Option<u32> {
    let slot = &XDP_REDIRECT_TARGET[current_cpu()];
    match slot.swap(0, Ordering::Relaxed) {
        0 => None,
        biased => Some(biased - 1),
    }
}

/// Drop any stale redirect target on the current CPU.
///
/// Called before running an XDP program so a `bpf_redirect` from a *previous*
/// frame that then returned a non-redirect action cannot leak into this one.
pub fn clear_xdp_redirect_target() {
    XDP_REDIRECT_TARGET[current_cpu()].store(0, Ordering::Relaxed);
}

/// Record `ifindex` as this CPU's pending XDP redirect target.
///
/// The shared write both [`bpf_redirect`] and `bpf_redirect_map` make: it
/// `+1`-biases the value so a real ifindex of 0 stays distinct from the "no
/// request" sentinel [`clear_xdp_redirect_target`] leaves, and
/// [`take_xdp_redirect_target`] un-biases on read. Called on the same CPU with
/// IRQs masked (the caller holds `XDP_PROGS`), so the store pairs with the
/// classifier's read a few instructions later.
pub fn set_xdp_redirect_target(ifindex: u32) {
    XDP_REDIRECT_TARGET[current_cpu()].store(ifindex.wrapping_add(1), Ordering::Relaxed);
}

/// The kfunc id of `bpf_xdp_adjust_head`, for the interpreter's interception
/// and the JIT's refusal. Derived from the name exactly as the registry's ids
/// are, so the two cannot drift.
pub const XDP_ADJUST_HEAD_ID: i32 = fnv1a32_nonzero("bpf_xdp_adjust_head") as i32;
/// The kfunc id of `bpf_xdp_adjust_tail`.
pub const XDP_ADJUST_TAIL_ID: i32 = fnv1a32_nonzero("bpf_xdp_adjust_tail") as i32;

/// Whether `id` names one of the XDP frame-resizing interpreter intrinsics.
///
/// Both `bpf_xdp_adjust_head`/`_tail` move the packet window inside the VM's
/// staged frame buffer, which native code has no handle on. The JIT refuses any
/// program that calls one (as it does the ring-buffer intrinsics), so such a
/// program runs interpreted and the interpreter intercepts the id.
#[must_use]
pub fn is_xdp_adjust(id: i32) -> bool {
    id == XDP_ADJUST_HEAD_ID || id == XDP_ADJUST_TAIL_ID
}

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

    /// Request that the current XDP frame be redirected out interface `ifindex`.
    ///
    /// Models Linux's `bpf_redirect(ifindex, flags)` helper. The frame is
    /// read-only, so there is no writable context word to carry the target
    /// through; instead the ifindex is stashed in a per-CPU slot that the
    /// classifier consults when the program returns `XDP_REDIRECT` (4). The
    /// program itself still has to return 4 for the redirect to take effect —
    /// this kfunc only records *where*. Returns `XDP_REDIRECT` so a program may
    /// `return bpf_redirect(n, 0)` directly, matching Linux, where the helper's
    /// return value is the action the program is expected to propagate.
    ///
    /// `flags` is accepted for Linux source compatibility and currently
    /// ignored: `BPF_F_BROADCAST`/`BPF_F_EXCLUDE_INGRESS` need devmap *fan-out*
    /// (one frame to many ports), which is a further step beyond the single-port
    /// `bpf_redirect_map` (see `crate::map`).
    #[context(Atomic)]
    pub fn bpf_redirect(ifindex: u32, _flags: u64) -> u64 {
        set_xdp_redirect_target(ifindex);
        // XDP_REDIRECT.
        4
    }

    /// Move the XDP frame's `data` pointer by `delta` bytes — the
    /// `bpf_xdp_adjust_head(ctx, delta)` shape.
    ///
    /// `delta > 0` shrinks the packet from the front (removes `delta` header
    /// bytes: `data += delta`); `delta < 0` grows it, prepending `|delta|` bytes
    /// of headroom (`data -= |delta|`). The new `data` must stay within the
    /// staged frame buffer and at or below `data_end`. Returns `0` on success or
    /// `-ENOMEM` when there is no room, in which case `data` is left unmoved
    /// (fail-closed). The kfunc writes the new `data` back into `ctx[0]` and
    /// re-bases the packet window, so the program re-reads the moved pointer on
    /// its next `*(ctx+0)` load — and the verifier drops every proven packet
    /// bound at this call, forcing a fresh `data < data_end` before the next
    /// access.
    ///
    /// This body is unreachable: the interpreter intercepts the call and
    /// mutates the VM's context words and packet window directly, because in the
    /// interpreter the context is synthetic (see [`XDP_ADJUST_HEAD_ID`] and
    /// `crate::interp`). It declines with `-ENOMEM` rather than panicking, so a
    /// bypassed interception fails closed.
    #[context(Atomic)]
    pub fn bpf_xdp_adjust_head(ctx: crate::types::XdpCtx, delta: i32) -> i64 {
        let _ = (ctx, delta);
        -12 // -ENOMEM
    }

    /// Move the XDP frame's `data_end` pointer by `delta` bytes — the
    /// `bpf_xdp_adjust_tail(ctx, delta)` shape.
    ///
    /// `delta > 0` grows the packet, appending `delta` bytes of tailroom;
    /// `delta < 0` shrinks it (`data_end += delta`). The new `data_end` must
    /// stay at or above `data` and within the staged frame buffer. Returns `0`
    /// on success or `-ENOMEM` when there is no room, leaving `data_end` unmoved.
    /// Writes the new `data_end` back into `ctx[1]` and re-bases the packet
    /// window; the verifier drops every proven packet bound at the call.
    ///
    /// Interpreter intrinsic, as [`bpf_xdp_adjust_head`]; this body never runs.
    #[context(Atomic)]
    pub fn bpf_xdp_adjust_tail(ctx: crate::types::XdpCtx, delta: i32) -> i64 {
        let _ = (ctx, delta);
        -12 // -ENOMEM
    }

    /// Copy one declared field from the current typed tracing object.
    ///
    /// The verifier requires `offset` and `dst.len()` to exactly match the
    /// schema attached to the program. The live wrapper checks both again so
    /// verifier unsoundness cannot widen this into an arbitrary kernel read.
    #[context(Atomic)]
    pub fn narf_probe_read(
        dst: &mut [u8],
        _dst_len: u64,
        source: TraceSource,
        offset: TraceFieldOffset,
    ) -> i64 {
        // SAFETY: this kfunc can only receive `TraceSource` from a program
        // entered through `BpfProg::run_typed_probe`; public raw-context entry
        // points decline typed programs before interpreting or entering JIT.
        if unsafe { source.copy_field(offset.get(), dst) } {
            0
        } else {
            -22 // EINVAL: runtime schema or object-bound mismatch.
        }
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
