//! # `narf-bpf-verifier` — BPF static verification
//!
//! Proves a BPF program memory-safe before it is allowed to run. Pure logic:
//! this crate has no kernel dependencies, contains no `unsafe`, and builds and
//! tests on the host.
//!
//! ## How it fits together
//!
//! | Module | Job |
//! |---|---|
//! | [`ir`] | decode → basic blocks → CFG, dominators, SCCs, call graph |
//! | [`domain`] | the numeric abstract domain: `tnum × signed interval` |
//! | [`state`] | registers, stack, typed pointers, live references |
//! | [`liveness`] | liveness and precision, as one lattice dataflow |
//! | [`fixpoint`] | the forward worklist and the transfer functions |
//! | [`kfunc`] | the one call ABI, with semantics carried by Rust types |
//!
//! [`verify`] runs all of it and returns a [`VerifiedProgram`]: the validated
//! image plus everything the JIT and the runtime need — peak stack across the
//! call graph, the fault sites needing exception-table coverage, subprogram
//! boundaries, and the initial fuel.
//!
//! Still unimplemented, and failing *closed* rather than guessing: the
//! `LD_IMM64` map and BTF pseudo-forms, which need registries `Program` does
//! not yet carry (maps are Phase 3), and callback subprogram addresses, which
//! need a callback-typed kfunc argument.
//!
//! ## Why this is a separate crate
//!
//! Linux's `kernel/bpf/verifier.c` is 26,199 lines and can only be exercised
//! by booting a kernel. Keeping NARF's verifier dependency-free means
//! `cargo test -p narf-bpf-verifier` can differentially fuzz every transfer
//! function against a concrete reference interpreter in seconds, on the host,
//! with no QEMU. For a component whose bugs are kernel-compromise bugs, that
//! is worth more than any amount of in-kernel testing.
//!
//! ## Design, in brief
//!
//! Full rationale in `bpf/specification/spec.md`; the load-bearing choices:
//!
//! * **Termination is a runtime property, not a verification one.** Every
//!   program runs with a fuel counter, so the verifier needs only a sound
//!   over-approximation that converges by widening — not a termination proof.
//!   That deletes Linux's instruction limit, state-count limits, and its five
//!   separate loop constructs, and makes acceptance a function of the program
//!   alone rather than of a search budget.
//! * **One numeric domain** (`tnum × signed interval`), not Linux's six
//!   overlapping ones with ~800 lines of pairwise deduction.
//! * **One call ABI**, with argument semantics carried by Rust types. See
//!   [`kfunc`].
//! * **Verify an IR, lower once.** Nothing here patches instructions in
//!   place, so there is no `delta` bookkeeping threaded through rewrite
//!   passes.
//! * **One rule for references, locks, and sleep safety.** At an await point,
//!   every value whose [`ValidityDomain`] fails `survives_await()` dies. That
//!   single rule is Linux's `REF_TYPE_LOCK`, `active_lock_id`,
//!   `process_spin_lock()`, `invalidate_non_owning_refs()`,
//!   `bpf_rcu_read_lock`, `KF_RCU_PROTECTED`, and `MEM_RCU` — see
//!   [`state::AbsState::kill_at_await`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

use narf_bpf_isa::{DecodeError, Insn};

pub mod domain;
pub mod fixpoint;
pub mod ir;
pub mod kfunc;
pub mod liveness;
pub mod state;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod interp;
#[cfg(test)]
mod ir_tests;
#[cfg(test)]
mod liveness_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod verify_tests;

pub use kfunc::{
    ArgDesc, ArgFlags, Context, KfuncDesc, KfuncError, PtrKind, TypeKey, TypeKind, ValidityDomain,
};

/// A program submitted for verification.
#[derive(Debug)]
pub struct Program<'a> {
    /// The instruction image.
    pub insns: &'a [Insn],
    /// The execution context the target hook provides. A program is verified
    /// *for* a context; see [`Context`].
    pub context: Context,
    /// Types of the context tuple's fields, in order. The context is the
    /// hook's real argument list — NARF has no `struct __sk_buff`-style
    /// fiction and therefore no context-rewriting pass.
    pub ctx_fields: &'a [ArgDesc],
    /// Every kfunc this program may call.
    pub kfuncs: &'a [KfuncDesc],
}

/// An instruction that can fault at runtime and must be covered by an
/// exception-table entry.
///
/// Probe reads and arena accesses are emitted without bounds checks; a fault
/// zeroes the destination register and resumes at the next instruction. The
/// JIT turns each of these into an `ExEntry`, and registration must happen
/// *before* the text is published as executable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FaultSite {
    /// Index of the faulting instruction.
    pub insn_index: u32,
    /// Which BPF register to zero on fault. `None` for a store, which has no
    /// destination to clear.
    pub dst_reg: Option<u8>,
    /// Whether this is an arena access, which reports differently.
    pub arena: bool,
}

/// One subprogram's static properties.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SubprogInfo {
    /// Index of the subprogram's first instruction.
    pub start: u32,
    /// Bytes of BPF stack this subprogram uses.
    pub stack_bytes: u32,
}

/// The result of successful verification: everything the JIT and the runtime
/// need, and nothing about *how* it was proved.
#[derive(Debug)]
pub struct VerifiedProgram {
    /// The validated instruction image, unchanged. Verification does not
    /// rewrite instructions — lowering is the JIT's job and happens once.
    pub insns: Vec<Insn>,
    /// The context this program was verified for.
    pub context: Context,
    /// Peak BPF stack usage across the whole call graph, in bytes.
    ///
    /// Atomic programs draw this from the per-CPU BPF stack region; sleepable
    /// ones get a heap stack owned by the future, since a sleeping program
    /// cannot hold a per-CPU slot across a yield.
    pub max_stack_bytes: u32,
    /// Initial fuel. Decremented on back-edges and calls; exhaustion
    /// terminates the program with a diagnostic rather than a fault.
    pub initial_fuel: u64,
    /// Instructions needing exception-table coverage.
    pub fault_sites: Vec<FaultSite>,
    /// Subprogram boundaries and stack usage.
    pub subprogs: Vec<SubprogInfo>,
    /// Whether the program touches an arena, and so needs the arena base
    /// register pinned for its whole body.
    pub uses_arena: bool,
}

/// Why verification failed.
///
/// Every variant names an instruction index where one exists, because "your
/// program was rejected" without a location is the single most-complained-about
/// property of Linux's verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The instruction stream could not be decoded.
    Decode { at: u32, err: DecodeError },
    /// The program was empty.
    Empty,
    /// Control flow can run off the end without an `exit`.
    FallsOffEnd { at: u32 },
    /// A jump or call target is outside the program.
    BadTarget { at: u32, target: i64 },
    /// A register was read before anything was written to it.
    UninitRegister { at: u32, reg: u8 },
    /// An attempt to write R10, the read-only frame pointer.
    WriteToFramePointer { at: u32 },
    /// A memory access the verifier could not prove in bounds.
    OutOfBounds { at: u32 },
    /// A call to a kfunc this program was not given.
    UnknownKfunc { at: u32, id: i32 },
    /// A kfunc call whose arguments do not match its signature.
    KfuncSignature {
        at: u32,
        arg: usize,
        expected: ArgDesc,
    },
    /// A kfunc requiring a sleepable context was called from an atomic one.
    ContextMismatch {
        at: u32,
        required: Context,
        actual: Context,
    },
    /// A pointer that does not survive a sleep was live across an await.
    /// Covers sleeping with a lock held, and holding a `Trusted<T>` or a
    /// QSBR-domain pointer across a yield — one rule, three failure modes.
    PointerCrossesAwait {
        at: u32,
        reg: u8,
        domain: ValidityDomain,
    },
    /// A reference was still held when the program exited.
    LeakedReference { at: u32, reg: u8 },
    /// A consuming kfunc argument was given a reference the program does not
    /// hold — a double release, or a pointer that was never acquired.
    ReleaseOfUnacquired { at: u32, reg: u8 },
    /// More critical-section guards were live than v1 allows. Nesting needs a
    /// declared lock-order lattice; see `bpf/specification/spec.md` §8.3.
    TooManyLocks { at: u32 },
    /// A memory access through something that is not a pointer.
    NotAPointer { at: u32, reg: u8 },
    /// Arithmetic that is not defined on a pointer — anything but adding or
    /// subtracting a scalar, outside an arena.
    PointerArithmetic { at: u32, reg: u8 },
    /// A pointer that may be null was dereferenced without being tested.
    PossiblyNull { at: u32, reg: u8 },
    /// A store through a read-only pointer.
    WriteToReadOnly { at: u32 },
    /// A read of stack bytes nothing has written.
    UninitStack { at: u32, off: i64 },
    /// The static call graph contains a cycle. Fuel bounds a program's *work*,
    /// not its stack, so recursion has no bound this verifier can compute.
    Recursion { at: u32 },
    /// The static call graph needs more stack than a program may use.
    StackTooDeep { needed: u32, limit: u32 },
    /// A malformed kfunc descriptor was supplied.
    Kfunc(KfuncError),
    /// This construct is not implemented yet.
    NotImplemented(&'static str),
}

impl From<KfuncError> for VerifyError {
    fn from(e: KfuncError) -> Self {
        VerifyError::Kfunc(e)
    }
}

/// Largest BPF stack a single program may use, in bytes.
///
/// Linux's `MAX_BPF_STACK` is 512, forced by the BPF stack living on the
/// *kernel* stack. NARF gives BPF a dedicated per-CPU region, so the limit is
/// a budget rather than a hard architectural constraint — see
/// `bpf/specification/spec.md` §1.5.
pub const MAX_STACK_BYTES: u32 = 16 * 1024;

/// Default starting fuel.
///
/// Bounds total work, not wall time. A program that exhausts it is terminated
/// with a diagnostic; `narf_yield()` lets a sleepable program cooperate
/// without refilling it.
pub const DEFAULT_FUEL: u64 = 1 << 20;

/// Verify a program.
///
/// # Errors
///
/// Returns the first [`VerifyError`] found. The verifier fails closed: any
/// construct it cannot prove safe is rejected.
pub fn verify(prog: &Program<'_>) -> Result<VerifiedProgram, VerifyError> {
    if prog.insns.is_empty() {
        return Err(VerifyError::Empty);
    }
    // A malformed descriptor is a build-time bug in a `kfunc!` invocation.
    // Reasoning from a broken contract would be worse than refusing to.
    for k in prog.kfuncs {
        k.validate()?;
    }
    fixpoint::run(prog)
}
