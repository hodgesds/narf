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
//! Still unimplemented, and failing *closed* rather than guessing — two
//! constructs, both `LD_IMM64` pseudo-forms, and both blocked on something
//! outside this crate rather than on a transfer function:
//!
//!   * **`Imm64::BtfId`**, a kernel variable's address. Needs a registry of
//!     kernel variables on [`Program`], and a runtime that can resolve one;
//!     NARF carries no vmlinux BTF, so there is nothing to resolve against.
//!   * **`Imm64::SubprogAddr`**, a subprogram address taken as a value. Needs a
//!     callback-typed kfunc argument to give it a meaning — the address is only
//!     ever a callback handed to a kfunc — and a runtime able to call back into
//!     BPF. Neither exists, and no registered kfunc declares such a parameter.
//!
//! Implementing either here alone would move them from "rejected" to
//! "accepted, then traps on the first run", which is a worse contract than the
//! rejection. The map pseudo-forms, which this list used to include, are
//! resolved against [`Program::maps`] and no longer among them.
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
    fnv1a32_nonzero, ArgDesc, ArgFlags, Context, KfuncDesc, KfuncError, PtrKind, TypeKey, TypeKind,
    ValidityDomain, MAP_HANDLE_TYPE_KEY, MAP_HANDLE_TYPE_NAME,
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
    /// Every map this program may reference. Descriptor-local fd-array indices
    /// are explicit on [`MapDesc`] rather than implied by slice position.
    pub maps: &'a [MapDesc],
    /// Rust-native layouts of typed objects this program may inspect through
    /// mediated tracing kfuncs.
    pub objects: &'a [ObjectDesc<'a>],
}

/// One readable field in a Rust-native typed object descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectField {
    /// Byte offset from the object base.
    pub offset: u32,
    /// Exact readable width in bytes.
    pub size: u32,
}

/// The verifier-facing shape of one typed tracing object.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectDesc<'a> {
    /// Stable Rust-native type identity.
    pub key: TypeKey,
    /// Whole object size, used to validate field declarations.
    pub size: u32,
    /// Exact fields a program may request from the mediated read kfunc.
    pub fields: &'a [ObjectField],
}

/// What the verifier knows about one map a program references.
///
/// The verifier needs three things and nothing else: which descriptor a
/// `LD_IMM64` map pseudo-form names, and — for the value form — how wide a
/// value is, so `PtrClass::MapValue` gets a real bound instead of an
/// unbounded region. Everything else about a map (its kind, its locking, its
/// storage) is the runtime's business.
///
/// Linux keeps a `struct bpf_map *` array on `bpf_prog_aux` and reaches through
/// it for `map->value_size`, `map->key_size`, `map->map_type`, `map->ops`, and
/// twelve other fields, which is how `verifier.c` ends up knowing about map
/// *implementations*. A flat descriptor is what keeps that coupling out.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MapDesc {
    /// The file descriptor the loader put in `LD_IMM64`'s `imm` for the
    /// `MapFd` / `MapValue` forms.
    ///
    /// Resolution is by fd value, not by position, because that is what the
    /// instruction encoding carries. The `MapIdx` forms use
    /// [`Self::fd_array_idx`] instead, which is why both values are meaningful.
    pub fd: i32,
    /// Position in `bpf_attr.prog_load.fd_array` for a
    /// `BPF_PSEUDO_MAP_IDX` reference, or `None` when this descriptor is only
    /// addressable by fd.
    ///
    /// Kept separate from slice position: the array may contain BTF fds,
    /// duplicate maps, or unreferenced holes, none of which may renumber an
    /// instruction's index.
    pub fd_array_idx: Option<i32>,
    /// Key width in bytes.
    pub key_size: u32,
    /// Value width in bytes, as one program-visible value.
    pub value_size: u32,
    /// Capacity.
    pub max_entries: u32,
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

/// A non-arena memory instruction whose raw native dereference is safe.
///
/// The verifier publishes this only for accesses through its bounded stack or
/// immutable context classes. The JIT admission gate checks the instruction
/// index rather than guessing safety from the physical register number.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BareAccessSite {
    /// Index of the load, store, or atomic instruction.
    pub insn_index: u32,
}

/// A `BPF_LDX` load proved to name an exact declared field of a schema-tracked
/// [`PtrClass::TraceObject`](crate::state::PtrClass) pointer.
///
/// The same field-existence check `narf_probe_read` performs at runtime, moved
/// to verification time: the base register holds a trace-object pointer at
/// offset zero and the `(field_offset, size)` pair names one exact field of the
/// pointer's schema. That certifies the load as safe *provenance*, but not as a
/// bare host dereference: the base register holds the address of the tracing
/// wrapper, not of the object, so the field lives one indirection away
/// (`narf_tracing::TypedProbeRef::copy_field`). The load is therefore never
/// added to [`BareAccessSite`] — the JIT's pointer-base gate refuses it and the
/// whole program runs interpreted, where the interpreter reads the field
/// through the wrapper and repeats the runtime bound check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypedLoadSite {
    /// Index of the `BPF_LDX` load.
    pub insn_index: u32,
    /// Byte offset of the field from the object base, as named by the load's
    /// displacement.
    pub field_offset: u32,
    /// Exact field width the load reads, in bytes.
    pub size: u32,
}

/// A `call` to a kfunc, as resolved during verification.
///
/// The verifier resolves each `call`'s immediate against [`Program::kfuncs`]
/// already — it has to, to type-check the arguments — and this records the
/// answer so codegen does not have to resolve it a second time against a
/// registry it has no access to. `narf-bpf-jit` deliberately depends on nothing
/// kernel-side, so a shim address can only reach it through this struct.
///
/// Per *call site*, not per kfunc, and that is the point: an emitter walks
/// instructions, so "what does the call at index `i` target" is the question it
/// actually asks. A site with no entry here is one the fixpoint never reached
/// (dead code), and an emitter must refuse it rather than invent a target.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KfuncCallSite {
    /// Index of the `call` instruction.
    pub insn_index: u32,
    /// The id the instruction's `imm` carried, i.e. [`KfuncDesc::id`].
    pub id: i32,
    /// Address of the `extern "C"` shim — [`KfuncDesc::addr`], copied so the
    /// JIT needs no descriptor lifetime.
    pub addr: usize,
    /// The weakest context this kfunc may be entered from.
    ///
    /// Carried because it is what distinguishes the two shim ABIs: a
    /// [`Context::Sleepable`] kfunc's shim returns a boxed future, not a `u64`,
    /// so native code must not call it through the uniform ABI. Recording the
    /// context rather than a "callable" boolean keeps the decision with the
    /// backend that has to make it.
    pub context: Context,
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
    /// Instructions proved safe to lower as bare host-pointer dereferences.
    pub bare_access_sites: Vec<BareAccessSite>,
    /// `BPF_LDX` loads proved to name an exact declared field of a trace-object
    /// pointer, sorted by instruction index. Certified typed reads the
    /// interpreter services through the tracing wrapper; deliberately disjoint
    /// from [`Self::bare_access_sites`] so the JIT does not lower one as a bare
    /// dereference of the wrapper.
    pub typed_load_sites: Vec<TypedLoadSite>,
    /// Subprogram boundaries and stack usage.
    pub subprogs: Vec<SubprogInfo>,
    /// Whether the program touches an arena, and so needs the arena base
    /// register pinned for its whole body.
    pub uses_arena: bool,
    /// Every reachable kfunc `call`, sorted by instruction index.
    ///
    /// Additive: nothing that existed before this field depends on it, and a
    /// backend that ignores it behaves exactly as it did — which is what makes
    /// "the emitter refuses `Decoded::Call`" and "the emitter emits it" both
    /// expressible against the same struct.
    pub kfunc_calls: Vec<KfuncCallSite>,
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
    /// A context-field descriptor is malformed.
    BadCtxField {
        field: usize,
        err: kfunc::KfuncError,
    },
    /// A Rust-native typed-object descriptor was malformed.
    BadObjectDescriptor { object: usize },
    /// A control-flow edge leaves the subprogram it starts in.
    ///
    /// Every analysis downstream assumes subprograms are CFG-disjoint: each is
    /// analysed once with its own entry state and its own fresh `Stack`, stack
    /// depth is summed along the call *graph*, and the graph attributes a call
    /// to the subprogram whose slot range encloses it. A branch across that
    /// boundary breaks all three at once — it can reach a subprogram after its
    /// turn in the topological order has passed (so it is analysed never, and
    /// dismissed as dead code), and it makes the call graph describe edges the
    /// real control flow does not have, hiding recursion and under-counting the
    /// frame budget.
    ///
    /// Linux rejects the same thing in `check_subprogs()`. Its diagnostic is
    /// worth quoting because it is the whole reason this is an error and not a
    /// precision loss: "jump out of range".
    CrossSubprogEdge { at: u32, target: u32 },
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
    /// The static call graph nests deeper than [`MAX_CALL_DEPTH`].
    CallDepth { needed: u32, limit: u32 },
    /// A malformed kfunc descriptor was supplied.
    Kfunc(KfuncError),
    /// A dereference of an opaque object pointer.
    ///
    /// A `Trusted<T>`/`Owned<T>` is a handle to hand back to a kfunc, not
    /// something to load through: without BTF nothing says how large the
    /// object is, so no offset — constant or otherwise — can be proved in
    /// bounds. Linux permits field access only because `btf_struct_access()`
    /// can check the offset names a real field.
    ///
    /// The exception table does not help here. It makes an *unmapped* address
    /// survivable; it does nothing for a mapped one, so an unchecked object
    /// access is an arbitrary kernel read/write primitive rather than a
    /// recoverable fault.
    OpaqueDeref { at: u32, reg: u8 },
    /// A direct load through a trace-object pointer whose `(offset, size)` does
    /// not name an exact declared field of the pointer's schema.
    ///
    /// A trace-object pointer is the one opaque class a direct load *can* reach,
    /// but only at an exact field: this is the same authority boundary
    /// `narf_probe_read` enforces at runtime, brought forward to verification.
    /// A shifted offset, a truncated width, a variable offset, or a store — all
    /// land here rather than reaching the object. An in-object-but-not-a-field
    /// access is deliberately not enough; the schema is the boundary.
    TypedFieldMismatch { at: u32, reg: u8 },
    /// An arena access whose offset could not be proved inside the window.
    ///
    /// The guard slots are derived from the ISA's 16-bit displacement, so
    /// they catch an escape by immediate — not one by register-width
    /// arithmetic.
    ArenaOutOfWindow { at: u32, reg: u8 },
    /// The abstract-interpretation fixpoint did not converge within its round
    /// budget.
    ///
    /// A verifier bug rather than a program bug: termination is meant to be
    /// structural (finite-height lattice + widening at every back-edge
    /// target), so reaching this means the lattice has an infinite ascending
    /// chain somewhere. Reported distinctly from an ordinary rejection so it
    /// cannot be mistaken for one.
    FixpointDiverged { subprog: u32, rounds: u64 },
    /// A `LD_IMM64` map pseudo-form naming a map the load request did not
    /// supply.
    ///
    /// Fails closed rather than admitting an unknown map: the value width is
    /// what bounds every access through the resulting pointer, and there is no
    /// safe default for a width nobody stated. Linux reports the same condition
    /// as `EBADF`/`EINVAL` from `resolve_pseudo_ldimm64` before the verifier
    /// proper runs; here the resolution *is* a transfer function, so it is a
    /// `VerifyError` with an instruction index.
    UnknownMap { at: u32, fd: i32 },
    /// A `LD_IMM64` map-value pseudo-form whose offset is outside the map's
    /// value.
    MapValueOffset { at: u32, off: i32, size: u32 },
    /// An address-space cast naming a pair of address spaces that has no
    /// meaning.
    ///
    /// Address space 1 is the arena and 0 is the kernel; the only two casts
    /// that exist are between them. Anything else is a *malformed* instruction
    /// rather than an unimplemented one — there is no construct to implement,
    /// because nothing generates the encoding and nothing could execute it.
    ///
    /// Reported separately from [`VerifyError::NotImplemented`] because the two
    /// mean opposite things to a caller: `NotImplemented` says "this program
    /// might be fine, the verifier just cannot say", and `narf-bpf`'s loader
    /// answers it by retrying under a weaker structural check. A malformed
    /// operand must never take that path, however that path is gated in future.
    BadAddrSpaceCast { at: u32, dst_as: u16, src_as: u16 },
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

/// Size of the arena window an in-program arena pointer may address.
///
/// The guard slots either side are derived from the ISA's 16-bit displacement
/// — the trick NARF keeps from `kernel/bpf/arena.c:45` — so an escape *by
/// immediate* lands in unmapped VA and is caught by the exception table. An
/// escape by register-width arithmetic is not covered by that argument, which
/// is why the verifier bounds the computed offset against this explicitly.
/// # Load-bearing: this must stay exactly `2^32`
///
/// 32-bit ALU on an arena pointer keeps `PtrClass::Arena` and does **not**
/// truncate the abstract offset, while the concrete register holds
/// `sum mod 2^32`. That is sound only because `access` requires the whole
/// abstract offset range to lie in `[0, ARENA_WINDOW_BYTES)`, and on a window
/// of exactly `2^32` the reduction `mod 2^32` is the identity there — so at any
/// *accepted* access the abstract and concrete offsets coincide.
///
/// Widening the window (spec §8.1 contemplates "lifting the 4 GiB cap") breaks
/// that silently: the abstract offset would then admit values the concrete
/// register cannot hold, and a 32-bit `+=` would be verified against an offset
/// the hardware never computes. Whoever lifts it must first make the 32-bit
/// path zero-extend the offset. The `const` assertion below is the tripwire;
/// the dependency was previously stated nowhere.
pub const ARENA_WINDOW_BYTES: u64 = 4 << 30;

const _: () = assert!(
    ARENA_WINDOW_BYTES == 1 << 32,
    "the 32-bit arena ALU path relies on `mod 2^32` being the identity on \
     [0, ARENA_WINDOW_BYTES); see the note above before changing this"
);

/// Maximum subprogram nesting depth.
///
/// Must match the interpreter's `MAX_CALL_FRAMES` and the JIT's frame layout.
/// The verifier previously had no limit at all while the runtime enforced one,
/// so a nine-deep call chain verified and then trapped — a program accepted by
/// the verifier that cannot run is a contract break even though it is not a
/// safety hole.
pub const MAX_CALL_DEPTH: u32 = 8;

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
    // The *context* descriptor was never validated, only the kfunc ones — so a
    // `Scalar { bits: 0 }` ctx field reached `Scalar::signed_bits(0)` and
    // panicked the verifier on a `1 << (bits - 1)` underflow. Same class of
    // "reasoning from a broken contract", one descriptor over.
    for (i, f) in prog.ctx_fields.iter().enumerate() {
        kfunc::validate_type(*f, i).map_err(|err| VerifyError::BadCtxField { field: i, err })?;
    }
    for (i, object) in prog.objects.iter().enumerate() {
        if !object.key.is_some()
            || object.size == 0
            || object.fields.iter().any(|field| {
                field.size == 0
                    || u64::from(field.offset) + u64::from(field.size) > u64::from(object.size)
            })
            || prog.objects[..i]
                .iter()
                .any(|earlier| earlier.key == object.key)
        {
            return Err(VerifyError::BadObjectDescriptor { object: i });
        }
    }
    fixpoint::run(prog)
}
