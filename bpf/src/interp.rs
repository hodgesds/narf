//! The fuel-metered interpreter.
//!
//! An `async fn` over the verified instruction image. Async because
//! `bpf/specification/spec.md` §1.10 puts sleepable programs here rather than
//! in the JIT: `block_on` panics inside an executor poll and an
//! `IrqSafeSpinLock` held across an await deadlocks, so a sleepable program
//! cannot be a plain JITed function that blocks. Making the interpreter a
//! future puts the program's state in the future and lets a sleepable kfunc
//! be an ordinary `.await`. Atomic programs never reach an await point, so
//! the same body serves both and the atomic path polls exactly once.
//!
//! ## Fuel
//!
//! Every instruction retired decrements the fuel counter; exhaustion stops the
//! program with a diagnostic, never a fault, and fuel is **never refilled**
//! (§4.9). Per *instruction* rather than per back-edge, because the latter
//! bounds iterations rather than work — 65536 straight-line instructions cost
//! one unit, which is no bound at all inside an atomic probe. That is what lets the verifier be a plain converging
//! fixpoint instead of Linux's termination heuristics — a 1M instruction
//! budget, 8192 pushed states, 64 states/insn, SCC computation, open-coded
//! iterator convergence, `may_goto` counters, and `bpf_loop` callbacks, five
//! loop constructs between them.
//!
//! ## The address model
//!
//! Every pointer a program can hold names a byte offset into a region the
//! runtime supplied, and every load and store is bounds-checked against it. A
//! program that escapes its regions is terminated rather than faulting. There
//! are two kinds of region and they differ in one important way.
//!
//! **Stack and context** are *synthetic*: [`STACK_REGION`] and [`CTX_REGION`]
//! are fabricated bases that exist only inside the VM, so the address a program
//! computes is not an address at all and cannot be dereferenced even by mistake.
//! An escape gets [`Trap::BadAccess`].
//!
//! **Arenas are not synthetic**, and this is the one place the interpreter turns
//! a program-supplied value into a real kernel address. It has to: an arena
//! pointer is a slot-relative handle, a program stores handles *inside* the
//! arena, and userspace walks those handles through its own mapping — so biasing
//! them by a fabricated base would make every stored pointer meaningless outside
//! this interpreter, and would make the interpreter and the JIT disagree about
//! the bytes in shared memory. What replaces the fabricated base is a bound:
//! [`crate::arena::resolve_in`] admits a handle only if it lies entirely inside
//! the **live** extent of one of *the running program's own* arenas, and traps
//! [`Trap::ArenaOutOfBounds`] otherwise. Live rather than reserved, and the
//! distinction is not cosmetic: `ProgArena::new_reserved` leaves VA above the
//! populated prefix, so "all of which are fully populated" — what this
//! paragraph used to say — stopped being true when demand population landed.
//! The bound reads the live extent with one acquire load, and it only grows, so
//! a handle that resolved once keeps resolving. So the reachable set is
//! exactly this program's arena bytes — never kernel memory, never another
//! program's arena — but it is reached by a real dereference and not by an index
//! into a slice. A program with no arena bound reaches nothing this way and gets
//! [`Trap::BadAccess`] as before.
//!
//! That bound is a *runtime* check, so it holds even if the verifier is wrong,
//! which is what matters while the abstract interpreter is still being trusted.
//! The JIT trades these checks for the extable and the arena guard slots — the
//! same bargain Linux strikes at `verifier.c:16186` — and it now takes that
//! trade: `crate::jit_glue` gate 2 admits a program with exactly one arena.
//!
//! The two paths reach the same verdict by different routes, which is the thing
//! to hold on to when reading either. Here, a handle that names no live arena
//! byte is refused by comparison and never dereferenced. There, it *is*
//! dereferenced, lands on a page the slot's guards and the arena's own extent
//! leave unmapped, and the exception table turns the fault into the same
//! [`Trap::ArenaOutOfBounds`] — carrying the same handle, because the emitter
//! folds the displacement into the index register so the fault epilogue can
//! return it. `smoke_bpf_jit_diff_arena_out_of_bounds_traps_like_the_interpreter`
//! is what holds the two together; the JIT's set is only equal to this one for a
//! program with a *single* arena, which is gate 2's remaining job.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context as TaskContext, Poll};

use narf_bpf_isa::{
    decode, AluOp, AtomicOp, ByteOrder, CondOp, Decoded, Imm64, Insn, Reg, Size, Source,
};
use narf_bpf_verifier::kfunc::Context;

use narf_bpf_verifier::SubprogInfo;

use crate::kfunc::{KfuncShim, Registry};
use crate::mem::StackFrame;

/// Synthetic base of the program's stack region.
///
/// Arbitrary but distinctive: these values only ever exist inside the VM, so
/// a stray one in a diagnostic is immediately recognisable as a BPF pointer
/// rather than a kernel address.
pub const STACK_REGION: u64 = 0x0000_2000_0000_0000;
/// Synthetic base of the read-only context tuple.
pub const CTX_REGION: u64 = 0x0000_3000_0000_0000;
/// Synthetic base of the current `bpf_ringbuf_reserve` record.
///
/// A distinct region so a write to a reserved record is routed to the staged
/// buffer, and so a stray reserve pointer is recognisable in a diagnostic. Only
/// one reservation is live at a time; the address is the same for each.
pub const RESERVE_REGION: u64 = 0x0000_4000_0000_0000;

/// Largest record `bpf_ringbuf_reserve` can stage. Larger records use
/// `bpf_ringbuf_output`, which copies from the program's own buffer and has no
/// staging area to bound. A reserve of more than this returns null.
pub const MAX_RESERVE: usize = 512;

/// Maximum context words. `tracing::dispatch::ProbeArgs` is `[u64; 4]`, which
/// is already the BPF ctx-array shape — the trampoline Linux needs to spill
/// native arguments into a stack array (`bpf_jit_comp.c:3150-3210`) does not
/// exist here because the probe ABI *is* that array.
pub const MAX_CTX_WORDS: usize = 4;

/// Maximum nested subprogram frames. Matches Linux's `MAX_CALL_FRAMES`.
pub const MAX_CALL_FRAMES: usize = 8;

/// The production fuel policy: one unit per instruction retired (§4.9).
///
/// A named code rather than a bare literal at the one call site, so the `const`
/// parameter on the interpreter loop reads as a policy selection. The other two
/// values exist only under the `bench` feature; see [`Vm::run_fuel_hoisted`] and
/// [`Vm::run_fuel_per_insn_control`].
pub const FUEL_PER_INSN: u8 = 0;

/// The single policy code that hoists the burn.
///
/// Private and unconditional, because the interpreter loop compares against it
/// in every build while the *public* name for it exists only under `bench`.
const POLICY_HOISTED: u8 = 1;

/// Burn fuel only on back-edges and calls — the policy §8 item 7 replaced.
#[cfg(feature = "bench")]
pub const FUEL_HOISTED: u8 = POLICY_HOISTED;

/// [`FUEL_PER_INSN`]'s semantics under a second policy code, and therefore a
/// second monomorphisation of the same loop.
///
/// The A/A control. Two instantiations of identical source differ in code
/// placement, and on an out-of-order core that is worth a percent or two by
/// itself — so an A/B difference between the two *policies* is only
/// interpretable next to the difference between two *identical* ones. Without
/// this arm, "per-instruction fuel costs 2%" and "these two functions landed at
/// different alignments" are the same measurement.
#[cfg(feature = "bench")]
pub const FUEL_PER_INSN_CONTROL: u8 = 2;

/// Bytes each subprogram frame gets inside the stack region.
pub const FRAME_BYTES: usize = 512;

/// Why a program stopped early.
///
/// Every variant carries the instruction index, because "your program was
/// rejected/killed" without a location is the single most-complained-about
/// property of Linux's verifier and there is no reason to repeat it at
/// runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Trap {
    /// Fuel ran out. Not a fault: the program is stopped and the caller sees
    /// a diagnostic (§4.9).
    OutOfFuel { at: u32 },
    /// A load or store outside every region the program may reach.
    BadAccess { at: u32, addr: u64, len: usize },
    /// A jump or call target outside the program.
    BadTarget { at: u32 },
    /// An instruction the interpreter does not implement.
    Unsupported { at: u32, what: &'static str },
    /// A `call` naming a kfunc that is not registered.
    UnknownKfunc { at: u32, id: i32 },
    /// A sleepable kfunc called from an atomic program. Normally impossible —
    /// the verifier rejects it — but the interpreter checks anyway because
    /// the consequence of getting it wrong is sleeping with IRQs masked.
    WrongContext { at: u32 },
    /// Subprogram nesting exceeded [`MAX_CALL_FRAMES`].
    CallDepth { at: u32 },
    /// A write to R10, the read-only frame pointer.
    WroteFramePointer { at: u32 },
    /// The stack region could not accommodate another frame.
    StackExhausted { at: u32 },
    /// An arena access whose handle does not lie entirely inside one of the
    /// running program's arenas.
    ///
    /// Distinct from [`Trap::BadAccess`] only in *which program* got it: this
    /// one is what a program that has at least one arena gets for any address
    /// that is neither stack nor context, and [`Trap::BadAccess`] is what a
    /// program with no arena gets for the same value. So it covers walking off
    /// the end of an arena, into the slot's null guard, and into a gap between
    /// two arenas — but it also covers a wild value that was never a handle,
    /// because once a program has an arena the runtime has no way to tell those
    /// apart. Carries the handle so the offending value is visible instead of
    /// inferred, which is the part that makes it diagnosable.
    ArenaOutOfBounds { at: u32, handle: u64, len: usize },
    /// An atomic read-modify-write on a misaligned arena address.
    ///
    /// Arena memory is shared with userspace, so an arena atomic has to be a
    /// real atomic instruction, and a real atomic instruction needs its operand
    /// naturally aligned. Refused rather than emulated: emulating it would make
    /// the operation non-atomic with respect to the other side of the mapping,
    /// which is the one property the program asked for.
    ArenaUnaligned { at: u32, handle: u64, len: usize },
    /// A `LD_IMM64` map reference the runtime could not resolve.
    ///
    /// Normally impossible: the verifier resolved the same reference against the
    /// same set. Reaching it means the verifier's `Program::maps` and the
    /// program's own list disagreed, and the alternative to trapping is handing
    /// a kfunc a null it will treat as non-null.
    UnresolvedMap { at: u32 },
}

/// How a program run ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Ran to `exit` with this value in R0.
    Returned(u64),
    /// Stopped early.
    Trapped(Trap),
}

impl Outcome {
    /// The program's return value, or `0` if it trapped.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Outcome::Returned(v) => v,
            Outcome::Trapped(_) => 0,
        }
    }

    /// Whether the program ran to completion.
    #[inline]
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Outcome::Returned(_))
    }
}

/// One subprogram activation.
#[derive(Copy, Clone, Debug, Default)]
struct Frame {
    /// Instruction index to resume at.
    return_pc: usize,
    /// Callee-saved registers, per the BPF ABI: R6..R9 plus R10.
    saved: [u64; 5],
    /// The caller's frame base within the stack region.
    frame_base: u64,
    /// The caller's [`Vm::current_sp`], restored on `exit`.
    saved_sp: usize,
}

/// A `yield` point for sleepable programs: returns `Pending` exactly once, so
/// the executor gets a chance to run something else.
///
/// This is the whole of `narf_yield()` (§1.12). Yielding deliberately does
/// **not** refill fuel: fuel bounds total work, yielding only lets other tasks
/// interleave, and keeping them orthogonal is what makes a long iterator walk
/// cooperative rather than either CPU-hogging or fuel-fatal.
#[derive(Debug, Default)]
struct YieldNow {
    yielded: bool,
}

/// Yield once to the executor.
///
/// The primitive behind the `narf_yield()` kfunc. Public so that kfunc lives
/// in `crate::kfuncs` with every other one, rather than being special-cased
/// inside the interpreter's dispatch — which is what it had to be while the
/// kfunc ABI could not express suspension.
pub async fn yield_now() {
    YieldNow::default().await;
}

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// The program-derived half of a [`Vm`]'s inputs.
///
/// Grouped because these four always come from the same `VerifiedProgram` and
/// are only meaningful together — in particular `subprogs` must be the table
/// the same verification produced, or frame layout silently disagrees with
/// what was proved. Passing them positionally alongside the run-specific
/// arguments made that easy to get wrong.
#[derive(Copy, Clone, Debug)]
pub struct VmProgram<'a> {
    /// The verified instruction image.
    pub insns: &'a [Insn],
    /// Per-subprogram frame sizes from that same verification.
    pub subprogs: &'a [SubprogInfo],
    /// The execution context the program was verified for.
    pub context: Context,
    /// Starting fuel.
    pub fuel: u64,
    /// Maps the program may reference, paired with the file descriptors its
    /// `LD_IMM64` immediates name.
    ///
    /// Resolved here rather than patched into the image: verification does not
    /// rewrite instructions (spec §1.7), so Linux's
    /// `resolve_pseudo_ldimm64`-rewrites-the-insn trick is not available and a
    /// reference costs one lookup per execution instead. There are at most a
    /// handful of maps per program, so the lookup is a linear scan.
    pub maps: &'a [(i32, alloc::sync::Arc<crate::map::BpfMap>)],
}

/// The virtual machine.
pub struct Vm<'a> {
    regs: [u64; 11],
    fuel: u64,
    insns: &'a [Insn],
    ctx: [u64; MAX_CTX_WORDS],
    ctx_len: usize,
    stack: StackFrame<'a>,
    /// Active subprogram frames, innermost last.
    ///
    /// A fixed array, not a `Vec`: [`MAX_CALL_FRAMES`] is a compile-time
    /// constant, and a `Vec` meant the *running program* called the global
    /// allocator on every BPF-to-BPF call. Spec §4.6 forbids exactly that on
    /// these paths — `run_xdp` invokes with `XDP_PROGS` held and IRQs masked,
    /// `drain_irq_samples` with `PERF_EVENT_REGISTRY` *and* the event's program
    /// lock held — and it was also an unadmitted panic site, since
    /// `Vec::push`'s allocation failure calls `handle_alloc_error`, i.e. a
    /// kernel panic driven by a program instruction.
    frames: [Frame; MAX_CALL_FRAMES],
    /// Number of live entries in `frames`.
    depth: usize,
    /// Per-subprogram stack sizes, from the verifier.
    ///
    /// Frames used to be a fixed [`FRAME_BYTES`], which disagreed with the
    /// verifier in both directions: a program of eight tiny subprograms
    /// verified with a 64-byte budget and then exhausted the region on its
    /// *first* call, while a single 1 KiB callee verified and then wrote
    /// below the region. `Ok` from the verifier is only meaningful if the
    /// frames are laid out the way it modelled them.
    subprogs: &'a [SubprogInfo],
    /// Index into [`Self::subprogs`] of the subprogram currently executing.
    ///
    /// Load-bearing for frame layout, and the reason it exists: the callee's
    /// frame base is `caller_base - size(caller)`, so laying out a call needs
    /// the size of the subprogram making it. `push_frame` used to look up the
    /// *callee's* size instead, which is wrong in both directions and matched
    /// the verifier only when the two happened to be equal — which is exactly
    /// what the one existing frame-overlap test did (8 bytes on both sides).
    current_sp: usize,
    registry: &'static Registry,
    context: Context,
    /// The arenas this program may address, in slot placement order.
    ///
    /// Empty for a program with no arena, which is what makes an arena-shaped
    /// address unreachable for it rather than merely out of bounds.
    ///
    /// Not part of [`VmProgram`] even though it is program-derived: `VmProgram`
    /// is constructed by struct literal in `crate::bench`, so growing it would
    /// break a file this change has no business editing. [`Vm::with_arenas`] is
    /// the seam instead.
    arenas: &'a [alloc::sync::Arc<crate::arena::ProgArena>],
    /// See [`VmProgram::maps`].
    maps: &'a [(i32, alloc::sync::Arc<crate::map::BpfMap>)],
    /// The ring buffer a live `bpf_ringbuf_reserve` targets, or `None` when no
    /// reservation is outstanding. Holding the `Arc` keeps the ring alive for
    /// the reservation even if the program's own reference were somehow
    /// dropped.
    reserve_map: Option<alloc::sync::Arc<crate::map::BpfMap>>,
    /// The reserved record's length. Meaningful only while [`Self::reserve_map`]
    /// is `Some`; `reserve_buf[..reserve_len]` is the staged record the program
    /// writes through [`RESERVE_REGION`] and `submit` copies into the ring.
    reserve_len: usize,
    /// The staged record bytes. A `u64` array so the whole `Vm` needs no
    /// alignment beyond its other fields; only `reserve_len` bytes are used.
    reserve_buf: [u8; MAX_RESERVE],
    /// Instructions retired, for diagnostics.
    steps: u64,
}

impl core::fmt::Debug for Vm<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vm")
            .field("fuel", &self.fuel)
            .field("steps", &self.steps)
            .field("insns", &self.insns.len())
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl<'a> Vm<'a> {
    /// Build a VM over a verified instruction image.
    #[must_use]
    pub fn new(
        prog: VmProgram<'a>,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
        stack: StackFrame<'a>,
        registry: &'static Registry,
    ) -> Self {
        let VmProgram {
            insns,
            subprogs,
            context,
            fuel,
            maps,
        } = prog;
        let mut regs = [0u64; 11];
        // BPF entry convention: R1 = context pointer, R10 = frame pointer.
        regs[1] = CTX_REGION;
        regs[10] = STACK_REGION + stack.len() as u64;
        Self {
            regs,
            fuel,
            insns,
            ctx,
            ctx_len: ctx_len.min(MAX_CTX_WORDS),
            stack,
            frames: [Frame::default(); MAX_CALL_FRAMES],
            depth: 0,
            subprogs,
            // Entry is subprogram 0 by construction: the verifier always emits
            // the program entry as `subprogs[0]` with `start == 0`.
            current_sp: 0,
            registry,
            context,
            arenas: &[],
            maps,
            reserve_map: None,
            reserve_len: 0,
            reserve_buf: [0u8; MAX_RESERVE],
            steps: 0,
        }
    }

    /// Bind the arenas this program may address.
    ///
    /// Without this a program's arena handles resolve to nothing and its first
    /// arena access is [`Trap::BadAccess`] — fail-closed, which is why this is a
    /// builder step rather than a mandatory argument: forgetting it costs a
    /// program its run, not its containment.
    #[must_use]
    pub fn with_arenas(mut self, arenas: &'a [alloc::sync::Arc<crate::arena::ProgArena>]) -> Self {
        self.arenas = arenas;
        self
    }

    /// Fuel remaining.
    #[inline]
    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    /// Instructions retired.
    #[inline]
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    // ── memory ──────────────────────────────────────────────────────

    /// Resolve `addr..addr+len` to a stack-region byte range.
    ///
    /// Returns `None` for anything outside the stack region, including the
    /// read-only context region — the caller handles that case separately so
    /// a store into the context is rejected rather than silently aliasing.
    #[inline]
    fn stack_range(&self, addr: u64, len: usize) -> Option<(usize, usize)> {
        let end = addr.checked_add(len as u64)?;
        let limit = STACK_REGION.checked_add(self.stack.len() as u64)?;
        if addr < STACK_REGION || end > limit {
            return None;
        }
        let off = (addr - STACK_REGION) as usize;
        Some((off, off + len))
    }

    /// The staged-record byte range an address falls in, or `None`.
    ///
    /// Bounded by `reserve_len`, not by the buffer's size, so a write proved
    /// in bounds by the verifier (against the reserved size) lands in the
    /// staged record and a wild one does not — the same shape as
    /// [`Vm::stack_range`], for the same reason.
    #[inline]
    fn reserve_range(&self, addr: u64, len: usize) -> Option<(usize, usize)> {
        self.reserve_map.as_ref()?;
        let end = addr.checked_add(len as u64)?;
        let limit = RESERVE_REGION.checked_add(self.reserve_len as u64)?;
        if addr < RESERVE_REGION || end > limit {
            return None;
        }
        let off = (addr - RESERVE_REGION) as usize;
        Some((off, off + len))
    }

    /// Resolve an arena handle to a real kernel address, or trap.
    ///
    /// `None` from [`crate::arena::resolve_in`] covers every way out of an arena:
    /// past the end, into the slot's null guard, into a gap between two arenas,
    /// or a handle belonging to no arena at all.
    #[inline]
    fn arena_kva(&self, at: u32, handle: u64, len: usize) -> Result<u64, Trap> {
        crate::arena::resolve_in(self.arenas, handle, len).ok_or(Trap::ArenaOutOfBounds {
            at,
            handle,
            len,
        })
    }

    /// Whether an address that matched no synthetic region may be treated as an
    /// arena handle at all.
    ///
    /// Only when the program has an arena. A program with none must keep getting
    /// [`Trap::BadAccess`] for a wild address: "you walked out of your arena" is
    /// a different diagnosis from "that was never a pointer", and reporting the
    /// former for a program that has no arena would be a lie. It says nothing
    /// about whether any *particular* address is in range — that is
    /// [`Vm::arena_kva`]'s job, and it is the only bound there is.
    #[inline]
    fn has_arena(&self) -> bool {
        !self.arenas.is_empty()
    }

    /// The map named by this file descriptor.
    fn map_by_fd(&self, fd: i32) -> Option<&alloc::sync::Arc<crate::map::BpfMap>> {
        self.maps.iter().find(|(f, _)| *f == fd).map(|(_, m)| m)
    }

    /// The map a handle register carries, resolved by the address `map_addr`
    /// hands out (`Arc::as_ptr`). `None` when no held map matches — the same
    /// two-halves-disagreeing case [`Vm::map_addr`] traps on.
    fn map_from_addr(&self, addr: u64) -> Option<&alloc::sync::Arc<crate::map::BpfMap>> {
        self.maps
            .iter()
            .find(|(_, m)| alloc::sync::Arc::as_ptr(m) as u64 == addr)
            .map(|(_, m)| m)
    }

    /// `bpf_ringbuf_reserve(map, size, flags)`: stage a record and hand back
    /// [`RESERVE_REGION`], or `0` (null) if it cannot be staged. See
    /// [`crate::ringbuf`].
    fn ringbuf_reserve(&mut self, map_addr: u64, size: u64, flags: u64) -> u64 {
        // Only the wakeup-control flags are defined; a live reservation blocks a
        // second (one is staged at a time); the record must fit the staging
        // area. Any of these declines with null, which the program null-checks.
        if flags & !crate::ringbuf::RESERVE_WAKEUP_FLAGS != 0 || self.reserve_map.is_some() {
            return 0;
        }
        let size = size as usize;
        if size > MAX_RESERVE {
            return 0;
        }
        let Some(map) = self.map_from_addr(map_addr) else {
            return 0;
        };
        let Some(rb) = map.ringbuf() else {
            return 0;
        };
        if !rb.has_room(size) {
            return 0;
        }
        let map = alloc::sync::Arc::clone(map);
        self.reserve_buf[..size].fill(0);
        self.reserve_len = size;
        self.reserve_map = Some(map);
        RESERVE_REGION
    }

    /// `bpf_ringbuf_submit`: copy the staged record into the ring and clear the
    /// reservation. A no-op if nothing is staged (the verifier prevents that).
    fn ringbuf_submit(&mut self) {
        if let Some(map) = self.reserve_map.take() {
            if let Some(rb) = map.ringbuf() {
                // Best-effort: `has_room` was checked at reserve, so under the
                // single-producer model this always succeeds. A concurrent
                // producer that filled the ring in between drops the record —
                // a lost event, never a corrupt one.
                let _ = rb.output(&self.reserve_buf[..self.reserve_len]);
            }
        }
        self.reserve_len = 0;
    }

    /// `bpf_ringbuf_discard`: drop the staged record without publishing it.
    fn ringbuf_discard(&mut self) {
        self.reserve_map = None;
        self.reserve_len = 0;
    }

    /// The address a map handle carries.
    ///
    /// `Arc::as_ptr`, not a synthetic token: the kfunc shim reconstitutes a
    /// `Trusted<BpfMap>` from the register, and the program holds the `Arc` for
    /// its whole life, so the pointee outlives every call that can see it.
    ///
    /// `None` means the verifier accepted a reference the runtime cannot
    /// resolve, which is the two halves disagreeing — a trap rather than a
    /// silent zero, since a zero here would reach `NonNull::new_unchecked`.
    fn map_addr(
        &self,
        at: u32,
        m: Option<&alloc::sync::Arc<crate::map::BpfMap>>,
    ) -> Result<u64, Trap> {
        match m {
            Some(m) => Ok(alloc::sync::Arc::as_ptr(m) as u64),
            None => Err(Trap::UnresolvedMap { at }),
        }
    }

    fn load(&mut self, at: u32, addr: u64, size: Size, signed: bool) -> Result<u64, Trap> {
        let len = size_bytes(size);
        if let Some((lo, hi)) = self.stack_range(addr, len) {
            let mut buf = [0u8; 8];
            buf[..len].copy_from_slice(&self.stack.bytes_mut()[lo..hi]);
            return Ok(widen(u64::from_le_bytes(buf), size, signed));
        }
        // A read-back of the record being staged for `bpf_ringbuf_reserve`.
        if let Some((lo, hi)) = self.reserve_range(addr, len) {
            let mut buf = [0u8; 8];
            buf[..len].copy_from_slice(&self.reserve_buf[lo..hi]);
            return Ok(widen(u64::from_le_bytes(buf), size, signed));
        }
        // The context tuple is word-addressed and read-only.
        //
        // `checked_add` is load-bearing on both sides, exactly as in
        // `stack_range`. Computing `addr + len` unchecked let `u64::MAX` wrap
        // to 0, which satisfied *both* guards — `addr >= CTX_REGION` and
        // `0 <= ctx_limit` — and the load then indexed a `[u64; 4]` far out of
        // bounds. That is a kernel panic in the layer `crate::provisional`
        // nominates as the reason the runtime is safe when the verifier is
        // wrong, so it has to be the layer that cannot itself be broken.
        let ctx_limit = CTX_REGION.checked_add((self.ctx_len as u64) * 8);
        let end = addr.checked_add(len as u64);
        if let (Some(limit), Some(end)) = (ctx_limit, end) {
            if addr >= CTX_REGION && end <= limit {
                let off = (addr - CTX_REGION) as usize;
                let word = self.ctx[off / 8];
                let shift = (off % 8) * 8;
                let raw = word >> shift;
                return Ok(widen(raw, size, signed));
            }
        }
        // Neither region matched, so the only remaining meaning of the value is
        // an arena handle. See the module docs on why this one is a real
        // dereference and what bounds it.
        if self.has_arena() {
            let kva = self.arena_kva(at, addr, len)?;
            let mut buf = [0u8; 8];
            // SAFETY: `arena_kva` proved `[kva, kva + len)` lies inside a
            // populated page range of one of this program's arenas, which is
            // mapped RW in the kernel root for the arena's whole life. Byte-wise
            // rather than a typed read because BPF permits unaligned access and
            // `read_volatile` does not.
            unsafe {
                core::ptr::copy_nonoverlapping(kva as *const u8, buf.as_mut_ptr(), len);
            }
            return Ok(widen(u64::from_le_bytes(buf), size, signed));
        }
        Err(Trap::BadAccess { at, addr, len })
    }

    fn store(&mut self, at: u32, addr: u64, size: Size, value: u64) -> Result<(), Trap> {
        let len = size_bytes(size);
        let bytes = value.to_le_bytes();
        if let Some((lo, hi)) = self.stack_range(addr, len) {
            self.stack.bytes_mut()[lo..hi].copy_from_slice(&bytes[..len]);
            return Ok(());
        }
        // A write into the record being staged for `bpf_ringbuf_reserve`. The
        // interpreter never hands the ring's own bytes to the program; the
        // record is copied into the ring only at `submit`.
        if let Some((lo, hi)) = self.reserve_range(addr, len) {
            self.reserve_buf[lo..hi].copy_from_slice(&bytes[..len]);
            return Ok(());
        }
        // The context region is deliberately not tried here: it is read-only, so
        // a store into it must be rejected rather than silently aliasing.
        if self.has_arena() {
            let kva = self.arena_kva(at, addr, len)?;
            // SAFETY: as in `load` — `arena_kva` bounded the range to a mapped,
            // populated, writable arena page belonging to this program.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), kva as *mut u8, len);
            }
            return Ok(());
        }
        Err(Trap::BadAccess { at, addr, len })
    }

    // ── execution ───────────────────────────────────────────────────

    /// Run to completion.
    ///
    /// Atomic programs never hit an await point, so polling this future once
    /// is enough for them; sleepable programs park at `narf_yield()`.
    pub async fn run(&mut self) -> Outcome {
        match self.run_inner::<FUEL_PER_INSN>().await {
            Ok(v) => Outcome::Returned(v),
            Err(t) => Outcome::Trapped(t),
        }
    }

    /// Run with the fuel burn hoisted off the per-instruction path and onto
    /// back-edges and calls — the policy this interpreter used before
    /// `bpf/specification/spec.md` §8 item 7 was resolved to "per instruction".
    ///
    /// This is **not** a supported way to run a program: the bound it gives is
    /// on iterations, not on work, which is precisely why it was replaced. It
    /// exists so the cost of the replacement can be measured rather than
    /// asserted, and it is compiled only under the `bench` feature so a
    /// production build cannot name it.
    #[cfg(feature = "bench")]
    pub async fn run_fuel_hoisted(&mut self) -> Outcome {
        match self.run_inner::<FUEL_HOISTED>().await {
            Ok(v) => Outcome::Returned(v),
            Err(t) => Outcome::Trapped(t),
        }
    }

    /// Run under [`FUEL_PER_INSN_CONTROL`] — identical semantics to [`Vm::run`],
    /// a different monomorphisation. The A/A control; see that constant.
    #[cfg(feature = "bench")]
    pub async fn run_fuel_per_insn_control(&mut self) -> Outcome {
        match self.run_inner::<FUEL_PER_INSN_CONTROL>().await {
            Ok(v) => Outcome::Returned(v),
            Err(t) => Outcome::Trapped(t),
        }
    }

    /// The interpreter loop, parameterised on where fuel is spent.
    ///
    /// A `const` parameter rather than a field, deliberately: the whole
    /// question the A/B asks is what a decrement-and-branch per instruction
    /// costs, and a *runtime* policy check would add a second load and branch
    /// per instruction to production in order to measure the first one.
    /// Monomorphised, `POLICY` folds at compile time and the production
    /// instantiation keeps exactly the code it had before this parameter
    /// existed.
    #[allow(clippy::too_many_lines)]
    async fn run_inner<const POLICY: u8>(&mut self) -> Result<u64, Trap> {
        // Folds to a constant in every instantiation, so neither arm carries a
        // policy test at runtime. Written once here rather than repeated at
        // each of the five burn sites, so adding a policy cannot leave one site
        // reading the old sense of the comparison.
        let per_insn = POLICY != POLICY_HOISTED;
        let mut pc: usize = 0;
        let mut frame_base: u64 = STACK_REGION + self.stack.len() as u64;
        loop {
            let at = pc as u32;
            if pc >= self.insns.len() {
                return Err(Trap::BadTarget { at });
            }
            let (insn, width) = decode(self.insns, pc).map_err(|_| Trap::Unsupported {
                at,
                what: "undecodable instruction",
            })?;
            self.steps = self.steps.wrapping_add(1);
            // Fuel burns per instruction retired, not only on back-edges.
            //
            // Burning only on back-edges and calls made fuel a bound on
            // *iterations* rather than on work: a straight-line program of
            // 65536 instructions cost one unit, so the default tank of 2^20
            // permitted on the order of 7e10 instructions per invocation. That
            // is not a usable bound in an atomic probe, where the program runs
            // with IRQs masked on someone else's timeslice.
            //
            // A decrement per instruction is what makes §4.9's claim — fuel
            // bounds total work — actually true. The interpreter is already
            // paying a decode and a match per instruction, so the marginal
            // cost is noise. The JIT will burn per basic block instead, which
            // is the same bound at coarser granularity.
            if per_insn {
                self.burn(at)?;
            }
            let next = pc + width;

            match insn {
                Decoded::Alu { wide, op, dst, src } => {
                    let a = self.reg(dst);
                    let b = self.src_value(src);
                    let v = alu(op, wide, a, b);
                    self.set_reg(at, dst, mask(v, wide))?;
                    pc = next;
                }
                Decoded::Neg { wide, dst } => {
                    let v = (self.reg(dst) as i64).wrapping_neg() as u64;
                    self.set_reg(at, dst, mask(v, wide))?;
                    pc = next;
                }
                Decoded::Mov {
                    wide,
                    dst,
                    src,
                    sign_extend,
                } => {
                    let raw = self.src_value(src);
                    let v = match sign_extend {
                        None => mask(raw, wide),
                        Some(8) => raw as i8 as i64 as u64,
                        Some(16) => raw as i16 as i64 as u64,
                        Some(_) => raw as i32 as i64 as u64,
                    };
                    self.set_reg(at, dst, if wide { v } else { mask(v, false) })?;
                    pc = next;
                }
                Decoded::Div {
                    wide,
                    signed,
                    dst,
                    src,
                } => {
                    let a = self.reg(dst);
                    let b = self.src_value(src);
                    // Linux defines division by zero as producing 0 rather
                    // than faulting (`kernel/bpf/core.c` DIV64_X handling), so
                    // the JIT's div-by-zero guard is a lowering rule, not a
                    // trap. Match it.
                    let v = div(a, b, wide, signed);
                    self.set_reg(at, dst, mask(v, wide))?;
                    pc = next;
                }
                Decoded::Mod {
                    wide,
                    signed,
                    dst,
                    src,
                } => {
                    let a = self.reg(dst);
                    let b = self.src_value(src);
                    let v = rem(a, b, wide, signed);
                    self.set_reg(at, dst, mask(v, wide))?;
                    pc = next;
                }
                Decoded::End { dst, order, width } => {
                    let v = byteswap(self.reg(dst), order, width);
                    self.set_reg(at, dst, v)?;
                    pc = next;
                }
                Decoded::AddrSpaceCast {
                    dst,
                    src,
                    dst_as,
                    src_as,
                } => {
                    // NARF needs no truncation sequence here, and that answers
                    // half of spec §8.1. Linux's `cast_kern`/`cast_user` exist
                    // because its in-program arena pointer is the low 32 bits of
                    // a *user* address, so moving between address spaces means
                    // adding or stripping the top half. A base-relative handle
                    // has the same value in both spaces — the base is supplied by
                    // the addressing mode, not by the pointer — so both casts are
                    // the identity, and the verifier models exactly that (it
                    // keeps `PtrClass::Arena` and loses the offset's precision,
                    // which is why a cast pointer usually needs re-bounding
                    // before it can be dereferenced).
                    //
                    // The pair is still checked: address space 1 is the arena, 0
                    // the kernel, and anything else is an encoding NARF has no
                    // meaning for. The verifier rejects it too; this is the
                    // runtime saying the same thing rather than trusting it.
                    if !matches!((dst_as, src_as), (0, 1) | (1, 0)) {
                        return Err(Trap::Unsupported {
                            at,
                            what: "address-space cast outside the arena pair",
                        });
                    }
                    let v = self.reg(src);
                    self.set_reg(at, dst, v)?;
                    pc = next;
                }
                Decoded::Load {
                    size,
                    sign_extend,
                    dst,
                    src,
                    off,
                } => {
                    let addr = self.reg(src).wrapping_add(off as i64 as u64);
                    let v = self.load(at, addr, size, sign_extend)?;
                    self.set_reg(at, dst, v)?;
                    pc = next;
                }
                Decoded::Store {
                    size,
                    dst,
                    off,
                    src,
                } => {
                    let addr = self.reg(dst).wrapping_add(off as i64 as u64);
                    let v = self.src_value(src);
                    self.store(at, addr, size, v)?;
                    pc = next;
                }
                Decoded::Atomic {
                    size,
                    op,
                    dst,
                    src,
                    off,
                } => {
                    let addr = self.reg(dst).wrapping_add(off as i64 as u64);
                    self.atomic(at, addr, size, op, src)?;
                    pc = next;
                }
                Decoded::LoadImm64 { dst, value } => {
                    let v = match value {
                        Imm64::Value(v) => v,
                        // A map handle is the map's own address. That is a real
                        // kernel pointer in a program-visible register, which is
                        // a deliberate exception to "the interpreter never
                        // dereferences a program-supplied address" — the
                        // interpreter still never dereferences it. Loads and
                        // stores through it are rejected (`stack_range` and the
                        // ctx window do not contain it, so `Trap::BadAccess`),
                        // and the only thing that *can* consume it is a kfunc
                        // whose `Trusted<BpfMap>` parameter the verifier proved
                        // was passed at offset zero. `crate::provisional` cannot
                        // discharge that obligation and therefore rejects every
                        // map form, so this value only ever exists in a fully
                        // verified program.
                        Imm64::MapFd(fd) => self.map_addr(at, self.map_by_fd(fd))?,
                        Imm64::MapIdx(idx) => {
                            let m = usize::try_from(idx)
                                .ok()
                                .and_then(|i| self.maps.get(i))
                                .map(|(_, m)| m);
                            self.map_addr(at, m)?
                        }
                        // LINUX-GAP: `BPF_PSEUDO_MAP_VALUE` — a pointer into
                        // the map's first value, which is what LLVM emits for a
                        // global variable. The verifier resolves and bounds it;
                        // the interpreter has no synthetic region that aliases a
                        // map's value bytes, and `BpfMapOps` is copy-based by
                        // design (see `map_lookup_elem`'s note on why a
                        // borrowed map-value pointer is not offered). Rejected
                        // at load by `BpfProg::load` so this arm is unreachable
                        // from a loaded program; it exists so that enabling the
                        // form cannot silently produce a wrong address.
                        Imm64::MapValue { .. } | Imm64::MapIdxValue { .. } => {
                            return Err(Trap::Unsupported {
                                at,
                                what: "LD_IMM64 map-value pseudo-form",
                            })
                        }
                        _ => {
                            return Err(Trap::Unsupported {
                                at,
                                what: "LD_IMM64 pseudo-form",
                            })
                        }
                    };
                    self.set_reg(at, dst, v)?;
                    pc = next;
                }
                Decoded::Jump { off } => {
                    // Gated on the policy, exactly as `JumpCond` below. It was
                    // not, so under the production per-instruction policy an
                    // unconditional backwards `goto` burned twice — once as an
                    // instruction retired and once again here — while the JIT
                    // charged it once as part of its block. Same program,
                    // different verdict depending on whether it happened to
                    // clear `jit_glue`'s gates.
                    if !per_insn && off < 0 {
                        self.burn(at)?;
                    }
                    pc = self.branch(at, next, off)?;
                }
                Decoded::JumpCond {
                    wide,
                    op,
                    dst,
                    src,
                    off,
                } => {
                    let a = self.reg(dst);
                    let b = self.src_value(src);
                    if cond(op, wide, a, b) {
                        // No extra burn for a back-edge: every instruction
                        // already burns one, so a loop pays per iteration
                        // through its body rather than a flat unit per turn.
                        // Under the hoisted policy this *is* the whole meter,
                        // so the back-edge has to pay for the iteration.
                        if !per_insn && off < 0 {
                            self.burn(at)?;
                        }
                        pc = self.branch(at, next, i32::from(off))?;
                    } else {
                        pc = next;
                    }
                }
                Decoded::MayGoto { off } => {
                    // `may_goto` exists in Linux because the verifier needs a
                    // bounded-loop construct. Fuel makes that unnecessary, so
                    // here it is simply a back-edge that burns fuel and stops
                    // branching when the tank is dry — the same observable
                    // behaviour with none of the machinery.
                    // The per-instruction burn above already stopped the
                    // program if the tank was dry, so reaching here means
                    // there is fuel and the branch may be taken. `may_goto`
                    // needs no counter of its own — that is the whole point of
                    // metering at runtime.
                    if !per_insn {
                        self.burn(at)?;
                    }
                    pc = self.branch(at, next, i32::from(off))?;
                }
                Decoded::Call(target) => match target {
                    narf_bpf_isa::CallTarget::Kfunc(id) => {
                        // The hoisted policy metered calls as well as
                        // back-edges, so a program could not spin through an
                        // unmetered kfunc loop. Kept for fidelity: the arm is
                        // only worth measuring if it is the policy that was
                        // actually replaced.
                        if !per_insn {
                            self.burn(at)?;
                        }
                        self.call_kfunc(at, id).await?;
                        pc = next;
                    }
                    narf_bpf_isa::CallTarget::Subprog(rel) => {
                        if !per_insn {
                            self.burn(at)?;
                        }
                        let target = self.subprog_target(at, next, rel)?;
                        self.push_frame(at, next, &mut frame_base, target as u32)?;
                        pc = target;
                    }
                },
                Decoded::Exit => {
                    if self.depth == 0 {
                        return Ok(self.regs[0]);
                    }
                    self.depth -= 1;
                    let f = self.frames[self.depth];
                    self.regs[6..11].copy_from_slice(&f.saved);
                    frame_base = f.frame_base;
                    self.current_sp = f.saved_sp;
                    pc = f.return_pc;
                }
            }
        }
    }

    // ── helpers ─────────────────────────────────────────────────────

    #[inline]
    fn reg(&self, r: Reg) -> u64 {
        self.regs[r.as_usize()]
    }

    #[inline]
    fn set_reg(&mut self, at: u32, r: Reg, v: u64) -> Result<(), Trap> {
        if r.is_frame_ptr() {
            return Err(Trap::WroteFramePointer { at });
        }
        self.regs[r.as_usize()] = v;
        Ok(())
    }

    #[inline]
    fn src_value(&self, src: Source) -> u64 {
        match src {
            Source::Reg(r) => self.reg(r),
            Source::Imm(i) => i as i64 as u64,
        }
    }

    /// Spend one unit of fuel. Exhaustion is a stop, not a fault (§4.9).
    #[inline]
    fn burn(&mut self, at: u32) -> Result<(), Trap> {
        match self.fuel.checked_sub(1) {
            Some(f) => {
                self.fuel = f;
                Ok(())
            }
            None => Err(Trap::OutOfFuel { at }),
        }
    }

    fn branch(&self, at: u32, next: usize, off: i32) -> Result<usize, Trap> {
        let target = (next as i64) + i64::from(off);
        if target < 0 || target as usize >= self.insns.len() {
            return Err(Trap::BadTarget { at });
        }
        Ok(target as usize)
    }

    fn subprog_target(&self, at: u32, next: usize, rel: i32) -> Result<usize, Trap> {
        let target = (next as i64) + i64::from(rel);
        if target < 0 || target as usize >= self.insns.len() {
            return Err(Trap::BadTarget { at });
        }
        Ok(target as usize)
    }

    fn push_frame(
        &mut self,
        at: u32,
        return_pc: usize,
        frame_base: &mut u64,
        target_slot: u32,
    ) -> Result<(), Trap> {
        if self.depth >= MAX_CALL_FRAMES {
            return Err(Trap::CallDepth { at });
        }
        // Which subprogram are we calling? Needed to track `current_sp` across
        // the call. The verifier creates a subprogram for every call target, so
        // a miss means the image and the descriptor disagree — refuse rather
        // than guess a layout.
        let callee_sp = self
            .subprogs
            .iter()
            .position(|s| s.start == target_slot)
            .ok_or(Trap::BadTarget { at })?;

        // The callee's frame sits directly below the *caller's*, so the amount
        // to descend is the size of the subprogram making the call — not the
        // size of the one being called.
        //
        // This used to look up the callee's size, which matched the verifier
        // only when caller and callee happened to be equal-sized. The verifier
        // models frames as disjoint and sizes the region as a sum down the
        // deepest path (`total[sp] = align8(depth[sp]) + max(callee totals)`),
        // so getting it backwards broke both ways:
        //
        //   * main uses 8 bytes, callee 512 → region is 520, top = SR+520, and
        //     subtracting the *callee's* 512 put its base at SR+8, so its
        //     `r10-512` addressed SR-504: a `BadAccess` in a program the
        //     verifier had proved fits.
        //   * main uses 512, callee 8 → the callee's base landed 8 below the
        //     top, i.e. *inside* main's frame, and it silently overwrote a slot
        //     the verifier had proved untouched (`clobber()` only runs when a
        //     frame pointer is actually passed, so main's slot model survived
        //     the call intact).
        let bytes = self
            .subprogs
            .get(self.current_sp)
            .map_or(FRAME_BYTES as u64, |s| u64::from(s.stack_bytes));
        let new_base = frame_base
            .checked_sub(bytes)
            .ok_or(Trap::StackExhausted { at })?;
        if new_base < STACK_REGION {
            return Err(Trap::StackExhausted { at });
        }
        let mut saved = [0u64; 5];
        saved.copy_from_slice(&self.regs[6..11]);
        self.frames[self.depth] = Frame {
            return_pc,
            saved,
            frame_base: *frame_base,
            saved_sp: self.current_sp,
        };
        self.depth += 1;
        self.current_sp = callee_sp;
        *frame_base = new_base;
        self.regs[10] = new_base;
        Ok(())
    }

    fn atomic(
        &mut self,
        at: u32,
        addr: u64,
        size: Size,
        op: AtomicOp,
        src: Reg,
    ) -> Result<(), Trap> {
        let wide = size == Size::Dw;
        // Arena memory is shared: the same frames are mapped into userspace and
        // may be reached from another CPU. A read-modify-write there has to be a
        // real atomic instruction, so it takes a separate path.
        //
        // The stack is different and stays where it was: the interpreter holds
        // the only reference to this frame, so a read-modify-write on it is
        // atomic by construction and the sequence below is a faithful *semantic*
        // model rather than an ordering implementation. That was the whole story
        // before arenas existed, which is why this comment used to say ordering
        // "arrives with shared maps and arenas in Phase 3" — for arenas it has,
        // just above.
        if self.has_arena() && self.stack_range(addr, size_bytes(size)).is_none() {
            return self.atomic_arena(at, addr, size, op, src);
        }
        let cur = self.load(at, addr, size, false)?;
        let operand = self.reg(src);
        let (new, fetched, writes_src) = match op {
            AtomicOp::Add { fetch } => (cur.wrapping_add(operand), cur, fetch),
            AtomicOp::Or { fetch } => (cur | operand, cur, fetch),
            AtomicOp::And { fetch } => (cur & operand, cur, fetch),
            AtomicOp::Xor { fetch } => (cur ^ operand, cur, fetch),
            AtomicOp::Xchg => (operand, cur, true),
            AtomicOp::LoadAcquire => (cur, cur, true),
            AtomicOp::StoreRelease => (operand, cur, false),
            AtomicOp::Cmpxchg => {
                // Compares against R0 and clobbers it with the pre-op value.
                let expected = mask(self.regs[0], wide);
                let new = if mask(cur, wide) == expected {
                    operand
                } else {
                    cur
                };
                self.regs[0] = mask(cur, wide);
                (new, cur, false)
            }
        };
        self.store(at, addr, size, new)?;
        if writes_src {
            self.set_reg(at, src, mask(fetched, wide))?;
        }
        Ok(())
    }

    /// A read-modify-write on arena memory, with real atomicity.
    ///
    /// Each BPF atomic maps onto one hardware primitive rather than onto a
    /// load-compute-store sequence, because the other side of the mapping is
    /// userspace and a sequence would give it a window to observe or clobber.
    ///
    /// Orderings mirror Linux's: the non-fetching forms are `atomic_add()` and
    /// friends, which carry no ordering, and the fetching forms are
    /// `atomic_fetch_add()` and friends, which Linux documents as fully ordered.
    /// `LoadAcquire`/`StoreRelease` say what they mean.
    fn atomic_arena(
        &mut self,
        at: u32,
        handle: u64,
        size: Size,
        op: AtomicOp,
        src: Reg,
    ) -> Result<(), Trap> {
        use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        let len = size_bytes(size);
        // BPF has no byte or halfword atomic — Linux's verifier rejects those
        // widths too — so there is nothing to lower rather than something to
        // emulate.
        if size != Size::W && size != Size::Dw {
            return Err(Trap::Unsupported {
                at,
                what: "atomic narrower than a word",
            });
        }
        let kva = self.arena_kva(at, handle, len)?;
        if kva % len as u64 != 0 {
            return Err(Trap::ArenaUnaligned { at, handle, len });
        }
        let wide = size == Size::Dw;
        let operand = self.reg(src);
        let expected = mask(self.regs[0], wide);

        // Fetching forms are fully ordered, non-fetching ones carry no ordering —
        // Linux's `atomic_fetch_add()` versus `atomic_add()`.
        let ord = |fetch: bool| {
            if fetch {
                Ordering::AcqRel
            } else {
                Ordering::Relaxed
            }
        };
        //
        // The two references below are *deliberately* not exclusive: the same
        // frames are mapped SHARED into userspace, which is the whole purpose of
        // an arena. That is why every access through them is an atomic operation
        // and none is a plain load or store. A concurrent *non*-atomic access
        // from the other side of the mapping is a race this cannot prevent and
        // does not claim to — the same is true of every `mmap_frames` mapping in
        // the tree, `/dev/fb0` included.
        let (fetched, writes_src) = if wide {
            // SAFETY: `arena_kva` proved `[kva, kva + 8)` lies inside a
            // populated, RW-mapped page of one of this program's arenas, and the
            // alignment check above makes `kva` a valid `AtomicU64` address. See
            // the note above on why shared access is intended.
            let a = unsafe { &*(kva as *const AtomicU64) };
            match op {
                AtomicOp::Add { fetch } => (a.fetch_add(operand, ord(fetch)), fetch),
                AtomicOp::Or { fetch } => (a.fetch_or(operand, ord(fetch)), fetch),
                AtomicOp::And { fetch } => (a.fetch_and(operand, ord(fetch)), fetch),
                AtomicOp::Xor { fetch } => (a.fetch_xor(operand, ord(fetch)), fetch),
                AtomicOp::Xchg => (a.swap(operand, Ordering::AcqRel), true),
                AtomicOp::LoadAcquire => (a.load(Ordering::Acquire), true),
                AtomicOp::StoreRelease => {
                    a.store(operand, Ordering::Release);
                    (0, false)
                }
                AtomicOp::Cmpxchg => {
                    // One instruction, not a loop: the program asked to swap
                    // exactly once and to be told what was there.
                    let prev = match a.compare_exchange(
                        expected,
                        operand,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(v) | Err(v) => v,
                    };
                    self.regs[0] = prev;
                    (prev, false)
                }
            }
        } else {
            // SAFETY: as the `AtomicU64` arm — bounded by `arena_kva`, 4-byte
            // aligned by the check above, and shared on purpose.
            let a = unsafe { &*(kva as *const AtomicU32) };
            let operand32 = operand as u32;
            match op {
                AtomicOp::Add { fetch } => (u64::from(a.fetch_add(operand32, ord(fetch))), fetch),
                AtomicOp::Or { fetch } => (u64::from(a.fetch_or(operand32, ord(fetch))), fetch),
                AtomicOp::And { fetch } => (u64::from(a.fetch_and(operand32, ord(fetch))), fetch),
                AtomicOp::Xor { fetch } => (u64::from(a.fetch_xor(operand32, ord(fetch))), fetch),
                AtomicOp::Xchg => (u64::from(a.swap(operand32, Ordering::AcqRel)), true),
                AtomicOp::LoadAcquire => (u64::from(a.load(Ordering::Acquire)), true),
                AtomicOp::StoreRelease => {
                    a.store(operand32, Ordering::Release);
                    (0, false)
                }
                AtomicOp::Cmpxchg => {
                    let prev = match a.compare_exchange(
                        expected as u32,
                        operand32,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(v) | Err(v) => v,
                    };
                    self.regs[0] = u64::from(prev);
                    (u64::from(prev), false)
                }
            }
        };
        if writes_src {
            self.set_reg(at, src, mask(fetched, wide))?;
        }
        Ok(())
    }

    async fn call_kfunc(&mut self, at: u32, id: i32) -> Result<(), Trap> {
        // The ring-buffer reserve/submit/discard kfuncs are intrinsics: they
        // read and write the VM's staged reservation, which a plain shim cannot
        // reach. Intercepted here before the registry dispatch, exactly as the
        // JIT refuses to compile them (`ringbuf::is_intrinsic`), so the two
        // backends agree that these run only interpreted. R1..R5 are the
        // argument registers; the BPF ABI clobbers them across any call.
        if crate::ringbuf::is_intrinsic(id) {
            self.regs[0] = if id == crate::ringbuf::RESERVE_ID {
                self.ringbuf_reserve(self.regs[1], self.regs[2], self.regs[3])
            } else if id == crate::ringbuf::SUBMIT_ID {
                self.ringbuf_submit();
                0
            } else {
                self.ringbuf_discard();
                0
            };
            self.regs[1..6].fill(0);
            return Ok(());
        }
        let entry = *self
            .registry
            .by_id(id)
            .ok_or(Trap::UnknownKfunc { at, id })?;
        // Re-checked here even though the verifier already rejected it: the
        // consequence of being wrong is a program sleeping with IRQs masked
        // and a per-CPU stack level held, which is not a failure worth
        // discovering in production.
        if !self.context.permits(entry.effective_context()) {
            return Err(Trap::WrongContext { at });
        }
        // R1..R5 are the argument registers; R0 takes the result. Everything
        // the callee did not declare arrives as the caller left it, which is
        // harmless because the shim only reads the registers its own
        // signature names.
        let mut args = [
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
        ];

        // Translate byte-region arguments from the interpreter's *synthetic*
        // address space into real kernel addresses.
        //
        // This is the seam `crate::provisional` rests its whole safety story on
        // — "the interpreter never dereferences a program-supplied address" —
        // and for byte regions that was false the moment such a kfunc existed.
        // R10 here is `STACK_REGION` (0x0000_2000_0000_0000), a *fabricated*
        // base, and `<&[u8]>::from_raw` does
        // `core::slice::from_raw_parts(raw as *const u8, len)` on the register
        // verbatim. So a `kfunc!` taking `&[u8]` would have been handed a slice
        // pointing into the **user half** of the address space (`0x2000…` is
        // canonical and user-mappable): a fault or SMAP violation at best, a
        // user-influenced address at worst.
        //
        // The verifier cannot prevent this — `check_mem_arg` proves the pointer
        // is an in-bounds *BPF stack* offset, which is exactly the thing that
        // is not a kernel address. And the same kfunc works correctly under the
        // JIT, where R10 really is the frame, so the interpreter was the only
        // backend where it broke.
        //
        // Translated rather than rejected because the descriptors are already
        // expressive enough to be correct here, and refusing `PtrKind::Mem`
        // outright would make `&[u8]`/`&mut MaybeUninit<T>` undeclarable.
        for (k, arg) in entry.args.iter().enumerate().take(args.len()) {
            let is_mem = matches!(
                arg.kind,
                narf_bpf_verifier::TypeKind::Ptr {
                    kind: narf_bpf_verifier::PtrKind::Mem,
                    ..
                }
            );
            if !is_mem {
                continue;
            }
            let synthetic = args[k];
            // A null region stays null: `from_raw` maps it to an empty slice,
            // which is what a `NULLABLE` byte-region argument means.
            if synthetic == 0 {
                continue;
            }
            // `SIZED_BY_NEXT` puts the length in the following register. The
            // descriptor validator guarantees that register exists and is a
            // scalar, so `k + 1` is in range.
            let len = if arg
                .flags
                .contains(narf_bpf_verifier::ArgFlags::SIZED_BY_NEXT)
            {
                args.get(k + 1).copied().unwrap_or(0)
            } else {
                // No declared length: the callee reads a fixed-size `T`, and
                // the narrowest thing we can safely admit is a single byte —
                // anything more would be asserting a size the descriptor did
                // not state. `check_mem_arg` currently rejects this shape
                // outright, so this arm is unreachable today and exists so that
                // enabling it cannot silently skip the bounds check.
                1
            };
            let (lo, hi) = self
                .stack_range(synthetic, usize::try_from(len).unwrap_or(usize::MAX))
                .ok_or(Trap::BadAccess {
                    at,
                    addr: synthetic,
                    len: usize::try_from(len).unwrap_or(usize::MAX),
                })?;
            debug_assert!(hi <= self.stack.len());
            let base = self.stack.bytes_mut().as_mut_ptr();
            // SAFETY: `stack_range` proved `lo..hi` lies inside the frame, so
            // `base.add(lo)` is in bounds of the same allocation.
            args[k] = unsafe { base.add(lo) } as u64;
        }
        let (a0, a1, a2, a3, a4) = (args[0], args[1], args[2], args[3], args[4]);
        self.regs[0] = match entry.shim {
            KfuncShim::Sync(f) => f(a0, a1, a2, a3, a4),
            // The point of the two-variant ABI: a kfunc that suspends is just
            // an `.await` here. Under a uniform `u64`-returning shim there was
            // nowhere to put the suspension, so `narf_yield()` had to be an
            // interpreter intrinsic and no other kfunc could sleep at all.
            KfuncShim::Sleepable(f) => f(a0, a1, a2, a3, a4).await,
        };
        // The BPF ABI clobbers R1..R5 across a call.
        self.regs[1..6].fill(0);
        Ok(())
    }
}

// ── pure ALU helpers ────────────────────────────────────────────────

#[inline]
const fn size_bytes(s: Size) -> usize {
    match s {
        Size::B => 1,
        Size::H => 2,
        Size::W => 4,
        Size::Dw => 8,
    }
}

#[inline]
const fn mask(v: u64, wide: bool) -> u64 {
    if wide {
        v
    } else {
        v & 0xFFFF_FFFF
    }
}

#[inline]
const fn widen(raw: u64, size: Size, signed: bool) -> u64 {
    match (size, signed) {
        (Size::B, false) => raw & 0xFF,
        (Size::H, false) => raw & 0xFFFF,
        (Size::W, false) => raw & 0xFFFF_FFFF,
        (Size::Dw, _) => raw,
        (Size::B, true) => raw as u8 as i8 as i64 as u64,
        (Size::H, true) => raw as u16 as i16 as i64 as u64,
        (Size::W, true) => raw as u32 as i32 as i64 as u64,
    }
}

fn alu(op: AluOp, wide: bool, a: u64, b: u64) -> u64 {
    // Shift counts wrap at the operand width, exactly as the hardware does
    // and exactly as Linux's interpreter does.
    let shift = if wide { b & 63 } else { b & 31 } as u32;
    match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::Mul => a.wrapping_mul(b),
        AluOp::Or => a | b,
        AluOp::And => a & b,
        AluOp::Xor => a ^ b,
        AluOp::Lsh => {
            if wide {
                a.wrapping_shl(shift)
            } else {
                ((a as u32).wrapping_shl(shift)) as u64
            }
        }
        AluOp::Rsh => {
            if wide {
                a.wrapping_shr(shift)
            } else {
                ((a as u32).wrapping_shr(shift)) as u64
            }
        }
        AluOp::Arsh => {
            if wide {
                (a as i64).wrapping_shr(shift) as u64
            } else {
                ((a as u32 as i32).wrapping_shr(shift)) as u32 as u64
            }
        }
    }
}

fn div(a: u64, b: u64, wide: bool, signed: bool) -> u64 {
    if wide {
        if signed {
            let (x, y) = (a as i64, b as i64);
            if y == 0 {
                0
            } else {
                x.wrapping_div(y) as u64
            }
        } else if b == 0 {
            0
        } else {
            a / b
        }
    } else if signed {
        let (x, y) = (a as u32 as i32, b as u32 as i32);
        if y == 0 {
            0
        } else {
            x.wrapping_div(y) as u32 as u64
        }
    } else {
        let (x, y) = (a as u32, b as u32);
        if y == 0 {
            0
        } else {
            u64::from(x / y)
        }
    }
}

fn rem(a: u64, b: u64, wide: bool, signed: bool) -> u64 {
    // Linux leaves the dividend untouched when the divisor is zero (the JIT
    // skips the division), which differs from the quotient case returning 0.
    if wide {
        if signed {
            let (x, y) = (a as i64, b as i64);
            if y == 0 {
                a
            } else {
                x.wrapping_rem(y) as u64
            }
        } else if b == 0 {
            a
        } else {
            a % b
        }
    } else if signed {
        let (x, y) = (a as u32 as i32, b as u32 as i32);
        if y == 0 {
            a & 0xFFFF_FFFF
        } else {
            x.wrapping_rem(y) as u32 as u64
        }
    } else {
        let (x, y) = (a as u32, b as u32);
        if y == 0 {
            u64::from(x)
        } else {
            u64::from(x % y)
        }
    }
}

fn cond(op: CondOp, wide: bool, a: u64, b: u64) -> bool {
    if wide {
        match op {
            CondOp::Eq => a == b,
            CondOp::Ne => a != b,
            CondOp::Gt => a > b,
            CondOp::Ge => a >= b,
            CondOp::Lt => a < b,
            CondOp::Le => a <= b,
            CondOp::Sgt => (a as i64) > (b as i64),
            CondOp::Sge => (a as i64) >= (b as i64),
            CondOp::Slt => (a as i64) < (b as i64),
            CondOp::Sle => (a as i64) <= (b as i64),
            CondOp::Set => (a & b) != 0,
        }
    } else {
        let (x, y) = (a as u32, b as u32);
        match op {
            CondOp::Eq => x == y,
            CondOp::Ne => x != y,
            CondOp::Gt => x > y,
            CondOp::Ge => x >= y,
            CondOp::Lt => x < y,
            CondOp::Le => x <= y,
            CondOp::Sgt => (x as i32) > (y as i32),
            CondOp::Sge => (x as i32) >= (y as i32),
            CondOp::Slt => (x as i32) < (y as i32),
            CondOp::Sle => (x as i32) <= (y as i32),
            CondOp::Set => (x & y) != 0,
        }
    }
}

fn byteswap(v: u64, order: ByteOrder, width: u8) -> u64 {
    // NARF is little-endian on both supported targets, so `Little` is the
    // identity and `Big`/`Swap` reverse.
    let swap = match order {
        ByteOrder::Little => false,
        ByteOrder::Big | ByteOrder::Swap => true,
    };
    match (width, swap) {
        (16, true) => u64::from((v as u16).swap_bytes()),
        (16, false) => v & 0xFFFF,
        (32, true) => u64::from((v as u32).swap_bytes()),
        (32, false) => v & 0xFFFF_FFFF,
        (_, true) => v.swap_bytes(),
        (_, false) => v,
    }
}

/// Drive a future to completion on the current thread with a no-op waker.
///
/// Legal here — and only here — because the interpreter's *only* await point
/// is [`YieldNow`], which wakes itself before returning `Pending`. There is no
/// external event to wait on, so this loop always terminates and never blocks
/// a CPU on something that will not happen. A real sleepable kfunc that parks
/// on I/O would need a real executor task instead; that is the Phase-2
/// question recorded in `bpf/specification/spec.md` §8.
pub fn drive<F: Future>(fut: F) -> F::Output {
    use core::task::{RawWaker, RawWakerVTable, Waker};

    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

    // SAFETY: the vtable's four entries are all no-ops over a null data
    // pointer, so every operation the waker can perform is trivially valid.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = TaskContext::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
