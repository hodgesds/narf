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
//! The interpreter never dereferences a program-supplied address. Every
//! pointer a program can hold names a byte offset into one of a small set of
//! synthetic regions, and every load and store is bounds-checked against
//! them. A program that escapes its regions gets [`Trap::BadAccess`] and is
//! terminated; it cannot reach kernel memory even if the verifier is wrong,
//! which matters while the abstract interpreter is still Phase 2. The JIT
//! trades these checks for the extable and the arena guard slots — that is
//! the same bargain Linux strikes at `verifier.c:16186`, and it is only sound
//! once the verifier is real.

use alloc::vec::Vec;
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
#[derive(Copy, Clone, Debug)]
struct Frame {
    /// Instruction index to resume at.
    return_pc: usize,
    /// Callee-saved registers, per the BPF ABI: R6..R9 plus R10.
    saved: [u64; 5],
    /// The caller's frame base within the stack region.
    frame_base: u64,
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
}

/// The virtual machine.
pub struct Vm<'a> {
    regs: [u64; 11],
    fuel: u64,
    insns: &'a [Insn],
    ctx: [u64; MAX_CTX_WORDS],
    ctx_len: usize,
    stack: StackFrame<'a>,
    frames: Vec<Frame>,
    /// Per-subprogram stack sizes, from the verifier.
    ///
    /// Frames used to be a fixed [`FRAME_BYTES`], which disagreed with the
    /// verifier in both directions: a program of eight tiny subprograms
    /// verified with a 64-byte budget and then exhausted the region on its
    /// *first* call, while a single 1 KiB callee verified and then wrote
    /// below the region. `Ok` from the verifier is only meaningful if the
    /// frames are laid out the way it modelled them.
    subprogs: &'a [SubprogInfo],
    registry: &'static Registry,
    context: Context,
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
            frames: Vec::new(),
            subprogs,
            registry,
            context,
            steps: 0,
        }
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

    fn load(&mut self, at: u32, addr: u64, size: Size, signed: bool) -> Result<u64, Trap> {
        let len = size_bytes(size);
        if let Some((lo, hi)) = self.stack_range(addr, len) {
            let mut buf = [0u8; 8];
            buf[..len].copy_from_slice(&self.stack.bytes_mut()[lo..hi]);
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
        Err(Trap::BadAccess { at, addr, len })
    }

    fn store(&mut self, at: u32, addr: u64, size: Size, value: u64) -> Result<(), Trap> {
        let len = size_bytes(size);
        let (lo, hi) = self
            .stack_range(addr, len)
            .ok_or(Trap::BadAccess { at, addr, len })?;
        let bytes = value.to_le_bytes();
        self.stack.bytes_mut()[lo..hi].copy_from_slice(&bytes[..len]);
        Ok(())
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
                Decoded::AddrSpaceCast { .. } => {
                    return Err(Trap::Unsupported {
                        at,
                        what: "address-space cast (arenas are Phase 3)",
                    })
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
                        _ => {
                            return Err(Trap::Unsupported {
                                at,
                                what: "LD_IMM64 pseudo-form (maps are Phase 3)",
                            })
                        }
                    };
                    self.set_reg(at, dst, v)?;
                    pc = next;
                }
                Decoded::Jump { off } => {
                    pc = self.branch(at, next, off)?;
                    if off < 0 {
                        self.burn(at)?;
                    }
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
                Decoded::Exit => match self.frames.pop() {
                    None => return Ok(self.regs[0]),
                    Some(f) => {
                        self.regs[6..11].copy_from_slice(&f.saved);
                        frame_base = f.frame_base;
                        pc = f.return_pc;
                    }
                },
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
        if self.frames.len() >= MAX_CALL_FRAMES {
            return Err(Trap::CallDepth { at });
        }
        // The callee's frame is exactly what the verifier sized it at. A
        // fixed width here is what made `Ok` from the verifier meaningless:
        // it modelled one layout and the interpreter used another.
        let bytes = self
            .subprogs
            .iter()
            .find(|s| s.start == target_slot)
            .map_or(FRAME_BYTES as u64, |s| u64::from(s.stack_bytes));
        let new_base = frame_base
            .checked_sub(bytes)
            .ok_or(Trap::StackExhausted { at })?;
        if new_base < STACK_REGION {
            return Err(Trap::StackExhausted { at });
        }
        let mut saved = [0u64; 5];
        saved.copy_from_slice(&self.regs[6..11]);
        self.frames.push(Frame {
            return_pc,
            saved,
            frame_base: *frame_base,
        });
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
        // Single-threaded with respect to the program: the interpreter holds
        // the only reference to this stack frame, so a read-modify-write is
        // atomic by construction. Real atomicity — and real memory ordering
        // for `LoadAcquire`/`StoreRelease` — arrives with shared maps and
        // arenas in Phase 3. This is a faithful *semantic* model and is
        // marked so nobody mistakes it for an ordering implementation.
        let wide = size == Size::Dw;
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

    async fn call_kfunc(&mut self, at: u32, id: i32) -> Result<(), Trap> {
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
        let (a0, a1, a2, a3, a4) = (
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
        );
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
