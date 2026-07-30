//! The forward worklist fixpoint, and the per-instruction transfer functions.
//!
//! ## Termination is by construction
//!
//! There is no instruction budget, no state-count limit, no per-instruction
//! visit cap. Linux needs all three (`BPF_COMPLEXITY_LIMIT_INSNS` at 1M, 8192
//! pushed states, 64 states per instruction) because it explores a *tree* of
//! near-concrete states and has to stop somewhere; `bpf_design_QA.rst:105`
//! concedes the consequence — "the only way to know that the program is going
//! to be accepted by the verifier is to try to load it."
//!
//! This is one abstract state per program point, joined at merges. The state
//! lattice has finite height — eleven registers over a domain whose tnum
//! saturates in 64 steps, a stack bounded by the stack budget, and a reference
//! set keyed by *acquisition site* rather than by a fresh counter — and every
//! transfer function is monotone. So the fixpoint converges on any CFG, for
//! any program, and acceptance is a function of the program alone.
//!
//! Widening exists to make convergence *fast*, not to make it happen. It is
//! applied wherever [`crate::ir::Block::widen_here`] is set: back-edge targets
//! and, for the irreducible cases dominance cannot see, entries into a
//! non-trivial SCC.
//!
//! The termination question Linux is really asking — does the *program*
//! terminate? — NARF answers at runtime with fuel. That is what lets this file
//! contain no loop constructs, no `may_goto` counter, no open-coded-iterator
//! convergence heuristic, and no back-edge rejection.
//!
//! ## Interprocedural analysis
//!
//! Subprograms are analysed one at a time in call-graph topological order,
//! each with its own frame. A callee's entry state is the join of its call
//! sites' argument registers; a stack pointer passed as an argument becomes a
//! bounded [`PtrClass::Mem`] region in the callee, which decouples the frames
//! without needing Linux's `frame[MAX_CALL_FRAMES]` array.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::{AluOp, AtomicOp, CallTarget, CondOp, Decoded, Imm64, Reg, Size, Source};

use crate::domain::Scalar;
use crate::ir::Ir;
use crate::kfunc::{ArgDesc, ArgFlags, Context, KfuncDesc, PtrKind, TypeKind};
use crate::liveness::{self, Masks};
use crate::state::{weaker_domain, AbsState, AbsValue, PtrClass, PtrVal, Ref, Stack, NO_REF};
use crate::{FaultSite, Program, SubprogInfo, VerifiedProgram, VerifyError, MAX_STACK_BYTES};

/// Everything the fixpoint accumulates that outlives a single block.
struct Analysis<'a, 'p> {
    ir: &'a Ir,
    prog: &'a Program<'p>,
    live: Masks,
    prec: Masks,
    fault_sites: Vec<FaultSite>,
    uses_arena: bool,
    /// Entry state per subprogram, built up from call sites.
    entry: Vec<Option<AbsState>>,
    /// Deepest stack byte each subprogram touches.
    depth: Vec<u32>,
    /// Which subprogram is being analysed, for depth accounting.
    current: u32,
}

/// Verify a program: build the IR, run the fixpoint, and assemble the result.
///
/// # Errors
///
/// The first [`VerifyError`] found. The verifier fails closed.
pub fn run(prog: &Program<'_>) -> Result<VerifiedProgram, VerifyError> {
    let ir = Ir::build(prog.insns)?;
    let order = topological_order(&ir)?;

    let ctx_size = (prog.ctx_fields.len() as u64) * 8;
    let mut a = Analysis {
        live: liveness::liveness(&ir),
        prec: liveness::precision(&ir),
        ir: &ir,
        prog,
        fault_sites: Vec::new(),
        uses_arena: false,
        entry: vec![None; ir.subprogs.len()],
        depth: vec![0; ir.subprogs.len()],
        current: 0,
    };
    a.entry[0] = Some(AbsState::entry(ctx_size));

    for &sp in &order {
        // A subprogram nothing calls is dead code. Skipping it is not a
        // soundness hole — it can never run, and inventing an entry state
        // would mean reporting errors in instructions that never execute.
        let Some(entry) = a.entry[sp as usize].clone() else {
            continue;
        };
        a.current = sp;
        a.analyse_subprog(sp, entry)?;
    }

    // Stack depth along the call graph. Linux's
    // `check_max_stack_depth_subprog()` is 159 lines because the BPF stack
    // lives on the *kernel* stack and every frame has to fit inside 512 bytes;
    // NARF gives BPF its own region (spec §1.5), so this is a sum over a DAG.
    let mut total = vec![0u32; ir.subprogs.len()];
    for &sp in order.iter().rev() {
        let callee_max = ir.subprogs[sp as usize]
            .callees
            .iter()
            .map(|&c| total[c as usize])
            .max()
            .unwrap_or(0);
        total[sp as usize] = align8(a.depth[sp as usize]) + callee_max;
    }
    // Nesting depth along the same DAG. The runtime enforces a frame limit,
    // so the verifier has to agree with it — otherwise a deep-but-safe program
    // verifies and then traps on its first run.
    let mut depth = vec![1u32; ir.subprogs.len()];
    for &sp in order.iter().rev() {
        let callee_max = ir.subprogs[sp as usize]
            .callees
            .iter()
            .map(|&c| depth[c as usize])
            .max()
            .unwrap_or(0);
        depth[sp as usize] = 1 + callee_max;
    }
    if depth[0] > crate::MAX_CALL_DEPTH {
        return Err(VerifyError::CallDepth {
            needed: depth[0],
            limit: crate::MAX_CALL_DEPTH,
        });
    }

    let max_stack_bytes = total[0];
    if max_stack_bytes > MAX_STACK_BYTES {
        return Err(VerifyError::StackTooDeep {
            needed: max_stack_bytes,
            limit: MAX_STACK_BYTES,
        });
    }

    let mut fault_sites = a.fault_sites;
    fault_sites.sort_unstable_by_key(|f| f.insn_index);
    fault_sites.dedup_by_key(|f| f.insn_index);

    let subprogs = ir
        .subprogs
        .iter()
        .enumerate()
        .map(|(i, s)| SubprogInfo {
            start: s.entry_slot,
            stack_bytes: align8(a.depth[i]),
        })
        .collect();

    Ok(VerifiedProgram {
        insns: prog.insns.to_vec(),
        context: prog.context,
        max_stack_bytes,
        initial_fuel: crate::DEFAULT_FUEL,
        fault_sites,
        subprogs,
        uses_arena: a.uses_arena,
    })
}

/// Worklist rounds allowed before we declare the fixpoint divergent.
///
/// Generous: with a sound widening operator a block re-enters the worklist a
/// small constant number of times, so anything approaching this is a bug in
/// the lattice rather than an unusually hard program. Sized off the block
/// count so a large program is not penalised for being large, and saturating
/// so the arithmetic itself cannot be the overflow.
pub(crate) fn fixpoint_round_budget(blocks: usize) -> u64 {
    const PER_BLOCK: u64 = 512;
    const FLOOR: u64 = 16_384;
    (blocks as u64).saturating_mul(PER_BLOCK).max(FLOOR)
}

fn align8(n: u32) -> u32 {
    n.div_ceil(8) * 8
}

/// Call-graph topological order, callers before callees.
///
/// A cycle is rejected: fuel bounds a program's *work*, not its stack, so
/// recursion has no depth this verifier can compute and no runtime mechanism
/// that would catch the overflow.
fn topological_order(ir: &Ir) -> Result<Vec<u32>, VerifyError> {
    let n = ir.subprogs.len();
    let mut indegree = vec![0u32; n];
    for sp in &ir.subprogs {
        for &c in &sp.callees {
            indegree[c as usize] += 1;
        }
    }
    let mut ready: Vec<u32> = (0..n as u32)
        .filter(|&i| indegree[i as usize] == 0)
        .collect();
    let mut order = Vec::with_capacity(n);
    while let Some(sp) = ready.pop() {
        order.push(sp);
        for &c in &ir.subprogs[sp as usize].callees {
            indegree[c as usize] -= 1;
            if indegree[c as usize] == 0 {
                ready.push(c);
            }
        }
    }
    if order.len() != n {
        let stuck = (0..n).find(|&i| indegree[i] > 0).unwrap_or(0);
        return Err(VerifyError::Recursion {
            at: ir.subprogs[stuck].entry_slot,
        });
    }
    Ok(order)
}

/// A jump predicate, extended with the one the ISA cannot spell.
///
/// `JSET`'s negation — "no bits in common" — is not an opcode, but it is the
/// side of the branch that actually deduces something, so refinement needs a
/// vocabulary one member larger than [`CondOp`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Pred {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Sgt,
    Sge,
    Slt,
    Sle,
    Set,
    NotSet,
}

impl Pred {
    fn of(op: CondOp) -> Pred {
        match op {
            CondOp::Eq => Pred::Eq,
            CondOp::Ne => Pred::Ne,
            CondOp::Gt => Pred::Gt,
            CondOp::Ge => Pred::Ge,
            CondOp::Lt => Pred::Lt,
            CondOp::Le => Pred::Le,
            CondOp::Sgt => Pred::Sgt,
            CondOp::Sge => Pred::Sge,
            CondOp::Slt => Pred::Slt,
            CondOp::Sle => Pred::Sle,
            CondOp::Set => Pred::Set,
        }
    }

    fn negate(self) -> Pred {
        match self {
            Pred::Eq => Pred::Ne,
            Pred::Ne => Pred::Eq,
            Pred::Gt => Pred::Le,
            Pred::Ge => Pred::Lt,
            Pred::Lt => Pred::Ge,
            Pred::Le => Pred::Gt,
            Pred::Sgt => Pred::Sle,
            Pred::Sge => Pred::Slt,
            Pred::Slt => Pred::Sge,
            Pred::Sle => Pred::Sgt,
            Pred::Set => Pred::NotSet,
            Pred::NotSet => Pred::Set,
        }
    }

    /// Whether the comparison is unsigned, which decides how a 32-bit form may
    /// be reflected into a 64-bit abstract value.
    fn is_unsigned(self) -> bool {
        matches!(
            self,
            Pred::Eq
                | Pred::Ne
                | Pred::Gt
                | Pred::Ge
                | Pred::Lt
                | Pred::Le
                | Pred::Set
                | Pred::NotSet
        )
    }
}

impl Analysis<'_, '_> {
    /// Intra-subprogram forward fixpoint.
    fn analyse_subprog(&mut self, sp: u32, entry: AbsState) -> Result<(), VerifyError> {
        let entry_block = self.ir.subprogs[sp as usize].entry_block;
        let reachable = liveness::reachable_blocks(self.ir, entry_block);

        let mut in_state: Vec<Option<AbsState>> = vec![None; self.ir.blocks.len()];
        in_state[entry_block as usize] = Some(entry);
        let mut worklist = vec![entry_block];

        // Hard cap on worklist rounds.
        //
        // Termination is supposed to be structural — a finite-height lattice
        // plus a widening operator at every back-edge target. This cap is the
        // backstop for that argument being *wrong*, and it has already earned
        // its place: stack slots were joined rather than widened, so any value
        // carried around a loop through a slot climbed forever. Without a cap
        // that is not a slow load, it is a kernel hang — `verify()` runs
        // synchronously inside `sys_bpf` with no yield point, and the
        // scheduler does not tick inside a syscall.
        //
        // Exceeding it is a verifier bug, not a program bug, so it is worth
        // reporting distinctly from an ordinary rejection.
        let mut rounds = 0u64;
        let budget = fixpoint_round_budget(self.ir.blocks.len());

        while let Some(b) = worklist.pop() {
            rounds += 1;
            if rounds > budget {
                return Err(VerifyError::FixpointDiverged {
                    subprog: sp,
                    rounds,
                });
            }
            let Some(start) = in_state[b as usize].clone() else {
                continue;
            };
            for (succ, st) in self.walk_block(b, start)? {
                if !reachable[succ as usize] {
                    continue;
                }
                let (merged, changed) = match &in_state[succ as usize] {
                    None => (st, true),
                    Some(old) => {
                        let m = if self.ir.blocks[succ as usize].widen_here {
                            let entry = self.ir.blocks[succ as usize].start;
                            old.widen(&st, &self.ir.thresholds, self.prec.before[entry as usize])
                        } else {
                            old.join(&st)
                        };
                        let changed = !m.is_subset_of(old);
                        (m, changed)
                    }
                };
                if changed {
                    in_state[succ as usize] = Some(merged);
                    if !worklist.contains(&succ) {
                        worklist.push(succ);
                    }
                }
            }
        }
        Ok(())
    }

    /// Run one block's instructions and produce each successor's input state.
    fn walk_block(
        &mut self,
        b: u32,
        mut st: AbsState,
    ) -> Result<Vec<(u32, AbsState)>, VerifyError> {
        let (start, end, succs) = {
            let blk = &self.ir.blocks[b as usize];
            (blk.start, blk.end, blk.succs.clone())
        };
        let last = end - 1;
        for i in start..last {
            self.step(&mut st, i)?;
        }

        let insn = self.ir.insns[last as usize];
        let at = insn.slot;
        match insn.op {
            Decoded::Exit => {
                self.check_exit(&st, at)?;
                Ok(Vec::new())
            }
            Decoded::JumpCond {
                wide,
                op,
                dst,
                src,
                off,
            } => {
                let taken_block = self.block_at_slot(insn.next_slot(), i64::from(off));
                let fall_block = self.block_at_slot(insn.next_slot(), 0);
                let p = Pred::of(op);
                let mut out = Vec::new();
                if let Some(s) = self.refine(&st, at, wide, p, dst, src)? {
                    out.push((taken_block, s));
                }
                if let Some(s) = self.refine(&st, at, wide, p.negate(), dst, src)? {
                    out.push((fall_block, s));
                }
                Ok(out)
            }
            // `may_goto` decrements a counter the verifier does not model, so
            // both edges are simply possible. Linux needs dedicated state for
            // it precisely because it is trying to bound the loop; under fuel
            // there is nothing to bound.
            Decoded::MayGoto { off } => Ok(vec![
                (
                    self.block_at_slot(insn.next_slot(), i64::from(off)),
                    st.clone(),
                ),
                (self.block_at_slot(insn.next_slot(), 0), st),
            ]),
            _ => {
                self.step(&mut st, last)?;
                Ok(succs.iter().map(|&s| (s, st.clone())).collect())
            }
        }
    }

    fn block_at_slot(&self, next_slot: u32, off: i64) -> u32 {
        let target = (i64::from(next_slot) + off) as usize;
        self.ir.block_of[self.ir.ir_of_slot[target] as usize]
    }

    // ── Register access helpers ─────────────────────────────────────

    fn get(&self, st: &AbsState, at: u32, r: Reg) -> Result<AbsValue, VerifyError> {
        match st.regs[r.as_usize()] {
            AbsValue::NotInit => Err(VerifyError::UninitRegister { at, reg: r.index() }),
            v => Ok(v),
        }
    }

    fn get_scalar(&self, st: &AbsState, at: u32, r: Reg) -> Result<Scalar, VerifyError> {
        match self.get(st, at, r)? {
            AbsValue::Scalar(s) => Ok(s),
            _ => Err(VerifyError::PointerArithmetic { at, reg: r.index() }),
        }
    }

    fn get_ptr(&self, st: &AbsState, at: u32, r: Reg) -> Result<PtrVal, VerifyError> {
        match self.get(st, at, r)? {
            AbsValue::Ptr(p) => Ok(p),
            _ => Err(VerifyError::NotAPointer { at, reg: r.index() }),
        }
    }

    fn set(&self, st: &mut AbsState, at: u32, r: Reg, v: AbsValue) -> Result<(), VerifyError> {
        if r.is_frame_ptr() {
            return Err(VerifyError::WriteToFramePointer { at });
        }
        st.regs[r.as_usize()] = v;
        Ok(())
    }

    /// The value of an ALU or jump source operand.
    fn source(
        &self,
        st: &AbsState,
        at: u32,
        src: Source,
        wide: bool,
    ) -> Result<AbsValue, VerifyError> {
        match src {
            Source::Reg(r) => self.get(st, at, r),
            // A 64-bit operation sign-extends the immediate; a 32-bit one
            // works on the low half, so the two views differ above bit 31.
            Source::Imm(k) => Ok(AbsValue::Scalar(Scalar::constant(if wide {
                i64::from(k)
            } else {
                i64::from(k as u32)
            }))),
        }
    }

    fn scalar_source(
        &self,
        st: &AbsState,
        at: u32,
        src: Source,
        wide: bool,
    ) -> Result<Scalar, VerifyError> {
        match self.source(st, at, src, wide)? {
            AbsValue::Scalar(s) => Ok(s),
            _ => Err(VerifyError::PointerArithmetic {
                at,
                reg: match src {
                    Source::Reg(r) => r.index(),
                    Source::Imm(_) => 0,
                },
            }),
        }
    }

    // ── The transfer function ───────────────────────────────────────

    fn step(&mut self, st: &mut AbsState, i: u32) -> Result<(), VerifyError> {
        let insn = self.ir.insns[i as usize];
        let at = insn.slot;
        match insn.op {
            Decoded::Alu { wide, op, dst, src } => self.alu(st, at, wide, op, dst, src),

            Decoded::Neg { wide, dst } => {
                let d = self.get_scalar(st, at, dst)?;
                self.set(st, at, dst, AbsValue::Scalar(d.neg_op(wide)))
            }

            Decoded::Mov {
                wide,
                dst,
                src,
                sign_extend,
            } => {
                let v = self.source(st, at, src, wide)?;
                let out = match v {
                    // A full-width plain move copies a pointer intact; any
                    // narrowing or sign-extending form does not, because the
                    // result is no longer the same address.
                    AbsValue::Ptr(p) if wide && sign_extend.is_none() => AbsValue::Ptr(p),
                    AbsValue::Ptr(_) => AbsValue::UNKNOWN_SCALAR,
                    AbsValue::Scalar(s) => AbsValue::Scalar(s.mov_op(wide, sign_extend)),
                    AbsValue::NotInit => AbsValue::NotInit,
                };
                self.set(st, at, dst, out)
            }

            Decoded::Div {
                wide,
                signed,
                dst,
                src,
            } => {
                let d = self.get_scalar(st, at, dst)?;
                let s = self.scalar_source(st, at, src, wide)?;
                self.set(st, at, dst, AbsValue::Scalar(d.div_op(wide, signed, &s)))
            }

            Decoded::Mod {
                wide,
                signed,
                dst,
                src,
            } => {
                let d = self.get_scalar(st, at, dst)?;
                let s = self.scalar_source(st, at, src, wide)?;
                self.set(st, at, dst, AbsValue::Scalar(d.mod_op(wide, signed, &s)))
            }

            Decoded::End { dst, order, width } => {
                let d = self.get_scalar(st, at, dst)?;
                self.set(st, at, dst, AbsValue::Scalar(d.end_op(order, width)))
            }

            Decoded::AddrSpaceCast {
                dst,
                src,
                dst_as,
                src_as,
            } => self.addr_space_cast(st, at, dst, src, dst_as, src_as),

            Decoded::Load {
                size,
                sign_extend,
                dst,
                src,
                off,
            } => self.load(st, at, size, sign_extend, dst, src, off),

            Decoded::Store {
                size,
                dst,
                off,
                src,
            } => self.store(st, at, size, dst, off, src),

            Decoded::Atomic {
                size,
                op,
                dst,
                src,
                off,
            } => self.atomic(st, at, size, op, dst, src, off),

            Decoded::LoadImm64 { dst, value } => {
                let v =
                    match value {
                        Imm64::Value(v) => AbsValue::Scalar(Scalar::constant(v as i64)),
                        // The remaining `LD_IMM64` pseudo-forms all name something
                        // the verifier would have to look up — a map's value size,
                        // a BTF id's type, a callback's signature — and `Program`
                        // carries no registry for any of them. Maps and BTF are
                        // Phase 3; failing closed is the only honest answer until
                        // the contract grows a place to put them.
                        Imm64::MapFd(_)
                        | Imm64::MapValue { .. }
                        | Imm64::MapIdx(_)
                        | Imm64::MapIdxValue { .. } => {
                            return Err(VerifyError::NotImplemented(
                                "map pseudo-immediates need a map registry in Program",
                            ))
                        }
                        Imm64::BtfId(_) => {
                            return Err(VerifyError::NotImplemented(
                                "kernel-variable addresses need a type registry in Program",
                            ))
                        }
                        Imm64::SubprogAddr(_) => return Err(VerifyError::NotImplemented(
                            "callback subprogram addresses need a callback-typed kfunc argument",
                        )),
                    };
                self.set(st, at, dst, v)
            }

            Decoded::Call(CallTarget::Subprog(off)) => {
                self.call_subprog(st, at, insn.next_slot(), off)
            }
            Decoded::Call(CallTarget::Kfunc(id)) => self.call_kfunc(st, at, i, id),

            // Terminators; `walk_block` owns them because they need the edge.
            Decoded::Jump { .. } | Decoded::JumpCond { .. } | Decoded::MayGoto { .. } => Ok(()),
            Decoded::Exit => self.check_exit(st, at),
        }
    }

    fn alu(
        &mut self,
        st: &mut AbsState,
        at: u32,
        wide: bool,
        op: AluOp,
        dst: Reg,
        src: Source,
    ) -> Result<(), VerifyError> {
        let d = self.get(st, at, dst)?;
        let s = self.source(st, at, src, wide)?;

        let out = match (d, s) {
            (AbsValue::Scalar(a), AbsValue::Scalar(b)) => AbsValue::Scalar(a.alu(op, wide, &b)),

            (AbsValue::Ptr(p), _) if p.class == PtrClass::Arena => {
                // Unrestricted arena arithmetic: safety comes from the guard
                // regions and the exception table, not from a proof about the
                // offset. The same bargain Linux strikes at
                // `verifier.c:16186`, but with a whole unmapped 512 GiB slot
                // on each side of the window (spec §5), so an escape by the
                // ISA's 16-bit displacement is structurally impossible rather
                // than merely improbable.
                self.uses_arena = true;
                let off = match (op, s) {
                    (AluOp::Add, AbsValue::Scalar(b)) => p.off.add(&b),
                    (AluOp::Sub, AbsValue::Scalar(b)) => p.off.sub(&b),
                    _ => Scalar::UNKNOWN,
                };
                AbsValue::Ptr(PtrVal { off, ..p })
            }

            (AbsValue::Ptr(p), AbsValue::Scalar(b)) if wide => match op {
                AluOp::Add => AbsValue::Ptr(PtrVal {
                    off: p.off.add(&b),
                    ..p
                }),
                AluOp::Sub => AbsValue::Ptr(PtrVal {
                    off: p.off.sub(&b),
                    ..p
                }),
                _ => {
                    return Err(VerifyError::PointerArithmetic {
                        at,
                        reg: dst.index(),
                    })
                }
            },

            // The difference of two pointers into the same region is a scalar,
            // and is how a program measures how far it has walked.
            (AbsValue::Ptr(p), AbsValue::Ptr(q))
                if wide
                    && op == AluOp::Sub
                    && p.class == q.class
                    && p.ref_id == q.ref_id
                    && p.class != PtrClass::Null =>
            {
                AbsValue::Scalar(p.off.sub(&q.off))
            }

            _ => {
                return Err(VerifyError::PointerArithmetic {
                    at,
                    reg: dst.index(),
                })
            }
        };
        self.set(st, at, dst, out)
    }

    fn addr_space_cast(
        &mut self,
        st: &mut AbsState,
        at: u32,
        dst: Reg,
        src: Reg,
        dst_as: u16,
        src_as: u16,
    ) -> Result<(), VerifyError> {
        // Only the arena's two casts exist: address space 1 is the arena,
        // address space 0 the kernel. Anything else is an encoding LLVM does
        // not emit and NARF has no meaning for.
        if !matches!((dst_as, src_as), (0, 1) | (1, 0)) {
            return Err(VerifyError::NotImplemented(
                "address-space cast outside the arena pair",
            ));
        }
        let p = self.get_ptr(st, at, src)?;
        if p.class != PtrClass::Arena {
            return Err(VerifyError::NotAPointer {
                at,
                reg: src.index(),
            });
        }
        self.uses_arena = true;
        // The cast changes the representation, not the region; whatever the
        // truncation leaves is not something the offset domain can track.
        self.set(
            st,
            at,
            dst,
            AbsValue::Ptr(PtrVal {
                off: Scalar::UNKNOWN,
                ..p
            }),
        )
    }

    // ── Memory ──────────────────────────────────────────────────────

    /// Resolve an access, checking bounds and recording fault sites.
    ///
    /// Returns the resolved offset for regions the caller can model — the
    /// constant frame offset for a stack access — and `None` for the faulting
    /// classes, whose safety comes from the exception table instead.
    #[allow(clippy::too_many_arguments)]
    fn access(
        &mut self,
        st: &AbsState,
        at: u32,
        reg: Reg,
        off: i16,
        size: Size,
        write: bool,
        fault_dst: Option<u8>,
    ) -> Result<Option<i64>, VerifyError> {
        let p = self.get_ptr(st, at, reg)?;
        if p.nullable || p.class == PtrClass::Null {
            return Err(VerifyError::PossiblyNull {
                at,
                reg: reg.index(),
            });
        }
        if write && p.readonly {
            return Err(VerifyError::WriteToReadOnly { at });
        }

        let addr = p.off.add(&Scalar::constant(i64::from(off)));
        let bytes = size.bytes();

        if p.class.is_faulting() {
            // A faulting class still has to be proved in bounds first.
            //
            // The exception table makes an *unmapped* address survivable; it
            // does nothing for a mapped one. Treating "it faults safely" as
            // "it needs no bounds check" turned unbounded arithmetic on a
            // live kernel object into an arbitrary read/write primitive —
            // six instructions, verified clean, with a recorded fault site.
            match p.class {
                PtrClass::Object => {
                    // No BTF, so nothing says how large the object is and no
                    // offset can be proved to land inside it — not even a
                    // constant one, since the constant comes from an
                    // attacker-supplied program. Linux permits field access
                    // only because `btf_struct_access()` can check the offset
                    // names a real field.
                    //
                    // So a `Trusted<T>`/`Owned<T>` is a handle to hand back to
                    // a kfunc, not something to load through. This is
                    // deliberately stricter than Linux and lifts when a type
                    // registry lands.
                    return Err(VerifyError::OpaqueDeref {
                        at,
                        reg: reg.index(),
                    });
                }
                PtrClass::Arena => {
                    // The guard slots are sized from the ISA's 16-bit
                    // displacement (the derivation NARF keeps from
                    // `kernel/bpf/arena.c:45`), so they catch an escape by
                    // immediate. They do not catch one by register-width
                    // arithmetic, which is what this bound is for.
                    if addr.min < 0
                        || (addr.max as u64).saturating_add(bytes) > crate::ARENA_WINDOW_BYTES
                    {
                        return Err(VerifyError::ArenaOutOfWindow {
                            at,
                            reg: reg.index(),
                        });
                    }
                }
                _ => {}
            }

            // Past the bounds check, the extable covers what remains: the
            // object may have been freed, or the arena page may not be
            // populated. A fault zeroes the destination register and resumes
            // at the next instruction, which is why `fault_sites` exists — the
            // JIT must register an extable entry *before* the text is
            // published (spec §4.3).
            if p.class == PtrClass::Arena {
                self.uses_arena = true;
            }
            self.fault_sites.push(FaultSite {
                insn_index: at,
                dst_reg: fault_dst,
                arena: p.class == PtrClass::Arena,
            });
            return Ok(None);
        }

        if p.class == PtrClass::Stack {
            // // LINUX-GAP: a variable stack offset is rejected. Linux permits
            // it within proved bounds in some cases; here a non-constant frame
            // offset means the access could touch any slot, and tracking that
            // would mean joining every slot it might reach. LLVM emits
            // constant frame offsets for spills, which is the case that
            // matters; a variable one means an array on the stack, which
            // belongs in an arena.
            let Some(a) = addr.as_const() else {
                return Err(VerifyError::OutOfBounds { at });
            };
            if a >= 0 || a < -i64::from(MAX_STACK_BYTES) || a + bytes as i64 > 0 {
                return Err(VerifyError::OutOfBounds { at });
            }
            return Ok(Some(a));
        }

        let Some(region) = p.size else {
            return Err(VerifyError::OutOfBounds { at });
        };
        if addr.min < 0 || (addr.max as u64).saturating_add(bytes) > region {
            return Err(VerifyError::OutOfBounds { at });
        }
        if p.class == PtrClass::Ctx {
            // The context is a tuple, so a field is always at a constant
            // offset; a variable one would name a field the verifier cannot
            // identify and would have to type as the join of all of them.
            return addr
                .as_const()
                .map(Some)
                .ok_or(VerifyError::OutOfBounds { at });
        }
        Ok(Some(addr.min))
    }

    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        st: &mut AbsState,
        at: u32,
        size: Size,
        sign_extend: bool,
        dst: Reg,
        src: Reg,
        off: i16,
    ) -> Result<(), VerifyError> {
        let class = self.get_ptr(st, at, src)?.class;
        let resolved = self.access(st, at, src, off, size, false, Some(dst.index()))?;

        let value = match (class, resolved) {
            (PtrClass::Stack, Some(a)) => {
                if !st.stack.is_initialized(a, size.bytes()) {
                    return Err(VerifyError::UninitStack { at, off: a });
                }
                st.stack.read(a, size)
            }
            (PtrClass::Ctx, Some(a)) => self.ctx_field(at, a, size)?,
            // // LINUX-GAP: Linux types a load through a `PTR_TO_BTF_ID` using
            // in-kernel BTF, so `task->pid` comes back as a `u32` and a nested
            // pointer field comes back as another typed pointer. NARF has no
            // in-kernel BTF — CO-RE is a userspace concern (spec §1) — so a
            // field load is an unknown scalar of the access width. Sound, and
            // strictly less precise: reaching a second level of a kernel
            // structure needs a kfunc rather than a chain of loads.
            _ => AbsValue::Scalar(Scalar::unsigned_bits(size.bits())),
        };

        let value = match (value, sign_extend) {
            (AbsValue::Scalar(s), true) => AbsValue::Scalar(s.sign_extend(size.bits())),
            (v, _) => v,
        };
        self.set(st, at, dst, value)
    }

    fn store(
        &mut self,
        st: &mut AbsState,
        at: u32,
        size: Size,
        dst: Reg,
        off: i16,
        src: Source,
    ) -> Result<(), VerifyError> {
        let value = match self.source(st, at, src, true)? {
            // A store narrower than a doubleword cannot preserve a pointer, so
            // the slot records bytes rather than a value.
            AbsValue::Ptr(_) if size != Size::Dw => AbsValue::UNKNOWN_SCALAR,
            v => v,
        };
        let class = self.get_ptr(st, at, dst)?.class;
        let resolved = self.access(st, at, dst, off, size, true, None)?;
        if let (PtrClass::Stack, Some(a)) = (class, resolved) {
            st.stack.write(a, size, value);
            self.note_depth(st.stack.depth);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn atomic(
        &mut self,
        st: &mut AbsState,
        at: u32,
        size: Size,
        op: AtomicOp,
        dst: Reg,
        src: Reg,
        off: i16,
    ) -> Result<(), VerifyError> {
        // An atomic both reads and writes, and the operand is always a plain
        // scalar — the ISA has no atomic pointer update.
        let _ = self.get_scalar(st, at, src)?;
        if matches!(op, AtomicOp::Cmpxchg) {
            // The only instruction in the ISA with an implicit register
            // operand: the comparand is R0, and R0 is clobbered with the
            // pre-operation value.
            let _ = self.get_scalar(st, at, Reg::R0)?;
        }
        let class = self.get_ptr(st, at, dst)?.class;
        let resolved = self.access(st, at, dst, off, size, true, None)?;
        let width = AbsValue::Scalar(Scalar::unsigned_bits(size.bits()));
        if let (PtrClass::Stack, Some(a)) = (class, resolved) {
            st.stack.write(a, size, width);
            self.note_depth(st.stack.depth);
        }
        if op.writes_src() {
            self.set(st, at, src, width)?;
        }
        if matches!(op, AtomicOp::Cmpxchg) {
            self.set(st, at, Reg::R0, width)?;
        }
        Ok(())
    }

    /// The value of a context field.
    ///
    /// The context *is* the hook's argument list, spilled to an array by the
    /// trampoline — the mechanism `btf_ctx_access()` uses, and the reason NARF
    /// has no `convert_ctx_accesses()` pass (298 LOC), no `gen_prologue`, no
    /// narrow-load fixups, and no `struct __sk_buff` fiction (spec §1.6). One
    /// field per eight bytes, read at its natural width, and that is the whole
    /// of context access.
    fn ctx_field(&self, at: u32, a: i64, size: Size) -> Result<AbsValue, VerifyError> {
        if size != Size::Dw || a % 8 != 0 {
            return Err(VerifyError::OutOfBounds { at });
        }
        let Some(f) = self.prog.ctx_fields.get((a / 8) as usize) else {
            return Err(VerifyError::OutOfBounds { at });
        };
        Ok(value_of(f, NO_REF))
    }

    fn note_depth(&mut self, depth: u32) {
        let sp = self.current as usize;
        self.depth[sp] = self.depth[sp].max(depth);
    }

    // ── Calls ───────────────────────────────────────────────────────

    fn call_subprog(
        &mut self,
        st: &mut AbsState,
        at: u32,
        next_slot: u32,
        off: i32,
    ) -> Result<(), VerifyError> {
        let target = (i64::from(next_slot) + i64::from(off)) as u32;
        let callee = self
            .ir
            .subprogs
            .iter()
            .position(|s| s.entry_slot == target)
            .ok_or(VerifyError::BadTarget {
                at,
                target: i64::from(target),
            })? as u32;

        // The callee's entry state: arguments in R1..R5, a fresh frame, no
        // inherited references. R6..R9 are callee-saved and start
        // uninitialised, so a callee that reads one before writing it is
        // rejected — which is what Linux does too, and what every compiler
        // already assumes.
        let mut entry = AbsState {
            regs: [AbsValue::NotInit; 11],
            stack: Stack::default(),
            refs: Vec::new(),
        };
        entry.regs[10] = AbsValue::Ptr(PtrVal::frame_pointer());
        let mut passed_frame_pointer = false;
        for k in 1..=5u8 {
            entry.regs[k as usize] = match st.regs[k as usize] {
                // A pointer into the caller's frame becomes a bounded byte
                // region in the callee. That decouples the two frames without
                // Linux's `frame[MAX_CALL_FRAMES]` array, at the cost of the
                // callee losing per-byte initialisation tracking for it.
                // // LINUX-GAP: the callee may therefore read caller stack
                // bytes nothing wrote.
                //
                // Those bytes are never another program's: **the runtime is
                // required to zero a frame before handing it out**, and every
                // provider in `bpf/src/mem.rs` does (pinned by
                // `smoke_bpf_fresh_frame_is_zeroed`). Without that this would
                // be a cross-program information leak, because the per-CPU
                // region is reused and would otherwise still hold the previous
                // program's spills.
                //
                // Stated here explicitly because it is a *cross-crate*
                // obligation: a plausible optimisation in `mem.rs` — skipping
                // the memset of a large frame on a hot probe path — would
                // silently turn this precision loss into a disclosure, with
                // nothing in that crate saying why the fill is load-bearing.
                // The region is clamped to the frame and *counted* in the stack
                // budget. Both were missing, and together they were the whole
                // primitive back: `room` was `-off` with no upper bound, and
                // this path never called `note_depth`, so
                //
                //     r1 = r10; r1 -= 1000000; call sub
                //     sub: *(u64*)(r1+0) = r2
                //
                // verified with `max_stack_bytes = 0` — a writable megabyte
                // region based a megabyte *below* a frame the runtime was told
                // needed nothing. The `// LINUX-GAP` above was fail-open under
                // it: "the runtime zeroes the frame" bounds what a callee can
                // read from *inside* the frame, and says nothing about a
                // writable region extending arbitrarily below it.
                AbsValue::Ptr(p) if p.class == PtrClass::Stack => {
                    passed_frame_pointer = true;
                    // A frame pointer offset is negative and measured down from
                    // R10; anything at or above R10, or beyond the frame
                    // ceiling, is not a frame slot at all.
                    let Some(off) = p.off.as_const() else {
                        return Err(VerifyError::OutOfBounds { at });
                    };
                    let room = (-off).max(0) as u64;
                    if room > u64::from(MAX_STACK_BYTES) {
                        return Err(VerifyError::OutOfBounds { at });
                    }
                    // The callee can address the whole region, so the frame has
                    // to be at least that deep for the runtime's layout to match
                    // what was proved here.
                    // `room <= MAX_STACK_BYTES` was just checked, so the
                    // narrowing cannot truncate.
                    self.note_depth(room as u32);
                    AbsValue::Ptr(PtrVal::region(PtrClass::Mem, room))
                }
                v => v,
            };
        }

        self.entry[callee as usize] = Some(match self.entry[callee as usize].take() {
            None => entry,
            Some(prev) => prev.join(&entry),
        });

        if passed_frame_pointer {
            st.stack.clobber();
        }
        // // LINUX-GAP: a callee's return value is not propagated back — `R0`
        // is an unknown scalar after a BPF-to-BPF call, so a subprogram cannot
        // return a pointer or an acquired reference. Linux analyses the callee
        // in the caller's context and gets both. Matching that means either
        // inlining subprograms into the fixpoint or iterating call-site
        // summaries to a second fixpoint, and neither is worth building before
        // there is a program that needs it.
        st.regs[Reg::R0.as_usize()] = AbsValue::UNKNOWN_SCALAR;
        for k in 1..=5u8 {
            st.regs[k as usize] = AbsValue::NotInit;
        }
        Ok(())
    }

    fn call_kfunc(
        &mut self,
        st: &mut AbsState,
        at: u32,
        i: u32,
        id: i32,
    ) -> Result<(), VerifyError> {
        // `imm` carries the kfunc's *id*, and resolution is a search on that
        // id — deliberately not an index into `prog.kfuncs`. Indexing would
        // couple every compiled program to the order in which the loader
        // enumerates the registry, so registering one more kfunc would
        // silently re-target existing programs' calls.
        //
        // Linux puts a BTF id here and looks it up against a global registry
        // plus a hardcoded `special_kfunc_list[]` of ~60 ids the verifier
        // knows by name (`verifier.c:13911`); here the verifier's entire
        // model of a kfunc is its descriptor, so there is nothing to
        // special-case. Linear scan: the registry is a closed, audited set of
        // tens of entries, and this runs once per call site at load time.
        let desc = *self
            .prog
            .kfuncs
            .iter()
            .find(|d| d.id == id)
            .ok_or(VerifyError::UnknownKfunc { at, id })?;

        if !self.prog.context.permits(desc.context) {
            return Err(VerifyError::ContextMismatch {
                at,
                required: desc.context,
                actual: self.prog.context,
            });
        }

        self.check_args(st, at, &desc)?;

        // A kfunc that may sleep is an await point. Everything whose validity
        // domain does not survive it dies here — spec §4.4, the single rule
        // that delivers sleep safety, lock discipline, and reference validity
        // at once.
        //
        // The runtime is currently narrower than this: the uniform kfunc shim
        // returns a `u64`, so a kfunc cannot suspend through it and
        // `narf_yield()` is an interpreter intrinsic. Treating *every*
        // `Context::Sleepable` kfunc as an await point is therefore a strict
        // over-approximation of what can actually suspend today — it rejects
        // more, never less — and it means the rule needs no revisiting when
        // the shim grows a suspending form.
        if desc.context == Context::Sleepable {
            for (reg, domain) in st.kill_at_await() {
                // Liveness turns a silent kill into a diagnostic: report only
                // the registers something downstream was still going to read,
                // naming the register and its domain rather than failing with
                // "uninitialised register" several instructions later.
                if self.live.after_has(i, reg) {
                    return Err(VerifyError::PointerCrossesAwait { at, reg, domain });
                }
            }
        }

        for k in 1..=5u8 {
            st.regs[k as usize] = AbsValue::NotInit;
        }
        // Acquisition is the mirror of release: whatever a type consumes in
        // argument position, it acquires in return position. One predicate,
        // read both ways round, so an acquire whose release was forgotten is
        // not expressible.
        let is_lock = matches!(
            desc.ret.kind,
            TypeKind::Ptr {
                kind: PtrKind::LockGuard,
                ..
            }
        );
        let ret_ref = if desc.ret.consumes_in_arg_position() {
            if is_lock && st.live_locks() >= 1 {
                return Err(VerifyError::TooManyLocks { at });
            }
            // Keyed by acquisition site, not by a counter: re-acquiring in a
            // loop yields the same id, which is what keeps the reference set
            // bounded and the fixpoint convergent.
            st.acquire(Ref {
                id: i,
                is_lock,
                domain: desc.ret.domain,
            });
            i
        } else {
            NO_REF
        };
        st.regs[Reg::R0.as_usize()] = value_of(&desc.ret, ret_ref);
        Ok(())
    }

    fn check_args(
        &mut self,
        st: &mut AbsState,
        at: u32,
        desc: &KfuncDesc,
    ) -> Result<(), VerifyError> {
        for k in 0..desc.args.len() {
            let arg = desc.args[k];
            let r = Reg::new(k as u8 + 1).expect("validate() capped args at five");
            let v = self.get(st, at, r)?;
            let bad = VerifyError::KfuncSignature {
                at,
                arg: k,
                expected: arg,
            };

            match (arg.kind, v) {
                (TypeKind::Scalar { .. }, AbsValue::Scalar(s)) => {
                    // `Const<N>`: the verifier must have proved a single
                    // value, not merely a range. Linux spells this as a `__k`
                    // suffix on a BTF parameter name.
                    if arg.flags.contains(ArgFlags::CONST) && s.as_const().is_none() {
                        return Err(bad);
                    }
                }
                (TypeKind::Ptr { kind, key }, AbsValue::Ptr(p)) => {
                    if p.nullable && !arg.flags.contains(ArgFlags::NULLABLE) {
                        return Err(VerifyError::PossiblyNull { at, reg: r.index() });
                    }
                    // A pointer may be *stronger* than asked for — an
                    // `Owned<T>` satisfies a `Trusted<T>` parameter — but
                    // never weaker. The verifier never widens a domain.
                    if weaker_domain(p.domain, arg.domain) != arg.domain {
                        return Err(bad);
                    }
                    let want = match kind {
                        PtrKind::Object => PtrClass::Object,
                        PtrKind::Mem => PtrClass::Mem,
                        PtrKind::Arena => PtrClass::Arena,
                        PtrKind::Ctx => PtrClass::Ctx,
                        PtrKind::MapValue => PtrClass::MapValue,
                        PtrKind::LockGuard => PtrClass::LockGuard,
                    };
                    if kind == PtrKind::Mem {
                        // A byte region may be anything with a length: a stack
                        // slice, a map value, an arena range.
                        self.check_mem_arg(st, at, k, desc, &p)?;
                    } else if p.class != want || (kind == PtrKind::Object && p.key != key) {
                        return Err(bad);
                    } else if p.off.as_const() != Some(0) {
                        // The offset must be exactly zero for every non-`Mem`
                        // pointer argument. Linux requires the same
                        // (`reg->off == 0` for these argument types) and it is
                        // load-bearing here for a blunt reason: the kfunc shim
                        // turns the register straight into a Rust reference.
                        // `Trusted<T>::from_raw` and `Owned<T>::from_raw` do
                        // `NonNull::new_unchecked(raw as *mut T)` on the
                        // strength of "the verifier proves this".
                        //
                        // Nothing proved it. `alu`'s `(Ptr, Scalar)` arm permits
                        // unbounded add/sub on every pointer class, and this arm
                        // checked nullability, the validity domain, the class and
                        // the `TypeKey` — and never the offset. So
                        //
                        //     r6 = ctx[0]        // Trusted<Task>
                        //     r1 = r6
                        //     r1 += ctx[2]       // attacker-chosen u64
                        //     use_trusted(r1)
                        //
                        // verified, handing a kfunc a `NonNull<Task>` at an
                        // arbitrary address. The same shape freed an `Owned<T>`
                        // at a shifted address, walked off a map value or a ctx
                        // tuple, and unlocked with a bogus lock token.
                        //
                        // Latent only because today's registered kfuncs take
                        // scalars — but this is the *contract*, so the first
                        // `kfunc!` declaring a `Trusted<T>` parameter would have
                        // inherited an arbitrary kernel write on day one.
                        //
                        // `Mem` is exempt because `check_mem_arg` bounds offset
                        // and length together against the region it resolves.
                        return Err(bad);
                    }
                    if p.class == PtrClass::Arena {
                        self.uses_arena = true;
                    }
                    // Positional, not a flag: an `Owned<T>` in argument
                    // position releases what the same type in return position
                    // acquired, which is why there is no way to declare an
                    // acquire whose release was forgotten.
                    if arg.consumes_in_arg_position() {
                        if p.ref_id == NO_REF || !st.release(p.ref_id) {
                            return Err(VerifyError::ReleaseOfUnacquired { at, reg: r.index() });
                        }
                        st.kill_ref(p.ref_id);
                    }
                }
                // A null pointer is acceptable only where the signature says
                // so; everything else is a type error at the call site.
                (TypeKind::Ptr { .. }, AbsValue::Scalar(s))
                    if arg.flags.contains(ArgFlags::NULLABLE) && s.as_const() == Some(0) => {}
                _ => return Err(bad),
            }
        }
        Ok(())
    }

    /// Check a `&[u8]`-shaped argument: a pointer plus the following
    /// argument's length.
    fn check_mem_arg(
        &mut self,
        st: &mut AbsState,
        at: u32,
        k: usize,
        desc: &KfuncDesc,
        p: &PtrVal,
    ) -> Result<(), VerifyError> {
        let arg = desc.args[k];
        let bad = VerifyError::KfuncSignature {
            at,
            arg: k,
            expected: arg,
        };
        if !arg.flags.contains(ArgFlags::SIZED_BY_NEXT) {
            // An unsized byte pointer carries no length, so there is nothing
            // to check the region against. `validate()` permits the shape
            // because a descriptor is not wrong for having it; the verifier
            // simply cannot prove anything about the access.
            return Err(bad);
        }
        let Some(len_reg) = Reg::new(k as u8 + 2) else {
            return Err(bad);
        };
        let AbsValue::Scalar(len) = self.get(st, at, len_reg)? else {
            return Err(bad);
        };
        let (_, len_max) = len.unsigned_bounds();
        let writes = arg.flags.contains(ArgFlags::UNINIT);

        match p.class {
            PtrClass::Stack => {
                let Some(off) = p.off.as_const() else {
                    return Err(VerifyError::OutOfBounds { at });
                };
                // `len_max` is a u64 that may be `u64::MAX` when nothing has
                // bounded the length; widening the sum to i128 is what stops
                // it wrapping into a *negative* offset and passing the check.
                if off >= 0
                    || off < -i64::from(MAX_STACK_BYTES)
                    || i128::from(off) + i128::from(len_max) > 0
                {
                    return Err(VerifyError::OutOfBounds { at });
                }
                if writes {
                    // `&mut MaybeUninit<T>`: the callee promises to fill it,
                    // so the caller need not have, and afterwards it is
                    // defined. Linux spells this as a `__uninit` suffix.
                    st.stack.write_unspecified(off, len_max);
                    self.note_depth(st.stack.depth);
                } else if !st.stack.is_initialized(off, len_max) {
                    return Err(VerifyError::UninitStack { at, off });
                }
            }
            PtrClass::Mem | PtrClass::MapValue | PtrClass::Ctx => {
                let Some(size) = p.size else {
                    return Err(VerifyError::OutOfBounds { at });
                };
                if p.off.min < 0 || (p.off.max as u64).saturating_add(len_max) > size {
                    return Err(VerifyError::OutOfBounds { at });
                }
                if writes && p.readonly {
                    return Err(VerifyError::WriteToReadOnly { at });
                }
            }
            PtrClass::Arena => {
                // An arena byte region is still a bounded region. The guard
                // slots are sized from the ISA's 16-bit displacement, so they
                // say nothing about a u64 length — without this a kfunc taking
                // `&[u8]` could be handed an attacker-chosen offset *and* an
                // attacker-chosen length, and `<&[u8]>::from_raw` would call
                // `slice::from_raw_parts` on it.
                if p.off.min < 0
                    || (p.off.max as u64).saturating_add(len_max) > crate::ARENA_WINDOW_BYTES
                {
                    return Err(VerifyError::OutOfBounds { at });
                }
                if writes && p.readonly {
                    return Err(VerifyError::WriteToReadOnly { at });
                }
                self.uses_arena = true;
            }
            _ => return Err(bad),
        }
        Ok(())
    }

    fn check_exit(&self, st: &AbsState, at: u32) -> Result<(), VerifyError> {
        if let Some(r) = st.refs.first() {
            // Name a register still holding it if there is one; otherwise the
            // reference was dropped on the floor and only its acquisition site
            // identifies it.
            let reg = st
                .regs
                .iter()
                .position(|v| matches!(v, AbsValue::Ptr(p) if p.ref_id == r.id))
                .map_or(0, |i| i as u8);
            return Err(VerifyError::LeakedReference { at, reg });
        }
        // `exit` returns R0 to the kernel. An uninitialised R0 hands back
        // whatever the last program to use this stack left there, and a
        // pointer hands back a kernel address; both are rejected.
        match st.regs[Reg::R0.as_usize()] {
            AbsValue::NotInit => Err(VerifyError::UninitRegister { at, reg: 0 }),
            AbsValue::Ptr(_) => Err(VerifyError::PointerArithmetic { at, reg: 0 }),
            AbsValue::Scalar(_) => Ok(()),
        }
    }

    // ── Branch refinement ───────────────────────────────────────────

    /// The state on one edge out of a conditional branch, or `None` when the
    /// edge is infeasible.
    #[allow(clippy::too_many_arguments)]
    fn refine(
        &self,
        st: &AbsState,
        at: u32,
        wide: bool,
        pred: Pred,
        dst: Reg,
        src: Source,
    ) -> Result<Option<AbsState>, VerifyError> {
        let d = self.get(st, at, dst)?;
        let s = self.source(st, at, src, wide)?;

        // Null tests. This is the only pointer refinement there is, and it is
        // what makes `Option<T>` a verifier-enforced obligation rather than a
        // convention: a nullable result is unusable until a comparison against
        // zero has cleared the flag on one edge.
        if let (AbsValue::Ptr(p), AbsValue::Scalar(z)) = (d, s) {
            // `wide` is load-bearing: `(u32)ptr == 0` does not imply
            // `ptr == 0`. Refining on a 32-bit compare let a one-bit opcode
            // change — JEQ32 for JEQ64 — convince the verifier an acquired
            // reference had been released, and at run time any object whose
            // low 32 bits are zero would then leak its refcount. With a
            // lock guard in place of an object it is worse: the verifier
            // believes the lock was dropped, so `kill_at_await` finds nothing
            // to kill and the program may sleep holding it.
            //
            // A narrow compare against zero simply says nothing about a
            // pointer, so both edges keep the unrefined state.
            if wide && z.as_const() == Some(0) && matches!(pred, Pred::Eq | Pred::Ne) {
                let mut out = st.clone();
                if pred == Pred::Eq {
                    if !p.nullable {
                        return Ok(None); // a non-null pointer is never zero
                    }
                    // On the null edge the value is just zero — and if it
                    // carried an acquired reference, the acquisition failed,
                    // so there is nothing left to release.
                    out.regs[dst.as_usize()] = AbsValue::Scalar(Scalar::constant(0));
                    if p.ref_id != NO_REF {
                        out.release(p.ref_id);
                    }
                } else {
                    out.regs[dst.as_usize()] = AbsValue::Ptr(PtrVal {
                        nullable: false,
                        ..p
                    });
                }
                return Ok(Some(out));
            }
            return Ok(Some(st.clone()));
        }

        let (AbsValue::Scalar(a), AbsValue::Scalar(b)) = (d, s) else {
            // A pointer-to-pointer comparison says nothing about either side.
            return Ok(Some(st.clone()));
        };

        // A 32-bit comparison constrains only the low half. Reflecting that
        // into a 64-bit abstract value is exact only when the high bits are
        // already known — which they are after any 32-bit load or 32-bit ALU
        // result, which is where these comparisons come from.
        // // LINUX-GAP: Linux keeps dedicated `s32`/`u32` range pairs and can
        // refine even when the high half is unknown. NARF derives its 32-bit
        // view on demand and declines to refine in that case. Sound; strictly
        // less precise for a `JMP32` against a value whose upper 32 bits
        // nothing has established.
        let refinable = |v: &Scalar| {
            wide || (v.min >= 0
                && v.max
                    <= if pred.is_unsigned() {
                        0xffff_ffff
                    } else {
                        0x7fff_ffff
                    })
        };
        if !refinable(&a) || !refinable(&b) {
            return Ok(Some(st.clone()));
        }

        let (au, bu) = (a.unsigned_bounds(), b.unsigned_bounds());
        let (na, nb) = match pred {
            Pred::Eq => (a.refine_eq(&b), b.refine_eq(&a)),
            Pred::Ne => (a.refine_ne(&b), b.refine_ne(&a)),
            Pred::Gt => (
                a.refine_unsigned_min(bu.0.saturating_add(1)),
                b.refine_unsigned_max(au.1.saturating_sub(1)),
            ),
            Pred::Ge => (a.refine_unsigned_min(bu.0), b.refine_unsigned_max(au.1)),
            Pred::Lt => (
                a.refine_unsigned_max(bu.1.saturating_sub(1)),
                b.refine_unsigned_min(au.0.saturating_add(1)),
            ),
            Pred::Le => (a.refine_unsigned_max(bu.1), b.refine_unsigned_min(au.0)),
            Pred::Sgt => (
                a.refine_signed_min(b.min.saturating_add(1)),
                b.refine_signed_max(a.max.saturating_sub(1)),
            ),
            Pred::Sge => (a.refine_signed_min(b.min), b.refine_signed_max(a.max)),
            Pred::Slt => (
                a.refine_signed_max(b.max.saturating_sub(1)),
                b.refine_signed_min(a.min.saturating_add(1)),
            ),
            Pred::Sle => (a.refine_signed_max(b.max), b.refine_signed_min(a.min)),
            Pred::Set => (a.refine_bits_set(&b), Some(b)),
            // "No bits in common" is the side of `JSET` that actually deduces
            // something, and it is not an opcode — hence [`Pred`].
            Pred::NotSet => (a.refine_bits_clear(&b), Some(b)),
        };

        let (Some(na), Some(nb)) = (na, nb) else {
            return Ok(None);
        };
        let mut out = st.clone();
        out.regs[dst.as_usize()] = AbsValue::Scalar(na);
        if let Source::Reg(sr) = src {
            if !sr.is_frame_ptr() && sr != dst {
                out.regs[sr.as_usize()] = AbsValue::Scalar(nb);
            }
        }
        Ok(Some(out))
    }
}

/// The abstract value an [`ArgDesc`] describes.
fn value_of(d: &ArgDesc, ref_id: u32) -> AbsValue {
    match d.kind {
        TypeKind::Void => AbsValue::NotInit,
        TypeKind::Scalar { bits, signed } => AbsValue::Scalar(if signed {
            Scalar::signed_bits(u32::from(bits))
        } else {
            Scalar::unsigned_bits(u32::from(bits))
        }),
        TypeKind::Ptr { kind, key } => {
            let class = match kind {
                PtrKind::Object => PtrClass::Object,
                PtrKind::Mem => PtrClass::Mem,
                PtrKind::Arena => PtrClass::Arena,
                PtrKind::Ctx => PtrClass::Ctx,
                PtrKind::MapValue => PtrClass::MapValue,
                PtrKind::LockGuard => PtrClass::LockGuard,
            };
            AbsValue::Ptr(PtrVal {
                class,
                key,
                domain: d.domain,
                off: Scalar::constant(0),
                // A returned region carries no length, so a direct load
                // through it cannot be proved in bounds — deliberately.
                // Opaque objects and arena pointers need no length; a sized
                // region would need the descriptor to carry its size, which
                // the contract does not express in return position.
                size: match class {
                    PtrClass::LockGuard => Some(0),
                    _ => None,
                },
                nullable: d.flags.contains(ArgFlags::NULLABLE),
                ref_id,
                readonly: d.flags.contains(ArgFlags::READONLY),
            })
        }
    }
}

#[cfg(test)]
mod pred_tests {
    use super::*;

    /// Evaluate a predicate concretely, so the negation table can be checked
    /// against something other than itself.
    fn holds(p: Pred, a: u64, b: u64) -> bool {
        match p {
            Pred::Eq => a == b,
            Pred::Ne => a != b,
            Pred::Gt => a > b,
            Pred::Ge => a >= b,
            Pred::Lt => a < b,
            Pred::Le => a <= b,
            Pred::Sgt => (a as i64) > (b as i64),
            Pred::Sge => (a as i64) >= (b as i64),
            Pred::Slt => (a as i64) < (b as i64),
            Pred::Sle => (a as i64) <= (b as i64),
            Pred::Set => (a & b) != 0,
            Pred::NotSet => (a & b) == 0,
        }
    }

    const ALL: &[Pred] = &[
        Pred::Eq,
        Pred::Ne,
        Pred::Gt,
        Pred::Ge,
        Pred::Lt,
        Pred::Le,
        Pred::Sgt,
        Pred::Sge,
        Pred::Slt,
        Pred::Sle,
        Pred::Set,
        Pred::NotSet,
    ];

    #[test]
    fn negation_is_exact_for_every_predicate() {
        // The fallthrough edge is refined by the *negated* predicate. If the
        // table were wrong in either direction the verifier would apply a
        // constraint that does not hold on that edge — which is the shape of
        // bug that proves a false bound rather than merely rejecting a
        // program. Checked against a concrete evaluator, not against itself.
        let values: &[u64] = &[
            0,
            1,
            2,
            7,
            0xff,
            0x8000_0000,
            0xffff_ffff,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            u64::MAX,
        ];
        for &p in ALL {
            assert_eq!(p.negate().negate(), p, "{p:?} is not an involution");
            for &a in values {
                for &b in values {
                    assert_ne!(
                        holds(p, a, b),
                        holds(p.negate(), a, b),
                        "{p:?} and its negation agree on ({a:#x}, {b:#x})"
                    );
                }
            }
        }
    }

    #[test]
    fn every_isa_predicate_maps_into_pred() {
        // `CondOp::Set` is the only one whose negation is not itself an
        // opcode; everything else must round-trip through `Pred` unchanged.
        for op in [
            CondOp::Eq,
            CondOp::Ne,
            CondOp::Gt,
            CondOp::Ge,
            CondOp::Lt,
            CondOp::Le,
            CondOp::Sgt,
            CondOp::Sge,
            CondOp::Slt,
            CondOp::Sle,
            CondOp::Set,
        ] {
            let p = Pred::of(op);
            assert!(ALL.contains(&p), "{op:?} mapped outside the predicate set");
        }
        assert_eq!(Pred::of(CondOp::Set).negate(), Pred::NotSet);
    }

    #[test]
    fn signedness_classification_matches_the_predicates() {
        // The 32-bit refinement gate depends on this: an unsigned comparison
        // may be reflected from a value in `[0, u32::MAX]`, a signed one only
        // from `[0, i32::MAX]`. Getting the classification wrong would let a
        // signed `JMP32` refine a value whose sign the 64-bit view disagrees
        // about.
        for &p in ALL {
            assert_eq!(
                p.is_unsigned(),
                !matches!(p, Pred::Sgt | Pred::Sge | Pred::Slt | Pred::Sle),
                "{p:?}"
            );
            assert_eq!(p.is_unsigned(), p.negate().is_unsigned());
        }
    }
}
