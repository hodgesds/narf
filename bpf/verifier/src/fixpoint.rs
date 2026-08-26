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
//! Widening is applied wherever [`crate::ir::Block::widen_here`] is set, and
//! [`crate::ir`] guarantees that **every cycle contains at least one such
//! block** — back-edge targets, entries into a non-trivial SCC, and heads for
//! cycles nested inside another cycle.
//!
//! That third case is why the guarantee is stated here rather than assumed. The
//! text above used to claim convergence "on any CFG, for any program" while the
//! CFG pass only handled *maximal* SCCs, so a loop nested inside another had no
//! widening point at all: joins alone climbed forever and only
//! `fixpoint_round_budget` stopped it, at 16 385 rounds for a 15-instruction
//! program and ~13 s extrapolated to `MAX_INSNS` — un-preemptible, inside
//! `sys_bpf`. The claim is now backed by a structural invariant with a test
//! (`every_cycle_has_a_widening_point`) rather than by inspection.
//!
//! Widening therefore does two jobs: it makes convergence *fast* where a cycle
//! would otherwise converge slowly, and it makes convergence *happen* where the
//! lattice has no finite ascending chain of its own.
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
use crate::kfunc::{
    ArgDesc, ArgFlags, Context, KfuncDesc, PtrKind, TypeKey, TypeKind, ValidityDomain,
    MAP_HANDLE_TYPE_KEY,
};
use crate::liveness::{self, Masks};
use crate::state::{weaker_domain, AbsState, AbsValue, PtrClass, PtrVal, Ref, Stack, NO_REF};
use crate::{
    BareAccessSite, FaultSite, KfuncCallSite, MapDesc, Program, SubprogInfo, TypedLoadSite,
    VerifiedProgram, VerifyError, MAX_STACK_BYTES,
};

/// Everything the fixpoint accumulates that outlives a single block.
struct Analysis<'a, 'p> {
    ir: &'a Ir,
    prog: &'a Program<'p>,
    live: Masks,
    prec: Masks,
    fault_sites: Vec<FaultSite>,
    /// Raw dereferences whose pointer class is Stack or Ctx. Appended per
    /// fixpoint visit and deduplicated when verification converges.
    bare_access_sites: Vec<BareAccessSite>,
    /// Direct trace-object field loads proved to name an exact schema field.
    /// Accumulated and deduplicated the same way as [`Self::bare_access_sites`];
    /// every duplicate of a given index is byte-identical because the field is a
    /// pure function of the instruction and the schema.
    typed_load_sites: Vec<TypedLoadSite>,
    /// Every kfunc `call` the fixpoint resolved. Appended per visit, so the
    /// same site lands here once per worklist round; deduped at the end, as
    /// `fault_sites` is.
    kfunc_calls: Vec<KfuncCallSite>,
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
        bare_access_sites: Vec::new(),
        typed_load_sites: Vec::new(),
        kfunc_calls: Vec::new(),
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

    // Same shape as `fault_sites`: a block can be re-analysed several times
    // before the fixpoint settles, so a call site is recorded once per visit
    // and collapsed here. `sort_unstable` is fine — every duplicate of a given
    // index is byte-identical, because resolution is a pure function of the
    // instruction's immediate and `Program::kfuncs`.
    let mut kfunc_calls = a.kfunc_calls;
    kfunc_calls.sort_unstable_by_key(|c| c.insn_index);
    kfunc_calls.dedup_by_key(|c| c.insn_index);

    let mut bare_access_sites = a.bare_access_sites;
    bare_access_sites.sort_unstable_by_key(|site| site.insn_index);
    bare_access_sites.dedup_by_key(|site| site.insn_index);

    let mut typed_load_sites = a.typed_load_sites;
    typed_load_sites.sort_unstable_by_key(|site| site.insn_index);
    typed_load_sites.dedup_by_key(|site| site.insn_index);

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
        bare_access_sites,
        typed_load_sites,
        subprogs,
        uses_arena: a.uses_arena,
        kfunc_calls,
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

/// What [`Analysis::access`] proved about *where* an in-bounds access lands.
///
/// Only the frame and the context have a per-offset model, so only they have
/// anything to say here; every other class is bounds-checked and then opaque.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Resolved {
    /// One known frame or context offset.
    Const(i64),
    /// A frame access whose exact offset is unknown, but whose every possible
    /// byte lies in `[lo, hi)` — and that range lies inside the frame.
    StackRange { lo: i64, hi: i64 },
    /// In bounds, with no offset the caller can act on: a faulting class whose
    /// safety comes from the exception table, or a sized region with no
    /// per-byte state to update.
    Opaque,
    /// A direct load proved to name an exact declared field of a trace-object
    /// pointer. The runtime reads it through the tracing wrapper rather than as
    /// a bare dereference; the value is an unknown scalar of the access width,
    /// exactly as a mediated read or a Linux `PTR_TO_BTF_ID` field load is.
    TypedField,
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

    fn swap_operands(self) -> Pred {
        match self {
            Pred::Eq => Pred::Eq,
            Pred::Ne => Pred::Ne,
            Pred::Gt => Pred::Lt,
            Pred::Ge => Pred::Le,
            Pred::Lt => Pred::Gt,
            Pred::Le => Pred::Ge,
            Pred::Sgt => Pred::Slt,
            Pred::Sge => Pred::Sle,
            Pred::Slt => Pred::Sgt,
            Pred::Sle => Pred::Sge,
            Pred::Set => Pred::Set,
            Pred::NotSet => Pred::NotSet,
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
        // Membership is separate from the LIFO worklist so enqueue remains
        // O(1) even for a wide CFG. Keep the vector (rather than changing to a
        // queue or set) because pop order affects convergence work, while a
        // block-indexed bit preserves the existing order exactly.
        let mut queued = vec![false; self.ir.blocks.len()];
        queued[entry_block as usize] = true;

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
            queued[b as usize] = false;
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
                    if !queued[succ as usize] {
                        worklist.push(succ);
                        queued[succ as usize] = true;
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

    // ── `LD_IMM64` map pseudo-forms ─────────────────────────────────

    /// The descriptor for the map with this file descriptor.
    ///
    /// Linear search: the map set is a handful of entries per program (Linux's
    /// `MAX_USED_MAPS` is 64) and a linear scan over a `&[MapDesc]` beats
    /// building a lookup structure the fixpoint would have to carry. The same
    /// reasoning `Registry::by_id` uses for kfuncs.
    fn map_by_fd(&self, at: u32, fd: i32) -> Result<MapDesc, VerifyError> {
        self.prog
            .maps
            .iter()
            .copied()
            .find(|m| m.fd == fd)
            .ok_or(VerifyError::UnknownMap { at, fd })
    }

    /// The descriptor at this position in the loader's fd array.
    ///
    /// `BPF_PSEUDO_MAP_IDX` indexes the array rather than naming an fd, which
    /// is how a `libbpf`-shaped loader avoids patching instructions after it
    /// has created the maps. A negative or past-the-end index is the same
    /// failure as an unknown fd and reports as one, carrying the index in the
    /// `fd` field because that is the number the instruction actually held.
    fn map_by_idx(&self, at: u32, idx: i32) -> Result<MapDesc, VerifyError> {
        self.prog
            .maps
            .iter()
            .find(|map| map.fd_array_idx == Some(idx))
            .copied()
            .ok_or(VerifyError::UnknownMap { at, fd: idx })
    }

    /// A map *handle*: Linux's `CONST_PTR_TO_MAP`.
    ///
    /// Opaque and read-only. `Static` because a program holds a reference to
    /// every map it names for its whole life, so the handle survives an await —
    /// which is what lets a sleepable program touch a map at all.
    ///
    /// `readonly` is belt to `access()`'s brace: an `Object` deref is rejected
    /// outright, so the flag can never be the thing that stops a store. It is
    /// set because a handle is not a place, and a future class that *is*
    /// dereferenceable should not inherit "writable" from this constructor.
    fn map_handle(&self, _at: u32, _m: MapDesc) -> AbsValue {
        AbsValue::Ptr(PtrVal {
            class: PtrClass::Object,
            key: MAP_HANDLE_TYPE_KEY,
            domain: ValidityDomain::Static,
            off: Scalar::constant(0),
            size: None,
            nullable: false,
            ref_id: NO_REF,
            readonly: true,
        })
    }

    /// A pointer `value_offset` bytes into the map's first value.
    ///
    /// `BPF_PSEUDO_MAP_VALUE` is what LLVM emits for a global variable, whose
    /// storage is a one-entry `.data`/`.bss` map. The offset is folded into the
    /// pointer and the region is the whole value, so `access()` and
    /// `check_mem_arg` bound `off + len <= value_size` with no map-specific
    /// code — the size is the only thing they were missing.
    fn map_value_ptr(
        &self,
        at: u32,
        m: MapDesc,
        value_offset: i32,
    ) -> Result<AbsValue, VerifyError> {
        // A negative offset, or one at or past the end, has no in-bounds access
        // through it at all. Rejecting here rather than letting every later
        // access fail names the instruction that is actually wrong. Linux
        // rejects the same thing in `resolve_pseudo_ldimm64`
        // (`off >= map->value_size` ⇒ `-EINVAL`).
        if value_offset < 0 || value_offset.unsigned_abs() >= m.value_size {
            return Err(VerifyError::MapValueOffset {
                at,
                off: value_offset,
                size: m.value_size,
            });
        }
        Ok(AbsValue::Ptr(PtrVal {
            class: PtrClass::MapValue,
            key: TypeKey::NONE,
            domain: ValidityDomain::Static,
            off: Scalar::constant(i64::from(value_offset)),
            size: Some(u64::from(m.value_size)),
            nullable: false,
            ref_id: NO_REF,
            readonly: false,
        }))
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
                        // The four map pseudo-forms split two ways, exactly as
                        // Linux's `resolve_pseudo_ldimm64` splits them.
                        //
                        // `MapFd`/`MapIdx` produce a *handle*: Linux's
                        // `CONST_PTR_TO_MAP`, here an opaque `PtrClass::Object`
                        // keyed `MAP_HANDLE_TYPE_KEY`. `access()` already
                        // rejects dereferencing an `Object`, which is the
                        // correct behaviour for a handle and needed no new
                        // class to say so — the only thing a program may do
                        // with one is hand it to a map kfunc.
                        //
                        // `MapValue`/`MapIdxValue` produce a *pointer into the
                        // map's first value* at a fixed offset. That is what
                        // LLVM emits for a global variable in a `.data`/`.bss`
                        // map, and it is where the value width earns its keep:
                        // `PtrClass::MapValue` with `size = value_size` is what
                        // `access()` and `check_mem_arg` bound against.
                        Imm64::MapFd(fd) => self.map_handle(at, self.map_by_fd(at, fd)?),
                        Imm64::MapIdx(idx) => self.map_handle(at, self.map_by_idx(at, idx)?),
                        Imm64::MapValue { fd, value_offset } => {
                            self.map_value_ptr(at, self.map_by_fd(at, fd)?, value_offset)?
                        }
                        Imm64::MapIdxValue { idx, value_offset } => {
                            self.map_value_ptr(at, self.map_by_idx(at, idx)?, value_offset)?
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

            (AbsValue::Ptr(p), AbsValue::Scalar(b)) if wide && p.class != PtrClass::MemEnd => {
                match op {
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
                }
            }

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
        //
        // That makes it *malformed*, not unimplemented, and the distinction is
        // load-bearing rather than cosmetic. `NotImplemented` is the one error
        // `narf-bpf`'s loader answers by falling through to `crate::provisional`
        // — a structural check that proves nothing about values — so labelling a
        // meaningless operand pair "not implemented yet" put a malformed
        // instruction on the one path that exists for programs the verifier
        // merely cannot reason about. `provisional` happens to reject every
        // `AddrSpaceCast` today, so nothing got through; the fix is to not
        // depend on that, because it is a property of a different module.
        if !matches!((dst_as, src_as), (0, 1) | (1, 0)) {
            return Err(VerifyError::BadAddrSpaceCast { at, dst_as, src_as });
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
    /// Returns what the caller can *model* about where the access lands, which
    /// is a different question from whether it is in bounds — that has already
    /// been decided by the time this returns.
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
    ) -> Result<Resolved, VerifyError> {
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
                PtrClass::TraceObject => {
                    // A trace-object pointer *does* carry a schema — the
                    // Rust-native field layout the loader attached — so a direct
                    // load can be admitted at an exact declared field, which is
                    // the field-existence check `narf_probe_read` performs at
                    // runtime brought forward to here. Everything else about the
                    // opaque case still holds: a store is refused (a trace object
                    // is read-only, caught above), a variable or shifted offset
                    // names no field, and an in-object-but-not-a-field access is
                    // deliberately not enough. Failing that certification is a
                    // rejection, never a fallback to a raw dereference.
                    return self.typed_field_load(at, reg, &p, &addr, size, write);
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
            return Ok(Resolved::Opaque);
        }

        if p.class == PtrClass::Stack {
            // The whole byte range the access could touch, `[lo, hi)`. For a
            // constant offset the two collapse to one slot's worth and this is
            // the check that was always here; for a variable one it is the
            // generalisation, and the *only* thing that makes the variable case
            // safe. The concrete address is some `a` in `[addr.min, addr.max]`
            // — that is the domain's soundness invariant, and what
            // `fuzz.rs` differentially tests — so the concrete bytes
            // `[a, a + bytes)` are contained in `[lo, hi)` and proving that
            // range inside the frame proves the access inside the frame.
            let lo = addr.min;
            // `addr.max` is `i64::MAX` for a wholly unknown offset, so the sum
            // is where this would wrap into a *negative* `hi` and pass the
            // bound. Checked, not saturating: saturating to `i64::MAX` would
            // also be rejected by `hi > 0`, but only by accident.
            let Some(hi) = addr.max.checked_add(bytes as i64) else {
                return Err(VerifyError::OutOfBounds { at });
            };
            if lo >= 0 || lo < -i64::from(MAX_STACK_BYTES) || hi > 0 {
                return Err(VerifyError::OutOfBounds { at });
            }
            self.bare_access_sites
                .push(BareAccessSite { insn_index: at });
            return Ok(match addr.as_const() {
                Some(a) => Resolved::Const(a),
                // // LINUX-GAP: the range is proved, but nothing narrower is
                // modelled — a variable-offset read yields the access width and
                // a variable-offset write yields no value at all. Linux tracks
                // the same access against per-slot state and can sometimes keep
                // more. What it cannot do, and this does, is stay a single
                // interval check.
                None => Resolved::StackRange { lo, hi },
            });
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
            let resolved = addr
                .as_const()
                .map(Resolved::Const)
                .ok_or(VerifyError::OutOfBounds { at })?;
            self.bare_access_sites
                .push(BareAccessSite { insn_index: at });
            return Ok(resolved);
        }
        if p.class == PtrClass::Mem {
            self.bare_access_sites
                .push(BareAccessSite { insn_index: at });
        }
        Ok(Resolved::Opaque)
    }

    /// Admit a direct load through a trace-object pointer, but only at an exact
    /// declared field of its schema.
    ///
    /// This is the mediator's field check ([`Analysis::object_field_matches`]),
    /// applied to a bare `BPF_LDX` load instead of a
    /// `narf_probe_read` call. The base register must carry the wrapper pointer
    /// with no arithmetic on it — `p.off == 0` — because the runtime recovers
    /// the wrapper from that register directly; a shifted base would name a
    /// wrapper the interpreter never received. The effective offset is then the
    /// load's displacement, which must be a non-negative constant naming a field
    /// whose exact width equals the access size. A recorded [`TypedLoadSite`] is
    /// how the interpreter learns to service the load through the wrapper; it is
    /// pointedly *not* a [`BareAccessSite`], so the JIT refuses the program and
    /// it runs interpreted.
    fn typed_field_load(
        &mut self,
        at: u32,
        reg: Reg,
        p: &PtrVal,
        addr: &Scalar,
        size: Size,
        write: bool,
    ) -> Result<Resolved, VerifyError> {
        let mismatch = VerifyError::TypedFieldMismatch {
            at,
            reg: reg.index(),
        };
        // A store never names a readable field, and a trace object is read-only
        // regardless. Reject rather than record a certified write.
        if write {
            return Err(mismatch);
        }
        // The base must be the raw wrapper pointer: no arithmetic folded in, so
        // the whole effective offset is the load's constant displacement.
        if p.off.as_const() != Some(0) {
            return Err(mismatch);
        }
        let Some(field_offset) = addr.as_const().and_then(|v| u32::try_from(v).ok()) else {
            return Err(mismatch);
        };
        let width = size.bytes();
        let Ok(width) = u32::try_from(width) else {
            return Err(mismatch);
        };
        let names_field = self
            .prog
            .objects
            .iter()
            .find(|candidate| candidate.key == p.key)
            .is_some_and(|object| {
                object
                    .fields
                    .iter()
                    .any(|field| field.offset == field_offset && field.size == width)
            });
        if !names_field {
            return Err(mismatch);
        }
        self.typed_load_sites.push(TypedLoadSite {
            insn_index: at,
            field_offset,
            size: width,
        });
        Ok(Resolved::TypedField)
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
            (PtrClass::Stack, Resolved::Const(a)) => {
                if !st.stack.is_initialized(a, size.bytes()) {
                    return Err(VerifyError::UninitStack { at, off: a });
                }
                st.stack.read(a, size)
            }
            (PtrClass::Stack, Resolved::StackRange { lo, hi }) => {
                // Any byte in the range could be one of the bytes read, so
                // every byte in it has to be defined. Checking only `[lo, lo +
                // bytes)` would be the hole: the concrete offset is free to be
                // `addr.max`, and nothing said those bytes were written.
                let len = (hi - lo) as u64;
                if !st.stack.is_initialized(lo, len) {
                    return Err(VerifyError::UninitStack { at, off: lo });
                }
                // The frame has to be deep enough for every byte the load
                // could reach. Ordinarily the writes that initialised the range
                // already said so, but that is a fact about a *different*
                // instruction and, for a range initialised in another block,
                // about a different `Stack` — so it is asserted here rather
                // than inferred.
                self.note_depth((-lo) as u32);
                // No slot's value survives being read at an unknown offset: a
                // spilled pointer read from "one of these eight slots" is not
                // that pointer. Nothing but the width is left.
                AbsValue::Scalar(Scalar::unsigned_bits(size.bits()))
            }
            (PtrClass::Ctx, Resolved::Const(a)) => self.ctx_field(at, a, size)?,
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
        match (class, resolved) {
            (PtrClass::Stack, Resolved::Const(a)) => {
                st.stack.write(a, size, value);
                self.note_depth(st.stack.depth);
            }
            (PtrClass::Stack, Resolved::StackRange { lo, hi }) => {
                // A store nobody can place defines nothing and preserves
                // nothing — see `Stack::write_maybe` for why those are two
                // separate statements and why only one of them is obvious.
                st.stack.write_maybe(lo, hi);
                self.note_depth(st.stack.depth);
            }
            _ => {}
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
        match (class, resolved) {
            (PtrClass::Stack, Resolved::Const(a)) => {
                st.stack.write(a, size, width);
                self.note_depth(st.stack.depth);
            }
            (PtrClass::Stack, Resolved::StackRange { lo, hi }) => {
                st.stack.write_maybe(lo, hi);
                self.note_depth(st.stack.depth);
            }
            _ => {}
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

        // For a return that acquires a byte region (`bpf_ringbuf_reserve`), the
        // region is sized by its constant size argument. Read it now, while the
        // argument registers still hold it — they are cleared below — so the
        // returned pointer can carry a size and a write through it be proved in
        // bounds against exactly what was reserved.
        let acquired_mem_size = self.acquired_mem_size(st, at, &desc)?;

        // Record the resolution for codegen. After `check_args`, so a site only
        // lands here once the call itself is well-typed — a program that fails
        // verification produces no `VerifiedProgram` at all, but keeping the
        // order means the list can never describe a call the verifier rejected.
        self.kfunc_calls.push(KfuncCallSite {
            insn_index: at,
            id: desc.id,
            addr: desc.addr,
            context: desc.context,
        });

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
        let mut ret = value_of(&desc.ret, ret_ref);
        // Stamp the acquired region's size (see above). Only an acquiring `Mem`
        // return has one; every other return kind leaves `ret` untouched.
        if let (AbsValue::Ptr(p), Some(sz)) = (&mut ret, acquired_mem_size) {
            p.size = Some(sz);
        }
        st.regs[Reg::R0.as_usize()] = ret;

        // A kfunc handed the mutable context pointer can resize the packet
        // frame — `bpf_xdp_adjust_head`/`_tail` move `data`/`data_end`. Its
        // `PtrKind::Ctx` argument is the structural marker: no read-only helper
        // takes one, so its presence is exactly "this call may have moved the
        // packet window". Every proven packet extent is therefore struck off,
        // so a subsequent packet access without a fresh `data < data_end`
        // comparison is rejected. See [`AbsState::invalidate_packet_bounds`].
        if desc.args.iter().any(|a| {
            matches!(
                a.kind,
                TypeKind::Ptr {
                    kind: PtrKind::Ctx,
                    ..
                }
            )
        }) {
            st.invalidate_packet_bounds();
        }
        Ok(())
    }

    /// The byte size of an acquired region return, from its constant size
    /// argument — or `None` if the return does not acquire a byte region.
    ///
    /// `bpf_ringbuf_reserve(map, size, flags)` returns a region of exactly
    /// `size` bytes, and `size` must be a proven constant so the region can be
    /// bounded at verification time — Linux requires the same. The size is the
    /// argument the descriptor marks [`ArgFlags::CONST`]; `check_args` has
    /// already proved that argument is a single value.
    fn acquired_mem_size(
        &mut self,
        st: &mut AbsState,
        at: u32,
        desc: &KfuncDesc,
    ) -> Result<Option<u64>, VerifyError> {
        let acquires_mem = matches!(
            desc.ret.kind,
            TypeKind::Ptr {
                kind: PtrKind::Mem,
                ..
            }
        ) && desc.ret.consumes_in_arg_position();
        if !acquires_mem {
            return Ok(None);
        }
        // A descriptor of this shape without exactly one `CONST` size argument
        // is malformed. `KfuncDesc::validate` rejects it, but a missing size
        // would leave the region unbounded, so guard rather than trust.
        let sig_err = |arg| VerifyError::KfuncSignature {
            at,
            arg,
            expected: desc.ret,
        };
        let idx = desc
            .args
            .iter()
            .position(|a| a.flags.contains(ArgFlags::CONST))
            .ok_or_else(|| sig_err(0))?;
        let reg = Reg::new(idx as u8 + 1).ok_or_else(|| sig_err(idx))?;
        let AbsValue::Scalar(s) = self.get(st, at, reg)? else {
            return Err(sig_err(idx));
        };
        let c = s.as_const().ok_or_else(|| sig_err(idx))?;
        // The runtime caps the actual reservation; the verifier's job is only
        // to bound writes to what the program named. A `u64` reinterpretation
        // of a negative constant is an absurdly large region the runtime will
        // decline (returning null), which the mandatory null-check then
        // catches — so it is sound, if useless, and needs no rejection here.
        Ok(Some(c as u64))
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
                    if arg.flags.contains(ArgFlags::OBJECT_FIELD_OFFSET)
                        && !self.object_field_matches(st, at, k, desc, &s)
                    {
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
                        PtrKind::TraceObject => PtrClass::TraceObject,
                        PtrKind::Mem => PtrClass::Mem,
                        PtrKind::MemEnd => PtrClass::MemEnd,
                        PtrKind::Arena => PtrClass::Arena,
                        PtrKind::Ctx => PtrClass::Ctx,
                        PtrKind::MapValue => PtrClass::MapValue,
                        PtrKind::LockGuard => PtrClass::LockGuard,
                    };
                    if kind == PtrKind::Mem && arg.consumes_in_arg_position() {
                        // A released byte-region handle
                        // (`bpf_ringbuf_submit`/`discard`): the whole acquired
                        // region is handed back, so it must actually be a `Mem`
                        // region and — as for every other non-`Mem` pointer
                        // argument — its offset must be exactly zero. There is
                        // no separate length to bound; the release is
                        // discharged below.
                        if p.class != PtrClass::Mem || p.off.as_const() != Some(0) {
                            return Err(bad);
                        }
                    } else if kind == PtrKind::Mem {
                        // A byte region may be anything with a length: a stack
                        // slice, a map value, an arena range.
                        self.check_mem_arg(st, at, k, desc, &p)?;
                    } else if p.class != want
                        || (matches!(kind, PtrKind::Object | PtrKind::TraceObject)
                            && !arg.flags.contains(ArgFlags::ANY_TRACE_OBJECT)
                            && p.key != key)
                    {
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
                    //
                    // The `p.ref_id == NO_REF` disjunct is belt to the second
                    // one's brace, and deliberately kept: a `Ref` is keyed by
                    // its acquisition site's *instruction index* and `NO_REF`
                    // is `u32::MAX`, so `release(NO_REF)` finds nothing and the
                    // second test would fire on its own. Deleting the first
                    // therefore changes no verdict — mutation testing reports
                    // it as an equivalent mutant, and that is a fact about the
                    // sentinel's value rather than a gap in the tests. Change
                    // the sentinel to something inside the index range and it
                    // becomes load-bearing immediately;
                    // `releasing_the_no_ref_sentinel_never_discharges_a_reference`
                    // in `tests.rs` is what says so.
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

    /// Validate the relational part of the typed probe-read signature.
    ///
    /// `OBJECT_FIELD_OFFSET` names an exact field of an earlier object
    /// argument; the access width is the constant length paired with an
    /// earlier `SIZED_BY_NEXT` memory destination. The runtime repeats this
    /// check against the live wrapper, so this improves load-time diagnostics
    /// without becoming the only bounds check.
    fn object_field_matches(
        &self,
        st: &AbsState,
        at: u32,
        field_arg: usize,
        desc: &KfuncDesc,
        offset: &Scalar,
    ) -> bool {
        let Some(offset) = offset.as_const().and_then(|v| u32::try_from(v).ok()) else {
            return false;
        };
        let object = (0..field_arg).rev().find_map(|i| {
            let arg = desc.args[i];
            if !arg.flags.contains(ArgFlags::ANY_TRACE_OBJECT) {
                return None;
            }
            let reg = Reg::new(i as u8 + 1)?;
            match self.get(st, at, reg).ok()? {
                AbsValue::Ptr(p) if p.class == PtrClass::TraceObject => Some(p),
                _ => None,
            }
        });
        let Some(object) = object else {
            return false;
        };
        let width = (0..field_arg).find_map(|i| {
            if !desc.args[i].flags.contains(ArgFlags::SIZED_BY_NEXT) {
                return None;
            }
            let len_reg = Reg::new(i as u8 + 2)?;
            match self.get(st, at, len_reg).ok()? {
                AbsValue::Scalar(s) => s.as_const().and_then(|v| u32::try_from(v).ok()),
                _ => None,
            }
        });
        let Some(width) = width else {
            return false;
        };
        self.prog
            .objects
            .iter()
            .find(|candidate| candidate.key == object.key)
            .is_some_and(|object| {
                object
                    .fields
                    .iter()
                    .any(|field| field.offset == offset && field.size == width)
            })
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

        // A hook may expose a dynamically-sized byte region as a `Mem` /
        // `MemEnd` pair carrying one non-zero key. The program must compare a
        // derived data pointer with its paired exclusive end before a load.
        // On the safe edge, the compared offset is a lower bound on the live
        // extent, so publish that guarantee to every register alias of the
        // region. Stack spills deliberately remain unrefined for now: failing
        // to recover an alias rejects a safe program, while guessing one would
        // admit an unchecked dereference.
        if wide {
            if let (AbsValue::Ptr(dp), AbsValue::Ptr(sp), Source::Reg(_)) = (d, s, src) {
                let dynamic = match (dp.class, sp.class) {
                    (PtrClass::Mem, PtrClass::MemEnd) => Some((dp, sp, pred)),
                    (PtrClass::MemEnd, PtrClass::Mem) => Some((sp, dp, pred.swap_operands())),
                    _ => None,
                };
                if let Some((mem, end, relation)) = dynamic {
                    if mem.key.is_some() && mem.key == end.key {
                        let limit = match (relation, mem.off.as_const()) {
                            (Pred::Eq | Pred::Le, Some(off)) if off >= 0 => Some(off as u64),
                            (Pred::Lt, Some(off)) if off >= 0 => (off as u64).checked_add(1),
                            _ => None,
                        };
                        if let Some(limit) = limit {
                            let mut out = st.clone();
                            for value in &mut out.regs {
                                if let AbsValue::Ptr(alias) = value {
                                    if alias.class == PtrClass::Mem && alias.key == mem.key {
                                        alias.size =
                                            Some(alias.size.map_or(limit, |n| n.max(limit)));
                                    }
                                }
                            }
                            return Ok(Some(out));
                        }
                    }
                    // A comparison of dynamic pointers that did not establish
                    // a readable prefix still says nothing useful, but it is a
                    // legal runtime comparison.
                    return Ok(Some(st.clone()));
                }
            }
        }

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
                PtrKind::TraceObject => PtrClass::TraceObject,
                PtrKind::Mem => PtrClass::Mem,
                PtrKind::MemEnd => PtrClass::MemEnd,
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
