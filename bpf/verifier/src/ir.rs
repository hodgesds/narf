//! Decode → basic blocks → CFG, with dominators and SCCs.
//!
//! This is the layer that lets NARF *lower once*. Linux verifies the raw
//! instruction array and then patches it — `bpf_patch_insn_data()` shifts every
//! index, a `delta` is threaded through `convert_ctx_accesses()`,
//! `do_misc_fixups()` (959 LOC) and the `opt_*` passes, `adjust_jmp_off()`
//! repairs displacements, and `insn_aux_data` carries an `orig_idx` so
//! diagnostics can name the instruction the user actually wrote. All of that
//! exists only because there is no IR.
//!
//! Here, [`Ir`] is built once and never mutated. Every rewrite the JIT needs
//! (div-by-zero guards, probe-load conversion, arena base folding, Spectre
//! masking) is a *lowering rule* applied while emitting, not an edit to a
//! shared array. [`IrInsn::slot`] keeps the original instruction index around
//! purely so error messages can point at the user's program.
//!
//! ## What the CFG is for
//!
//! Exactly two things:
//!
//!   * **Where to widen.** The fixpoint ([`crate::fixpoint`]) widens at loop
//!     entries, and needs them identified up front. Three passes, because the
//!     first two are each insufficient on their own:
//!
//!     1. back-edges found by dominance, which cover reducible loops;
//!     2. entries into a non-trivial SCC, which cover the irreducible ones a
//!        hostile program can construct — nothing stops a compiler-shaped
//!        invariant from being violated by hand-written bytecode;
//!     3. heads for cycles *nested* inside another cycle, which neither of the
//!        above finds: Tarjan returns maximal SCCs, so an inner loop shares its
//!        parent's component and has no predecessor outside it, and if it is
//!        also irreducible then dominance sees no back-edge for it.
//!
//!     Together these establish the invariant the fixpoint needs and could not
//!     previously rely on: **every cycle contains at least one widening point.**
//!     Pinned by `every_cycle_has_a_widening_point`, which removes the marked
//!     blocks and asserts the remainder is acyclic.
//!   * **Where subprograms begin and end,** so stack depth can be summed along
//!     the static call graph.
//!
//! Notably it is *not* used to reject back-edges. Linux's `check_cfg()` does
//! that because it must prove termination; NARF proves nothing of the sort —
//! fuel terminates the program at runtime, so the verifier only needs a sound
//! over-approximation that converges. Arbitrary loops, including unbounded
//! ones, reach the fixpoint like any other control flow.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::{decode, CallTarget, Decoded, Imm64, Insn, Reg};

use crate::VerifyError;

/// Sentinel for "no block" / "no dominator" / "not in a non-trivial SCC".
pub const NONE: u32 = u32::MAX;

/// One instruction in the IR.
///
/// One entry per *decoded* instruction, so a `LD_IMM64` is a single IR
/// instruction rather than two slots. [`slot`](Self::slot) maps back to the
/// user's instruction index for diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IrInsn {
    /// The decoded operation.
    pub op: Decoded,
    /// Index of the first encoded slot this came from.
    pub slot: u32,
    /// How many slots it occupied — two for `LD_IMM64`, one otherwise.
    pub width: u8,
}

impl IrInsn {
    /// Slot index one past this instruction.
    #[inline]
    #[must_use]
    pub const fn next_slot(&self) -> u32 {
        self.slot + self.width as u32
    }
}

/// A basic block: a maximal straight-line run of IR instructions.
///
/// Calls do **not** end a block. A call is a transfer function like any other
/// (the callee is summarised, not inlined), and treating it as a terminator
/// would double the block count for no analysis benefit.
#[derive(Clone, Debug)]
pub struct Block {
    /// First IR index in the block.
    pub start: u32,
    /// One past the last IR index.
    pub end: u32,
    /// Successor block indices.
    pub succs: Vec<u32>,
    /// Predecessor block indices.
    pub preds: Vec<u32>,
    /// Which subprogram this block belongs to.
    pub subprog: u32,
    /// Immediate dominator, or [`NONE`] for a subprogram entry.
    pub idom: u32,
    /// Reverse-postorder number within the subprogram.
    pub rpo: u32,
    /// Strongly-connected-component id, or [`NONE`] if the block is not part
    /// of any cycle.
    pub scc: u32,
    /// Whether the fixpoint must widen on entry to this block.
    ///
    /// True for the target of a back-edge, and for any entry into a
    /// non-trivial SCC. The second condition is what makes termination
    /// independent of the CFG being reducible.
    pub widen_here: bool,
}

impl Block {
    /// Number of IR instructions in the block.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.end - self.start
    }

    /// Whether the block contains no instructions. Never true for a
    /// well-formed [`Ir`]; present because clippy asks for it.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// One subprogram: an entry point plus everything reachable from it without
/// crossing a call.
#[derive(Clone, Debug)]
pub struct Subprog {
    /// Encoded slot index of the entry instruction.
    pub entry_slot: u32,
    /// Block index of the entry.
    pub entry_block: u32,
    /// Blocks belonging to this subprogram, in reverse postorder.
    pub rpo: Vec<u32>,
    /// Subprograms this one calls directly.
    pub callees: Vec<u32>,
}

/// The whole verified-against program, in analysable form.
#[derive(Clone, Debug)]
pub struct Ir {
    /// Instructions, in program order.
    pub insns: Vec<IrInsn>,
    /// Encoded-slot index → IR index, or [`NONE`] for a continuation slot
    /// (the second half of a `LD_IMM64`).
    pub ir_of_slot: Vec<u32>,
    /// Basic blocks.
    pub blocks: Vec<Block>,
    /// IR index → owning block.
    pub block_of: Vec<u32>,
    /// Subprograms; index 0 is always the program entry.
    pub subprogs: Vec<Subprog>,
    /// Back-edges as `(from_block, to_block)`, found by dominance.
    pub back_edges: Vec<(u32, u32)>,
    /// Every distinct constant the program mentions, sorted.
    ///
    /// These are the widening thresholds. Jumping straight to `i64::MIN` /
    /// `i64::MAX` on the first widening would lose every bound a loop
    /// establishes; landing on a constant the program itself compares against
    /// keeps almost all of them. See [`crate::fixpoint`].
    pub thresholds: Vec<i64>,
}

impl Ir {
    /// The IR instruction at `index`.
    #[inline]
    #[must_use]
    pub fn insn(&self, index: u32) -> &IrInsn {
        &self.insns[index as usize]
    }

    /// The encoded-slot index of IR instruction `index`, for diagnostics.
    #[inline]
    #[must_use]
    pub fn slot_of(&self, index: u32) -> u32 {
        self.insns[index as usize].slot
    }

    /// Build the IR from an encoded program.
    ///
    /// # Errors
    ///
    /// [`VerifyError::Decode`] for a malformed instruction,
    /// [`VerifyError::BadTarget`] for a branch or call leaving the program,
    /// and [`VerifyError::FallsOffEnd`] if control can run past the last
    /// instruction.
    pub fn build(insns: &[Insn]) -> Result<Ir, VerifyError> {
        if insns.is_empty() {
            return Err(VerifyError::Empty);
        }

        // ── Pass 1: decode ──────────────────────────────────────────
        let mut ir: Vec<IrInsn> = Vec::new();
        let mut ir_of_slot = vec![NONE; insns.len()];
        let mut slot = 0usize;
        while slot < insns.len() {
            let (op, width) = decode(insns, slot).map_err(|err| VerifyError::Decode {
                at: slot as u32,
                err,
            })?;
            ir_of_slot[slot] = ir.len() as u32;
            ir.push(IrInsn {
                op,
                slot: slot as u32,
                width: width as u8,
            });
            slot += width;
        }
        // A `LD_IMM64` whose second slot is past the end is already caught by
        // the decoder; this catches a program whose last instruction claims to
        // be wider than the image.
        if slot != insns.len() {
            return Err(VerifyError::Decode {
                at: (insns.len() - 1) as u32,
                err: narf_bpf_isa::DecodeError::TruncatedImm64,
            });
        }

        // ── Pass 2: resolve control flow, in slot space ─────────────
        // Successors are computed on encoded slots because that is what the
        // ISA's displacements are counted in; they are mapped into IR indices
        // immediately afterwards so nothing downstream deals in slots.
        let n = ir.len();
        let mut succ_slots: Vec<Vec<u32>> = Vec::with_capacity(n);
        let mut subprog_entry_slots: Vec<u32> = vec![0];
        let mut thresholds: Vec<i64> = Vec::new();

        for (i, insn) in ir.iter().enumerate() {
            let at = insn.slot;
            let next = insn.next_slot();
            let mut succs: Vec<u32> = Vec::new();

            let branch = |off: i64| -> Result<u32, VerifyError> {
                let t = i64::from(next) + off;
                if t < 0 || t >= insns.len() as i64 || ir_of_slot[t as usize] == NONE {
                    return Err(VerifyError::BadTarget { at, target: t });
                }
                Ok(t as u32)
            };
            let fallthrough = |succs: &mut Vec<u32>| -> Result<(), VerifyError> {
                if next as usize >= insns.len() {
                    return Err(VerifyError::FallsOffEnd { at });
                }
                succs.push(next);
                Ok(())
            };

            match insn.op {
                Decoded::Exit => {}
                Decoded::Jump { off } => succs.push(branch(i64::from(off))?),
                Decoded::JumpCond { off, src, .. } => {
                    succs.push(branch(i64::from(off))?);
                    fallthrough(&mut succs)?;
                    if let narf_bpf_isa::Source::Imm(imm) = src {
                        thresholds.push(i64::from(imm));
                    }
                }
                // `may_goto` decrements a hidden counter and branches while it
                // lasts. NARF has no need for Linux's dedicated handling of it
                // (`verifier.c`'s `may_goto` state and the `BPF_MAY_GOTO`
                // rewrite): under fuel it is simply a nondeterministic branch,
                // which is exactly what the abstract semantics of "taken or
                // not, we cannot say" already is.
                Decoded::MayGoto { off } => {
                    succs.push(branch(i64::from(off))?);
                    fallthrough(&mut succs)?;
                }
                Decoded::Call(CallTarget::Subprog(off)) => {
                    let entry = branch(i64::from(off))?;
                    subprog_entry_slots.push(entry);
                    fallthrough(&mut succs)?;
                }
                Decoded::LoadImm64 {
                    value: Imm64::SubprogAddr(off),
                    ..
                } => {
                    // A subprogram address taken as a value — used for
                    // callback-style kfuncs. It creates a subprogram even
                    // though no call instruction targets it.
                    let entry = branch(i64::from(off))?;
                    subprog_entry_slots.push(entry);
                    fallthrough(&mut succs)?;
                }
                _ => {
                    fallthrough(&mut succs)?;
                    match insn.op {
                        Decoded::Alu {
                            src: narf_bpf_isa::Source::Imm(imm),
                            ..
                        }
                        | Decoded::Mov {
                            src: narf_bpf_isa::Source::Imm(imm),
                            ..
                        } => thresholds.push(i64::from(imm)),
                        Decoded::LoadImm64 {
                            value: Imm64::Value(v),
                            ..
                        } => thresholds.push(v as i64),
                        _ => {}
                    }
                }
            }
            let _ = i;
            succ_slots.push(succs);
        }

        subprog_entry_slots.sort_unstable();
        subprog_entry_slots.dedup();

        // ── Pass 2b: confine every edge to its own subprogram ───────
        //
        // Pass 2 could not do this: it *discovers* subprogram entries while it
        // resolves control flow, so the entry set is only complete now.
        //
        // This is what makes "the CFG has no inter-subprogram edges" true. It
        // used to be asserted (below, at pass 5) and not checked, and three
        // separate analyses were resting on it:
        //
        //   1. `run()` analyses subprograms in call-graph topological order and
        //      skips any whose entry state is still `None`, on the grounds that
        //      nothing calls it so it is dead code. A branch into another
        //      subprogram can populate an entry state *after* that
        //      subprogram's turn has passed — so it is never analysed, and its
        //      instructions are then dismissed as unreachable. Unverified code
        //      that runs. A 10-instruction program was enough: `call` into a
        //      subprogram whose body is `goto` backwards into a *second* call,
        //      and the second callee is never looked at.
        //
        //   2. The call graph attributes a `call` to
        //      `blocks[block_of[i]].subprog` — a slot-range label, not the
        //      subprogram whose control flow actually reaches it. So a
        //      cross-subprogram jump makes the graph describe edges that do not
        //      exist, which defeats the `Recursion` check (a real cycle looks
        //      acyclic) and under-reports `max_stack_bytes` (the sum walks the
        //      wrong path). That number is what `jit_glue`/`mem.rs` size the
        //      frame from.
        //
        //   3. Each subprogram is analysed with a fresh `Stack`, which is only
        //      sound if control cannot arrive mid-subprogram carrying another
        //      frame's slot model.
        //
        // Checked for *every* successor, fallthrough included: an instruction
        // falling through into the next subprogram's first slot is the same
        // violation as jumping there. A `call` is not an edge here — it is
        // recorded as a call-graph edge and its fallthrough stays local — so
        // legitimate calls are unaffected.
        {
            // `subprog_entry_slots` is sorted and deduped, so the enclosing
            // subprogram of a slot is the last entry at or below it.
            let enclosing = |slot: u32| -> (u32, u32) {
                let idx = subprog_entry_slots.partition_point(|&e| e <= slot) - 1;
                let lo = subprog_entry_slots[idx];
                let hi = subprog_entry_slots
                    .get(idx + 1)
                    .copied()
                    .unwrap_or(insns.len() as u32);
                (lo, hi)
            };
            for (i, succs) in succ_slots.iter().enumerate() {
                let at = ir[i].slot;
                let (lo, hi) = enclosing(at);
                for &t in succs {
                    if t < lo || t >= hi {
                        return Err(VerifyError::CrossSubprogEdge { at, target: t });
                    }
                }
            }
        }

        // ── Pass 3: block leaders ───────────────────────────────────
        let mut is_leader = vec![false; n];
        is_leader[0] = true;
        for &s in &subprog_entry_slots {
            is_leader[ir_of_slot[s as usize] as usize] = true;
        }
        for (i, succs) in succ_slots.iter().enumerate() {
            let straight_line = succs.len() == 1 && succs[0] == ir[i].next_slot();
            if !straight_line {
                // Anything that is not a plain fallthrough ends its block, and
                // every target it names starts one.
                if (i + 1) < n {
                    is_leader[i + 1] = true;
                }
                for &s in succs {
                    is_leader[ir_of_slot[s as usize] as usize] = true;
                }
            }
        }

        // ── Pass 4: blocks ──────────────────────────────────────────
        let mut block_of = vec![NONE; n];
        let mut blocks: Vec<Block> = Vec::new();
        for i in 0..n {
            if is_leader[i] {
                if let Some(prev) = blocks.last_mut() {
                    prev.end = i as u32;
                }
                blocks.push(Block {
                    start: i as u32,
                    end: n as u32,
                    succs: Vec::new(),
                    preds: Vec::new(),
                    subprog: NONE,
                    idom: NONE,
                    rpo: NONE,
                    scc: NONE,
                    widen_here: false,
                });
            }
            block_of[i] = (blocks.len() - 1) as u32;
        }

        for bi in 0..blocks.len() {
            let last = blocks[bi].end - 1;
            let succs: Vec<u32> = succ_slots[last as usize]
                .iter()
                .map(|&s| block_of[ir_of_slot[s as usize] as usize])
                .collect();
            for &s in &succs {
                blocks[s as usize].preds.push(bi as u32);
            }
            blocks[bi].succs = succs;
        }
        for b in &mut blocks {
            b.succs.dedup();
            b.preds.sort_unstable();
            b.preds.dedup();
        }

        // ── Pass 5: subprograms ─────────────────────────────────────
        // Subprograms partition the instruction stream the way Linux's
        // `subprog_info[]` does: entry points sorted, each running to the next.
        // The CFG has no inter-subprogram edges, so each is its own connected
        // component and can be analysed independently.
        let mut subprogs: Vec<Subprog> = subprog_entry_slots
            .iter()
            .map(|&entry_slot| Subprog {
                entry_slot,
                entry_block: block_of[ir_of_slot[entry_slot as usize] as usize],
                rpo: Vec::new(),
                callees: Vec::new(),
            })
            .collect();
        for (si, sp) in subprogs.iter().enumerate() {
            let lo = ir_of_slot[sp.entry_slot as usize];
            let hi = subprog_entry_slots
                .get(si + 1)
                .map_or(n as u32, |&s| ir_of_slot[s as usize]);
            for i in lo..hi {
                blocks[block_of[i as usize] as usize].subprog = si as u32;
            }
        }

        // Call graph. Callee ids are resolved through the entry-slot table, so
        // a call to something that is not a subprogram entry is impossible by
        // construction — the entry list was built from the call targets.
        for (i, insn) in ir.iter().enumerate() {
            if let Decoded::Call(CallTarget::Subprog(off)) = insn.op {
                let target = (i64::from(insn.next_slot()) + i64::from(off)) as u32;
                let callee = subprog_entry_slots.binary_search(&target).unwrap_or(0) as u32;
                let caller = blocks[block_of[i] as usize].subprog;
                subprogs[caller as usize].callees.push(callee);
            }
        }
        for sp in &mut subprogs {
            sp.callees.sort_unstable();
            sp.callees.dedup();
        }

        // ── Pass 6: RPO, dominators, back-edges ─────────────────────
        let mut back_edges = Vec::new();
        // Entry blocks are snapshotted first so the loop can hold `&mut
        // blocks` without also borrowing `subprogs`.
        let entries: Vec<u32> = subprogs.iter().map(|s| s.entry_block).collect();
        for (si, &entry) in entries.iter().enumerate() {
            let rpo = reverse_postorder(&blocks, entry);
            for (k, &b) in rpo.iter().enumerate() {
                blocks[b as usize].rpo = k as u32;
            }
            compute_idoms(&mut blocks, &rpo, entry);
            for &b in &rpo {
                let succs = blocks[b as usize].succs.clone();
                for s in succs {
                    if dominates(&blocks, s, b) {
                        back_edges.push((b, s));
                        blocks[s as usize].widen_here = true;
                    }
                }
            }
            subprogs[si].rpo = rpo;
        }

        // ── Pass 7: SCCs ────────────────────────────────────────────
        // Dominance-derived back-edges only find loop headers in *reducible*
        // CFGs. LLVM emits reducible control flow, but a hostile program is
        // hand-written bytecode, not LLVM output, and an irreducible loop whose
        // entries are never widened would not converge. Marking every entry
        // into a non-trivial SCC closes that hole, which is why the SCC pass
        // exists at all.
        tarjan_scc(&mut blocks);
        for bi in 0..blocks.len() {
            let scc = blocks[bi].scc;
            if scc == NONE {
                continue;
            }
            let entered_from_outside = blocks[bi]
                .preds
                .iter()
                .any(|&p| blocks[p as usize].scc != scc);
            if entered_from_outside {
                blocks[bi].widen_here = true;
            }
        }

        // ── Pass 7b: nested cycles ──────────────────────────────────
        //
        // Everything above finds widening points for *maximal* SCCs, and that
        // is not enough. Tarjan returns maximal components, so a loop nested
        // inside another shares its parent's SCC: the inner header has no
        // predecessor outside the component, `entered_from_outside` is false,
        // and if the inner loop is irreducible then dominance finds no back-edge
        // for it either. Nothing widened it, joins alone climbed forever, and
        // the only thing that stopped it was `fixpoint_round_budget` — so a safe
        // program was rejected with `FixpointDiverged`, which the docs
        // (correctly) describe as a verifier bug rather than a program bug.
        //
        // It was also a latency problem, and a much bigger one than §8.11
        // assessed: measured 16 385 rounds / 6 ms at 13 slots, rising linearly
        // to 8 195 073 rounds / 3.3 s at 16 013 slots, i.e. ~13 s at
        // `MAX_INSNS`, un-preemptible inside `sys_bpf`. §8.11 had reasoned that
        // the measured per-instruction cost "is the cost of a fixpoint that
        // *converges* — real work proportional to branching, not a divergence."
        // That reasoning does not cover this shape, because this shape *is* a
        // divergence.
        //
        // Fixed by iterating to a fixed point on the widening set, which is the
        // essential content of Bourdoncle's hierarchical decomposition without
        // needing to materialise the weak topological order: repeatedly find the
        // cyclic components among blocks that are *not yet* widening points, and
        // give each one a head. Treating an already-marked block as absent is
        // what makes this work — a cycle passing through a widening point is
        // already bounded, so only cycles avoiding every marked block still need
        // one. Each round marks at least one block, so this terminates, and on
        // exit **every cycle in the CFG contains a widening point** — which is
        // the property the module doc claims and previously did not have.
        //
        // Additive rather than a replacement: the pass above marks *every*
        // entry into a maximal SCC, and this only adds heads for cycles it
        // missed. Widening at more points is always sound (it costs precision,
        // never termination), and keeping the existing marks means the
        // irreducible-entry behaviour the tests pin is unchanged.
        mark_nested_widening_points(&mut blocks);

        thresholds.push(0);
        thresholds.push(-1);
        thresholds.push(i64::from(i32::MIN));
        thresholds.push(i64::from(i32::MAX));
        thresholds.push(u32::MAX as i64);
        thresholds.sort_unstable();
        thresholds.dedup();

        Ok(Ir {
            insns: ir,
            ir_of_slot,
            blocks,
            block_of,
            subprogs,
            back_edges,
            thresholds,
        })
    }

    /// Registers written by an instruction, for the liveness dataflow.
    ///
    /// Kept next to the CFG rather than in [`crate::liveness`] because it is a
    /// property of the instruction encoding, and having exactly one place that
    /// knows it is how the two dataflows stay consistent with the abstract
    /// interpreter.
    #[must_use]
    pub fn defs(op: &Decoded) -> DefUse {
        let mut d = DefUse::default();
        match *op {
            Decoded::Alu { dst, src, .. }
            | Decoded::Div { dst, src, .. }
            | Decoded::Mod { dst, src, .. } => {
                d.def(dst);
                d.use_(dst);
                d.use_src(src);
            }
            Decoded::Neg { dst, .. } | Decoded::End { dst, .. } => {
                d.def(dst);
                d.use_(dst);
            }
            Decoded::Mov { dst, src, .. } => {
                d.def(dst);
                d.use_src(src);
            }
            Decoded::AddrSpaceCast { dst, src, .. } => {
                d.def(dst);
                d.use_(src);
            }
            Decoded::Load { dst, src, .. } => {
                d.def(dst);
                d.use_(src);
                d.address = true;
            }
            Decoded::Store { dst, src, .. } => {
                d.use_(dst);
                d.use_src(src);
                d.address = true;
            }
            Decoded::Atomic { dst, src, op, .. } => {
                d.use_(dst);
                d.use_(src);
                d.address = true;
                if op.writes_src() {
                    d.def(src);
                }
                if matches!(op, narf_bpf_isa::AtomicOp::Cmpxchg) {
                    d.use_(Reg::R0);
                    d.def(Reg::R0);
                }
            }
            Decoded::LoadImm64 { dst, .. } => d.def(dst),
            Decoded::JumpCond { dst, src, .. } => {
                d.use_(dst);
                d.use_src(src);
                d.condition = true;
            }
            Decoded::Jump { .. } | Decoded::MayGoto { .. } => {}
            Decoded::Call(_) => {
                // R1..R5 are argument registers and R0 is the return value;
                // the ABI clobbers all six regardless of the callee's arity,
                // so liveness must not carry any of them past a call.
                for r in 1..=5u8 {
                    d.use_(Reg::new(r).unwrap());
                }
                for r in 0..=5u8 {
                    d.def(Reg::new(r).unwrap());
                }
            }
            // `exit` returns R0, so R0 is live out of every return site. That
            // is what makes "an `Owned` reference still in R0 at exit" a leak
            // the liveness pass can see.
            Decoded::Exit => d.use_(Reg::R0),
        }
        d
    }
}

/// Which registers an instruction reads and writes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DefUse {
    /// Bitmask of registers written.
    pub defs: u16,
    /// Bitmask of registers read.
    pub uses: u16,
    /// Whether the instruction computes a memory address, making its operands
    /// safety-relevant. Seeds the precision analysis.
    pub address: bool,
    /// Whether the instruction is a branch condition — likewise safety-
    /// relevant, because a bound established by a branch is only useful if the
    /// compared value was tracked precisely.
    pub condition: bool,
}

impl DefUse {
    fn def(&mut self, r: Reg) {
        self.defs |= 1 << r.index();
    }
    fn use_(&mut self, r: Reg) {
        self.uses |= 1 << r.index();
    }
    fn use_src(&mut self, s: narf_bpf_isa::Source) {
        if let narf_bpf_isa::Source::Reg(r) = s {
            self.use_(r);
        }
    }
}

/// Depth-first reverse postorder from `entry`, iteratively.
///
/// Iterative rather than recursive throughout this module: a program is
/// attacker-supplied and the kernel stack is not a place to discover that a
/// 100,000-block chain overflows it.
fn reverse_postorder(blocks: &[Block], entry: u32) -> Vec<u32> {
    let mut seen = vec![false; blocks.len()];
    let mut post: Vec<u32> = Vec::new();
    let mut stack: Vec<(u32, usize)> = vec![(entry, 0)];
    seen[entry as usize] = true;
    while let Some(&mut (b, ref mut next)) = stack.last_mut() {
        if *next < blocks[b as usize].succs.len() {
            let s = blocks[b as usize].succs[*next];
            *next += 1;
            if !seen[s as usize] {
                seen[s as usize] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
            stack.pop();
        }
    }
    post.reverse();
    post
}

/// Cooper–Harvey–Kennedy iterative dominators.
///
/// Chosen over Lengauer–Tarjan for the usual reason: on the block counts a BPF
/// program produces it is faster in practice and about a fifth of the code,
/// and the code is the part that has to be right.
fn compute_idoms(blocks: &mut [Block], rpo: &[u32], entry: u32) {
    blocks[entry as usize].idom = entry;
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let mut new_idom = NONE;
            for pi in 0..blocks[b as usize].preds.len() {
                let p = blocks[b as usize].preds[pi];
                if blocks[p as usize].idom == NONE {
                    continue; // not yet processed, or unreachable
                }
                new_idom = if new_idom == NONE {
                    p
                } else {
                    intersect(blocks, p, new_idom)
                };
            }
            if new_idom != NONE && blocks[b as usize].idom != new_idom {
                blocks[b as usize].idom = new_idom;
                changed = true;
            }
        }
    }
    // A subprogram entry dominates itself but has no dominator proper; leave
    // the self-reference so `dominates` terminates, and treat it as the root.
}

fn intersect(blocks: &[Block], mut a: u32, mut b: u32) -> u32 {
    while a != b {
        while blocks[a as usize].rpo > blocks[b as usize].rpo {
            let next = blocks[a as usize].idom;
            if next == a || next == NONE {
                return b;
            }
            a = next;
        }
        while blocks[b as usize].rpo > blocks[a as usize].rpo {
            let next = blocks[b as usize].idom;
            if next == b || next == NONE {
                return a;
            }
            b = next;
        }
    }
    a
}

/// Whether `a` dominates `b`.
#[must_use]
pub fn dominates(blocks: &[Block], a: u32, b: u32) -> bool {
    let mut cur = b;
    loop {
        if cur == a {
            return true;
        }
        let next = blocks[cur as usize].idom;
        if next == cur || next == NONE {
            return false;
        }
        cur = next;
    }
}

/// Give every cycle a widening point, including cycles nested inside another.
///
/// See pass 7b for why the maximal-SCC pass is not sufficient. The loop below
/// is the fixed-point formulation: while some cycle avoids every block already
/// marked `widen_here`, give that cycle a head.
///
/// Terminates because each round marks at least one previously-unmarked block,
/// and there are finitely many blocks.
fn mark_nested_widening_points(blocks: &mut [Block]) {
    loop {
        let comps = cyclic_components_avoiding_marked(blocks);
        if comps.is_empty() {
            return;
        }
        for comp in &comps {
            let head = pick_component_head(blocks, comp);
            blocks[head as usize].widen_here = true;
        }
    }
}

/// The head to widen at, chosen deterministically.
///
/// Determinism is not cosmetic here: acceptance must be a function of the
/// program alone (that is the whole point of §1.1's fuel model), and the
/// widening set changes precision, so a nondeterministic choice would make a
/// program's acceptance depend on iteration order.
///
/// Prefers a block entered from outside the component — that is the natural
/// loop header and widening there loses the least — and falls back to the
/// lowest block index when the component has no external entry, which happens
/// once an enclosing head has been removed.
fn pick_component_head(blocks: &[Block], comp: &[u32]) -> u32 {
    let in_comp = |b: u32| comp.contains(&b);
    let mut entry: Option<u32> = None;
    for &b in comp {
        if blocks[b as usize].preds.iter().any(|&p| !in_comp(p)) {
            entry = Some(entry.map_or(b, |e: u32| e.min(b)));
        }
    }
    entry.unwrap_or_else(|| comp.iter().copied().min().expect("non-empty component"))
}

/// Cyclic SCCs of the subgraph induced by blocks that are **not** already
/// widening points.
///
/// Marked blocks are treated as absent, edges through them included: a cycle
/// that passes through a widening point is already bounded, so it must not keep
/// being reported as needing one (which would loop forever).
fn cyclic_components_avoiding_marked(blocks: &[Block]) -> Vec<Vec<u32>> {
    let n = blocks.len();
    let live = |b: usize| !blocks[b].widen_here;

    let mut index = vec![NONE; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut next_index = 0u32;
    let mut out: Vec<Vec<u32>> = Vec::new();

    for root in 0..n {
        if !live(root) || index[root] != NONE {
            continue;
        }
        let mut work: Vec<(u32, usize)> = vec![(root as u32, 0)];
        index[root] = next_index;
        lowlink[root] = next_index;
        next_index += 1;
        stack.push(root as u32);
        on_stack[root] = true;

        while let Some(&mut (v, ref mut si)) = work.last_mut() {
            let vu = v as usize;
            if *si < blocks[vu].succs.len() {
                let w = blocks[vu].succs[*si] as usize;
                *si += 1;
                if !live(w) {
                    continue;
                }
                if index[w] == NONE {
                    index[w] = next_index;
                    lowlink[w] = next_index;
                    next_index += 1;
                    stack.push(w as u32);
                    on_stack[w] = true;
                    work.push((w as u32, 0));
                } else if on_stack[w] {
                    lowlink[vu] = lowlink[vu].min(index[w]);
                }
            } else {
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    let pu = parent as usize;
                    lowlink[pu] = lowlink[pu].min(lowlink[vu]);
                }
                if lowlink[vu] == index[vu] {
                    let mut members: Vec<u32> = Vec::new();
                    loop {
                        let w = stack.pop().expect("scc stack underflow");
                        on_stack[w as usize] = false;
                        members.push(w);
                        if w == v {
                            break;
                        }
                    }
                    // A single block is a cycle only if it loops to itself, and
                    // that self-edge must itself be live.
                    let cyclic = members.len() > 1 || (blocks[vu].succs.contains(&v) && live(vu));
                    if cyclic {
                        members.sort_unstable();
                        out.push(members);
                    }
                }
            }
        }
    }
    out
}

/// Iterative Tarjan SCC. Assigns [`Block::scc`] for every block that is part
/// of a cycle, leaving [`NONE`] for blocks that are not.
fn tarjan_scc(blocks: &mut [Block]) {
    let n = blocks.len();
    let mut index = vec![NONE; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut next_index = 0u32;
    let mut next_scc = 0u32;

    for root in 0..n {
        if index[root] != NONE {
            continue;
        }
        // (block, next successor to visit)
        let mut work: Vec<(u32, usize)> = vec![(root as u32, 0)];
        index[root] = next_index;
        lowlink[root] = next_index;
        next_index += 1;
        stack.push(root as u32);
        on_stack[root] = true;

        while let Some(&mut (v, ref mut si)) = work.last_mut() {
            let vu = v as usize;
            if *si < blocks[vu].succs.len() {
                let w = blocks[vu].succs[*si] as usize;
                *si += 1;
                if index[w] == NONE {
                    index[w] = next_index;
                    lowlink[w] = next_index;
                    next_index += 1;
                    stack.push(w as u32);
                    on_stack[w] = true;
                    work.push((w as u32, 0));
                } else if on_stack[w] {
                    lowlink[vu] = lowlink[vu].min(index[w]);
                }
            } else {
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    let pu = parent as usize;
                    lowlink[pu] = lowlink[pu].min(lowlink[vu]);
                }
                if lowlink[vu] == index[vu] {
                    // Pop one component. A component of a single block is only
                    // a real cycle if that block loops to itself.
                    let mut members: Vec<u32> = Vec::new();
                    loop {
                        let w = stack.pop().expect("scc stack underflow");
                        on_stack[w as usize] = false;
                        members.push(w);
                        if w == v {
                            break;
                        }
                    }
                    let cyclic = members.len() > 1 || blocks[vu].succs.contains(&v);
                    if cyclic {
                        for &m in &members {
                            blocks[m as usize].scc = next_scc;
                        }
                        next_scc += 1;
                    }
                }
            }
        }
    }
}
