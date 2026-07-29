//! Liveness and precision, as two instances of the same lattice dataflow.
//!
//! ## Liveness
//!
//! Textbook backward live-variable analysis:
//!
//! ```text
//!   live_out[i] = ⋃ live_in[s]   for s ∈ succ(i)
//!   live_in[i]  = (live_out[i] \ def[i]) ∪ use[i]
//! ```
//!
//! This is the shape `kernel/bpf/liveness.c:9-80` arrived at in 2025, after
//! twenty years of ad-hoc parent-chain marking. Its comment writes the
//! equations out in exactly this form, which is the strongest possible
//! argument for starting here rather than evolving into it. (Linux's instance
//! computes liveness of *stack slots*, call-chain sensitively, to drive state
//! pruning; NARF has no state pruning to drive, so this instance is over
//! registers and drives diagnostics instead — see below.)
//!
//! Liveness earns its place here by making one diagnostic possible. At an
//! await point the verifier kills every register whose validity domain does
//! not survive it (spec §4.4). Without liveness, a program that held a
//! `Trusted<T>` across a sleep would fail several instructions later with
//! "uninitialised register", naming neither the pointer nor the sleep. With
//! it, the killed set is intersected with the live set and the error names the
//! register, its domain, and the await that killed it.
//!
//! ## Precision
//!
//! Same equations, different seed. A register is *precise* at a point if its
//! value can still influence a memory address, a branch that guards one, or a
//! kfunc argument that must be a verified constant:
//!
//! ```text
//!   prec_out[i] = ⋃ prec_in[s]
//!   prec_in[i]  = (prec_out[i] \ def[i]) ∪ use[i]   if def[i] ∩ prec_out[i] ≠ ∅
//!                                                      or i addresses memory
//!                                                      or i is a branch
//! ```
//!
//! Linux computes the same information *retroactively*: `backtrack_insn()`
//! plus `__mark_chain_precision()` walk the state history backwards from the
//! point a bound turns out to matter, 474 lines of it, prefaced by a 95-line
//! comment at `verifier.c:4798` explaining why it has to work that way. It has
//! to work that way because precision is discovered mid-search, and the search
//! has already pruned states by then. NARF has no search — one abstract state
//! per program point, reached by a fixpoint — so the question "does this value
//! matter?" can be answered before analysis begins, by a dataflow that fits in
//! a page.
//!
//! What it is used for: the widening operator. A precise value is widened to
//! the nearest program constant, keeping the loop bound a later bounds check
//! depends on; an imprecise one is widened straight to top, which converges
//! faster and cannot cost an accepted program anything, because nothing
//! downstream reads it.

use alloc::vec;
use alloc::vec::Vec;

use crate::ir::{Ir, NONE};

/// A per-instruction bitmask result.
#[derive(Clone, Debug, Default)]
pub struct Masks {
    /// Registers live (or precise) *before* each IR instruction.
    pub before: Vec<u16>,
    /// Registers live (or precise) *after* each IR instruction.
    pub after: Vec<u16>,
}

impl Masks {
    /// Whether register `r` is in the set before instruction `i`.
    #[inline]
    #[must_use]
    pub fn before_has(&self, i: u32, r: u8) -> bool {
        (self.before[i as usize] & (1 << r)) != 0
    }

    /// Whether register `r` is in the set after instruction `i`.
    #[inline]
    #[must_use]
    pub fn after_has(&self, i: u32, r: u8) -> bool {
        (self.after[i as usize] & (1 << r)) != 0
    }
}

/// Successors of an IR instruction, in IR indices.
///
/// Inside a block this is just the next instruction; at a block's last
/// instruction it is the block's successors' entry instructions.
fn successors(ir: &Ir, i: u32) -> Vec<u32> {
    let b = &ir.blocks[ir.block_of[i as usize] as usize];
    if i + 1 < b.end {
        return vec![i + 1];
    }
    b.succs
        .iter()
        .map(|&s| ir.blocks[s as usize].start)
        .collect()
}

/// The shared backward fixpoint. `seed(i)` decides whether instruction `i`'s
/// uses enter the set unconditionally.
fn backward<F>(ir: &Ir, seed: F) -> Masks
where
    F: Fn(u32) -> bool,
{
    let n = ir.insns.len();
    let mut before = vec![0u16; n];
    let mut after = vec![0u16; n];

    // Iterate to a fixpoint over the whole program. The lattice is 11 bits per
    // instruction and the transfer functions are monotone, so this terminates
    // in at most 11·n rounds and in practice in three or four; no worklist is
    // worth the code at these sizes.
    let mut changed = true;
    while changed {
        changed = false;
        for i in (0..n).rev() {
            let i = i as u32;
            let mut out = 0u16;
            for s in successors(ir, i) {
                out |= before[s as usize];
            }
            let du = Ir::defs(&ir.insns[i as usize].op);
            let mut new_before = out & !du.defs;
            if seed(i) || (du.defs & out) != 0 {
                new_before |= du.uses;
            }
            if out != after[i as usize] || new_before != before[i as usize] {
                after[i as usize] = out;
                before[i as usize] = new_before;
                changed = true;
            }
        }
    }
    Masks { before, after }
}

/// Live-variable analysis over registers.
#[must_use]
pub fn liveness(ir: &Ir) -> Masks {
    // Every instruction's uses are live; that is what makes this liveness
    // rather than precision.
    backward(ir, |_| true)
}

/// Precision analysis: which registers' *values* can still reach a memory
/// address, a branch that guards one, or a kfunc argument.
///
/// Calls are seeded wholesale rather than only where an argument carries
/// [`crate::kfunc::ArgFlags::CONST`]. Over-approximating here costs a few
/// extra threshold lookups during widening and nothing else, and it keeps the
/// seed a property of the *instruction* — so this analysis stays independent
/// of the kfunc registry and can run before it is consulted.
#[must_use]
pub fn precision(ir: &Ir) -> Masks {
    let seeds: Vec<bool> = ir
        .insns
        .iter()
        .map(|insn| {
            let du = Ir::defs(&insn.op);
            du.address || du.condition || matches!(insn.op, narf_bpf_isa::Decoded::Call(_))
        })
        .collect();
    backward(ir, |i| seeds[i as usize])
}

/// Blocks reachable from a subprogram entry.
///
/// Unreachable code is not analysed — there is no state to give it, and
/// inventing one would mean reporting errors in instructions that never run.
#[must_use]
pub fn reachable_blocks(ir: &Ir, entry: u32) -> Vec<bool> {
    let mut seen = vec![false; ir.blocks.len()];
    if entry == NONE {
        return seen;
    }
    let mut stack = vec![entry];
    seen[entry as usize] = true;
    while let Some(b) = stack.pop() {
        for &s in &ir.blocks[b as usize].succs {
            if !seen[s as usize] {
                seen[s as usize] = true;
                stack.push(s);
            }
        }
    }
    seen
}
