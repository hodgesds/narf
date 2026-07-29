//! Host tests for the IR and CFG.
//!
//! The CFG's job here is narrower than Linux's `check_cfg()`, which exists to
//! *reject* back-edges it cannot prove bounded. NARF accepts every loop, so
//! these tests are about the two things the fixpoint actually needs: correct
//! dominance, and every cycle entry marked for widening — including the
//! irreducible ones dominance alone cannot find.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CallTarget, CondOp, Decoded, Imm64, Insn, Reg, Source};

use crate::ir::{self, Ir};
use crate::VerifyError;

fn prog_of(insns: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in insns {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

fn build(insns: &[Decoded]) -> Ir {
    Ir::build(&prog_of(insns)).expect("well-formed program")
}

fn jeq(off: i16) -> Decoded {
    Decoded::JumpCond {
        wide: true,
        op: CondOp::Eq,
        dst: Reg::R1,
        src: Source::Imm(0),
        off,
    }
}

fn mov(v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: Reg::R0,
        src: Source::Imm(v),
        sign_extend: None,
    }
}

#[test]
fn straight_line_code_is_one_block() {
    let ir = build(&[mov(1), Decoded::Exit]);
    assert_eq!(ir.blocks.len(), 1);
    assert_eq!(ir.subprogs.len(), 1);
    assert!(ir.back_edges.is_empty());
    assert!(!ir.blocks[0].widen_here);
}

#[test]
fn ld_imm64_is_one_ir_instruction_over_two_slots() {
    // The IR is per-instruction, not per-slot. Getting this wrong would make
    // every jump displacement past a `LD_IMM64` land one instruction short.
    let ir = build(&[
        Decoded::LoadImm64 {
            dst: Reg::R0,
            value: Imm64::Value(0x1_0000_0000),
        },
        Decoded::Exit,
    ]);
    assert_eq!(ir.insns.len(), 2);
    assert_eq!(ir.insns[0].width, 2);
    assert_eq!(ir.insns[1].slot, 2);
    assert_eq!(ir.ir_of_slot[1], ir::NONE);
}

#[test]
fn a_diamond_gets_the_right_dominators() {
    //   0: if r1 == 0 goto 3
    //   1: r0 = 1
    //   2: goto 4
    //   3: r0 = 2
    //   4: exit
    let ir = build(&[
        jeq(2),
        mov(1),
        Decoded::Jump { off: 1 },
        mov(2),
        Decoded::Exit,
    ]);
    assert_eq!(ir.blocks.len(), 4);
    let join = ir.block_of[4];
    // The merge point is dominated by the branch, not by either arm.
    assert!(ir::dominates(&ir.blocks, 0, join));
    assert!(!ir::dominates(&ir.blocks, ir.block_of[1], join));
    assert!(ir.back_edges.is_empty());
}

#[test]
fn a_loop_is_accepted_and_marked_for_widening() {
    // Linux's `check_cfg()` rejects a back-edge outright unless it can prove
    // the loop bounded. NARF accepts it: fuel handles termination at runtime,
    // so the only thing the CFG needs to say is "widen here".
    //   0: r0 += 1
    //   1: if r1 == 0 goto -2
    //   2: exit
    let ir = build(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: Reg::R0,
            src: Source::Imm(1),
        },
        jeq(-2),
        Decoded::Exit,
    ]);
    assert_eq!(ir.back_edges.len(), 1);
    let (from, to) = ir.back_edges[0];
    assert_eq!(to, ir.block_of[0]);
    assert!(ir::dominates(&ir.blocks, to, from));
    assert!(ir.blocks[to as usize].widen_here);
    assert_ne!(ir.blocks[to as usize].scc, ir::NONE);
}

#[test]
fn an_irreducible_loop_is_still_widened() {
    // Two blocks that jump to each other, *entered at both* — so neither
    // dominates the other and dominance finds no back-edge at all. LLVM never
    // emits this, but a hostile program is hand-written bytecode, and a cycle
    // whose entries are never widened is a fixpoint that does not converge.
    // This is the case the SCC pass exists for.
    //   0: if r1 == 0 goto 3
    //   1: goto 4
    //   2: exit                (unreachable)
    //   3: goto 4
    //   4: goto 3
    let ir = build(&[
        jeq(2),
        Decoded::Jump { off: 2 },
        Decoded::Exit,
        Decoded::Jump { off: 0 },
        Decoded::Jump { off: -2 },
    ]);
    let a = ir.block_of[3];
    let b = ir.block_of[4];
    assert!(
        ir.back_edges.is_empty(),
        "dominance should find nothing here"
    );
    assert_ne!(ir.blocks[a as usize].scc, ir::NONE);
    assert_eq!(ir.blocks[a as usize].scc, ir.blocks[b as usize].scc);
    assert!(ir.blocks[a as usize].widen_here);
    assert!(ir.blocks[b as usize].widen_here);
}

#[test]
fn a_self_loop_is_a_cycle() {
    // A single block branching to itself: the SCC has one member, so the pass
    // has to check the self-edge explicitly or miss the cycle entirely.
    let ir = build(&[jeq(-1), Decoded::Exit]);
    let b = ir.block_of[0];
    assert_ne!(ir.blocks[b as usize].scc, ir::NONE);
    assert!(ir.blocks[b as usize].widen_here);
}

#[test]
fn nested_loops_get_two_widening_points() {
    //   0: r0 += 1            outer header
    //   1: r0 += 1            inner header
    //   2: if r1 == 0 goto -2   → 1
    //   3: if r1 == 0 goto -4   → 0
    //   4: exit
    let add = Decoded::Alu {
        wide: true,
        op: AluOp::Add,
        dst: Reg::R0,
        src: Source::Imm(1),
    };
    let ir = build(&[add, add, jeq(-2), jeq(-4), Decoded::Exit]);
    assert_eq!(ir.back_edges.len(), 2);
    let widened = ir.blocks.iter().filter(|b| b.widen_here).count();
    assert_eq!(widened, 2);
}

#[test]
fn a_call_creates_a_subprogram_and_a_call_graph_edge() {
    //   0: call +1        (target = 2)
    //   1: exit
    //   2: exit           (the subprogram)
    let ir = build(&[
        Decoded::Call(CallTarget::Subprog(1)),
        Decoded::Exit,
        Decoded::Exit,
    ]);
    assert_eq!(ir.subprogs.len(), 2);
    assert_eq!(ir.subprogs[1].entry_slot, 2);
    assert_eq!(ir.subprogs[0].callees, vec![1]);
    assert!(ir.subprogs[1].callees.is_empty());
    // A call does not end a basic block: the callee is summarised, not
    // inlined, so there is no CFG edge to split on.
    assert_eq!(ir.block_of[0], ir.block_of[1]);
}

#[test]
fn a_subprogram_address_taken_as_a_value_still_creates_a_subprogram() {
    // `LD_IMM64` with the `PSEUDO_FUNC` form is how a callback is handed to a
    // kfunc. No call instruction targets it, so the entry list has to come
    // from the immediate as well as from call sites.
    let ir = build(&[
        Decoded::LoadImm64 {
            dst: Reg::R1,
            value: Imm64::SubprogAddr(1),
        },
        Decoded::Exit,
        Decoded::Exit,
    ]);
    assert_eq!(ir.subprogs.len(), 2);
    assert_eq!(ir.subprogs[1].entry_slot, 3);
}

#[test]
fn a_branch_out_of_the_program_is_rejected_with_a_location() {
    let insns = prog_of(&[jeq(100), Decoded::Exit]);
    match Ir::build(&insns).unwrap_err() {
        VerifyError::BadTarget { at: 0, target } => assert_eq!(target, 101),
        other => panic!("expected BadTarget, got {other:?}"),
    }
}

#[test]
fn a_branch_into_the_middle_of_ld_imm64_is_rejected() {
    // The second slot of a `LD_IMM64` is not an instruction; jumping to it
    // would make the program mean something the decoder never saw.
    let insns = prog_of(&[
        jeq(0),
        Decoded::LoadImm64 {
            dst: Reg::R0,
            value: Imm64::Value(1),
        },
        Decoded::Exit,
    ]);
    // Target slot 1 is the first slot of the LD_IMM64, which is legal; slot 2
    // is its continuation, which is not.
    let bad = prog_of(&[
        jeq(1),
        Decoded::LoadImm64 {
            dst: Reg::R0,
            value: Imm64::Value(1),
        },
        Decoded::Exit,
    ]);
    assert!(Ir::build(&insns).is_ok());
    assert!(matches!(
        Ir::build(&bad).unwrap_err(),
        VerifyError::BadTarget { at: 0, target: 2 }
    ));
}

#[test]
fn falling_off_the_end_is_rejected() {
    let insns = prog_of(&[mov(0)]);
    assert!(matches!(
        Ir::build(&insns).unwrap_err(),
        VerifyError::FallsOffEnd { at: 0 }
    ));
}

#[test]
fn compared_constants_become_widening_thresholds() {
    // A loop bound is almost always a constant the program compares against;
    // if it is not in the threshold set, the first widening discards exactly
    // the fact the loop's memory accesses depend on.
    let ir = build(&[
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Ge,
            dst: Reg::R1,
            src: Source::Imm(64),
            off: 0,
        },
        Decoded::Exit,
    ]);
    assert!(ir.thresholds.contains(&64), "{:?}", ir.thresholds);
    assert!(ir.thresholds.contains(&0));
    assert!(
        ir.thresholds.windows(2).all(|w| w[0] < w[1]),
        "sorted+deduped"
    );
}

#[test]
fn def_use_marks_a_call_as_clobbering_the_whole_abi() {
    // R0..R5 are all clobbered by a call regardless of the callee's arity.
    // Liveness that carried R3 across a call would let a released reference
    // look alive, which is the sort of hole that only shows up as a UAF.
    let du = Ir::defs(&Decoded::Call(CallTarget::Kfunc(0)));
    assert_eq!(du.defs, 0b11_1111);
    assert_eq!(du.uses, 0b11_1110);
}

#[test]
fn def_use_marks_exit_as_reading_r0() {
    // Without this, an `Owned` reference left in R0 at exit is not "live" and
    // the leak check has nothing to look at.
    let du = Ir::defs(&Decoded::Exit);
    assert_eq!(du.uses, 1);
    assert_eq!(du.defs, 0);
}
