//! Host tests for the liveness and precision dataflows.
//!
//! Both are the same lattice fixpoint with different seeds, so the tests check
//! the two things that differ: what the seed lets through, and what the
//! transfer function kills.

use alloc::vec::Vec;

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CallTarget, CondOp, Decoded, Insn, Reg, Size, Source};

use crate::ir::Ir;
use crate::liveness::{liveness, precision, reachable_blocks};

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

fn build(insns: &[Decoded]) -> Ir {
    let mut image: Vec<Insn> = Vec::new();
    for d in insns {
        image.extend_from_slice(encode(*d).slots());
    }
    Ir::build(&image).expect("well-formed program")
}

fn mov(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

fn movr(dst: u8, src: u8) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Reg(r(src)),
        sign_extend: None,
    }
}

#[test]
fn a_value_is_live_from_its_definition_to_its_last_use() {
    //   0: r6 = 1
    //   1: r7 = 2       (r6 live across, r7 defined)
    //   2: r0 = r6
    //   3: exit
    let ir = build(&[mov(6, 1), mov(7, 2), movr(0, 6), Decoded::Exit]);
    let l = liveness(&ir);
    assert!(l.after_has(0, 6), "r6 live after its definition");
    assert!(l.after_has(1, 6), "r6 live across the intervening write");
    assert!(!l.after_has(2, 6), "r6 dead after its last use");
    // R7 is written and never read, so it is dead everywhere.
    assert!(!l.after_has(1, 7));
}

#[test]
fn a_definition_kills_the_previous_value() {
    let ir = build(&[mov(6, 1), mov(6, 2), movr(0, 6), Decoded::Exit]);
    let l = liveness(&ir);
    // The first write is dead: the second overwrites it before any read.
    assert!(!l.after_has(0, 6));
    assert!(l.after_has(1, 6));
}

#[test]
fn liveness_flows_backwards_across_a_branch() {
    //   0: if r1 == 0 goto 3
    //   1: r0 = 1
    //   2: goto 4
    //   3: r0 = r6         ← the only use of r6
    //   4: exit
    let ir = build(&[
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Eq,
            dst: r(1),
            src: Source::Imm(0),
            off: 2,
        },
        mov(0, 1),
        Decoded::Jump { off: 1 },
        movr(0, 6),
        Decoded::Exit,
    ]);
    let l = liveness(&ir);
    // r6 must be live on the path that reaches its use, and that includes the
    // branch itself — a merge is a union, not an intersection.
    assert!(l.before_has(0, 6), "r6 live entering the branch");
    assert!(
        !l.before_has(1, 6),
        "…but not on the arm that never reads it"
    );
}

#[test]
fn r0_is_live_at_every_exit() {
    // Without this, an `Owned` reference sitting in R0 at exit is not "live"
    // and nothing looks at it.
    let ir = build(&[mov(0, 0), Decoded::Exit]);
    let l = liveness(&ir);
    assert!(l.before_has(1, 0));
    assert!(l.after_has(0, 0));
}

#[test]
fn a_call_reads_every_argument_register_and_writes_every_clobbered_one() {
    //   0: r1 = 1
    //   1: call kfunc      ← uses R1..R5, defines R0..R5
    //   2: r0 = r6
    //   3: exit
    //
    // Liveness says R1 is live *into* the call, because the call reads it. It
    // deliberately says nothing about whether the value defined at 0 survives
    // — that is a reaching-definitions question, and the abstract interpreter
    // answers it by marking R1..R5 uninitialised after every call. The two
    // together are what stop a released reference from looking alive.
    let ir = build(&[
        mov(1, 1),
        Decoded::Call(CallTarget::Kfunc(0)),
        movr(0, 6),
        Decoded::Exit,
    ]);
    let l = liveness(&ir);
    assert!(l.before_has(1, 1), "the call reads R1");
    assert!(l.after_has(0, 1));
    // R2 is never written by the program, yet the call still reads it — which
    // is exactly why the verifier rejects a call with an uninitialised
    // argument register only when the descriptor names that argument.
    assert!(l.before_has(1, 2));
    assert!(l.before_has(1, 6), "R6 survives the call to reach its use");
}

#[test]
fn callee_saved_registers_survive_a_call() {
    let ir = build(&[
        mov(6, 1),
        Decoded::Call(CallTarget::Kfunc(0)),
        movr(0, 6),
        Decoded::Exit,
    ]);
    let l = liveness(&ir);
    assert!(l.after_has(1, 6), "R6..R9 are callee-saved");
}

#[test]
fn precision_reaches_back_from_an_address_computation() {
    //   0: r6 = 1
    //   1: r7 = 2          ← never used in an address
    //   2: r1 = r6
    //   3: *(u64 *)(r1 - 8) = 0
    let ir = build(&[
        mov(6, 1),
        mov(7, 2),
        movr(1, 6),
        Decoded::Store {
            size: Size::Dw,
            dst: r(1),
            off: -8,
            src: Source::Imm(0),
        },
        mov(0, 0),
        Decoded::Exit,
    ]);
    let p = precision(&ir);
    // R6's value reaches an address, so it must be tracked precisely across
    // the widening at any loop that contains it.
    assert!(p.after_has(0, 6), "r6 feeds an address");
    // R7's does not.
    assert!(!p.after_has(1, 7), "r7 reaches nothing that matters");
}

#[test]
fn precision_reaches_back_from_a_branch() {
    // A bound is only useful if the value it constrains was tracked precisely,
    // so a comparison seeds precision the same way an address does.
    let ir = build(&[
        mov(6, 1),
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Gt,
            dst: r(6),
            src: Source::Imm(4),
            off: 0,
        },
        mov(0, 0),
        Decoded::Exit,
    ]);
    let p = precision(&ir);
    assert!(p.after_has(0, 6));
}

#[test]
fn a_counter_that_reaches_nothing_is_imprecise() {
    // The case the widening operator exploits: a value nothing downstream
    // reads for an address or a branch can go straight to top on the first
    // widening, which is both faster and free.
    let ir = build(&[
        mov(6, 0),
        Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(6),
            src: Source::Imm(1),
        },
        mov(0, 0),
        Decoded::Exit,
    ]);
    let p = precision(&ir);
    assert!(!p.after_has(0, 6));
}

#[test]
fn unreachable_blocks_are_identified() {
    //   0: goto 2
    //   1: r0 = 1      ← unreachable
    //   2: r0 = 2
    //   3: exit
    let ir = build(&[
        Decoded::Jump { off: 1 },
        mov(0, 1),
        mov(0, 2),
        Decoded::Exit,
    ]);
    let seen = reachable_blocks(&ir, ir.subprogs[0].entry_block);
    assert!(seen[ir.block_of[0] as usize]);
    assert!(!seen[ir.block_of[1] as usize], "dead code is not analysed");
    assert!(seen[ir.block_of[2] as usize]);
}
