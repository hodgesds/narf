//! Host tests for the emitter.
//!
//! Golden encodings rather than execution: running JITed code on the host would
//! need an executable mapping and a matching ABI, and the property that matters
//! here is that the *bytes* are right. Execution is covered in-kernel, where
//! the same image runs against the interpreter's result.

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CondOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::{Context, VerifiedProgram};

use crate::{compile, is_imm8_branch, JitError, MAX_SIZING_PASSES};

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

/// Wrap instructions in a `VerifiedProgram` without going through the
/// verifier. Sound for a *codegen* test: the emitter's contract is "given a
/// program the verifier accepted, produce equivalent machine code", and what
/// is under test is the second half.
fn verified(items: &[Decoded]) -> VerifiedProgram {
    let mut insns: Vec<Insn> = Vec::new();
    for d in items {
        insns.extend_from_slice(encode(*d).slots());
    }
    VerifiedProgram {
        insns,
        context: Context::Atomic,
        max_stack_bytes: 64,
        initial_fuel: 1024,
        fault_sites: Vec::new(),
        subprogs: Vec::new(),
        uses_arena: false,
    }
}

const EXIT: Decoded = Decoded::Exit;

fn mov(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

#[test]
fn emits_a_trivial_program() {
    let c = compile(&verified(&[mov(0, 42), EXIT])).expect("should compile");
    // Prologue saves the four callee-saved hosts, body, epilogue restores and
    // returns. The exact length is not the contract; that it terminates in
    // `ret` is.
    assert_eq!(*c.code.last().expect("non-empty"), 0xC3, "must end in ret");
    assert_eq!(c.entry_off, 0);
    assert!(c.faults.0.is_empty());
}

#[test]
fn mov_imm64_is_the_ten_byte_form() {
    // Deliberately not the shortest encoding. A `mov` whose size depends on
    // its immediate would change length between sizing passes, which is the
    // other way (besides branches) to make the fixpoint oscillate.
    let c = compile(&verified(&[mov(0, 1), EXIT])).expect("compiles");
    let c2 = compile(&verified(&[mov(0, i32::MAX), EXIT])).expect("compiles");
    assert_eq!(
        c.code.len(),
        c2.code.len(),
        "immediate magnitude must not change the emitted size"
    );
}

#[test]
fn sizing_converges_for_a_long_forward_branch() {
    // A body long enough that the branch cannot take a short displacement.
    let mut items = vec![Decoded::JumpCond {
        wide: true,
        op: CondOp::Eq,
        dst: r(0),
        src: Source::Imm(0),
        off: 300,
    }];
    for _ in 0..300 {
        items.push(Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(0),
            src: Source::Imm(1),
        });
    }
    items.push(mov(0, 0));
    items.push(EXIT);
    let c = compile(&verified(&items)).expect("a long branch must still compile");
    assert!(c.code.len() > 300);
}

#[test]
fn reports_unsupported_rather_than_emitting_wrong_code() {
    // Multiply is not emitted yet. The caller answers `Unsupported` by
    // interpreting, so this must be an error and never a silently wrong
    // encoding — the interpreter is a complete implementation, which is what
    // makes growing this backend incrementally safe.
    let prog = verified(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Mul,
            dst: r(0),
            src: Source::Imm(3),
        },
        EXIT,
    ]);
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn load_and_store_against_the_frame_encode() {
    let prog = verified(&[
        Decoded::Store {
            size: Size::Dw,
            dst: r(10),
            off: -8,
            src: Source::Reg(r(0)),
        },
        Decoded::Load {
            size: Size::Dw,
            sign_extend: false,
            dst: r(1),
            src: r(10),
            off: -8,
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("frame access must compile");
    // R10 maps to rbp, which needs an explicit displacement byte even at zero
    // — the encoding trap `modrm_mem` handles. A negative offset exercises it.
    assert!(c.code.windows(2).any(|w| w[1] == 0xF8 || w[0] == 0xF8));
}

// ── the convergence cap ─────────────────────────────────────────────

#[test]
fn short_branch_cap_is_123_not_127() {
    // The five bytes of headroom are the fix for a real oscillation between a
    // 2-byte and a 6-byte `je` paired with a 5-byte and a 2-byte `jmp`
    // (`arch/x86/net/bpf_jit_comp.c:70-113`). Asserted as a boundary, because
    // "it happens to converge on the programs we tried" is exactly how the
    // Linux bug survived.
    assert!(is_imm8_branch(123));
    assert!(!is_imm8_branch(124));
    assert!(!is_imm8_branch(127));
    assert!(is_imm8_branch(-128));
    assert!(!is_imm8_branch(-129));
}

#[test]
fn sizing_pass_budget_is_finite() {
    // Divergence must be reported, never looped on: this crate has no fuel of
    // its own and runs inside a syscall.
    assert!(MAX_SIZING_PASSES > 0 && MAX_SIZING_PASSES < 1000);
}
