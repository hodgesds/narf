//! Host tests for the emitter.
//!
//! Golden encodings rather than execution: running JITed code on the host would
//! need an executable mapping and a matching ABI, and the property that matters
//! here is that the *bytes* are right. Execution is covered in-kernel, where
//! the same image runs against the interpreter's result.

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CondOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::{Context, VerifiedProgram};

use crate::{compile, JitError};

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
    // Atomics are not emitted yet. The caller answers `Unsupported` by
    // interpreting, so this must be an error and never a silently wrong
    // encoding — the interpreter is a complete implementation, which is what
    // makes growing this backend incrementally safe.
    //
    // This test previously used multiply, which is now emitted. Deliberately
    // re-pointed at something still unhandled rather than deleted: the
    // property under test is "unemitted means refused", not any one opcode,
    // and it stops being tested at all the moment the chosen instruction gets
    // an encoding.
    let prog = verified(&[
        Decoded::Atomic {
            size: Size::Dw,
            op: narf_bpf_isa::AtomicOp::Add { fetch: false },
            dst: r(10),
            src: r(0),
            off: -8,
        },
        EXIT,
    ]);
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

/// The prologue, hand-derived from the Intel SDM.
///
/// `push rbp; push rbx; push r13; push r14; push r15; mov rbp, rdi; mov rdi, rsi`
///
/// `push rbp` is not decoration: R10 maps to rbp so the body overwrites it, and
/// rbp is callee-saved in SysV. An earlier version of this constant omitted it
/// and therefore *faithfully pinned the bug* — the test passed while every
/// invocation destroyed the caller's frame pointer. A golden test is only as
/// good as the derivation behind it.
const PROLOGUE: &[u8] = &[
    0x55, // push rbp
    0x53, // push rbx
    0x41, 0x55, // push r13
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    0x48, 0x89, 0xFD, // mov rbp, rdi
    0x48, 0x89, 0xF7, // mov rdi, rsi
];

/// `pop r15; pop r14; pop r13; pop rbx; ret`
const EPILOGUE: &[u8] = &[
    0x41, 0x5F, // pop r15
    0x41, 0x5E, // pop r14
    0x41, 0x5D, // pop r13
    0x5B, // pop rbx
    0x5D, // pop rbp
    0xC3, // ret
];

/// Assert the emitted body — everything between prologue and epilogue — is
/// exactly `want`.
///
/// Exact bytes, not "contains". The earlier tests asserted things like
/// `code.contains(&0xD3)`, which passes on wrong code that happens to include
/// that byte somewhere, and one asserted a displacement byte appeared *anywhere*
/// in the image, which is close to vacuous. For a code generator the encoding
/// *is* the behaviour, so the test has to pin it.
#[track_caller]
fn assert_body(items: &[Decoded], want: &[u8]) {
    let c = compile(&verified(items)).expect("should compile");
    assert!(
        c.code.starts_with(PROLOGUE),
        "prologue changed:\n got {:02X?}\nwant {PROLOGUE:02X?}",
        &c.code[..PROLOGUE.len().min(c.code.len())]
    );
    assert!(
        c.code.ends_with(EPILOGUE),
        "epilogue changed: got {:02X?}",
        &c.code[c.code.len().saturating_sub(EPILOGUE.len())..]
    );
    let body = &c.code[PROLOGUE.len()..c.code.len() - EPILOGUE.len()];
    assert_eq!(body, want, "\n got {body:02X?}\nwant {want:02X?}");
}

#[test]
fn golden_mov_imm64() {
    // r0 = 42; exit  →  mov rax, 42 (10-byte form) ; jmp epilogue
    assert_body(
        &[mov(0, 42), EXIT],
        &[
            0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0, // mov rax, 42
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32 -> epilogue (disp 0)
        ],
    );
}

#[test]
fn golden_add_reg() {
    // r0 += r1  →  add rax, rdi
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Add,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
            EXIT,
        ],
        &[0x48, 0x01, 0xF8, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_shift_imm() {
    // r0 <<= 5  →  shl rax, 5
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Lsh,
                dst: r(0),
                src: Source::Imm(5),
            },
            EXIT,
        ],
        &[0x48, 0xC1, 0xE0, 0x05, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_imul_reg() {
    // r0 *= r1  →  imul rax, rdi  (two-operand; the one-operand form would
    // clobber rdx = R3)
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Mul,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
            EXIT,
        ],
        &[0x48, 0x0F, 0xAF, 0xC7, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_frame_store_and_load() {
    // *(u64*)(r10-8) = r0 ; r1 = *(u64*)(r10-8)
    //   mov [rbp-8], rax   →  48 89 45 F8
    //   mov rdi, [rbp-8]   →  48 8B 7D F8
    // rbp as a base needs an explicit displacement byte even at zero, which is
    // the encoding trap `modrm_mem`'s `force_disp` exists for.
    assert_body(
        &[
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
            EXIT,
        ],
        &[
            0x48, 0x89, 0x45, 0xF8, // mov [rbp-8], rax
            0x48, 0x8B, 0x7D, 0xF8, // mov rdi, [rbp-8]
            0xE9, 0, 0, 0, 0,
        ],
    );
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
    // Superseded by `golden_frame_store_and_load`, which pins the exact
    // bytes. Kept as a smoke that the shape compiles at all.
    compile(&prog).expect("frame access must compile");
}

// ── branch encoding ─────────────────────────────────────────────────

#[test]
fn every_branch_is_rel32() {
    // This replaces a test that asserted a 123-byte short-branch cap as though
    // it were load-bearing. It was not: the emitter never selected a short
    // form, so the cap, the convergence loop, and that test all guarded a
    // hazard the code was not exposed to. Both are gone.
    //
    // What is worth pinning is the property the emitter actually has, because
    // it is the premise of there being no sizing fixpoint at all: every branch
    // is `rel32`. A short branch appearing without the loop coming back is the
    // regression this catches.
    let items = &[
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Eq,
            dst: r(0),
            src: Source::Imm(0),
            off: 1,
        },
        mov(0, 1),
        mov(0, 0),
        EXIT,
    ];
    let c = compile(&verified(items)).expect("compiles");
    // 0F 84 (je rel32) — not 74 (je rel8).
    assert!(
        c.code.windows(2).any(|w| w == [0x0F, 0x84]),
        "conditional branch should be the rel32 form"
    );
    assert!(
        !c.code.contains(&0x74),
        "a rel8 je appeared; the sizing fixpoint must come back with it"
    );
    // E9 (jmp rel32), never EB (jmp rel8).
    assert!(c.code.contains(&0xE9));
    assert!(!c.code.contains(&0xEB));
}

// ── shifts and multiply ─────────────────────────────────────────────

#[test]
fn shift_by_register_routes_through_cl() {
    // x86 requires a variable shift count in `cl`. `rcx` is absent from the
    // BPF→host map precisely so the count can be moved there without saving
    // anything — if a BPF register lived in `rcx` this would silently corrupt
    // it.
    let prog = verified(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Lsh,
            dst: r(0),
            src: Source::Reg(r(1)),
        },
        EXIT,
    ]);
    let c = compile(&prog).expect("register shift must compile");
    // Exact: mov rcx, rdi (48 89 F9) then shl rax, cl (48 D3 E0).
    //
    // Note the ModRM byte: for opcode 0x89 (`MOV r/m64, r64`) the reg field is
    // the *source* and r/m is the destination, so `mov rcx, rdi` is F9 —
    // reg=111(rdi), rm=001(rcx). CF would be `mov rdi, rcx`, the other
    // direction. I wrote CF here first and this test caught it, which is the
    // argument for exact encodings over byte-presence checks.
    let body = &c.code[PROLOGUE.len()..c.code.len() - EPILOGUE.len()];
    assert_eq!(
        &body[..6],
        &[0x48, 0x89, 0xF9, 0x48, 0xD3, 0xE0],
        "got {:02X?}",
        &body[..6.min(body.len())]
    );
}

#[test]
fn shift_by_immediate_is_masked_to_the_operand_width() {
    // BPF masks the count to the operand width and so does x86 in hardware,
    // so the low bits pass through — but the emitted byte must still be the
    // masked value, or a 64-bit shift by 65 would encode as 65 and a 32-bit
    // one differently again.
    for (wide, count, want) in [(true, 65i32, 1u8), (false, 33, 1), (true, 63, 63)] {
        let prog = verified(&[
            Decoded::Alu {
                wide,
                op: AluOp::Lsh,
                dst: r(0),
                src: Source::Imm(count),
            },
            EXIT,
        ]);
        let c = compile(&prog).expect("immediate shift must compile");
        assert!(
            c.code.contains(&want),
            "shift of {count} (wide={wide}) should encode a masked count of {want}"
        );
    }
}

#[test]
fn multiply_uses_the_two_operand_form() {
    // The one-operand `mul` writes rdx:rax, which would clobber R3 (rdx) and
    // R0. BPF's multiply is truncating, so `imul r64, r/m64` is both correct
    // and side-effect free — a real trap, since the obvious encoding is wrong.
    let prog = verified(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Mul,
            dst: r(0),
            src: Source::Reg(r(1)),
        },
        EXIT,
    ]);
    let c = compile(&prog).expect("multiply must compile");
    assert!(
        c.code.windows(2).any(|w| w == [0x0F, 0xAF]),
        "expected the two-operand imul (0F AF), not the rdx-clobbering form"
    );
    // And the one-operand form's /5 ModRM under 0xF7 must not appear.
    assert!(
        !c.code
            .windows(2)
            .any(|w| w[0] == 0xF7 && (w[1] >> 3) & 7 == 5),
        "one-operand imul would clobber rdx (R3) and rax (R0)"
    );
}
