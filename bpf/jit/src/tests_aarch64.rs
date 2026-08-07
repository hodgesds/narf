//! Host tests for the aarch64 emitter.
//!
//! Two kinds, and the split matters.
//!
//! **Golden encodings.** For a code generator the encoding *is* the behaviour,
//! and an x86-64 host cannot execute aarch64 bytes, so the bytes are pinned
//! exactly. Every expectation here was produced by assembling the intended
//! mnemonic with `llvm-mc -triple=aarch64 -show-encoding` and by disassembling
//! the emitted image with `llvm-objdump -d` — not by reading bit layouts out of
//! the manual, which is where transcription errors come from.
//!
//! **Differential.** [`a64_diff`] runs each program shape through a reference
//! BPF evaluator *and* through an aarch64 emulator fed the emitted image, then
//! compares the outcome including the *kind* of stop. Agreement on "both
//! stopped somehow" is worth nothing — that is the defect a review found in the
//! x86-64 suite's in-kernel harness. Agreement on "both returned 24" and "both
//! ran out of fuel at exactly 27 units" is the property.
//!
//! The emulator decodes from architectural bit fields and *panics* on anything
//! it does not recognise, so a new encoding cannot slip through untested by
//! being silently skipped.
//!
//! These call [`crate::aarch64::compile`] directly rather than [`crate::compile`]
//! so they run on an x86-64 host too. A backend tested only on its own
//! architecture is a backend whose tests nobody runs. Execution against the
//! *real* interpreter happens in-kernel, in `bpf/src/tests.rs`, which stops
//! skipping now that `has_backend()` is true on aarch64.

use narf_bpf_isa::{AluOp, CondOp, Decoded, Size, Source};

use narf_bpf_verifier::Context;

use crate::aarch64;
use crate::tests::{kcall, mov, r, verified, verified_calling, EXIT};
use crate::JitError;

/// The emitted image as instruction words. Every aarch64 instruction is four
/// bytes, little-endian regardless of data endianness.
fn a64_words(code: &[u8]) -> Vec<u32> {
    assert_eq!(code.len() % 4, 0, "image must be a whole number of words");
    code.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// The prologue:
///
/// ```text
///   stp  x19, x20, [sp, #-64]!
///   stp  x21, x22, [sp, #16]
///   stp  x24, x25, [sp, #32]
///   stur x30, [sp, #48]      ; the link register, which BLR clobbers
///   stur x3,  [sp, #56]      ; the arena slot base, in the frame's padding
///   mov x24, x2      ; fuel, before anything writes x2 (R2)
///   mov x25, x0      ; frame top, before anything writes x0 (R0)
///   mov x0, xzr      ; R0 := 0, so an unset R0 cannot return frame_top
/// ```
///
/// There is deliberately **no** `mov x1, x1`: the context pointer arrives in
/// `x1`, which is already R1's host register. That absence is load-bearing and
/// pinned here, because "no instruction needed" stops being true silently if
/// the register map is edited.
///
/// `x25` (R10) and `x24` (fuel) appear in the third `stp` for the reason the
/// x86-64 backend's `push rbp` exists: the body overwrites them and they are
/// callee-saved. [`a64_callee_saved_registers_survive`] proves the round trip
/// by *executing* it rather than by matching these bytes, because a golden
/// constant pins a bug as faithfully as it pins a fix — which is exactly how
/// the x86-64 prologue once shipped without `push rbp` and its test passed.
const A64_PROLOGUE: [u32; 8] = [
    0xa9bc_53f3,
    0xa901_5bf5,
    0xa902_67f8,
    0xf803_03fe,
    0xf803_83e3,
    0xaa02_03f8,
    0xaa00_03f9,
    0xaa1f_03e0,
];

/// `ldp x21,x22,[sp,#16]; ldp x24,x25,[sp,#32]; ldur x30,[sp,#48];`
/// `ldp x19,x20,[sp],#64; ret`
const A64_RESTORE: [u32; 5] = [
    0xa941_5bf5,
    0xa942_67f8,
    0xf843_03fe,
    0xa8c4_53f3,
    0xd65f_03c0,
];

/// The normal epilogue: `mov x1, xzr` (exhaustion flag clear) then the restore.
const A64_EPILOGUE: [u32; 6] = [
    0xaa1f_03e1,
    A64_RESTORE[0],
    A64_RESTORE[1],
    A64_RESTORE[2],
    A64_RESTORE[3],
    A64_RESTORE[4],
];

/// The out-of-fuel epilogue: `mov x1, #1` then the same restore.
const A64_OOF_EPILOGUE: [u32; 6] = [
    0xd280_0021,
    A64_RESTORE[0],
    A64_RESTORE[1],
    A64_RESTORE[2],
    A64_RESTORE[3],
    A64_RESTORE[4],
];

/// The arena-fault epilogue: `mov x0, x9` (the offending handle), `mov x1, #2`
/// (`status::ARENA_FAULT`), then the same restore.
///
/// Last in the image, and reached only through the exception table — nothing
/// branches here. Returning the handle is why the emitter folds `off16` into
/// `x9` instead of leaving it in the `LDUR`.
const A64_ARENA_EPILOGUE: [u32; 7] = [
    0xaa09_03e0,
    0xd280_0041,
    A64_RESTORE[0],
    A64_RESTORE[1],
    A64_RESTORE[2],
    A64_RESTORE[3],
    A64_RESTORE[4],
];

/// `subs x24, x24, #n` — the per-block fuel charge. The immediate is bits
/// 10..21.
fn a64_subs_fuel(n: u32) -> u32 {
    0xf100_0000 | (n << 10) | (24 << 5) | 24
}

/// `b.lo`, whatever its displacement: the per-block fuel test.
fn a64_is_b_lo(w: u32) -> bool {
    w & 0xff00_001f == 0x5400_0003
}

/// Compile and return the image words plus the range holding the body —
/// everything after the prologue and the leading fuel burn, up to the normal
/// epilogue.
///
/// The end is located by *searching* for the epilogue rather than by
/// arithmetic, so a change to either epilogue's length cannot silently shift
/// what is compared.
#[track_caller]
fn a64_image(items: &[Decoded]) -> (Vec<u32>, core::ops::Range<usize>) {
    let c = aarch64::compile(&verified(items)).expect("should compile");
    assert_eq!(c.entry_off, 0);
    assert!(
        c.faults.0.is_empty(),
        "a program with no arena access has nothing to record"
    );
    let w = a64_words(&c.code);
    assert_eq!(
        &w[..A64_PROLOGUE.len()],
        &A64_PROLOGUE,
        "prologue changed:\n got {:08x?}\nwant {A64_PROLOGUE:08x?}",
        &w[..A64_PROLOGUE.len()]
    );
    assert_eq!(
        &w[w.len() - A64_ARENA_EPILOGUE.len()..],
        &A64_ARENA_EPILOGUE,
        "the image must end with the arena-fault epilogue"
    );
    let start = A64_PROLOGUE.len() + 2; // the first block's `subs` + `b.lo`
    let end = w
        .windows(A64_EPILOGUE.len())
        .position(|x| x == A64_EPILOGUE)
        .expect("the normal epilogue must appear after the body");
    (w, start..end)
}

/// Assert the emitted body is exactly `want`.
#[track_caller]
fn a64_body(items: &[Decoded], want: &[u32]) {
    let (w, body) = a64_image(items);
    let burn = &w[A64_PROLOGUE.len()..A64_PROLOGUE.len() + 2];
    assert!(
        burn[0] & 0xffc0_03ff == 0xf100_0318 && a64_is_b_lo(burn[1]),
        "expected `subs x24,x24,#n; b.lo` at the block head, got {burn:08x?}"
    );
    assert_eq!(
        &w[body.clone()],
        want,
        "\n got {:08x?}\nwant {want:08x?}",
        &w[body]
    );
}

#[test]
fn a64_golden_prologue_and_epilogues() {
    // The two epilogues share a restore sequence and differ in exactly one
    // word — that one word is the whole out-of-band reporting mechanism, so
    // both must be present and they must disagree.
    let (w, _) = a64_image(&[mov(0, 42), EXIT]);
    assert!(
        w.windows(A64_EPILOGUE.len()).any(|x| x == A64_EPILOGUE),
        "the flag-clearing epilogue is missing"
    );
    assert_ne!(
        A64_EPILOGUE[0], A64_OOF_EPILOGUE[0],
        "the two epilogues must disagree about the exhaustion flag"
    );
}

#[test]
fn a64_golden_mov_imm() {
    // r0 = 42  →  four-word materialisation into x0, then `b` to the epilogue.
    a64_body(
        &[mov(0, 42), EXIT],
        &[
            0xd280_0540, // mov  x0, #42
            0xf2a0_0000, // movk x0, #0, lsl #16
            0xf2c0_0000, // movk x0, #0, lsl #32
            0xf2e0_0000, // movk x0, #0, lsl #48
            0x1400_0001, // b -> epilogue
        ],
    );
}

#[test]
fn a64_golden_mov_imm32_zero_extends() {
    // A 32-bit `mov` of -1 must leave 0x0000_0000_ffff_ffff, which two `W`
    // writes give for free: writing a W register zeroes the top half. Emitting
    // the 64-bit sequence here would sign-extend, and be wrong.
    a64_body(
        &[
            Decoded::Mov {
                wide: false,
                dst: r(6),
                src: Source::Imm(-1),
                sign_extend: None,
            },
            mov(0, 0),
            EXIT,
        ],
        &[
            0x529f_fff3, // mov  w19, #0xffff
            0x72bf_fff3, // movk w19, #0xffff, lsl #16
            0xd280_0000, // mov  x0, #0
            0xf2a0_0000,
            0xf2c0_0000,
            0xf2e0_0000,
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_immediate_magnitude_does_not_change_the_emitted_size() {
    // The materialisation is a fixed four words whatever the value. A shorter
    // sequence for small constants would be a size that varies with the
    // operand, which is the other way (besides branches) to make a sizing
    // fixpoint oscillate. This backend has none, and keeping immediates
    // constant-size is half of why.
    let a = aarch64::compile(&verified(&[mov(0, 1), EXIT])).expect("compiles");
    let b = aarch64::compile(&verified(&[mov(0, i32::MAX), EXIT])).expect("compiles");
    let c = aarch64::compile(&verified(&[mov(0, i32::MIN), EXIT])).expect("compiles");
    assert_eq!(a.code.len(), b.code.len());
    assert_eq!(a.code.len(), c.code.len());
}

#[test]
fn a64_golden_alu_register() {
    // Every register-source binary form in one image, so a swapped Rn/Rm or a
    // mis-set `sf` shows up as a byte difference here rather than as a wrong
    // answer three tests away.
    let mut items = Vec::new();
    for (op, dst, src) in [
        (AluOp::Add, 0u8, 1u8),
        (AluOp::Sub, 6, 7),
        (AluOp::Or, 2, 3),
        (AluOp::And, 4, 5),
        (AluOp::Xor, 8, 9),
        (AluOp::Mul, 0, 1),
    ] {
        for wide in [true, false] {
            items.push(Decoded::Alu {
                wide,
                op,
                dst: r(dst),
                src: Source::Reg(r(src)),
            });
        }
    }
    items.push(EXIT);
    a64_body(
        &items,
        &[
            0x8b01_0000, // add x0, x0, x1
            0x0b01_0000, // add w0, w0, w1
            0xcb14_0273, // sub x19, x19, x20
            0x4b14_0273, // sub w19, w19, w20
            0xaa03_0042, // orr x2, x2, x3
            0x2a03_0042, // orr w2, w2, w3
            0x8a05_0084, // and x4, x4, x5
            0x0a05_0084, // and w4, w4, w5
            0xca16_02b5, // eor x21, x21, x22
            0x4a16_02b5, // eor w21, w21, w22
            0x9b01_7c00, // mul x0, x0, x1   (MADD with Ra = xzr)
            0x1b01_7c00, // mul w0, w0, w1
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_shift_and_neg() {
    // Shifts use the variable forms even for a constant count: the hardware
    // masks the count to the operand width (mod 64 / mod 32), which is exactly
    // the interpreter's `b & 63` / `b & 31`. The constant-shift aliases
    // (`UBFM`/`SBFM`, whose immediate fields are *inverted* functions of the
    // count) would save one instruction and add an encoding class to get wrong.
    a64_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Lsh,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
            Decoded::Alu {
                wide: false,
                op: AluOp::Rsh,
                dst: r(3),
                src: Source::Reg(r(4)),
            },
            Decoded::Alu {
                wide: true,
                op: AluOp::Arsh,
                dst: r(3),
                src: Source::Reg(r(4)),
            },
            Decoded::Neg {
                wide: true,
                dst: r(0),
            },
            Decoded::Neg {
                wide: false,
                dst: r(0),
            },
            EXIT,
        ],
        &[
            0x9ac1_2000, // lsl x0, x0, x1
            0x1ac4_2463, // lsr w3, w3, w4
            0x9ac4_2863, // asr x3, x3, x4
            0xcb00_03e0, // neg x0, x0   (sub x0, xzr, x0)
            0x4b00_03e0, // neg w0, w0
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_alu_immediate_goes_through_the_scratch_register() {
    // `x16` is the immediate scratch, absent from the BPF→host map, so no BPF
    // register can be living in it. A 64-bit operation gets the sign-extended
    // immediate; a 32-bit one only ever reads the low half, so two words do.
    a64_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Add,
                dst: r(0),
                src: Source::Imm(-2),
            },
            Decoded::Alu {
                wide: false,
                op: AluOp::And,
                dst: r(0),
                src: Source::Imm(0x1234_5678),
            },
            EXIT,
        ],
        &[
            0xd29f_ffd0, // mov  x16, #0xfffe
            0xf2bf_fff0, // movk x16, #0xffff, lsl #16
            0xf2df_fff0, // movk x16, #0xffff, lsl #32
            0xf2ff_fff0, // movk x16, #0xffff, lsl #48   → -2
            0x8b10_0000, // add  x0, x0, x16
            0x528a_cf10, // mov  w16, #0x5678
            0x72a2_4690, // movk w16, #0x1234, lsl #16
            0x0a10_0000, // and  w0, w0, w16
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_frame_store_and_load() {
    // *(u64*)(r10-8) = r0 ; r1 = *(u64*)(r10-8)
    //
    // `LDUR`/`STUR` — the *unscaled* forms — so a negative displacement needs no
    // special case. The scaled forms (`LDR`/`STR` with `uimm12`) cannot express
    // a negative offset at all, and every BPF stack access is negative.
    a64_body(
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
            0xf81f_8320, // stur x0, [x25, #-8]
            0xf85f_8321, // ldur x1, [x25, #-8]
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_store_immediate() {
    // *(u64*)(r10-16) = 0x1234. The stored value is the immediate sign-extended
    // to 64 bits, matching the interpreter's `imm as i64 as u64`. The value
    // uses `x16` and the address `x17`, which is why the two scratch registers
    // are kept apart instead of shared.
    a64_body(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(10),
                off: -16,
                src: Source::Imm(0x1234),
            },
            mov(0, 0),
            EXIT,
        ],
        &[
            0xd282_4690, // mov  x16, #0x1234
            0xf2a0_0010,
            0xf2c0_0010,
            0xf2e0_0010,
            0xf81f_0330, // stur x16, [x25, #-16]
            0xd280_0000, // mov  x0, #0
            0xf2a0_0000,
            0xf2c0_0000,
            0xf2e0_0000,
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_narrower_store_and_sign_extending_load() {
    // *(u32*)(r10-8) = r0 ; r1 = *(s8*)(r10-8)
    //
    // The width rides the `[31:30]` size field of the same unscaled encoding —
    // `size=10` for the word store — and a sign-extending load switches the
    // `[23:22]` opc to `10`, which extends to the full 64-bit register to match
    // the interpreter's `widen`.
    a64_body(
        &[
            Decoded::Store {
                size: Size::W,
                dst: r(10),
                off: -8,
                src: Source::Reg(r(0)),
            },
            Decoded::Load {
                size: Size::B,
                sign_extend: true,
                dst: r(1),
                src: r(10),
                off: -8,
            },
            EXIT,
        ],
        &[
            0xb81f_8320, // stur  w0, [x25, #-8]   (size=10)
            0x389f_8321, // ldursb x1, [x25, #-8]  (size=00, opc=10)
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_far_displacement_folds_into_the_address_register() {
    // `LDUR`'s `simm9` reaches ±256. Beyond that the displacement is folded
    // into `x17` and the access uses a zero displacement — reusing the one
    // memory encoding instead of adding the scaled and register-offset forms.
    // Fewer encodings is fewer chances to emit something that assembles and
    // addresses the wrong place.
    a64_body(
        &[
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(2),
                src: r(1),
                off: 1000,
            },
            mov(0, 0),
            EXIT,
        ],
        &[
            0xd280_7d11, // mov  x17, #1000
            0xf2a0_0011,
            0xf2c0_0011,
            0xf2e0_0011,
            0x8b11_0031, // add  x17, x1, x17
            0xf840_0222, // ldur x2, [x17]
            0xd280_0000, // mov  x0, #0
            0xf2a0_0000,
            0xf2c0_0000,
            0xf2e0_0000,
            0x1400_0001,
        ],
    );
    // The boundary itself: 255 stays in the short form, 256 does not.
    let load = |off: i16| {
        aarch64::compile(&verified(&[
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(2),
                src: r(1),
                off,
            },
            EXIT,
        ]))
        .expect("compiles")
        .code
        .len()
    };
    assert!(
        load(256) > load(255),
        "off=256 must leave the LDUR range and off=255 must stay inside it"
    );
    assert!(
        load(-256) == load(255),
        "off=-256 is the negative end of the same range"
    );
    assert!(load(-257) > load(-256));
}

#[test]
fn a64_golden_conditional_branch_is_an_inverted_skip_over_a_long_branch() {
    // if r0 == r1 goto +1 ; r0 = 1 ; r0 = 0 ; exit
    //
    // The shape is fixed: compare, `b.<inverted>` two words forward, `b` to the
    // target. Two instructions whatever the distance, so nothing is re-measured
    // and there is no convergence loop to oscillate — the hazard Linux's x86 JIT
    // documents at `arch/x86/net/bpf_jit_comp.c:70-113`.
    a64_body(
        &[
            Decoded::JumpCond {
                wide: true,
                op: CondOp::Eq,
                dst: r(0),
                src: Source::Reg(r(1)),
                off: 1,
            },
            mov(0, 1),
            mov(0, 0),
            EXIT,
        ],
        &[
            0xeb01_001f, // cmp  x0, x1      (subs xzr, x0, x1)
            0x5400_0041, // b.ne #8          (inverted, skipping the `b`)
            0x1400_0007, // b    -> insn 2, seven words on
            // insn 1 follows a branch, so it opens a block of its own: one
            // instruction, charged one unit.
            0xf100_0718, // subs x24, x24, #1
            0x5400_0243, // b.lo -> the out-of-fuel epilogue
            0xd280_0020, // mov  x0, #1
            0xf2a0_0000,
            0xf2c0_0000,
            0xf2e0_0000,
            // insn 2 is a branch target, so it opens a block too: itself plus
            // `exit`, charged two.
            0xf100_0b18, // subs x24, x24, #2
            0x5400_0183,
            0xd280_0000, // mov  x0, #0
            0xf2a0_0000,
            0xf2c0_0000,
            0xf2e0_0000,
            0x1400_0001,
        ],
    );
}

#[test]
fn a64_golden_jset_uses_tst_not_cmp() {
    // `JSET` is "bits in common", which is `ANDS` to `xzr` — `TST`. Emitting
    // `CMP` here would compare the operands instead of testing them, and the
    // two encodings differ only in bits 24 and 29.
    a64_body(
        &[
            Decoded::JumpCond {
                wide: true,
                op: CondOp::Set,
                dst: r(0),
                src: Source::Reg(r(2)),
                off: 0,
            },
            EXIT,
        ],
        &[
            0xea02_001f, // tst x0, x2
            0x5400_0040, // b.eq #8   (inverted NE)
            0x1400_0001, // b -> insn 1 (the next word: `off: 0` falls through)
            0xf100_0718, // insn 1 opens a block
            0x5400_0103,
            0x1400_0001, // b -> epilogue
        ],
    );
}

#[test]
fn a64_every_condition_inverts_correctly() {
    // The skip branch must carry the *complement* of the taken condition; the
    // architecture makes that `cond ^ 1` for every code used here. Getting one
    // wrong inverts a single comparison, which is the kind of defect a
    // "compiles and mostly works" JIT ships with.
    let want = [
        (CondOp::Eq, 1u32), // taken EQ → skip NE
        (CondOp::Ne, 0),    // taken NE → skip EQ
        (CondOp::Gt, 9),    // taken HI → skip LS
        (CondOp::Ge, 3),    // taken HS → skip LO
        (CondOp::Lt, 2),    // taken LO → skip HS
        (CondOp::Le, 8),    // taken LS → skip HI
        (CondOp::Sgt, 13),  // taken GT → skip LE
        (CondOp::Sge, 11),  // taken GE → skip LT
        (CondOp::Slt, 10),  // taken LT → skip GE
        (CondOp::Sle, 12),  // taken LE → skip GT
        (CondOp::Set, 0),   // taken NE → skip EQ
    ];
    for (op, skip_cc) in want {
        let (w, body) = a64_image(&[
            Decoded::JumpCond {
                wide: true,
                op,
                dst: r(0),
                src: Source::Reg(r(1)),
                off: 0,
            },
            EXIT,
        ]);
        let skip = w[body.start + 1];
        assert_eq!(
            skip & 0xff00_0000,
            0x5400_0000,
            "{op:?}: expected a b.cond skip, got {skip:08x}"
        );
        assert_eq!(
            skip & 0xf,
            skip_cc,
            "{op:?}: skip condition should be {skip_cc}, got {}",
            skip & 0xf
        );
        assert_eq!(
            skip >> 5 & 0x7_ffff,
            2,
            "{op:?}: the skip must jump exactly over the following `b`"
        );
    }
}

#[test]
fn a64_no_conditional_branch_ever_takes_a_computed_displacement() {
    // The property behind "no sizing fixpoint": the only long-range branch is
    // `B`, and every `B.cond` is either the fixed two-word skip or the per-block
    // fuel test. A `B.cond` with any other displacement would mean someone
    // taught the emitter to pick a form based on distance, which needs the
    // convergence loop this backend does not have.
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
    let c = aarch64::compile(&verified(&items)).expect("a long branch must still compile");
    let w = a64_words(&c.code);
    let mut skips = 0usize;
    for x in &w {
        if x & 0xff00_0010 == 0x5400_0000 {
            let disp = (x >> 5) & 0x7_ffff;
            if disp == 2 {
                skips += 1;
            } else {
                assert!(
                    a64_is_b_lo(*x),
                    "unexpected b.cond with displacement {disp}: {x:08x}"
                );
            }
        }
    }
    assert!(skips > 0, "the conditional jump should have emitted a skip");
    assert!(c.code.len() > 300 * 4);
}

#[test]
fn a64_fuel_burn_charges_the_block_length() {
    // Four moves plus `exit` is one block of five, charged once. A
    // per-instruction charge, or a charge computed from the wrong block, shows
    // up here as a single wrong immediate.
    let (w, _) = a64_image(&[mov(0, 1), mov(2, 2), mov(3, 3), mov(4, 4), EXIT]);
    assert_eq!(
        w[A64_PROLOGUE.len()],
        a64_subs_fuel(5),
        "one block of five instructions must be charged five units"
    );
}

#[test]
fn a64_a_block_longer_than_the_immediate_reaches_still_charges_exactly() {
    // `SUBS`'s immediate is twelve bits. A longer block must materialise the
    // charge rather than truncate it: a truncated charge is a *fuel* bug, and
    // fuel is the one thing the interpreter and the JIT must not disagree on.
    let n = 5000usize;
    let mut items: Vec<Decoded> = (0..n - 1)
        .map(|_| Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(0),
            src: Source::Reg(r(1)),
        })
        .collect();
    items.push(EXIT);
    let c = aarch64::compile(&verified(&items)).expect("compiles");
    let w = a64_words(&c.code);
    let burn = &w[A64_PROLOGUE.len()..A64_PROLOGUE.len() + 5];
    assert_eq!(
        burn[0], 0xd282_7110,
        "expected `mov x16, #5000`, got {burn:08x?}"
    );
    assert_eq!(burn[4], 0xeb10_0318, "expected `subs x24, x24, x16`");
    assert!(
        !w.contains(&a64_subs_fuel(5000 & 0xfff)),
        "a truncated fuel charge was emitted"
    );
}

#[test]
fn a64_an_image_too_large_for_the_fuel_branch_is_refused_not_truncated() {
    // The per-block fuel test is the one `B.cond` with a computed displacement,
    // and `imm19` reaches ±1 MiB. Past that the emitter must refuse: a
    // truncated displacement is a branch into the middle of an instruction,
    // whereas an error means the program runs interpreted — a complete
    // implementation.
    //
    // One block, so the single fuel test at the top must reach the out-of-fuel
    // epilogue at the very bottom. Each `r0 += imm` is five words, so 60k
    // instructions clears 1 MiB.
    let mut items: Vec<Decoded> = (0..60_000)
        .map(|_| Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(0),
            src: Source::Imm(1),
        })
        .collect();
    items.push(EXIT);
    assert!(
        matches!(
            aarch64::compile(&verified(&items)),
            Err(JitError::BadTarget { .. })
        ),
        "an image past imm19 range must fail closed"
    );
}

#[test]
fn a64_reports_unsupported_rather_than_emitting_wrong_code() {
    // Everything this backend deliberately leaves to the interpreter. Each is
    // checked individually: a single representative stops covering the rest the
    // moment it gains an encoding, which is how the x86-64 suite's
    // "unsupported" test came to be pointed at multiply after multiply started
    // being emitted.
    let cases: [(&str, Decoded); 6] = [
        (
            "atomic",
            Decoded::Atomic {
                size: Size::Dw,
                op: narf_bpf_isa::AtomicOp::Add { fetch: false },
                dst: r(10),
                src: r(0),
                off: -8,
            },
        ),
        (
            "div",
            Decoded::Div {
                wide: true,
                signed: false,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
        ),
        (
            "mod",
            Decoded::Mod {
                wide: true,
                signed: false,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
        ),
        (
            "movsx",
            Decoded::Mov {
                wide: true,
                dst: r(0),
                src: Source::Reg(r(1)),
                sign_extend: Some(8),
            },
        ),
        (
            "byteswap",
            Decoded::End {
                dst: r(0),
                order: narf_bpf_isa::ByteOrder::Big,
                width: 32,
            },
        ),
        (
            "ld_imm64",
            Decoded::LoadImm64 {
                dst: r(0),
                value: narf_bpf_isa::Imm64::Value(1),
            },
        ),
    ];
    for (what, insn) in cases {
        assert!(
            matches!(
                aarch64::compile(&verified(&[insn, EXIT])),
                Err(JitError::Unsupported { at: 0, .. })
            ),
            "{what} must be refused, not mis-encoded"
        );
    }
}

/// Compile an arena program on this backend and return its words.
///
/// Through `aarch64::compile` rather than `compile`, which dispatches to the
/// *host* — so these run on an x86-64 developer machine too, which is the whole
/// reason this file exists.
#[track_caller]
fn a64_arena_words(
    items: &[Decoded],
    fault_at: u32,
    dst: Option<u8>,
) -> (Vec<u32>, crate::Compiled) {
    let prog = crate::tests::verified_arena(items, fault_at, dst);
    let c = aarch64::compile(&prog).expect("the arena shape is emitted now");
    (a64_words(&c.code), c)
}

#[test]
fn a64_an_arena_store_takes_the_slot_relative_shape() {
    // The aarch64 half of `an_arena_access_lowers_to_the_slot_relative_shape`.
    // Stated per backend because the lowering is written per backend, so one of
    // them could regress without the other.
    //
    // Every word below was cross-checked against `llvm-mc -triple=aarch64
    // -show-encoding` rather than read off the manual, which is the same rule
    // the rest of this file's constants follow.
    let (w, c) = a64_arena_words(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(1),
                off: 8,
                src: Source::Imm(1),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let body = &w[A64_PROLOGUE.len() + 2..];
    assert_eq!(
        &body[..14],
        &[
            0x2a01_03e9, // mov  w9, w1        — zero-extend the handle
            0xd280_0110, // movz x16, #8       — the displacement, sign-extended
            0xf2a0_0010, // movk x16, #0, lsl #16
            0xf2c0_0010, // movk x16, #0, lsl #32
            0xf2e0_0010, // movk x16, #0, lsl #48
            0x8b10_0129, // add  x9, x9, x16   — x9 is now the handle
            0xf843_83f1, // ldur x17, [sp,#56] — the parked slot base
            0x8b09_0231, // add  x17, x17, x9  — the address
            0xd280_0030, // movz x16, #1       — the stored value
            0xf2a0_0010, // movk x16, #0, lsl #16
            0xf2c0_0010, // movk x16, #0, lsl #32
            0xf2e0_0010, // movk x16, #0, lsl #48
            0xf800_0230, // stur x16, [x17]    — the faulting instruction
            0xd280_0000, // (mov x0, #0 — the next BPF instruction)
        ],
        "\n got {:08x?}",
        &body[..14]
    );
    // The value is materialised *after* the address, because `emit_arena_addr`
    // uses x16 as scratch for the displacement. Reversing the two would store a
    // displacement instead of a value, and the golden above is what says so.
    assert_eq!(c.faults.0.len(), 1);
    assert!(c.faults.0[0].arena);
    assert_eq!(c.faults.0[0].dst_host_reg, None);
    // The faulting word is the `stur`, not the address arithmetic before it.
    assert_eq!(
        c.faults.0[0].fault_off as usize,
        (A64_PROLOGUE.len() + 2 + 12) * 4
    );
}

#[test]
fn a64_the_arena_fixup_is_the_epilogue_and_not_the_next_instruction() {
    // The property that separates this from Linux's `ex_handler_bpf`: a probe
    // read zeroes its destination and carries on, an arena fault *stops*.
    //
    // Mutation: point `fixup_off` at the next instruction and this goes red.
    let (w, c) = a64_arena_words(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(1),
                off: 0,
                src: Source::Imm(1),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let arena_epi = w.len() - A64_ARENA_EPILOGUE.len();
    assert_eq!(
        &w[arena_epi..],
        &A64_ARENA_EPILOGUE,
        "the image must end with the arena-fault epilogue"
    );
    assert_eq!(
        c.faults.0[0].fixup_off as usize,
        arena_epi * 4,
        "the fixup must name the arena epilogue, not the next instruction"
    );
}

#[test]
fn a64_an_arena_load_and_a_register_store_take_the_same_shape() {
    // The other two arena forms, and the zero-displacement path — which skips
    // the four-word immediate materialisation entirely.
    let (w, _) = a64_arena_words(
        &[
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(3),
                src: r(2),
                off: 0,
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        Some(3),
    );
    let body = &w[A64_PROLOGUE.len() + 2..];
    assert_eq!(
        &body[..4],
        &[
            0x2a02_03e9, // mov  w9, w2
            0xf843_83f1, // ldur x17, [sp,#56]
            0x8b09_0231, // add  x17, x17, x9
            0xf840_0223, // ldur x3, [x17]
        ],
        "\n got {:08x?}",
        &body[..4]
    );

    let (w, _) = a64_arena_words(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(2),
                off: 0,
                src: Source::Reg(r(3)),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let body = &w[A64_PROLOGUE.len() + 2..];
    assert_eq!(
        &body[..4],
        &[
            0x2a02_03e9, // mov  w9, w2
            0xf843_83f1, // ldur x17, [sp,#56]
            0x8b09_0231, // add  x17, x17, x9
            0xf800_0223, // stur x3, [x17]
        ],
        "\n got {:08x?}",
        &body[..4]
    );
}

#[test]
fn a64_a_non_arena_access_keeps_the_plain_shape() {
    // Lifting gate 2 must not give *every* access the arena shape. Same
    // instruction, no fault site, plain `[base, #disp]` — and no fault entry.
    //
    // Without this, an emitter that ignored `arena_access_map` and always took
    // the arena path would pass every arena test above.
    let c = aarch64::compile(&verified(&[
        Decoded::Store {
            size: Size::Dw,
            dst: r(1),
            off: 8,
            src: Source::Imm(1),
        },
        mov(0, 0),
        EXIT,
    ]))
    .expect("compiles");
    let w = a64_words(&c.code);
    let body = &w[A64_PROLOGUE.len() + 2..];
    // `movz x16, #1` + three `movk`, then `stur x16, [x1, #8]`.
    assert_eq!(
        body[4], 0xf800_8030,
        "a non-arena store must keep the plain addressing shape, got {:08x}",
        body[4]
    );
    assert!(c.faults.0.is_empty());
}

#[test]
fn a64_an_arena_atomic_the_emitter_cannot_shape_is_refused() {
    // Fail-closed, and specifically not by falling through to the plain
    // lowering — which would be a bare dereference of a handle. Narrower loads
    // and stores are emitted now; an atomic still has no arena shape.
    let prog = crate::tests::verified_arena(
        &[
            Decoded::Atomic {
                size: Size::Dw,
                op: narf_bpf_isa::AtomicOp::Add { fetch: false },
                dst: r(1),
                src: r(0),
                off: 8,
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    assert!(matches!(
        aarch64::compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

// ── differential: reference evaluator vs. emulated native code ───────

/// Base of the flat memory region both sides share the layout of.
const MEM_BASE: u64 = 0x1_0000;
const MEM_LEN: usize = 0x4000;
/// Native stack top. Well above the BPF frame, so the prologue's saves cannot
/// alias what the program stores.
const SP_INIT: u64 = MEM_BASE + 0x3000;
/// What the runtime passes as `frame_top`; the BPF frame grows down from here.
const FRAME_TOP: u64 = MEM_BASE + 0x1000;
/// What the runtime passes as the context pointer.
const CTX_ADDR: u64 = MEM_BASE + 0x2000;

/// How a run ended. The variant *is* the trap kind, which is what makes
/// comparing two of these worth doing.
#[derive(Debug, PartialEq, Eq)]
enum Run {
    Returned(u64),
    OutOfFuel,
    BadAccess,
    /// Jumped outside the program. `compile` rejects those, so seeing one means
    /// the harness built a program the emitter should not have accepted.
    BadTarget,
}

#[derive(Clone, Debug)]
struct Mem {
    bytes: Vec<u8>,
}

impl Mem {
    fn new() -> Self {
        Self {
            bytes: vec![0u8; MEM_LEN],
        }
    }
    /// Every aligned doubleword holds its own address, so a load *identifies*
    /// the address it read from.
    ///
    /// Mutation testing is why this exists: widening the `LDUR` range by one
    /// made the emitter encode `+256` as `imm9 = -256`, and a store-then-load
    /// round trip through the same wrong address still returned the right
    /// value. A test that cannot see *where* an access landed cannot see an
    /// address-computation bug.
    fn patterned() -> Self {
        let mut m = Self::new();
        for slot in 0..MEM_LEN / 8 {
            let addr = MEM_BASE + (slot * 8) as u64;
            m.store64(addr, addr).expect("in bounds");
        }
        m
    }
    fn index(&self, addr: u64) -> Option<usize> {
        let off = addr.checked_sub(MEM_BASE)? as usize;
        if off.checked_add(8)? <= MEM_LEN {
            Some(off)
        } else {
            None
        }
    }
    fn load64(&self, addr: u64) -> Option<u64> {
        let i = self.index(addr)?;
        Some(u64::from_le_bytes(
            self.bytes[i..i + 8].try_into().expect("eight bytes"),
        ))
    }
    fn store64(&mut self, addr: u64, v: u64) -> Option<()> {
        let i = self.index(addr)?;
        self.bytes[i..i + 8].copy_from_slice(&v.to_le_bytes());
        Some(())
    }
}

/// The reference BPF evaluator: one unit of fuel per instruction retired,
/// exactly as `bpf/src/interp.rs` does.
///
/// Covers only what the aarch64 backend emits, and panics on anything else, so
/// a harness that grows a shape the emitter handles differently cannot quietly
/// compare two wrong answers.
fn bpf_reference(items: &[Decoded], mut fuel: u64, mem: &mut Mem) -> Run {
    let mut reg = [0u64; 11];
    reg[1] = CTX_ADDR;
    reg[10] = FRAME_TOP;
    let mut pc = 0usize;
    let mask = |v: u64, wide: bool| if wide { v } else { v & 0xffff_ffff };
    let src_val = |s: Source, reg: &[u64; 11]| match s {
        Source::Reg(x) => reg[x.as_usize()],
        Source::Imm(i) => i as i64 as u64,
    };
    loop {
        if pc >= items.len() {
            return Run::BadTarget;
        }
        if fuel == 0 {
            return Run::OutOfFuel;
        }
        fuel -= 1;
        match items[pc] {
            Decoded::Mov {
                wide,
                dst,
                src,
                sign_extend: None,
            } => {
                reg[dst.as_usize()] = mask(src_val(src, &reg), wide);
                pc += 1;
            }
            Decoded::Neg { wide, dst } => {
                let v = (reg[dst.as_usize()] as i64).wrapping_neg() as u64;
                reg[dst.as_usize()] = mask(v, wide);
                pc += 1;
            }
            Decoded::Alu { wide, op, dst, src } => {
                let a = reg[dst.as_usize()];
                let b = src_val(src, &reg);
                let s = (if wide { b & 63 } else { b & 31 }) as u32;
                let v = match op {
                    AluOp::Add => a.wrapping_add(b),
                    AluOp::Sub => a.wrapping_sub(b),
                    AluOp::Mul => a.wrapping_mul(b),
                    AluOp::Or => a | b,
                    AluOp::And => a & b,
                    AluOp::Xor => a ^ b,
                    AluOp::Lsh => {
                        if wide {
                            a.wrapping_shl(s)
                        } else {
                            u64::from((a as u32).wrapping_shl(s))
                        }
                    }
                    AluOp::Rsh => {
                        if wide {
                            a.wrapping_shr(s)
                        } else {
                            u64::from((a as u32).wrapping_shr(s))
                        }
                    }
                    AluOp::Arsh => {
                        if wide {
                            (a as i64).wrapping_shr(s) as u64
                        } else {
                            u64::from((a as u32 as i32).wrapping_shr(s) as u32)
                        }
                    }
                };
                reg[dst.as_usize()] = mask(v, wide);
                pc += 1;
            }
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst,
                src,
                off,
            } => {
                let addr = reg[src.as_usize()].wrapping_add(off as i64 as u64);
                match mem.load64(addr) {
                    Some(v) => reg[dst.as_usize()] = v,
                    None => return Run::BadAccess,
                }
                pc += 1;
            }
            Decoded::Store {
                size: Size::Dw,
                dst,
                off,
                src,
            } => {
                let addr = reg[dst.as_usize()].wrapping_add(off as i64 as u64);
                let v = src_val(src, &reg);
                if mem.store64(addr, v).is_none() {
                    return Run::BadAccess;
                }
                pc += 1;
            }
            Decoded::Jump { off } => {
                let t = pc as i64 + 1 + i64::from(off);
                if t < 0 || t as usize > items.len() {
                    return Run::BadTarget;
                }
                pc = t as usize;
            }
            Decoded::JumpCond {
                wide,
                op,
                dst,
                src,
                off,
            } => {
                let a = reg[dst.as_usize()];
                let b = src_val(src, &reg);
                let taken = if wide {
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
                };
                if taken {
                    let t = pc as i64 + 1 + i64::from(off);
                    if t < 0 || t as usize > items.len() {
                        return Run::BadTarget;
                    }
                    pc = t as usize;
                } else {
                    pc += 1;
                }
            }
            Decoded::Exit => return Run::Returned(reg[0]),
            other => panic!("the reference evaluator does not model {other:?}"),
        }
    }
}

/// Registers AAPCS64 requires a callee to preserve, seeded with sentinels so
/// the prologue/epilogue pair can be checked by *executing* it.
const CALLEE_SAVED: [u8; 11] = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29];

/// An aarch64 machine, big enough for exactly the forms the emitter produces.
#[derive(Debug)]
struct Cpu {
    x: [u64; 31],
    sp: u64,
    n: bool,
    z: bool,
    c: bool,
    v: bool,
    mem: Mem,
}

impl Cpu {
    fn new(fuel: u64, mem: Mem) -> Self {
        let mut c = Self {
            x: [0; 31],
            sp: SP_INIT,
            n: false,
            z: false,
            c: false,
            v: false,
            mem,
        };
        // The ABI: (frame_top, ctx_ptr, fuel) in x0, x1, x2.
        c.x[0] = FRAME_TOP;
        c.x[1] = CTX_ADDR;
        c.x[2] = fuel;
        for r in CALLEE_SAVED {
            c.x[r as usize] = 0xC0DE_0000 | u64::from(r);
        }
        c
    }
    fn read(&self, r: u32, wide: bool) -> u64 {
        let v = if r == 31 { 0 } else { self.x[r as usize] };
        if wide {
            v
        } else {
            v & 0xffff_ffff
        }
    }
    fn write(&mut self, r: u32, wide: bool, v: u64) {
        if r == 31 {
            return;
        }
        // A `W`-register write zero-extends into the `X` register.
        self.x[r as usize] = if wide { v } else { v & 0xffff_ffff };
    }
    /// `Rn == 31` means `sp` for the memory forms and `xzr` for everything
    /// else — a distinction the encoding does not carry, so it comes from the
    /// instruction rather than from the field.
    fn mem_base(&self, r: u32) -> u64 {
        if r == 31 {
            self.sp
        } else {
            self.x[r as usize]
        }
    }
    fn set_sub_flags(&mut self, a: u64, b: u64, wide: bool) -> u64 {
        if wide {
            let (res, borrow) = a.overflowing_sub(b);
            self.c = !borrow;
            self.v = (a as i64).overflowing_sub(b as i64).1;
            self.n = (res as i64) < 0;
            self.z = res == 0;
            res
        } else {
            let (x, y) = (a as u32, b as u32);
            let (res, borrow) = x.overflowing_sub(y);
            self.c = !borrow;
            self.v = (x as i32).overflowing_sub(y as i32).1;
            self.n = (res as i32) < 0;
            self.z = res == 0;
            u64::from(res)
        }
    }
    fn set_logic_flags(&mut self, res: u64, wide: bool) {
        self.n = if wide {
            (res as i64) < 0
        } else {
            (res as u32 as i32) < 0
        };
        self.z = if wide { res == 0 } else { res as u32 == 0 };
        self.c = false;
        self.v = false;
    }
    fn cond(&self, cc: u32) -> bool {
        match cc {
            0 => self.z,
            1 => !self.z,
            2 => self.c,
            3 => !self.c,
            4 => self.n,
            5 => !self.n,
            6 => self.v,
            7 => !self.v,
            8 => self.c && !self.z,
            9 => !self.c || self.z,
            10 => self.n == self.v,
            11 => self.n != self.v,
            12 => !self.z && self.n == self.v,
            13 => self.z || self.n != self.v,
            _ => true,
        }
    }
}

/// Sign-extend the low `bits` of `v`.
fn sext(v: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((u64::from(v) << shift) as i64) >> shift
}

/// Execute an emitted image, returning the machine state and the `(x0, x1)`
/// pair AAPCS64 defines as the 128-bit result — `(value, exhausted)`.
fn a64_execute(code: &[u8], fuel: u64, mem: Mem) -> Result<(Cpu, u64, u64), Run> {
    let words = a64_words(code);
    let mut cpu = Cpu::new(fuel, mem);
    let mut pc = 0usize;
    // Generous but finite: a dropped fuel burn turns a BPF loop into a
    // non-terminating one, and "the emulator ran forever" has to be a test
    // failure rather than a hung suite.
    let mut steps = 0u64;
    loop {
        steps += 1;
        assert!(
            steps < 5_000_000,
            "emulated code did not terminate — is the fuel burn missing?"
        );
        let w = *words.get(pc).expect("pc left the image");
        let here = pc;
        pc += 1;
        let rd = w & 31;
        let rn = (w >> 5) & 31;
        let rm = (w >> 16) & 31;
        let wide = w >> 31 == 1;
        // The arms below are disjoint by construction; each mask pins every
        // field that distinguishes its encoding from a neighbour's.
        if w == 0xd65f_03c0 {
            // RET
            let (a, b) = (cpu.x[0], cpu.x[1]);
            return Ok((cpu, a, b));
        } else if w & 0xfc00_0000 == 0x1400_0000 {
            // B
            pc = (here as i64 + sext(w & 0x03ff_ffff, 26)) as usize;
        } else if w & 0xff00_0010 == 0x5400_0000 {
            // B.cond
            if cpu.cond(w & 0xf) {
                pc = (here as i64 + sext((w >> 5) & 0x7_ffff, 19)) as usize;
            }
        } else if w & 0x7f80_0000 == 0x5280_0000 {
            // MOVZ
            let hw = (w >> 21) & 3;
            let imm = u64::from((w >> 5) & 0xffff);
            cpu.write(rd, wide, imm << (16 * hw));
        } else if w & 0x7f80_0000 == 0x7280_0000 {
            // MOVK
            let hw = (w >> 21) & 3;
            let imm = u64::from((w >> 5) & 0xffff);
            let cur = cpu.read(rd, wide);
            let keep = !(0xffff_u64 << (16 * hw));
            cpu.write(rd, wide, (cur & keep) | (imm << (16 * hw)));
        } else if w & 0x7f80_0000 == 0x7100_0000 {
            // SUBS (immediate)
            let sh = (w >> 22) & 1;
            let imm = u64::from((w >> 10) & 0xfff) << (12 * sh);
            let a = cpu.read(rn, wide);
            let res = cpu.set_sub_flags(a, imm, wide);
            cpu.write(rd, wide, res);
        } else if w & 0x7fe0_8000 == 0x1b00_0000 {
            // MADD Rd, Rn, Rm, Ra
            let ra = (w >> 10) & 31;
            let v = cpu
                .read(rn, wide)
                .wrapping_mul(cpu.read(rm, wide))
                .wrapping_add(cpu.read(ra, wide));
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_f000 == 0x1ac0_2000 {
            // LSLV / LSRV / ASRV
            let a = cpu.read(rn, wide);
            let s = (cpu.read(rm, wide) & if wide { 63 } else { 31 }) as u32;
            let v = match (w >> 10) & 0x3f {
                0x08 => {
                    if wide {
                        a << s
                    } else {
                        u64::from((a as u32) << s)
                    }
                }
                0x09 => {
                    if wide {
                        a >> s
                    } else {
                        u64::from((a as u32) >> s)
                    }
                }
                0x0a => {
                    if wide {
                        ((a as i64) >> s) as u64
                    } else {
                        u64::from(((a as u32 as i32) >> s) as u32)
                    }
                }
                other => panic!("unmodelled 2-source op {other:#x}: {w:08x}"),
            };
            cpu.write(rd, wide, v);
        } else if w & 0xffe0_0c00 == 0xf840_0000 {
            // LDUR, 64-bit
            let addr = cpu
                .mem_base(rn)
                .wrapping_add(sext((w >> 12) & 0x1ff, 9) as u64);
            match cpu.mem.load64(addr) {
                Some(v) => cpu.write(rd, true, v),
                None => return Err(Run::BadAccess),
            }
        } else if w & 0xffe0_0c00 == 0xf800_0000 {
            // STUR, 64-bit
            let addr = cpu
                .mem_base(rn)
                .wrapping_add(sext((w >> 12) & 0x1ff, 9) as u64);
            let v = cpu.read(rd, true);
            if cpu.mem.store64(addr, v).is_none() {
                return Err(Run::BadAccess);
            }
        } else if matches!(
            w & 0xffc0_0000,
            0xa880_0000 | 0xa8c0_0000 | 0xa900_0000 | 0xa940_0000 | 0xa980_0000 | 0xa9c0_0000
        ) {
            // STP/LDP, signed-offset / pre-indexed / post-indexed.
            let imm = sext((w >> 15) & 0x7f, 7) * 8;
            let rt2 = (w >> 10) & 31;
            let load = w & 0x0040_0000 != 0;
            let pre = matches!(w & 0xffc0_0000, 0xa980_0000 | 0xa9c0_0000);
            let post = matches!(w & 0xffc0_0000, 0xa880_0000 | 0xa8c0_0000);
            assert_eq!(rn, 31, "only sp-based pairs are emitted: {w:08x}");
            if pre {
                cpu.sp = cpu.sp.wrapping_add(imm as u64);
            }
            let addr = cpu
                .sp
                .wrapping_add(if pre || post { 0 } else { imm as u64 });
            for (i, reg) in [rd, rt2].into_iter().enumerate() {
                let a = addr + 8 * i as u64;
                if load {
                    match cpu.mem.load64(a) {
                        Some(v) => cpu.write(reg, true, v),
                        None => return Err(Run::BadAccess),
                    }
                } else if cpu.mem.store64(a, cpu.read(reg, true)).is_none() {
                    return Err(Run::BadAccess);
                }
            }
            if post {
                cpu.sp = cpu.sp.wrapping_add(imm as u64);
            }
        } else if w & 0x7fe0_0000 == 0x0b00_0000 {
            // ADD (shifted register)
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide).wrapping_add(cpu.read(rm, wide));
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_0000 == 0x4b00_0000 {
            // SUB (shifted register) — `neg` when Rn is 31.
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide).wrapping_sub(cpu.read(rm, wide));
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_0000 == 0x6b00_0000 {
            // SUBS (shifted register) — `cmp` when Rd is 31.
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let (a, b) = (cpu.read(rn, wide), cpu.read(rm, wide));
            let res = cpu.set_sub_flags(a, b, wide);
            cpu.write(rd, wide, res);
        } else if w & 0x7fe0_0000 == 0x0a00_0000 {
            // AND (shifted register)
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide) & cpu.read(rm, wide);
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_0000 == 0x6a00_0000 {
            // ANDS (shifted register) — `tst` when Rd is 31.
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide) & cpu.read(rm, wide);
            cpu.set_logic_flags(v, wide);
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_0000 == 0x2a00_0000 {
            // ORR (shifted register) — `mov` when Rn is 31.
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide) | cpu.read(rm, wide);
            cpu.write(rd, wide, v);
        } else if w & 0x7fe0_0000 == 0x4a00_0000 {
            // EOR (shifted register)
            assert_eq!((w >> 10) & 0x3f, 0, "shifted operand: {w:08x}");
            let v = cpu.read(rn, wide) ^ cpu.read(rm, wide);
            cpu.write(rd, wide, v);
        } else {
            panic!("the emulator does not model {w:08x} at word {here}");
        }
    }
}

/// Compile, run both ways from the same starting memory, and require the
/// outcomes to match exactly — value *and* trap kind.
#[track_caller]
fn a64_diff_from(items: &[Decoded], fuel: u64, mem: &Mem) {
    let prog = verified(items);
    // Every supported instruction is one slot wide, so the reference's item
    // index and the emitter's slot index are the same number. Asserted rather
    // than assumed: `LD_IMM64` would break it, and it is `Unsupported`.
    assert_eq!(
        prog.insns.len(),
        items.len(),
        "the harness assumes one slot per instruction"
    );
    let compiled = aarch64::compile(&prog).expect("the harness only builds supported programs");

    let mut ref_mem = mem.clone();
    let reference = bpf_reference(items, fuel, &mut ref_mem);

    let native = match a64_execute(&compiled.code, fuel, mem.clone()) {
        Err(trap) => trap,
        Ok((cpu, x0, x1)) => {
            for r in CALLEE_SAVED {
                assert_eq!(
                    cpu.x[r as usize],
                    0xC0DE_0000 | u64::from(r),
                    "x{r} was not restored by the epilogue"
                );
            }
            assert_eq!(cpu.sp, SP_INIT, "the epilogue left sp unbalanced");
            if x1 == 0 {
                Run::Returned(x0)
            } else {
                Run::OutOfFuel
            }
        }
    };
    assert_eq!(
        native, reference,
        "native and reference disagree on {items:?} with fuel {fuel}"
    );
}

#[track_caller]
fn a64_diff(items: &[Decoded], fuel: u64) {
    a64_diff_from(items, fuel, &Mem::new());
}

/// Immediates chosen for sign-extension and shift-count boundaries.
const SWEEP_IMMS: [i32; 10] = [0, 1, -1, 2, -2, 7, 31, 32, 63, 64];
/// Wider boundaries, for the operands rather than the counts.
const SWEEP_VALS: [i32; 8] = [0, 1, -1, i32::MAX, i32::MIN, 0x7FFF, -0x8000, 0x5A5A_5A5A];

const ALL_ALU: [AluOp; 9] = [
    AluOp::Add,
    AluOp::Sub,
    AluOp::Mul,
    AluOp::Or,
    AluOp::And,
    AluOp::Lsh,
    AluOp::Rsh,
    AluOp::Xor,
    AluOp::Arsh,
];

const ALL_COND: [CondOp; 11] = [
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
];

#[test]
fn a64_callee_saved_registers_survive() {
    // R10 maps to `x25` and the fuel counter to `x24`, both callee-saved, and
    // the body overwrites both. The x86-64 backend once shipped a prologue
    // missing `push rbp` with its golden test passing, because the constant
    // pinned the bug. Executing the round trip is the check that cannot do
    // that: every callee-saved register and `sp` must come back unchanged.
    //
    // `a64_diff` asserts the same thing for every differential case below;
    // this test exists so the property has a name and can fail on its own.
    let items = [mov(0, 7), mov(6, 1), mov(9, 2), EXIT];
    let compiled = aarch64::compile(&verified(&items)).expect("compiles");
    let (cpu, x0, x1) = a64_execute(&compiled.code, 100, Mem::new()).expect("runs");
    assert_eq!((x0, x1), (7, 0));
    assert_eq!(cpu.sp, SP_INIT, "sp unbalanced");
    for r in CALLEE_SAVED {
        assert_eq!(
            cpu.x[r as usize],
            0xC0DE_0000 | u64::from(r),
            "x{r} clobbered"
        );
    }
}

#[test]
fn a64_the_context_pointer_arrives_in_r1_untouched() {
    // The prologue emits no move for the context pointer, so this is the test
    // that the claim in the module docs is true: `r0 = *(u64 *)(r1 + 8)` must
    // read the context the caller passed.
    let items = [
        Decoded::Load {
            size: Size::Dw,
            sign_extend: false,
            dst: r(0),
            src: r(1),
            off: 8,
        },
        EXIT,
    ];
    let mut mem = Mem::new();
    mem.store64(CTX_ADDR + 8, 0xFEED_FACE).expect("in bounds");
    a64_diff_from(&items, 64, &mem);
    let compiled = aarch64::compile(&verified(&items)).expect("compiles");
    let (_, x0, _) = a64_execute(&compiled.code, 64, mem).expect("runs");
    assert_eq!(x0, 0xFEED_FACE, "R1 must still be the context pointer");
}

#[test]
fn a64_r0_is_zero_on_entry_and_never_leaks_the_frame_pointer() {
    // `x0` arrives holding `frame_top`, a kernel address. A program that
    // reaches `exit` without writing R0 must return 0, not that pointer — which
    // is why the prologue zeroes it and x86-64 (where R0's host register is not
    // an argument register) does not need to.
    let compiled = aarch64::compile(&verified(&[EXIT])).expect("compiles");
    let (_, x0, x1) = a64_execute(&compiled.code, 64, Mem::new()).expect("runs");
    assert_eq!((x0, x1), (0, 0), "an unwritten R0 must not be frame_top");
}

#[test]
fn a64_diff_alu_sweep() {
    // Every operation × both widths × immediate and register source × boundary
    // operands, against the reference. This is where a wrong `sf`, a swapped
    // Rn/Rm, or a 32-bit result that failed to zero-extend shows up as a value.
    for &op in &ALL_ALU {
        for wide in [false, true] {
            for &a in &SWEEP_VALS {
                for &b in &SWEEP_IMMS {
                    a64_diff(
                        &[
                            mov(0, a),
                            Decoded::Alu {
                                wide,
                                op,
                                dst: r(0),
                                src: Source::Imm(b),
                            },
                            EXIT,
                        ],
                        64,
                    );
                    a64_diff(
                        &[
                            mov(0, a),
                            mov(2, b),
                            Decoded::Alu {
                                wide,
                                op,
                                dst: r(0),
                                src: Source::Reg(r(2)),
                            },
                            EXIT,
                        ],
                        64,
                    );
                }
            }
        }
    }
}

#[test]
fn a64_diff_neg_sweep() {
    for &a in &SWEEP_VALS {
        for wide in [false, true] {
            a64_diff(&[mov(0, a), Decoded::Neg { wide, dst: r(0) }, EXIT], 64);
        }
    }
}

#[test]
fn a64_diff_mov_sweep() {
    // Both widths, both sources. The 32-bit forms are the point: BPF's
    // `wide == false` move *zero-extends*, and emitting the 64-bit
    // materialisation instead would sign-extend a negative immediate. Mutation
    // testing found that only the golden encoding caught it, because every
    // other sweep here sets registers with a 64-bit move — a differential
    // suite is only as good as the shapes it actually builds.
    for &a in &SWEEP_VALS {
        for wide in [false, true] {
            a64_diff(
                &[
                    Decoded::Mov {
                        wide,
                        dst: r(0),
                        src: Source::Imm(a),
                        sign_extend: None,
                    },
                    EXIT,
                ],
                64,
            );
            a64_diff(
                &[
                    mov(2, a),
                    Decoded::Mov {
                        wide,
                        dst: r(0),
                        src: Source::Reg(r(2)),
                        sign_extend: None,
                    },
                    EXIT,
                ],
                64,
            );
        }
    }
}

#[test]
fn a64_diff_conditional_sweep() {
    // Both arms of every condition, so an inverted skip is caught by the
    // *value* and not only by the golden encoding: taking the wrong branch
    // returns 2 where 1 was right.
    for &op in &ALL_COND {
        for wide in [false, true] {
            for &a in &SWEEP_VALS {
                for &b in &SWEEP_VALS {
                    a64_diff(
                        &[
                            mov(0, a),
                            Decoded::JumpCond {
                                wide,
                                op,
                                dst: r(0),
                                src: Source::Imm(b),
                                off: 2,
                            },
                            mov(0, 1),
                            EXIT,
                            mov(0, 2),
                            EXIT,
                        ],
                        64,
                    );
                    a64_diff(
                        &[
                            mov(0, a),
                            mov(2, b),
                            Decoded::JumpCond {
                                wide,
                                op,
                                dst: r(0),
                                src: Source::Reg(r(2)),
                                off: 2,
                            },
                            mov(0, 1),
                            EXIT,
                            mov(0, 2),
                            EXIT,
                        ],
                        64,
                    );
                }
            }
        }
    }
}

#[test]
fn a64_diff_frame_memory() {
    // Store then load, at offsets on both sides of the `LDUR` range boundary,
    // with register and immediate sources. The far positive offsets go through
    // the context pointer, which sits far enough into the region to stay in
    // bounds.
    for off in [-8i16, -16, -256, -264, -512] {
        a64_diff(
            &[
                mov(0, 0x5A5A),
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(10),
                    off,
                    src: Source::Reg(r(0)),
                },
                mov(0, 0),
                Decoded::Load {
                    size: Size::Dw,
                    sign_extend: false,
                    dst: r(0),
                    src: r(10),
                    off,
                },
                EXIT,
            ],
            64,
        );
        a64_diff(
            &[
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(10),
                    off,
                    src: Source::Imm(-3),
                },
                Decoded::Load {
                    size: Size::Dw,
                    sign_extend: false,
                    dst: r(0),
                    src: r(10),
                    off,
                },
                EXIT,
            ],
            64,
        );
    }
    for off in [0i16, 8, 255, 256, 1000, 2048] {
        a64_diff(
            &[
                mov(0, 0x1234),
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(1),
                    off,
                    src: Source::Reg(r(0)),
                },
                mov(0, 0),
                Decoded::Load {
                    size: Size::Dw,
                    sign_extend: false,
                    dst: r(0),
                    src: r(1),
                    off,
                },
                EXIT,
            ],
            64,
        );
    }
}

#[test]
fn a64_diff_a_load_lands_at_the_address_it_names() {
    // Loads only, out of a memory where every doubleword holds its own address,
    // so the returned value *is* the address read. A store-then-load round trip
    // cannot see an address bug — both halves land at the same wrong place and
    // agree — which mutation testing demonstrated: widening the `LDUR` range by
    // one turned `+256` into `imm9 = -256` and only the golden encoding
    // noticed.
    let mem = Mem::patterned();
    for off in [
        -512i16, -264, -256, -16, -8, 0, 8, 255, 256, 264, 1000, 2048,
    ] {
        a64_diff_from(
            &[
                Decoded::Load {
                    size: Size::Dw,
                    sign_extend: false,
                    dst: r(0),
                    src: r(1),
                    off,
                },
                EXIT,
            ],
            64,
            &mem,
        );
        // And through the frame pointer, whose base is a different register.
        if off <= 0 {
            a64_diff_from(
                &[
                    Decoded::Load {
                        size: Size::Dw,
                        sign_extend: false,
                        dst: r(0),
                        src: r(10),
                        off,
                    },
                    EXIT,
                ],
                64,
                &mem,
            );
        }
    }
}

#[test]
fn a64_diff_a_store_lands_at_the_address_it_names() {
    // The mirror image: store to one offset, then read back a *neighbouring*
    // doubleword out of the patterned memory. If the store went somewhere else
    // it overwrote the wrong slot, and the read-back sees it.
    let mem = Mem::patterned();
    for off in [-512i16, -264, -256, -16, -8] {
        for probe in [off, off + 8, off - 8] {
            a64_diff_from(
                &[
                    mov(0, 0x7777),
                    Decoded::Store {
                        size: Size::Dw,
                        dst: r(10),
                        off,
                        src: Source::Reg(r(0)),
                    },
                    Decoded::Load {
                        size: Size::Dw,
                        sign_extend: false,
                        dst: r(0),
                        src: r(10),
                        off: probe,
                    },
                    EXIT,
                ],
                64,
                &mem,
            );
        }
    }
}

/// `r0 = 0; r2 = 8;  L: r0 += 3; r2 -= 1; if r2 != 0 goto L;  exit`
///
/// Retires 2 + 8×3 + 1 = 27 instructions and returns 24. Three blocks, charged
/// 2 + 3×8 + 1 — the same total, which is the whole point.
fn bounded_loop() -> [Decoded; 6] {
    [
        mov(0, 0),
        mov(2, 8),
        Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(0),
            src: Source::Imm(3),
        },
        Decoded::Alu {
            wide: true,
            op: AluOp::Sub,
            dst: r(2),
            src: Source::Imm(1),
        },
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Ne,
            dst: r(2),
            src: Source::Imm(0),
            off: -3,
        },
        EXIT,
    ]
}

#[test]
fn a64_diff_fuel_boundary_is_identical() {
    // The strongest fuel test there is. The per-block charge and the
    // interpreter's per-instruction charge must agree not merely on generous
    // tanks but on the *exact* value where the verdict flips — a program that
    // completes JITed and exhausts fuel interpreted is a program whose answer
    // depends on which path it happened to take.
    let straight = [mov(0, 0), mov(2, 1), mov(3, 2), mov(4, 3), EXIT];
    // r0 = 0; L: r0 += 1; goto L — never returns, whatever the tank.
    let unbounded = [
        mov(0, 0),
        Decoded::Alu {
            wide: true,
            op: AluOp::Add,
            dst: r(0),
            src: Source::Imm(1),
        },
        Decoded::Jump { off: -2 },
    ];
    for fuel in 0..64u64 {
        a64_diff(&straight, fuel);
        a64_diff(&bounded_loop(), fuel);
        a64_diff(&unbounded, fuel);
    }
    // And the boundary is where the instruction count says, not merely the same
    // on both sides — otherwise "both always run out" would satisfy the sweep.
    let mut mem = Mem::new();
    assert_eq!(bpf_reference(&straight, 4, &mut mem), Run::OutOfFuel);
    assert_eq!(bpf_reference(&straight, 5, &mut mem), Run::Returned(0));
    assert_eq!(bpf_reference(&bounded_loop(), 26, &mut mem), Run::OutOfFuel);
    assert_eq!(
        bpf_reference(&bounded_loop(), 27, &mut mem),
        Run::Returned(24)
    );
}

#[test]
fn a64_diff_a_bounded_loop_returns_the_right_value() {
    // The other half of the fuel story: fuel must not fire on a loop that
    // legitimately finishes. Without this, "everything runs out of fuel" would
    // satisfy the boundary test above.
    a64_diff(&bounded_loop(), 1024);
    let compiled = aarch64::compile(&verified(&bounded_loop())).expect("compiles");
    let (_, x0, x1) = a64_execute(&compiled.code, 1024, Mem::new()).expect("runs");
    assert_eq!(
        (x0, x1),
        (24, 0),
        "the native loop must return 24 with fuel to spare"
    );
}

#[test]
fn a64_diff_multiple_exits_share_one_epilogue() {
    // Two `exit`s, one epilogue, and both paths must restore and report
    // identically. A duplicated epilogue would still work; a branch to the
    // *wrong* one would set the exhaustion flag on a clean return, which the
    // trap-kind comparison catches and a value comparison alone would not.
    for a in [0i32, 1] {
        a64_diff(
            &[
                mov(0, a),
                Decoded::JumpCond {
                    wide: true,
                    op: CondOp::Eq,
                    dst: r(0),
                    src: Source::Imm(0),
                    off: 2,
                },
                mov(0, 10),
                EXIT,
                mov(0, 20),
                EXIT,
            ],
            64,
        );
    }
}

// ── kfunc calls ─────────────────────────────────────────────────────

/// A shim address with a bit set in every 16-bit lane, so a `MOVZ`/`MOVK`
/// sequence that dropped or misplaced a lane cannot look right by accident.
const A64_SHIM: usize = 0xDEAD_BEEF_1234_5678;

/// Compile with a resolved call table and return the body words.
#[track_caller]
fn a64_call_body(items: &[Decoded], sites: &[(u32, i32, usize)], want: &[u32]) {
    let c = aarch64::compile(&verified_calling(items, sites)).expect("should compile");
    let w = a64_words(&c.code);
    let start = A64_PROLOGUE.len() + 2; // the first block's `subs` + `b.lo`
    let end = w
        .windows(A64_EPILOGUE.len())
        .position(|x| x == A64_EPILOGUE)
        .expect("the normal epilogue must appear after the body");
    assert_eq!(
        &w[start..end],
        want,
        "\n got {:08x?}\nwant {want:08x?}",
        &w[start..end]
    );
}

#[test]
fn a64_golden_kfunc_call_sequence() {
    // AAPCS64 takes arguments in x0..x4 and BPF supplies them in x1..x5, so
    // every one moves and the map is off by exactly one register. The moves go
    // *forward*: each source is read before anything writes it, and `x0`'s old
    // value is R0, which a call clobbers by definition. Emitting them in
    // reverse smears R5 across all five argument registers — code that
    // assembles, runs, and passes garbage.
    a64_call_body(
        &[kcall(7), EXIT],
        &[(0, 7, A64_SHIM)],
        &[
            0xaa01_03e0, // mov x0, x1
            0xaa02_03e1, // mov x1, x2
            0xaa03_03e2, // mov x2, x3
            0xaa04_03e3, // mov x3, x4
            0xaa05_03e4, // mov x4, x5
            0xd28a_cf10, // mov  x16, #0x5678
            0xf2a2_4690, // movk x16, #0x1234, lsl #16
            0xf2d7_ddf0, // movk x16, #0xbeef, lsl #32
            0xf2fb_d5b0, // movk x16, #0xdead, lsl #48
            0xd63f_0200, // blr  x16
            0x1400_0001, // b -> epilogue
        ],
    );
}

/// Decode the pre-indexed `STP`'s byte displacement — the frame the prologue
/// claims. Signed 7-bit field, scaled by 8.
fn a64_stp_pre_bytes(w: u32) -> i32 {
    let imm7 = ((w >> 15) & 0x7F) as i32;
    let signed = if imm7 >= 64 { imm7 - 128 } else { imm7 };
    signed * 8
}

/// Decode an unscaled `LDUR`/`STUR` displacement. Signed 9-bit field.
fn a64_ldst_ur_bytes(w: u32) -> i32 {
    let imm9 = ((w >> 12) & 0x1FF) as i32;
    if imm9 >= 256 {
        imm9 - 512
    } else {
        imm9
    }
}

#[test]
fn a64_the_prologue_saves_x30_because_blr_clobbers_it() {
    // The one thing emitting a call cost this backend that x86-64 did not need.
    // `BLR` writes `x30`, so without this save the first kfunc call would
    // overwrite the address the epilogue's `RET` branches to — and the program
    // would return into the middle of itself.
    //
    // Read out of the *emitted image* rather than out of [`A64_PROLOGUE`], and
    // located by searching for the register rather than by index: a golden
    // constant pins whatever the emitter does, so a test comparing only against
    // one would agree with an emitter that had stopped saving `x30`, provided
    // someone updated the constant to match.
    let c = aarch64::compile(&verified(&[mov(0, 42), EXIT])).expect("compiles");
    let w = a64_words(&c.code);
    let x30_ur = |load: bool| {
        let base = if load { 0xF840_0000u32 } else { 0xF800_0000 };
        w.iter()
            .copied()
            .filter(move |&x| {
                (x & 0xFFE0_0000) == base && (x & 0x1F) == 30 && ((x >> 5) & 0x1F) == 31
            })
            .map(a64_ldst_ur_bytes)
            .collect::<Vec<i32>>()
    };
    let saves = x30_ur(false);
    let loads = x30_ur(true);
    assert_eq!(
        saves.len(),
        1,
        "expected exactly one x30 save, got {saves:?}"
    );
    assert!(!loads.is_empty(), "no epilogue reloads x30");
    assert!(
        loads.iter().all(|&o| o == saves[0]),
        "x30 saved at {saves:?} and reloaded from {loads:?}"
    );
}

#[test]
fn a64_the_claimed_frame_is_sixteen_byte_aligned_and_holds_every_saved_slot() {
    // AAPCS64 requires `sp` 16-aligned at *every* instruction boundary, not
    // merely at a call, and the architecture can be configured to fault on a
    // misaligned `sp` outright — so this is stricter than SysV's rule and
    // cheaper to get wrong, since the frame grew by a register that does not
    // pair with anything.
    let c = aarch64::compile(&verified(&[mov(0, 42), EXIT])).expect("compiles");
    let w = a64_words(&c.code);
    let frame = -a64_stp_pre_bytes(w[0]);
    assert_eq!(frame % 16, 0, "frame of {frame} bytes is not 16-aligned");
    // Every byte the prologue writes has to be inside it. The deepest is the
    // `x30` slot, which is the one with no `STP` partner to bound it.
    let x30_off = w
        .iter()
        .copied()
        .find(|&x| (x & 0xFFE0_0000) == 0xF800_0000 && (x & 0x1F) == 30)
        .map(a64_ldst_ur_bytes)
        .expect("the prologue must store x30");
    assert!(
        x30_off + 8 <= frame,
        "x30 is stored at {x30_off}, past the {frame}-byte frame"
    );
}

#[test]
fn a64_a_call_the_verifier_never_reached_is_refused_rather_than_guessed() {
    let prog = verified(&[kcall(7), EXIT]);
    assert!(prog.kfunc_calls.is_empty(), "premise: no table");
    assert!(matches!(
        aarch64::compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a64_a_call_site_that_names_a_different_kfunc_is_refused() {
    let prog = verified_calling(&[kcall(7), EXIT], &[(0, 9, A64_SHIM)]);
    assert!(matches!(
        aarch64::compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a64_a_sleepable_kfuncs_shim_is_never_entered_from_native_code() {
    let mut prog = verified_calling(&[kcall(7), EXIT], &[(0, 7, A64_SHIM)]);
    prog.kfunc_calls[0].context = Context::Sleepable;
    assert!(matches!(
        aarch64::compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a64_a_subprogram_call_is_still_unsupported() {
    let prog = verified(&[
        Decoded::Call(narf_bpf_isa::CallTarget::Subprog(1)),
        mov(0, 0),
        EXIT,
    ]);
    assert!(matches!(
        aarch64::compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}
