//! Host tests. Run with `cargo test -p narf-bpf-isa` or `cargo xtask host-test`.
//!
//! Three tiers:
//!   1. Golden encodings — hand-checked against `include/uapi/linux/bpf.h`, so
//!      a transcription error in `opcode.rs` fails here rather than silently
//!      mis-JITing.
//!   2. `decode ∘ encode == id` over an exhaustive enumeration of every
//!      instruction shape crossed with interesting operands.
//!   3. Rejection — every encoding NARF deliberately does not implement, plus
//!      every malformed one, must produce the *specific* `DecodeError` rather
//!      than being silently accepted.
//!
//! Tier 3 is the one that matters most: a decoder that accepts garbage hands
//! the verifier something it was never designed to reason about.

use crate::encode::encode;
use crate::insn::{decode, CallTarget, DecodeError, Decoded, Imm64, Insn};
use crate::opcode::*;

fn r(n: u8) -> Reg {
    Reg::new(n).expect("test uses a valid register")
}

/// Decode a single-slot instruction built from raw fields.
fn dec1(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Result<Decoded, DecodeError> {
    let prog = [Insn {
        code,
        regs: Insn::pack_regs(dst, src),
        off,
        imm,
    }];
    decode(&prog, 0).map(|(d, n)| {
        assert_eq!(n, 1, "expected a one-slot instruction");
        d
    })
}

// ─── Tier 1: golden encodings ───────────────────────────────────────

#[test]
fn golden_opcode_bytes() {
    // Spot-check the exact bytes for instructions whose encoding is easy to
    // get subtly wrong. Values cross-checked against bpf_common.h / bpf.h.
    let cases: &[(Decoded, u8)] = &[
        // ALU64 | ADD | X = 0x07 | 0x00 | 0x08 = 0x0f
        (
            Decoded::Alu {
                wide: true,
                op: AluOp::Add,
                dst: r(1),
                src: Source::Reg(r(2)),
            },
            0x0f,
        ),
        // ALU | MOV | K = 0x04 | 0xb0 | 0x00 = 0xb4
        (
            Decoded::Mov {
                wide: false,
                dst: r(0),
                src: Source::Imm(7),
                sign_extend: None,
            },
            0xb4,
        ),
        // LDX | MEM | DW = 0x01 | 0x60 | 0x18 = 0x79
        (
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(1),
                src: r(10),
                off: -8,
            },
            0x79,
        ),
        // LDX | MEMSX | W = 0x01 | 0x80 | 0x00 = 0x81
        (
            Decoded::Load {
                size: Size::W,
                sign_extend: true,
                dst: r(1),
                src: r(2),
                off: 0,
            },
            0x81,
        ),
        // STX | ATOMIC | DW = 0x03 | 0xc0 | 0x18 = 0xdb
        (
            Decoded::Atomic {
                size: Size::Dw,
                op: AtomicOp::Add { fetch: false },
                dst: r(1),
                src: r(2),
                off: 0,
            },
            0xdb,
        ),
        // JMP | EXIT = 0x05 | 0x90 = 0x95
        (Decoded::Exit, 0x95),
        // JMP | CALL = 0x05 | 0x80 = 0x85
        (Decoded::Call(CallTarget::Kfunc(3)), 0x85),
        // LD | IMM | DW = 0x00 | 0x00 | 0x18 = 0x18
        (
            Decoded::LoadImm64 {
                dst: r(1),
                value: Imm64::Value(0),
            },
            0x18,
        ),
        // JMP32 | JEQ | K = 0x06 | 0x10 | 0x00 = 0x16
        (
            Decoded::JumpCond {
                wide: false,
                op: CondOp::Eq,
                dst: r(1),
                src: Source::Imm(0),
                off: 1,
            },
            0x16,
        ),
    ];

    for (d, want) in cases {
        let got = encode(*d).slots()[0].code;
        assert_eq!(got, *want, "wrong opcode byte for {d}: {got:#04x}");
    }
}

#[test]
fn golden_register_nibble_order() {
    // C's `dst_reg:4; src_reg:4` puts dst in the LOW nibble on little-endian.
    // Getting this backwards would swap every operand in the kernel.
    let e = encode(Decoded::Alu {
        wide: true,
        op: AluOp::Add,
        dst: r(1),
        src: Source::Reg(r(2)),
    });
    assert_eq!(e.slots()[0].regs, 0x21, "dst must be the low nibble");
}

#[test]
fn golden_atomic_imm_values() {
    // The wide ones exceed 8 bits, which is exactly why they live in `imm`.
    assert_eq!(AtomicOp::Xchg.to_imm(), 0xe1);
    assert_eq!(AtomicOp::Cmpxchg.to_imm(), 0xf1);
    assert_eq!(AtomicOp::LoadAcquire.to_imm(), 0x100);
    assert_eq!(AtomicOp::StoreRelease.to_imm(), 0x110);
    assert_eq!(AtomicOp::Add { fetch: true }.to_imm(), 0x01);
    assert_eq!(AtomicOp::Add { fetch: false }.to_imm(), 0x00);
}

// ─── Tier 2: round-trip ─────────────────────────────────────────────

/// Every instruction shape crossed with interesting operands. Not random:
/// an explicit enumeration is reproducible and covers the boundary values a
/// random sweep would mostly miss.
fn all_shapes() -> Vec<Decoded> {
    let mut out = Vec::new();
    let regs = [r(0), r(1), r(9), r(10)];
    let imms = [0i32, 1, -1, i32::MAX, i32::MIN];
    let offs = [0i16, 1, -1, i16::MAX, i16::MIN];
    let sizes = [Size::B, Size::H, Size::W, Size::Dw];

    for &wide in &[false, true] {
        for &dst in &regs {
            for &op in &[
                AluOp::Add,
                AluOp::Sub,
                AluOp::Mul,
                AluOp::Or,
                AluOp::And,
                AluOp::Lsh,
                AluOp::Rsh,
                AluOp::Xor,
                AluOp::Arsh,
            ] {
                out.push(Decoded::Alu {
                    wide,
                    op,
                    dst,
                    src: Source::Reg(r(3)),
                });
                for &i in &imms {
                    out.push(Decoded::Alu {
                        wide,
                        op,
                        dst,
                        src: Source::Imm(i),
                    });
                }
            }
            out.push(Decoded::Neg { wide, dst });
            for &se in &[None, Some(8u8), Some(16), Some(32)] {
                out.push(Decoded::Mov {
                    wide,
                    dst,
                    src: Source::Reg(r(4)),
                    sign_extend: se,
                });
            }
            out.push(Decoded::Mov {
                wide,
                dst,
                src: Source::Imm(-5),
                sign_extend: None,
            });
            for &signed in &[false, true] {
                out.push(Decoded::Div {
                    wide,
                    signed,
                    dst,
                    src: Source::Reg(r(2)),
                });
                out.push(Decoded::Mod {
                    wide,
                    signed,
                    dst,
                    src: Source::Imm(3),
                });
            }
            for &op in &[
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
                for &off in &offs {
                    out.push(Decoded::JumpCond {
                        wide,
                        op,
                        dst,
                        src: Source::Reg(r(5)),
                        off,
                    });
                    out.push(Decoded::JumpCond {
                        wide,
                        op,
                        dst,
                        src: Source::Imm(-7),
                        off,
                    });
                }
            }
        }
    }

    for &dst in &regs {
        for &width in &[16u8, 32, 64] {
            out.push(Decoded::End {
                dst,
                order: ByteOrder::Little,
                width,
            });
            out.push(Decoded::End {
                dst,
                order: ByteOrder::Big,
                width,
            });
            out.push(Decoded::End {
                dst,
                order: ByteOrder::Swap,
                width,
            });
        }
        out.push(Decoded::AddrSpaceCast {
            dst,
            src: r(6),
            dst_as: 0,
            src_as: 1,
        });
        out.push(Decoded::AddrSpaceCast {
            dst,
            src: r(6),
            dst_as: 1,
            src_as: 0,
        });

        for &size in &sizes {
            for &off in &offs {
                // MEMSX is not defined at doubleword width.
                if size != Size::Dw {
                    out.push(Decoded::Load {
                        size,
                        sign_extend: true,
                        dst,
                        src: r(7),
                        off,
                    });
                }
                out.push(Decoded::Load {
                    size,
                    sign_extend: false,
                    dst,
                    src: r(7),
                    off,
                });
                out.push(Decoded::Store {
                    size,
                    dst,
                    off,
                    src: Source::Reg(r(8)),
                });
                out.push(Decoded::Store {
                    size,
                    dst,
                    off,
                    src: Source::Imm(42),
                });
            }
        }

        // Atomics exist only at word and doubleword width.
        for &size in &[Size::W, Size::Dw] {
            for &op in &[
                AtomicOp::Add { fetch: false },
                AtomicOp::Add { fetch: true },
                AtomicOp::Or { fetch: false },
                AtomicOp::Or { fetch: true },
                AtomicOp::And { fetch: false },
                AtomicOp::And { fetch: true },
                AtomicOp::Xor { fetch: false },
                AtomicOp::Xor { fetch: true },
                AtomicOp::Xchg,
                AtomicOp::Cmpxchg,
                AtomicOp::LoadAcquire,
                AtomicOp::StoreRelease,
            ] {
                out.push(Decoded::Atomic {
                    size,
                    op,
                    dst,
                    src: r(2),
                    off: -16,
                });
            }
        }

        for v in [
            Imm64::Value(0),
            Imm64::Value(u64::MAX),
            Imm64::Value(0x1234_5678_9abc_def0),
            Imm64::MapFd(3),
            Imm64::MapValue {
                fd: 3,
                value_offset: 16,
            },
            Imm64::BtfId(99),
            Imm64::SubprogAddr(12),
            Imm64::MapIdx(1),
            Imm64::MapIdxValue {
                idx: 1,
                value_offset: 8,
            },
        ] {
            out.push(Decoded::LoadImm64 { dst, value: v });
        }
    }

    for &off in &offs {
        out.push(Decoded::Jump {
            off: i32::from(off),
        });
        out.push(Decoded::MayGoto { off });
    }
    // Displacements past i16 must round-trip through the JMP32 `gotol` form.
    out.push(Decoded::Jump { off: 40_000 });
    out.push(Decoded::Jump { off: -40_000 });
    out.push(Decoded::Call(CallTarget::Subprog(5)));
    out.push(Decoded::Call(CallTarget::Subprog(-5)));
    out.push(Decoded::Call(CallTarget::Kfunc(1234)));
    out.push(Decoded::Exit);

    out
}

#[test]
fn decode_encode_round_trips() {
    let shapes = all_shapes();
    assert!(shapes.len() > 1000, "enumeration got unexpectedly small");
    for want in shapes {
        let e = encode(want);
        let (got, n) =
            decode(e.slots(), 0).unwrap_or_else(|err| panic!("failed to decode {want}: {err:?}"));
        assert_eq!(n, e.len(), "slot count mismatch for {want}");
        assert_eq!(got, want, "round-trip changed the instruction");
    }
}

#[test]
fn byte_round_trips() {
    for d in all_shapes() {
        for slot in encode(d).slots() {
            assert_eq!(Insn::from_bytes(slot.to_bytes()), *slot);
        }
    }
}

#[test]
fn every_decoded_shape_disassembles() {
    // Display must be total — a panic here would take out a trap handler.
    for d in all_shapes() {
        let s = format!("{d}");
        assert!(!s.is_empty(), "empty disassembly for {d:?}");
    }
}

#[test]
fn i16_min_offset_does_not_overflow_display() {
    // `- (-32768)` overflows i16; Offset negates through i32 to avoid it.
    let d = Decoded::Load {
        size: Size::W,
        sign_extend: false,
        dst: r(1),
        src: r(2),
        off: i16::MIN,
    };
    assert_eq!(format!("{d}"), "r1 = *(u32 *)(r2 - 32768)");
}

// ─── Tier 3: rejection ──────────────────────────────────────────────

#[test]
fn rejects_helper_calls() {
    // NARF has one call ABI. A helper call must be named as such, not
    // mistaken for a kfunc — see spec §3.
    assert_eq!(
        dec1(CLASS_JMP | JMP_CALL, 0, CALL_HELPER, 0, 12),
        Err(DecodeError::HelperCall(12))
    );
}

#[test]
fn rejects_legacy_packet_loads() {
    for mode in [MODE_ABS, MODE_IND] {
        assert_eq!(
            dec1(CLASS_LD | mode | SIZE_W, 0, 0, 0, 0),
            Err(DecodeError::LegacyPacketLoad)
        );
    }
}

#[test]
fn rejects_out_of_range_registers() {
    for bad in 11u8..=15 {
        assert_eq!(
            dec1(CLASS_ALU64 | ALU_ADD | SRC_K, bad, 0, 0, 1),
            Err(DecodeError::BadRegister(bad))
        );
        assert_eq!(
            dec1(CLASS_ALU64 | ALU_ADD | SRC_X, 0, bad, 0, 0),
            Err(DecodeError::BadRegister(bad))
        );
    }
}

#[test]
fn rejects_truncated_ld_imm64() {
    let prog = [Insn {
        code: CLASS_LD | MODE_IMM | SIZE_DW,
        regs: 1,
        off: 0,
        imm: 0,
    }];
    assert_eq!(decode(&prog, 0), Err(DecodeError::TruncatedImm64));
}

#[test]
fn rejects_malformed_ld_imm64_trailer() {
    // The trailing slot must be zero except for `imm`.
    for bad in [
        Insn {
            code: 1,
            regs: 0,
            off: 0,
            imm: 0,
        },
        Insn {
            code: 0,
            regs: 1,
            off: 0,
            imm: 0,
        },
        Insn {
            code: 0,
            regs: 0,
            off: 1,
            imm: 0,
        },
    ] {
        let prog = [
            Insn {
                code: CLASS_LD | MODE_IMM | SIZE_DW,
                regs: 1,
                off: 0,
                imm: 0,
            },
            bad,
        ];
        assert_eq!(decode(&prog, 0), Err(DecodeError::MalformedImm64));
    }
}

#[test]
fn rejects_pseudo_forms_with_stray_high_immediate() {
    // Only Value / MapValue / MapIdxValue give the trailing `imm` a meaning.
    for pseudo in [PSEUDO_MAP_FD, PSEUDO_BTF_ID, PSEUDO_FUNC, PSEUDO_MAP_IDX] {
        let prog = [
            Insn {
                code: CLASS_LD | MODE_IMM | SIZE_DW,
                regs: Insn::pack_regs(1, pseudo),
                off: 0,
                imm: 3,
            },
            Insn {
                code: 0,
                regs: 0,
                off: 0,
                imm: 0xbad,
            },
        ];
        assert_eq!(decode(&prog, 0), Err(DecodeError::MalformedImm64));
    }
}

#[test]
fn rejects_unassigned_pseudo_ld_imm64() {
    let prog = [
        Insn {
            code: CLASS_LD | MODE_IMM | SIZE_DW,
            regs: Insn::pack_regs(1, 7),
            off: 0,
            imm: 0,
        },
        Insn::default(),
    ];
    assert_eq!(decode(&prog, 0), Err(DecodeError::BadRegister(7)));
}

#[test]
fn rejects_memsx_at_doubleword() {
    assert_eq!(
        dec1(CLASS_LDX | MODE_MEMSX | SIZE_DW, 1, 2, 0, 0),
        Err(DecodeError::BadMode(MODE_MEMSX))
    );
}

#[test]
fn rejects_subword_atomics() {
    for size in [SIZE_B, SIZE_H] {
        assert_eq!(
            dec1(CLASS_STX | MODE_ATOMIC | size, 1, 2, 0, ATOMIC_ADD),
            Err(DecodeError::BadMode(size))
        );
    }
}

#[test]
fn rejects_unassigned_atomic_op() {
    assert_eq!(
        dec1(CLASS_STX | MODE_ATOMIC | SIZE_DW, 1, 2, 0, 0x77),
        Err(DecodeError::BadImm(0x77))
    );
}

#[test]
fn rejects_bad_movsx_width() {
    for off in [2i16, 7, 31, 33, 64] {
        assert_eq!(
            dec1(CLASS_ALU64 | ALU_MOV | SRC_X, 1, 2, off, 0),
            Err(DecodeError::BadOff(off))
        );
    }
}

#[test]
fn rejects_bad_endianness_width() {
    for imm in [0i32, 8, 128] {
        assert_eq!(
            dec1(CLASS_ALU | ALU_END | SRC_K, 1, 0, 0, imm),
            Err(DecodeError::BadImm(imm))
        );
    }
}

#[test]
fn rejects_neg_with_operand() {
    // NEG takes no source; a stray immediate or source bit is malformed.
    assert_eq!(
        dec1(CLASS_ALU64 | ALU_NEG | SRC_K, 1, 0, 0, 5),
        Err(DecodeError::BadOp(CLASS_ALU64 | ALU_NEG | SRC_K))
    );
    assert_eq!(
        dec1(CLASS_ALU64 | ALU_NEG | SRC_X, 1, 2, 0, 0),
        Err(DecodeError::BadOp(CLASS_ALU64 | ALU_NEG | SRC_X))
    );
}

#[test]
fn rejects_dirty_exit() {
    // EXIT must have every other field clear.
    assert_eq!(
        dec1(CLASS_JMP | JMP_EXIT, 1, 0, 0, 0),
        Err(DecodeError::BadOp(CLASS_JMP | JMP_EXIT))
    );
    assert_eq!(
        dec1(CLASS_JMP | JMP_EXIT, 0, 0, 0, 9),
        Err(DecodeError::BadOp(CLASS_JMP | JMP_EXIT))
    );
}

#[test]
fn rejects_ja_with_both_displacements() {
    // JMP|JA uses `off` and must leave `imm` clear; JMP32|JA is the reverse.
    assert_eq!(
        dec1(CLASS_JMP | JMP_JA, 0, 0, 4, 4),
        Err(DecodeError::BadImm(4))
    );
    assert_eq!(
        dec1(CLASS_JMP32 | JMP_JA, 0, 0, 4, 4),
        Err(DecodeError::BadOff(4))
    );
}

#[test]
fn rejects_unassigned_jcond() {
    assert_eq!(
        dec1(CLASS_JMP | JMP_JCOND, 0, 0, 1, 5),
        Err(DecodeError::BadImm(5))
    );
}

#[test]
fn rejects_call_and_exit_in_jmp32() {
    // CALL, EXIT, and JCOND exist only in the 64-bit jump class.
    for op in [JMP_CALL, JMP_EXIT, JMP_JCOND] {
        assert!(
            matches!(
                dec1(CLASS_JMP32 | op, 0, 0, 0, 0),
                Err(DecodeError::BadOp(_))
            ),
            "JMP32 op {op:#04x} should not decode"
        );
    }
}

#[test]
fn rejects_alu64_end_with_source_bit() {
    // ALU64|END|K is bswap; ALU64|END|X is unassigned.
    assert_eq!(
        dec1(CLASS_ALU64 | ALU_END | SRC_X, 1, 0, 0, 32),
        Err(DecodeError::BadOp(CLASS_ALU64 | ALU_END | SRC_X))
    );
}

#[test]
fn rejects_bad_store_mode() {
    assert_eq!(
        dec1(CLASS_ST | MODE_ATOMIC | SIZE_W, 1, 0, 0, 0),
        Err(DecodeError::BadMode(MODE_ATOMIC))
    );
}

/// No opcode byte may panic the decoder. A malformed program reaching the
/// verifier must produce an error, never a crash — this sweeps the entire
/// 8-bit opcode space against a fixed set of operand patterns.
#[test]
fn no_opcode_byte_panics() {
    for code in 0u8..=255 {
        for regs in [0x00u8, 0x21, 0xBB, 0xFF] {
            for off in [0i16, 1, -1] {
                for imm in [0i32, 1, -1, 0x100] {
                    let prog = [
                        Insn {
                            code,
                            regs,
                            off,
                            imm,
                        },
                        Insn::default(),
                    ];
                    // Only requirement: it returns.
                    let _ = decode(&prog, 0);
                }
            }
        }
    }
}

#[test]
fn slots_from_bytes_rejects_partial_slot() {
    assert!(crate::insn::slots_from_bytes(&[0u8; 7]).is_none());
    assert!(crate::insn::slots_from_bytes(&[0u8; 8]).is_some());
    assert!(crate::insn::slots_from_bytes(&[0u8; 16]).is_some());
}
