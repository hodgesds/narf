//! The encoded instruction word, and its structured decoding.
//!
//! An instruction is eight bytes:
//!
//! ```text
//!   0        1        2      3        4              7
//! ┌────────┬────┬────┬───────────────┬───────────────────┐
//! │  code  │dst │src │      off      │        imm        │
//! └────────┴────┴────┴───────────────┴───────────────────┘
//!    u8      u4   u4        i16                i32
//! ```
//!
//! `LD_IMM64` is the sole exception: it occupies two slots, the second
//! carrying the high 32 bits of the immediate in its `imm` field and zero
//! everywhere else.
//!
//! Note the nibble order. C's `__u8 dst_reg:4; __u8 src_reg:4;` places
//! `dst_reg` in the *low* nibble on every little-endian target, which is the
//! only layout Linux supports. [`Insn::dst_raw`] and [`Insn::src_raw`] encode
//! that directly rather than relying on bitfield layout.

use crate::opcode::*;

/// One encoded instruction slot.
///
/// Field-for-field identical to Linux's `struct bpf_insn`, so a program image
/// can be reinterpreted in place.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Insn {
    /// Opcode: class, operation, and mode/source bits.
    pub code: u8,
    /// Packed register pair — `dst` in the low nibble, `src` in the high.
    pub regs: u8,
    /// Signed 16-bit offset. Memory displacement, jump displacement, or an
    /// ALU variant selector (see [`OFF_SIGNED`], [`OFF_ADDR_SPACE_CAST`]).
    pub off: i16,
    /// Signed 32-bit immediate. Also carries the atomic operation, the
    /// helper/kfunc id, and the low half of a 64-bit immediate.
    pub imm: i32,
}

impl Insn {
    /// The destination register field, unvalidated.
    #[inline]
    #[must_use]
    pub const fn dst_raw(self) -> u8 {
        self.regs & 0x0F
    }

    /// The source register field, unvalidated.
    #[inline]
    #[must_use]
    pub const fn src_raw(self) -> u8 {
        self.regs >> 4
    }

    /// Build the packed register byte.
    #[inline]
    #[must_use]
    pub const fn pack_regs(dst: u8, src: u8) -> u8 {
        (dst & 0x0F) | (src << 4)
    }

    /// The instruction class.
    #[inline]
    #[must_use]
    pub const fn class(self) -> Class {
        Class::from_code(self.code)
    }

    /// Decode from eight little-endian bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(b: [u8; INSN_SIZE]) -> Self {
        Self {
            code: b[0],
            regs: b[1],
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Encode to eight little-endian bytes.
    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; INSN_SIZE] {
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code, self.regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }

    /// `true` if this is the first slot of a 16-byte `LD_IMM64`.
    #[inline]
    #[must_use]
    pub const fn is_wide_imm(self) -> bool {
        self.code == (CLASS_LD | MODE_IMM | SIZE_DW)
    }
}

/// Why an instruction could not be decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A register field named R11 or higher.
    BadRegister(u8),
    /// The opcode's operation nibble is not assigned in this class.
    BadOp(u8),
    /// The addressing mode is not valid for this class.
    BadMode(u8),
    /// The `off` field carried a value the opcode gives no meaning to.
    BadOff(i16),
    /// The `imm` field carried a value the opcode gives no meaning to.
    BadImm(i32),
    /// A `LD_IMM64` was truncated by the end of the program.
    TruncatedImm64,
    /// The trailing slot of a `LD_IMM64` had non-zero reserved fields.
    MalformedImm64,
    /// A helper call. NARF has no helper table; kfuncs replace it entirely.
    /// See `bpf/specification/spec.md` §3.
    HelperCall(i32),
    /// The legacy cBPF packet-load instructions, which NARF does not
    /// implement. `Documentation/bpf/bpf_design_QA.rst:227` calls them an
    /// "artifact of compatibility with classic BPF".
    LegacyPacketLoad,
}

/// What a `LD_IMM64` is actually loading.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Imm64 {
    /// A plain 64-bit constant.
    Value(u64),
    /// Address of the map identified by this file descriptor.
    MapFd(i32),
    /// Address of `value_offset` bytes into map `fd`'s first value.
    MapValue { fd: i32, value_offset: i32 },
    /// Address of the kernel variable with this type id.
    BtfId(i32),
    /// Address of the subprogram beginning at this instruction index.
    SubprogAddr(i32),
    /// Address of the map at this index in the loader's fd array.
    MapIdx(i32),
    /// Address of `value_offset` bytes into the value of the map at this
    /// index in the loader's fd array.
    MapIdxValue { idx: i32, value_offset: i32 },
}

/// The callee of a `CALL` instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CallTarget {
    /// Another subprogram in the same program, at a pc-relative offset
    /// counted in instruction slots from the instruction *after* the call.
    Subprog(i32),
    /// A kernel function, identified by its type id.
    Kfunc(i32),
}

/// A structured view of one instruction.
///
/// Faithful to the encoding — this is a decoding, not an IR. The verifier
/// builds the actual IR on top (see `bpf/specification/spec.md` §5), which is
/// where instruction indices stop being meaningful.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Binary arithmetic. `wide` distinguishes `ALU64` from `ALU`.
    Alu {
        wide: bool,
        op: AluOp,
        dst: Reg,
        src: Source,
    },
    /// Two's-complement negation. Takes no second operand.
    Neg { wide: bool, dst: Reg },
    /// Register or immediate move. `sign_extend` is `Some(bits)` for the
    /// `MOVSX` forms, where `off` selects 8, 16, or 32.
    Mov {
        wide: bool,
        dst: Reg,
        src: Source,
        sign_extend: Option<u8>,
    },
    /// Division. `signed` is the `off == 1` variant.
    Div {
        wide: bool,
        signed: bool,
        dst: Reg,
        src: Source,
    },
    /// Modulo. `signed` is the `off == 1` variant.
    Mod {
        wide: bool,
        signed: bool,
        dst: Reg,
        src: Source,
    },
    /// Byte-order conversion of `width` bits (16, 32, or 64).
    End {
        dst: Reg,
        order: ByteOrder,
        width: u8,
    },
    /// Address-space cast — `ALU64 | MOV | X` with `off == 1`.
    AddrSpaceCast {
        dst: Reg,
        src: Reg,
        dst_as: u16,
        src_as: u16,
    },
    /// `dst = *(size *)(src + off)`, sign-extending when `sign_extend`.
    Load {
        size: Size,
        sign_extend: bool,
        dst: Reg,
        src: Reg,
        off: i16,
    },
    /// `*(size *)(dst + off) = src`, where `src` may be an immediate (`ST`)
    /// or a register (`STX`).
    Store {
        size: Size,
        dst: Reg,
        off: i16,
        src: Source,
    },
    /// Atomic read-modify-write on `*(size *)(dst + off)`.
    Atomic {
        size: Size,
        op: AtomicOp,
        dst: Reg,
        src: Reg,
        off: i16,
    },
    /// The 16-byte wide immediate load.
    LoadImm64 { dst: Reg, value: Imm64 },
    /// Unconditional jump, displacement in instruction slots relative to the
    /// following instruction. `JMP | JA` uses `off`; `JMP32 | JA` (`gotol`)
    /// uses `imm`, which is how it reaches past ±32K.
    Jump { off: i32 },
    /// Conditional jump. `wide` distinguishes 64-bit `JMP` from 32-bit
    /// `JMP32` comparison.
    JumpCond {
        wide: bool,
        op: CondOp,
        dst: Reg,
        src: Source,
        off: i16,
    },
    /// `may_goto +off` — decrement a hidden counter, branch while it lasts.
    MayGoto { off: i16 },
    /// A call.
    Call(CallTarget),
    /// Return from the current subprogram, or from the program.
    Exit,
}

/// Decode the instruction at `index`.
///
/// Returns the decoded form and how many slots it consumed — two for
/// `LD_IMM64`, one for everything else.
///
/// # Errors
///
/// Returns [`DecodeError`] for any encoding NARF does not implement, which
/// deliberately includes helper calls and the legacy packet loads.
pub fn decode(prog: &[Insn], index: usize) -> Result<(Decoded, usize), DecodeError> {
    let insn = prog[index];
    let code = insn.code;

    let dst = Reg::new(insn.dst_raw()).ok_or(DecodeError::BadRegister(insn.dst_raw()))?;
    // The source field is only meaningful for some encodings, so validate it
    // lazily rather than rejecting instructions that legitimately leave it 0.
    let src_reg = || Reg::new(insn.src_raw()).ok_or(DecodeError::BadRegister(insn.src_raw()));
    let source = |i: Insn| -> Result<Source, DecodeError> {
        if (i.code & SRC_MASK) == SRC_X {
            Ok(Source::Reg(
                Reg::new(i.src_raw()).ok_or(DecodeError::BadRegister(i.src_raw()))?,
            ))
        } else {
            Ok(Source::Imm(i.imm))
        }
    };

    let class = Class::from_code(code);
    let decoded = match class {
        Class::Alu | Class::Alu64 => {
            let wide = class == Class::Alu64;
            match code & OP_MASK {
                ALU_ADD => Decoded::Alu {
                    wide,
                    op: AluOp::Add,
                    dst,
                    src: source(insn)?,
                },
                ALU_SUB => Decoded::Alu {
                    wide,
                    op: AluOp::Sub,
                    dst,
                    src: source(insn)?,
                },
                ALU_MUL => Decoded::Alu {
                    wide,
                    op: AluOp::Mul,
                    dst,
                    src: source(insn)?,
                },
                ALU_OR => Decoded::Alu {
                    wide,
                    op: AluOp::Or,
                    dst,
                    src: source(insn)?,
                },
                ALU_AND => Decoded::Alu {
                    wide,
                    op: AluOp::And,
                    dst,
                    src: source(insn)?,
                },
                ALU_LSH => Decoded::Alu {
                    wide,
                    op: AluOp::Lsh,
                    dst,
                    src: source(insn)?,
                },
                ALU_RSH => Decoded::Alu {
                    wide,
                    op: AluOp::Rsh,
                    dst,
                    src: source(insn)?,
                },
                ALU_XOR => Decoded::Alu {
                    wide,
                    op: AluOp::Xor,
                    dst,
                    src: source(insn)?,
                },
                ALU_ARSH => Decoded::Alu {
                    wide,
                    op: AluOp::Arsh,
                    dst,
                    src: source(insn)?,
                },
                ALU_NEG => {
                    // NEG takes no source operand; both fields must be clear.
                    if (code & SRC_MASK) != SRC_K || insn.imm != 0 || insn.off != 0 {
                        return Err(DecodeError::BadOp(code));
                    }
                    Decoded::Neg { wide, dst }
                }
                ALU_DIV | ALU_MOD => {
                    let signed = match insn.off {
                        0 => false,
                        OFF_SIGNED => true,
                        other => return Err(DecodeError::BadOff(other)),
                    };
                    let src = source(insn)?;
                    if (code & OP_MASK) == ALU_DIV {
                        Decoded::Div {
                            wide,
                            signed,
                            dst,
                            src,
                        }
                    } else {
                        Decoded::Mod {
                            wide,
                            signed,
                            dst,
                            src,
                        }
                    }
                }
                ALU_MOV => {
                    // Three encodings share MOV, separated by `off`:
                    //   off == 0          → plain move
                    //   off ∈ {8,16,32}   → sign-extending move
                    //   off == 1, ALU64|X → address-space cast
                    if wide && (code & SRC_MASK) == SRC_X && insn.off == OFF_ADDR_SPACE_CAST {
                        let imm = insn.imm as u32;
                        return Ok((
                            Decoded::AddrSpaceCast {
                                dst,
                                src: src_reg()?,
                                dst_as: (imm >> 16) as u16,
                                src_as: imm as u16,
                            },
                            1,
                        ));
                    }
                    let sign_extend = match insn.off {
                        0 => None,
                        8 | 16 => Some(insn.off as u8),
                        32 => Some(32),
                        other => return Err(DecodeError::BadOff(other)),
                    };
                    Decoded::Mov {
                        wide,
                        dst,
                        src: source(insn)?,
                        sign_extend,
                    }
                }
                ALU_END => {
                    let order = if wide {
                        // ALU64 | END | K is the unconditional byte swap.
                        // ALU64 | END | X is unassigned.
                        if (code & SRC_MASK) != SRC_K {
                            return Err(DecodeError::BadOp(code));
                        }
                        ByteOrder::Swap
                    } else if (code & SRC_MASK) == SRC_K {
                        ByteOrder::Little
                    } else {
                        ByteOrder::Big
                    };
                    let width = match insn.imm {
                        16 | 32 | 64 => insn.imm as u8,
                        other => return Err(DecodeError::BadImm(other)),
                    };
                    Decoded::End { dst, order, width }
                }
                other => return Err(DecodeError::BadOp(other)),
            }
        }

        Class::Jmp | Class::Jmp32 => {
            let wide = class == Class::Jmp;
            match code & OP_MASK {
                JMP_JA => {
                    // JMP|JA takes its displacement from `off`; JMP32|JA
                    // ("gotol") takes it from `imm`, reaching ±2G.
                    if wide {
                        if insn.imm != 0 {
                            return Err(DecodeError::BadImm(insn.imm));
                        }
                        Decoded::Jump {
                            off: i32::from(insn.off),
                        }
                    } else {
                        if insn.off != 0 {
                            return Err(DecodeError::BadOff(insn.off));
                        }
                        Decoded::Jump { off: insn.imm }
                    }
                }
                JMP_CALL if wide => match insn.src_raw() {
                    CALL_PSEUDO => Decoded::Call(CallTarget::Subprog(insn.imm)),
                    CALL_KFUNC => Decoded::Call(CallTarget::Kfunc(insn.imm)),
                    CALL_HELPER => return Err(DecodeError::HelperCall(insn.imm)),
                    other => return Err(DecodeError::BadRegister(other)),
                },
                JMP_EXIT if wide => {
                    if insn.regs != 0 || insn.off != 0 || insn.imm != 0 {
                        return Err(DecodeError::BadOp(code));
                    }
                    Decoded::Exit
                }
                JMP_JCOND if wide => match insn.imm {
                    JCOND_MAY_GOTO => Decoded::MayGoto { off: insn.off },
                    other => return Err(DecodeError::BadImm(other)),
                },
                op => {
                    let cond = match op {
                        JMP_JEQ => CondOp::Eq,
                        JMP_JNE => CondOp::Ne,
                        JMP_JGT => CondOp::Gt,
                        JMP_JGE => CondOp::Ge,
                        JMP_JLT => CondOp::Lt,
                        JMP_JLE => CondOp::Le,
                        JMP_JSGT => CondOp::Sgt,
                        JMP_JSGE => CondOp::Sge,
                        JMP_JSLT => CondOp::Slt,
                        JMP_JSLE => CondOp::Sle,
                        JMP_JSET => CondOp::Set,
                        other => return Err(DecodeError::BadOp(other)),
                    };
                    Decoded::JumpCond {
                        wide,
                        op: cond,
                        dst,
                        src: source(insn)?,
                        off: insn.off,
                    }
                }
            }
        }

        Class::Ldx => {
            let sign_extend = match code & MODE_MASK {
                MODE_MEM => false,
                MODE_MEMSX => true,
                other => return Err(DecodeError::BadMode(other)),
            };
            let size = Size::from_code(code);
            // MEMSX on a doubleword would sign-extend a full-width value,
            // which is a no-op and not an encoding LLVM emits.
            if sign_extend && size == Size::Dw {
                return Err(DecodeError::BadMode(MODE_MEMSX));
            }
            Decoded::Load {
                size,
                sign_extend,
                dst,
                src: src_reg()?,
                off: insn.off,
            }
        }

        Class::St => {
            if (code & MODE_MASK) != MODE_MEM {
                return Err(DecodeError::BadMode(code & MODE_MASK));
            }
            Decoded::Store {
                size: Size::from_code(code),
                dst,
                off: insn.off,
                src: Source::Imm(insn.imm),
            }
        }

        Class::Stx => match code & MODE_MASK {
            MODE_MEM => Decoded::Store {
                size: Size::from_code(code),
                dst,
                off: insn.off,
                src: Source::Reg(src_reg()?),
            },
            MODE_ATOMIC => {
                let op = AtomicOp::from_imm(insn.imm).ok_or(DecodeError::BadImm(insn.imm))?;
                let size = Size::from_code(code);
                // Atomics exist only at word and doubleword width.
                if !matches!(size, Size::W | Size::Dw) {
                    return Err(DecodeError::BadMode(code & SIZE_MASK));
                }
                Decoded::Atomic {
                    size,
                    op,
                    dst,
                    src: src_reg()?,
                    off: insn.off,
                }
            }
            other => return Err(DecodeError::BadMode(other)),
        },

        Class::Ld => {
            match code & MODE_MASK {
                MODE_IMM => {
                    if Size::from_code(code) != Size::Dw {
                        return Err(DecodeError::BadMode(code & SIZE_MASK));
                    }
                    let next = *prog.get(index + 1).ok_or(DecodeError::TruncatedImm64)?;
                    // The trailing slot carries only the high immediate.
                    if next.code != 0 || next.regs != 0 || next.off != 0 {
                        return Err(DecodeError::MalformedImm64);
                    }
                    let lo = insn.imm as u32 as u64;
                    let hi = next.imm as u32 as u64;
                    let value = match insn.src_raw() {
                        PSEUDO_IMM64 => Imm64::Value((hi << 32) | lo),
                        PSEUDO_MAP_FD => {
                            if next.imm != 0 {
                                return Err(DecodeError::MalformedImm64);
                            }
                            Imm64::MapFd(insn.imm)
                        }
                        PSEUDO_MAP_VALUE => Imm64::MapValue {
                            fd: insn.imm,
                            value_offset: next.imm,
                        },
                        PSEUDO_BTF_ID => {
                            if next.imm != 0 {
                                return Err(DecodeError::MalformedImm64);
                            }
                            Imm64::BtfId(insn.imm)
                        }
                        PSEUDO_FUNC => {
                            if next.imm != 0 {
                                return Err(DecodeError::MalformedImm64);
                            }
                            Imm64::SubprogAddr(insn.imm)
                        }
                        PSEUDO_MAP_IDX => {
                            if next.imm != 0 {
                                return Err(DecodeError::MalformedImm64);
                            }
                            Imm64::MapIdx(insn.imm)
                        }
                        PSEUDO_MAP_IDX_VALUE => Imm64::MapIdxValue {
                            idx: insn.imm,
                            value_offset: next.imm,
                        },
                        other => return Err(DecodeError::BadRegister(other)),
                    };
                    return Ok((Decoded::LoadImm64 { dst, value }, 2));
                }
                MODE_ABS | MODE_IND => return Err(DecodeError::LegacyPacketLoad),
                other => return Err(DecodeError::BadMode(other)),
            }
        }
    };

    Ok((decoded, 1))
}

/// Reinterpret a byte image as instruction slots.
///
/// Returns `None` if `bytes` is not a whole number of slots.
#[must_use]
pub fn slots_from_bytes(bytes: &[u8]) -> Option<impl Iterator<Item = Insn> + '_> {
    if bytes.len() % INSN_SIZE != 0 {
        return None;
    }
    Some(bytes.chunks_exact(INSN_SIZE).map(|c| {
        let mut b = [0u8; INSN_SIZE];
        b.copy_from_slice(c);
        Insn::from_bytes(b)
    }))
}
