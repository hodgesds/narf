//! Encoding — the inverse of [`decode`](crate::decode).
//!
//! Used by the in-tree program builders (tests, the struct_ops trampoline
//! stubs, and the JIT's own self-tests) and, more importantly, to make
//! `decode ∘ encode == id` a property we can fuzz on the host. Linux has no
//! equivalent, which is part of why its instruction-rewriting passes are so
//! delicate.

use crate::insn::{CallTarget, Decoded, Imm64, Insn};
use crate::opcode::*;

/// An encoded instruction: one slot, or two for `LD_IMM64`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    slots: [Insn; 2],
    len: usize,
}

impl Encoded {
    /// The encoded slots.
    #[inline]
    #[must_use]
    pub fn slots(&self) -> &[Insn] {
        &self.slots[..self.len]
    }

    /// How many slots this instruction occupies.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always `false` — every instruction occupies at least one slot. Present
    /// because clippy asks for it alongside `len`.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[inline]
    const fn one(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            slots: [
                Insn {
                    code,
                    regs: Insn::pack_regs(dst, src),
                    off,
                    imm,
                },
                Insn {
                    code: 0,
                    regs: 0,
                    off: 0,
                    imm: 0,
                },
            ],
            len: 1,
        }
    }

    #[inline]
    const fn two(dst: u8, pseudo: u8, lo: i32, hi: i32) -> Self {
        Self {
            slots: [
                Insn {
                    code: CLASS_LD | MODE_IMM | SIZE_DW,
                    regs: Insn::pack_regs(dst, pseudo),
                    off: 0,
                    imm: lo,
                },
                Insn {
                    code: 0,
                    regs: 0,
                    off: 0,
                    imm: hi,
                },
            ],
            len: 2,
        }
    }
}

/// Split a [`Source`] into the opcode's source bit, its register field, and
/// its immediate field.
#[inline]
const fn split(src: Source) -> (u8, u8, i32) {
    match src {
        Source::Imm(i) => (SRC_K, 0, i),
        Source::Reg(r) => (SRC_X, r.index(), 0),
    }
}

/// Encode one instruction.
///
/// Total: every [`Decoded`] value is a valid instruction by construction, so
/// there is no error case. This is the inverse of [`decode`](crate::decode)
/// over the set of encodings NARF accepts.
#[must_use]
pub fn encode(d: Decoded) -> Encoded {
    match d {
        Decoded::Alu { wide, op, dst, src } => {
            let (sbit, sreg, imm) = split(src);
            let class = if wide { CLASS_ALU64 } else { CLASS_ALU };
            Encoded::one(class | op.to_code() | sbit, dst.index(), sreg, 0, imm)
        }

        Decoded::Neg { wide, dst } => {
            let class = if wide { CLASS_ALU64 } else { CLASS_ALU };
            Encoded::one(class | ALU_NEG | SRC_K, dst.index(), 0, 0, 0)
        }

        Decoded::Mov {
            wide,
            dst,
            src,
            sign_extend,
        } => {
            let (sbit, sreg, imm) = split(src);
            let class = if wide { CLASS_ALU64 } else { CLASS_ALU };
            let off = sign_extend.map_or(0, i16::from);
            Encoded::one(class | ALU_MOV | sbit, dst.index(), sreg, off, imm)
        }

        Decoded::Div {
            wide,
            signed,
            dst,
            src,
        }
        | Decoded::Mod {
            wide,
            signed,
            dst,
            src,
        } => {
            let (sbit, sreg, imm) = split(src);
            let class = if wide { CLASS_ALU64 } else { CLASS_ALU };
            let op = if matches!(d, Decoded::Div { .. }) {
                ALU_DIV
            } else {
                ALU_MOD
            };
            let off = if signed { OFF_SIGNED } else { 0 };
            Encoded::one(class | op | sbit, dst.index(), sreg, off, imm)
        }

        Decoded::End { dst, order, width } => {
            let (class, sbit) = match order {
                ByteOrder::Little => (CLASS_ALU, SRC_K),
                ByteOrder::Big => (CLASS_ALU, SRC_X),
                ByteOrder::Swap => (CLASS_ALU64, SRC_K),
            };
            Encoded::one(class | ALU_END | sbit, dst.index(), 0, 0, i32::from(width))
        }

        Decoded::AddrSpaceCast {
            dst,
            src,
            dst_as,
            src_as,
        } => {
            let imm = ((u32::from(dst_as) << 16) | u32::from(src_as)) as i32;
            Encoded::one(
                CLASS_ALU64 | ALU_MOV | SRC_X,
                dst.index(),
                src.index(),
                OFF_ADDR_SPACE_CAST,
                imm,
            )
        }

        Decoded::Load {
            size,
            sign_extend,
            dst,
            src,
            off,
        } => {
            let mode = if sign_extend { MODE_MEMSX } else { MODE_MEM };
            Encoded::one(
                CLASS_LDX | mode | size.to_code(),
                dst.index(),
                src.index(),
                off,
                0,
            )
        }

        Decoded::Store {
            size,
            dst,
            off,
            src,
        } => match src {
            Source::Imm(imm) => Encoded::one(
                CLASS_ST | MODE_MEM | size.to_code(),
                dst.index(),
                0,
                off,
                imm,
            ),
            Source::Reg(r) => Encoded::one(
                CLASS_STX | MODE_MEM | size.to_code(),
                dst.index(),
                r.index(),
                off,
                0,
            ),
        },

        Decoded::Atomic {
            size,
            op,
            dst,
            src,
            off,
        } => Encoded::one(
            CLASS_STX | MODE_ATOMIC | size.to_code(),
            dst.index(),
            src.index(),
            off,
            op.to_imm(),
        ),

        Decoded::LoadImm64 { dst, value } => {
            let d = dst.index();
            match value {
                Imm64::Value(v) => Encoded::two(
                    d,
                    PSEUDO_IMM64,
                    (v & 0xFFFF_FFFF) as u32 as i32,
                    (v >> 32) as u32 as i32,
                ),
                Imm64::MapFd(fd) => Encoded::two(d, PSEUDO_MAP_FD, fd, 0),
                Imm64::MapValue { fd, value_offset } => {
                    Encoded::two(d, PSEUDO_MAP_VALUE, fd, value_offset)
                }
                Imm64::BtfId(id) => Encoded::two(d, PSEUDO_BTF_ID, id, 0),
                Imm64::SubprogAddr(o) => Encoded::two(d, PSEUDO_FUNC, o, 0),
                Imm64::MapIdx(i) => Encoded::two(d, PSEUDO_MAP_IDX, i, 0),
                Imm64::MapIdxValue { idx, value_offset } => {
                    Encoded::two(d, PSEUDO_MAP_IDX_VALUE, idx, value_offset)
                }
            }
        }

        // `JMP | JA` carries its displacement in `off`; when it does not fit,
        // `JMP32 | JA` ("gotol") carries it in `imm` instead.
        Decoded::Jump { off } => {
            if let Ok(o) = i16::try_from(off) {
                Encoded::one(CLASS_JMP | JMP_JA, 0, 0, o, 0)
            } else {
                Encoded::one(CLASS_JMP32 | JMP_JA, 0, 0, 0, off)
            }
        }

        Decoded::JumpCond {
            wide,
            op,
            dst,
            src,
            off,
        } => {
            let (sbit, sreg, imm) = split(src);
            let class = if wide { CLASS_JMP } else { CLASS_JMP32 };
            Encoded::one(class | op.to_code() | sbit, dst.index(), sreg, off, imm)
        }

        Decoded::MayGoto { off } => Encoded::one(CLASS_JMP | JMP_JCOND, 0, 0, off, JCOND_MAY_GOTO),

        Decoded::Call(t) => match t {
            CallTarget::Subprog(o) => Encoded::one(CLASS_JMP | JMP_CALL, 0, CALL_PSEUDO, 0, o),
            CallTarget::Kfunc(id) => Encoded::one(CLASS_JMP | JMP_CALL, 0, CALL_KFUNC, 0, id),
        },

        Decoded::Exit => Encoded::one(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    }
}
