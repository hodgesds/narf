//! Raw BPF opcode constants and their structured enum forms.
//!
//! The encoding is Linux's, verbatim — see `bpf/specification/spec.md` §2 for
//! why we keep it (LLVM's `bpf` target is our compiler, so the encoding is not
//! ours to change). Constants below are transcribed from, and must stay
//! byte-identical to:
//!
//!   * `include/uapi/linux/bpf_common.h` — classes, sizes, modes, ALU/JMP ops
//!     shared with classic BPF.
//!   * `include/uapi/linux/bpf.h` — the eBPF additions (`JMP32`, `ALU64`,
//!     `DW`, `MEMSX`, `ATOMIC`, `MOV`, `ARSH`, `END`, the signed jumps,
//!     `JCOND`, and the atomic op codes that live in `imm`).
//!
//! Note the two cBPF-only encodings that eBPF reuses: class `0x06` was `RET`
//! and is now `JMP32`; class `0x07` was `MISC` and is now `ALU64`. Likewise
//! mode `0x80` was `LEN` and is now `MEMSX`, and `0xa0` was `MSH` and is
//! unused. We implement the eBPF meanings only.

/// Mask for the instruction class — `code & 0x07`.
pub const CLASS_MASK: u8 = 0x07;
/// Mask for the ALU/JMP operation — `code & 0xf0`.
pub const OP_MASK: u8 = 0xf0;
/// Mask for the operand source bit — `code & 0x08`.
pub const SRC_MASK: u8 = 0x08;
/// Mask for the load/store width — `code & 0x18`.
pub const SIZE_MASK: u8 = 0x18;
/// Mask for the load/store addressing mode — `code & 0xe0`.
pub const MODE_MASK: u8 = 0xe0;

// ─── Instruction classes (code & 0x07) ──────────────────────────────
/// Non-standard loads: `LD_IMM64`, and the legacy `ABS`/`IND` packet loads.
pub const CLASS_LD: u8 = 0x00;
/// Loads into a register.
pub const CLASS_LDX: u8 = 0x01;
/// Stores of an immediate.
pub const CLASS_ST: u8 = 0x02;
/// Stores of a register.
pub const CLASS_STX: u8 = 0x03;
/// 32-bit arithmetic.
pub const CLASS_ALU: u8 = 0x04;
/// 64-bit conditional jumps, plus `CALL`/`EXIT`.
pub const CLASS_JMP: u8 = 0x05;
/// 32-bit conditional jumps.
pub const CLASS_JMP32: u8 = 0x06;
/// 64-bit arithmetic.
pub const CLASS_ALU64: u8 = 0x07;

// ─── Operand source (code & 0x08) ───────────────────────────────────
/// Operand is the 32-bit signed immediate.
pub const SRC_K: u8 = 0x00;
/// Operand is the source register.
pub const SRC_X: u8 = 0x08;

// ─── Load/store width (code & 0x18) ─────────────────────────────────
/// 32-bit.
pub const SIZE_W: u8 = 0x00;
/// 16-bit.
pub const SIZE_H: u8 = 0x08;
/// 8-bit.
pub const SIZE_B: u8 = 0x10;
/// 64-bit.
pub const SIZE_DW: u8 = 0x18;

// ─── Addressing mode (code & 0xe0) ──────────────────────────────────
/// Immediate. With `LD | DW` this is the 16-byte `LD_IMM64`.
pub const MODE_IMM: u8 = 0x00;
/// Legacy absolute packet load (cBPF compatibility).
pub const MODE_ABS: u8 = 0x20;
/// Legacy indirect packet load (cBPF compatibility).
pub const MODE_IND: u8 = 0x40;
/// Ordinary memory access.
pub const MODE_MEM: u8 = 0x60;
/// Sign-extending load. eBPF-only; was `LEN` in classic BPF.
pub const MODE_MEMSX: u8 = 0x80;
/// Atomic read-modify-write; the actual operation lives in `imm`.
pub const MODE_ATOMIC: u8 = 0xc0;

// ─── ALU operations (code & 0xf0) ───────────────────────────────────
pub const ALU_ADD: u8 = 0x00;
pub const ALU_SUB: u8 = 0x10;
pub const ALU_MUL: u8 = 0x20;
/// Unsigned divide, or signed divide when `off == 1`.
pub const ALU_DIV: u8 = 0x30;
pub const ALU_OR: u8 = 0x40;
pub const ALU_AND: u8 = 0x50;
pub const ALU_LSH: u8 = 0x60;
pub const ALU_RSH: u8 = 0x70;
/// Negate. Takes no source operand.
pub const ALU_NEG: u8 = 0x80;
/// Unsigned modulo, or signed modulo when `off == 1`.
pub const ALU_MOD: u8 = 0x90;
pub const ALU_XOR: u8 = 0xa0;
/// Move, or sign-extending move when `off` is 8, 16, or 32. With class
/// `ALU64`, source `X`, and `off == 1` it is instead `ADDR_SPACE_CAST`.
pub const ALU_MOV: u8 = 0xb0;
/// Arithmetic (sign-propagating) shift right.
pub const ALU_ARSH: u8 = 0xc0;
/// Byte-order conversion. `ALU | END` selects by `SRC` bit; `ALU64 | END`
/// with `SRC_K` is an unconditional byte swap.
pub const ALU_END: u8 = 0xd0;

// ─── Jump operations (code & 0xf0) ──────────────────────────────────
/// Unconditional jump. In class `JMP` the displacement is `off`; in class
/// `JMP32` it is `imm`, which is how `gotol` reaches beyond ±32K.
pub const JMP_JA: u8 = 0x00;
pub const JMP_JEQ: u8 = 0x10;
pub const JMP_JGT: u8 = 0x20;
pub const JMP_JGE: u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE: u8 = 0x50;
pub const JMP_JSGT: u8 = 0x60;
pub const JMP_JSGE: u8 = 0x70;
pub const JMP_CALL: u8 = 0x80;
pub const JMP_EXIT: u8 = 0x90;
pub const JMP_JLT: u8 = 0xa0;
pub const JMP_JLE: u8 = 0xb0;
pub const JMP_JSLT: u8 = 0xc0;
pub const JMP_JSLE: u8 = 0xd0;
/// Conditional pseudo-jump; the variant is selected by `imm`. Only
/// [`JCOND_MAY_GOTO`] exists today.
pub const JMP_JCOND: u8 = 0xe0;

/// `may_goto +off` — decrement a hidden counter and branch while it lasts.
pub const JCOND_MAY_GOTO: i32 = 0;

// ─── Atomic operations (stored in `imm`) ────────────────────────────
/// Modifier bit: also return the pre-operation value in the source register.
pub const ATOMIC_FETCH: i32 = 0x01;
pub const ATOMIC_ADD: i32 = 0x00;
pub const ATOMIC_OR: i32 = 0x40;
pub const ATOMIC_AND: i32 = 0x50;
pub const ATOMIC_XOR: i32 = 0xa0;
/// Unconditional exchange. Always fetches.
pub const ATOMIC_XCHG: i32 = 0xe0 | ATOMIC_FETCH;
/// Compare-and-exchange. Compares against R0 and clobbers it — the only
/// instruction in the ISA with an implicit register operand.
pub const ATOMIC_CMPXCHG: i32 = 0xf0 | ATOMIC_FETCH;
/// Load-acquire. Exceeds 8 bits, so it is an `imm` value and not an opcode.
pub const ATOMIC_LOAD_ACQ: i32 = 0x100;
/// Store-release. Likewise `imm`-only.
pub const ATOMIC_STORE_REL: i32 = 0x110;

// ─── `off` variant selectors on ALU instructions ────────────────────
/// `off == 1` on `DIV`/`MOD` selects the signed form.
pub const OFF_SIGNED: i16 = 1;
/// `off == 1` on `ALU64 | MOV | X` selects `ADDR_SPACE_CAST`.
pub const OFF_ADDR_SPACE_CAST: i16 = 1;

// ─── `src_reg` pseudo-encodings on `LD_IMM64` ───────────────────────
/// Plain 64-bit immediate.
pub const PSEUDO_IMM64: u8 = 0;
/// `imm` is a map fd; loads the address of the map.
pub const PSEUDO_MAP_FD: u8 = 1;
/// `imm` is a map fd, `next_imm` an offset; loads into the map's value.
pub const PSEUDO_MAP_VALUE: u8 = 2;
/// `imm` is the type id of a kernel variable; loads its address.
pub const PSEUDO_BTF_ID: u8 = 3;
/// `imm` is an instruction offset; loads the address of that subprogram.
pub const PSEUDO_FUNC: u8 = 4;
/// `imm` indexes the loader's fd array; loads the address of the map.
pub const PSEUDO_MAP_IDX: u8 = 5;
/// As [`PSEUDO_MAP_IDX`], but with a value offset in `next_imm`.
pub const PSEUDO_MAP_IDX_VALUE: u8 = 6;

// ─── `src_reg` pseudo-encodings on `CALL` ───────────────────────────
/// A helper call; `imm` is the helper id. NARF has no helper table — this
/// encoding is rejected at decode time in favour of kfuncs. See
/// `bpf/specification/spec.md` §3.
pub const CALL_HELPER: u8 = 0;
/// A call to another subprogram in the same program; `imm` is a
/// pc-relative instruction offset.
pub const CALL_PSEUDO: u8 = 1;
/// A call to a kernel function; `imm` is its type id.
pub const CALL_KFUNC: u8 = 2;

/// Number of general-purpose registers, R0..=R10. R10 is a read-only frame
/// pointer.
pub const NUM_REGS: u8 = 11;

/// Size in bytes of one encoded instruction slot. `LD_IMM64` occupies two.
pub const INSN_SIZE: usize = 8;

/// Instruction class — the low three bits of `code`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Ld,
    Ldx,
    St,
    Stx,
    Alu,
    Jmp,
    Jmp32,
    Alu64,
}

impl Class {
    /// Extract the class from a raw opcode byte. Total: every one of the
    /// eight bit patterns is a valid class.
    #[inline]
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & CLASS_MASK {
            CLASS_LD => Self::Ld,
            CLASS_LDX => Self::Ldx,
            CLASS_ST => Self::St,
            CLASS_STX => Self::Stx,
            CLASS_ALU => Self::Alu,
            CLASS_JMP => Self::Jmp,
            CLASS_JMP32 => Self::Jmp32,
            _ => Self::Alu64,
        }
    }

    /// The raw three-bit encoding.
    #[inline]
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Ld => CLASS_LD,
            Self::Ldx => CLASS_LDX,
            Self::St => CLASS_ST,
            Self::Stx => CLASS_STX,
            Self::Alu => CLASS_ALU,
            Self::Jmp => CLASS_JMP,
            Self::Jmp32 => CLASS_JMP32,
            Self::Alu64 => CLASS_ALU64,
        }
    }

    /// `true` for the two arithmetic classes.
    #[inline]
    #[must_use]
    pub const fn is_alu(self) -> bool {
        matches!(self, Self::Alu | Self::Alu64)
    }

    /// `true` for the two jump classes.
    #[inline]
    #[must_use]
    pub const fn is_jmp(self) -> bool {
        matches!(self, Self::Jmp | Self::Jmp32)
    }

    /// `true` if the class operates on full 64-bit values rather than
    /// 32-bit subregisters.
    #[inline]
    #[must_use]
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Alu64 | Self::Jmp)
    }
}

/// Access width for loads, stores, and atomics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Size {
    /// 8-bit.
    B,
    /// 16-bit.
    H,
    /// 32-bit.
    W,
    /// 64-bit.
    Dw,
}

impl Size {
    /// Extract the width from a raw opcode byte. Total.
    #[inline]
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & SIZE_MASK {
            SIZE_W => Self::W,
            SIZE_H => Self::H,
            SIZE_B => Self::B,
            _ => Self::Dw,
        }
    }

    /// The raw two-bit encoding.
    #[inline]
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::W => SIZE_W,
            Self::H => SIZE_H,
            Self::B => SIZE_B,
            Self::Dw => SIZE_DW,
        }
    }

    /// Width in bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::B => 1,
            Self::H => 2,
            Self::W => 4,
            Self::Dw => 8,
        }
    }

    /// Width in bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        (self.bytes() as u32) * 8
    }
}

/// Where the second operand of an ALU or jump instruction comes from.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The 32-bit signed immediate, sign-extended to the operation width.
    Imm(i32),
    /// A register.
    Reg(Reg),
}

/// A register number, R0..=R10.
///
/// The type maintains the invariant that the number is in range, so decoding
/// is the only place that has to check.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reg(u8);

impl Reg {
    /// The return-value and first-argument register.
    pub const R0: Reg = Reg(0);
    /// The context pointer on entry.
    pub const R1: Reg = Reg(1);
    /// The read-only frame pointer.
    pub const R10: Reg = Reg(10);

    /// Construct a register number, rejecting anything past R10.
    #[inline]
    #[must_use]
    pub const fn new(n: u8) -> Option<Self> {
        if n < NUM_REGS {
            Some(Self(n))
        } else {
            None
        }
    }

    /// The register number as an integer.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    /// The register number as a slice index.
    #[inline]
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// `true` for R10, which no instruction may write.
    #[inline]
    #[must_use]
    pub const fn is_frame_ptr(self) -> bool {
        self.0 == 10
    }
}

impl core::fmt::Debug for Reg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl core::fmt::Display for Reg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

/// Byte-order conversion direction for [`ALU_END`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ByteOrder {
    /// Convert to little-endian.
    Little,
    /// Convert to big-endian.
    Big,
    /// Unconditional byte swap — `ALU64 | END | K`.
    Swap,
}

/// A binary arithmetic operation, excluding the ones that decode to their own
/// [`Decoded`](crate::Decoded) variants (`NEG`, `MOV`, `DIV`, `MOD`, `END`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Or,
    And,
    Lsh,
    Rsh,
    Xor,
    Arsh,
}

impl AluOp {
    /// The raw four-bit encoding.
    #[inline]
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Add => ALU_ADD,
            Self::Sub => ALU_SUB,
            Self::Mul => ALU_MUL,
            Self::Or => ALU_OR,
            Self::And => ALU_AND,
            Self::Lsh => ALU_LSH,
            Self::Rsh => ALU_RSH,
            Self::Xor => ALU_XOR,
            Self::Arsh => ALU_ARSH,
        }
    }
}

/// A conditional-jump predicate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CondOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// unsigned `>`
    Gt,
    /// unsigned `>=`
    Ge,
    /// unsigned `<`
    Lt,
    /// unsigned `<=`
    Le,
    /// signed `>`
    Sgt,
    /// signed `>=`
    Sge,
    /// signed `<`
    Slt,
    /// signed `<=`
    Sle,
    /// bitwise-and is non-zero
    Set,
}

impl CondOp {
    /// The raw four-bit encoding.
    #[inline]
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Eq => JMP_JEQ,
            Self::Ne => JMP_JNE,
            Self::Gt => JMP_JGT,
            Self::Ge => JMP_JGE,
            Self::Lt => JMP_JLT,
            Self::Le => JMP_JLE,
            Self::Sgt => JMP_JSGT,
            Self::Sge => JMP_JSGE,
            Self::Slt => JMP_JSLT,
            Self::Sle => JMP_JSLE,
            Self::Set => JMP_JSET,
        }
    }
}

/// An atomic read-modify-write operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AtomicOp {
    /// `*(dst + off) op= src`. When `fetch` is set, the pre-operation value
    /// is returned in `src`.
    Add {
        fetch: bool,
    },
    Or {
        fetch: bool,
    },
    And {
        fetch: bool,
    },
    Xor {
        fetch: bool,
    },
    /// Unconditional exchange; always fetches.
    Xchg,
    /// Compare-and-exchange against R0; clobbers R0.
    Cmpxchg,
    /// Load-acquire.
    LoadAcquire,
    /// Store-release.
    StoreRelease,
}

impl AtomicOp {
    /// The `imm` encoding.
    #[inline]
    #[must_use]
    pub const fn to_imm(self) -> i32 {
        match self {
            Self::Add { fetch } => ATOMIC_ADD | if fetch { ATOMIC_FETCH } else { 0 },
            Self::Or { fetch } => ATOMIC_OR | if fetch { ATOMIC_FETCH } else { 0 },
            Self::And { fetch } => ATOMIC_AND | if fetch { ATOMIC_FETCH } else { 0 },
            Self::Xor { fetch } => ATOMIC_XOR | if fetch { ATOMIC_FETCH } else { 0 },
            Self::Xchg => ATOMIC_XCHG,
            Self::Cmpxchg => ATOMIC_CMPXCHG,
            Self::LoadAcquire => ATOMIC_LOAD_ACQ,
            Self::StoreRelease => ATOMIC_STORE_REL,
        }
    }

    /// Decode from the `imm` field. `None` for unassigned encodings.
    #[inline]
    #[must_use]
    pub const fn from_imm(imm: i32) -> Option<Self> {
        let fetch = (imm & ATOMIC_FETCH) != 0;
        match imm {
            ATOMIC_XCHG => Some(Self::Xchg),
            ATOMIC_CMPXCHG => Some(Self::Cmpxchg),
            ATOMIC_LOAD_ACQ => Some(Self::LoadAcquire),
            ATOMIC_STORE_REL => Some(Self::StoreRelease),
            _ => match imm & !ATOMIC_FETCH {
                ATOMIC_ADD => Some(Self::Add { fetch }),
                ATOMIC_OR => Some(Self::Or { fetch }),
                ATOMIC_AND => Some(Self::And { fetch }),
                ATOMIC_XOR => Some(Self::Xor { fetch }),
                _ => None,
            },
        }
    }

    /// `true` if the operation writes a value back into the source register.
    #[inline]
    #[must_use]
    pub const fn writes_src(self) -> bool {
        match self {
            Self::Add { fetch }
            | Self::Or { fetch }
            | Self::And { fetch }
            | Self::Xor { fetch } => fetch,
            Self::Xchg | Self::LoadAcquire => true,
            Self::Cmpxchg | Self::StoreRelease => false,
        }
    }
}
