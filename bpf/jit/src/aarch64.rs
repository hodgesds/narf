//! The aarch64 emitter.
//!
//! ## Register allocation
//!
//! Fixed, not allocated — same reason as the x86-64 backend: a static map lets
//! the fault table name a *host* register directly, with no translation table
//! to drift out of step (see [`FaultEntry::dst_host_reg`]).
//!
//! ```text
//!   R0 → x0     R4 → x4     R8  → x21
//!   R1 → x1     R5 → x5     R9  → x22
//!   R2 → x2     R6 → x19    R10 → x25   (frame pointer, read-only)
//!   R3 → x3     R7 → x20
//! ```
//!
//! R0 → `x0` and R1..R5 → `x1`..`x5` is the AAPCS64 argument sequence, so a
//! kfunc call would need almost no shuffling — the same reasoning as SysV on
//! x86-64. R6..R9 and R10 land in callee-saved registers because BPF requires
//! them to survive a call.
//!
//! **R10 is `x25`, deliberately not `x29`.** The x86-64 backend maps R10 to
//! `rbp`, which is tempting to mirror as `x29`. It is not mirrored, because
//! `x29` is architecturally the frame-record pointer that AAPCS64 backtraces
//! follow, and a fault in JITed code that the BPF extable does not cover ends
//! in `rust_aarch64_sync`'s diagnostic dump — an intact frame chain is exactly
//! what makes that dump readable. `x25` is a plain callee-saved register with
//! none of that meaning.
//!
//! The original wording said aarch64 had *no* kernel fault recovery at all, and
//! that has not been true since `frame/src/aarch64/trap.rs` grew its
//! `EC = 0b100101` arm. The conclusion survives the correction — an
//! unregistered fault is still fatal by design (`bpf_extable` invariant §4.3),
//! so a readable dump is still the thing `x29` buys — but see the fault-site
//! note at the end of this block, which the old wording made look impossible.
//!
//! `x24` holds the fuel counter. `x16`/`x17` (IP0/IP1) are the scratch pair:
//! `x16` carries materialised immediates, `x17` carries computed addresses.
//! None of the four appears in the register map, so no BPF register can alias them —
//! which is what makes writing them unconditionally safe. `x18` is left alone
//! entirely (it is the platform register).
//!
//! [`hr::AHANDLE`] (`x9`) is the third scratch, and it exists only for the
//! arena shape: `x16` is unavailable there because a `ST` immediate needs it for
//! the stored value, and the handle has to survive to the faulting instruction
//! so the arena-fault epilogue can name it. `x9` is a plain caller-saved
//! temporary, absent from the map and never live across a call.
//!
//! ## Immediates always go through a register
//!
//! Every immediate operand is materialised into `x16` with a MOVZ/MOVK
//! sequence and then used through the register form of the operation. That is
//! more instructions than aarch64's immediate forms would need, and it is
//! deliberate: `ADD`/`SUB` take a 12-bit unsigned immediate, `AND`/`ORR`/`EOR`
//! take a *bitmask* immediate whose encoding is a rotate/element-width triple,
//! and BPF immediates are `i32` sign-extended to 64 bits. Selecting between
//! those forms means several encodings per operation, each an opportunity to
//! emit something that assembles and computes the wrong thing. One register
//! form per operation is one encoding to get right. Correctness first; the
//! immediate forms are a size optimisation available later.
//!
//! The materialisation is a fixed four instructions (two for a 32-bit operand)
//! regardless of the value, so an immediate's magnitude never changes the
//! emitted size.
//!
//! ## Branch policy, and why it cannot oscillate
//!
//! `B` reaches ±128 MiB; `B.cond` only ±1 MiB. Rather than choose per branch —
//! which needs the distance *before* emission and therefore a sizing fixpoint
//! — every BPF branch lowers to a **fixed-size** shape:
//!
//! * unconditional (`ja`, `exit`): one `B`.
//! * conditional: `B.<inverted cond> +8` over one `B`. Two instructions,
//!   always, with the long-range `B` carrying the displacement.
//!
//! Nothing depends on the distance, so nothing is re-measured and there is no
//! convergence loop to oscillate. That is the hazard Linux's x86 JIT documents
//! at `arch/x86/net/bpf_jit_comp.c:70-113`: choosing a short form shrinks the
//! image, which brings other branches into short range, which shrinks it
//! again, and a branch that was in range at one size is out of range at the
//! next. A single fixed shape has no such feedback.
//!
//! The one conditional branch that is *not* a trampoline is the per-block fuel
//! test, which is `B.cond` straight to the out-of-fuel epilogue: it is the
//! hottest branch in the image (one per block) and the trampoline would add an
//! instruction to every block. Its range is checked when the displacement is
//! patched and a program too large for `imm19` returns
//! [`JitError::BadTarget`] — fail closed to the interpreter, never a truncated
//! displacement.
//!
//! ## What is emitted, and what is not
//!
//! The subset `narf_bpf::jit_glue`'s gates admit: ALU (32 and 64 bit), `MOV`,
//! doubleword loads and stores through R10/R1, jumps, conditional jumps,
//! `exit`, and **kfunc calls**. Subprogram calls are still refused — they need
//! a BPF frame push, which is a different feature from entering a C function.
//! Everything else returns [`JitError::Unsupported`] and runs interpreted,
//! which is a complete implementation — so an unemitted instruction costs
//! speed, not correctness.
//!
//! Emitting a call cost this backend one thing the x86-64 one did not need: an
//! `x30` save. `BLR` writes the link register, and the prologue had no reason
//! to preserve it while nothing here branched with link. See [`hr::LR`].
//!
//! ## Fault sites, and the arena shape that produces them
//!
//! This file records [`FaultEntry`]s now. It used not to for an architectural
//! reason — aarch64 had *no* current-EL data-abort recovery, so a faulting
//! access in emitted code was fatal rather than fixable — and that stopped being
//! true when `frame/src/aarch64/trap.rs` grew its `EC = 0b100101` (Data Abort
//! from the current EL) arm: it consults
//! `narf_memory::bpf_extable::try_recover` and rewrites `frame.elr`, the same
//! fixup shape x86-64 uses.
//!
//! The only faulting access emitted is the arena one, whose address is
//! `slot_base + handle + off16`:
//!
//! ```text
//!   mov  w9, w<handle>          ; zero-extend into the handle scratch
//!   [movz/movk x16, #off16 ; add x9, x9, x16]   ; only when off16 != 0
//!   ldur x17, [sp, #56]         ; the slot base the prologue parked
//!   add  x17, x17, x9           ; the address
//!   ldur <dst>, [x17]           ; the faulting instruction
//! ```
//!
//! The slot base arrives as the fourth entry argument in `x3` and the prologue
//! parks it in the 8 bytes of padding [`FRAME_BYTES`] already claims — see
//! [`ARENA_BASE_SLOT`]. Reloaded per access rather than pinned: `x23`/`x26`..`x28`
//! *are* free here, unlike on x86-64, but a pinned base would mean a
//! seventh saved register, an odd [`SAVED`] count, and a larger frame for every
//! program including the ones with no arena.
//!
//! Two details are load-bearing rather than incidental, and both are pinned by
//! golden encodings. The `W`-register move **zero-extends**, which bounds the
//! index to `[0, 2^32)` in the emitted words rather than by inheriting a
//! verifier invariant; and the displacement is folded into `x9` rather than left
//! in the `LDUR`, so at the fault `x9` holds exactly the handle the interpreter
//! would have computed and [`emit_arena_epilogue`] can return it. Folding it
//! also sidesteps `LDUR`'s `simm9` reach with no second addressing shape.

use alloc::vec::Vec;

use narf_bpf_isa::{decode, AluOp, ByteOrder, CallTarget, CondOp, Decoded, Reg, Size, Source};
use narf_bpf_verifier::{Context, KfuncCallSite, VerifiedProgram};

use crate::blocks::{block_len, block_starts};
use crate::{status, Compiled, FaultEntry, FaultTable, JitError};

/// Host register numbers.
mod hr {
    /// Holds the remaining fuel for the whole program. Callee-saved and absent
    /// from [`super::REGS`], so no BPF register aliases it.
    pub const FUEL: u8 = 24;
    /// R10, the BPF frame pointer. See the module docs for why this is not
    /// `x29`.
    pub const FP: u8 = 25;
    /// Scratch for materialised immediates (IP0).
    pub const IMM: u8 = 16;
    /// Scratch for computed addresses (IP1).
    pub const ADDR: u8 = 17;
    /// Scratch holding an arena access's **handle** — zero-extended, with the
    /// displacement folded in — from the address computation to the access
    /// itself, and read by the arena-fault epilogue.
    ///
    /// A third scratch rather than reusing [`IMM`], because a `ST` immediate
    /// needs `IMM` for the value it stores and the handle has to outlive that.
    /// `x9` is a caller-saved temporary, absent from [`super::REGS`], and never
    /// live across a call — the arena sequence has none in it.
    pub const AHANDLE: u8 = 9;
    /// The link register. `BLR` writes it, so the prologue has to save it —
    /// which it did not need to do while nothing here emitted a call.
    pub const LR: u8 = 30;
    /// `sp` and `xzr` share encoding 31; which one an instruction means is
    /// fixed by the instruction, not by the field.
    pub const SP: u8 = 31;
    /// The zero register.
    pub const ZR: u8 = 31;
}

/// The BPF → host register map. See the module docs for why it is fixed.
const REGS: [u8; 11] = [
    0,      // R0
    1,      // R1
    2,      // R2
    3,      // R3
    4,      // R4
    5,      // R5
    19,     // R6
    20,     // R7
    21,     // R8
    22,     // R9
    hr::FP, // R10 — frame pointer
];

#[inline]
const fn host(r: Reg) -> u8 {
    REGS[r.as_usize()]
}

/// Callee-saved registers the body clobbers, in the order the prologue stores
/// them. Three `STP` pairs, so the count must stay even.
const SAVED: [u8; 6] = [19, 20, 21, 22, hr::FUEL, hr::FP];

/// Bytes of stack the prologue claims for [`SAVED`] and [`hr::LR`].
///
/// 48 for the three pairs, 8 for `x30`, and 8 of padding to keep the total a
/// multiple of 16 — AAPCS64 requires `sp` 16-aligned at every instruction
/// boundary, not merely at a call, and the architecture can be configured to
/// fault on a misaligned `sp` outright.
const FRAME_BYTES: i32 = 64;

/// Offset of the saved [`hr::LR`] within the claimed frame.
const LR_SLOT: i32 = 48;

/// Offset within the claimed frame where the prologue parks the arena slot base.
///
/// The 8 bytes [`FRAME_BYTES`] already spends on 16-alignment, reused rather
/// than added to: a dedicated slot would grow every program's frame by 16 (the
/// alignment quantum) for a value read at most once per arena access.
///
/// `sp` does not move between the prologue and any access — nothing in the body
/// adjusts it, and a `BLR`'s callee builds its frame below — so the parked base
/// survives a kfunc call untouched.
const ARENA_BASE_SLOT: i32 = 56;

// The pad slot must be inside the claimed frame and must not overlap `x30`'s.
const _: () = assert!(
    ARENA_BASE_SLOT == LR_SLOT + 8 && ARENA_BASE_SLOT + 8 == FRAME_BYTES,
    "the arena base slot must be the frame's alignment padding, not a saved register"
);

// ── instruction encoders ─────────────────────────────────────────────
//
// Every base constant below is the *64-bit* form; `sf` clears bit 31 to select
// the 32-bit form, which is uniform across every class used here. Each was
// cross-checked against `llvm-mc -triple=aarch64 -show-encoding` rather than
// read off the manual, because the manual is where transcription errors come
// from.

/// Select the 32-bit form by clearing `sf` (bit 31).
#[inline]
const fn sf(base: u32, wide: bool) -> u32 {
    if wide {
        base
    } else {
        base & !(1 << 31)
    }
}

/// `<op> Rd, Rn, Rm` — the shifted-register form with no shift.
#[inline]
const fn shifted_reg(base: u32, wide: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    sf(base, wide) | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
}

const ADD_X: u32 = 0x8B00_0000;
const SUB_X: u32 = 0xCB00_0000;
const SUBS_X: u32 = 0xEB00_0000;
const AND_X: u32 = 0x8A00_0000;
const ANDS_X: u32 = 0xEA00_0000;
const ORR_X: u32 = 0xAA00_0000;
const EOR_X: u32 = 0xCA00_0000;
/// `MADD Rd, Rn, Rm, Ra`; with `Ra = xzr` it is `MUL`.
const MADD_X: u32 = 0x9B00_0000;
/// `MSUB Rd, Rn, Rm, Ra` — `Rd = Ra - Rn*Rm`, the `o0` bit of `MADD`. Used with
/// a quotient to recover the remainder for `mod`.
const MSUB_X: u32 = 0x9B00_8000;
/// `UDIV Rd, Rn, Rm` and `SDIV Rd, Rn, Rm`, the data-processing 2-source group
/// (same base as [`LSLV_X`], opcode in bits [15:10]). aarch64 division needs no
/// guards: divide-by-zero produces zero and `INT_MIN / -1` produces the wrapping
/// `INT_MIN`, both without trapping — exactly the interpreter's semantics.
const UDIV_X: u32 = 0x9AC0_0800;
const SDIV_X: u32 = 0x9AC0_0C00;
/// Data-processing 2-source shift group. `LSLV` as encoded; `+0x400` selects
/// `LSRV` and `+0x800` selects `ASRV`.
const LSLV_X: u32 = 0x9AC0_2000;

/// `MOV Rd, Rm` — `ORR Rd, ZR, Rm`.
#[inline]
const fn mov_rr(wide: bool, rd: u8, rm: u8) -> u32 {
    shifted_reg(ORR_X, wide, rd, hr::ZR, rm)
}

/// `SUBS Rd, Rn, #imm12` (no shift). `imm` must be ≤ 0xFFF.
#[inline]
const fn subs_imm(wide: bool, rd: u8, rn: u8, imm: u16) -> u32 {
    sf(0xF100_0000, wide) | ((imm as u32 & 0xFFF) << 10) | ((rn as u32) << 5) | rd as u32
}

/// `MOVZ Rd, #imm16, LSL #(16*hw)`.
#[inline]
const fn movz(wide: bool, rd: u8, hw: u8, imm: u16) -> u32 {
    sf(0xD280_0000, wide) | ((hw as u32) << 21) | ((imm as u32) << 5) | rd as u32
}

/// `MOVK Rd, #imm16, LSL #(16*hw)`.
#[inline]
const fn movk(wide: bool, rd: u8, hw: u8, imm: u16) -> u32 {
    sf(0xF280_0000, wide) | ((hw as u32) << 21) | ((imm as u32) << 5) | rd as u32
}

/// `REV Rd, Rn` — reverse all bytes of the register. The 32-bit form (`sf` off)
/// reverses four bytes and zero-extends; the 64-bit form reverses all eight.
#[inline]
const fn rev(wide: bool, rd: u8, rn: u8) -> u32 {
    // `REV Wd,Wn` = 0x5AC0_0800; the 64-bit `REV Xd,Xn` = 0xDAC0_0C00, which is
    // `sf` plus the doubleword opcode bit — spelled directly to keep it obvious.
    let base = if wide { 0xDAC0_0C00 } else { 0x5AC0_0800 };
    base | ((rn as u32) << 5) | rd as u32
}

/// `REV16 Wd, Wn` — reverse the bytes within each 16-bit halfword.
#[inline]
const fn rev16(rd: u8, rn: u8) -> u32 {
    0x5AC0_0400 | ((rn as u32) << 5) | rd as u32
}

/// A bitfield-move (`SBFM`/`UBFM`) with immediates `immr`/`imms`. The 64-bit
/// form sets both `sf` (bit 31) and `N` (bit 22) together — `N` must equal `sf`
/// or the encoding is unallocated. The base constants are the 32-bit forms
/// (both bits clear), so unlike the `_X`-based helpers this does not go through
/// [`sf`], which only clears bit 31 and would leave `sf = 0, N = 1`.
#[inline]
const fn bfm(base: u32, wide: bool, rd: u8, rn: u8, immr: u32, imms: u32) -> u32 {
    let sfn = if wide { (1 << 31) | (1 << 22) } else { 0 };
    base | sfn | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | rd as u32
}

/// `UBFM` base, 32-bit form. `UXTH Wd,Wn` is `UBFM Wd,Wn,#0,#15`.
const UBFM: u32 = 0x5300_0000;
/// `SBFM` base, 32-bit form. `SXTB`/`SXTH`/`SXTW` are `SBFM Rd,Rn,#0,#{7,15,31}`.
const SBFM: u32 = 0x1300_0000;

/// `LDUR Rt, [Rn, #simm9]` — the unscaled form, so a negative or unaligned
/// displacement needs no special case. `simm9` must be in `-256..=255`.
#[inline]
const fn ldur(rt: u8, rn: u8, simm9: i32) -> u32 {
    0xF840_0000 | (((simm9 as u32) & 0x1FF) << 12) | ((rn as u32) << 5) | rt as u32
}

/// `STUR Rt, [Rn, #simm9]`.
#[inline]
const fn stur(rt: u8, rn: u8, simm9: i32) -> u32 {
    0xF800_0000 | (((simm9 as u32) & 0x1FF) << 12) | ((rn as u32) << 5) | rt as u32
}

/// A load/store unscaled-immediate (`LDUR*`/`STUR*`) of any width.
///
/// `size2` is the width in the `[31:30]` field (0=byte, 1=half, 2=word,
/// 3=doubleword) and `opc2` is the `[23:22]` field — `0b00` store, `0b01`
/// zero-extending load, `0b10` load sign-extending to 64 bits. [`ldur`] and
/// [`stur`] are the `size2 = 3` cases of this, kept as their own names because
/// the doubleword forms are on every non-widened path.
#[inline]
const fn ldst_unscaled(size2: u32, opc2: u32, rt: u8, rn: u8, simm9: i32) -> u32 {
    0x3800_0000
        | (size2 << 30)
        | (opc2 << 22)
        | (((simm9 as u32) & 0x1FF) << 12)
        | ((rn as u32) << 5)
        | rt as u32
}

/// The `[31:30]` width field for a BPF access size.
#[inline]
const fn size_field(size: Size) -> u32 {
    match size {
        Size::B => 0,
        Size::H => 1,
        Size::W => 2,
        Size::Dw => 3,
    }
}

/// `LDUR*` of `size` into `rt`, zero- or sign-extending to a full 64-bit
/// register to match the interpreter's `widen`.
#[inline]
const fn ldur_sized(size: Size, sign_extend: bool, rt: u8, rn: u8, simm9: i32) -> u32 {
    // opc `0b10` sign-extends to the 64-bit register; `0b01` zero-extends. A
    // doubleword fills the register either way, so it always takes `0b01`.
    let opc = if sign_extend && !matches!(size, Size::Dw) {
        0b10
    } else {
        0b01
    };
    ldst_unscaled(size_field(size), opc, rt, rn, simm9)
}

/// `STUR*` of the low `size` bytes of `rt`.
#[inline]
const fn stur_sized(size: Size, rt: u8, rn: u8, simm9: i32) -> u32 {
    ldst_unscaled(size_field(size), 0b00, rt, rn, simm9)
}

/// `STP Rt, Rt2, [Rn, #imm]` with the addressing mode chosen by `base`.
#[inline]
const fn pair(base: u32, rt: u8, rt2: u8, rn: u8, byte_off: i32) -> u32 {
    let imm7 = (byte_off / 8) as u32 & 0x7F;
    base | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32
}

/// `STP Rt, Rt2, [Rn, #imm]!` — pre-indexed, writing the base back.
const STP_PRE: u32 = 0xA980_0000;
/// `STP Rt, Rt2, [Rn, #imm]` — signed offset, base unchanged.
const STP_OFF: u32 = 0xA900_0000;
/// `LDP Rt, Rt2, [Rn, #imm]` — signed offset.
const LDP_OFF: u32 = 0xA940_0000;
/// `LDP Rt, Rt2, [Rn], #imm` — post-indexed, writing the base back.
const LDP_POST: u32 = 0xA8C0_0000;

/// `RET` (to `x30`).
const RET: u32 = 0xD65F_03C0;

/// `BLR Rn` — branch with link to an absolute address in a register.
#[inline]
const fn blr(rn: u8) -> u32 {
    0xD63F_0000 | ((rn as u32) << 5)
}

/// The AAPCS64 condition codes this backend uses. Inverting any of them is
/// `code ^ 1`, which the architecture guarantees for every code except
/// `AL`/`NV` — neither of which appears here.
mod cc {
    pub const EQ: u8 = 0;
    pub const NE: u8 = 1;
    /// Unsigned ≥ — also "no borrow" after `SUBS`.
    pub const HS: u8 = 2;
    /// Unsigned < — also "borrow" after `SUBS`.
    pub const LO: u8 = 3;
    /// Unsigned >.
    pub const HI: u8 = 8;
    /// Unsigned ≤.
    pub const LS: u8 = 9;
    pub const GE: u8 = 10;
    pub const LT: u8 = 11;
    pub const GT: u8 = 12;
    pub const LE: u8 = 13;
}

/// The condition to branch on when a BPF conditional jump is *taken*.
///
/// `JSET` is `TST`-then-not-zero; the caller emits the `TST`.
const fn cond_cc(op: CondOp) -> u8 {
    match op {
        CondOp::Eq => cc::EQ,
        CondOp::Ne => cc::NE,
        CondOp::Gt => cc::HI,
        CondOp::Ge => cc::HS,
        CondOp::Lt => cc::LO,
        CondOp::Le => cc::LS,
        CondOp::Sgt => cc::GT,
        CondOp::Sge => cc::GE,
        CondOp::Slt => cc::LT,
        CondOp::Sle => cc::LE,
        CondOp::Set => cc::NE,
    }
}

/// `B.<cond> #(4*imm19)`, relative to this instruction.
#[inline]
const fn b_cond(cond: u8, imm19: i32) -> u32 {
    0x5400_0000 | (((imm19 as u32) & 0x7_FFFF) << 5) | cond as u32
}

/// `B #(4*imm26)`, relative to this instruction.
#[inline]
const fn b(imm26: i32) -> u32 {
    0x1400_0000 | ((imm26 as u32) & 0x03FF_FFFF)
}

/// A byte sink that also records where things landed.
#[derive(Debug, Default)]
struct Emit {
    buf: Vec<u8>,
    faults: Vec<FaultEntry>,
}

impl Emit {
    #[inline]
    fn len(&self) -> u32 {
        self.buf.len() as u32
    }
    /// Append one instruction word. Every aarch64 instruction is four bytes,
    /// little-endian regardless of data endianness.
    #[inline]
    fn w(&mut self, insn: u32) {
        self.buf.extend_from_slice(&insn.to_le_bytes());
    }
    /// Overwrite the word at `off`, for branch patching.
    fn patch(&mut self, off: u32, insn: u32) {
        let at = off as usize;
        self.buf[at..at + 4].copy_from_slice(&insn.to_le_bytes());
    }
    fn word_at(&self, off: u32) -> u32 {
        let at = off as usize;
        u32::from_le_bytes([
            self.buf[at],
            self.buf[at + 1],
            self.buf[at + 2],
            self.buf[at + 3],
        ])
    }
}

/// Materialise a 64-bit constant into `dst`.
///
/// Always four instructions, so the size never depends on the value — the same
/// property the x86-64 backend gets from always using the 10-byte `mov
/// reg, imm64`. A shorter sequence for small constants would be a size that
/// varies with the operand, which is the other way (besides branches) to make
/// a sizing fixpoint oscillate. This backend has no fixpoint and intends to
/// keep it that way.
fn mov_imm64(e: &mut Emit, dst: u8, v: i64) {
    let u = v as u64;
    e.w(movz(true, dst, 0, u as u16));
    e.w(movk(true, dst, 1, (u >> 16) as u16));
    e.w(movk(true, dst, 2, (u >> 32) as u16));
    e.w(movk(true, dst, 3, (u >> 48) as u16));
}

/// Materialise a 32-bit constant into `dst`, zero-extending to 64 bits.
///
/// Two instructions, likewise constant. Writing a `W` register zeroes the top
/// half of the `X` register, which is exactly BPF's 32-bit `MOV` semantics.
fn mov_imm32(e: &mut Emit, dst: u8, v: i32) {
    let u = v as u32;
    e.w(movz(false, dst, 0, u as u16));
    e.w(movk(false, dst, 1, (u >> 16) as u16));
}

/// `MOV Rd, #imm` — sign-extended to 64 bits for a wide move, zero-extended
/// from 32 for a narrow one, matching the interpreter's move semantics.
fn emit_mov_imm(e: &mut Emit, wide: bool, dst: u8, v: i32) {
    if wide {
        mov_imm64(e, dst, i64::from(v));
    } else {
        mov_imm32(e, dst, v);
    }
}

/// Sign-extend the low `bits` of `v` to 64 bits — the compile-time twin of the
/// `MOVSX` register forms, for the immediate case.
fn sext_imm(v: i32, bits: u8) -> i64 {
    match bits {
        8 => v as i8 as i64,
        16 => v as i16 as i64,
        _ => i64::from(v),
    }
}

/// `MOVSX`: sign-extend the low `bits` of `src` into `dst` as one `SBFM`. A
/// 32-bit destination extends within 32 bits and zero-extends the top half; a
/// 32-bit-source extension to a 32-bit destination is the identity move.
fn movsx(wide: bool, bits: u8, dst: u8, src: u8) -> u32 {
    match bits {
        8 => bfm(SBFM, wide, dst, src, 0, 7),
        16 => bfm(SBFM, wide, dst, src, 0, 15),
        _ if wide => bfm(SBFM, true, dst, src, 0, 31),
        _ => mov_rr(false, dst, src),
    }
}

/// `END` / `bswap`: reverse or truncate `dst` by width, matching the
/// interpreter's `byteswap`. `Little` only masks to width; `Big`/`Swap`
/// reverses. Every case zero-extends the result.
fn emit_byteswap(
    e: &mut Emit,
    at: u32,
    dst: u8,
    order: ByteOrder,
    width: u8,
) -> Result<(), JitError> {
    let swap = matches!(order, ByteOrder::Big | ByteOrder::Swap);
    match (width, swap) {
        // `REV16` swaps the bytes in the low halfword (and the high one); `UXTH`
        // then keeps only the low 16 bits, matching `(v as u16).swap_bytes()`.
        (16, true) => {
            e.w(rev16(dst, dst));
            e.w(bfm(UBFM, false, dst, dst, 0, 15));
        }
        // `UXTH` — value & 0xFFFF.
        (16, false) => e.w(bfm(UBFM, false, dst, dst, 0, 15)),
        // `REV Wd` reverses four bytes and zero-extends the top half.
        (32, true) => e.w(rev(false, dst, dst)),
        // `MOV Wd, Wd` — value & 0xFFFF_FFFF via the zero-extending W write.
        (32, false) => e.w(mov_rr(false, dst, dst)),
        // `REV Xd` reverses all eight bytes.
        (64, true) => e.w(rev(true, dst, dst)),
        // A 64-bit little-endian swap is the identity.
        (64, false) => {}
        _ => {
            return Err(JitError::Unsupported {
                at,
                what: "byteswap width must be 16, 32, or 64",
            })
        }
    }
    Ok(())
}

/// Put an immediate operand in [`hr::IMM`] and return that register.
///
/// For a 32-bit operation only the low half is ever read, so the two-word
/// materialisation suffices; for a 64-bit one the immediate is sign-extended
/// to 64 bits, matching the interpreter's `imm as i64 as u64`.
fn imm_operand(e: &mut Emit, wide: bool, v: i32) -> u8 {
    if wide {
        mov_imm64(e, hr::IMM, i64::from(v));
    } else {
        mov_imm32(e, hr::IMM, v);
    }
    hr::IMM
}

/// The register holding `src`, materialising an immediate if needed.
fn src_reg(e: &mut Emit, wide: bool, src: Source) -> u8 {
    match src {
        Source::Reg(r) => host(r),
        Source::Imm(v) => imm_operand(e, wide, v),
    }
}

/// The shifted-register base for a binary ALU operation, or `None` for the
/// ones with their own encoding.
const fn alu_base(op: AluOp) -> Option<u32> {
    Some(match op {
        AluOp::Add => ADD_X,
        AluOp::Sub => SUB_X,
        AluOp::Or => ORR_X,
        AluOp::And => AND_X,
        AluOp::Xor => EOR_X,
        // Multiply is `MADD`; shifts are the 2-source group.
        AluOp::Mul | AluOp::Lsh | AluOp::Rsh | AluOp::Arsh => return None,
    })
}

/// The 2-source shift encoding for a shift operation.
const fn shift_insn(op: AluOp, wide: bool, rd: u8, rn: u8, rm: u8) -> Option<u32> {
    let base = match op {
        AluOp::Lsh => LSLV_X,
        AluOp::Rsh => LSLV_X + 0x400,  // LSRV — logical, matching BPF
        AluOp::Arsh => LSLV_X + 0x800, // ASRV
        _ => return None,
    };
    Some(shifted_reg(base, wide, rd, rn, rm))
}

/// Reloc target meaning "the shared epilogue" rather than a BPF instruction.
///
/// Every `exit` branches here instead of duplicating the restore sequence.
/// Not a real instruction index, so it resolves against the final entry of the
/// offset table, which is where the body ends and the epilogue begins.
const EPILOGUE: u32 = u32::MAX;

/// Reloc target meaning "the out-of-fuel epilogue".
const OOF_EPILOGUE: u32 = u32::MAX - 1;

/// Which branch field a relocation patches.
///
/// Both are fixed width — the point of the branch policy in the module docs is
/// that a relocation never changes an instruction's *size*, only the
/// displacement inside it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RelKind {
    /// `B`, `imm26`, ±128 MiB.
    B26,
    /// `B.cond`, `imm19`, ±1 MiB.
    Cond19,
}

/// A branch whose target is a BPF instruction index, resolved once every
/// instruction's offset is known.
#[derive(Copy, Clone, Debug)]
struct Reloc {
    /// Offset of the branch instruction word. aarch64 branch displacements are
    /// relative to the branch itself, not to the following instruction, so
    /// there is no separate base to record.
    at: u32,
    /// Target BPF instruction index, or one of the two pseudo-targets.
    target: u32,
    kind: RelKind,
}

/// Compile a verified program.
///
/// A single pass, with no sizing fixpoint: every branch shape has a fixed size
/// that does not depend on how far it reaches (module docs), and every
/// immediate materialisation has a fixed size that does not depend on its
/// value. Nothing shrinks, so nothing needs re-measuring.
///
/// # Errors
///
/// [`JitError`]. `Unsupported` means "run this one interpreted".
pub fn compile(prog: &VerifiedProgram) -> Result<Compiled, JitError> {
    let e = emit_pass(prog)?;
    Ok(Compiled {
        code: e.buf,
        faults: {
            let mut f = e.faults;
            f.sort_unstable_by_key(|x| x.fault_off);
            FaultTable(f)
        },
        entry_off: 0,
    })
}

fn emit_pass(prog: &VerifiedProgram) -> Result<Emit, JitError> {
    let mut e = Emit::default();
    let mut relocs: Vec<Reloc> = Vec::new();
    let mut out = Vec::with_capacity(prog.insns.len() + 1);
    let starts = block_starts(prog)?;
    // Which accesses take the arena shape — the same function `jit_glue`'s
    // gate 5 consults, so the gate and the emitter cannot disagree.
    let arena = crate::arena_access_map(prog);

    emit_prologue(&mut e);

    let mut i = 0usize;
    while i < prog.insns.len() {
        out.push(e.len());
        // Burn this block's worth of fuel on entry. Per block rather than per
        // instruction: the same total as the interpreter charges, because a
        // block that is entered retires all of its instructions. The charge is
        // taken *before* the block runs, so a block that cannot be paid for
        // does not execute at all.
        if starts[i] {
            emit_fuel_burn(&mut e, block_len(prog, &starts, i), &mut relocs);
        }
        let (insn, width) =
            decode(&prog.insns, i).map_err(|_| JitError::Decode { at: i as u32 })?;
        emit_insn(
            &mut e,
            &insn,
            i as u32,
            &mut relocs,
            &prog.kfunc_calls,
            arena[i],
        )?;
        i += width;
        // A wide instruction occupies two slots. `LD_IMM64` is the only one and
        // it is `Unsupported` here, so `width` is always 1 today; the trailing
        // slot records the *following* instruction's offset, which is only
        // sound because the verifier rejects a jump into it.
        for _ in 1..width {
            out.push(e.len());
        }
    }
    out.push(e.len());

    emit_epilogue(&mut e);
    let oof_at = e.len();
    emit_oof_epilogue(&mut e);
    let arena_at = e.len();
    emit_arena_epilogue(&mut e);

    // An arena fault site resumes at the arena epilogue, never at the next
    // instruction. Patched unconditionally here rather than recorded at the
    // access, because the epilogue's offset is not known until the body is
    // emitted — and anything left holding a next-instruction fixup would be the
    // zero-and-continue shape the arena lowering exists to avoid.
    for f in &mut e.faults {
        if f.arena {
            f.fixup_off = arena_at;
        }
    }

    for r in &relocs {
        let target = if r.target == OOF_EPILOGUE {
            oof_at
        } else if r.target == EPILOGUE {
            // The last offset recorded is one past the body — the epilogue.
            *out.last()
                .expect("the offset table always has the trailing entry")
        } else {
            *out.get(r.target as usize)
                .ok_or(JitError::BadTarget { at: r.target })?
        };
        // Relative to the branch itself, in instruction words.
        let words = (i64::from(target) - i64::from(r.at)) / 4;
        let word = e.word_at(r.at);
        let patched = match r.kind {
            RelKind::B26 => {
                if !(-(1 << 25)..(1 << 25)).contains(&words) {
                    return Err(JitError::BadTarget { at: r.target });
                }
                b(words as i32)
            }
            RelKind::Cond19 => {
                // Out of `imm19` range means the image is larger than 1 MiB.
                // Refused rather than truncated: a wrong displacement is a
                // branch into the middle of an instruction, and the caller's
                // answer to an error is to interpret.
                if !(-(1 << 18)..(1 << 18)).contains(&words) {
                    return Err(JitError::BadTarget { at: r.target });
                }
                b_cond((word & 0xF) as u8, words as i32)
            }
        };
        e.patch(r.at, patched);
    }
    Ok(e)
}

/// Save the callee-saved registers the body clobbers, then install the ABI's
/// arguments in the registers the body expects them in.
///
/// The ABI is `(frame_top, ctx_ptr, fuel)` in `x0`/`x1`/`x2`.
fn emit_prologue(e: &mut Emit) {
    // Three pairs in 48 bytes: the first is pre-indexed to claim the frame,
    // the rest are plain offsets from the new `sp`.
    e.w(pair(STP_PRE, SAVED[0], SAVED[1], hr::SP, -FRAME_BYTES));
    e.w(pair(STP_OFF, SAVED[2], SAVED[3], hr::SP, 16));
    e.w(pair(STP_OFF, SAVED[4], SAVED[5], hr::SP, 32));
    // `x30` is saved alone rather than paired, because [`SAVED`] has an even
    // count and pairing it with `xzr` would store a word nothing reads back.
    // A `BLR` overwrites it, so without this the first kfunc call would return
    // the *program* into the middle of itself.
    e.w(stur(hr::LR, hr::SP, LR_SLOT));
    // Park the arena slot base (AAPCS64 arg 4, `x3`) in the frame's padding,
    // **before** anything writes `x3`, which R3 maps to. See
    // [`ARENA_BASE_SLOT`]. Emitted unconditionally: one store per invocation
    // beats two prologue shapes to reason about, and a program with no arena
    // simply never reads it back.
    e.w(stur(3, hr::SP, ARENA_BASE_SLOT));
    // Fuel out of `x2` **before** anything writes `x2`, which R2 maps to.
    e.w(mov_rr(true, hr::FUEL, 2));
    // Frame top out of `x0` before anything writes `x0`, which R0 maps to.
    e.w(mov_rr(true, hr::FP, 0));
    // The context pointer needs no move at all: it arrives in `x1`, which is
    // exactly R1's host register. Absence of an instruction is the kind of
    // claim that stops being true silently if the register map is edited, so
    // it is pinned two ways: `A64_PROLOGUE` is an exact word list with no
    // `mov x1, x1` in it, and `a64_the_context_pointer_arrives_in_r1_untouched`
    // loads through R1 and checks the value.
    //
    // R0 is zeroed. x86-64 does not, because there R0's host register is not
    // an argument register and holds nothing meaningful on entry; here `x0`
    // arrives holding `frame_top`, a kernel pointer, and a program that
    // reached `exit` without writing R0 would return it to the caller.
    e.w(mov_rr(true, 0, hr::ZR));
}

/// The normal epilogue: exhaustion flag clear, restore, return.
fn emit_epilogue(e: &mut Emit) {
    // `x1` is the high half of the 128-bit return — the exhaustion flag.
    // Cleared here so a clean exit is unambiguous. Writing `x1` clobbers R1,
    // which is finished with by definition at the epilogue.
    e.w(mov_rr(true, 1, hr::ZR));
    emit_restore(e);
}

/// The out-of-fuel epilogue: flag set, and `x0` left as-is (meaningless).
fn emit_oof_epilogue(e: &mut Emit) {
    e.w(movz(true, 1, 0, status::OUT_OF_FUEL as u16));
    emit_restore(e);
}

/// The arena-fault epilogue: status 2 in `x1`, the offending handle in `x0`.
///
/// Reached only through the exception table — nothing branches here — so `sp` is
/// exactly as the faulting instruction left it, which is the state
/// [`emit_restore`] expects. That is why the fixup can be a plain resume address
/// with no per-site stub: nothing in the body moves `sp`.
///
/// **Not** Linux's `ex_handler_bpf` shape. Zeroing the destination and resuming
/// would make an out-of-bounds arena access return a value natively and
/// `Trap::ArenaOutOfBounds` interpreted — one program, two verdicts, decided by
/// whether it cleared `jit_glue`'s gates. [`hr::AHANDLE`] still holds the handle
/// because [`emit_arena_addr`] folded the displacement into it.
fn emit_arena_epilogue(e: &mut Emit) {
    e.w(mov_rr(true, 0, hr::AHANDLE));
    e.w(movz(true, 1, 0, status::ARENA_FAULT as u16));
    emit_restore(e);
}

fn emit_restore(e: &mut Emit) {
    e.w(pair(LDP_OFF, SAVED[2], SAVED[3], hr::SP, 16));
    e.w(pair(LDP_OFF, SAVED[4], SAVED[5], hr::SP, 32));
    e.w(ldur(hr::LR, hr::SP, LR_SLOT));
    // Post-indexed, releasing the frame as it loads the first pair.
    e.w(pair(LDP_POST, SAVED[0], SAVED[1], hr::SP, FRAME_BYTES));
    e.w(RET);
}

/// `subs x24, x24, n` then a branch to the out-of-fuel epilogue on borrow.
///
/// `B.LO` is the right test: `SUBS` clears `C` exactly when the subtraction
/// borrowed, i.e. when there was not enough fuel left to pay for this block.
/// Testing the *result* instead would need a second comparison and would
/// misread a wrapped counter as plenty.
fn emit_fuel_burn(e: &mut Emit, n: u32, relocs: &mut Vec<Reloc>) {
    if n <= 0xFFF {
        e.w(subs_imm(true, hr::FUEL, hr::FUEL, n as u16));
    } else {
        burn_via_scratch(e, n);
    }
    let at = e.len();
    e.w(b_cond(cc::LO, 0));
    relocs.push(Reloc {
        at,
        target: OOF_EPILOGUE,
        kind: RelKind::Cond19,
    });
}

/// The fuel burn for a block longer than `SUBS`'s 12-bit immediate reaches —
/// more than 4095 instructions with no branch and no branch target in them.
///
/// Rare, but a silently truncated charge would be a *fuel* bug, which is the
/// class the interpreter and the JIT must not disagree on. Costing five words
/// instead of one here is free of consequences: the block length is known
/// before emission, so a size that varies with it cannot perturb any branch.
/// There is no fixpoint to disturb.
fn burn_via_scratch(e: &mut Emit, n: u32) {
    mov_imm64(e, hr::IMM, i64::from(n));
    e.w(shifted_reg(SUBS_X, true, hr::FUEL, hr::FUEL, hr::IMM));
}

/// Emit a conditional branch to a BPF instruction as an inverted-condition
/// skip over an unconditional `B`. See the module docs for why the shape is
/// fixed rather than chosen.
fn emit_cond_branch(e: &mut Emit, taken: u8, target: u32, relocs: &mut Vec<Reloc>) {
    // `+2` words skips the `B` that follows. Inverting the condition is
    // `taken ^ 1` — architecturally exact for every code this backend uses.
    e.w(b_cond(taken ^ 1, 2));
    let at = e.len();
    e.w(b(0));
    relocs.push(Reloc {
        at,
        target,
        kind: RelKind::B26,
    });
}

/// The register holding `base + off`, and the displacement to use with it.
///
/// `LDUR`/`STUR` take an unscaled `simm9`, so they reach `-256..=255` — which
/// covers every stack frame BPF allows. Beyond that the displacement is folded
/// into [`hr::ADDR`] and the access uses a zero displacement, reusing the one
/// memory encoding rather than adding the scaled and register-offset forms.
/// Fewer encodings is fewer chances to emit something that assembles and
/// addresses the wrong place.
///
/// The unscaled forms are also why negative offsets need no special case at
/// all: `LDR`/`STR` with `uimm12` cannot express one, and every BPF stack
/// access is negative.
fn addr_operand(e: &mut Emit, base: u8, off: i16) -> (u8, i32) {
    let off = i32::from(off);
    if (-256..=255).contains(&off) {
        (base, off)
    } else {
        mov_imm64(e, hr::ADDR, i64::from(off));
        e.w(shifted_reg(ADD_X, true, hr::ADDR, base, hr::ADDR));
        (hr::ADDR, 0)
    }
}

/// The whole of a kfunc call: the AAPCS64 shuffle, the target, and the `BLR`.
///
/// BPF passes arguments in R1..R5 and AAPCS64 in `x0`..`x4`, so the map is
/// off by exactly one register and every argument moves. The moves go
/// **forward** — `x0 := x1`, then `x1 := x2`, and so on — which is the order
/// that works: each source is read before anything writes it, and `x0`'s old
/// value is R0, which a call clobbers by definition. Walking the other way
/// would smear R5 across all five argument registers.
///
/// Nothing is saved around the call. R0..R5 live in `x0`..`x5`, which AAPCS64
/// lets the callee destroy and the BPF ABI likewise declares caller-saved;
/// R6..R10 and the fuel counter live in `x19`..`x22`, `x24` and `x25`, which
/// AAPCS64 requires the callee to preserve. `x30` is the one exception, and the
/// prologue saves it — see [`hr::LR`].
fn emit_kfunc_call(e: &mut Emit, addr: usize) {
    for k in 0..5u8 {
        e.w(mov_rr(true, k, k + 1));
    }
    // Through `x16` (IP0): it is the scratch register the platform reserves for
    // exactly this, absent from [`REGS`], and caller-saved, so the callee is
    // welcome to destroy it.
    mov_imm64(e, hr::IMM, addr as i64);
    e.w(blr(hr::IMM));
}

/// The call site the verifier resolved for the `call` at `at`, or a refusal.
///
/// Byte-identical reasoning to the x86-64 backend's `resolve_call`, and
/// deliberately duplicated rather than shared: the two backends already
/// duplicate `emit_pass`, `emit_prologue` and the reloc patcher, and a
/// three-line shared helper would be the only cross-backend coupling in the
/// crate. Every arm is fail-closed — see that function for what each means.
fn resolve_call(calls: &[KfuncCallSite], at: u32, id: i32) -> Result<KfuncCallSite, JitError> {
    let site = calls
        .binary_search_by_key(&at, |c| c.insn_index)
        .map(|k| calls[k])
        .map_err(|_| JitError::Unsupported {
            at,
            what: "kfunc call the verifier never resolved",
        })?;
    if site.id != id {
        return Err(JitError::Unsupported {
            at,
            what: "kfunc call site disagrees with the instruction's immediate",
        });
    }
    if site.context != Context::Atomic {
        return Err(JitError::Unsupported {
            at,
            what: "a sleepable kfunc's shim does not use the uniform u64 ABI",
        });
    }
    if site.addr == 0 {
        return Err(JitError::Unsupported {
            at,
            what: "kfunc shim address is null",
        });
    }
    Ok(site)
}

/// Compute `slot_base + zx32(handle) + off` into [`hr::ADDR`], leaving the
/// handle itself in [`hr::AHANDLE`].
///
/// Returns nothing: the access that follows always uses `[ADDR]` with a zero
/// displacement, because the displacement is folded in here. That is one
/// addressing shape for every arena access whatever `off16` holds, where
/// [`addr_operand`] needs two.
///
/// [`hr::IMM`] is left free on exit, which a `ST` immediate depends on.
fn emit_arena_addr(e: &mut Emit, handle: u8, off: i16) {
    debug_assert!(
        handle != hr::AHANDLE && handle != hr::IMM && handle != hr::ADDR,
        "the arena scratch registers must not be a BPF register"
    );
    // `W`-register move: zero-extends, which is what bounds the index to
    // `[0, 2^32)` in the emitted words. See the module docs.
    e.w(mov_rr(false, hr::AHANDLE, handle));
    if off != 0 {
        // Sign-extended to 64 bits, matching the ISA's signed `off` field.
        mov_imm64(e, hr::IMM, i64::from(off));
        e.w(shifted_reg(ADD_X, true, hr::AHANDLE, hr::AHANDLE, hr::IMM));
    }
    e.w(ldur(hr::ADDR, hr::SP, ARENA_BASE_SLOT));
    e.w(shifted_reg(ADD_X, true, hr::ADDR, hr::ADDR, hr::AHANDLE));
}

fn emit_insn(
    e: &mut Emit,
    insn: &Decoded,
    at: u32,
    relocs: &mut Vec<Reloc>,
    calls: &[KfuncCallSite],
    arena: bool,
) -> Result<(), JitError> {
    // The arena forms first: same instructions, different addressing, and a
    // recorded fault site. Only the doubleword width is emitted, matching the
    // non-arena arms — anything else falls through to `Unsupported` and runs
    // interpreted rather than being lowered as a bare dereference.
    if arena {
        match *insn {
            Decoded::Load {
                size,
                sign_extend,
                dst,
                src,
                off,
            } => {
                emit_arena_addr(e, host(src), off);
                let fault_off = e.len();
                e.w(ldur_sized(size, sign_extend, host(dst), hr::ADDR, 0));
                record_fault(e, fault_off);
                return Ok(());
            }
            Decoded::Store {
                size,
                dst,
                off,
                src: Source::Reg(s),
            } => {
                emit_arena_addr(e, host(dst), off);
                let fault_off = e.len();
                e.w(stur_sized(size, host(s), hr::ADDR, 0));
                record_fault(e, fault_off);
                return Ok(());
            }
            Decoded::Store {
                size,
                dst,
                off,
                src: Source::Imm(v),
            } => {
                // Address first, value second: [`emit_arena_addr`] uses
                // [`hr::IMM`] as scratch for the displacement, so materialising
                // the stored value into it beforehand would be destroyed.
                emit_arena_addr(e, host(dst), off);
                mov_imm64(e, hr::IMM, i64::from(v));
                let fault_off = e.len();
                e.w(stur_sized(size, hr::IMM, hr::ADDR, 0));
                record_fault(e, fault_off);
                return Ok(());
            }
            // An arena atomic — no lowering yet, so it runs interpreted.
            _ => {
                return Err(JitError::Unsupported {
                    at,
                    what: "arena atomic not yet emitted by the aarch64 backend",
                })
            }
        }
    }
    match *insn {
        Decoded::Call(CallTarget::Kfunc(id)) => {
            let site = resolve_call(calls, at, id)?;
            emit_kfunc_call(e, site.addr);
        }

        Decoded::Mov {
            wide,
            dst,
            src,
            sign_extend: None,
        } => match src {
            Source::Reg(s) => e.w(mov_rr(wide, host(dst), host(s))),
            Source::Imm(v) => emit_mov_imm(e, wide, host(dst), v),
        },

        Decoded::Mov {
            wide,
            dst,
            src: Source::Reg(s),
            sign_extend: Some(bits),
        } => e.w(movsx(wide, bits, host(dst), host(s))),

        Decoded::Mov {
            wide,
            dst,
            src: Source::Imm(v),
            sign_extend: Some(bits),
        } => {
            // Sign-extending a constant is a constant; materialise it — the
            // interpreter's `raw as iN as i64 as u64`, then the `wide` mask.
            let ext = sext_imm(v, bits);
            if wide {
                mov_imm64(e, host(dst), ext);
            } else {
                mov_imm32(e, host(dst), ext as i32);
            }
        }

        Decoded::Alu {
            wide,
            op: op @ (AluOp::Lsh | AluOp::Rsh | AluOp::Arsh),
            dst,
            src,
        } => {
            // The count goes through a register even when it is a constant.
            // `LSLV`/`LSRV`/`ASRV` mask it to the operand width in hardware —
            // mod 64 for `X`, mod 32 for `W` — which is exactly the
            // interpreter's `b & 63` / `b & 31`. The constant-shift forms
            // (`UBFM`/`SBFM` aliases, with their inverted immediate fields)
            // would save one instruction and add an encoding class to get
            // wrong.
            let rm = src_reg(e, wide, src);
            let Some(w) = shift_insn(op, wide, host(dst), host(dst), rm) else {
                return Err(JitError::Unsupported {
                    at,
                    what: "unhandled shift operation",
                });
            };
            e.w(w);
        }

        Decoded::Alu {
            wide,
            op: AluOp::Mul,
            dst,
            src,
        } => {
            // `MADD Rd, Rn, Rm, xzr` — the truncating multiply, which is what
            // BPF's is. There is no wide-result register pair to clobber the
            // way x86-64's one-operand `mul` has, so no trap here.
            let rm = src_reg(e, wide, src);
            e.w(sf(MADD_X, wide)
                | ((rm as u32) << 16)
                | ((hr::ZR as u32) << 10)
                | ((host(dst) as u32) << 5)
                | host(dst) as u32);
        }

        Decoded::Div {
            wide,
            signed,
            dst,
            src,
        } => {
            // `SDIV`/`UDIV Rd, Rn, Rm` writes the quotient straight into dst; the
            // hardware already matches BPF for the zero and overflow cases.
            let rm = src_reg(e, wide, src);
            let base = if signed { SDIV_X } else { UDIV_X };
            e.w(shifted_reg(base, wide, host(dst), host(dst), rm));
        }

        Decoded::Mod {
            wide,
            signed,
            dst,
            src,
        } => {
            // No remainder instruction: divide into a scratch, then
            // `MSUB dst, quotient, divisor, dividend` = dividend - quotient*divisor.
            // The quotient lands in ADDR rather than IMM so that an immediate
            // divisor (materialised into IMM by `src_reg`) survives to the MSUB.
            let rm = src_reg(e, wide, src);
            let base = if signed { SDIV_X } else { UDIV_X };
            e.w(shifted_reg(base, wide, hr::ADDR, host(dst), rm));
            e.w(sf(MSUB_X, wide)
                | ((rm as u32) << 16)
                | ((host(dst) as u32) << 10)
                | ((hr::ADDR as u32) << 5)
                | host(dst) as u32);
        }

        Decoded::Neg { wide, dst } => {
            // `NEG Rd, Rd` — `SUB Rd, ZR, Rd`.
            e.w(shifted_reg(SUB_X, wide, host(dst), hr::ZR, host(dst)));
        }

        Decoded::End { dst, order, width } => emit_byteswap(e, at, host(dst), order, width)?,

        Decoded::Alu { wide, op, dst, src } => {
            let Some(base) = alu_base(op) else {
                return Err(JitError::Unsupported {
                    at,
                    what: "unhandled ALU operation",
                });
            };
            let rm = src_reg(e, wide, src);
            e.w(shifted_reg(base, wide, host(dst), host(dst), rm));
        }

        Decoded::Load {
            size,
            sign_extend,
            dst,
            src,
            off,
        } => {
            let (base, disp) = addr_operand(e, host(src), off);
            e.w(ldur_sized(size, sign_extend, host(dst), base, disp));
        }

        Decoded::Store {
            size,
            dst,
            off,
            src: Source::Reg(s),
        } => {
            let (base, disp) = addr_operand(e, host(dst), off);
            e.w(stur_sized(size, host(s), base, disp));
        }

        Decoded::Store {
            size,
            dst,
            off,
            src: Source::Imm(v),
        } => {
            // The stored value is the immediate sign-extended to 64 bits,
            // matching the interpreter's `imm as i64 as u64`; a narrower `STUR*`
            // then keeps only the low bytes. `hr::IMM` holds the value and
            // `hr::ADDR` the address, so the two scratch uses cannot collide.
            mov_imm64(e, hr::IMM, i64::from(v));
            let (base, disp) = addr_operand(e, host(dst), off);
            e.w(stur_sized(size, hr::IMM, base, disp));
        }

        Decoded::Jump { off } => {
            let at_word = e.len();
            e.w(b(0));
            relocs.push(Reloc {
                at: at_word,
                target: (at as i64 + 1 + i64::from(off)) as u32,
                kind: RelKind::B26,
            });
        }

        Decoded::JumpCond {
            wide,
            op,
            dst,
            src,
            off,
        } => {
            // Compare, then branch. `JSET` is `TST` (`ANDS` to `xzr`) instead
            // of `CMP` (`SUBS` to `xzr`).
            let rm = src_reg(e, wide, src);
            let base = if op == CondOp::Set { ANDS_X } else { SUBS_X };
            e.w(shifted_reg(base, wide, hr::ZR, host(dst), rm));
            emit_cond_branch(
                e,
                cond_cc(op),
                (at as i64 + 1 + i64::from(off)) as u32,
                relocs,
            );
        }

        Decoded::Exit => {
            // Branch to the shared epilogue rather than duplicating the
            // restore sequence at every `exit`.
            let at_word = e.len();
            e.w(b(0));
            relocs.push(Reloc {
                at: at_word,
                target: EPILOGUE,
                kind: RelKind::B26,
            });
        }

        // Including `CallTarget::Subprog`: a BPF-to-BPF call needs the frame
        // push the interpreter does in `push_frame`, which is a different
        // feature from entering a C function.
        _ => {
            return Err(JitError::Unsupported {
                at,
                what: "instruction not yet emitted by the aarch64 backend",
            })
        }
    }
    Ok(())
}

/// Record the arena access at `fault_off` as a recoverable site.
///
/// `fixup_off` is zero here and patched to the arena epilogue by [`emit_pass`],
/// which is the only place that knows where it landed. `dst_host_reg` is `None`:
/// an arena fault does not resume into the program, so no destination's value is
/// ever read — zeroing one would be exactly the shape this avoids.
fn record_fault(e: &mut Emit, fault_off: u32) {
    e.faults.push(FaultEntry {
        fault_off,
        fixup_off: 0,
        dst_host_reg: None,
        arena: true,
    });
}
