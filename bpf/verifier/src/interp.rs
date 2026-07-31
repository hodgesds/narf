//! A concrete reference interpreter, for differential testing.
//!
//! This is the whole reason the verifier is a dependency-free crate. An
//! abstract transfer function is only correct if `f#(γ(x)) ⊆ γ(f#(x))` — every
//! concrete result lands in the abstract result — and that is a property you
//! check by *running* the concrete semantics on random inputs and asserting
//! membership. Linux cannot do this: its transfer functions are entangled with
//! `struct bpf_reg_state`, the verifier environment, and a kernel, so its only
//! recourse is `BPF_F_TEST_REG_INVARIANTS`, which checks that its six numeric
//! domains agree with *each other* — not that any of them is sound.
//!
//! Two rules keep this honest:
//!
//!   1. The interpreter is written from the ISA document
//!      (`Documentation/bpf/standardization/instruction-set.rst`), not from the
//!      abstract domain. Where the two share code — division by zero,
//!      `LLONG_MIN / -1`, byte swaps — the shared definition lives in
//!      [`crate::domain`] and is the *concrete* one, so a bug there fails a
//!      test rather than cancelling out.
//!   2. It is deliberately dumb. No bounds inference, no shortcuts: registers
//!      are `u64`, the stack is a byte array, and everything wraps.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::{AluOp, ByteOrder, CondOp, Decoded, Imm64, Insn, Reg, Size, Source};

use crate::domain::{
    concrete_bswap, concrete_sdiv, concrete_sdiv32, concrete_smod, concrete_smod32, concrete_udiv,
    concrete_umod,
};

/// Bytes of stack the reference interpreter provides. R10 points one past the
/// top; offsets are negative.
///
/// Deliberately the same as the verifier's budget, so that "the verifier
/// accepted this stack access" and "the concrete machine can perform it" are
/// the same statement. A smaller concrete stack would make the program-level
/// safety differential report false traps for accesses the verifier was right
/// to allow.
pub const STACK_BYTES: usize = crate::MAX_STACK_BYTES as usize;

/// Address of the context tuple, when a machine is given one.
///
/// Chosen to be nowhere near the stack, which occupies `[0, STACK_BYTES)`, so
/// that "which region is this address in" is a comparison rather than a
/// convention. A machine from [`Machine::new`] has no context and leaves R1 at
/// zero, exactly as before this region existed.
///
/// The context is what a differential test uses to make a value the *verifier*
/// cannot pin — the abstract domain knows only that a context field is some
/// `u64`. Without it every register in a generated program traces back to an
/// immediate, so the verifier constant-folds the whole thing and the interesting
/// transfer functions (a bounded-but-unknown index, in particular) are never
/// reached.
pub const CTX_BASE: u64 = 1 << 32;

/// Why a concrete run stopped early.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Trap {
    /// A load or store left the stack region.
    BadAccess,
    /// A load read a stack byte no store in this run had written.
    ///
    /// Not something a real machine reports — the bytes are simply whatever
    /// was there. It is here because the *verifier* claims a program never
    /// does it ([`crate::VerifyError::UninitStack`]), and a claim with no
    /// concrete counterpart is a claim nothing tests.
    ///
    /// This is the differential counterpart to `Stack`'s per-byte `init`
    /// bits, and it is the only way to catch an abstract write that marks
    /// bytes defined which the concrete store never touched — the exact
    /// failure mode a variable-offset store invites, because the abstract
    /// range covers many bytes and the concrete store covers one width's
    /// worth somewhere inside it.
    UninitRead,
    /// Control left the program.
    BadPc,
    /// A construct the reference interpreter does not model (calls, maps).
    Unsupported,
    /// Fuel ran out — the same outcome the real runtime produces, and the
    /// reason the verifier never has to prove termination.
    OutOfFuel,
}

/// A concrete machine state.
#[derive(Clone, Debug)]
pub struct Machine {
    /// R0..R10.
    pub regs: [u64; 11],
    /// The stack, addressed as `R10 + off` for `off` in `-STACK_BYTES..0`.
    pub stack: Vec<u8>,
    /// The context tuple, as little-endian bytes at [`CTX_BASE`]. Empty unless
    /// the machine was built with one.
    pub ctx: Vec<u8>,
    /// Which stack bytes a store in this run has written.
    ///
    /// A shadow, not part of the machine: the concrete stack is zeroed at
    /// construction and a real one is not, so "reads as zero" is not the same
    /// question as "was written". Keeping the two separate is what lets
    /// [`Trap::UninitRead`] mean something.
    pub defined: Vec<bool>,
    /// Remaining fuel.
    pub fuel: u64,
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Machine {
    /// A machine with zeroed registers and stack.
    #[must_use]
    pub fn new() -> Machine {
        let mut regs = [0u64; 11];
        // R10 is a frame pointer one past the top of the stack; the concrete
        // stack is indexed by `STACK_BYTES + off`, so the numeric value is
        // irrelevant and held at the region size for readability.
        regs[10] = STACK_BYTES as u64;
        Machine {
            regs,
            stack: vec![0u8; STACK_BYTES],
            ctx: Vec::new(),
            defined: vec![false; STACK_BYTES],
            fuel: 1 << 20,
        }
    }

    /// A machine whose R1 points at a context tuple of these words.
    ///
    /// The words are the *only* input to a generated program that the verifier
    /// cannot see through, so this is what turns a differential test from
    /// "does this constant-folded program still work" into "does this hold for
    /// every value the index could take".
    #[must_use]
    pub fn with_ctx(words: &[u64]) -> Machine {
        let mut m = Machine::new();
        m.ctx = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        m.regs[1] = CTX_BASE;
        m
    }

    /// Read from the context, if `addr` names it.
    ///
    /// `None` means "not a context address", which is how the caller knows to
    /// try the stack. A context address that is out of range is a trap rather
    /// than a fallthrough — landing in the stack because the context read
    /// overran would make a bug look like a success.
    fn ctx_load(&self, addr: u64, size: Size) -> Option<Result<u64, Trap>> {
        if addr < CTX_BASE {
            return None;
        }
        let off = (addr - CTX_BASE) as usize;
        let n = size.bytes() as usize;
        let Some(end) = off.checked_add(n).filter(|&e| e <= self.ctx.len()) else {
            return Some(Err(Trap::BadAccess));
        };
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(&self.ctx[off..end]);
        Some(Ok(u64::from_le_bytes(buf)))
    }

    fn slot(&self, addr: u64, size: Size) -> Result<usize, Trap> {
        // Only stack addresses are modelled, and only fully in range.
        let base = addr as i64 - STACK_BYTES as i64;
        let idx = STACK_BYTES as i64 + base;
        if idx < 0 || idx as usize + size.bytes() as usize > STACK_BYTES {
            return Err(Trap::BadAccess);
        }
        Ok(idx as usize)
    }

    fn load(&self, addr: u64, size: Size) -> Result<u64, Trap> {
        if let Some(v) = self.ctx_load(addr, size) {
            return v;
        }
        let i = self.slot(addr, size)?;
        let n = size.bytes() as usize;
        if !self.defined[i..i + n].iter().all(|&d| d) {
            return Err(Trap::UninitRead);
        }
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(&self.stack[i..i + n]);
        Ok(u64::from_le_bytes(buf))
    }

    fn store(&mut self, addr: u64, size: Size, v: u64) -> Result<(), Trap> {
        // The context is read-only to a BPF program — the verifier marks it so
        // — and this machine models no writable region but the stack. A store
        // there is a trap rather than a silent fallthrough into stack indices,
        // which is what the arithmetic would otherwise produce.
        if addr >= CTX_BASE {
            return Err(Trap::BadAccess);
        }
        let i = self.slot(addr, size)?;
        let n = size.bytes() as usize;
        let bytes = v.to_le_bytes();
        self.stack[i..i + n].copy_from_slice(&bytes[..n]);
        self.defined[i..i + n].fill(true);
        Ok(())
    }
}

/// Evaluate a binary ALU operation concretely.
///
/// `wide` selects 64-bit; the 32-bit forms compute on the low half and
/// zero-extend, which is the single rule behind every `ALU` opcode.
#[must_use]
pub fn alu(op: AluOp, wide: bool, dst: u64, src: u64) -> u64 {
    if wide {
        match op {
            AluOp::Add => dst.wrapping_add(src),
            AluOp::Sub => dst.wrapping_sub(src),
            AluOp::Mul => dst.wrapping_mul(src),
            AluOp::Or => dst | src,
            AluOp::And => dst & src,
            AluOp::Xor => dst ^ src,
            AluOp::Lsh => dst << (src & 63),
            AluOp::Rsh => dst >> (src & 63),
            AluOp::Arsh => ((dst as i64) >> (src & 63)) as u64,
        }
    } else {
        let a = dst as u32;
        let b = src as u32;
        let r = match op {
            AluOp::Add => a.wrapping_add(b),
            AluOp::Sub => a.wrapping_sub(b),
            AluOp::Mul => a.wrapping_mul(b),
            AluOp::Or => a | b,
            AluOp::And => a & b,
            AluOp::Xor => a ^ b,
            AluOp::Lsh => a << (b & 31),
            AluOp::Rsh => a >> (b & 31),
            AluOp::Arsh => ((a as i32) >> (b & 31)) as u32,
        };
        u64::from(r)
    }
}

/// Evaluate a division concretely, honouring the ISA's zero and overflow
/// cases (`instruction-set.rst:349-356`).
#[must_use]
pub fn div(wide: bool, signed: bool, dst: u64, src: u64) -> u64 {
    match (wide, signed) {
        (true, false) => concrete_udiv(dst, src),
        (true, true) => concrete_sdiv(dst as i64, src as i64) as u64,
        (false, false) => {
            u64::from(concrete_udiv(u64::from(dst as u32), u64::from(src as u32)) as u32)
        }
        (false, true) => u64::from(concrete_sdiv32(dst as u32 as i32, src as u32 as i32) as u32),
    }
}

/// Evaluate a modulo concretely. Returns the new destination value, which for
/// a zero divisor is the old one (32-bit: the old low half, zero-extended) —
/// `instruction-set.rst:357-362`.
#[must_use]
pub fn rem(wide: bool, signed: bool, dst: u64, src: u64) -> u64 {
    match (wide, signed) {
        (true, false) => concrete_umod(dst, src),
        (true, true) => concrete_smod(dst as i64, src as i64) as u64,
        (false, false) => {
            u64::from(concrete_umod(u64::from(dst as u32), u64::from(src as u32)) as u32)
        }
        (false, true) => u64::from(concrete_smod32(dst as u32 as i32, src as u32 as i32) as u32),
    }
}

/// Evaluate a byte-order conversion concretely.
#[must_use]
pub fn end(order: ByteOrder, width: u8, dst: u64) -> u64 {
    let truncated = match width {
        16 => u64::from(dst as u16),
        32 => u64::from(dst as u32),
        _ => dst,
    };
    match order {
        // NARF, like Linux, is little-endian-only on both supported targets,
        // so "to little" is the identity and "to big" is a swap.
        ByteOrder::Little => truncated,
        ByteOrder::Big | ByteOrder::Swap => concrete_bswap(dst, width),
    }
}

/// Evaluate a conditional-jump predicate concretely.
#[must_use]
pub fn cond(op: CondOp, wide: bool, a: u64, b: u64) -> bool {
    if wide {
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
        let (a, b) = (a as u32, b as u32);
        match op {
            CondOp::Eq => a == b,
            CondOp::Ne => a != b,
            CondOp::Gt => a > b,
            CondOp::Ge => a >= b,
            CondOp::Lt => a < b,
            CondOp::Le => a <= b,
            CondOp::Sgt => (a as i32) > (b as i32),
            CondOp::Sge => (a as i32) >= (b as i32),
            CondOp::Slt => (a as i32) < (b as i32),
            CondOp::Sle => (a as i32) <= (b as i32),
            CondOp::Set => (a & b) != 0,
        }
    }
}

/// Sign-extend the low `bits` of `v`.
#[must_use]
pub fn sext(v: u64, bits: u32) -> u64 {
    if bits >= 64 {
        return v;
    }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

/// Run a program to completion, returning R0.
///
/// Supports the subset the verifier's own tests need: ALU, jumps, stack loads
/// and stores, and `exit`. Calls and maps are [`Trap::Unsupported`] — those
/// belong to the runtime, and modelling them here would mean maintaining a
/// second implementation of the kfunc ABI.
///
/// # Errors
///
/// [`Trap`] on a bad access, a bad program counter, an unmodelled construct,
/// or fuel exhaustion.
pub fn run(prog: &[Insn], m: &mut Machine) -> Result<u64, Trap> {
    let mut pc = 0usize;
    loop {
        if m.fuel == 0 {
            return Err(Trap::OutOfFuel);
        }
        m.fuel -= 1;
        if pc >= prog.len() {
            return Err(Trap::BadPc);
        }
        let (op, width) = narf_bpf_isa::decode(prog, pc).map_err(|_| Trap::Unsupported)?;
        let next = pc + width;
        let val = |m: &Machine, s: Source, wide: bool| -> u64 {
            match s {
                Source::Reg(r) => m.regs[r.as_usize()],
                // An immediate is sign-extended to the operation width, then
                // truncated by the operation itself if it is 32-bit.
                Source::Imm(i) => {
                    if wide {
                        i as i64 as u64
                    } else {
                        u64::from(i as u32)
                    }
                }
            }
        };
        match op {
            Decoded::Alu {
                wide,
                op: a,
                dst,
                src,
            } => {
                let s = val(m, src, wide);
                m.regs[dst.as_usize()] = alu(a, wide, m.regs[dst.as_usize()], s);
                pc = next;
            }
            Decoded::Neg { wide, dst } => {
                let d = m.regs[dst.as_usize()];
                m.regs[dst.as_usize()] = if wide {
                    (d as i64).wrapping_neg() as u64
                } else {
                    u64::from((d as u32).wrapping_neg())
                };
                pc = next;
            }
            Decoded::Mov {
                wide,
                dst,
                src,
                sign_extend,
            } => {
                let s = val(m, src, wide);
                m.regs[dst.as_usize()] = match (sign_extend, wide) {
                    (Some(bits), true) => sext(s, u32::from(bits)),
                    (Some(bits), false) => u64::from(sext(s, u32::from(bits)) as u32),
                    (None, true) => s,
                    (None, false) => u64::from(s as u32),
                };
                pc = next;
            }
            Decoded::Div {
                wide,
                signed,
                dst,
                src,
            } => {
                let s = val(m, src, wide);
                m.regs[dst.as_usize()] = div(wide, signed, m.regs[dst.as_usize()], s);
                pc = next;
            }
            Decoded::Mod {
                wide,
                signed,
                dst,
                src,
            } => {
                let s = val(m, src, wide);
                m.regs[dst.as_usize()] = rem(wide, signed, m.regs[dst.as_usize()], s);
                pc = next;
            }
            Decoded::End { dst, order, width } => {
                m.regs[dst.as_usize()] = end(order, width, m.regs[dst.as_usize()]);
                pc = next;
            }
            Decoded::Load {
                size,
                sign_extend,
                dst,
                src,
                off,
            } => {
                let addr = m.regs[src.as_usize()].wrapping_add(off as i64 as u64);
                let v = m.load(addr, size)?;
                m.regs[dst.as_usize()] = if sign_extend { sext(v, size.bits()) } else { v };
                pc = next;
            }
            Decoded::Store {
                size,
                dst,
                off,
                src,
            } => {
                let addr = m.regs[dst.as_usize()].wrapping_add(off as i64 as u64);
                let v = val(m, src, true);
                m.store(addr, size, v)?;
                pc = next;
            }
            Decoded::LoadImm64 {
                dst,
                value: Imm64::Value(v),
            } => {
                m.regs[dst.as_usize()] = v;
                pc = next;
            }
            Decoded::Jump { off } => {
                pc = (next as i64 + i64::from(off)) as usize;
            }
            Decoded::JumpCond {
                wide,
                op: c,
                dst,
                src,
                off,
            } => {
                let s = val(m, src, wide);
                pc = if cond(c, wide, m.regs[dst.as_usize()], s) {
                    (next as i64 + i64::from(off)) as usize
                } else {
                    next
                };
            }
            Decoded::Exit => return Ok(m.regs[Reg::R0.as_usize()]),
            _ => return Err(Trap::Unsupported),
        }
    }
}
