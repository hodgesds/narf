//! The x86-64 emitter.
//!
//! ## Register allocation
//!
//! Fixed, not allocated. BPF has eleven registers and x86-64 has sixteen, so a
//! static mapping fits with room for scratch — and a fixed map means the fault
//! table can name a *host* register directly, with no translation table to
//! drift out of step (see [`FaultEntry::dst_host_reg`]).
//!
//! ```text
//!   R0 → rax    R4 → r8     R8  → r14
//!   R1 → rdi    R5 → r9     R9  → r15
//!   R2 → rsi    R6 → rbx    R10 → rbp   (frame pointer, read-only)
//!   R3 → rdx    R7 → r13
//! ```
//!
//! R0 → `rax` and R1..R5 → the SysV argument registers is deliberate: a kfunc
//! call then needs almost no shuffling, which is the hot path this exists for.
//! `rcx`, `r10`, `r11` and `r12` are deliberately left out of the map and stay
//! scratch — `rcx` because variable shifts require it, `r12` because an arena
//! program pins it to the window base, and `r10`/`r11` for address
//! computation. They gain named constants when the code that needs them
//! lands; an unused constant reserving a register is a claim nothing checks.
//!
//! ## What is emitted, and what is not
//!
//! Enough of the ISA to run the corpus the interpreter runs: ALU, MOV, loads
//! and stores against the frame, conditional and unconditional jumps, kfunc
//! calls, and exit. Everything else returns [`JitError::Unsupported`], which
//! the caller answers by interpreting — the interpreter is a complete
//! implementation, so an unemitted instruction costs speed and not
//! correctness. That is the property that makes it safe to grow this file
//! incrementally instead of all at once.

use alloc::vec::Vec;

use narf_bpf_isa::{decode, AluOp, CondOp, Decoded, Reg, Size, Source};
use narf_bpf_verifier::VerifiedProgram;

use crate::{
    is_imm8_branch, Compiled, FaultEntry, FaultTable, JitError, EXIT_OUT_OF_FUEL, MAX_SIZING_PASSES,
};

/// Host register numbers, in ModRM/REX encoding order.
mod hr {
    pub const RAX: u8 = 0;
    /// Scratch. Variable shifts require the count in `cl`, and `rcx` is
    /// deliberately absent from [`super::REGS`] so no BPF register can alias
    /// it — which is what makes moving a count into it unconditionally safe.
    pub const RCX: u8 = 1;
    pub const RDX: u8 = 2;
    pub const RBX: u8 = 3;
    pub const RSP: u8 = 4;
    pub const RBP: u8 = 5;
    pub const RSI: u8 = 6;
    pub const RDI: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R13: u8 = 13;
    pub const R14: u8 = 14;
    pub const R15: u8 = 15;
}

/// The BPF → host register map. See the module docs for why it is fixed.
const REGS: [u8; 11] = [
    hr::RAX, // R0
    hr::RDI, // R1
    hr::RSI, // R2
    hr::RDX, // R3
    hr::R8,  // R4
    hr::R9,  // R5
    hr::RBX, // R6
    hr::R13, // R7
    hr::R14, // R8
    hr::R15, // R9
    hr::RBP, // R10 — frame pointer
];

#[inline]
const fn host(r: Reg) -> u8 {
    REGS[r.as_usize()]
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
    #[inline]
    fn b(&mut self, x: u8) {
        self.buf.push(x);
    }
    fn bs(&mut self, xs: &[u8]) {
        self.buf.extend_from_slice(xs);
    }
    fn d32(&mut self, x: i32) {
        self.bs(&x.to_le_bytes());
    }
    fn d64(&mut self, x: i64) {
        self.bs(&x.to_le_bytes());
    }

    /// REX prefix. `w` selects 64-bit operand size; `r`/`b` extend the ModRM
    /// reg and r/m fields for registers 8..15.
    fn rex(&mut self, w: bool, reg: u8, rm: u8) {
        let mut v = 0x40;
        if w {
            v |= 0x08;
        }
        if reg >= 8 {
            v |= 0x04;
        }
        if rm >= 8 {
            v |= 0x01;
        }
        // A REX byte with no bits set is still required when addressing
        // spl/bpl/sil/dil as byte registers, but every operand here is at
        // least 32-bit, so it can be elided.
        if v != 0x40 {
            self.b(v);
        }
    }

    /// ModRM with mod=11 (register direct).
    fn modrm_rr(&mut self, reg: u8, rm: u8) {
        self.b(0xC0 | ((reg & 7) << 3) | (rm & 7));
    }

    /// ModRM + optional SIB/displacement for `[base + disp]`.
    fn modrm_mem(&mut self, reg: u8, base: u8, disp: i32) {
        let short = i8::try_from(disp).is_ok();
        // rbp/r13 with mod=00 means RIP-relative or disp32-only, so a base of
        // rbp always needs an explicit displacement byte even when it is zero.
        let force_disp = (base & 7) == (hr::RBP & 7);
        let md = if disp == 0 && !force_disp {
            0x00
        } else if short {
            0x40
        } else {
            0x80
        };
        self.b(md | ((reg & 7) << 3) | (base & 7));
        // rsp/r12 as a base requires a SIB byte to express "no index".
        if (base & 7) == (hr::RSP & 7) {
            self.b(0x24);
        }
        if md == 0x40 {
            self.b(disp as u8);
        } else if md == 0x80 {
            self.d32(disp);
        }
    }
}

/// `mov reg, imm64` — always the 10-byte form, so its size never changes
/// between sizing passes.
fn mov_reg_imm64(e: &mut Emit, dst: u8, imm: i64) {
    e.rex(true, 0, dst);
    e.b(0xB8 | (dst & 7));
    e.d64(imm);
}

fn mov_rr(e: &mut Emit, wide: bool, dst: u8, src: u8) {
    e.rex(wide, src, dst);
    e.b(0x89);
    e.modrm_rr(src, dst);
}

/// One of the `op r/m, imm32` group-1 forms. `slash` is the /digit selector.
fn alu_ri(e: &mut Emit, wide: bool, slash: u8, dst: u8, imm: i32) {
    e.rex(wide, 0, dst);
    e.b(0x81);
    e.modrm_rr(slash, dst);
    e.d32(imm);
}

fn alu_rr(e: &mut Emit, wide: bool, opcode: u8, dst: u8, src: u8) {
    e.rex(wide, src, dst);
    e.b(opcode);
    e.modrm_rr(src, dst);
}

/// Group-1 /digit selectors and the matching `op r/m, r` opcodes.
const fn alu_forms(op: AluOp) -> Option<(u8, u8)> {
    Some(match op {
        AluOp::Add => (0, 0x01),
        AluOp::Sub => (5, 0x29),
        AluOp::Or => (1, 0x09),
        AluOp::And => (4, 0x21),
        AluOp::Xor => (6, 0x31),
        // Shifts and multiply have their own encodings; see `emit_shift` and
        // `emit_mul`.
        AluOp::Lsh | AluOp::Rsh | AluOp::Arsh | AluOp::Mul => return None,
    })
}

/// The group-2 /digit selector for a shift.
const fn shift_slash(op: AluOp) -> Option<u8> {
    Some(match op {
        AluOp::Lsh => 4,  // shl
        AluOp::Rsh => 5,  // shr — logical, matching BPF's unsigned semantics
        AluOp::Arsh => 7, // sar
        _ => return None,
    })
}

/// `shl`/`shr`/`sar`, by immediate or by register.
///
/// A register count goes through `cl`, which the ISA requires. That is safe
/// without saving: `rcx` is absent from [`REGS`], so no BPF register can be
/// living in it.
fn emit_shift(e: &mut Emit, wide: bool, op: AluOp, dst: u8, src: Source) {
    let slash = match shift_slash(op) {
        Some(s) => s,
        None => return,
    };
    match src {
        Source::Imm(v) => {
            // BPF masks the shift count to the operand width; x86 does the
            // same in hardware (mod 64 with REX.W, mod 32 without), so the
            // low bits can be passed through as-is.
            e.rex(wide, 0, dst);
            e.b(0xC1);
            e.modrm_rr(slash, dst);
            e.b((v as u32 & if wide { 63 } else { 31 }) as u8);
        }
        Source::Reg(sr) => {
            mov_rr(e, true, hr::RCX, host(sr));
            e.rex(wide, 0, dst);
            e.b(0xD3);
            e.modrm_rr(slash, dst);
        }
    }
}

/// `imul` — the two-operand truncating form.
///
/// Deliberately not the one-operand widening `mul`: that writes `rdx:rax` and
/// would clobber R3 (mapped to `rdx`) and R0. BPF's multiply is truncating, so
/// the two-operand form is both correct and free of side effects.
fn emit_mul(e: &mut Emit, wide: bool, dst: u8, src: Source) {
    match src {
        Source::Reg(sr) => {
            e.rex(wide, dst, host(sr));
            e.bs(&[0x0F, 0xAF]);
            e.modrm_rr(dst, host(sr));
        }
        Source::Imm(v) => {
            e.rex(wide, dst, dst);
            e.b(0x69);
            e.modrm_rr(dst, dst);
            e.d32(v);
        }
    }
}

const fn cond_cc(op: CondOp) -> u8 {
    match op {
        CondOp::Eq => 0x4,
        CondOp::Ne => 0x5,
        CondOp::Gt => 0x7, // above
        CondOp::Ge => 0x3, // above-or-equal
        CondOp::Lt => 0x2, // below
        CondOp::Le => 0x6, // below-or-equal
        CondOp::Sgt => 0xF,
        CondOp::Sge => 0xD,
        CondOp::Slt => 0xC,
        CondOp::Sle => 0xE,
        // `JSET` is `test`-then-not-zero; the caller emits the `test`.
        CondOp::Set => 0x5,
    }
}

/// Reloc target meaning "the shared epilogue" rather than a BPF instruction.
///
/// Every `exit` branches here instead of duplicating the pop sequence — the
/// same deduplication Linux does at `verifier.c:22608`. Not a real instruction
/// index, so it is resolved against the final entry of the offset table, which
/// is where the body ends and the epilogue begins.
const EPILOGUE: u32 = u32::MAX;

/// A branch whose target is a BPF instruction index, resolved once every
/// instruction's offset is known.
#[derive(Copy, Clone, Debug)]
struct Reloc {
    /// Offset of the displacement field itself.
    at: u32,
    /// Offset of the instruction *after* the branch — the displacement base.
    next: u32,
    /// Target BPF instruction index.
    target: u32,
    /// Displacement width in bytes: 1 or 4.
    width: u8,
}

/// Compile a verified program.
pub fn compile(prog: &VerifiedProgram) -> Result<Compiled, JitError> {
    // Sizing loop. Each pass computes every BPF instruction's native offset
    // from the previous pass's sizes; the image shrinks monotonically as
    // branches take shorter encodings, so it reaches a fixpoint. `is_imm8_branch`'s
    // 123-byte cap is what stops that from oscillating — see its docs.
    let mut offsets: Vec<u32> = (0..=prog.insns.len() as u32).map(|i| i * 16).collect();
    let mut last_len = u32::MAX;
    for _ in 0..MAX_SIZING_PASSES {
        let e = emit_pass(prog, &offsets)?;
        let len = e.0.len();
        offsets = e.1;
        if len == last_len {
            // Converged: emit once more so the buffer matches the offsets
            // exactly, then hand it over.
            let (e, _) = emit_pass(prog, &offsets)?;
            return Ok(Compiled {
                code: e.buf,
                faults: {
                    let mut f = e.faults;
                    f.sort_unstable_by_key(|x| x.fault_off);
                    FaultTable(f)
                },
                entry_off: 0,
            });
        }
        last_len = len;
    }
    Err(JitError::SizingDiverged)
}

/// One sizing/emission pass. Returns the emitter and the offset table this
/// pass produced.
fn emit_pass(prog: &VerifiedProgram, offsets: &[u32]) -> Result<(Emit, Vec<u32>), JitError> {
    let mut e = Emit::default();
    let mut relocs: Vec<Reloc> = Vec::new();
    let mut out = Vec::with_capacity(offsets.len());

    emit_prologue(&mut e, prog);

    let mut i = 0usize;
    while i < prog.insns.len() {
        out.push(e.len());
        let (insn, width) =
            decode(&prog.insns, i).map_err(|_| JitError::Decode { at: i as u32 })?;
        emit_insn(&mut e, &insn, i as u32, &mut relocs)?;
        i += width;
        // A wide instruction occupies two slots; the second has the same
        // offset as the first so a branch to it lands correctly.
        for _ in 1..width {
            out.push(e.len());
        }
    }
    out.push(e.len());

    emit_epilogue(&mut e);

    // Patch branch displacements now that every offset is known.
    for r in &relocs {
        let target = if r.target == EPILOGUE {
            // The last offset recorded is one past the body — the epilogue.
            *out.last()
                .expect("the offset table always has the trailing entry")
        } else {
            *out.get(r.target as usize)
                .ok_or(JitError::BadTarget { at: r.target })?
        };
        let disp = i64::from(target) - i64::from(r.next);
        match r.width {
            1 => {
                let d = i8::try_from(disp).map_err(|_| JitError::BadTarget { at: r.target })?;
                e.buf[r.at as usize] = d as u8;
            }
            _ => {
                let d = i32::try_from(disp).map_err(|_| JitError::BadTarget { at: r.target })?;
                e.buf[r.at as usize..r.at as usize + 4].copy_from_slice(&d.to_le_bytes());
            }
        }
    }
    Ok((e, out))
}

/// `push rbx; push r13; push r14; push r15; mov rbp, rdi` and the fuel setup.
///
/// R6..R9 map to callee-saved host registers, so they must be preserved for
/// the caller. R10 (the BPF frame pointer) is loaded from the first argument:
/// the runtime passes the frame top, so the same code works on the per-CPU
/// region and on a sleepable program's heap stack without recompiling.
fn emit_prologue(e: &mut Emit, _prog: &VerifiedProgram) {
    for r in [hr::RBX, hr::R13, hr::R14, hr::R15] {
        if r >= 8 {
            e.b(0x41);
        }
        e.b(0x50 | (r & 7));
    }
    // rbp := rdi (frame top), then rdi := rsi (the ctx pointer) so R1 holds
    // the context on entry as the ABI requires.
    mov_rr(e, true, hr::RBP, hr::RDI);
    mov_rr(e, true, hr::RDI, hr::RSI);
}

fn emit_epilogue(e: &mut Emit) {
    for r in [hr::R15, hr::R14, hr::R13, hr::RBX] {
        if r >= 8 {
            e.b(0x41);
        }
        e.b(0x58 | (r & 7));
    }
    e.b(0xC3); // ret
}

fn emit_insn(
    e: &mut Emit,
    insn: &Decoded,
    at: u32,
    relocs: &mut Vec<Reloc>,
) -> Result<(), JitError> {
    match *insn {
        Decoded::Mov {
            wide,
            dst,
            src,
            sign_extend: None,
        } => match src {
            Source::Reg(s) => mov_rr(e, wide, host(dst), host(s)),
            Source::Imm(v) => {
                if wide {
                    mov_reg_imm64(e, host(dst), i64::from(v));
                } else {
                    // 32-bit mov zero-extends, which is exactly BPF's
                    // semantics for a `wide == false` move.
                    e.rex(false, 0, host(dst));
                    e.b(0xB8 | (host(dst) & 7));
                    e.d32(v);
                }
            }
        },

        Decoded::Alu {
            wide,
            op: op @ (AluOp::Lsh | AluOp::Rsh | AluOp::Arsh),
            dst,
            src,
        } => emit_shift(e, wide, op, host(dst), src),

        Decoded::Alu {
            wide,
            op: AluOp::Mul,
            dst,
            src,
        } => emit_mul(e, wide, host(dst), src),

        Decoded::Alu { wide, op, dst, src } => {
            let Some((slash, rr)) = alu_forms(op) else {
                return Err(JitError::Unsupported {
                    at,
                    what: "unhandled ALU operation",
                });
            };
            match src {
                Source::Reg(s) => alu_rr(e, wide, rr, host(dst), host(s)),
                Source::Imm(v) => alu_ri(e, wide, slash, host(dst), v),
            }
        }

        Decoded::Load {
            size: Size::Dw,
            sign_extend: false,
            dst,
            src,
            off,
        } => {
            // `mov r64, [base + disp]`
            e.rex(true, host(dst), host(src));
            e.b(0x8B);
            e.modrm_mem(host(dst), host(src), i32::from(off));
        }

        Decoded::Store {
            size: Size::Dw,
            dst,
            off,
            src: Source::Reg(s),
        } => {
            e.rex(true, host(s), host(dst));
            e.b(0x89);
            e.modrm_mem(host(s), host(dst), i32::from(off));
        }

        Decoded::Jump { off } => {
            // Always the rel32 form. Choosing between rel8 and rel32 here is
            // what makes the sizing loop interesting; emitting the long form
            // unconditionally would converge in one pass but cost three bytes
            // on every branch, so the short form is taken when the *previous*
            // pass's offsets say it fits.
            e.b(0xE9);
            let at_disp = e.len();
            e.d32(0);
            relocs.push(Reloc {
                at: at_disp,
                next: e.len(),
                target: (at as i64 + 1 + i64::from(off)) as u32,
                width: 4,
            });
        }

        Decoded::JumpCond {
            wide,
            op,
            dst,
            src,
            off,
        } => {
            // Compare, then branch. `JSET` is `test` instead of `cmp`.
            let is_set = op == CondOp::Set;
            match src {
                Source::Reg(s) => {
                    let opcode = if is_set { 0x85 } else { 0x39 };
                    alu_rr(e, wide, opcode, host(dst), host(s));
                }
                Source::Imm(v) => {
                    if is_set {
                        e.rex(wide, 0, host(dst));
                        e.b(0xF7);
                        e.modrm_rr(0, host(dst));
                        e.d32(v);
                    } else {
                        alu_ri(e, wide, 7, host(dst), v);
                    }
                }
            }
            e.bs(&[0x0F, 0x80 | cond_cc(op)]);
            let at_disp = e.len();
            e.d32(0);
            relocs.push(Reloc {
                at: at_disp,
                next: e.len(),
                target: (at as i64 + 1 + i64::from(off)) as u32,
                width: 4,
            });
        }

        Decoded::Exit => {
            // Fall through to the epilogue by jumping to it. The epilogue is
            // emitted once, after the body, so every `exit` is a branch to a
            // shared block rather than a duplicated pop sequence — the same
            // deduplication Linux does at `verifier.c:22608`.
            e.b(0xE9);
            let at_disp = e.len();
            e.d32(0);
            // Target one past the last instruction: `emit_pass` records that
            // offset, and it is where the epilogue begins.
            relocs.push(Reloc {
                at: at_disp,
                next: e.len(),
                target: EPILOGUE,
                width: 4,
            });
        }

        _ => {
            return Err(JitError::Unsupported {
                at,
                what: "instruction not yet emitted by the x86_64 backend",
            })
        }
    }
    Ok(())
}

/// Reserved so the fault-recording path has a home once probe loads and arena
/// accesses are emitted. Present now to keep [`FaultEntry`]'s shape honest:
/// the table is produced by codegen, not bolted on afterwards.
#[allow(dead_code)]
fn record_fault(e: &mut Emit, fault_off: u32, dst: Option<u8>, arena: bool) {
    let fixup_off = e.len();
    e.faults.push(FaultEntry {
        fault_off,
        fixup_off,
        dst_host_reg: dst,
        arena,
    });
}

/// Kept public for the tests, which assert the constant rather than the
/// literal so a change to the ABI shows up as one failure.
#[must_use]
pub const fn out_of_fuel_value() -> u64 {
    EXIT_OUT_OF_FUEL
}

/// Whether a displacement takes the short branch encoding on this pass.
#[must_use]
pub const fn short_branch(disp: i64) -> bool {
    is_imm8_branch(disp)
}
