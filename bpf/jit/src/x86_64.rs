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

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::{decode, AluOp, CondOp, Decoded, Reg, Size, Source};
use narf_bpf_verifier::VerifiedProgram;

use crate::{Compiled, FaultEntry, FaultTable, JitError};

/// Host register numbers, in ModRM/REX encoding order.
mod hr {
    pub const RAX: u8 = 0;
    /// Holds the remaining fuel for the whole program.
    ///
    /// Callee-saved and absent from [`super::REGS`], so no BPF register aliases
    /// it. Note spec §5 earmarks a pinned register for the arena window base;
    /// arena programs are not compiled yet (gate 2), and whichever lands second
    /// picks a different one — `r10`/`r11` are still free.
    pub const R12: u8 = 12;
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
        // rbp/r13 with mod=00 means RIP-relative, so those bases need an
        // explicit displacement byte even when it is zero — without it,
        // `[r13 + 0]` encodes as a RIP-relative load and reads the wrong
        // address entirely.
        //
        // **Currently unreachable through `narf_bpf::jit_glue`**, and mutation
        // testing is how that was discovered: deleting this line broke nothing.
        // The verifier requires stack offsets to be negative (so R10/rbp never
        // has disp 0) and gate 5 restricts load bases to R10 and R1, and R1 is
        // `rdi`. R7 maps to r13 and would reach it, but gate 5 blocks R7.
        //
        // Kept because it is correct and becomes live the moment gate 5
        // relaxes — which happens as soon as map values or kfunc returns are
        // emitted. Covered by `golden_r13_base_needs_a_displacement_byte`,
        // which calls the emitter directly rather than pretending the
        // differential sweep reaches it.
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
            // Masking here is **cosmetic, not load-bearing**: x86 masks the
            // count in hardware (mod 32 for a 32-bit operand, mod 64 with
            // REX.W), so emitting an unmasked count would behave identically.
            // Mutation testing proved it — changing the 32-bit mask to 63 was
            // an *equivalent* mutant that no test could distinguish, because
            // there is nothing to distinguish.
            //
            // Kept so a disassembly reads as the shift the program actually
            // performs rather than one the CPU silently reinterprets. Do not
            // mistake it for a correctness check.
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

/// Reloc target meaning "the out-of-fuel epilogue".
const OOF_EPILOGUE: u32 = u32::MAX - 1;

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
    /// Displacement width in bytes. Always 4 — see `compile`.
    width: u8,
}

/// Instruction indices that begin a basic block.
///
/// Index 0, every branch target, and the instruction after every branch. A
/// pre-pass rather than a real CFG because that is all per-block fuel needs:
/// the count of instructions between one boundary and the next.
fn block_starts(prog: &VerifiedProgram) -> Result<Vec<bool>, JitError> {
    let n = prog.insns.len();
    let mut starts = vec![false; n + 1];
    if n == 0 {
        return Ok(starts);
    }
    starts[0] = true;
    let mut i = 0usize;
    while i < n {
        let (d, width) = decode(&prog.insns, i).map_err(|_| JitError::Decode { at: i as u32 })?;
        let next = i + width;
        let mut mark_target = |off: i64| -> Result<(), JitError> {
            let t = i as i64 + 1 + off;
            if t < 0 || t as usize > n {
                return Err(JitError::BadTarget { at: i as u32 });
            }
            starts[t as usize] = true;
            Ok(())
        };
        match d {
            Decoded::Jump { off } => {
                mark_target(i64::from(off))?;
                if next <= n {
                    starts[next] = true;
                }
            }
            Decoded::JumpCond { off, .. } => {
                mark_target(i64::from(off))?;
                if next <= n {
                    starts[next] = true;
                }
            }
            // `exit` ends a block; whatever follows begins one.
            Decoded::Exit => {
                if next <= n {
                    starts[next] = true;
                }
            }
            _ => {}
        }
        i = next;
    }
    Ok(starts)
}

/// Instructions in the block beginning at `i`.
fn block_len(prog: &VerifiedProgram, starts: &[bool], i: usize) -> u32 {
    let mut count = 0u32;
    let mut k = i;
    while k < prog.insns.len() {
        if k != i && starts[k] {
            break;
        }
        let width = decode(&prog.insns, k).map(|(_, w)| w).unwrap_or(1);
        count += 1;
        k += width;
    }
    count.max(1)
}

/// `sub r12, n` then a branch to the out-of-fuel epilogue on borrow.
///
/// `jb` (borrow) is the right test: `sub` sets CF exactly when the subtrahend
/// exceeds the minuend, i.e. when there was not enough fuel left to pay for
/// this block. Testing the *result* instead would need a comparison and would
/// misread a wrapped value as plenty.
fn emit_fuel_burn(e: &mut Emit, n: u32, relocs: &mut Vec<Reloc>) {
    // sub r12, imm32 — always the imm32 form, so the size does not vary with
    // the block length and cannot perturb offsets.
    e.rex(true, 0, hr::R12);
    e.b(0x81);
    e.modrm_rr(5, hr::R12);
    e.d32(n as i32);
    // jb rel32 -> out-of-fuel epilogue
    e.bs(&[0x0F, 0x82]);
    let at_disp = e.len();
    e.d32(0);
    relocs.push(Reloc {
        at: at_disp,
        next: e.len(),
        target: OOF_EPILOGUE,
        width: 4,
    });
}

/// Compile a verified program.
///
/// A single pass. There is no sizing fixpoint, because every branch this
/// backend emits is `rel32`: nothing shrinks, so nothing needs re-measuring.
///
/// An earlier version ran a convergence loop with a 123-byte short-branch cap
/// copied from `arch/x86/net/bpf_jit_comp.c:70-113`, and the module documented
/// the oscillation bug that cap defends against. That was theatre — the
/// emitter never selected a short encoding, so the loop compared identical
/// lengths, `is_imm8_branch` was never called outside its own test, and the
/// `width == 1` patch arm was unreachable. It has been removed rather than
/// left to imply a mechanism that does not exist.
///
/// If `rel8` selection is ever added, the loop comes back **with** the cap and
/// with a real convergence argument — the Linux post-mortem is a genuine
/// hazard, just not one this code was exposed to.
pub fn compile(prog: &VerifiedProgram) -> Result<Compiled, JitError> {
    let (e, _) = emit_pass(prog)?;
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

/// One sizing/emission pass. Returns the emitter and the offset table this
/// pass produced.
fn emit_pass(prog: &VerifiedProgram) -> Result<(Emit, Vec<u32>), JitError> {
    let mut e = Emit::default();
    let mut relocs: Vec<Reloc> = Vec::new();
    let mut out = Vec::with_capacity(prog.insns.len() + 1);
    let starts = block_starts(prog)?;

    emit_prologue(&mut e, prog);

    let mut i = 0usize;
    while i < prog.insns.len() {
        out.push(e.len());
        // Burn this block's worth of fuel on entry. Per block rather than per
        // instruction: the same bound, one `sub`/`jb` pair instead of one per
        // instruction. The charge is taken *before* the block runs, so a block
        // that cannot be paid for does not execute at all.
        if starts[i] {
            emit_fuel_burn(&mut e, block_len(prog, &starts, i), &mut relocs);
        }
        let (insn, width) =
            decode(&prog.insns, i).map_err(|_| JitError::Decode { at: i as u32 })?;
        emit_insn(&mut e, &insn, i as u32, &mut relocs)?;
        i += width;
        // A wide instruction occupies two slots. This records the *following*
        // instruction's offset for the trailing slot, not the wide
        // instruction's own — which is fine only because nothing can branch
        // there: the verifier rejects a jump into an `LD_IMM64`'s second slot,
        // and `LD_IMM64` is `Unsupported` here anyway so `width` is always 1
        // today. An earlier comment claimed the two slots shared an offset,
        // which the loop order does not do. Whichever is wanted must be
        // decided before LD_IMM64 emission lands.
        for _ in 1..width {
            out.push(e.len());
        }
    }
    out.push(e.len());

    emit_epilogue(&mut e);
    let oof_at = e.len();
    emit_oof_epilogue(&mut e);

    // Patch branch displacements now that every offset is known.
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
    // `rbp` first, and it is not optional: R10 maps to rbp, so the body
    // overwrites it — and rbp is callee-saved in SysV. Omitting it destroyed
    // the *caller's* frame pointer on every invocation, which then misbehaved
    // after the program returned cleanly. Worst failure class there is:
    // executes, corrupts elsewhere, blames someone else.
    for r in [hr::RBP, hr::RBX, hr::R12, hr::R13, hr::R14, hr::R15] {
        if r >= 8 {
            e.b(0x41);
        }
        e.b(0x50 | (r & 7));
    }
    // r12 := rdx (fuel) **before** anything writes rdx, which R3 maps to.
    // Ordering matters for the same reason as the rdi/rsi pair below.
    mov_rr(e, true, hr::R12, hr::RDX);
    // rbp := rdi (frame top), then rdi := rsi (the ctx pointer) so R1 holds
    // the context on entry as the ABI requires.
    mov_rr(e, true, hr::RBP, hr::RDI);
    mov_rr(e, true, hr::RDI, hr::RSI);
}

/// The normal epilogue: `rdx = 0` (fuel intact), restore, return.
fn emit_epilogue(e: &mut Emit) {
    // rdx is the high half of the 128-bit return — the exhaustion flag.
    // Zeroed here so a clean exit is unambiguous.
    e.rex(true, 0, hr::RDX);
    e.b(0x31);
    e.modrm_rr(hr::RDX, hr::RDX);
    emit_restore(e);
}

/// The out-of-fuel epilogue: `rdx = 1`, and `rax` is left as-is (meaningless).
fn emit_oof_epilogue(e: &mut Emit) {
    mov_reg_imm64(e, hr::RDX, 1);
    emit_restore(e);
}

fn emit_restore(e: &mut Emit) {
    for r in [hr::R15, hr::R14, hr::R13, hr::R12, hr::RBX, hr::RBP] {
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

        Decoded::Neg { wide, dst } => {
            // `neg r/m` — F7 /3. Included so the ALU differential sweep can be
            // exhaustive over the operation space rather than skipping a hole.
            e.rex(wide, 0, host(dst));
            e.b(0xF7);
            e.modrm_rr(3, host(dst));
        }

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

        Decoded::Store {
            size: Size::Dw,
            dst,
            off,
            src: Source::Imm(v),
        } => {
            // `mov qword [base + disp], imm32` — C7 /0. The immediate is
            // sign-extended to 64 bits by REX.W, which matches BPF's `ST`
            // semantics (the interpreter does `imm as i64 as u64`).
            e.rex(true, 0, host(dst));
            e.b(0xC7);
            e.modrm_mem(0, host(dst), i32::from(off));
            e.d32(v);
        }

        Decoded::Jump { off } => {
            // Always `rel32`. A short form would save three bytes per branch
            // but requires the sizing fixpoint this backend deliberately does
            // not have — see `compile`.
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
