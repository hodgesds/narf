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
//! `rcx`, `r10`, `r11` and `r12` are deliberately left out of the map — `rcx`
//! because variable shifts require it, `r12` because it holds the fuel counter
//! (see [`hr::R12`]), and `r11` because a call target's absolute address has to
//! be materialised somewhere ([`hr::R11`]). `r10` still has no named constant;
//! an unused constant reserving a register is a claim nothing checks.
//!
//! This paragraph used to say `r12` was reserved "because an arena program pins
//! it to the window base", contradicting [`hr::R12`] two screens down. Worth
//! recording *why* that is not merely a typo to swap back: the map leaves **no
//! callee-saved register free**. rbx, rbp and r13..r15 are BPF R6..R10, r12 is
//! fuel, and Linux's choice of `r12` for the arena base is unavailable here for
//! exactly that reason. A pinned arena base therefore has to come from
//! somewhere — a seventh saved slot reloaded per access, or a re-balanced map —
//! and that decision belongs with the code that needs it, not with a comment
//! claiming a register is already spoken for.
//!
//! **It came from the first of those.** The arena base arrives as the fourth
//! entry argument in `rcx` and the prologue parks it in the 8-byte slot it
//! already claims for SysV alignment ([`STACK_ALIGN_PAD`]); an arena access
//! reloads it into `r11` and uses `rcx` as the index. Both are caller-saved,
//! which would be fatal for a *pinned* base and is irrelevant for one reloaded
//! per access — and it is why the frame shape does not change at all, so a
//! program with no arena pays nothing.
//!
//! **Kfunc calls needed none of that.** The register pressure that blocks a
//! pinned arena base does not touch call emission, and the reason is worth
//! stating because the two look like the same problem: a call needs *scratch*,
//! which is caller-saved and plentiful, while an arena base needs a value that
//! survives a call, which is callee-saved and exhausted. BPF's own ABI then
//! does the rest — R1..R5 are caller-saved by definition and R0 takes the
//! result, and those are exactly the registers SysV lets a callee destroy. So
//! nothing is saved around a call and nothing is reloaded after one.
//!
//! ## What is emitted, and what is not
//!
//! Enough of the ISA to run the corpus the interpreter runs: ALU, MOV, loads
//! and stores against the frame, conditional and unconditional jumps, exit, and
//! **kfunc calls**. Subprogram calls (`CallTarget::Subprog`) are still refused:
//! they need the BPF frame push the interpreter does in `push_frame`, which is
//! a different feature from entering a C function.
//!
//! Everything else returns [`JitError::Unsupported`], which the caller answers
//! by interpreting — the interpreter is a complete implementation, so an
//! unemitted instruction costs speed and not correctness. That is the property
//! that makes it safe to grow this file incrementally instead of all at once.
//!
//! ## The arena access shape
//!
//! A kfunc return is the verifier's only producer of `PtrClass::Arena`, so
//! until call emission landed *no* arena program reached any arena lowering — it
//! was refused at the call — and `jit_glue`'s gate 2 was then the only thing
//! between an arena program and a bare dereference of a slot-relative handle.
//! Both are now gone, and this is what replaced them:
//!
//! ```text
//!   mov  r11, [rsp]              ; the slot base the prologue parked
//!   mov  ecx, <handle>d          ; zero-extend — see below
//!   add  rcx, <off16>            ; fold the displacement into the index
//!   mov  <dst>, [r11 + rcx]      ; the faulting instruction
//! ```
//!
//! The 32-bit `mov` is not an optimisation. It bounds the index to `[0, 2^32)`
//! *in the emitted bytes*, so the address is inside the slot's guards whatever
//! the register holds — the reachable-set argument becomes a property of this
//! sequence rather than one inherited from the verifier. `ARENA_USABLE_BYTES`
//! is 4 GiB, so no handle that names a real arena byte is affected.
//!
//! Folding the displacement into `rcx` rather than leaving it in the ModRM
//! displacement costs one instruction and buys the diagnostic: at the fault,
//! `rcx` holds exactly the handle the interpreter would have computed, and
//! [`emit_arena_epilogue`] returns it. Without that the trap could only report a
//! zero, and `Trap::ArenaOutOfBounds` exists to name the offending value.
//!
//! `an_arena_program_reaches_its_arena_access_once_the_call_is_emitted` used to
//! show the bare dereference in bytes and now shows this shape instead.

use alloc::vec::Vec;

use narf_bpf_isa::{
    decode, AluOp, AtomicOp, ByteOrder, CallTarget, CondOp, Decoded, Imm64, Reg, Size, Source,
};
use narf_bpf_verifier::{Context, KfuncCallSite, VerifiedProgram};

use crate::blocks::{block_len, block_starts};
use crate::{status, Compiled, FaultEntry, FaultTable, JitError};

/// Host register numbers, in ModRM/REX encoding order.
mod hr {
    pub const RAX: u8 = 0;
    /// Holds the remaining fuel for the whole program.
    ///
    /// Callee-saved and absent from [`super::REGS`], so no BPF register aliases
    /// it. Spec §5 earmarks a pinned register for the arena window base and
    /// Linux uses `r12` for it, but here `r12` is taken and every other
    /// callee-saved register is a BPF register — see the module docs. `r10` is
    /// free but caller-saved, so it would survive an arena access and not a
    /// kfunc call; `r11` is likewise caller-saved and now spoken for by
    /// [`R11`].
    pub const R12: u8 = 12;
    /// Scratch for a call target's absolute address.
    ///
    /// Caller-saved, which is exactly right here: its value is consumed by the
    /// `call` that reads it and is never wanted afterwards, so the callee is
    /// welcome to destroy it. Absent from [`super::REGS`], so materialising an
    /// address into it cannot be clobbering a BPF register — the same argument
    /// [`RCX`] rests on.
    pub const R11: u8 = 11;
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
    fn d16(&mut self, x: i16) {
        self.bs(&x.to_le_bytes());
    }
    fn d32(&mut self, x: i32) {
        self.bs(&x.to_le_bytes());
    }
    fn d64(&mut self, x: i64) {
        self.bs(&x.to_le_bytes());
    }

    /// Emit a `jcc`/`jmp rel8` with a zero displacement and return the offset of
    /// the displacement byte, to be resolved later by [`Emit::patch_rel8`]. Used
    /// only for the short forward branches *within* a single instruction's
    /// lowering (the `div`/`mod` guards), whose targets are a handful of bytes
    /// away — never for inter-instruction control flow, which the reloc table
    /// resolves as `rel32`.
    fn jmp_rel8(&mut self, opcode: u8) -> u32 {
        self.b(opcode);
        let at = self.len();
        self.b(0);
        at
    }

    /// Fill in the `rel8` displacement of a branch whose byte was reserved by
    /// [`Emit::jmp_rel8`], now that its target is the current end of the buffer.
    fn patch_rel8(&mut self, at: u32) {
        let rel = self.buf.len() as i64 - (at as i64 + 1);
        debug_assert!(
            (-128..=127).contains(&rel),
            "rel8 branch target out of reach: {rel}"
        );
        self.buf[at as usize] = rel as i8 as u8;
    }

    /// A REX prefix like [`Emit::rex`], but emitted even when it would be the
    /// bare `0x40` — which a byte store of `spl`/`bpl`/`sil`/`dil` requires to
    /// name the low byte rather than `ah`/`ch`/`dh`/`bh`.
    fn rex_forced(&mut self, w: bool, reg: u8, rm: u8, force: bool) {
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
        if v != 0x40 || force {
            self.b(v);
        }
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

    /// ModRM + SIB for `[base + index]`, scale 1, no displacement.
    ///
    /// The arena addressing mode, and the only place this backend emits an
    /// index. `mod = 00` with `rm = 100` selects a SIB byte; the SIB's own
    /// `base = 101` would mean "no base, disp32", so a base whose low three
    /// bits are `rbp`'s cannot be encoded this way — which is fine and asserted
    /// rather than assumed, because [`emit_arena_addr`] always passes
    /// [`hr::R11`].
    fn modrm_sib_index(&mut self, reg: u8, base: u8, index: u8) {
        debug_assert!(
            (base & 7) != (hr::RBP & 7),
            "mod=00 SIB cannot encode an rbp/r13 base"
        );
        debug_assert!(
            (index & 7) != (hr::RSP & 7),
            "SIB index 100 means no index at all"
        );
        // `rex` has no X bit, so an index of 8..15 would silently encode as its
        // low three bits. Never reached — the index is always `rcx` — but a
        // future second caller must not discover that the hard way.
        debug_assert!(index < 8, "REX.X is not emitted, so the index must be 0..7");
        self.b(((reg & 7) << 3) | 0x04);
        self.b(((index & 7) << 3) | (base & 7));
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

/// BPF `div`/`mod`, lowered to x86 `div`/`idiv`.
///
/// x86 division is hardwired to `rdx:rax` — quotient to `rax`, remainder to
/// `rdx` — and both alias BPF registers (R0, R3), so they are saved on the stack
/// around the sequence and the result is carried out through `r11`. `rcx` holds
/// the divisor; neither `rcx`, `r11` nor `r12` (fuel) aliases a BPF register, so
/// only the destination is disturbed. The `push`/`pop` are balanced within this
/// one instruction and it contains no call, arena access or fuel check, so the
/// "the body never moves `rsp`" invariant the fault epilogues rest on holds.
///
/// The two hardware traps are branched around rather than taken, matching the
/// interpreter (and Linux): divide-by-zero yields a zero quotient and the
/// dividend unchanged as the remainder, and the signed `INT_MIN / -1` overflow
/// is the wrapping identity `x / -1 == -x`, `x % -1 == 0`.
fn emit_div_mod(e: &mut Emit, wide: bool, signed: bool, want_rem: bool, dst: u8, src: Source) {
    // Divisor into rcx first, while every BPF register still holds its value —
    // src may be R0 (rax) or R3 (rdx), which the steps below overwrite.
    match src {
        Source::Reg(s) => mov_rr(e, wide, hr::RCX, host(s)),
        Source::Imm(v) => emit_mov_imm(e, wide, hr::RCX, i64::from(v)),
    }
    // Preserve rax and rdx; the divide overwrites both.
    e.b(0x50 | hr::RAX); // push rax
    e.b(0x50 | hr::RDX); // push rdx
                         // Dividend into rax. A 32-bit move zero-extends, leaving eax as the low half
                         // and edx set below; a 64-bit move takes the whole register.
    mov_rr(e, wide, hr::RAX, dst);

    let result = if want_rem { hr::RDX } else { hr::RAX };

    // Divide-by-zero guard: `test` the divisor, branch away if it is zero.
    alu_rr(e, wide, 0x85, hr::RCX, hr::RCX);
    let to_divzero = e.jmp_rel8(0x74); // jz divzero

    let to_neg_one = if signed {
        // `x / -1` overflows `idiv` for x == INT_MIN, so the whole `-1` divisor
        // case is handled as the wrapping identity instead of dividing.
        alu_ri(e, wide, 7, hr::RCX, -1); // cmp rcx, -1
        Some(e.jmp_rel8(0x74)) // je neg_one
    } else {
        None
    };

    if signed {
        // Sign-extend rax into rdx (cdq/cqo), then idiv.
        if wide {
            e.b(0x48);
        }
        e.b(0x99);
        e.rex(wide, 0, hr::RCX);
        e.b(0xF7);
        e.modrm_rr(7, hr::RCX); // idiv rcx
    } else {
        // Zero rdx (a 32-bit xor clears the whole register), then div.
        alu_rr(e, false, 0x31, hr::RDX, hr::RDX);
        e.rex(wide, 0, hr::RCX);
        e.b(0xF7);
        e.modrm_rr(6, hr::RCX); // div rcx
    }
    let to_done_from_div = e.jmp_rel8(0xEB); // jmp done

    // divzero: quotient 0, remainder = dividend (still in rax).
    e.patch_rel8(to_divzero);
    if want_rem {
        mov_rr(e, wide, hr::RDX, hr::RAX);
    } else {
        alu_rr(e, false, 0x31, hr::RAX, hr::RAX); // xor eax, eax
    }
    let to_done_from_divzero = signed.then(|| e.jmp_rel8(0xEB)); // jmp done (skip neg_one)

    // neg_one (signed only): quotient = -dividend, remainder 0.
    if let Some(at) = to_neg_one {
        e.patch_rel8(at);
        if want_rem {
            alu_rr(e, false, 0x31, hr::RDX, hr::RDX); // xor edx, edx
        } else {
            e.rex(wide, 0, hr::RAX);
            e.b(0xF7);
            e.modrm_rr(3, hr::RAX); // neg rax
        }
    }

    // done: carry the result out past the pops, restore, and land it in dst.
    e.patch_rel8(to_done_from_div);
    if let Some(at) = to_done_from_divzero {
        e.patch_rel8(at);
    }
    mov_rr(e, wide, hr::R11, result);
    e.b(0x58 | hr::RDX); // pop rdx
    e.b(0x58 | hr::RAX); // pop rax
    mov_rr(e, wide, dst, hr::R11);
}

/// A BPF atomic against a certified base (stack or context), lowered to the
/// x86 locked read-modify-write instructions.
///
/// The memory operand is `[base + off]`, the same addressing every stack access
/// uses. Widths are word and doubleword only (the ISA has no narrower atomic),
/// so no byte-register REX hazard arises. `LOCK` (`0xF0`) prefixes the
/// non-implicitly-locked forms; `xchg` with a memory operand locks on its own.
///
/// The fetching bitwise forms (`fetch` on or/and/xor) are **not** emitted: x86
/// has no atomic fetch-and-{or,and,xor}, only a `cmpxchg` retry loop, so they
/// stay interpreted — [`smoke_bpf_jit_fuzz_unlowered_shapes_still_fall_back`]
/// pins that boundary. Every other form is one instruction.
fn emit_atomic(
    e: &mut Emit,
    at: u32,
    size: Size,
    op: AtomicOp,
    dst: Reg,
    off: i16,
    src: Reg,
) -> Result<(), JitError> {
    let wide = size == Size::Dw;
    let m = host(dst);
    let s = host(src);
    let disp = i32::from(off);
    // `lock; <op> [m + disp], s` for the group-1 read-modify-writes.
    let locked_rmw = |e: &mut Emit, opcode: u8| {
        e.b(0xF0);
        e.rex(wide, s, m);
        e.b(opcode);
        e.modrm_mem(s, m, disp);
    };
    match op {
        AtomicOp::Add { fetch: false } => locked_rmw(e, 0x01),
        AtomicOp::Or { fetch: false } => locked_rmw(e, 0x09),
        AtomicOp::And { fetch: false } => locked_rmw(e, 0x21),
        AtomicOp::Xor { fetch: false } => locked_rmw(e, 0x31),
        // `lock; xadd [m], s` — s receives the pre-op value, m gets m + s. A
        // 32-bit form zero-extends s, matching the interpreter's `mask`.
        AtomicOp::Add { fetch: true } => {
            e.b(0xF0);
            e.rex(wide, s, m);
            e.bs(&[0x0F, 0xC1]);
            e.modrm_mem(s, m, disp);
        }
        // `xchg [m], s` — implicitly locked; s receives the old value.
        AtomicOp::Xchg => {
            e.rex(wide, s, m);
            e.b(0x87);
            e.modrm_mem(s, m, disp);
        }
        // `lock; cmpxchg [m], s` — compares rax (R0) with m; on equal stores s,
        // otherwise loads m into rax. That is exactly BPF cmpxchg: R0 is the
        // comparand and receives the pre-op value.
        AtomicOp::Cmpxchg => {
            e.b(0xF0);
            e.rex(wide, s, m);
            e.bs(&[0x0F, 0xB1]);
            e.modrm_mem(s, m, disp);
        }
        // x86 loads are acquire and stores are release under TSO, so these are
        // plain moves into / out of the source register.
        AtomicOp::LoadAcquire => {
            e.rex(wide, s, m);
            e.b(0x8B);
            e.modrm_mem(s, m, disp);
        }
        AtomicOp::StoreRelease => {
            e.rex(wide, s, m);
            e.b(0x89);
            e.modrm_mem(s, m, disp);
        }
        AtomicOp::Or { fetch: true }
        | AtomicOp::And { fetch: true }
        | AtomicOp::Xor { fetch: true } => {
            return Err(JitError::Unsupported {
                at,
                what:
                    "fetching bitwise atomic needs a cmpxchg loop the x86_64 backend does not emit",
            })
        }
    }
    Ok(())
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

/// Where the prologue parks the arena slot base, relative to `rsp`.
///
/// The [`STACK_ALIGN_PAD`] slot, reused rather than added to. A second 8-byte
/// slot would move `rsp` by 64 instead of 56 across the prologue, which is
/// `0 mod 16` again and would put the residue back where SysV does not want it —
/// so a dedicated slot would have cost 16 bytes and a re-derivation of the
/// alignment argument, for a value that is read at most once per arena access.
///
/// `rsp` does not move between the prologue and any access: a `call` pushes its
/// return address *below* this slot and the callee's whole frame is below that,
/// so the parked base survives a kfunc call untouched.
const ARENA_BASE_SLOT: i32 = 0;

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
    // Which accesses take the arena shape. Built from the verifier's fault
    // sites by the same function `jit_glue`'s gate 5 uses, so the gate and the
    // emitter cannot disagree — see [`crate::arena_access_map`].
    let arena = crate::arena_access_map(prog);

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
        emit_insn(
            &mut e,
            &insn,
            i as u32,
            &mut relocs,
            &prog.kfunc_calls,
            arena[i],
        )?;
        i += width;
        // A wide instruction (`LD_IMM64`) occupies two slots. Its own offset is
        // `out[i]`, recorded above; this records the *following* instruction's
        // offset for the trailing slot. That is sound because nothing branches
        // there — the verifier rejects a jump into an `LD_IMM64`'s second slot —
        // and it keeps `out` indexed one entry per slot, which is what the reloc
        // patcher assumes.
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
    // instruction. Patched here, unconditionally, rather than recorded at the
    // access: the epilogue's offset is not known until the body is emitted, and
    // a per-site "remember to fix this up" is the kind of step that gets
    // forgotten. Anything left holding a next-instruction fixup would be a
    // zero-and-continue, which is the exact divergence the arena shape exists to
    // avoid.
    for f in &mut e.faults {
        if f.arena {
            f.fixup_off = arena_at;
        }
    }

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

/// Bytes the prologue subtracts from `rsp` purely to satisfy SysV's alignment
/// rule, on top of the register saves.
///
/// SysV requires `rsp % 16 == 0` **at the point a `call` executes**, so a
/// function sees `rsp % 16 == 8` on entry. This image is such a function: it is
/// entered at 8, and the six pushes below move `rsp` by 48 — a multiple of 16 —
/// so they leave it at 8. A `call` from the body would then enter a kfunc with
/// the alignment inverted, which is the class of bug that shows up as a
/// `movaps` fault somewhere inside the callee rather than anywhere near here.
/// One more 8-byte step puts the whole body at 0.
///
/// Derived, not copied: a note this work started from claimed six pushes were
/// wrong and that "+48" fixed it. 48 is what the pushes already move `rsp` by
/// and it is `0 mod 16`, so it changes nothing. The residue is what matters, and
/// `the_prologue_leaves_the_stack_aligned_for_a_sysv_call` re-derives it from
/// the emitted bytes rather than trusting either number.
///
/// Emitted unconditionally rather than only for programs containing a call: a
/// prologue whose frame shape depends on the body is two shapes to reason about
/// and two to test, for one instruction that executes once per invocation.
const STACK_ALIGN_PAD: i32 = 8;

/// `sub rsp, imm8` / `add rsp, imm8` — the group-1 sign-extended-imm8 forms.
fn emit_rsp_adjust(e: &mut Emit, slash: u8, imm: i32) {
    e.rex(true, 0, hr::RSP);
    e.b(0x83);
    e.modrm_rr(slash, hr::RSP);
    e.b(imm as u8);
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
    // `sub rsp, 8` — see [`STACK_ALIGN_PAD`]. Released by `emit_restore`.
    emit_rsp_adjust(e, 5, STACK_ALIGN_PAD);
    // Park the arena slot base (SysV arg 4, `rcx`) in that slot, **before**
    // anything writes `rcx` — `emit_shift` and `emit_kfunc_call` both do. See
    // [`ARENA_BASE_SLOT`]. Emitted unconditionally, for the same reason the pad
    // itself is: one store per invocation is cheaper than two prologue shapes to
    // reason about, and a program with no arena simply never reads it back.
    e.rex(true, hr::RCX, hr::RSP);
    e.b(0x89);
    e.modrm_mem(hr::RCX, hr::RSP, ARENA_BASE_SLOT);
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
    mov_reg_imm64(e, hr::RDX, status::OUT_OF_FUEL as i64);
    emit_restore(e);
}

/// The arena-fault epilogue: `rdx = 2`, `rax = rcx` (the offending handle).
///
/// Reached only through the exception table — nothing branches here — so the
/// stack is exactly as the faulting instruction left it, which is the state
/// [`emit_restore`] expects. That is the whole reason the fixup can be a plain
/// resume address with no per-site stub: the body never moves `rsp`.
///
/// **Not** Linux's `ex_handler_bpf` shape, and deliberately. Zeroing the
/// destination and resuming would make an out-of-bounds arena access *return a
/// value* natively and `Trap::ArenaOutOfBounds` interpreted — the same program
/// with two verdicts, decided by whether it happened to clear `jit_glue`'s
/// gates. `rcx` still holds the handle because [`emit_arena_addr`] folded the
/// displacement into it, so the trap names the value instead of inferring it.
fn emit_arena_epilogue(e: &mut Emit) {
    mov_rr(e, true, hr::RAX, hr::RCX);
    mov_reg_imm64(e, hr::RDX, status::ARENA_FAULT as i64);
    emit_restore(e);
}

fn emit_restore(e: &mut Emit) {
    // `add rsp, 8` — undo [`STACK_ALIGN_PAD`] before the pops, or every one of
    // them would read the wrong slot.
    emit_rsp_adjust(e, 0, STACK_ALIGN_PAD);
    for r in [hr::R15, hr::R14, hr::R13, hr::R12, hr::RBX, hr::RBP] {
        if r >= 8 {
            e.b(0x41);
        }
        e.b(0x58 | (r & 7));
    }
    e.b(0xC3); // ret
}

/// The whole of a kfunc call: the SysV shuffle, the target, and the `call`.
///
/// BPF passes arguments in R1..R5; SysV passes them in `rdi`, `rsi`, `rdx`,
/// `rcx`, `r8`. The register map lines the first three up exactly — that is the
/// reason it was chosen — so only the last two move, and the order they move in
/// is load-bearing: `rcx` must take `r8`'s value **before** `r8` takes `r9`'s,
/// or R4 is overwritten by R5 and lost. Writing the two moves the other way
/// round produces code that assembles, runs, and passes the wrong argument.
///
/// Nothing is saved. Every register SysV lets the callee destroy —
/// `rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`..`r11` — holds either a BPF register
/// the BPF ABI *also* declares caller-saved (R0..R5) or nothing. R6..R10 and
/// the fuel counter live in `rbx`, `r13`..`r15`, `rbp` and `r12`, all of which
/// SysV requires the callee to preserve.
///
/// The address is materialised into `r11` rather than encoded as a `call rel32`
/// displacement, because the JIT does not know where its own text will land
/// when it emits — `bpf_text::alloc` chooses the VA afterwards — so a
/// PC-relative target is not expressible at emission time and a fixup pass would
/// buy nothing but a fixup pass.
fn emit_kfunc_call(e: &mut Emit, addr: usize) {
    mov_rr(e, true, hr::RCX, hr::R8); // SysV arg3 := BPF R4
    mov_rr(e, true, hr::R8, hr::R9); // SysV arg4 := BPF R5
    mov_reg_imm64(e, hr::R11, addr as i64);
    // `call r11` — FF /2. REX.B for the high register; no REX.W, because a
    // near call is 64-bit by default in long mode.
    e.rex(false, 0, hr::R11);
    e.b(0xFF);
    e.modrm_rr(2, hr::R11);
}

/// The call site the verifier resolved for the `call` at `at`, or a refusal.
///
/// Every arm here is fail-closed and every one is reachable through a
/// `VerifiedProgram` that some caller could hand this crate, so none of them is
/// a `debug_assert`:
///
/// * **no entry** — the fixpoint never reached this instruction, so nobody
///   type-checked its arguments. Dead code, and there is no target to invent.
/// * **id mismatch** — the table describes a different callee than the
///   instruction names. Emitting either one would be a guess.
/// * **sleepable** — that kfunc's shim returns a boxed future rather than a
///   `u64` (see `narf_bpf::kfunc::KfuncShim`), so entering it through the
///   uniform ABI would reinterpret a `Pin<Box<dyn Future>>` as a return value.
///   The *program's* context does not decide this; the callee's does.
/// * **null address** — no shim to enter.
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

/// Set up `[r11 + rcx]` to address `slot_base + zx32(handle) + off`.
///
/// Leaves `rcx` holding the handle itself — zero-extended and with the
/// displacement folded in — which is what [`emit_arena_epilogue`] returns and
/// what makes the JIT's `Trap::ArenaOutOfBounds` name the same value the
/// interpreter's does.
///
/// Neither scratch can alias a BPF register: `rcx` and `r11` are both absent
/// from [`REGS`], which is the same argument variable shifts and call targets
/// already rest on.
fn emit_arena_addr(e: &mut Emit, handle: u8, off: i16) {
    debug_assert!(
        handle != hr::RCX && handle != hr::R11,
        "the arena scratch registers must not be a BPF register"
    );
    // mov r11, [rsp] — the slot base the prologue parked.
    e.rex(true, hr::R11, hr::RSP);
    e.b(0x8B);
    e.modrm_mem(hr::R11, hr::RSP, ARENA_BASE_SLOT);
    // mov ecx, <handle>d. The 32-bit form zero-extends, which is what bounds
    // the index to `[0, 2^32)` in the bytes rather than by inheritance from the
    // verifier. See the module docs.
    mov_rr(e, false, hr::RCX, handle);
    if off != 0 {
        // add rcx, imm32 (sign-extended by REX.W), so `rcx` is the handle and
        // the access itself needs no displacement.
        alu_ri(e, true, 0, hr::RCX, i32::from(off));
    }
}

/// The prefix + opcode of a memory load of `size` into host register `reg`,
/// addressed through a base whose extension bit `rm` supplies. The caller emits
/// the ModRM (and any SIB / displacement) next. Zero-extends when `sign_extend`
/// is false and sign-extends to 64 bits otherwise — matching the interpreter's
/// `widen`, which always produces a full-width register value.
fn load_prefix_opcode(e: &mut Emit, size: Size, sign_extend: bool, reg: u8, rm: u8) {
    match (size, sign_extend) {
        // `movzx r32, r/m8|16` — the 32-bit destination zero-extends to 64.
        (Size::B, false) => {
            e.rex(false, reg, rm);
            e.bs(&[0x0F, 0xB6]);
        }
        (Size::H, false) => {
            e.rex(false, reg, rm);
            e.bs(&[0x0F, 0xB7]);
        }
        // `mov r32, r/m32` — a 32-bit load likewise zero-extends the upper half.
        (Size::W, false) => {
            e.rex(false, reg, rm);
            e.b(0x8B);
        }
        // `mov r64, r/m64`. A sign-extending doubleword load is a no-op widen,
        // so it takes this same plain form.
        (Size::Dw, _) => {
            e.rex(true, reg, rm);
            e.b(0x8B);
        }
        // `movsx r64, r/m8|16` and `movsxd r64, r/m32`.
        (Size::B, true) => {
            e.rex(true, reg, rm);
            e.bs(&[0x0F, 0xBE]);
        }
        (Size::H, true) => {
            e.rex(true, reg, rm);
            e.bs(&[0x0F, 0xBF]);
        }
        (Size::W, true) => {
            e.rex(true, reg, rm);
            e.b(0x63);
        }
    }
}

/// The prefix + opcode of a register→memory store of `size` from host register
/// `reg`. `0x66` gives the 16-bit operand size; a byte store forces a REX so it
/// can reach the low byte of `rsi`/`rdi`/`rbp` (which R2/R1/R10 map to).
fn store_reg_prefix_opcode(e: &mut Emit, size: Size, reg: u8, rm: u8) {
    match size {
        Size::B => {
            e.rex_forced(false, reg, rm, matches!(reg, 4..=7));
            e.b(0x88);
        }
        Size::H => {
            e.b(0x66);
            e.rex(false, reg, rm);
            e.b(0x89);
        }
        Size::W => {
            e.rex(false, reg, rm);
            e.b(0x89);
        }
        Size::Dw => {
            e.rex(true, reg, rm);
            e.b(0x89);
        }
    }
}

/// The prefix + opcode of an immediate→memory store of `size` (`C6`/`C7 /0`).
/// The caller emits the ModRM (reg field 0) and then the immediate through
/// [`store_imm_tail`].
fn store_imm_prefix_opcode(e: &mut Emit, size: Size, rm: u8) {
    match size {
        Size::B => {
            e.rex(false, 0, rm);
            e.b(0xC6);
        }
        Size::H => {
            e.b(0x66);
            e.rex(false, 0, rm);
            e.b(0xC7);
        }
        Size::W => {
            e.rex(false, 0, rm);
            e.b(0xC7);
        }
        Size::Dw => {
            e.rex(true, 0, rm);
            e.b(0xC7);
        }
    }
}

/// The immediate tail of a `C6`/`C7` store: 1/2/4 bytes by width. A doubleword
/// store carries an `imm32` the REX.W sign-extends, matching BPF's `ST`.
fn store_imm_tail(e: &mut Emit, size: Size, v: i32) {
    match size {
        Size::B => e.b(v as u8),
        Size::H => e.d16(v as i16),
        Size::W | Size::Dw => e.d32(v),
    }
}

/// `mov reg, imm` — the ten-byte form for 64-bit, the five-byte zero-extending
/// form for 32-bit (which is exactly BPF's `wide == false` move semantics).
fn emit_mov_imm(e: &mut Emit, wide: bool, dst: u8, imm: i64) {
    if wide {
        mov_reg_imm64(e, dst, imm);
    } else {
        e.rex(false, 0, dst);
        e.b(0xB8 | (dst & 7));
        e.d32(imm as i32);
    }
}

/// Sign-extend the low `bits` of `v` to 64 bits — the compile-time twin of
/// `movsx`, for the immediate `MOVSX` form.
fn sext_imm(v: i32, bits: u8) -> i64 {
    match bits {
        8 => v as i8 as i64,
        16 => v as i16 as i64,
        _ => i64::from(v),
    }
}

/// `MOVSX`: sign-extend the low `bits` of `src` into `dst`. A 64-bit
/// destination sign-extends to the full register; a 32-bit one sign-extends
/// within 32 bits and zero-extends the upper half, both matching the
/// interpreter's `raw as iN as i64` then the `wide` mask.
fn emit_movsx_rr(e: &mut Emit, wide: bool, bits: u8, dst: u8, src: u8) {
    match bits {
        // `movsx r, r/m8`. A byte source register in `spl`/`sil`/`dil`/`bpl`
        // needs a REX present to name its low byte — forced here for the 32-bit
        // form, which is otherwise prefix-free.
        8 => {
            e.rex_forced(wide, dst, src, matches!(src, 4..=7));
            e.bs(&[0x0F, 0xBE]);
            e.modrm_rr(dst, src);
        }
        // `movsx r, r/m16`.
        16 => {
            e.rex(wide, dst, src);
            e.bs(&[0x0F, 0xBF]);
            e.modrm_rr(dst, src);
        }
        // `movsxd r64, r/m32`. A 32-bit destination cannot sign-extend from 32
        // bits, so it is a plain 32-bit move (the interpreter masks to 32).
        _ => {
            if wide {
                e.rex(true, dst, src);
                e.b(0x63);
                e.modrm_rr(dst, src);
            } else {
                mov_rr(e, false, dst, src);
            }
        }
    }
}

/// `END` / `bswap`: reverse or truncate `dst` by width. `Little` keeps the
/// bytes and only masks to width; `Big`/`Swap` reverses them. Both zero-extend
/// the result, matching the interpreter's `byteswap`.
fn emit_byteswap(
    e: &mut Emit,
    at: u32,
    dst: u8,
    order: ByteOrder,
    width: u8,
) -> Result<(), JitError> {
    let swap = matches!(order, ByteOrder::Big | ByteOrder::Swap);
    match (width, swap) {
        // `ror r/m16, 8` swaps the two bytes; `movzx r32, r/m16` then zero-
        // extends, clearing the upper 48 bits.
        (16, true) => {
            e.b(0x66);
            e.rex(false, 0, dst);
            e.b(0xC1);
            e.modrm_rr(1, dst);
            e.b(8);
            e.rex(false, dst, dst);
            e.bs(&[0x0F, 0xB7]);
            e.modrm_rr(dst, dst);
        }
        // `movzx r32, r/m16` — value & 0xFFFF.
        (16, false) => {
            e.rex(false, dst, dst);
            e.bs(&[0x0F, 0xB7]);
            e.modrm_rr(dst, dst);
        }
        // `bswap r32` — reverses four bytes; the 32-bit form zero-extends.
        (32, true) => {
            e.rex(false, 0, dst);
            e.b(0x0F);
            e.b(0xC8 | (dst & 7));
        }
        // `mov r32, r32` — value & 0xFFFF_FFFF.
        (32, false) => mov_rr(e, false, dst, dst),
        // `bswap r64` — reverses all eight bytes.
        (64, true) => {
            e.rex(true, 0, dst);
            e.b(0x0F);
            e.b(0xC8 | (dst & 7));
        }
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
    // interpreted.
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
                load_prefix_opcode(e, size, sign_extend, host(dst), hr::R11);
                e.modrm_sib_index(host(dst), hr::R11, hr::RCX);
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
                store_reg_prefix_opcode(e, size, host(s), hr::R11);
                e.modrm_sib_index(host(s), hr::R11, hr::RCX);
                record_fault(e, fault_off);
                return Ok(());
            }
            Decoded::Store {
                size,
                dst,
                off,
                src: Source::Imm(v),
            } => {
                emit_arena_addr(e, host(dst), off);
                let fault_off = e.len();
                store_imm_prefix_opcode(e, size, hr::R11);
                e.modrm_sib_index(0, hr::R11, hr::RCX);
                store_imm_tail(e, size, v);
                record_fault(e, fault_off);
                return Ok(());
            }
            // An arena atomic. Refused rather than lowered as a *non*-arena
            // access, which is the failure this whole branch exists to prevent.
            _ => {
                return Err(JitError::Unsupported {
                    at,
                    what: "arena atomic not yet emitted by the x86_64 backend",
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
            Source::Reg(s) => mov_rr(e, wide, host(dst), host(s)),
            Source::Imm(v) => emit_mov_imm(e, wide, host(dst), i64::from(v)),
        },

        Decoded::Mov {
            wide,
            dst,
            src: Source::Reg(s),
            sign_extend: Some(bits),
        } => emit_movsx_rr(e, wide, bits, host(dst), host(s)),

        Decoded::Mov {
            wide,
            dst,
            src: Source::Imm(v),
            sign_extend: Some(bits),
        } => {
            // Sign-extending a constant is itself a constant, so materialise it
            // — the interpreter's `raw as iN as i64 as u64`, then the `wide` mask.
            let ext = sext_imm(v, bits);
            emit_mov_imm(
                e,
                wide,
                host(dst),
                if wide { ext } else { ext & 0xFFFF_FFFF },
            );
        }

        // A plain 64-bit constant is the 10-byte `mov r64, imm64`. The map and
        // subprogram pseudo-forms resolve to addresses this pass does not have,
        // so they fall through to `Unsupported` and run interpreted.
        Decoded::LoadImm64 {
            dst,
            value: Imm64::Value(v),
        } => mov_reg_imm64(e, host(dst), v as i64),

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

        Decoded::Div {
            wide,
            signed,
            dst,
            src,
        } => emit_div_mod(e, wide, signed, false, host(dst), src),

        Decoded::Mod {
            wide,
            signed,
            dst,
            src,
        } => emit_div_mod(e, wide, signed, true, host(dst), src),

        Decoded::Atomic {
            size,
            op,
            dst,
            src,
            off,
        } => emit_atomic(e, at, size, op, dst, off, src)?,

        Decoded::Neg { wide, dst } => {
            // `neg r/m` — F7 /3. Included so the ALU differential sweep can be
            // exhaustive over the operation space rather than skipping a hole.
            e.rex(wide, 0, host(dst));
            e.b(0xF7);
            e.modrm_rr(3, host(dst));
        }

        Decoded::End { dst, order, width } => emit_byteswap(e, at, host(dst), order, width)?,

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
            size,
            sign_extend,
            dst,
            src,
            off,
        } => {
            // `mov`/`movzx`/`movsx` r, [base + disp] — width and extension in
            // the opcode.
            load_prefix_opcode(e, size, sign_extend, host(dst), host(src));
            e.modrm_mem(host(dst), host(src), i32::from(off));
        }

        Decoded::Store {
            size,
            dst,
            off,
            src: Source::Reg(s),
        } => {
            store_reg_prefix_opcode(e, size, host(s), host(dst));
            e.modrm_mem(host(s), host(dst), i32::from(off));
        }

        Decoded::Store {
            size,
            dst,
            off,
            src: Source::Imm(v),
        } => {
            // `mov [base + disp], imm` — C6/C7 /0. A doubleword's imm32 is
            // sign-extended to 64 bits by REX.W; narrower widths carry a
            // truncated immediate. Both match BPF's `ST` (`imm as i64 as u64`
            // then a `size`-byte store).
            store_imm_prefix_opcode(e, size, host(dst));
            e.modrm_mem(0, host(dst), i32::from(off));
            store_imm_tail(e, size, v);
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

        // Including `CallTarget::Subprog`: a BPF-to-BPF call needs the frame
        // push the interpreter does in `push_frame` — saving R6..R9, moving
        // the frame base, and a return path — none of which this emits.
        _ => {
            return Err(JitError::Unsupported {
                at,
                what: "instruction not yet emitted by the x86_64 backend",
            })
        }
    }
    Ok(())
}

/// Record the arena access that begins at `fault_off` as a recoverable site.
///
/// `fixup_off` is left at zero and patched to the arena epilogue by
/// [`emit_pass`], because that offset is not known until the body is emitted.
/// `dst_host_reg` is `None`: an arena fault does not resume into the program, so
/// there is no destination whose value would ever be read — zeroing one would be
/// the "zero and continue" shape this deliberately is not.
fn record_fault(e: &mut Emit, fault_off: u32) {
    e.faults.push(FaultEntry {
        fault_off,
        fixup_off: 0,
        dst_host_reg: None,
        arena: true,
    });
}
