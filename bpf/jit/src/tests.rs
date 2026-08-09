//! Host tests for the x86-64 emitter, and the program-building helpers both
//! backends' tests share.
//!
//! Golden encodings rather than execution: running JITed code on the host would
//! need an executable mapping and a matching ABI, and the property that matters
//! here is that the *bytes* are right. Execution is covered in-kernel, where
//! the same image runs against the interpreter's result.
//!
//! The aarch64 emitter's tests live in [`crate::tests_aarch64`], which adds a
//! differential harness — an emulator plus a reference evaluator — because a
//! host cannot execute the bytes it emits.

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{
    AluOp, AtomicOp, ByteOrder, CallTarget, CondOp, Decoded, Imm64, Insn, Reg, Size, Source,
};
use narf_bpf_verifier::{Context, KfuncCallSite, VerifiedProgram};

use crate::{compile, Compiled, JitError};

pub(crate) fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

/// Wrap instructions in a `VerifiedProgram` without going through the
/// verifier. Sound for a *codegen* test: the emitter's contract is "given a
/// program the verifier accepted, produce equivalent machine code", and what
/// is under test is the second half.
pub(crate) fn verified(items: &[Decoded]) -> VerifiedProgram {
    let mut insns: Vec<Insn> = Vec::new();
    for d in items {
        insns.extend_from_slice(encode(*d).slots());
    }
    VerifiedProgram {
        insns,
        context: Context::Atomic,
        max_stack_bytes: 64,
        initial_fuel: 1024,
        fault_sites: Vec::new(),
        bare_access_sites: Vec::new(),
        subprogs: Vec::new(),
        uses_arena: false,
        kfunc_calls: Vec::new(),
    }
}

/// A `call` to a kfunc whose id and shim address the test chooses.
pub(crate) fn kcall(id: i32) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(id))
}

/// As [`verified`], plus the subprogram table — `(start_slot, stack_bytes)`
/// pairs — so the emitter can tell which `exit` returns to a caller and how far
/// a `call` descends the frame. The verifier would have derived these; a codegen
/// test states them directly.
pub(crate) fn verified_subprogs(items: &[Decoded], subprogs: &[(u32, u32)]) -> VerifiedProgram {
    let mut v = verified(items);
    v.subprogs = subprogs
        .iter()
        .map(|&(start, stack_bytes)| narf_bpf_verifier::SubprogInfo { start, stack_bytes })
        .collect();
    v
}

/// As [`verified`], plus the resolved call table the verifier would have built.
///
/// `sites` is `(insn_index, id, addr)`; the context is [`Context::Atomic`],
/// which is the only one whose shim uses the uniform `u64` ABI. Kept sorted by
/// index, because `resolve_call` binary-searches — an unsorted table is a
/// malformed `VerifiedProgram`, not an input the emitter must tolerate.
pub(crate) fn verified_calling(items: &[Decoded], sites: &[(u32, i32, usize)]) -> VerifiedProgram {
    let mut v = verified(items);
    v.kfunc_calls = sites
        .iter()
        .map(|&(insn_index, id, addr)| KfuncCallSite {
            insn_index,
            id,
            addr,
            context: Context::Atomic,
        })
        .collect();
    v.kfunc_calls.sort_by_key(|c| c.insn_index);
    v
}

pub(crate) const EXIT: Decoded = Decoded::Exit;

pub(crate) fn mov(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

/// An atomic against the frame pointer (R10) — the base every generated and
/// golden atomic uses. `src` is a BPF register index.
pub(crate) fn atomic(size: Size, op: AtomicOp, src: u8, off: i16) -> Decoded {
    Decoded::Atomic {
        size,
        op,
        dst: r(10),
        src: r(src),
        off,
    }
}

#[test]
fn emits_a_trivial_program() {
    let c = compile(&verified(&[mov(0, 42), EXIT])).expect("should compile");
    // Prologue saves the four callee-saved hosts, body, epilogue restores and
    // returns. The exact length is not the contract; that it terminates in
    // `ret` is.
    assert_eq!(*c.code.last().expect("non-empty"), 0xC3, "must end in ret");
    assert_eq!(c.entry_off, 0);
    assert!(c.faults.0.is_empty());
}

#[test]
fn mov_imm64_is_the_ten_byte_form() {
    // Deliberately not the shortest encoding. A `mov` whose size depends on
    // its immediate would change length between sizing passes, which is the
    // other way (besides branches) to make the fixpoint oscillate.
    let c = compile(&verified(&[mov(0, 1), EXIT])).expect("compiles");
    let c2 = compile(&verified(&[mov(0, i32::MAX), EXIT])).expect("compiles");
    assert_eq!(
        c.code.len(),
        c2.code.len(),
        "immediate magnitude must not change the emitted size"
    );
}

#[test]
fn sizing_converges_for_a_long_forward_branch() {
    // A body long enough that the branch cannot take a short displacement.
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
    let c = compile(&verified(&items)).expect("a long branch must still compile");
    assert!(c.code.len() > 300);
}

#[test]
fn reports_unsupported_rather_than_emitting_wrong_code() {
    // The caller answers `Unsupported` by interpreting, so an unemitted shape
    // must be an error and never a silently wrong encoding — the interpreter is a
    // complete implementation, which is what makes growing this backend
    // incrementally safe.
    //
    // This test previously used multiply, then an atomic, then a plain
    // `LD_IMM64` — all now emitted. Deliberately re-pointed at something still
    // unhandled rather than deleted: the property under test is "unemitted means
    // refused", not any one opcode, and it stops being tested at all the moment
    // the chosen instruction gets an encoding. A *map pseudo-form* `LD_IMM64` is
    // the durable choice — it resolves to an address the emitter never has, so
    // it stays interpreted.
    let prog = verified(&[
        Decoded::LoadImm64 {
            dst: r(0),
            value: Imm64::MapFd(3),
        },
        EXIT,
    ]);
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

/// As [`verified`], but describing a program the verifier saw touch an arena.
///
/// `fault_at` is the instruction index of the arena access, which the verifier
/// records because an in-window arena page may simply not be populated. Both
/// halves matter: `uses_arena` is what `jit_glue` gate 2 tests, and the fault
/// site is what gate 3 tests, and an arena access sets *both*.
pub(crate) fn verified_arena(
    items: &[Decoded],
    fault_at: u32,
    dst_reg: Option<u8>,
) -> VerifiedProgram {
    let mut v = verified(items);
    v.uses_arena = true;
    v.fault_sites = vec![narf_bpf_verifier::FaultSite {
        insn_index: fault_at,
        dst_reg,
        arena: true,
    }];
    v
}

#[test]
fn an_arena_program_reaches_its_arena_access_once_the_call_is_emitted() {
    // This test has now asserted three different things, and the sequence is
    // the point.
    //
    // `PtrClass::Arena` has exactly one producer in the verifier
    // (`fixpoint.rs`'s `value_of`, reached from a kfunc's return descriptor),
    // so every program that touches an arena contains a `call`. While no
    // backend emitted `Decoded::Call`, an arena program was refused *there* —
    // at instruction 0 — before any arena lowering was reached, which is why
    // lifting `jit_glue` gate 2 alone would have compiled nothing.
    //
    // Then the call landed and this asserted the next failure along: the store
    // lowered to `mov qword [rax], 1`, a **bare dereference of the handle**,
    // which with `ARENA_BASE_HANDLE` at 4096 is a near-null kernel write. Gate 2
    // was the only thing standing between an arena program and it.
    //
    // Now the lowering exists, and this pins it: the slot base is reloaded, the
    // handle is zero-extended into the index, and the access is
    // `[r11 + rcx]` — with no displacement, because the emitter folds `off16`
    // into `rcx` so the arena-fault epilogue can return the handle.
    let prog = {
        let mut v = verified_arena(
            &[
                kcall(1),
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(0),
                    off: 0,
                    src: Source::Imm(1),
                },
                mov(0, 0),
                EXIT,
            ],
            1,
            None,
        );
        v.kfunc_calls = verified_calling(&[], &[(0, 1, SHIM)]).kfunc_calls;
        v
    };
    let c = compile(&prog).expect("the call is emitted now, and the store always was");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    // 19 bytes of call sequence, then the arena store.
    assert_eq!(
        &body[19..33],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]  — the parked slot base
            0x89, 0xC1, // mov ecx, eax    — zero-extend the handle
            // 49 C7 04 0B 01 00 00 00 — mov qword [r11 + rcx*1], 1
            0x49, 0xC7, 0x04, 0x0B, 0x01, 0x00, 0x00, 0x00,
        ],
        "an arena store must lower to the slot-relative shape, never a bare \
         dereference of the handle"
    );
    // …and it is covered, resuming at the arena epilogue rather than at the
    // next instruction.
    assert_eq!(c.faults.0.len(), 1, "the arena store must be a fault site");
    let f = c.faults.0[0];
    assert!(f.arena);
    assert_eq!(f.dst_host_reg, None, "a store has no destination to zero");
    assert!(
        f.fixup_off > f.fault_off,
        "the fixup must be the arena epilogue, which follows the body"
    );
}

#[test]
fn the_arena_fixup_is_the_epilogue_and_not_the_next_instruction() {
    // The property that separates this from Linux's `ex_handler_bpf`, as an
    // offset rather than as prose: a probe read zeroes and continues, an arena
    // fault *stops*. Resuming at the next instruction would make an
    // out-of-bounds arena access return a value natively and
    // `Trap::ArenaOutOfBounds` interpreted — the divergence the differential
    // harness compares trap discriminants to catch.
    //
    // Mutation: set `fixup_off` to the instruction after the access and this
    // goes red, as does `smoke_bpf_jit_diff_arena_out_of_bounds_traps_like_the_interpreter`.
    let prog = verified_arena(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(2),
                off: 8,
                src: Source::Imm(1),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let c = compile(&prog).expect("the arena store is emitted now");
    assert_eq!(c.faults.0.len(), 1);
    let f = c.faults.0[0];
    // The arena-fault epilogue precedes the equal-sized unaligned epilogue;
    // both are `mov rax, rcx; mov rdx, status; RESTORE`.
    let arena_epilogue_len = 3 + 10 + RESTORE.len();
    let arena_epi = c.code.len() - 2 * arena_epilogue_len;
    assert_eq!(
        f.fixup_off as usize, arena_epi,
        "the fixup must name the arena epilogue"
    );
    assert_eq!(
        &c.code[arena_epi..arena_epi + 13],
        &[
            0x48, 0x89, 0xC8, // mov rax, rcx  — the offending handle
            0x48, 0xBA, 0x02, 0, 0, 0, 0, 0, 0, 0, // mov rdx, 2 (ARENA_FAULT)
        ],
        "the arena epilogue must return the handle and the arena status"
    );
}

#[test]
fn an_arena_access_lowers_to_the_slot_relative_shape() {
    // The counterpart of the test above, in bytes, for a *non*-zero
    // displacement — which is the case that shows the fold into `rcx`.
    //
    // An in-program arena pointer is a slot-relative handle, so the address is
    // `slot_base + handle + off16`. `off16` could have stayed in the ModRM
    // displacement; folding it into the index costs one instruction and is what
    // lets the arena-fault epilogue name the handle the interpreter would have
    // computed, rather than the handle-minus-displacement.
    let prog = verified_arena(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(2),
                off: 8,
                src: Source::Imm(1),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..21],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]
            0x89, 0xF1, // mov ecx, esi   — R2 is rsi; zero-extended
            0x48, 0x81, 0xC1, 0x08, 0x00, 0x00, 0x00, // add rcx, 8
            // 49 C7 04 0B 01 00 00 00 — mov qword [r11 + rcx*1], 1
            0x49, 0xC7, 0x04, 0x0B, 0x01, 0x00, 0x00, 0x00,
        ],
        "the displacement must be folded into the index register"
    );
}

#[test]
fn a_non_arena_access_keeps_the_plain_shape() {
    // The other half: lifting gate 2 must not give *every* access the arena
    // shape. Same instruction, same registers, no fault site — and it lowers to
    // the ordinary `[base + disp]` with no slot base in sight.
    //
    // Without this, an emitter that ignored `arena_access_map` and always took
    // the arena path would pass every test above.
    let prog = verified(&[
        Decoded::Store {
            size: Size::Dw,
            dst: r(2),
            off: 8,
            src: Source::Imm(1),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..8],
        // 48 C7 46 08 01 00 00 00 — mov qword [rsi+8], 1
        &[0x48, 0xC7, 0x46, 0x08, 0x01, 0x00, 0x00, 0x00],
        "a non-arena store must keep the plain addressing shape"
    );
    assert!(
        c.faults.0.is_empty(),
        "a non-arena access is not a fault site"
    );
}

#[test]
fn an_arena_load_and_a_register_store_take_the_same_shape() {
    // The two remaining arena forms, so the golden coverage is the whole set
    // rather than the one form the smoke tests happen to use.
    let load = verified_arena(
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
    let c = compile(&load).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..9],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]
            0x89, 0xF1, // mov ecx, esi
            0x49, 0x8B, 0x14, // mov rdx, [r11 + rcx*1] — R3 is rdx
        ],
        "an arena load must take the slot-relative shape"
    );
    assert_eq!(body[9], 0x0B, "SIB: index rcx, base r11");
    // The destination is *not* recorded for zeroing: an arena fault stops the
    // program, so nothing would ever read it. The verifier's `dst_reg` is
    // deliberately dropped here.
    assert_eq!(c.faults.0.len(), 1);
    assert_eq!(c.faults.0[0].dst_host_reg, None);

    let store = verified_arena(
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
    let c = compile(&store).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..10],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]
            0x89, 0xF1, // mov ecx, esi
            0x49, 0x89, 0x14, 0x0B, // mov [r11 + rcx*1], rdx
        ],
        "an arena register store must take the slot-relative shape"
    );
}

#[test]
fn a_narrower_arena_access_takes_the_slot_relative_shape() {
    // A word-sized (4-byte) arena store of an immediate: the same slot-relative
    // addressing as the doubleword form, with `C7 /0` and a 32-bit operand
    // (no REX.W) so only four bytes are written. The wrong answer this pins
    // against is `mov dword [rsi+8], 1` — a bare dereference of the handle.
    let store = verified_arena(
        &[
            Decoded::Store {
                size: Size::W,
                dst: r(2),
                off: 0,
                src: Source::Imm(1),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let c = compile(&store).expect("a narrower arena store is emitted now");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..14],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]
            0x89, 0xF1, // mov ecx, esi
            0x41, 0xC7, 0x04, 0x0B, // mov dword [r11 + rcx*1], ...  (REX.B, no REX.W)
            0x01, 0x00, 0x00, 0x00, // imm32 = 1
        ],
        "a word arena store must be the slot-relative C7 /0 with a 32-bit operand"
    );
    assert_eq!(
        c.faults.0.len(),
        1,
        "the narrower access is still a fault site"
    );

    // A byte register store from R2 (rsi): `88 /r`, storing the low byte. The
    // REX here is `.B` for the r11 base (present on every arena access), so this
    // pins the byte opcode; the *forced bare 0x40* that names `sil` on a
    // low-base store is isolated by `a_byte_store_forces_a_rex_to_reach_sil`.
    let byte_store = verified_arena(
        &[
            Decoded::Store {
                size: Size::B,
                dst: r(1),
                off: 0,
                src: Source::Reg(r(2)),
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let c = compile(&byte_store).expect("a byte arena store is emitted now");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..10],
        &[
            0x4C, 0x8B, 0x1C, 0x24, // mov r11, [rsp]
            0x89, 0xF9, // mov ecx, edi  (R1 is rdi)
            0x41, 0x88, 0x34, 0x0B, // mov byte [r11 + rcx*1], sil  (REX.B for r11)
        ],
        "a byte arena store must use the byte opcode with the slot-relative shape"
    );
}

#[test]
fn a_byte_store_forces_a_rex_to_reach_sil() {
    // A byte store of R2 (rsi) to a low base (R10 → rbp) has no extension bit to
    // set, so `Emit::rex` would elide the whole prefix — and `88 /r` with no REX
    // names `dh`, not `sil`. The store must therefore force a bare `0x40`. This
    // is the one memory-width edge with no doubleword analogue, so it earns a
    // golden of its own rather than resting on the differential fuzzer.
    let prog = verified(&[
        Decoded::Store {
            size: Size::B,
            dst: r(10),
            off: -8,
            src: Source::Reg(r(2)),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..4],
        // 40 88 75 F8 — mov byte [rbp-8], sil
        &[0x40, 0x88, 0x75, 0xF8],
        "a byte store of sil must force a REX prefix"
    );
}

#[test]
fn a_sign_extending_word_load_is_movsxd() {
    // LDXSW: `movsxd r64, r/m32` — 48 63 /r. The other widths ride the same
    // machinery; this pins the one whose opcode (0x63) is unique to sign
    // extension, so a regression that dropped the sign would show here.
    let prog = verified(&[
        Decoded::Load {
            size: Size::W,
            sign_extend: true,
            dst: r(3),
            src: r(2),
            off: 8,
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..4],
        // 48 63 56 08 — movsxd rdx, dword [rsi+8]   (R3 rdx, R2 rsi)
        &[0x48, 0x63, 0x56, 0x08],
        "a sign-extending word load must be movsxd"
    );
}

#[test]
fn a_register_movsx_sign_extends_a_byte() {
    // MOVSX R3 = (s8)R2 into a 64-bit register: `movsx rdx, sil` — REX.W plus
    // the byte source `sil`, which also needs the REX to be named at all.
    let prog = verified(&[
        Decoded::Mov {
            wide: true,
            dst: r(3),
            src: Source::Reg(r(2)),
            sign_extend: Some(8),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..4],
        // 48 0F BE D6 — movsx rdx, sil   (R3 rdx, R2 rsi)
        &[0x48, 0x0F, 0xBE, 0xD6],
        "a byte MOVSX into a 64-bit register must be movsx r64, r/m8"
    );
}

#[test]
fn a_byteswap_reverses_or_masks_by_width() {
    // A 32-bit swap is a single `bswap`; a 16-bit swap is `ror r16,8` then a
    // `movzx` to clear the upper bits, matching `(v as u16).swap_bytes()`.
    let swap32 = verified(&[
        Decoded::End {
            dst: r(0),
            order: ByteOrder::Big,
            width: 32,
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&swap32).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..2],
        &[0x0F, 0xC8], // bswap eax
        "a 32-bit byte swap must be a single bswap"
    );

    let swap16 = verified(&[
        Decoded::End {
            dst: r(0),
            order: ByteOrder::Big,
            width: 16,
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&swap16).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..7],
        &[
            0x66, 0xC1, 0xC8, 0x08, // ror ax, 8
            0x0F, 0xB7, 0xC0, // movzx eax, ax
        ],
        "a 16-bit byte swap must swap the two bytes and zero-extend"
    );
}

#[test]
fn an_unsigned_div_saves_rax_rdx_and_guards_zero() {
    // R6 / R7 (rbx / r13), unsigned 64-bit. The whole shape is pinned: the
    // divisor is captured into rcx before rax/rdx are pushed (R7 could have been
    // R0 or R3), the dividend goes to rax, a zero divisor is branched around to a
    // zero quotient, and the result is carried out through r11 past the pops.
    let prog = verified(&[
        Decoded::Div {
            wide: true,
            signed: false,
            dst: r(6),
            src: Source::Reg(r(7)),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..30],
        &[
            0x4C, 0x89, 0xE9, // mov rcx, r13     (divisor first)
            0x50, // push rax
            0x52, // push rdx
            0x48, 0x89, 0xD8, // mov rax, rbx     (dividend)
            0x48, 0x85, 0xC9, // test rcx, rcx
            0x74, 0x07, // jz +7 -> divzero
            0x31, 0xD2, // xor edx, edx
            0x48, 0xF7, 0xF1, // div rcx
            0xEB, 0x02, // jmp +2 -> done
            0x31, 0xC0, // xor eax, eax     (divzero: quotient 0)
            0x49, 0x89, 0xC3, // mov r11, rax     (done)
            0x5A, // pop rdx
            0x58, // pop rax
            0x4C, 0x89, 0xDB, // mov rbx, r11
        ],
        "an unsigned div must save rax/rdx, guard zero, and carry out via r11"
    );
}

#[test]
fn a_signed_mod_guards_zero_and_minus_one() {
    // R6 %s R7 (rbx / r13), signed 64-bit. Beyond the div shape this pins the two
    // signed-only branches: `cmp rcx, -1` avoids the `idiv` overflow trap on
    // `INT_MIN %s -1` (remainder 0), and the zero-divisor path leaves the
    // dividend as the remainder. The result register is rdx, not rax.
    let prog = verified(&[
        Decoded::Mod {
            wide: true,
            signed: true,
            dst: r(6),
            src: Source::Reg(r(7)),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..44],
        &[
            0x4C, 0x89, 0xE9, // mov rcx, r13
            0x50, // push rax
            0x52, // push rdx
            0x48, 0x89, 0xD8, // mov rax, rbx
            0x48, 0x85, 0xC9, // test rcx, rcx
            0x74, 0x10, // jz +16 -> divzero
            0x48, 0x81, 0xF9, 0xFF, 0xFF, 0xFF, 0xFF, // cmp rcx, -1
            0x74, 0x0C, // je +12 -> neg_one
            0x48, 0x99, // cqo
            0x48, 0xF7, 0xF9, // idiv rcx
            0xEB, 0x07, // jmp +7 -> done
            0x48, 0x89, 0xC2, // mov rdx, rax     (divzero: rem = dividend)
            0xEB, 0x02, // jmp +2 -> done
            0x31, 0xD2, // xor edx, edx     (neg_one: rem = 0)
            0x49, 0x89, 0xD3, // mov r11, rdx     (done)
            0x5A, // pop rdx
            0x58, // pop rax
            0x4C, 0x89, 0xDB, // mov rbx, r11
        ],
        "a signed mod must guard zero and the -1 overflow, result in rdx"
    );
}

#[test]
fn the_atomics_lower_to_locked_read_modify_writes() {
    // Every lowered atomic form, dst = R10 (rbp), src = R6 (rbx), off = -8,
    // doubleword unless noted. Pins the LOCK prefix, the implicit-lock xchg, the
    // rax-implicit cmpxchg, and the plain-move load-acquire / store-release —
    // and one word form to show REX.W drops out.
    let prog = verified(&[
        atomic(Size::Dw, AtomicOp::Add { fetch: false }, 6, -8),
        atomic(Size::Dw, AtomicOp::Add { fetch: true }, 6, -8),
        atomic(Size::Dw, AtomicOp::Xchg, 6, -8),
        atomic(Size::Dw, AtomicOp::Cmpxchg, 6, -8),
        atomic(Size::Dw, AtomicOp::Or { fetch: false }, 6, -8),
        atomic(Size::Dw, AtomicOp::And { fetch: false }, 6, -8),
        atomic(Size::Dw, AtomicOp::Xor { fetch: false }, 6, -8),
        atomic(Size::Dw, AtomicOp::LoadAcquire, 6, -8),
        atomic(Size::Dw, AtomicOp::StoreRelease, 6, -8),
        atomic(Size::W, AtomicOp::Add { fetch: true }, 6, -8),
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..49],
        &[
            0xF0, 0x48, 0x01, 0x5D, 0xF8, // lock add   [rbp-8], rbx
            0xF0, 0x48, 0x0F, 0xC1, 0x5D, 0xF8, // lock xadd  [rbp-8], rbx
            0x48, 0x87, 0x5D, 0xF8, // xchg  [rbp-8], rbx (implicitly locked)
            0xF0, 0x48, 0x0F, 0xB1, 0x5D, 0xF8, // lock cmpxchg [rbp-8], rbx
            0xF0, 0x48, 0x09, 0x5D, 0xF8, // lock or    [rbp-8], rbx
            0xF0, 0x48, 0x21, 0x5D, 0xF8, // lock and   [rbp-8], rbx
            0xF0, 0x48, 0x31, 0x5D, 0xF8, // lock xor   [rbp-8], rbx
            0x48, 0x8B, 0x5D, 0xF8, // mov   rbx, [rbp-8]  (load-acquire)
            0x48, 0x89, 0x5D, 0xF8, // mov   [rbp-8], rbx  (store-release)
            0xF0, 0x0F, 0xC1, 0x5D, 0xF8, // lock xadd  [rbp-8], ebx  (word)
        ],
        "atomic lowering drifted"
    );
}

#[test]
fn ld_imm64_is_a_ten_byte_move() {
    // Two back-to-back wide constants — R0 and R9 — then exit. Pins the
    // `mov r64, imm64` encoding (including REX.B for r15) and, because each is a
    // two-slot instruction, that they lay out contiguously with the right offset
    // for the trailing slot.
    let prog = verified(&[
        Decoded::LoadImm64 {
            dst: r(0),
            value: Imm64::Value(0x1122_3344_5566_7788),
        },
        Decoded::LoadImm64 {
            dst: r(9),
            value: Imm64::Value(0xFFFF_FFFF_0000_0000),
        },
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..20],
        &[
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // movabs rax, ...
            0x49, 0xBF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // movabs r15, ...
        ],
        "LD_IMM64 must be a 10-byte mov r64, imm64"
    );
}

#[test]
fn may_goto_is_an_unconditional_jump() {
    // The runtime always takes `may_goto` (it is metered by fuel, not a hidden
    // counter), so it lowers to the same `jmp rel32` (0xE9) as an unconditional
    // `Jump` rather than being refused. Proven differentially: the same program
    // with the `may_goto` removed emits exactly one fewer `jmp` — the `exit`'s.
    let add = Decoded::Alu {
        wide: true,
        op: AluOp::Add,
        dst: r(0),
        src: Source::Imm(1),
    };
    let with = compile(&verified(&[
        mov(0, 0),
        add,
        Decoded::MayGoto { off: -2 },
        EXIT,
    ]))
    .expect("may_goto must compile");
    let without = compile(&verified(&[mov(0, 0), add, EXIT])).expect("compiles");
    let jmps = |c: &Compiled| c.code.iter().filter(|&&b| b == 0xE9).count();
    assert_eq!(
        jmps(&with),
        jmps(&without) + 1,
        "may_goto must add exactly one unconditional jump"
    );
}

#[test]
fn an_unresolved_map_pseudo_ld_imm64_is_refused() {
    // Without a resolved address, a map pseudo-form has nothing to materialise,
    // so it runs interpreted rather than being mis-emitted. (`compile` is
    // `compile_resolved` with an empty table.)
    let prog = verified(&[
        Decoded::LoadImm64 {
            dst: r(0),
            value: Imm64::MapFd(3),
        },
        EXIT,
    ]);
    assert!(
        matches!(compile(&prog), Err(JitError::Unsupported { .. })),
        "an unresolved map pseudo LD_IMM64 must be refused, not mis-emitted"
    );
}

#[test]
fn a_resolved_map_pseudo_ld_imm64_materialises_the_address() {
    // Given the loader-resolved address, a map pseudo-form is the same 10-byte
    // `mov r64, imm64` as a plain constant — over the address, here R6 (rbx).
    let prog = verified(&[
        Decoded::LoadImm64 {
            dst: r(6),
            value: Imm64::MapFd(3),
        },
        mov(0, 0),
        EXIT,
    ]);
    let c = crate::compile_resolved(&prog, &[(0, 0x1122_3344_5566_7788)]).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..10],
        &[0x48, 0xBB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11], // movabs rbx, ...
        "a resolved map LD_IMM64 must materialise the address"
    );
}

#[test]
fn a_fetching_bitwise_atomic_is_a_cmpxchg_loop() {
    // x86 has no atomic fetch-and-{or,and,xor}, so a fetch-OR of R6 (rbx) into
    // [rbp-8] is a cmpxchg retry loop: the operand is captured in rcx, rax reads
    // the current value, and the loop retries until the exchange sticks. R0
    // (rax) is saved and the fetched value carried out through r11.
    let prog = verified(&[
        atomic(Size::Dw, AtomicOp::Or { fetch: true }, 6, -8),
        mov(0, 0),
        EXIT,
    ]);
    let c = compile(&prog).expect("compiles");
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..29],
        &[
            0x50, // push rax
            0x48, 0x89, 0xD9, // mov rcx, rbx        (operand, before rax is clobbered)
            0x48, 0x8B, 0x45, 0xF8, // mov rax, [rbp-8]    (initial comparand)
            0x49, 0x89, 0xC3, // mov r11, rax        (retry:)
            0x49, 0x09, 0xCB, // or  r11, rcx
            0xF0, 0x4C, 0x0F, 0xB1, 0x5D, 0xF8, // lock cmpxchg [rbp-8], r11
            0x75, 0xF2, // jnz retry (-14)
            0x49, 0x89, 0xC3, // mov r11, rax        (fetched old)
            0x58, // pop rax
            0x4C, 0x89, 0xDB, // mov rbx, r11
        ],
        "a fetching bitwise atomic must be a cmpxchg loop"
    );
}

#[test]
fn an_arena_atomic_uses_the_slot_relative_shape_and_records_its_fault() {
    let prog = verified_arena(
        &[
            Decoded::Atomic {
                size: Size::Dw,
                op: AtomicOp::Add { fetch: false },
                dst: r(2),
                src: r(3),
                off: 8,
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    let c = compile(&prog).expect("the arena atomic compiles");
    assert_eq!(c.faults.0.len(), 1);
    let fault = c.faults.0[0];
    assert!(fault.arena && fault.fixup_off > fault.fault_off);
    assert_eq!(c.code[fault.fault_off as usize], 0xF0, "lock prefix");
}

#[test]
fn a_fetching_bitwise_arena_atomic_still_falls_back_without_losing_its_shape() {
    let prog = verified_arena(
        &[
            Decoded::Atomic {
                size: Size::Dw,
                op: AtomicOp::Or { fetch: true },
                dst: r(2),
                src: r(3),
                off: 8,
            },
            mov(0, 0),
            EXIT,
        ],
        0,
        None,
    );
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

/// The prologue, hand-derived from the Intel SDM.
///
/// `push rbp/rbx/r12/r13/r14/r15; mov r12, rdx; mov rbp, rdi; mov rdi, rsi`
///
/// `push rbp` is not decoration: R10 maps to rbp so the body overwrites it, and
/// rbp is callee-saved in SysV. An earlier version of this constant omitted it
/// and therefore *faithfully pinned the bug* — the test passed while every
/// invocation destroyed the caller's frame pointer. A golden test is only as
/// good as the derivation behind it.
///
/// `r12` holds the fuel counter and is likewise callee-saved. `mov r12, rdx`
/// runs before anything can write rdx, which R3 maps to.
///
/// `mov [rsp], rcx` parks the arena slot base in the alignment padding, and
/// likewise has to run before anything writes `rcx` — a variable shift and a
/// kfunc call both do.
const PROLOGUE: &[u8] = &[
    0x55, // push rbp
    0x53, // push rbx
    0x41, 0x54, // push r12
    0x41, 0x55, // push r13
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    0x48, 0x83, 0xEC, 0x08, // sub rsp, 8     (SysV alignment; see STACK_ALIGN_PAD)
    0x48, 0x89, 0x0C, 0x24, // mov [rsp], rcx (the arena slot base; ARENA_BASE_SLOT)
    0x49, 0x89, 0xD4, // mov r12, rdx   (fuel)
    0x48, 0x89, 0xFD, // mov rbp, rdi
    0x48, 0x89, 0xF7, // mov rdi, rsi
];

/// The per-block fuel burn: `sub r12, imm32` then `jb rel32` to the
/// out-of-fuel epilogue. Thirteen bytes; the immediate and displacement vary.
const FUEL_BURN_LEN: usize = 13;

/// `add rsp, 8; pop r15; pop r14; pop r13; pop r12; pop rbx; pop rbp; ret`
/// The alignment release, the pops, and `ret`, shared by both epilogues.
const RESTORE: &[u8] = &[
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0x41, 0x5F, // pop r15
    0x41, 0x5E, // pop r14
    0x41, 0x5D, // pop r13
    0x41, 0x5C, // pop r12
    0x5B, // pop rbx
    0x5D, // pop rbp
    0xC3, // ret
];

/// The normal epilogue. The image ends with the *out-of-fuel* one, which shares
/// [`RESTORE`] but sets the flag instead of clearing it.
const EPILOGUE: &[u8] = &[
    0x48, 0x31, 0xD2, // xor rdx, rdx  — the exhaustion flag, cleared
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0x41, 0x5F, // pop r15
    0x41, 0x5E, // pop r14
    0x41, 0x5D, // pop r13
    0x41, 0x5C, // pop r12
    0x5B, // pop rbx
    0x5D, // pop rbp
    0xC3, // ret
];

/// Assert the emitted body — everything between prologue and epilogue — is
/// exactly `want`.
///
/// Exact bytes, not "contains". The earlier tests asserted things like
/// `code.contains(&0xD3)`, which passes on wrong code that happens to include
/// that byte somewhere, and one asserted a displacement byte appeared *anywhere*
/// in the image, which is close to vacuous. For a code generator the encoding
/// *is* the behaviour, so the test has to pin it.
#[track_caller]
fn assert_body(items: &[Decoded], want: &[u8]) {
    let c = compile(&verified(items)).expect("should compile");
    assert!(
        c.code.starts_with(PROLOGUE),
        "prologue changed:\n got {:02X?}\nwant {PROLOGUE:02X?}",
        &c.code[..PROLOGUE.len().min(c.code.len())]
    );
    // The image ends with the out-of-fuel epilogue, so it is `RESTORE` that
    // terminates it — the normal epilogue sits just before.
    assert!(
        c.code.ends_with(RESTORE),
        "image does not end in the restore sequence: got {:02X?}",
        &c.code[c.code.len().saturating_sub(RESTORE.len())..]
    );
    assert!(
        c.code.windows(EPILOGUE.len()).any(|w| w == EPILOGUE),
        "the normal (flag-clearing) epilogue is missing"
    );
    // Every block opens with a fuel burn: `sub r12, imm32` then `jb rel32` to
    // the out-of-fuel epilogue. Checked for shape and then skipped, so each
    // golden stays about the instruction under test rather than restating the
    // burn in every expectation.
    let after = &c.code[PROLOGUE.len()..];
    assert_eq!(
        &after[..3],
        &[0x49, 0x81, 0xEC],
        "expected `sub r12, imm32` at the block head, got {:02X?}",
        &after[..3]
    );
    assert_eq!(
        &after[7..9],
        &[0x0F, 0x82],
        "expected `jb rel32` after the fuel burn"
    );

    // The body runs from after the burn to the normal epilogue. Located by
    // searching rather than by arithmetic, so a change to either epilogue's
    // length cannot silently shift what is compared.
    let rest = &after[FUEL_BURN_LEN..];
    let end = rest
        .windows(EPILOGUE.len())
        .position(|w| w == EPILOGUE)
        .expect("the normal epilogue must appear after the body");
    let body = &rest[..end];
    assert_eq!(body, want, "\n got {body:02X?}\nwant {want:02X?}");
}

#[test]
fn golden_mov_imm64() {
    // r0 = 42; exit  →  mov rax, 42 (10-byte form) ; jmp epilogue
    assert_body(
        &[mov(0, 42), EXIT],
        &[
            0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0, // mov rax, 42
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32 -> epilogue (disp 0)
        ],
    );
}

#[test]
fn golden_add_reg() {
    // r0 += r1  →  add rax, rdi
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Add,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
            EXIT,
        ],
        &[0x48, 0x01, 0xF8, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_shift_imm() {
    // r0 <<= 5  →  shl rax, 5
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Lsh,
                dst: r(0),
                src: Source::Imm(5),
            },
            EXIT,
        ],
        &[0x48, 0xC1, 0xE0, 0x05, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_imul_reg() {
    // r0 *= r1  →  imul rax, rdi  (two-operand; the one-operand form would
    // clobber rdx = R3)
    assert_body(
        &[
            Decoded::Alu {
                wide: true,
                op: AluOp::Mul,
                dst: r(0),
                src: Source::Reg(r(1)),
            },
            EXIT,
        ],
        &[0x48, 0x0F, 0xAF, 0xC7, 0xE9, 0, 0, 0, 0],
    );
}

#[test]
fn golden_frame_store_and_load() {
    // *(u64*)(r10-8) = r0 ; r1 = *(u64*)(r10-8)
    //   mov [rbp-8], rax   →  48 89 45 F8
    //   mov rdi, [rbp-8]   →  48 8B 7D F8
    // rbp as a base needs an explicit displacement byte even at zero, which is
    // the encoding trap `modrm_mem`'s `force_disp` exists for.
    assert_body(
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
            0x48, 0x89, 0x45, 0xF8, // mov [rbp-8], rax
            0x48, 0x8B, 0x7D, 0xF8, // mov rdi, [rbp-8]
            0xE9, 0, 0, 0, 0,
        ],
    );
}

#[test]
fn load_and_store_against_the_frame_encode() {
    let prog = verified(&[
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
        mov(0, 0),
        EXIT,
    ]);
    // Superseded by `golden_frame_store_and_load`, which pins the exact
    // bytes. Kept as a smoke that the shape compiles at all.
    compile(&prog).expect("frame access must compile");
}

// ── branch encoding ─────────────────────────────────────────────────

#[test]
fn every_branch_is_rel32() {
    // This replaces a test that asserted a 123-byte short-branch cap as though
    // it were load-bearing. It was not: the emitter never selected a short
    // form, so the cap, the convergence loop, and that test all guarded a
    // hazard the code was not exposed to. Both are gone.
    //
    // What is worth pinning is the property the emitter actually has, because
    // it is the premise of there being no sizing fixpoint at all: every branch
    // is `rel32`. A short branch appearing without the loop coming back is the
    // regression this catches.
    let items = &[
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Eq,
            dst: r(0),
            src: Source::Imm(0),
            off: 1,
        },
        mov(0, 1),
        mov(0, 0),
        EXIT,
    ];
    let c = compile(&verified(items)).expect("compiles");
    // 0F 84 (je rel32) — not 74 (je rel8).
    assert!(
        c.code.windows(2).any(|w| w == [0x0F, 0x84]),
        "conditional branch should be the rel32 form"
    );
    assert!(
        !c.code.contains(&0x74),
        "a rel8 je appeared; the sizing fixpoint must come back with it"
    );
    // E9 (jmp rel32), never EB (jmp rel8).
    assert!(c.code.contains(&0xE9));
    assert!(!c.code.contains(&0xEB));
}

// ── shifts and multiply ─────────────────────────────────────────────

#[test]
fn shift_by_register_routes_through_cl() {
    // x86 requires a variable shift count in `cl`. `rcx` is absent from the
    // BPF→host map precisely so the count can be moved there without saving
    // anything — if a BPF register lived in `rcx` this would silently corrupt
    // it.
    let prog = verified(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Lsh,
            dst: r(0),
            src: Source::Reg(r(1)),
        },
        EXIT,
    ]);
    let c = compile(&prog).expect("register shift must compile");
    // Exact: mov rcx, rdi (48 89 F9) then shl rax, cl (48 D3 E0).
    //
    // Note the ModRM byte: for opcode 0x89 (`MOV r/m64, r64`) the reg field is
    // the *source* and r/m is the destination, so `mov rcx, rdi` is F9 —
    // reg=111(rdi), rm=001(rcx). CF would be `mov rdi, rcx`, the other
    // direction. I wrote CF here first and this test caught it, which is the
    // argument for exact encodings over byte-presence checks.
    let body = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    assert_eq!(
        &body[..6],
        &[0x48, 0x89, 0xF9, 0x48, 0xD3, 0xE0],
        "got {:02X?}",
        &body[..6.min(body.len())]
    );
}

#[test]
fn shift_by_immediate_is_masked_to_the_operand_width() {
    // BPF masks the count to the operand width and so does x86 in hardware,
    // so the low bits pass through — but the emitted byte must still be the
    // masked value, or a 64-bit shift by 65 would encode as 65 and a 32-bit
    // one differently again.
    for (wide, count, want) in [(true, 65i32, 1u8), (false, 33, 1), (true, 63, 63)] {
        let prog = verified(&[
            Decoded::Alu {
                wide,
                op: AluOp::Lsh,
                dst: r(0),
                src: Source::Imm(count),
            },
            EXIT,
        ]);
        let c = compile(&prog).expect("immediate shift must compile");
        assert!(
            c.code.contains(&want),
            "shift of {count} (wide={wide}) should encode a masked count of {want}"
        );
    }
}

#[test]
fn multiply_uses_the_two_operand_form() {
    // The one-operand `mul` writes rdx:rax, which would clobber R3 (rdx) and
    // R0. BPF's multiply is truncating, so `imul r64, r/m64` is both correct
    // and side-effect free — a real trap, since the obvious encoding is wrong.
    let prog = verified(&[
        Decoded::Alu {
            wide: true,
            op: AluOp::Mul,
            dst: r(0),
            src: Source::Reg(r(1)),
        },
        EXIT,
    ]);
    let c = compile(&prog).expect("multiply must compile");
    assert!(
        c.code.windows(2).any(|w| w == [0x0F, 0xAF]),
        "expected the two-operand imul (0F AF), not the rdx-clobbering form"
    );
    // And the one-operand form's /5 ModRM under 0xF7 must not appear.
    assert!(
        !c.code
            .windows(2)
            .any(|w| w[0] == 0xF7 && (w[1] >> 3) & 7 == 5),
        "one-operand imul would clobber rdx (R3) and rax (R0)"
    );
}

#[test]
fn golden_store_immediate() {
    // *(u64*)(r10-8) = 0x1234  →  mov qword [rbp-8], 0x1234
    //   48 C7 45 F8 34 12 00 00
    //
    // Found by the in-kernel differential test refusing to run: the corpus
    // used a `ST` with an immediate source, the emitter only handled a register
    // source, so the program silently fell back to the interpreter — and a
    // differential test whose subject is not compiled compares the interpreter
    // with itself and passes for free. Worth stating: the test caught a missing
    // *encoding* only because it asserted its subject was actually JITed.
    assert_body(
        &[
            Decoded::Store {
                size: Size::Dw,
                dst: r(10),
                off: -8,
                src: Source::Imm(0x1234),
            },
            mov(0, 0),
            EXIT,
        ],
        &[
            0x48, 0xC7, 0x45, 0xF8, 0x34, 0x12, 0x00, 0x00, // mov [rbp-8], 0x1234
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, 0
            0xE9, 0, 0, 0, 0,
        ],
    );
}

#[test]
fn golden_r13_base_needs_a_displacement_byte() {
    // `r0 = *(u64 *)(r7 + 0)`  →  mov rax, [r13+0]  →  49 8B 45 00
    //
    // R7 maps to r13, and r13 shares rm=101 with rbp: with mod=00 that
    // encoding means *RIP-relative*, so omitting the displacement byte would
    // read a completely different address. The `00` disp8 is what makes it a
    // plain base+0 load.
    //
    // Tested here, through `compile` directly, because the in-kernel
    // differential sweep cannot reach it: `jit_glue`'s gate 5 restricts load
    // bases to R10 and R1, and the verifier forbids a zero stack offset — so
    // no gate-passing program produces a zero-displacement rbp/r13 access.
    // Mutation testing found that gap: deleting `force_disp` left all 40
    // in-kernel smokes passing.
    assert_body(
        &[
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(0),
                src: r(7),
                off: 0,
            },
            EXIT,
        ],
        &[0x49, 0x8B, 0x45, 0x00, 0xE9, 0, 0, 0, 0],
    );
}

// ── kfunc calls ─────────────────────────────────────────────────────
//
// The emitter's only entry into kernel code. Golden bytes rather than
// execution, as everywhere in this file: the in-kernel differential smoke in
// `bpf/src/tests.rs` is what proves the sequence *runs*, and it can only be
// trusted to prove that if the bytes here are the ones intended.

/// A shim address with a bit set in every byte, so a truncated or
/// wrong-endian materialisation cannot look right by accident.
const SHIM: usize = 0xDEAD_BEEF_1234_5678;

#[test]
fn golden_kfunc_call_sequence() {
    // R4 → r8 and R5 → r9 in the BPF map; SysV wants arg3 in rcx and arg4 in
    // r8. So `rcx := r8` must run **first** — the other order overwrites R4
    // with R5 and passes it twice. That is the bug this golden exists for; the
    // rest of the sequence is uncontroversial.
    assert_call_body(
        &[kcall(7), EXIT],
        &[(0, 7, SHIM)],
        &[
            0x4C, 0x89, 0xC1, // mov rcx, r8        SysV arg3 := BPF R4
            0x4D, 0x89, 0xC8, // mov r8, r9         SysV arg4 := BPF R5
            0x49, 0xBB, 0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, // movabs r11, SHIM
            0x41, 0xFF, 0xD3, // call r11
            0xE9, 0, 0, 0, 0, // jmp -> epilogue
        ],
    );
}

/// `assert_body` compiles through [`verified`], which has no call table. The
/// call goldens need one, so they go through this instead.
#[track_caller]
fn assert_call_body(items: &[Decoded], sites: &[(u32, i32, usize)], want: &[u8]) {
    let c = compile(&verified_calling(items, sites)).expect("should compile");
    let rest = &c.code[PROLOGUE.len() + FUEL_BURN_LEN..];
    let end = rest
        .windows(EPILOGUE.len())
        .position(|w| w == EPILOGUE)
        .expect("the normal epilogue must appear after the body");
    assert_eq!(
        &rest[..end],
        want,
        "\n got {:02X?}\nwant {want:02X?}",
        &rest[..end]
    );
}

#[test]
fn a_call_the_verifier_never_reached_is_refused_rather_than_guessed() {
    // The verifier's table covers *reachable* call sites only — see
    // `narf_bpf_verifier`'s
    // `an_unreachable_call_is_not_recorded_so_the_emitter_must_fail_closed`.
    // An emitter walking instructions linearly therefore meets calls with no
    // entry, and the only safe answer is to refuse the whole program: there is
    // no address to emit and no way to tell "dead code" from "the table is
    // wrong" from inside this crate.
    let prog = verified(&[kcall(7), EXIT]);
    assert!(prog.kfunc_calls.is_empty(), "premise: no table");
    assert!(
        matches!(compile(&prog), Err(JitError::Unsupported { at: 0, .. })),
        "an unresolved call must not compile"
    );

    // The harder half: a **non-empty** table with nothing at this index, and
    // the same kfunc at another one. An emitter that fell back to "whatever
    // entry is nearest" would pass the empty case and this is where it would
    // be caught — the ids match, so nothing downstream of the index lookup can
    // tell the two sites apart.
    let prog = verified_calling(&[kcall(2), kcall(2), EXIT], &[(1, 2, SHIM)]);
    assert_eq!(prog.kfunc_calls.len(), 1, "premise: only one site resolved");
    assert!(
        matches!(compile(&prog), Err(JitError::Unsupported { at: 0, .. })),
        "a call at an index the table does not cover must not borrow another site's address"
    );
}

#[test]
fn a_call_site_that_names_a_different_kfunc_is_refused() {
    // Belt to the verifier's brace. The table is built by resolving the same
    // immediate this instruction carries, so a disagreement is impossible
    // today — which is exactly why it must fail closed rather than pick one:
    // if the two ever *do* disagree, whichever the emitter trusts is a guess,
    // and the wrong guess is an indirect call to an arbitrary kfunc.
    let prog = verified_calling(&[kcall(7), EXIT], &[(0, 9, SHIM)]);
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a_sleepable_kfuncs_shim_is_never_entered_from_native_code() {
    // `KfuncShim::Sleepable` is `fn(..) -> Pin<Box<dyn Future>>`, not
    // `extern "C" fn(..) -> u64`. Calling it through the uniform ABI would
    // reinterpret a boxed future as the program's R0 and leak it, and no
    // amount of correct register shuffling would help.
    let mut prog = verified_calling(&[kcall(7), EXIT], &[(0, 7, SHIM)]);
    prog.kfunc_calls[0].context = Context::Sleepable;
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a_null_shim_address_is_refused() {
    let prog = verified_calling(&[kcall(7), EXIT], &[(0, 7, 0)]);
    assert!(matches!(
        compile(&prog),
        Err(JitError::Unsupported { at: 0, .. })
    ));
}

#[test]
fn a_subprogram_call_saves_the_frame_and_returns() {
    // main (stack 16) calls a subprogram (stack 0) that returns 7. The call
    // saves R6..R9 and R10, descends the frame pointer by the caller's 16 bytes,
    // and `call`s; the callee's `exit` is a `ret`. Displacement-independent bytes
    // are pinned exactly; the `call` and the subprogram `ret` are checked to be
    // present (their exact offsets depend on the fuel-burn layout).
    let prog = verified_subprogs(
        &[Decoded::Call(CallTarget::Subprog(1)), EXIT, mov(0, 7), EXIT],
        &[(0, 16), (2, 0)],
    );
    let c = compile(&prog).expect("a subprogram call must compile");
    let frame = [
        0x53, // push rbx
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
        0x55, // push rbp
        0x48, 0x81, 0xED, 0x10, 0x00, 0x00, 0x00, // sub rbp, 16
    ];
    assert!(
        c.code.windows(frame.len()).any(|w| w == frame),
        "the call must save R6..R10 and descend the frame pointer"
    );
    let restore = [
        0x5D, // pop rbp
        0x41, 0x5F, // pop r15
        0x41, 0x5E, // pop r14
        0x41, 0x5D, // pop r13
        0x5B, // pop rbx
    ];
    assert!(
        c.code.windows(restore.len()).any(|w| w == restore),
        "the call must restore R6..R10 afterwards"
    );
    assert!(c.code.contains(&0xE8), "a near `call` must be emitted");
    assert!(
        c.code.contains(&0xC3),
        "the subprogram `exit` must be a `ret`"
    );
}

#[test]
fn each_call_site_gets_its_own_address() {
    // Resolution is per site, so two calls to two kfuncs must materialise two
    // different addresses. A backend that resolved by looking up the *first*
    // entry, or by id-with-a-linear-scan-of-a-stale-table, passes the
    // single-call golden and fails here.
    assert_call_body(
        &[kcall(1), kcall(2), EXIT],
        &[(0, 1, 0x1111_2222_3333_4444), (1, 2, 0x5555_6666_7777_8888)],
        &[
            0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xC8, //
            0x49, 0xBB, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22, 0x11, 0x11, //
            0x41, 0xFF, 0xD3, //
            0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xC8, //
            0x49, 0xBB, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66, 0x55, 0x55, //
            0x41, 0xFF, 0xD3, //
            0xE9, 0, 0, 0, 0,
        ],
    );
}

// ── stack discipline ────────────────────────────────────────────────

/// How far a straight-line run of bytes moves `rsp`.
///
/// Deliberately a *decoder* rather than a restatement of the constants the
/// emitter uses: the question is what the emitted image does, and a test that
/// recomputed `6 * 8 + STACK_ALIGN_PAD` would agree with any value of either.
/// Panics on an unrecognised encoding, so a prologue that grows a new shape
/// cannot silently fall out of the accounting.
fn rsp_delta(bytes: &[u8]) -> i64 {
    let mut delta = 0i64;
    let mut k = 0usize;
    while k < bytes.len() {
        let b = bytes[k];
        match b {
            // push r8..r15 / pop r8..r15 — REX.B then the short form.
            0x41 if (0x50..0x58).contains(&bytes[k + 1]) => {
                delta -= 8;
                k += 2;
            }
            0x41 if (0x58..0x60).contains(&bytes[k + 1]) => {
                delta += 8;
                k += 2;
            }
            0x50..=0x57 => {
                delta -= 8;
                k += 1;
            }
            0x58..=0x5F => {
                delta += 8;
                k += 1;
            }
            // 48 83 /digit rsp, imm8 — the only rsp arithmetic emitted.
            0x48 if bytes[k + 1] == 0x83 && bytes[k + 2] == 0xEC => {
                delta -= i64::from(bytes[k + 3]);
                k += 4;
            }
            0x48 if bytes[k + 1] == 0x83 && bytes[k + 2] == 0xC4 => {
                delta += i64::from(bytes[k + 3]);
                k += 4;
            }
            // REX + 89 /r with mod=00, rm=100 — a store *through* rsp, which is
            // the arena-base park (`mov [rsp], rcx`). It reads rsp and does not
            // move it, so it contributes nothing to the delta; the SIB byte is
            // what makes it four bytes long. Matched before the register-move
            // arm below, which would otherwise mistake the ModRM for one naming
            // rsp as a destination.
            0x48..=0x4F
                if bytes[k + 1] == 0x89
                    && bytes[k + 2] & 0xC0 == 0x00
                    && bytes[k + 2] & 7 == 4
                    && bytes[k + 3] == 0x24 =>
            {
                k += 4;
            }
            // REX + 89 /r — a register move. Cannot touch rsp: rsp is r/m
            // field 4, and `modrm_rr` puts the destination there.
            0x48..=0x4F if bytes[k + 1] == 0x89 => {
                // rsp is r/m field 4 *with REX.B clear*; with it set the same
                // field is r12, which the prologue really does write.
                assert!(
                    !(bytes[k + 2] & 7 == 4 && b & 1 == 0),
                    "a mov wrote rsp; the accounting above is wrong"
                );
                k += 3;
            }
            // 48 31 /r — `xor rdx, rdx` in the normal epilogue.
            0x48 if bytes[k + 1] == 0x31 => k += 3,
            0xC3 => k += 1, // ret
            _ => panic!("rsp_delta cannot decode {b:02X} at {k} in {bytes:02X?}"),
        }
    }
    delta
}

#[test]
fn the_prologue_leaves_the_stack_aligned_for_a_sysv_call() {
    // SysV requires `rsp % 16 == 0` at the instant a `call` executes, so a
    // function is entered at 8. This image is such a function, and its body
    // contains `call`s now.
    //
    // Six pushes move `rsp` by 48, which is `0 mod 16` and therefore leaves the
    // entry residue untouched — a note this work started from claimed "+48"
    // fixed the alignment, and it does nothing at all. The residue is the whole
    // question, so it is computed here from the emitted bytes.
    assert_eq!(
        (8 + rsp_delta(PROLOGUE)).rem_euclid(16),
        0,
        "a kfunc would be entered with SysV's alignment inverted"
    );
}

#[test]
fn the_epilogue_releases_exactly_what_the_prologue_claimed() {
    // The other half, and the one whose failure is unmissable: an imbalance
    // makes `ret` pop something that is not the return address. Stated as a
    // sum over the two sequences so neither can be edited alone.
    assert_eq!(
        rsp_delta(PROLOGUE) + rsp_delta(RESTORE),
        0,
        "prologue and epilogue disagree about the frame size"
    );
}
