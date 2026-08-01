//! End-to-end verification tests: a positive and a negative case per
//! instruction class, plus the rules that only exist at whole-program scope.
//!
//! Every negative case asserts the *specific* error, not merely that the
//! program was rejected. That is deliberate: "your program was rejected" with
//! no location is the single most-complained-about property of Linux's
//! verifier, and a test suite that only checks `is_err()` is how a diagnostic
//! silently degrades into that.
//!
//! The loop tests are the load-bearing ones. There is no instruction budget
//! and no state limit here, so a program with an unbounded loop must *finish
//! verifying* — if widening were wrong, these would hang rather than fail, and
//! that is exactly the property worth a test.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, AtomicOp, CallTarget, CondOp, Decoded, Imm64, Insn, Reg, Size, Source};

use crate::kfunc::{
    ArgDesc, ArgFlags, Context, KfuncDesc, PtrKind, TypeKey, TypeKind, ValidityDomain,
};
use crate::{interp, verify, MapDesc, Program, VerifiedProgram, VerifyError};

// ── Program construction ────────────────────────────────────────────

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

fn mov(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

fn movr(dst: u8, src: u8) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Reg(r(src)),
        sign_extend: None,
    }
}

fn alu(op: AluOp, dst: u8, v: i32) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Imm(v),
    }
}

fn alur(op: AluOp, dst: u8, src: u8) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Reg(r(src)),
    }
}

fn ldx(size: Size, dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}

fn stx(size: Size, dst: u8, off: i16, src: u8) -> Decoded {
    Decoded::Store {
        size,
        dst: r(dst),
        off,
        src: Source::Reg(r(src)),
    }
}

fn st(size: Size, dst: u8, off: i16, imm: i32) -> Decoded {
    Decoded::Store {
        size,
        dst: r(dst),
        off,
        src: Source::Imm(imm),
    }
}

fn jmp(op: CondOp, dst: u8, imm: i32, off: i16) -> Decoded {
    Decoded::JumpCond {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Imm(imm),
        off,
    }
}

fn call(id: i32) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(id))
}

const EXIT: Decoded = Decoded::Exit;

fn encode_all(insns: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in insns {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

/// Verify with an explicit context tuple, kfunc set, map set, and execution
/// context.
fn check_all(
    insns: &[Decoded],
    ctx_fields: &'static [ArgDesc],
    kfuncs: &[KfuncDesc],
    maps: &[MapDesc],
    context: Context,
) -> Result<VerifiedProgram, VerifyError> {
    let image = encode_all(insns);
    // Stamp ids by position. Resolution in the verifier is by *id*, never by
    // index — but the tests are far more readable when `call(N)` names the
    // Nth kfunc, so the harness keeps the two in step rather than making
    // every test invent and thread an id.
    let kfuncs: Vec<KfuncDesc> = kfuncs
        .iter()
        .enumerate()
        .map(|(i, k)| KfuncDesc { id: i as i32, ..*k })
        .collect();
    verify(&Program {
        insns: &image,
        context,
        ctx_fields,
        kfuncs: &kfuncs,
        maps,
    })
}

/// Verify with an explicit context tuple, kfunc set, and execution context.
fn check_full(
    insns: &[Decoded],
    ctx_fields: &'static [ArgDesc],
    kfuncs: &[KfuncDesc],
    context: Context,
) -> Result<VerifiedProgram, VerifyError> {
    check_all(insns, ctx_fields, kfuncs, &[], context)
}

/// Verify an atomic program against a map set.
fn check_maps(insns: &[Decoded], maps: &[MapDesc]) -> Result<VerifiedProgram, VerifyError> {
    check_all(insns, &[], &[], maps, Context::Atomic)
}

/// Verify an atomic program with no context and no kfuncs.
fn check(insns: &[Decoded]) -> Result<VerifiedProgram, VerifyError> {
    check_full(insns, &[], &[], Context::Atomic)
}

/// Verify with a context tuple.
fn check_ctx(
    insns: &[Decoded],
    ctx_fields: &'static [ArgDesc],
) -> Result<VerifiedProgram, VerifyError> {
    check_full(insns, ctx_fields, &[], Context::Atomic)
}

fn ok(insns: &[Decoded]) -> VerifiedProgram {
    check(insns).expect("program should verify")
}

fn err(insns: &[Decoded]) -> VerifyError {
    check(insns).expect_err("program should be rejected")
}

// ── Descriptor helpers ──────────────────────────────────────────────

const fn ptr_desc(kind: PtrKind, domain: ValidityDomain, flags: ArgFlags) -> ArgDesc {
    ArgDesc {
        kind: TypeKind::Ptr {
            kind,
            key: TypeKey(1),
        },
        domain,
        flags,
    }
}

/// Build a test kfunc. `id` is a placeholder — `check_full` stamps ids by
/// position, so `call(N)` names the Nth entry of the slice a test passes.
fn kfunc(
    name: &'static str,
    args: &'static [ArgDesc],
    ret: ArgDesc,
    context: Context,
) -> KfuncDesc {
    KfuncDesc {
        id: 0,
        name,
        addr: 0x1000,
        args,
        ret,
        context,
    }
}

static NO_ARGS: &[ArgDesc] = &[];
static SCALAR_ARG: &[ArgDesc] = &[ArgDesc::SCALAR64];
static OWNED_ARG: &[ArgDesc] = &[ptr_desc(
    PtrKind::Object,
    ValidityDomain::Owned,
    ArgFlags::NONE,
)];
static TRUSTED_ARG: &[ArgDesc] = &[ptr_desc(
    PtrKind::Object,
    ValidityDomain::NonPreemptible,
    ArgFlags::NONE,
)];
static GUARD_ARG: &[ArgDesc] = &[ptr_desc(
    PtrKind::LockGuard,
    ValidityDomain::NonPreemptible,
    ArgFlags::NONE,
)];
/// `&mut MaybeUninit<[u8]>` plus its length.
///
/// Built at runtime and leaked because [`ArgFlags`] composes only through
/// `BitOr`, which is not `const` — so a combination of two flags cannot appear
/// in a `static`. Noted rather than worked around silently: `kfunc!` will want
/// exactly this shape in a `#[link_section]` static, where leaking is not an
/// option.
fn uninit_mem_args() -> &'static [ArgDesc] {
    Vec::leak(vec![
        ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Mem,
                key: TypeKey::NONE,
            },
            domain: ValidityDomain::Static,
            flags: ArgFlags::SIZED_BY_NEXT | ArgFlags::UNINIT,
        },
        ArgDesc::SCALAR64,
    ])
}
static READ_MEM_ARGS: &[ArgDesc] = &[
    ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Mem,
            key: TypeKey::NONE,
        },
        domain: ValidityDomain::Static,
        flags: ArgFlags::SIZED_BY_NEXT,
    },
    ArgDesc::SCALAR64,
];
static CONST_ARG: &[ArgDesc] = &[ArgDesc {
    kind: TypeKind::Scalar {
        bits: 64,
        signed: false,
    },
    domain: ValidityDomain::Static,
    flags: ArgFlags::CONST,
}];

/// An acquiring kfunc: `fn acquire() -> Option<Owned<T>>`.
fn acquire_kfunc() -> KfuncDesc {
    kfunc(
        "acquire",
        NO_ARGS,
        ptr_desc(PtrKind::Object, ValidityDomain::Owned, ArgFlags::NULLABLE),
        Context::Atomic,
    )
}

/// `fn release(Owned<T>)`.
fn release_kfunc() -> KfuncDesc {
    kfunc("release", OWNED_ARG, ArgDesc::VOID, Context::Atomic)
}

/// `fn lock() -> Option<Guard<'_>>`.
fn lock_kfunc() -> KfuncDesc {
    kfunc(
        "lock",
        NO_ARGS,
        ptr_desc(
            PtrKind::LockGuard,
            ValidityDomain::NonPreemptible,
            ArgFlags::NULLABLE,
        ),
        Context::Atomic,
    )
}

/// `fn unlock(Guard<'_>)`.
fn unlock_kfunc() -> KfuncDesc {
    kfunc("unlock", GUARD_ARG, ArgDesc::VOID, Context::Atomic)
}

/// A kfunc that may sleep. Calling it is an await point.
fn sleepy_kfunc() -> KfuncDesc {
    kfunc("narf_yield", NO_ARGS, ArgDesc::VOID, Context::Sleepable)
}

// ── ALU ─────────────────────────────────────────────────────────────

#[test]
fn arithmetic_on_scalars_verifies() {
    let v = ok(&[
        mov(0, 1),
        alu(AluOp::Add, 0, 2),
        alu(AluOp::Mul, 0, 3),
        alu(AluOp::And, 0, 0xff),
        EXIT,
    ]);
    assert_eq!(v.max_stack_bytes, 0);
}

#[test]
fn reading_an_uninitialised_register_is_rejected() {
    assert_eq!(
        err(&[alu(AluOp::Add, 3, 1), mov(0, 0), EXIT]),
        VerifyError::UninitRegister { at: 0, reg: 3 }
    );
}

#[test]
fn writing_the_frame_pointer_is_rejected() {
    // R10 is read-only by the ISA, and a program that could move it could
    // point the frame anywhere.
    assert_eq!(
        err(&[mov(10, 0), mov(0, 0), EXIT]),
        VerifyError::WriteToFramePointer { at: 0 }
    );
}

#[test]
fn multiplying_a_pointer_is_rejected() {
    // Add and subtract are the only defined pointer arithmetic outside an
    // arena; anything else produces an address with no provenance.
    assert_eq!(
        err(&[movr(1, 10), alu(AluOp::Mul, 1, 4), mov(0, 0), EXIT]),
        VerifyError::PointerArithmetic { at: 1, reg: 1 }
    );
}

#[test]
fn thirty_two_bit_arithmetic_on_a_pointer_is_rejected() {
    // A 32-bit ALU result is zero-extended, so it is not the address it came
    // from — the pointer's provenance does not survive the truncation.
    assert_eq!(
        err(&[
            movr(1, 10),
            Decoded::Alu {
                wide: false,
                op: AluOp::Add,
                dst: r(1),
                src: Source::Imm(0),
            },
            mov(0, 0),
            EXIT,
        ]),
        VerifyError::PointerArithmetic { at: 1, reg: 1 }
    );
}

#[test]
fn the_difference_of_two_stack_pointers_is_a_scalar() {
    let v = ok(&[
        movr(1, 10),
        movr(2, 10),
        alu(AluOp::Sub, 2, 16),
        alur(AluOp::Sub, 1, 2),
        movr(0, 1),
        EXIT,
    ]);
    assert_eq!(v.max_stack_bytes, 0);
}

#[test]
fn returning_a_pointer_from_the_program_is_rejected() {
    // `exit` hands R0 to the kernel as a return code. A kernel address in it
    // is a leak with no purpose.
    assert_eq!(
        err(&[movr(0, 10), EXIT]),
        VerifyError::PointerArithmetic { at: 1, reg: 0 }
    );
}

#[test]
fn division_by_a_possibly_zero_value_verifies() {
    // The ISA defines `x / 0 == 0` (`instruction-set.rst:351`), so requiring a
    // proof that the divisor is non-zero would reject code LLVM emits freely.
    // The JIT's job is to emit the guard; the verifier's is not to demand one.
    let v = ok(&[mov(0, 100), mov(1, 0), alur(AluOp::Add, 0, 1), EXIT]);
    let _ = v;
    ok(&[
        mov(0, 100),
        mov(1, 0),
        Decoded::Div {
            wide: true,
            signed: false,
            dst: r(0),
            src: Source::Reg(r(1)),
        },
        EXIT,
    ]);
}

// ── Stack ───────────────────────────────────────────────────────────

#[test]
fn a_doubleword_spill_round_trips() {
    let v = ok(&[st(Size::Dw, 10, -8, 42), ldx(Size::Dw, 0, 10, -8), EXIT]);
    assert_eq!(v.max_stack_bytes, 8);
}

#[test]
fn reading_uninitialised_stack_is_rejected() {
    // The BPF stack is a per-CPU region reused between programs, so a read of
    // bytes nothing wrote returns whatever the previous program left.
    assert_eq!(
        err(&[ldx(Size::Dw, 0, 10, -8), EXIT]),
        VerifyError::UninitStack { at: 0, off: -8 }
    );
}

#[test]
fn byte_writes_initialise_a_slot_for_a_wider_read() {
    // Per-byte initialisation tracking, not per-slot: a compiler that fills a
    // word with four byte stores and then reads it is doing nothing wrong, and
    // slot-granular tracking would reject it.
    let v = ok(&[
        st(Size::B, 10, -4, 1),
        st(Size::B, 10, -3, 2),
        st(Size::B, 10, -2, 3),
        st(Size::B, 10, -1, 4),
        ldx(Size::W, 0, 10, -4),
        EXIT,
    ]);
    assert_eq!(v.max_stack_bytes, 8);
}

#[test]
fn a_partly_written_slot_is_not_readable_as_a_doubleword() {
    assert_eq!(
        err(&[st(Size::W, 10, -8, 1), ldx(Size::Dw, 0, 10, -8), EXIT]),
        VerifyError::UninitStack { at: 1, off: -8 }
    );
}

#[test]
fn a_spilled_pointer_survives_a_doubleword_round_trip() {
    ok(&[
        stx(Size::Dw, 10, -8, 10),
        ldx(Size::Dw, 1, 10, -8),
        st(Size::Dw, 1, -16, 7),
        mov(0, 0),
        EXIT,
    ]);
}

#[test]
fn overwriting_one_byte_of_a_spilled_pointer_destroys_it() {
    // Half a pointer is not a pointer. Without this, a program could forge an
    // address by spilling a real one and editing a byte.
    assert_eq!(
        err(&[
            stx(Size::Dw, 10, -8, 10),
            st(Size::B, 10, -8, 0),
            ldx(Size::Dw, 1, 10, -8),
            st(Size::Dw, 1, -16, 7),
            mov(0, 0),
            EXIT,
        ]),
        VerifyError::NotAPointer { at: 3, reg: 1 }
    );
}

#[test]
fn a_slot_written_on_only_one_path_is_not_initialised_after_the_merge() {
    // A byte is initialised only where it is initialised on *every* path — the
    // join intersects, it does not union. Getting that backwards is the
    // classic uninitialised-read hole, and it is invisible to any test that
    // only exercises straight-line code.
    //
    //   0: r2 = ctx[0]
    //   1: if r2 == 0 goto 3        ← skips the store
    //   2: *(u64 *)(r10 - 8) = 1
    //   3: r0 = *(u64 *)(r10 - 8)
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    assert_eq!(
        check_ctx(
            &[
                ldx(Size::Dw, 2, 1, 0),
                jmp(CondOp::Eq, 2, 0, 1),
                st(Size::Dw, 10, -8, 1),
                ldx(Size::Dw, 0, 10, -8),
                EXIT,
            ],
            CTX,
        )
        .unwrap_err(),
        VerifyError::UninitStack { at: 3, off: -8 }
    );
}

#[test]
fn a_slot_written_on_every_path_is_initialised_after_the_merge() {
    // The positive counterpart, so the rule above cannot be satisfied by
    // simply never believing a store.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    check_ctx(
        &[
            ldx(Size::Dw, 2, 1, 0),
            jmp(CondOp::Eq, 2, 0, 2),
            st(Size::Dw, 10, -8, 1),
            Decoded::Jump { off: 1 },
            st(Size::Dw, 10, -8, 2),
            ldx(Size::Dw, 0, 10, -8),
            EXIT,
        ],
        CTX,
    )
    .expect("both arms write the slot");
}

#[test]
fn a_pointer_spilled_on_only_one_path_is_not_a_pointer_after_the_merge() {
    // The same rule one level up: a slot holding a pointer on one path and a
    // scalar on the other holds neither afterwards.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let e = check_ctx(
        &[
            ldx(Size::Dw, 2, 1, 0),
            jmp(CondOp::Eq, 2, 0, 2),
            stx(Size::Dw, 10, -8, 10),
            Decoded::Jump { off: 1 },
            st(Size::Dw, 10, -8, 0),
            ldx(Size::Dw, 3, 10, -8),
            st(Size::Dw, 3, -16, 1),
            mov(0, 0),
            EXIT,
        ],
        CTX,
    )
    .unwrap_err();
    assert_eq!(e, VerifyError::NotAPointer { at: 6, reg: 3 });
}

#[test]
fn stack_access_above_the_frame_pointer_is_rejected() {
    assert_eq!(
        err(&[st(Size::Dw, 10, 0, 1), mov(0, 0), EXIT]),
        VerifyError::OutOfBounds { at: 0 }
    );
}

#[test]
fn stack_access_beyond_the_budget_is_rejected() {
    assert_eq!(
        err(&[st(Size::Dw, 10, -20000, 1), mov(0, 0), EXIT]),
        VerifyError::OutOfBounds { at: 0 }
    );
}

// ── variable frame offsets ──────────────────────────────────────────
//
// A stack access whose offset is not a constant. `r10 - K + i` for a bounded
// `i` is what an array on the stack compiles to, and rejecting it used to
// reject that whole shape. What makes it safe is one interval check: the
// concrete offset lies in `[addr.min, addr.max]` — the domain's soundness
// invariant, which `fuzz.rs` tests directly — so proving `[addr.min,
// addr.max + width)` inside the frame proves the access inside the frame.
//
// Every test below is a statement about *one* of the two halves: the bound
// that makes it safe, or the per-byte state that makes it useless to lie
// about.

/// `r3 = r10 - depth + (ctx[0] & mask)`, ready for an access at offset zero.
///
/// The mask, not a branch, is what bounds the index — the shape LLVM emits for
/// `buf[i & N]` and the one that survives being written twice in these tests.
fn variable_frame_ptr(depth: i32, mask: i32) -> Vec<Decoded> {
    vec![
        ldx(Size::Dw, 2, 1, 0), // r2 = ctx[0], wholly unknown
        alu(AluOp::And, 2, mask),
        movr(3, 10),
        alu(AluOp::Sub, 3, depth),
        alur(AluOp::Add, 3, 2),
    ]
}

static CTX1: &[ArgDesc] = &[ArgDesc::SCALAR64];

#[test]
fn a_variable_stack_offset_inside_the_frame_is_accepted() {
    // r3 ranges over [r10-16, r10-8]; an 8-byte store from there covers
    // [-16, 0), which is inside the frame.
    let mut p = variable_frame_ptr(16, 8);
    p.extend_from_slice(&[st(Size::Dw, 3, 0, 1), mov(0, 0), EXIT]);
    let v = check_ctx(&p, CTX1).expect("a bounded variable frame offset is safe");
    // The frame must be deep enough for the *lowest* byte the store could
    // reach, not for the one it happens to reach on some path.
    assert!(
        v.max_stack_bytes >= 16,
        "frame is {} bytes, store could reach 16 deep",
        v.max_stack_bytes
    );
}

#[test]
fn a_variable_stack_offset_that_could_cross_the_frame_pointer_is_rejected() {
    // Same shape, but the index reaches 16 while the base is only 16 down, so
    // the top of the range is `r10` itself — above the frame.
    let mut p = variable_frame_ptr(16, 31);
    p.extend_from_slice(&[st(Size::Dw, 3, 0, 1), mov(0, 0), EXIT]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");
}

#[test]
fn a_variable_stack_offset_that_could_undershoot_the_budget_is_rejected() {
    // The *bottom* edge: base deeper than the budget, index bounded.
    let mut p = variable_frame_ptr(20_000, 8);
    p.extend_from_slice(&[st(Size::Dw, 3, 0, 1), mov(0, 0), EXIT]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");
}

#[test]
fn an_unbounded_stack_offset_is_still_rejected() {
    // No mask: `addr.max` is `i64::MAX`, which is the case the width check has
    // to add to without wrapping into a negative — the one arithmetic mistake
    // that would admit everything.
    let p = vec![
        ldx(Size::Dw, 2, 1, 0),
        movr(3, 10),
        alu(AluOp::Sub, 3, 16),
        alur(AluOp::Add, 3, 2),
        st(Size::Dw, 3, 0, 1),
        mov(0, 0),
        EXIT,
    ];
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");
}

#[test]
fn a_variable_stack_read_needs_every_byte_it_could_reach() {
    // The range is [-16, 0); only [-8, 0) was written. The read is admitted
    // against `addr.min` alone if the initialisation check follows the
    // constant path, and that is the hole this pins.
    //
    // The written half is the *deep* one on purpose. Writing the shallow half
    // instead would leave `addr.min` uninitialised, so a check that only
    // looked at `addr.min` would reject too and the test would pass while
    // proving nothing — which is exactly what it did before the mutation table
    // caught it.
    let mut p = vec![st(Size::Dw, 10, -16, 0)];
    p.extend(variable_frame_ptr(16, 8));
    p.extend_from_slice(&[ldx(Size::Dw, 4, 3, 0), mov(0, 0), EXIT]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::UninitStack { .. }), "{e:?}");

    // …and the mirror, so neither edge can be the only one checked.
    let mut p = vec![st(Size::Dw, 10, -8, 0)];
    p.extend(variable_frame_ptr(16, 8));
    p.extend_from_slice(&[ldx(Size::Dw, 4, 3, 0), mov(0, 0), EXIT]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::UninitStack { .. }), "{e:?}");
}

#[test]
fn a_variable_stack_read_of_a_fully_written_range_is_accepted() {
    let mut p = vec![st(Size::Dw, 10, -8, 0), st(Size::Dw, 10, -16, 0)];
    p.extend(variable_frame_ptr(16, 8));
    p.extend_from_slice(&[ldx(Size::Dw, 4, 3, 0), mov(0, 0), EXIT]);
    check_ctx(&p, CTX1).expect("every byte the load could reach was written");
}

#[test]
fn a_variable_stack_write_does_not_initialise_the_range() {
    // The soundness statement for `Stack::write_maybe`, and the one that is
    // wrong in the tempting direction: a store at an unknown offset lands on
    // *one* width's worth of bytes somewhere in the range, so it defines no
    // particular byte. If it set the init bits for the whole range, this
    // constant read of a byte the store may never have touched would verify —
    // and the concrete machine would hand back whatever was in the frame.
    let mut p = variable_frame_ptr(16, 8);
    p.extend_from_slice(&[
        st(Size::Dw, 3, 0, 1),     // maybe-writes somewhere in [-16, 0)
        ldx(Size::Dw, 4, 10, -16), // definitely reads [-16, -8)
        mov(0, 0),
        EXIT,
    ]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::UninitStack { .. }), "{e:?}");
}

#[test]
fn a_variable_stack_write_destroys_a_spilled_pointer_it_could_hit() {
    // R10 spilled to [-16, -8), then a store that might land on it. The slot
    // afterwards holds either the frame pointer or `1`, which is not a
    // pointer — so using it as a base must be rejected.
    let mut p = vec![stx(Size::Dw, 10, -16, 10)];
    p.extend(variable_frame_ptr(16, 8));
    p.extend_from_slice(&[
        st(Size::Dw, 3, 0, 1),
        ldx(Size::Dw, 5, 10, -16),
        st(Size::Dw, 5, 0, 7), // store through what used to be a pointer
        mov(0, 0),
        EXIT,
    ]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::NotAPointer { .. }), "{e:?}");
}

#[test]
fn a_variable_stack_write_leaves_slots_outside_its_range_alone() {
    // The other side of the same coin: `write_maybe` must not be a blanket
    // clobber. The spill at [-8, 0) is above everything the store can reach,
    // so it is still a frame pointer afterwards.
    let mut p = vec![stx(Size::Dw, 10, -8, 10)];
    p.extend(variable_frame_ptr(32, 8));
    p.extend_from_slice(&[
        st(Size::Dw, 3, 0, 1), // reaches [-32, -16)
        ldx(Size::Dw, 5, 10, -8),
        st(Size::Dw, 5, -40, 7), // still a frame pointer, so this is fine
        mov(0, 0),
        EXIT,
    ]);
    check_ctx(&p, CTX1).expect("a spill outside the maybe-written range survives");
}

#[test]
fn a_variable_stack_offset_from_a_branch_bound_is_accepted() {
    // The other way a bound arrives: a comparison rather than a mask. Same
    // interval, reached through `refine` instead of `alu`.
    let p = vec![
        ldx(Size::Dw, 2, 1, 0),
        jmp(CondOp::Gt, 2, 8, 4), // if r2 > 8, skip the access
        movr(3, 10),
        alu(AluOp::Sub, 3, 16),
        alur(AluOp::Add, 3, 2),
        st(Size::Dw, 3, 0, 1),
        mov(0, 0),
        EXIT,
    ];
    check_ctx(&p, CTX1).expect("a branch-bounded variable frame offset is safe");
}

#[test]
fn a_variable_stack_offset_kfunc_region_is_still_rejected() {
    // // LINUX-GAP: `check_mem_arg` still requires a constant frame offset for
    // a `&[u8]`/`&mut [u8]` argument. Deliberately untouched: a byte region
    // combines an unknown offset with an unknown *length*, which is a second
    // interval and a different proof, and nothing needed it yet.
    static KF: &[KfuncDesc] = &[KfuncDesc {
        id: 0,
        name: "take_bytes",
        addr: 0x1000,
        args: &[
            ptr_desc(
                PtrKind::Mem,
                ValidityDomain::Static,
                ArgFlags::SIZED_BY_NEXT,
            ),
            ArgDesc::SCALAR64,
        ],
        ret: ArgDesc::SCALAR64,
        context: Context::Atomic,
    }];
    let mut p = vec![st(Size::Dw, 10, -8, 0), st(Size::Dw, 10, -16, 0)];
    p.extend(variable_frame_ptr(16, 8));
    p.extend_from_slice(&[movr(1, 3), mov(2, 8), call(0), mov(0, 0), EXIT]);
    let e = check_all(&p, CTX1, KF, &[], Context::Atomic).unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");
}

#[test]
fn stack_depth_is_the_deepest_byte_touched() {
    let v = ok(&[
        st(Size::Dw, 10, -8, 1),
        st(Size::Dw, 10, -128, 1),
        st(Size::B, 10, -200, 1),
        mov(0, 0),
        EXIT,
    ]);
    assert_eq!(v.max_stack_bytes, 200);
}

// ── Context ─────────────────────────────────────────────────────────

#[test]
fn a_context_field_load_produces_the_declared_type() {
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64, ArgDesc::SCALAR64];
    check_ctx(&[ldx(Size::Dw, 0, 1, 8), EXIT], CTX).expect("field 1 exists");
}

#[test]
fn a_context_load_past_the_tuple_is_rejected() {
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    assert_eq!(
        check_ctx(&[ldx(Size::Dw, 0, 1, 8), EXIT], CTX).unwrap_err(),
        VerifyError::OutOfBounds { at: 0 }
    );
}

#[test]
fn an_unaligned_context_load_is_rejected() {
    // The context is the hook's argument list spilled to an eight-byte-per-
    // field array by the trampoline. There is no narrow-load fixup layer here
    // because there is no fictional struct to fix up.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64, ArgDesc::SCALAR64];
    assert_eq!(
        check_ctx(&[ldx(Size::W, 0, 1, 4), EXIT], CTX).unwrap_err(),
        VerifyError::OutOfBounds { at: 0 }
    );
}

#[test]
fn storing_to_the_context_is_rejected() {
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    assert_eq!(
        check_ctx(&[st(Size::Dw, 1, 0, 0), mov(0, 0), EXIT], CTX).unwrap_err(),
        VerifyError::WriteToReadOnly { at: 0 }
    );
}

// ── Bounds checks and branch refinement ─────────────────────────────

#[test]
fn a_bounds_checked_index_permits_the_access() {
    // The whole point of the numeric domain, exercised end to end: an unknown
    // 64-bit value from the context, bounded by an unsigned comparison, used
    // as a variable offset into a region whose size the verifier knows.
    //
    // The region is the caller's frame seen from inside a subprogram, which is
    // where a *sized* region with a *variable* offset actually arises before
    // maps land in Phase 3.
    //
    //   main: r1 = r10 - 64; r2 = ctx[0]; if r2 > 48 goto skip
    //         call sub
    //   skip: r0 = 0; exit
    //   sub:  r1 += r2; r0 = *(u64 *)(r1 + 0); exit
    // The index is loaded before R1 is repurposed as the frame pointer.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let prog = &[
        ldx(Size::Dw, 2, 1, 0),
        movr(1, 10),
        alu(AluOp::Sub, 1, 64),
        jmp(CondOp::Gt, 2, 48, 1),
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        alur(AluOp::Add, 1, 2),
        ldx(Size::Dw, 0, 1, 0),
        EXIT,
    ];
    check_ctx(prog, CTX).expect("a bounded index into a sized region is safe");
}

#[test]
fn an_unbounded_index_is_rejected() {
    // The same program with the comparison removed. If this were accepted, the
    // bounds check above would be proving nothing.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let e = check_ctx(
        &[
            ldx(Size::Dw, 2, 1, 0),
            movr(1, 10),
            alu(AluOp::Sub, 1, 64),
            Decoded::Call(CallTarget::Subprog(2)),
            mov(0, 0),
            EXIT,
            alur(AluOp::Add, 1, 2),
            ldx(Size::Dw, 0, 1, 0),
            EXIT,
        ],
        CTX,
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");
}

#[test]
fn an_impossible_branch_is_not_analysed() {
    // `r0 = 1; if r0 == 0 goto bad` — the taken edge is unreachable, so the
    // uninitialised-register read on it is never reported.
    ok(&[
        mov(0, 1),
        jmp(CondOp::Eq, 0, 0, 1),
        EXIT,
        alu(AluOp::Add, 5, 1),
        EXIT,
    ]);
}

// ── Loops ───────────────────────────────────────────────────────────

#[test]
fn an_unbounded_loop_verifies() {
    // The headline property. Linux's `check_cfg()` rejects this outright
    // because it cannot bound the iteration count. NARF does not need to:
    // fuel terminates the program at runtime, so the verifier only has to
    // reach a fixpoint — and if widening were wrong this test would hang
    // rather than fail, which is precisely why it is worth having.
    //
    //   r0 = 0
    //   loop: r0 += 1; goto loop
    let v = ok(&[mov(0, 0), alu(AluOp::Add, 0, 1), Decoded::Jump { off: -2 }]);
    assert!(v.initial_fuel > 0);
}

#[test]
fn a_counted_loop_keeps_its_bound() {
    //   r0 = 0
    //   loop: r0 += 1; if r0 < 64 goto loop
    //   *(u64 *)(r10 - 8) = r0
    ok(&[
        mov(0, 0),
        alu(AluOp::Add, 0, 1),
        jmp(CondOp::Lt, 0, 64, -2),
        stx(Size::Dw, 10, -8, 0),
        EXIT,
    ]);
}

#[test]
fn a_loop_whose_counter_escapes_still_converges() {
    // A counter with no bound at all: the interval widens to top and the
    // fixpoint settles. Termination here is a property of the widening
    // operator, not of a visit budget.
    ok(&[
        mov(0, 0),
        alu(AluOp::Add, 0, 1),
        alu(AluOp::Mul, 0, 3),
        jmp(CondOp::Ne, 1, 0, -3),
        EXIT,
    ]);
}

#[test]
fn a_nested_loop_converges() {
    ok(&[
        mov(0, 0),
        mov(1, 0),
        alu(AluOp::Add, 1, 1),
        jmp(CondOp::Lt, 1, 16, -2),
        alu(AluOp::Add, 0, 1),
        jmp(CondOp::Lt, 0, 256, -5),
        EXIT,
    ]);
}

#[test]
fn may_goto_is_just_a_branch() {
    // Linux gives `may_goto` its own verifier state because it is trying to
    // bound the loop. Under fuel it is a branch that may or may not be taken,
    // which is what "we cannot say" already means abstractly.
    ok(&[
        mov(0, 0),
        alu(AluOp::Add, 0, 1),
        Decoded::MayGoto { off: -2 },
        EXIT,
    ]);
}

// ── Subprograms ─────────────────────────────────────────────────────

#[test]
fn a_subprogram_call_verifies_and_sums_stack() {
    //   main: *(u64 *)(r10 - 8) = 1; call sub; r0 = 0; exit
    //   sub:  *(u64 *)(r10 - 128) = 1; r0 = 0; exit
    let v = ok(&[
        st(Size::Dw, 10, -8, 1),
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        st(Size::Dw, 10, -128, 1),
        mov(0, 0),
        EXIT,
    ]);
    assert_eq!(v.subprogs.len(), 2);
    assert_eq!(v.subprogs[0].stack_bytes, 8);
    assert_eq!(v.subprogs[1].stack_bytes, 128);
    assert_eq!(v.max_stack_bytes, 136);
}

#[test]
fn direct_recursion_is_rejected() {
    // Fuel bounds a program's *work*, not its stack. A recursive call graph
    // has no depth the verifier can compute and nothing at runtime would catch
    // the overflow, so it is the one control-flow shape NARF still refuses.
    let e = check(&[
        Decoded::Call(CallTarget::Subprog(1)),
        EXIT,
        Decoded::Call(CallTarget::Subprog(-1)),
        EXIT,
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::Recursion { .. }), "{e:?}");
}

#[test]
fn mutual_recursion_is_rejected() {
    //   0: call +1      → 2
    //   1: exit
    //   2: call +1      → 4
    //   3: exit
    //   4: call -3      → 2
    //   5: exit
    let e = check(&[
        Decoded::Call(CallTarget::Subprog(1)),
        EXIT,
        Decoded::Call(CallTarget::Subprog(1)),
        EXIT,
        Decoded::Call(CallTarget::Subprog(-3)),
        EXIT,
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::Recursion { .. }), "{e:?}");
}

#[test]
fn a_call_graph_needing_too_much_stack_is_rejected() {
    // Each subprogram takes 8 KiB; two of them exceed the 16 KiB budget once
    // the leaf's frame is added.
    let e = check(&[
        st(Size::Dw, 10, -8192, 1),
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        st(Size::Dw, 10, -8192, 1),
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        st(Size::Dw, 10, -8192, 1),
        mov(0, 0),
        EXIT,
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::StackTooDeep { .. }), "{e:?}");
}

#[test]
fn a_callee_reading_a_callee_saved_register_first_is_rejected() {
    // R6..R9 are callee-saved: they hold the *caller's* values, which the
    // callee has no business reading.
    let e = check(&[
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        movr(0, 6),
        EXIT,
    ])
    .unwrap_err();
    assert_eq!(e, VerifyError::UninitRegister { at: 3, reg: 6 });
}

// ── kfunc calls ─────────────────────────────────────────────────────

#[test]
fn an_unknown_kfunc_id_is_rejected() {
    assert_eq!(
        check_full(&[call(7), mov(0, 0), EXIT], &[], &[], Context::Atomic).unwrap_err(),
        VerifyError::UnknownKfunc { at: 0, id: 7 }
    );
}

#[test]
fn an_argument_register_does_not_survive_a_call() {
    // R0..R5 are clobbered by the ABI whatever the callee's arity. A verifier
    // that let a value survive there would let a released reference look
    // alive, which is the shape of bug that only shows up as a use-after-free.
    let k = [kfunc(
        "takes_scalar",
        SCALAR_ARG,
        ArgDesc::VOID,
        Context::Atomic,
    )];
    assert_eq!(
        check_full(
            &[mov(1, 1), call(0), movr(0, 1), EXIT],
            &[],
            &k,
            Context::Atomic
        )
        .unwrap_err(),
        VerifyError::UninitRegister { at: 2, reg: 1 }
    );
}

#[test]
fn a_sleepable_kfunc_is_unreachable_from_an_atomic_program() {
    // Sleepability is declared by the *hook*, not by a program flag, so this
    // is a type error rather than a runtime check (spec §4.5).
    let k = [sleepy_kfunc()];
    assert_eq!(
        check_full(&[call(0), mov(0, 0), EXIT], &[], &k, Context::Atomic).unwrap_err(),
        VerifyError::ContextMismatch {
            at: 0,
            required: Context::Sleepable,
            actual: Context::Atomic,
        }
    );
    // …and reachable from a sleepable one.
    check_full(&[call(0), mov(0, 0), EXIT], &[], &k, Context::Sleepable)
        .expect("a sleepable program may yield");
}

#[test]
fn a_scalar_argument_must_be_a_scalar() {
    let k = [kfunc(
        "takes_scalar",
        SCALAR_ARG,
        ArgDesc::VOID,
        Context::Atomic,
    )];
    let e = check_full(
        &[movr(1, 10), call(0), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::KfuncSignature { arg: 0, .. }),
        "{e:?}"
    );

    check_full(
        &[mov(1, 5), call(0), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("a scalar argument is fine");
}

#[test]
fn a_const_argument_must_be_a_proved_constant() {
    // `Const<N>`, which Linux spells as a `__k` suffix on a BTF parameter
    // name. A range is not a constant, however narrow.
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let k = [kfunc(
        "takes_const",
        CONST_ARG,
        ArgDesc::VOID,
        Context::Atomic,
    )];
    check_full(
        &[mov(1, 5), call(0), mov(0, 0), EXIT],
        CTX,
        &k,
        Context::Atomic,
    )
    .expect("a literal is constant");

    let e = check_full(
        &[
            ldx(Size::Dw, 1, 1, 0),
            jmp(CondOp::Gt, 1, 4, 3),
            call(0),
            mov(0, 0),
            EXIT,
            mov(0, 0),
            EXIT,
        ],
        CTX,
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::KfuncSignature { arg: 0, .. }),
        "{e:?}"
    );
}

#[test]
fn a_nullable_result_must_be_tested_before_use() {
    // `Option<Owned<T>>` is a verifier-enforced obligation, not a convention.
    let k = [acquire_kfunc(), release_kfunc()];
    let e = check_full(
        &[call(0), movr(1, 0), call(1), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert_eq!(e, VerifyError::PossiblyNull { at: 2, reg: 1 });
}

#[test]
fn acquire_test_and_release_verifies() {
    //   r0 = acquire()
    //   if r0 == 0 goto out
    //   r1 = r0; release(r1)
    //   out: r0 = 0; exit
    let k = [acquire_kfunc(), release_kfunc()];
    check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 2),
            movr(1, 0),
            call(1),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("acquire, test, release is the whole idiom");
}

#[test]
fn an_unreleased_reference_is_a_leak() {
    let k = [acquire_kfunc(), release_kfunc()];
    let e = check_full(
        &[call(0), jmp(CondOp::Eq, 0, 0, 0), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::LeakedReference { .. }), "{e:?}");
}

#[test]
fn releasing_twice_is_rejected() {
    let k = [acquire_kfunc(), release_kfunc()];
    let e = check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 4),
            movr(6, 0),
            movr(1, 6),
            call(1),
            movr(1, 6),
            call(1),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            VerifyError::ReleaseOfUnacquired { .. } | VerifyError::UninitRegister { .. }
        ),
        "{e:?}"
    );
}

#[test]
fn releasing_something_never_acquired_is_rejected() {
    // A `Trusted<T>` from the context is not a reference, so handing it to a
    // release is a refcount underflow waiting to happen.
    static CTX: &[ArgDesc] = &[ptr_desc(
        PtrKind::Object,
        ValidityDomain::Owned,
        ArgFlags::NONE,
    )];
    let k = [release_kfunc()];
    let e = check_full(
        &[ldx(Size::Dw, 1, 1, 0), call(0), mov(0, 0), EXIT],
        CTX,
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    // The context field is loaded as an opaque scalar (there is no BTF to type
    // it with), so this is caught as a signature mismatch rather than as an
    // unacquired release — either way, it does not verify.
    assert!(
        matches!(
            e,
            VerifyError::ReleaseOfUnacquired { .. } | VerifyError::KfuncSignature { .. }
        ),
        "{e:?}"
    );
}

#[test]
fn a_weaker_pointer_domain_does_not_satisfy_a_stronger_one() {
    // The verifier never widens a validity domain: a `Trusted<T>` cannot be
    // passed where an `Owned<T>` is wanted, though the reverse is fine.
    let k = [
        kfunc(
            "get_trusted",
            NO_ARGS,
            ptr_desc(
                PtrKind::Object,
                ValidityDomain::NonPreemptible,
                ArgFlags::NONE,
            ),
            Context::Atomic,
        ),
        release_kfunc(),
        kfunc("takes_trusted", TRUSTED_ARG, ArgDesc::VOID, Context::Atomic),
    ];
    let e = check_full(
        &[call(0), movr(1, 0), call(1), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::KfuncSignature { arg: 0, .. }),
        "{e:?}"
    );

    check_full(
        &[call(0), movr(1, 0), call(2), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("a trusted pointer satisfies a trusted parameter");
}

// ── The one rule: validity domains at an await ──────────────────────

#[test]
fn a_trusted_pointer_cannot_cross_an_await() {
    // Spec §4.4, and the whole of NARF's sleep-safety story. Linux needs
    // `bpf_rcu_read_lock`, `KF_RCU_PROTECTED`, `MEM_RCU`, and refcounted kptrs
    // to say this, because sleepability arrived years after the pointer model.
    let k = [
        kfunc(
            "get_trusted",
            NO_ARGS,
            ptr_desc(
                PtrKind::Object,
                ValidityDomain::NonPreemptible,
                ArgFlags::NONE,
            ),
            Context::Atomic,
        ),
        sleepy_kfunc(),
        kfunc("takes_trusted", TRUSTED_ARG, ArgDesc::VOID, Context::Atomic),
    ];
    let e = check_full(
        &[
            call(0),
            movr(6, 0),
            call(1),
            movr(1, 6),
            call(2),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Sleepable,
    )
    .unwrap_err();
    assert_eq!(
        e,
        VerifyError::PointerCrossesAwait {
            at: 2,
            reg: 6,
            domain: ValidityDomain::NonPreemptible,
        }
    );
}

#[test]
fn an_owned_reference_survives_an_await() {
    // Same program shape, one field different in the descriptor. That is the
    // point of putting validity in the type system: the rule is the same, the
    // answer follows from the domain.
    let k = [acquire_kfunc(), sleepy_kfunc(), release_kfunc()];
    check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 4),
            movr(6, 0),
            call(1),
            movr(1, 6),
            call(2),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Sleepable,
    )
    .expect("a refcount holds the object alive across a sleep");
}

#[test]
fn a_lock_guard_cannot_be_held_across_an_await() {
    // "No sleeping with a lock held" is not a separate check — a guard is
    // simply not sleep-safe, so the same kill-at-await rule catches it.
    let k = [lock_kfunc(), sleepy_kfunc(), unlock_kfunc()];
    let e = check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 4),
            movr(6, 0),
            call(1),
            movr(1, 6),
            call(2),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Sleepable,
    )
    .unwrap_err();
    assert_eq!(
        e,
        VerifyError::PointerCrossesAwait {
            at: 3,
            reg: 6,
            domain: ValidityDomain::NonPreemptible,
        }
    );
}

#[test]
fn a_lock_must_be_released_before_exit() {
    // Linearity from the same bookkeeping as any acquired reference — no
    // `active_lock_id`, no `process_spin_lock()`, no
    // `invalidate_non_owning_refs()`.
    let k = [lock_kfunc(), unlock_kfunc()];
    let e = check_full(
        &[call(0), jmp(CondOp::Eq, 0, 0, 0), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::LeakedReference { .. }), "{e:?}");

    check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 2),
            movr(1, 0),
            call(1),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("lock, test, unlock");
}

#[test]
fn only_one_lock_may_be_held_at_a_time() {
    // v1 permits one live guard, enforced by counting them — free, given the
    // reference bookkeeping already exists. Nesting under a declared
    // lock-order lattice is spec §8.3.
    let k = [lock_kfunc(), unlock_kfunc()];
    let e = check_full(
        &[
            call(0),
            jmp(CondOp::Eq, 0, 0, 5),
            movr(6, 0),
            call(0),
            jmp(CondOp::Eq, 0, 0, 2),
            movr(1, 6),
            call(1),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            VerifyError::TooManyLocks { .. } | VerifyError::LeakedReference { .. }
        ),
        "{e:?}"
    );
}

// ── Sized memory arguments ──────────────────────────────────────────

#[test]
fn an_uninit_memory_argument_initialises_the_stack() {
    // `&mut MaybeUninit<[u8]>`: the callee fills it, so the caller need not
    // have, and the bytes are defined afterwards.
    let k = [kfunc(
        "fill",
        uninit_mem_args(),
        ArgDesc::VOID,
        Context::Atomic,
    )];
    check_full(
        &[
            movr(1, 10),
            alu(AluOp::Sub, 1, 16),
            mov(2, 16),
            call(0),
            ldx(Size::Dw, 0, 10, -16),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("the callee initialised the region");
}

#[test]
fn a_read_memory_argument_requires_initialised_bytes() {
    let k = [kfunc("read", READ_MEM_ARGS, ArgDesc::VOID, Context::Atomic)];
    let e = check_full(
        &[
            movr(1, 10),
            alu(AluOp::Sub, 1, 16),
            mov(2, 16),
            call(0),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert_eq!(e, VerifyError::UninitStack { at: 3, off: -16 });
}

#[test]
fn a_memory_argument_longer_than_its_region_is_rejected() {
    let k = [kfunc(
        "fill",
        uninit_mem_args(),
        ArgDesc::VOID,
        Context::Atomic,
    )];
    let e = check_full(
        &[
            movr(1, 10),
            alu(AluOp::Sub, 1, 16),
            mov(2, 32),
            call(0),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert_eq!(e, VerifyError::OutOfBounds { at: 3 });
}

#[test]
fn a_memory_argument_with_an_unbounded_length_is_rejected() {
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let k = [kfunc(
        "fill",
        uninit_mem_args(),
        ArgDesc::VOID,
        Context::Atomic,
    )];
    let e = check_full(
        &[
            ldx(Size::Dw, 2, 1, 0),
            movr(1, 10),
            alu(AluOp::Sub, 1, 16),
            call(0),
            mov(0, 0),
            EXIT,
        ],
        CTX,
        &k,
        Context::Atomic,
    )
    .unwrap_err();
    assert_eq!(e, VerifyError::OutOfBounds { at: 3 });
}

#[test]
fn a_bounded_length_makes_the_same_argument_safe() {
    static CTX: &[ArgDesc] = &[ArgDesc::SCALAR64];
    let k = [kfunc(
        "fill",
        uninit_mem_args(),
        ArgDesc::VOID,
        Context::Atomic,
    )];
    check_full(
        &[
            ldx(Size::Dw, 2, 1, 0),
            jmp(CondOp::Gt, 2, 16, 5),
            movr(1, 10),
            alu(AluOp::Sub, 1, 16),
            call(0),
            mov(0, 0),
            EXIT,
            mov(0, 0),
            EXIT,
        ],
        CTX,
        &k,
        Context::Atomic,
    )
    .expect("an unsigned upper bound is exactly what the region check needs");
}

// ── Fault sites: objects and arenas ─────────────────────────────────

#[test]
fn a_load_through_an_object_pointer_records_a_fault_site() {
    // A typed kernel object is opaque — there is no in-kernel BTF to give it a
    // layout — so the load is emitted unchecked and covered by the exception
    // table instead. That is what makes `task->mm->owner` safe to write
    // without a null test, and the JIT must register the entry *before*
    // publishing the text (spec §4.3).
    let k = [kfunc(
        "get_object",
        NO_ARGS,
        ptr_desc(
            PtrKind::Object,
            ValidityDomain::NonPreemptible,
            ArgFlags::NONE,
        ),
        Context::Atomic,
    )];
    // This test previously asserted the load *verified*, on the grounds that
    // "an unchecked probe load is safe because the extable covers it". That
    // is false: the extable makes an *unmapped* address survivable and does
    // nothing for a mapped one, so an unchecked object load is an arbitrary
    // kernel read. Without BTF there is no object size to check an offset
    // against, so the honest answer is to reject the dereference outright.
    let err = check_full(
        &[call(0), ldx(Size::Dw, 6, 0, 24), movr(0, 6), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .expect_err("an opaque object pointer must not be dereferenceable");
    assert!(
        matches!(err, VerifyError::OpaqueDeref { at: 1, .. }),
        "expected OpaqueDeref at the load, got {err:?}"
    );
}

#[test]
fn arena_arithmetic_is_bounded_and_records_arena_fault_sites() {
    // The guard slots either side of the window are sized from the ISA's
    // 16-bit displacement, so an escape *by immediate* is structurally
    // impossible — that much of the original argument holds, and is why an
    // in-window access still needs no explicit check beyond the window bound.
    //
    // What the argument does *not* cover, and what this test previously got
    // wrong, is an escape by register-width arithmetic: `r0 *= 12345` leaves
    // the offset unknown, and no guard slot bounds an unknown u64.
    let k = [kfunc(
        "arena_base",
        NO_ARGS,
        ptr_desc(PtrKind::Arena, ValidityDomain::Static, ArgFlags::NONE),
        Context::Atomic,
    )];
    // Unknown offset: rejected.
    let err = check_full(
        &[
            call(0),
            alu(AluOp::Mul, 0, 12345),
            st(Size::Dw, 0, 32767, 1),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .expect_err("an unknown arena offset must not verify");
    assert!(
        matches!(err, VerifyError::ArenaOutOfWindow { .. }),
        "expected ArenaOutOfWindow, got {err:?}"
    );

    // In-window access: verifies, and still records the fault site the JIT
    // needs, because an in-bounds arena page may simply not be populated.
    let v = check_full(
        &[call(0), st(Size::Dw, 0, 32767, 1), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("an in-window arena store is fine");
    assert!(v.uses_arena);
    assert_eq!(v.fault_sites.len(), 1);
    assert!(v.fault_sites[0].arena);
    assert_eq!(
        v.fault_sites[0].dst_reg, None,
        "a store has no register to zero"
    );
}

// ── Address-space casts ─────────────────────────────────────────────

fn cast(dst: u8, src: u8, dst_as: u16, src_as: u16) -> Decoded {
    Decoded::AddrSpaceCast {
        dst: r(dst),
        src: r(src),
        dst_as,
        src_as,
    }
}

#[test]
fn the_two_arena_casts_are_accepted() {
    let k = [kfunc(
        "arena_base",
        NO_ARGS,
        ptr_desc(PtrKind::Arena, ValidityDomain::Static, ArgFlags::NONE),
        Context::Atomic,
    )];
    for (dst_as, src_as) in [(0u16, 1u16), (1, 0)] {
        check_full(
            &[call(0), cast(1, 0, dst_as, src_as), mov(0, 0), EXIT],
            &[],
            &k,
            Context::Atomic,
        )
        .unwrap_or_else(|e| panic!("cast ({dst_as}, {src_as}) must verify, got {e:?}"));
    }
}

#[test]
fn an_address_space_cast_outside_the_arena_pair_is_malformed_not_unimplemented() {
    // Address space 1 is the arena and 0 is the kernel; there is no third one,
    // so no compiler emits this and no runtime could execute it. That makes it
    // a *malformed* operand pair, and it must not be reported as
    // `NotImplemented` — that is the one error `narf-bpf`'s loader answers by
    // retrying under a structural check, and a meaningless operand has no
    // business on the path reserved for programs the verifier merely cannot
    // reason about yet.
    let k = [kfunc(
        "arena_base",
        NO_ARGS,
        ptr_desc(PtrKind::Arena, ValidityDomain::Static, ArgFlags::NONE),
        Context::Atomic,
    )];
    for (dst_as, src_as) in [(0u16, 0u16), (1, 1), (0, 2), (2, 0), (3, 7)] {
        let e = check_full(
            &[call(0), cast(1, 0, dst_as, src_as), mov(0, 0), EXIT],
            &[],
            &k,
            Context::Atomic,
        )
        .expect_err("a cast outside the arena pair must be rejected");
        assert_eq!(
            e,
            VerifyError::BadAddrSpaceCast {
                at: 1,
                dst_as,
                src_as
            },
            "cast ({dst_as}, {src_as})"
        );
    }
}

#[test]
fn a_bad_address_space_cast_names_its_operands() {
    let k = [kfunc(
        "arena_base",
        NO_ARGS,
        ptr_desc(PtrKind::Arena, ValidityDomain::Static, ArgFlags::NONE),
        Context::Atomic,
    )];
    let e = check_full(
        &[call(0), cast(1, 0, 3, 7), mov(0, 0), EXIT],
        &[],
        &k,
        Context::Atomic,
    )
    .expect_err("a meaningless address-space pair must be rejected");
    assert_eq!(
        e,
        VerifyError::BadAddrSpaceCast {
            at: 1,
            dst_as: 3,
            src_as: 7
        },
        "the diagnostic must name the pair that made no sense"
    );
    assert!(
        !matches!(e, VerifyError::NotImplemented(_)),
        "a malformed operand is not an unimplemented construct"
    );
}

#[test]
fn casting_something_that_is_not_an_arena_pointer_is_rejected() {
    // The pair is legal; the operand is not. Two separate checks, and the
    // operand one must still fire.
    let e = check(&[mov(1, 0), cast(2, 1, 0, 1), mov(0, 0), EXIT])
        .expect_err("a scalar is not an arena pointer");
    assert!(matches!(e, VerifyError::NotAPointer { .. }), "{e:?}");
}

// ── Atomics ─────────────────────────────────────────────────────────

#[test]
fn an_atomic_add_on_the_stack_verifies() {
    ok(&[
        st(Size::Dw, 10, -8, 0),
        mov(1, 1),
        Decoded::Atomic {
            size: Size::Dw,
            op: AtomicOp::Add { fetch: true },
            dst: r(10),
            src: r(1),
            off: -8,
        },
        movr(0, 1),
        EXIT,
    ]);
}

#[test]
fn a_compare_and_exchange_clobbers_r0() {
    // The only instruction in the ISA with an implicit register operand.
    ok(&[
        st(Size::Dw, 10, -8, 0),
        mov(0, 0),
        mov(1, 1),
        Decoded::Atomic {
            size: Size::Dw,
            op: AtomicOp::Cmpxchg,
            dst: r(10),
            src: r(1),
            off: -8,
        },
        EXIT,
    ]);
}

#[test]
fn an_atomic_on_a_scalar_is_rejected() {
    assert_eq!(
        err(&[
            mov(2, 0),
            mov(1, 1),
            Decoded::Atomic {
                size: Size::Dw,
                op: AtomicOp::Add { fetch: false },
                dst: r(2),
                src: r(1),
                off: 0,
            },
            mov(0, 0),
            EXIT,
        ]),
        VerifyError::NotAPointer { at: 2, reg: 2 }
    );
}

/// An atomic through `r3`, which `variable_frame_ptr` leaves pointing into the
/// frame at an offset only known within a range.
fn variable_atomic(size: Size) -> Decoded {
    Decoded::Atomic {
        size,
        op: AtomicOp::Add { fetch: false },
        dst: r(3),
        src: r(4),
        off: 0,
    }
}

#[test]
fn a_variable_stack_atomic_is_bounded_and_defines_nothing() {
    // The atomic path resolves through the same `access` as a load and a store,
    // so the bound is shared — but the *state* update is its own arm, and it is
    // the arm no differential test can reach: the reference interpreter models
    // loads and stores and answers `Unsupported` for atomics, so the concrete
    // side of this is unit tests only. Said here rather than left implicit,
    // because "covered by the fuzzer" is otherwise a reasonable assumption.

    // In range: verifies.
    let mut p = variable_frame_ptr(16, 8);
    p.extend_from_slice(&[mov(4, 1), variable_atomic(Size::Dw), mov(0, 0), EXIT]);
    check_ctx(&p, CTX1).expect("a bounded variable atomic is in the frame");

    // Out of range at the top: rejected by the same interval check.
    let mut p = variable_frame_ptr(16, 31);
    p.extend_from_slice(&[mov(4, 1), variable_atomic(Size::Dw), mov(0, 0), EXIT]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { .. }), "{e:?}");

    // And it defines nothing: an atomic that might have landed anywhere in the
    // range cannot stand in for initialising a particular slot.
    let mut p = variable_frame_ptr(16, 8);
    p.extend_from_slice(&[
        mov(4, 1),
        variable_atomic(Size::Dw),
        ldx(Size::Dw, 5, 10, -16),
        mov(0, 0),
        EXIT,
    ]);
    let e = check_ctx(&p, CTX1).unwrap_err();
    assert!(matches!(e, VerifyError::UninitStack { .. }), "{e:?}");
}

// ── Constructs that fail closed ─────────────────────────────────────

#[test]
fn callback_subprogram_addresses_are_not_implemented_yet() {
    // Main must *terminate* before the callback's entry slot. It previously did
    // not — a `mov` sat where the boundary falls, so main fell straight through
    // into the callback body — and the program reached the `NotImplemented` arm
    // only because nothing checked subprogram confinement yet. Now that
    // something does, the malformed shape is caught first and this test would
    // have been asserting the wrong rejection.
    //
    // Fixed by making the program well-formed (which is what a compiler emits)
    // rather than by relaxing the check. The fallthrough-across-a-boundary case
    // it used to exercise by accident is now covered on purpose, by
    // `fallthrough_into_the_next_subprogram_is_rejected`.
    let e = check(&[
        Decoded::LoadImm64 {
            dst: r(1),
            value: Imm64::SubprogAddr(1),
        },
        EXIT,
        mov(0, 0),
        EXIT,
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::NotImplemented(_)), "{e:?}");
}

// ── `LD_IMM64` map pseudo-forms ──────────────────────────────────────

const MAP8: MapDesc = MapDesc {
    fd: 3,
    key_size: 4,
    value_size: 8,
    max_entries: 16,
};

fn ld_map_fd(dst: u8, fd: i32) -> Decoded {
    Decoded::LoadImm64 {
        dst: r(dst),
        value: Imm64::MapFd(fd),
    }
}

fn ld_map_value(dst: u8, fd: i32, value_offset: i32) -> Decoded {
    Decoded::LoadImm64 {
        dst: r(dst),
        value: Imm64::MapValue { fd, value_offset },
    }
}

#[test]
fn a_map_fd_immediate_resolves_against_the_map_set() {
    // Was `NotImplemented` before `Program` carried a map set. The handle is
    // opaque, so the only thing the program does with it here is not touch it.
    let v = check_maps(&[ld_map_fd(1, 3), mov(0, 0), EXIT], &[MAP8]).expect("map fd resolved");
    // A handle is not an arena pointer; naming one must not pin the arena base
    // register for the program's whole body.
    assert!(!v.uses_arena);
}

#[test]
fn an_unknown_map_fd_is_rejected() {
    // Fails closed: the value width is what bounds every access through a map
    // pointer, and there is no safe default for a width nobody stated.
    let e = check_maps(&[ld_map_fd(1, 9), mov(0, 0), EXIT], &[MAP8]).unwrap_err();
    assert!(
        matches!(e, VerifyError::UnknownMap { at: 0, fd: 9 }),
        "{e:?}"
    );
}

#[test]
fn a_map_fd_immediate_with_an_empty_map_set_is_rejected() {
    let e = check(&[ld_map_fd(1, 3), mov(0, 0), EXIT]).unwrap_err();
    assert!(
        matches!(e, VerifyError::UnknownMap { at: 0, fd: 3 }),
        "{e:?}"
    );
}

#[test]
fn a_map_handle_may_not_be_dereferenced() {
    // Linux's `CONST_PTR_TO_MAP` is equally undereferenceable. Here it falls out
    // of the handle being a `PtrClass::Object` with no BTF: nothing says how
    // large a `struct bpf_map` is, so no offset can be proved inside it.
    let e = check_maps(&[ld_map_fd(1, 3), ldx(Size::Dw, 0, 1, 0), EXIT], &[MAP8]).unwrap_err();
    assert!(
        matches!(e, VerifyError::OpaqueDeref { at: 2, reg: 1 }),
        "{e:?}"
    );
}

#[test]
fn a_map_handle_may_not_be_returned() {
    // `exit` hands R0 to the kernel. A pointer there is a kernel address
    // leaking into a program's return value.
    let e = check_maps(&[ld_map_fd(0, 3), EXIT], &[MAP8]).unwrap_err();
    assert!(
        matches!(e, VerifyError::PointerArithmetic { at: 2, reg: 0 }),
        "{e:?}"
    );
}

#[test]
fn a_map_index_immediate_resolves_by_position() {
    // `BPF_PSEUDO_MAP_IDX` indexes the loader's fd array instead of naming an
    // fd, which is how libbpf avoids patching instructions after creating the
    // maps. Descriptor 1 is deliberately given a *different* fd from its index,
    // so a resolver that confused the two would fail this.
    let maps = [
        MapDesc { fd: 40, ..MAP8 },
        MapDesc {
            fd: 41,
            value_size: 32,
            ..MAP8
        },
    ];
    let v = check_maps(
        &[
            Decoded::LoadImm64 {
                dst: r(1),
                value: Imm64::MapIdx(1),
            },
            mov(0, 0),
            EXIT,
        ],
        &maps,
    );
    assert!(v.is_ok(), "{:?}", v.unwrap_err());
    // ...and index 2 does not exist, even though there are fds 40 and 41.
    let e = check_maps(
        &[
            Decoded::LoadImm64 {
                dst: r(1),
                value: Imm64::MapIdx(2),
            },
            mov(0, 0),
            EXIT,
        ],
        &maps,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::UnknownMap { at: 0, fd: 2 }),
        "{e:?}"
    );
    // A negative index is the same failure, not a panic on the cast.
    let e = check_maps(
        &[
            Decoded::LoadImm64 {
                dst: r(1),
                value: Imm64::MapIdx(-1),
            },
            mov(0, 0),
            EXIT,
        ],
        &maps,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::UnknownMap { at: 0, fd: -1 }),
        "{e:?}"
    );
}

#[test]
fn a_map_value_immediate_is_a_bounded_writable_region() {
    // This is the form LLVM emits for a global variable, whose storage is a
    // one-entry `.data`/`.bss` map. The whole point of the descriptor is that
    // `value_size` bounds the access.
    let v = check_maps(
        &[
            ld_map_value(1, 3, 0),
            ldx(Size::Dw, 0, 1, 0),
            st(Size::Dw, 1, 0, 7),
            mov(0, 0),
            EXIT,
        ],
        &[MAP8],
    );
    assert!(v.is_ok(), "{:?}", v.unwrap_err());
    // A map value is not a faulting class, so no exception-table entry is owed
    // for an access through it.
    assert!(v.unwrap().fault_sites.is_empty());
}

#[test]
fn a_map_value_access_past_the_value_is_rejected() {
    // `value_size` is 8, so a dword load at +8 is one byte past the end. The
    // bound is what the whole descriptor exists to supply; without it this
    // pointer would be an unbounded region.
    let e = check_maps(
        &[ld_map_value(1, 3, 0), ldx(Size::Dw, 0, 1, 8), EXIT],
        &[MAP8],
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { at: 2 }), "{e:?}");
}

#[test]
fn a_map_value_offset_is_folded_into_the_pointer() {
    // `value_offset` shifts the whole window, so with a 16-byte value and an
    // offset of 8 the reachable range is [8, 16): a dword at +0 fits and one at
    // +8 does not. A resolver that dropped the offset would accept both.
    const MAP16: MapDesc = MapDesc {
        value_size: 16,
        ..MAP8
    };
    let ok = check_maps(
        &[ld_map_value(1, 3, 8), ldx(Size::Dw, 0, 1, 0), EXIT],
        &[MAP16],
    );
    assert!(ok.is_ok(), "{:?}", ok.unwrap_err());
    let e = check_maps(
        &[ld_map_value(1, 3, 8), ldx(Size::Dw, 0, 1, 8), EXIT],
        &[MAP16],
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { at: 2 }), "{e:?}");
}

#[test]
fn a_map_value_offset_outside_the_value_is_rejected_at_the_immediate() {
    // Rejected where the mistake is, not at the first access through it, so the
    // instruction index names something the loader can act on. Linux rejects
    // the same thing in `resolve_pseudo_ldimm64`.
    let e = check_maps(&[ld_map_value(1, 3, 8), mov(0, 0), EXIT], &[MAP8]).unwrap_err();
    assert!(
        matches!(
            e,
            VerifyError::MapValueOffset {
                at: 0,
                off: 8,
                size: 8
            }
        ),
        "{e:?}"
    );
    let e = check_maps(&[ld_map_value(1, 3, -4), mov(0, 0), EXIT], &[MAP8]).unwrap_err();
    assert!(
        matches!(e, VerifyError::MapValueOffset { at: 0, off: -4, .. }),
        "{e:?}"
    );
}

#[test]
fn a_map_value_pointer_may_be_passed_as_a_byte_region() {
    // `check_mem_arg` already bounds `PtrClass::MapValue` against `p.size`;
    // supplying the size is what makes that arm reachable at all.
    let take_mem = KfuncDesc {
        id: 0,
        name: "take_mem",
        addr: 0x1000,
        args: &[
            ArgDesc {
                kind: TypeKind::Ptr {
                    kind: PtrKind::Mem,
                    key: TypeKey::NONE,
                },
                domain: ValidityDomain::NonPreemptible,
                flags: ArgFlags::SIZED_BY_NEXT,
            },
            ArgDesc::SCALAR64,
        ],
        ret: ArgDesc::SCALAR64,
        context: Context::Atomic,
    };
    // The whole 8-byte value: in bounds.
    let ok = check_all(
        &[ld_map_value(1, 3, 0), mov(2, 8), call(0), mov(0, 0), EXIT],
        &[],
        &[take_mem],
        &[MAP8],
        Context::Atomic,
    );
    assert!(ok.is_ok(), "{:?}", ok.unwrap_err());
    // One byte more than the value holds.
    let e = check_all(
        &[ld_map_value(1, 3, 0), mov(2, 9), call(0), mov(0, 0), EXIT],
        &[],
        &[take_mem],
        &[MAP8],
        Context::Atomic,
    )
    .unwrap_err();
    assert!(matches!(e, VerifyError::OutOfBounds { at: 3 }), "{e:?}");
}

#[test]
fn a_map_handle_satisfies_a_trusted_object_parameter() {
    // How a map-access kfunc receives its map. The handle's domain is `Static`
    // — a program holds a reference to every map it names for its whole life —
    // and a `Static` pointer satisfies a `NonPreemptible` parameter because the
    // verifier accepts a *stronger* domain than asked for, never a weaker one.
    let take_map = KfuncDesc {
        id: 0,
        name: "take_map",
        addr: 0x1000,
        args: &[ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Object,
                key: crate::kfunc::MAP_HANDLE_TYPE_KEY,
            },
            domain: ValidityDomain::NonPreemptible,
            flags: ArgFlags::NONE,
        }],
        ret: ArgDesc::SCALAR64,
        context: Context::Atomic,
    };
    let ok = check_all(
        &[ld_map_fd(1, 3), call(0), mov(0, 0), EXIT],
        &[],
        &[take_map],
        &[MAP8],
        Context::Atomic,
    );
    assert!(ok.is_ok(), "{:?}", ok.unwrap_err());

    // A kfunc wanting some *other* object type must not accept a map handle:
    // the `TypeKey` is what keeps two opaque handles from being interchangeable.
    let take_other = KfuncDesc {
        args: &[ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Object,
                key: TypeKey(0xABCD),
            },
            domain: ValidityDomain::NonPreemptible,
            flags: ArgFlags::NONE,
        }],
        ..take_map
    };
    let e = check_all(
        &[ld_map_fd(1, 3), call(0), mov(0, 0), EXIT],
        &[],
        &[take_other],
        &[MAP8],
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::KfuncSignature { at: 2, arg: 0, .. }),
        "{e:?}"
    );
}

#[test]
fn a_shifted_map_handle_is_not_a_map_handle() {
    // `alu`'s (Ptr, Scalar) arm permits add/sub on every pointer class, so the
    // offset check in `check_args` is the only thing standing between a kfunc
    // and a `NonNull<BpfMap>` at an attacker-chosen address.
    let take_map = KfuncDesc {
        id: 0,
        name: "take_map",
        addr: 0x1000,
        args: &[ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Object,
                key: crate::kfunc::MAP_HANDLE_TYPE_KEY,
            },
            domain: ValidityDomain::NonPreemptible,
            flags: ArgFlags::NONE,
        }],
        ret: ArgDesc::SCALAR64,
        context: Context::Atomic,
    };
    let e = check_all(
        &[
            ld_map_fd(1, 3),
            alu(AluOp::Add, 1, 64),
            call(0),
            mov(0, 0),
            EXIT,
        ],
        &[],
        &[take_map],
        &[MAP8],
        Context::Atomic,
    )
    .unwrap_err();
    assert!(
        matches!(e, VerifyError::KfuncSignature { at: 3, arg: 0, .. }),
        "{e:?}"
    );
}

#[test]
fn the_map_handle_type_key_is_not_the_reserved_none() {
    // `TypeKey(0)` means "not a typed object", so a handle keyed 0 would be
    // interchangeable with every other untyped pointer at a kfunc boundary.
    assert!(crate::kfunc::MAP_HANDLE_TYPE_KEY.is_some());
    // And the hash is a pure function of the name, so `narf-bpf`'s `BpfObject`
    // impl can derive the same key without a shared registry.
    assert_eq!(
        crate::kfunc::MAP_HANDLE_TYPE_KEY,
        TypeKey(crate::kfunc::fnv1a32_nonzero(
            crate::kfunc::MAP_HANDLE_TYPE_NAME
        ))
    );
}

// ── Against the reference interpreter ───────────────────────────────

#[test]
fn a_verified_program_computes_what_the_reference_interpreter_says() {
    // Verification proves safety, not correctness — but a program the verifier
    // accepts must still *mean* what the ISA says, and running it is the only
    // way to check that the transfer functions were modelling the right
    // machine. If the abstract stack model disagreed with the concrete one
    // about slot addressing, this would diverge.
    let prog = &[
        mov(0, 7),
        alu(AluOp::Mul, 0, 6),
        stx(Size::Dw, 10, -8, 0),
        mov(0, 0),
        ldx(Size::Dw, 0, 10, -8),
        alu(AluOp::Add, 0, 1),
        EXIT,
    ];
    ok(prog);
    let image = encode_all(prog);
    let mut m = interp::Machine::new();
    assert_eq!(interp::run(&image, &mut m), Ok(43));
}

#[test]
fn a_verified_counted_loop_terminates_under_fuel() {
    // Fuel is what makes verification a safety problem rather than a
    // termination problem, so the two halves of that bargain are worth
    // exercising together: the verifier accepts the loop, and the concrete
    // machine's fuel is what stops it.
    let prog = &[
        mov(0, 0),
        alu(AluOp::Add, 0, 1),
        jmp(CondOp::Lt, 0, 64, -2),
        EXIT,
    ];
    ok(prog);
    let image = encode_all(prog);
    let mut m = interp::Machine::new();
    assert_eq!(interp::run(&image, &mut m), Ok(64));

    // An unbounded loop verifies just as happily, and fuel is what ends it.
    let spin = &[mov(0, 0), alu(AluOp::Add, 0, 1), Decoded::Jump { off: -2 }];
    ok(spin);
    let image = encode_all(spin);
    let mut m = interp::Machine::new();
    m.fuel = 1000;
    assert_eq!(interp::run(&image, &mut m), Err(interp::Trap::OutOfFuel));
}

#[test]
fn verification_is_a_function_of_the_program_alone() {
    // No budget means no dependence on how much work verification took, so the
    // same program verifies identically however large it is. A thousand
    // sequential adds would blow past Linux's per-instruction state limit long
    // before its instruction limit.
    let mut prog = vec![mov(0, 0)];
    for _ in 0..2000 {
        prog.push(alu(AluOp::Add, 0, 1));
    }
    prog.push(EXIT);
    let v = ok(&prog);
    assert_eq!(v.insns.len(), 2002);
}

// ── The whole-program safety property ───────────────────────────────

/// xorshift64*, so the corpus is reproducible without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_size(rng: &mut Rng) -> Size {
    match rng.below(4) {
        0 => Size::B,
        1 => Size::H,
        2 => Size::W,
        _ => Size::Dw,
    }
}

/// A displacement biased towards the two edges that matter.
///
/// A uniform draw over the whole frame almost never lands within eight bytes
/// of the frame pointer, which is exactly where a wide access straddles it —
/// the case a bounds check is most likely to get wrong. Nor does it often
/// reach past the budget. Both edges are sampled explicitly.
fn random_off(rng: &mut Rng) -> i16 {
    let mag = match rng.below(4) {
        0 => rng.below(9),
        1 => rng.below(64),
        2 => rng.below(4096),
        _ => rng.below(20_000),
    };
    -(mag.min(i16::MAX as u64) as i16)
}

/// A random program of stack traffic, arithmetic, and forward branches.
///
/// Only forward branches, so every generated program terminates and a trap
/// means a real out-of-bounds rather than exhausted fuel.
fn random_program(rng: &mut Rng, len: usize) -> Vec<Decoded> {
    let mut out = Vec::with_capacity(len + 2);
    for i in 0..len {
        let remaining = (len - i) as i16;
        out.push(match rng.below(9) {
            0 => mov(rng.below(7) as u8, rng.next() as i32),
            1 | 2 => {
                // Manufacture a frame pointer at a random depth. The register
                // pool is small on purpose: a store only reaches the stack if
                // it names a register some earlier instruction pointed there.
                let d = rng.below(4) as u8;
                if rng.below(2) == 0 {
                    movr(d, 10)
                } else {
                    alu(AluOp::Sub, d, rng.below(2048) as i32)
                }
            }
            3 => alu(
                [AluOp::Add, AluOp::Sub, AluOp::And, AluOp::Or, AluOp::Xor][rng.below(5) as usize],
                rng.below(7) as u8,
                rng.next() as i32,
            ),
            7 => alur(AluOp::Add, rng.below(7) as u8, rng.below(7) as u8),
            4 => st(
                random_size(rng),
                rng.below(4) as u8,
                random_off(rng),
                rng.next() as i32,
            ),
            5 => stx(
                random_size(rng),
                rng.below(4) as u8,
                random_off(rng),
                rng.below(7) as u8,
            ),
            6 => ldx(
                random_size(rng),
                rng.below(7) as u8,
                rng.below(4) as u8,
                random_off(rng),
            ),
            _ => jmp(
                CondOp::Gt,
                rng.below(7) as u8,
                rng.next() as i32,
                rng.below(remaining.max(1) as u64) as i16,
            ),
        });
    }
    out.push(mov(0, 0));
    out.push(EXIT);
    out
}

#[test]
fn every_program_the_verifier_accepts_runs_without_an_out_of_bounds_access() {
    // The property the whole crate exists for, stated end to end: verification
    // implies the concrete machine never leaves its stack. Most random
    // programs are rejected — that is fine and expected — but every one that
    // is *accepted* must run clean.
    //
    // The reference interpreter's stack is exactly the verifier's budget, so
    // "accepted" and "in range" are the same statement and a trap here is a
    // real hole rather than a modelling mismatch.
    let mut rng = Rng(0x5EED_1234_5678_9ABC);
    let mut accepted = 0usize;
    for _ in 0..20_000 {
        let len = 1 + rng.below(12) as usize;
        let prog = random_program(&mut rng, len);
        let image = encode_all(&prog);
        let Ok(verified) = verify(&Program {
            insns: &image,
            context: Context::Atomic,
            ctx_fields: &[],
            kfuncs: &[],
            maps: &[],
        }) else {
            continue;
        };
        accepted += 1;
        assert!(
            verified.max_stack_bytes <= crate::MAX_STACK_BYTES,
            "verified program claims {} bytes of stack",
            verified.max_stack_bytes
        );
        let mut m = interp::Machine::new();
        match interp::run(&image, &mut m) {
            Ok(_) => {}
            Err(interp::Trap::OutOfFuel) => {}
            Err(t) => panic!("verified program trapped with {t:?}:\n{prog:#?}"),
        }
        assert_frame_fits(&m, verified.max_stack_bytes, &prog);
    }
    // If the generator drifted into producing nothing acceptable, the test
    // above would pass vacuously. It must not be allowed to.
    assert!(
        accepted > 200,
        "only {accepted} of 20000 generated programs verified — the corpus has \
         stopped exercising anything"
    );
}

/// Assert the run stayed inside the frame the verifier asked the runtime for.
///
/// `max_stack_bytes` is not a diagnostic — it is how much stack the runtime
/// allocates — so a program that writes below it corrupts whatever is there.
/// The reference machine has the *whole* budget, so this is invisible to a
/// plain trap check: every byte below the claimed frame is still perfectly
/// addressable and the run comes back `Ok`. Only the `defined` shadow can see
/// it, which is the second reason that shadow exists.
fn assert_frame_fits(m: &interp::Machine, max_stack_bytes: u32, prog: &[Decoded]) {
    let below = interp::STACK_BYTES - max_stack_bytes as usize;
    if let Some(i) = m.defined[..below].iter().position(|&d| d) {
        panic!(
            "wrote {} bytes below R10 but the verified frame is only {max_stack_bytes}:\n{prog:#?}",
            interp::STACK_BYTES - i
        );
    }
}

// ── differential: a variable frame offset, over every index it admits ──

/// One randomly-shaped program built around a bounded variable frame offset.
///
/// The knobs are the ones that can each independently break the bound: how
/// deep the base is, how far the index can reach, how wide the access is,
/// *which window* of the frame was written first, and which direction the
/// access goes.
///
/// `init_from` is not decoration. Always pre-writing the frame from R10
/// downwards means the deep end of a read's range is the uninitialised end, so
/// an initialisation check that looked only at `addr.min` would reject the same
/// programs the correct one does and the differential would agree with a broken
/// verifier. A window that can start anywhere makes both ends reachable.
#[allow(clippy::too_many_arguments)]
fn variable_offset_program(
    depth: i32,
    mask: i32,
    disp: i16,
    size: Size,
    init_from: u32,
    init_words: u32,
    write: bool,
) -> Vec<Decoded> {
    let mut p = Vec::new();
    for j in init_from..init_from + init_words {
        p.push(st(Size::Dw, 10, -8 * (j as i16 + 1), 0));
    }
    p.push(ldx(Size::Dw, 2, 1, 0)); // r2 = ctx[0] — the unknown
    p.push(alu(AluOp::And, 2, mask));
    p.push(movr(3, 10));
    p.push(alu(AluOp::Sub, 3, depth));
    p.push(alur(AluOp::Add, 3, 2));
    p.push(if write {
        st(size, 3, disp, 0x5A)
    } else {
        ldx(size, 4, 3, disp)
    });
    p.push(mov(0, 0));
    p.push(EXIT);
    p
}

#[test]
fn a_verified_variable_frame_access_is_safe_for_every_index_it_admits() {
    // The differential for the transfer function this change added. A random
    // *program* is not enough here: the whole point of a variable offset is
    // that one program has many concrete behaviours, so each accepted program
    // is run once per value the mask admits — exhaustively, not sampled. If
    // the abstract range is wrong at either edge, the run at that edge traps.
    //
    // Three separate claims are checked per run, and they fail in different
    // ways: `BadAccess` means the range escaped the frame, `UninitRead` means
    // the initialisation check trusted bytes nothing wrote, and
    // `assert_frame_fits` means `note_depth` under-reported the frame the
    // runtime has to allocate — which no trap can catch, because the reference
    // machine always has the whole budget.
    let mut rng = Rng(0xB0FF_1234_ABCD_0001);
    let mut accepted = 0usize;
    let mut accepted_variable = 0usize;
    for _ in 0..3_000 {
        // Capped at 255 so every index can be enumerated rather than sampled.
        let mask = rng.below(256) as i32;
        let depth = match rng.below(4) {
            0 => rng.below(40) as i32,
            1 => rng.below(300) as i32,
            2 => 16_384 - rng.below(64) as i32,
            _ => rng.below(20_000) as i32,
        };
        let disp = match rng.below(3) {
            0 => 0,
            1 => rng.below(24) as i16,
            _ => -(rng.below(24) as i16),
        };
        let size = random_size(&mut rng);
        // The window starts anywhere in the shallow end of the frame and runs
        // downwards, so a read's range can be initialised at its deep end, its
        // shallow end, both, or neither.
        let init_from = rng.below(8) as u32;
        let init_words = rng.below(6) as u32;
        let write = rng.below(2) == 0;
        let prog = variable_offset_program(depth, mask, disp, size, init_from, init_words, write);
        let image = encode_all(&prog);
        let Ok(verified) = verify(&Program {
            insns: &image,
            context: Context::Atomic,
            ctx_fields: CTX1,
            kfuncs: &[],
            maps: &[],
        }) else {
            continue;
        };
        accepted += 1;
        if mask != 0 {
            accepted_variable += 1;
        }
        assert!(verified.max_stack_bytes <= crate::MAX_STACK_BYTES);
        for i in 0..=(mask as u64) {
            let mut m = interp::Machine::with_ctx(&[i]);
            match interp::run(&image, &mut m) {
                Ok(_) | Err(interp::Trap::OutOfFuel) => {}
                Err(t) => panic!("index {i} trapped with {t:?}:\n{prog:#?}"),
            }
            assert_frame_fits(&m, verified.max_stack_bytes, &prog);
        }
    }
    assert!(
        accepted > 300,
        "only {accepted} programs verified — the generator has stopped \
         producing provable ones"
    );
    // A mask of zero collapses to a constant offset, which is the *old* path.
    // Without this the whole test could pass while proving nothing about the
    // one it was written for.
    assert!(
        accepted_variable > 200,
        "only {accepted_variable} accepted programs had a genuinely variable \
         offset — this test is measuring the constant path"
    );
}

// ── termination: the stack must widen, not just join ────────────────

#[test]
fn stack_carried_counter_converges() {
    // r1 = 0; *(u64*)(r10-8) = r1
    // L: r1 = *(u64*)(r10-8); r1 += 1; *(u64*)(r10-8) = r1; goto L
    //
    // An unbounded loop is *supposed* to verify — fuel bounds it at run time
    // (spec §1.1). The hazard is the value carried around the loop through a
    // stack slot: `AbsState::widen` widened the eleven registers and then
    // took the plain join of the stack, so the slot's interval climbed one
    // step per round and the fixpoint never converged.
    //
    // That is not a slow load. `verify()` runs synchronously inside `sys_bpf`
    // with no yield point, and the scheduler does not tick inside a syscall,
    // so a non-converging fixpoint is an unprivileged kernel hang.
    //
    // The identical loop with the counter in a *register* has always
    // converged (see `unbounded_loop_verifies`), which is what made this easy
    // to miss: the widening operator was correct and simply never reached.
    let prog = &[
        mov(1, 0),
        stx(Size::Dw, 10, -8, 1),
        ldx(Size::Dw, 1, 10, -8),
        alu(AluOp::Add, 1, 1),
        stx(Size::Dw, 10, -8, 1),
        Decoded::Jump { off: -4 },
    ];
    let v = check_full(prog, &[], &[], Context::Atomic)
        .expect("a stack-carried counter must converge, not diverge");
    assert!(v.max_stack_bytes >= 8);
}

#[test]
fn divergence_is_reported_not_hung() {
    // The backstop itself: whatever the lattice does, the fixpoint must
    // terminate with an error rather than spin. Asserting the budget is
    // finite is enough — a regression that removes the cap turns
    // `stack_carried_counter_converges` from a failure into a hang, which is
    // exactly the outcome the cap exists to prevent.
    assert!(crate::fixpoint::fixpoint_round_budget(0) > 0);
    assert!(crate::fixpoint::fixpoint_round_budget(1_000_000) > 0);
}

// ── faulting pointer classes are still bounds-checked ───────────────

/// The review's proof-of-concept, verbatim in shape: take an
/// attacker-controlled word out of the context, add it to a kfunc-returned
/// object pointer, and dereference.
fn arbitrary_access_program(write: bool) -> Vec<Decoded> {
    let mut p = vec![
        ldx(Size::Dw, 7, 1, 0),   // r7 = ctx[0] — attacker-controlled
        call(0),                  // r0 = acquire() -> Option<Owned<T>>
        jmp(CondOp::Eq, 0, 0, 5), // null path skips straight to the exit
        movr(6, 0),
        alur(AluOp::Add, 6, 7), // r6 = obj + attacker word
    ];
    if write {
        p.push(stx(Size::Dw, 6, 0, 7));
    } else {
        p.push(ldx(Size::Dw, 8, 6, 0));
    }
    p.push(movr(1, 0));
    p.push(call(1)); // release
    p.push(mov(0, 0));
    p.push(EXIT);
    p
}

#[test]
fn unbounded_arithmetic_on_an_object_pointer_is_rejected() {
    // Before the fix this verified with `fault_sites=2`. The extable makes an
    // *unmapped* address survivable; it does nothing for a mapped one, so an
    // unbounded add to a live kernel object pointer is an arbitrary kernel
    // read/write primitive, not a recoverable fault.
    let k = [acquire_kfunc(), release_kfunc()];
    for write in [false, true] {
        let err = check_full(
            &arbitrary_access_program(write),
            &[ArgDesc::SCALAR64],
            &k,
            Context::Atomic,
        )
        .expect_err("unbounded arithmetic on an object pointer must be rejected");
        assert!(
            matches!(err, VerifyError::OpaqueDeref { .. }),
            "expected OpaqueDeref, got {err:?}"
        );
    }
}

#[test]
fn even_a_constant_offset_into_an_opaque_object_is_rejected() {
    // Constant does not mean safe: the constant is in an attacker-supplied
    // program, and without BTF nothing says how large the object is. Linux
    // permits field access only because `btf_struct_access()` can check the
    // offset names a real field. Until NARF has that, a `Trusted<T>` is a
    // handle to hand back to a kfunc, not something to dereference.
    let k = [acquire_kfunc(), release_kfunc()];
    let prog = &[
        call(0),
        jmp(CondOp::Eq, 0, 0, 3),
        ldx(Size::Dw, 8, 0, 16), // constant field offset
        movr(1, 0),
        call(1),
        mov(0, 0),
        EXIT,
    ];
    let err = check_full(prog, &[], &k, Context::Atomic)
        .expect_err("opaque object dereference must be rejected");
    assert!(
        matches!(err, VerifyError::OpaqueDeref { .. }),
        "expected OpaqueDeref, got {err:?}"
    );
}

// ── null tests must be 64-bit to refine a pointer ───────────────────

#[test]
fn a_32bit_null_test_does_not_release_the_reference() {
    // `(u32)ptr == 0` does not imply `ptr == 0`. Treating it as a null test
    // meant a one-bit opcode change — JEQ32 for JEQ64 — convinced the verifier
    // an acquired reference had been released. At run time any object whose
    // low 32 bits happen to be zero (page-aligned, or any handle-shaped
    // return) takes the branch and leaks the refcount permanently.
    //
    // The sharper form is locks: Option<Guard<'_>> acquires a lock reference
    // the same way, so the same substitution makes the verifier believe the
    // lock was dropped, and `kill_at_await` then finds nothing to kill. That
    // is spec §4.4 — the one rule covering sleep safety, lock discipline and
    // reference tracking — defeated by a choice of jump width.
    // The two programs below differ in exactly one bit — the jump class —
    // so the assertion cannot pass for an unrelated reason.
    let k = [acquire_kfunc(), release_kfunc()];
    let err = check_full(&null_check_program(false), &[], &k, Context::Atomic)
        .expect_err("a 32-bit null test must not discharge the reference");
    // PossiblyNull, not LeakedReference: with no refinement the pointer stays
    // nullable, so handing it to `release(Owned<T>)` is caught before the
    // program can reach an exit still holding the reference. Either would be
    // a sound rejection; this is the one that actually fires, and asserting
    // the specific variant keeps the test honest about what the verifier does.
    assert!(
        matches!(err, VerifyError::PossiblyNull { at: 3, .. }),
        "expected PossiblyNull at the release call, got {err:?}"
    );
}

#[test]
fn a_64bit_null_test_still_releases_the_reference() {
    // The control: the same program with JEQ64 is the idiomatic null check
    // and must keep verifying, or the fix above would just be a ban on
    // Option-returning kfuncs.
    let k = [acquire_kfunc(), release_kfunc()];
    check_full(&null_check_program(true), &[], &k, Context::Atomic)
        .expect("a 64-bit null test discharges the reference");
}

/// acquire; if (ptr == 0) skip; release(ptr); exit
///
/// `wide` selects JEQ64 or JEQ32 and is the *only* difference between the two
/// forms — which is the point: the narrow one must not be accepted.
fn null_check_program(wide: bool) -> Vec<Decoded> {
    vec![
        call(0),
        Decoded::JumpCond {
            wide,
            op: CondOp::Eq,
            dst: r(0),
            src: Source::Imm(0),
            off: 2,
        },
        movr(1, 0),
        call(1),
        mov(0, 0),
        EXIT,
    ]
}

// ── a byte region in an arena is still a bounded region ─────────────

#[test]
fn an_arena_mem_argument_is_bounds_checked() {
    // `check_mem_arg` had `PtrClass::Arena => { self.uses_arena = true; }` —
    // no bound on the offset, none on the length, no readonly check. A kfunc
    // taking `&[u8]` could therefore be handed an attacker-chosen offset *and*
    // an attacker-chosen length, and `<&[u8]>::from_raw` then calls
    // `slice::from_raw_parts` on it.
    //
    // The guard-slot argument does not cover this either: the slots are sized
    // from the ISA's 16-bit displacement, not from a u64 length.
    let k = [
        kfunc(
            "arena_base",
            NO_ARGS,
            ptr_desc(PtrKind::Arena, ValidityDomain::Static, ArgFlags::NONE),
            Context::Atomic,
        ),
        kfunc(
            "read_mem",
            READ_MEM_ARGS,
            ArgDesc::SCALAR64,
            Context::Atomic,
        ),
    ];

    // r2 is an unconstrained length read out of the context.
    let unbounded = &[
        ldx(Size::Dw, 6, 1, 0),
        call(0),
        movr(1, 0),
        movr(2, 6),
        call(1),
        mov(0, 0),
        EXIT,
    ];
    let err = check_full(unbounded, &[ArgDesc::SCALAR64], &k, Context::Atomic)
        .expect_err("an unbounded length into an arena region must be rejected");
    assert!(
        matches!(err, VerifyError::OutOfBounds { .. }),
        "expected OutOfBounds, got {err:?}"
    );

    // The control: a small constant length inside the window is fine, so the
    // fix is a bound and not a ban on arena byte regions.
    let bounded = &[call(0), movr(1, 0), mov(2, 64), call(1), mov(0, 0), EXIT];
    check_full(bounded, &[], &k, Context::Atomic).expect("a bounded arena region is fine");
}

// ── Subprogram confinement, and what rested on it ────────────────────
//
// Three analyses assumed subprograms are CFG-disjoint and nothing checked it:
// `run()` skips a subprogram whose entry state is still `None` as dead code,
// the call graph attributes a `call` to the subprogram whose *slot range*
// encloses it, and each subprogram is analysed with a fresh `Stack`. A branch
// across the boundary breaks all three.

#[test]
fn a_jump_out_of_its_own_subprogram_is_rejected() {
    // The shape that let unverified code run. Slot 7 is subprogram A, reached
    // by `call +5` from main. A's body jumps *backwards into main's slot range*
    // (slot 4), where a second `call +3` targets slot 8 — subprogram B.
    //
    // Because B's entry state was populated only while walking A, and A is
    // ordered after B in the call-graph topological order, B's turn had already
    // passed: `run()` saw `entry[B] == None`, called it dead code, and never
    // looked at it. `verify()` returned Ok. Slot 8 in isolation is a wild store
    // (`OutOfBounds`), so this accepted a program containing an unverified
    // out-of-bounds write.
    let e = check(&[
        movr(1, 10),                           // 0
        Decoded::Call(CallTarget::Subprog(5)), // 1 -> slot 7 (A)
        mov(0, 0),                             // 2
        EXIT,                                  // 3
        Decoded::Call(CallTarget::Subprog(3)), // 4 -> slot 8 (B)
        mov(0, 0),                             // 5
        EXIT,                                  // 6
        Decoded::Jump { off: -4 },             // 7  A: -> slot 4, out of A
        stx(Size::Dw, 10, -32000, 1),          // 8  B: never examined
        mov(0, 0),                             // 9
        EXIT,                                  // 10
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::CrossSubprogEdge { .. }), "{e:?}");
}

#[test]
fn fallthrough_into_the_next_subprogram_is_rejected() {
    // An edge is an edge: falling off the end of main into a callee's first
    // instruction is the same violation as jumping there, and it arrives
    // through a different arm of pass 2. Main's `mov` sits exactly on the
    // boundary.
    let e = check(&[
        Decoded::Call(CallTarget::Subprog(1)), // 0 -> slot 2
        mov(0, 0),                             // 1  falls through into slot 2
        mov(0, 0),                             // 2  callee entry
        EXIT,                                  // 3
    ])
    .unwrap_err();
    assert!(matches!(e, VerifyError::CrossSubprogEdge { .. }), "{e:?}");
}

#[test]
fn recursion_hidden_by_a_cross_subprogram_jump_is_rejected() {
    // Recursion detection reads the call *graph*, and the graph attributed this
    // `call` to whichever subprogram's slot range encloses it rather than to
    // the subprogram whose control flow reaches it. So this program — main
    // calls slot 2, whose body jumps back to slot 0 and calls it again —
    // presented as acyclic, verified with no `Recursion` error, and recursed
    // without bound at runtime. It also under-reported `max_stack_bytes`, which
    // is the number `jit_glue`/`mem.rs` size the frame from.
    let e = check(&[
        Decoded::Call(CallTarget::Subprog(1)), // 0 -> slot 2
        EXIT,                                  // 1
        Decoded::Jump { off: -3 },             // 2 -> slot 0, out of this subprog
        EXIT,                                  // 3
    ])
    .unwrap_err();
    assert!(
        matches!(
            e,
            VerifyError::CrossSubprogEdge { .. } | VerifyError::Recursion { .. }
        ),
        "{e:?}"
    );
}

// ── A frame pointer passed to a subprogram ───────────────────────────

#[test]
fn a_frame_pointer_passed_to_a_subprogram_is_clamped_and_counted() {
    // `room` was `-off` with no upper bound, and this path never called
    // `note_depth`. So an offset far below the frame produced a writable region
    // of that size, based that far below R10, in a program the runtime was told
    // needed *zero* stack. The callee's store then landed outside the frame
    // entirely.
    //
    // A megabyte below R10 is not a frame slot, so it is rejected outright.
    for &off in &[16_384_i32 + 8, 1_000_000] {
        let e = check(&[
            movr(1, 10),
            alu(AluOp::Sub, 1, off),
            Decoded::Call(CallTarget::Subprog(2)),
            mov(0, 0),
            EXIT,
            stx(Size::Dw, 1, 0, 1),
            mov(0, 0),
            EXIT,
        ])
        .unwrap_err();
        assert!(
            matches!(e, VerifyError::OutOfBounds { .. }),
            "off={off}: {e:?}"
        );
    }
}

#[test]
fn a_frame_pointer_passed_to_a_subprogram_counts_toward_the_frame() {
    // The in-range case must still be *counted*: the callee can address the
    // whole region, so the runtime has to allocate a frame at least that deep
    // or the layout it hands out disagrees with what was proved here. This
    // reported `max_stack_bytes == 0` before.
    let v = ok(&[
        movr(1, 10),
        alu(AluOp::Sub, 1, 64),
        Decoded::Call(CallTarget::Subprog(2)),
        mov(0, 0),
        EXIT,
        stx(Size::Dw, 1, 0, 1),
        mov(0, 0),
        EXIT,
    ]);
    assert!(
        v.max_stack_bytes >= 64,
        "a 64-byte region handed to a callee must be counted, got {}",
        v.max_stack_bytes
    );
}

#[test]
fn a_loop_nested_inside_an_scc_still_gets_a_widening_point() {
    // Tarjan returns *maximal* SCCs, so a cycle nested inside a larger one has
    // no predecessor outside the component: `entered_from_outside` is false for
    // its header, and being irreducible it has no dominance back-edge either.
    // Nothing widened it, joins climbed forever, and the only thing that stopped
    // the analysis was the round budget — so this program was rejected with
    // `FixpointDiverged`, which is documented as a *verifier* bug.
    //
    // Layout (slot: instruction):
    //   0   r0 = 0
    //   1   r0 += 1        <- outer header (target of both back-edges, widened)
    //   2   r2 = 0            fresh *bounded* value, set AFTER the widening
    //   3   may_goto +2  -> 6                \
    //   4   may_goto +4  -> 9                 \ two entries into the inner
    //   5   goto +8      -> 14 (exit)         / cycle, so it is irreducible
    //   6   r2 += 1         [B]              /
    //   7   may_goto +1  -> 9  (B -> C)
    //   8   goto -8      -> 1  (outer back-edge)
    //   9   r2 += 1         [C]
    //   10  may_goto -5  -> 6  (C -> B)
    //   11  goto -11     -> 1  (outer back-edge)
    //   12  r0 = 0       (unreachable filler)
    //   13  r0 = 0       (unreachable filler)
    //   14  exit
    //
    // Two details make this an actual divergence rather than a shape that merely
    // looks like one, and both were needed — earlier drafts of this test passed
    // with the fix disabled:
    //
    //   1. The inner cycle must increment a register the outer widening has not
    //      already saturated. `r2` is reset to 0 at slot 2, *after* the header
    //      where widening applies, so the inner cycle starts from [0, 0] every
    //      time and climbs 1, 2, 3, ... with nothing to stop it. An earlier
    //      version incremented `r0`, which the header had already widened to
    //      top, so the inner iteration converged immediately by absorption.
    //   2. The inner cycle must be entered from two places (slots 3 and 4) so it
    //      is irreducible and dominance finds no back-edge for it, and it must
    //      sit inside a larger SCC so `entered_from_outside` is false for both
    //      its blocks. That combination is exactly what the maximal-SCC pass
    //      cannot see.
    let prog = &[
        mov(0, 0),                    // 0
        alu(AluOp::Add, 0, 1),        // 1  outer header
        mov(2, 0),                    // 2  r2 = 0
        Decoded::MayGoto { off: 2 },  // 3  -> 6
        Decoded::MayGoto { off: 4 },  // 4  -> 9
        Decoded::Jump { off: 8 },     // 5  -> 14
        alu(AluOp::Add, 2, 1),        // 6  [B]
        Decoded::MayGoto { off: 1 },  // 7  -> 9
        Decoded::Jump { off: -8 },    // 8  -> 1
        alu(AluOp::Add, 2, 1),        // 9  [C]
        Decoded::MayGoto { off: -5 }, // 10 -> 6
        Decoded::Jump { off: -11 },   // 11 -> 1
        mov(0, 0),                    // 12
        mov(0, 0),                    // 13
        EXIT,                         // 14
    ];
    // The assertion that matters: it converges. Whether it is *accepted* is a
    // separate question (it is — nothing here is unsafe), but `FixpointDiverged`
    // specifically must not happen.
    match check(prog) {
        Ok(_) => {}
        Err(VerifyError::FixpointDiverged { rounds, .. }) => {
            panic!("fixpoint diverged after {rounds} rounds — a nested cycle has no widening point")
        }
        Err(e) => panic!("unexpected rejection: {e:?}"),
    }
}

#[test]
fn every_cycle_has_a_widening_point() {
    // The structural property the fix establishes, asserted directly on the IR
    // rather than inferred from convergence: after `Ir::build`, no cycle exists
    // among blocks that are not widening points.
    //
    // Checked by removing every `widen_here` block and confirming the remaining
    // subgraph is acyclic (a DFS finds no back-edge). This is the invariant the
    // module doc claims; before the nested-cycle pass it was false.
    let prog = &[
        mov(0, 0),
        Decoded::MayGoto { off: 2 },
        Decoded::MayGoto { off: 3 },
        Decoded::Jump { off: 5 },
        Decoded::MayGoto { off: 1 },
        Decoded::Jump { off: -5 },
        Decoded::MayGoto { off: -3 },
        Decoded::Jump { off: -7 },
        mov(0, 0),
        EXIT,
    ];
    let image = encode_all(prog);
    let ir = crate::ir::Ir::build(&image).expect("ir builds");

    // Iterative DFS with colouring over the unmarked subgraph.
    let n = ir.blocks.len();
    let mut colour = alloc::vec![0u8; n]; // 0 = unvisited, 1 = on path, 2 = done
    for root in 0..n {
        if ir.blocks[root].widen_here || colour[root] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = alloc::vec![(root, 0)];
        colour[root] = 1;
        while let Some(&mut (v, ref mut i)) = stack.last_mut() {
            if *i < ir.blocks[v].succs.len() {
                let w = ir.blocks[v].succs[*i] as usize;
                *i += 1;
                if ir.blocks[w].widen_here {
                    continue;
                }
                assert_ne!(
                    colour[w], 1,
                    "cycle through blocks {v} -> {w} with no widening point on it"
                );
                if colour[w] == 0 {
                    colour[w] = 1;
                    stack.push((w, 0));
                }
            } else {
                colour[v] = 2;
                stack.pop();
            }
        }
    }
}

// ── Kfunc call sites, as codegen sees them ──────────────────────────
//
// `VerifiedProgram::kfunc_calls` is the only path by which a shim address
// reaches `narf-bpf-jit`, which depends on nothing kernel-side and therefore
// cannot consult the registry itself. Its shape is a contract with the
// emitter: one entry per *reachable* call site, sorted, deduped, and carrying
// the address the verifier resolved rather than one codegen guessed.

/// A scalar-returning atomic kfunc with an explicit address, so a test can
/// tell two of them apart.
fn kfunc_at(name: &'static str, addr: usize) -> KfuncDesc {
    KfuncDesc {
        addr,
        ..kfunc(name, NO_ARGS, ArgDesc::SCALAR64, Context::Atomic)
    }
}

#[test]
fn a_resolved_kfunc_call_records_the_site_the_emitter_will_ask_about() {
    let k = [kfunc_at("k0", 0xDEAD_0000)];
    let v = check_full(&[call(0), EXIT], &[], &k, Context::Atomic)
        .expect("a scalar-returning kfunc initialises R0");
    assert_eq!(
        v.kfunc_calls,
        alloc::vec![crate::KfuncCallSite {
            insn_index: 0,
            id: 0,
            addr: 0xDEAD_0000,
            context: Context::Atomic,
        }],
    );
}

#[test]
fn each_call_site_gets_its_own_entry_with_its_own_address() {
    // Two different kfuncs, and the same one twice. Keyed by *site*, because
    // that is the question an emitter walking instructions actually asks —
    // keying by kfunc would make the third call indistinguishable from the
    // first and force the emitter to re-resolve the immediate itself.
    let k = [kfunc_at("k0", 0x1111_0000), kfunc_at("k1", 0x2222_0000)];
    let v =
        check_full(&[call(0), call(1), call(0), EXIT], &[], &k, Context::Atomic).expect("verifies");
    let got: Vec<(u32, i32, usize)> = v
        .kfunc_calls
        .iter()
        .map(|c| (c.insn_index, c.id, c.addr))
        .collect();
    assert_eq!(
        got,
        alloc::vec![
            (0, 0, 0x1111_0000),
            (1, 1, 0x2222_0000),
            (2, 0, 0x1111_0000)
        ],
    );
}

#[test]
fn a_call_inside_a_loop_is_recorded_once_however_often_the_block_is_reanalysed() {
    // The fixpoint re-enters a block until its input state stops changing, and
    // the recording happens inside the transfer function. Without the dedup an
    // emitter would see the same site several times — harmless if it looks the
    // site up, and a silent duplicate-emission bug if it walks the list. Pinned
    // rather than left to the reader.
    let k = [kfunc_at("k0", 0x3333_0000)];
    let v = check_full(
        &[
            mov(0, 0),
            call(0),                        // 1
            jmp(CondOp::Eq, 0, 12_345, -2), // 2 -> back to 1
            EXIT,
        ],
        &[],
        &k,
        Context::Atomic,
    )
    .expect("a call in a loop verifies; fuel bounds it at runtime");
    assert_eq!(v.kfunc_calls.len(), 1, "{:?}", v.kfunc_calls);
    assert_eq!(v.kfunc_calls[0].insn_index, 1);
}

#[test]
fn the_recorded_context_is_the_kfuncs_and_not_the_programs() {
    // A sleepable kfunc's shim returns a boxed future rather than a `u64`, so
    // native code must not enter it through the uniform ABI. The emitter's only
    // evidence for that is this field, and it must describe the *callee* — a
    // sleepable program calling an atomic kfunc is legal, and recording the
    // program's context would make that call look uncallable.
    let k = [
        kfunc_at("atomic_one", 0x4444_0000),
        kfunc("sleepy", NO_ARGS, ArgDesc::SCALAR64, Context::Sleepable),
    ];
    let v = check_full(&[call(0), call(1), EXIT], &[], &k, Context::Sleepable)
        .expect("a sleepable program may call either");
    assert_eq!(v.kfunc_calls[0].context, Context::Atomic);
    assert_eq!(v.kfunc_calls[1].context, Context::Sleepable);
}

#[test]
fn an_unreachable_call_is_not_recorded_so_the_emitter_must_fail_closed() {
    // The fixpoint only walks reachable blocks, so a call the program can
    // never execute resolves to nothing. That is the right answer — there is
    // no state in which to type-check its arguments — but it means the table
    // is *not* total over the instruction stream, and an emitter that walks
    // instructions linearly will meet a call with no entry. It must refuse
    // rather than invent a target; `narf_bpf_jit`'s
    // `a_call_the_verifier_never_reached_is_refused_rather_than_guessed` is the
    // other half of this contract.
    let k = [kfunc_at("k0", 0x5555_0000)];
    let v = check_full(&[mov(0, 0), EXIT, call(0), EXIT], &[], &k, Context::Atomic)
        .expect("dead code after an exit does not stop verification");
    assert!(
        v.kfunc_calls.is_empty(),
        "an unreachable call was resolved: {:?}",
        v.kfunc_calls
    );
}
