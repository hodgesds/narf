//! Host tests for the verification contract — the kfunc calling convention
//! and the `verify()` entry point. The abstract interpreter's own tests are in
//! `verify_tests.rs`.
//!
//! The contract is worth testing hard: it is the thing that replaces ~2,000
//! lines of Linux verifier code, and a hole in it is a hole in every kfunc
//! signature at once. Where a rule is a *conjunction* of predicates, assert
//! the conjunction — a lock guard that must be both linear and sleep-unsafe
//! spent a while being neither, because the two halves were asserted on
//! separate descriptors.

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{Decoded, Insn};

use crate::kfunc::*;
use crate::{verify, Program, VerifyError};

fn ptr(kind: PtrKind, domain: ValidityDomain, flags: ArgFlags) -> ArgDesc {
    ptr_const(kind, domain, flags)
}

/// The same, usable in a `static` — which is where `kfunc!` will build them.
const fn ptr_const(kind: PtrKind, domain: ValidityDomain, flags: ArgFlags) -> ArgDesc {
    ArgDesc {
        kind: TypeKind::Ptr {
            kind,
            key: TypeKey(1),
        },
        domain,
        flags,
    }
}

fn desc(args: &'static [ArgDesc], ret: ArgDesc, context: Context) -> KfuncDesc {
    KfuncDesc {
        id: 0,
        name: "test_kfunc",
        addr: 0x1000,
        args,
        ret,
        context,
    }
}

// ─── The sleep-safety rule ──────────────────────────────────────────

#[test]
fn only_owned_and_sleepable_rcu_survive_await() {
    // This table is NARF's entire sleep-safety story. Linux needs
    // bpf_rcu_read_lock, KF_RCU_PROTECTED, MEM_RCU, and refcounted kptrs to
    // express it, because sleepability arrived after the pointer model.
    assert!(!ValidityDomain::NonPreemptible.survives_await());
    assert!(!ValidityDomain::RcuRead.survives_await());
    assert!(ValidityDomain::SleepableRcuRead.survives_await());
    assert!(ValidityDomain::Owned.survives_await());
    assert!(ValidityDomain::Static.survives_await());
}

#[test]
fn qsbr_pointers_cannot_cross_an_await() {
    // NARF invariant #11: QSBR readers may not await inside a critical
    // section (`ReadGuard` is `!Send` to enforce it in Rust). The verifier
    // must agree with the kernel's own rule, or BPF becomes the one caller
    // that can violate it.
    let p = ptr(PtrKind::Object, ValidityDomain::RcuRead, ArgFlags::NONE);
    assert!(!p.survives_await());
}

#[test]
fn a_lock_guard_is_linear_and_sleep_unsafe_at_the_same_time() {
    // The property spec §1.11 promises, and the one an earlier version of this
    // file could not express: a `Guard` must be **both** linear (given back
    // before exit) **and** killed at an await (so no sleeping with a lock
    // held). Asserting the two halves on *separate* descriptors is what hid
    // the bug — `Guard` + `Owned` was linear but failed `validate()`, and
    // `Guard` + `NonPreemptible` validated but was not linear, so no single
    // spelling had both. The conjunction is the test.
    let guard = ptr(
        PtrKind::LockGuard,
        ValidityDomain::NonPreemptible,
        ArgFlags::NONE,
    );
    static GUARD_ARG: &[ArgDesc] = &[ptr_const(
        PtrKind::LockGuard,
        ValidityDomain::NonPreemptible,
        ArgFlags::NONE,
    )];

    assert!(!guard.survives_await(), "a guard must die at an await");
    assert!(
        guard.consumes_in_arg_position(),
        "a guard must be linear — passing it back is what releases the lock"
    );
    assert_eq!(
        desc(GUARD_ARG, ArgDesc::VOID, Context::Atomic).validate(),
        Ok(()),
        "…and the same descriptor must be declarable"
    );
    // Return position too: `lock() -> Option<Guard<'_>>`.
    assert_eq!(
        desc(
            &[],
            ptr_const(
                PtrKind::LockGuard,
                ValidityDomain::NonPreemptible,
                ArgFlags::NULLABLE,
            ),
            Context::Atomic,
        )
        .validate(),
        Ok(())
    );
}

#[test]
fn linearity_of_a_guard_does_not_depend_on_its_domain() {
    // Whatever lifetime a guard is given, you still have to give it back.
    // Keying linearity on `ValidityDomain::Owned` made "linear" and "not
    // sleep-safe" mutually exclusive, which is exactly backwards for a lock.
    for domain in [
        ValidityDomain::NonPreemptible,
        ValidityDomain::RcuRead,
        ValidityDomain::Owned,
    ] {
        assert!(
            ptr(PtrKind::LockGuard, domain, ArgFlags::NONE).consumes_in_arg_position(),
            "{domain:?}"
        );
    }
    // An object, by contrast, is linear only when it carries a refcount.
    assert!(ptr(PtrKind::Object, ValidityDomain::Owned, ArgFlags::NONE).consumes_in_arg_position());
    assert!(!ptr(
        PtrKind::Object,
        ValidityDomain::NonPreemptible,
        ArgFlags::NONE
    )
    .consumes_in_arg_position());
}

#[test]
fn a_sleep_safe_lock_guard_argument_is_rejected() {
    // The mirror of `rejects_a_sleep_safe_lock_guard`. Without it, a kfunc
    // could *take back* a guard it claims survived a sleep — legitimising the
    // exact state the return-position check exists to prevent.
    static OWNED_GUARD: &[ArgDesc] = &[ptr_const(
        PtrKind::LockGuard,
        ValidityDomain::Owned,
        ArgFlags::NONE,
    )];
    assert_eq!(
        desc(OWNED_GUARD, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::SleepableLockGuardArg(0))
    );

    // `Static` is rejected for the same reason: a guard that is always valid
    // is not a guard.
    static STATIC_GUARD: &[ArgDesc] = &[ptr_const(
        PtrKind::LockGuard,
        ValidityDomain::Static,
        ArgFlags::NONE,
    )];
    assert_eq!(
        desc(STATIC_GUARD, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::SleepableLockGuardArg(0))
    );
}

#[test]
fn scalars_always_survive_an_await() {
    // A scalar has no validity to lose; only pointers carry a domain.
    assert!(ArgDesc::SCALAR64.survives_await());
}

#[test]
fn owned_pointers_are_linear() {
    let owned = ptr(PtrKind::Object, ValidityDomain::Owned, ArgFlags::NONE);
    // Returned: acquires. Passed: releases. Positional, not a flag — which
    // is why there is no way to declare an acquire that forgets its release.
    assert!(owned.consumes_in_arg_position());
    assert!(owned.domain.requires_release());

    let trusted = ptr(
        PtrKind::Object,
        ValidityDomain::NonPreemptible,
        ArgFlags::NONE,
    );
    assert!(!trusted.consumes_in_arg_position());
    assert!(!trusted.domain.requires_release());
}

// ─── Context compatibility ──────────────────────────────────────────

#[test]
fn sleepable_programs_may_call_atomic_kfuncs_but_not_conversely() {
    assert!(Context::Sleepable.permits(Context::Atomic));
    assert!(Context::Sleepable.permits(Context::Sleepable));
    assert!(Context::Atomic.permits(Context::Atomic));
    // The one that matters: an atomic hook must never reach a sleeping
    // kfunc. Enforced by type at attach, not by a runtime flag check.
    assert!(!Context::Atomic.permits(Context::Sleepable));
}

// ─── Descriptor validation ──────────────────────────────────────────

#[test]
fn accepts_a_well_formed_descriptor() {
    static ARGS: &[ArgDesc] = &[ArgDesc::SCALAR64];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Ok(())
    );
}

#[test]
fn rejects_too_many_args() {
    static ARGS: &[ArgDesc] = &[
        ArgDesc::SCALAR64,
        ArgDesc::SCALAR64,
        ArgDesc::SCALAR64,
        ArgDesc::SCALAR64,
        ArgDesc::SCALAR64,
        ArgDesc::SCALAR64,
    ];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::TooManyArgs(6))
    );
}

#[test]
fn rejects_null_address() {
    let mut d = desc(&[], ArgDesc::VOID, Context::Atomic);
    d.addr = 0;
    assert_eq!(d.validate(), Err(KfuncError::NullAddress));
}

#[test]
fn rejects_sized_region_without_a_following_length() {
    // `&[u8]` lowers to (ptr, len). A descriptor claiming SIZED_BY_NEXT with
    // nothing after it would let the verifier read a length from nowhere.
    static TRAILING: &[ArgDesc] = &[ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Mem,
            key: TypeKey::NONE,
        },
        domain: ValidityDomain::Static,
        flags: ArgFlags::SIZED_BY_NEXT,
    }];
    assert_eq!(
        desc(TRAILING, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::MissingSizeArg(0))
    );

    // Following argument present but not a scalar — equally wrong.
    static NON_SCALAR: &[ArgDesc] = &[
        ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Mem,
                key: TypeKey::NONE,
            },
            domain: ValidityDomain::Static,
            flags: ArgFlags::SIZED_BY_NEXT,
        },
        ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::Mem,
                key: TypeKey::NONE,
            },
            domain: ValidityDomain::Static,
            flags: ArgFlags::NONE,
        },
    ];
    assert_eq!(
        desc(NON_SCALAR, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::MissingSizeArg(0))
    );
}

#[test]
fn accepts_sized_region_with_a_following_length() {
    static ARGS: &[ArgDesc] = &[
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
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Ok(())
    );
}

#[test]
fn rejects_scalar_with_a_validity_domain() {
    // A scalar with a domain is a sign the macro derived the wrong ArgDesc;
    // catching it at registration beats reasoning from a broken contract.
    static ARGS: &[ArgDesc] = &[ArgDesc {
        kind: TypeKind::Scalar {
            bits: 64,
            signed: false,
        },
        domain: ValidityDomain::Owned,
        flags: ArgFlags::NONE,
    }];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::ScalarWithDomain(0))
    );
}

#[test]
fn rejects_void_argument() {
    static ARGS: &[ArgDesc] = &[ArgDesc::VOID];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::VoidArgument(0))
    );
}

#[test]
fn rejects_a_sleep_safe_lock_guard() {
    // The one descriptor shape that would silently break lock discipline:
    // a guard claiming it survives a sleep.
    let bad = desc(
        &[],
        ArgDesc {
            kind: TypeKind::Ptr {
                kind: PtrKind::LockGuard,
                key: TypeKey(1),
            },
            domain: ValidityDomain::Owned,
            flags: ArgFlags::NONE,
        },
        Context::Atomic,
    );
    assert_eq!(bad.validate(), Err(KfuncError::SleepableLockGuard));
}

#[test]
fn arg_flags_compose_and_test() {
    let f = ArgFlags::NULLABLE | ArgFlags::READONLY;
    assert!(f.contains(ArgFlags::NULLABLE));
    assert!(f.contains(ArgFlags::READONLY));
    assert!(!f.contains(ArgFlags::UNINIT));
    assert!(f.contains(ArgFlags::NONE));
}

#[test]
fn type_key_none_is_distinguishable() {
    assert!(!TypeKey::NONE.is_some());
    assert!(TypeKey(1).is_some());
}

// ─── verify() entry point ───────────────────────────────────────────

fn prog_of(insns: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in insns {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

fn check(insns: &[Insn]) -> Result<crate::VerifiedProgram, VerifyError> {
    verify(&Program {
        insns,
        context: Context::Atomic,
        ctx_fields: &[],
        kfuncs: &[],
        maps: &[],
    })
}

#[test]
fn rejects_empty_program() {
    assert_eq!(check(&[]).unwrap_err(), VerifyError::Empty);
}

#[test]
fn rejects_undecodable_program_with_a_location() {
    // A helper call is well-formed BPF that NARF deliberately does not
    // implement; the error must point at it rather than being generic.
    let insns = prog_of(&[Decoded::Exit]);
    let mut bad = insns.clone();
    bad.insert(
        0,
        Insn {
            code: 0x85, // JMP | CALL
            regs: 0,    // src_reg 0 => helper
            off: 0,
            imm: 12,
        },
    );
    match check(&bad).unwrap_err() {
        VerifyError::Decode { at: 0, err } => {
            assert_eq!(err, narf_bpf_isa::DecodeError::HelperCall(12));
        }
        other => panic!("expected a located decode error, got {other:?}"),
    }
}

#[test]
fn rejects_program_that_falls_off_the_end() {
    let insns = prog_of(&[narf_bpf_isa::Decoded::Mov {
        wide: true,
        dst: narf_bpf_isa::Reg::R0,
        src: narf_bpf_isa::Source::Imm(0),
        sign_extend: None,
    }]);
    assert!(matches!(
        check(&insns).unwrap_err(),
        VerifyError::FallsOffEnd { .. }
    ));
}

#[test]
fn accepts_the_smallest_well_formed_program() {
    // A bare `exit` returns whatever R0 holds, which nothing wrote. That is a
    // *use* of an uninitialised register and the verifier says so, naming it —
    // which is more than "your program was rejected".
    let insns = prog_of(&[Decoded::Exit]);
    assert_eq!(
        check(&insns).unwrap_err(),
        VerifyError::UninitRegister { at: 0, reg: 0 }
    );

    // With R0 written first, it verifies.
    let insns = prog_of(&[
        narf_bpf_isa::Decoded::Mov {
            wide: true,
            dst: narf_bpf_isa::Reg::R0,
            src: narf_bpf_isa::Source::Imm(0),
            sign_extend: None,
        },
        Decoded::Exit,
    ]);
    let v = check(&insns).expect("a program that returns 0 is safe");
    assert_eq!(v.max_stack_bytes, 0);
    assert_eq!(v.subprogs.len(), 1);
    assert!(v.fault_sites.is_empty());
    assert!(!v.uses_arena);
    assert_eq!(v.initial_fuel, crate::DEFAULT_FUEL);
}

#[test]
fn propagates_malformed_kfunc_descriptors() {
    static ARGS: &[ArgDesc] = &[ArgDesc::VOID];
    let insns = prog_of(&[Decoded::Exit]);
    let kfuncs = [desc(ARGS, ArgDesc::VOID, Context::Atomic)];
    let err = verify(&Program {
        insns: &insns,
        context: Context::Atomic,
        ctx_fields: &[],
        kfuncs: &kfuncs,
        maps: &[],
    })
    .unwrap_err();
    assert_eq!(err, VerifyError::Kfunc(KfuncError::VoidArgument(0)));
}

#[test]
fn rejects_const_on_a_pointer_argument() {
    // `ArgFlags::CONST` means "the verifier proved a single value", which the
    // call-site check only ever applied to scalars. On a pointer it was
    // silently ignored, so `Const<Trusted<T>>` compiled, registered, verified,
    // and delivered nothing — a kfunc author had a guarantee they did not
    // have.
    static ARGS: &[ArgDesc] = &[ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Object,
            key: TypeKey(1),
        },
        domain: ValidityDomain::NonPreemptible,
        flags: ArgFlags::CONST,
    }];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Err(KfuncError::ConstOnNonScalar(0))
    );
}

#[test]
fn accepts_const_on_a_scalar_argument() {
    static ARGS: &[ArgDesc] = &[ArgDesc {
        kind: TypeKind::Scalar {
            bits: 64,
            signed: false,
        },
        domain: ValidityDomain::Static,
        flags: ArgFlags::CONST,
    }];
    assert_eq!(
        desc(ARGS, ArgDesc::VOID, Context::Atomic).validate(),
        Ok(())
    );
}
