//! Host tests for the verification contract.
//!
//! The abstract interpreter is Phase 2; what is testable now is the kfunc
//! calling contract, and it is worth testing hard — it is the thing that
//! replaces ~2,000 lines of Linux verifier code, and a hole in it is a hole
//! in every kfunc signature at once.

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{Decoded, Insn};

use crate::kfunc::*;
use crate::{verify, Program, VerifyError};

fn ptr(kind: PtrKind, domain: ValidityDomain, flags: ArgFlags) -> ArgDesc {
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
fn lock_guards_are_never_sleep_safe() {
    // "No sleeping with a lock held" is not a separate check — it falls out
    // of the guard's validity domain.
    let g = ptr(
        PtrKind::LockGuard,
        ValidityDomain::NonPreemptible,
        ArgFlags::NONE,
    );
    assert!(!g.survives_await());

    // A guard released back to the kernel is `Owned`-domain, which makes
    // "must be released before exit" the same linear-type rule as any other
    // acquired reference — no bespoke lock bookkeeping.
    let releasable = ptr(PtrKind::LockGuard, ValidityDomain::Owned, ArgFlags::NONE);
    assert!(releasable.consumes_in_arg_position());
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
    })
    .unwrap_err();
    assert_eq!(err, VerifyError::Kfunc(KfuncError::VoidArgument(0)));
}
