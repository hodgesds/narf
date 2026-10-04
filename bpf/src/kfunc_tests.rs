//! In-kernel smokes for the linear acquire/release kfunc surface.
//!
//! Separate from [`crate::tests`] because what these pin is one property: that
//! linear Rust wrappers and the verifier's reference bookkeeping are derived
//! from the *same* Rust type and therefore cannot drift. `Owned<T>` additionally
//! pins the kernel refcount. Everything here goes through the real registry
//! and the real verifier; nothing hand-builds an `ArgDesc`.
//!
//! Three layers, deliberately:
//!
//!   1. **descriptors** — the `kfunc!` macro derived the acquire/release shape
//!      from the signature (`derives_*`);
//!   2. **the kernel side** — `Owned<BpfMap>` and `Guard<'_, L>` are RAII
//!      linear: dropping releases, while handing one to a program transfers
//!      ownership without releasing (`owned_*`, `guard_transfer_*`);
//!   3. **the verifier side** — a real program calling the real kfuncs is
//!      accepted or rejected by each reference rule (`prog_*`).
//!
//! Layer 2 is the one with no host analogue and the one that used to be
//! untestable: before `narf_map_acquire` there was no kfunc that acquired
//! anything, so the verifier's `st.refs` machinery was exercised only against
//! hand-written descriptors in `narf-bpf-verifier`'s own tests.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{CallTarget, CondOp, Decoded, Imm64, Insn, Reg, Source};
use narf_bpf_verifier::kfunc::{ArgFlags, Context, PtrKind, TypeKind, ValidityDomain};
use narf_bpf_verifier::VerifyError;
use narf_capabilities::{Cap, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::map::{BpfMap, BpfMapCap, MapAttr, MapKind, MAX_BPF_PINS};
use crate::prog::{BpfProg, BpfProgLoad, LoadError, LoadRequest};
use crate::types::{BpfLock, BpfObject, BpfType, Guard, Owned, Trusted};

/// Bodies return `Result` so they read as a list of assertions.
type R = Result<(), &'static str>;

fn wrap(r: R) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

// ── fixtures ────────────────────────────────────────────────────────

/// One `Cap` per kind, minted once. `Cap::bootstrap()` allocates an
/// object-table slot per call, so calling it per smoke leaks a slot per run.
fn map_cap() -> &'static Cap<BpfMapCap, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfMapCap, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfMapCap,
            Grant,
        >::bootstrap(
        ))));
    }
    g.expect("just installed")
}

fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfProgLoad,
            Grant,
        >::bootstrap(
        ))));
    }
    g.expect("just installed")
}

fn a_map() -> Result<Arc<BpfMap>, &'static str> {
    BpfMap::create(
        map_cap(),
        MapAttr {
            kind: MapKind::Array,
            key_size: 4,
            value_size: 8,
            max_entries: 4,
        },
        alloc::string::String::from("kfref"),
    )
    .map_err(|_| "BpfMap::create failed")
}

// ── assembler ───────────────────────────────────────────────────────

const MAP_FD: i32 = 7;

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

fn asm(items: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in items {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

/// `r_dst = <map handle>` — `LD_IMM64`'s `MapFd` pseudo-form, two slots wide.
fn ld_map(dst: u8) -> Decoded {
    Decoded::LoadImm64 {
        dst: r(dst),
        value: Imm64::MapFd(MAP_FD),
    }
}

fn mov_imm(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

fn mov_reg(dst: u8, src: u8) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Reg(r(src)),
        sign_extend: None,
    }
}

fn jeq_imm(dst: u8, v: i32, off: i16) -> Decoded {
    Decoded::JumpCond {
        wide: true,
        op: CondOp::Eq,
        dst: r(dst),
        src: Source::Imm(v),
        off,
    }
}

fn ja(off: i32) -> Decoded {
    Decoded::Jump { off }
}

fn call(name: &str) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(crate::kfunc::id_for(name)))
}

const EXIT: Decoded = Decoded::Exit;

const ACQUIRE: &str = "narf_map_acquire";
const RELEASE: &str = "narf_map_release";
const GUARD_ACQUIRE: &str = "narf_test_guard_acquire";
const GUARD_RELEASE: &str = "narf_test_guard_release";
const OTHER_GUARD_RELEASE: &str = "narf_test_other_guard_release";

struct TestLock;

static TEST_LOCK_RELEASES: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK_LAST_TOKEN: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK_NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

// SAFETY: `acquire_test_guard` is the only token source and mints a fresh
// conceptual TestLock acquisition each time. Tokens are uniquely transferred
// through `Guard::into_raw`/`from_raw`; release is bounded atomic bookkeeping
// and cannot sleep or panic.
unsafe impl BpfLock for TestLock {
    const TYPE_NAME: &'static str = "narf_bpf_test_lock";

    unsafe fn release(token: u64) {
        TEST_LOCK_LAST_TOKEN.store(token, Ordering::SeqCst);
        TEST_LOCK_RELEASES.fetch_add(1, Ordering::SeqCst);
    }
}

fn acquire_test_guard() -> Option<Guard<'static, TestLock>> {
    let token = TEST_LOCK_NEXT_TOKEN.fetch_add(1, Ordering::SeqCst);
    if token == 0 {
        return None;
    }
    // SAFETY: minting a fresh token is the TestLock fixture's acquisition
    // operation. The returned guard uniquely owns it until transfer or drop.
    Some(unsafe { Guard::from_acquired_token(token) })
}

struct OtherTestLock;

// SAFETY: no test constructs a live `OtherTestLock` token. The implementation
// remains a valid bounded, non-sleeping release operation if one is added.
unsafe impl BpfLock for OtherTestLock {
    const TYPE_NAME: &'static str = "narf_bpf_other_test_lock";

    unsafe fn release(_token: u64) {}
}

// Test-only kfuncs that pin the public `Guard` type through the macro and the
// real registry. `TestLock` models acquisition/release with unique tokens and
// atomic counters so the smokes can observe the RAII path without depending on
// a production lock implementation.
crate::kfunc! {
    #[context(Atomic)]
    fn narf_test_guard_acquire() -> Option<Guard<'static, TestLock>> {
        acquire_test_guard()
    }

    #[context(Atomic)]
    fn narf_test_guard_release(guard: Guard<'static, TestLock>) -> () {
        let _ = guard.token();
    }

    #[context(Atomic)]
    fn narf_test_other_guard_release(_guard: Guard<'static, OtherTestLock>) -> () {}
}

/// Load a program that names `map` as fd [`MAP_FD`], through the real
/// verifier and the real kfunc registry.
fn load(
    name: &str,
    items: &[Decoded],
    ctx: Context,
    map: &Arc<BpfMap>,
) -> Result<Arc<BpfProg>, LoadError> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from(name),
            insns: asm(items),
            context: ctx,
            maps: alloc::vec![(MAP_FD, Arc::clone(map))],
            map_indices: alloc::vec::Vec::new(),
            load_references: alloc::vec::Vec::new(),
        },
    )
}

/// Load a program with no map operands through the real verifier and registry.
fn load_no_maps(name: &str, items: &[Decoded], ctx: Context) -> Result<Arc<BpfProg>, LoadError> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from(name),
            insns: asm(items),
            context: ctx,
            maps: alloc::vec::Vec::new(),
            map_indices: alloc::vec::Vec::new(),
            load_references: alloc::vec::Vec::new(),
        },
    )
}

/// The `VerifyError` a load failed with, or `None` if it failed for some other
/// reason (a revoked cap, a missing registry) — which would mean the smoke
/// asserting on it proved nothing.
fn verify_error(e: &LoadError) -> Option<&VerifyError> {
    match e {
        LoadError::Rejected(v) => Some(v),
        _ => None,
    }
}

// ── layer 1: the macro derived the descriptors ──────────────────────

/// The acquiring kfunc's descriptor is exactly `<Option<Owned<BpfMap>> as
/// BpfType>::DESC` — i.e. the macro read it off the Rust return type.
///
/// Comparing against the *type's* `DESC` rather than against a spelled-out
/// `ArgDesc` literal is the whole point: a hand-written expectation here would
/// be a second copy of the contract and could agree with neither the signature
/// nor the verifier.
fn body_derives_acquire_descriptor() -> R {
    let reg = crate::kfunc::registry().ok_or("kfunc registry not installed")?;
    let e = reg
        .by_name(ACQUIRE)
        .ok_or("narf_map_acquire not registered")?;

    if e.ret != <Option<Owned<BpfMap>> as BpfType>::DESC {
        return Err("narf_map_acquire's return descriptor is not the one \
                    Option<Owned<BpfMap>> derives — the macro is not reading \
                    the signature");
    }
    if e.args.len() != 1 || e.args[0] != <Trusted<BpfMap> as BpfType>::DESC {
        return Err("narf_map_acquire's argument descriptor is not the one \
                    Trusted<BpfMap> derives");
    }
    // And the properties the verifier actually consults, spelled out, so a
    // change to `BpfType for Option<Owned<T>>` that kept the two sides equal
    // but broke the *meaning* still goes red here.
    if e.ret.domain != ValidityDomain::Owned {
        return Err("the acquiring kfunc does not return an Owned-domain pointer");
    }
    if !e.ret.flags.contains(ArgFlags::NULLABLE) {
        return Err(
            "the acquiring kfunc's result is not nullable — the program \
                    would have no null-check obligation",
        );
    }
    if !e.ret.consumes_in_arg_position() {
        return Err("the acquiring kfunc's return type does not acquire: \
                    consumes_in_arg_position() is what the verifier reads \
                    both ways round");
    }
    if e.ret.kind
        != (TypeKind::Ptr {
            kind: PtrKind::Object,
            key: <BpfMap as BpfObject>::TYPE_KEY,
        })
    {
        return Err("the acquiring kfunc's result is not a BpfMap object pointer");
    }
    Ok(())
}
fn smoke_bpf_kfunc_derives_acquire_descriptor_pos() -> TestResult {
    wrap(body_derives_acquire_descriptor())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_derives_acquire_descriptor_pos);

/// The releasing kfunc's parameter is exactly `<Owned<BpfMap> as
/// BpfType>::DESC`, and consuming is *positional* — the same descriptor the
/// acquire returns.
fn body_derives_release_descriptor() -> R {
    let reg = crate::kfunc::registry().ok_or("kfunc registry not installed")?;
    let a = reg
        .by_name(ACQUIRE)
        .ok_or("narf_map_acquire not registered")?;
    let e = reg
        .by_name(RELEASE)
        .ok_or("narf_map_release not registered")?;

    if e.args.len() != 1 || e.args[0] != <Owned<BpfMap> as BpfType>::DESC {
        return Err("narf_map_release's parameter is not the one Owned<BpfMap> \
                    derives");
    }
    if !e.args[0].consumes_in_arg_position() {
        return Err(
            "narf_map_release does not consume its argument — a program \
                    could release the same reference twice",
        );
    }
    if !matches!(e.ret.kind, TypeKind::Void) {
        return Err("narf_map_release should return nothing");
    }
    // The positional rule, stated as an equality: what the acquire returns and
    // what the release takes differ *only* in nullability. There is no
    // KF_ACQUIRE/KF_RELEASE pair to keep in sync because there is no pair.
    if a.ret.kind != e.args[0].kind || a.ret.domain != e.args[0].domain {
        return Err("the acquire's result and the release's parameter are not \
                    the same type — the positional rule has been broken");
    }
    Ok(())
}
fn smoke_bpf_kfunc_derives_release_descriptor_pos() -> TestResult {
    wrap(body_derives_release_descriptor())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_derives_release_descriptor_pos);

/// `Guard<'_, L>` derives both halves of its contract through the real macro:
/// structural linearity from `PtrKind::LockGuard`, and sleep unsafety from
/// `ValidityDomain::NonPreemptible`.
fn body_derives_guard_descriptors() -> R {
    let reg = crate::kfunc::registry().ok_or("kfunc registry not installed")?;
    let acquire = reg
        .by_name(GUARD_ACQUIRE)
        .ok_or("narf_test_guard_acquire not registered")?;
    let release = reg
        .by_name(GUARD_RELEASE)
        .ok_or("narf_test_guard_release not registered")?;

    if acquire.ret != <Option<Guard<'static, TestLock>> as BpfType>::DESC {
        return Err("the guard acquire descriptor was not derived from its Rust return type");
    }
    if release.args != [<Guard<'static, TestLock> as BpfType>::DESC] {
        return Err("the guard release descriptor was not derived from its Rust argument type");
    }
    if !acquire.ret.flags.contains(ArgFlags::NULLABLE) {
        return Err("the fallible guard acquire is not nullable");
    }
    if !acquire.ret.consumes_in_arg_position() || !release.args[0].consumes_in_arg_position() {
        return Err("LockGuard is not structurally linear in both descriptor positions");
    }
    if acquire.ret.domain != ValidityDomain::NonPreemptible || acquire.ret.domain.survives_await() {
        return Err("LockGuard is not independently marked sleep-unsafe");
    }
    if acquire.ret.kind != release.args[0].kind || acquire.ret.domain != release.args[0].domain {
        return Err("the guard acquire and release descriptors disagree");
    }
    match acquire.ret.kind {
        TypeKind::Ptr {
            kind: PtrKind::LockGuard,
            key,
        } if key == TestLock::TYPE_KEY && key.is_some() => {}
        _ => return Err("the guard descriptor does not carry its lock class identity"),
    }
    Ok(())
}
fn smoke_bpf_kfunc_derives_guard_descriptors_pos() -> TestResult {
    wrap(body_derives_guard_descriptors())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_derives_guard_descriptors_pos);

/// Ownership crosses the raw BPF ABI without unlocking, then reconstructing
/// and dropping the release argument unlocks exactly once.
fn body_guard_transfer_releases_once() -> R {
    let before = TEST_LOCK_RELEASES.load(Ordering::SeqCst);

    let guard = acquire_test_guard().ok_or("test lock token space exhausted")?;
    let token = guard.token();
    let raw = guard.into_raw();
    if raw != token || TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before {
        return Err("transferring a Guard into BPF released it prematurely");
    }

    // SAFETY: `raw` owns exactly the acquisition transferred above, matching
    // the obligation the verifier discharges for a release-kfunc argument.
    let guard = unsafe { <Guard<'static, TestLock> as BpfType>::from_raw(raw, 0) };
    drop(guard);
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 1 {
        return Err("dropping the reconstructed Guard did not release exactly once");
    }
    if TEST_LOCK_LAST_TOKEN.load(Ordering::SeqCst) != token {
        return Err("Guard::drop released the wrong lock token");
    }
    Ok(())
}
fn smoke_bpf_kfunc_guard_transfer_releases_once_pos() -> TestResult {
    wrap(body_guard_transfer_releases_once())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_guard_transfer_releases_once_pos);

/// Nested BPF invocations use distinct cleanup slots. The test enters the
/// cleanup scopes directly because a real nested invocation reaches FRAME in
/// the trap prologue before re-entering BPF; directly nesting the same hardware
/// domain scope would violate the framekernel's domain-entry invariant.
fn body_guard_cleanup_scopes_nest() -> R {
    let before = TEST_LOCK_RELEASES.load(Ordering::SeqCst);
    let _preempt = narf_scheduler::preempt_disable();
    let outer_scope = crate::types::GuardCleanupScope::enter();
    let outer = acquire_test_guard().ok_or("test lock token space exhausted")?;
    let outer_raw = outer.into_raw();

    {
        let _inner_scope = crate::types::GuardCleanupScope::enter();
        let inner = acquire_test_guard().ok_or("test lock token space exhausted")?;
        let inner_token = inner.token();
        let inner_raw = inner.into_raw();
        if inner_raw != inner_token {
            return Err("the nested cleanup slot rejected its first Guard");
        }
        // `_inner_scope` drops here with its slot armed.
    }
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 1 {
        return Err("dropping the inner BPF scope did not release only its Guard");
    }

    // SAFETY: the outer cleanup slot still owns this exact acquisition after
    // the nested scope restored it as the current slot.
    let outer = unsafe { <Guard<'static, TestLock> as BpfType>::from_raw(outer_raw, 0) };
    drop(outer);
    drop(outer_scope);
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 2 {
        return Err("the outer Guard was lost or released more than once");
    }
    Ok(())
}
fn smoke_bpf_kfunc_guard_cleanup_scopes_nest_pos() -> TestResult {
    wrap(body_guard_cleanup_scopes_nest())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_guard_cleanup_scopes_nest_pos);

/// The runtime backstop for a verifier failure: a second distinct guard cannot
/// overwrite the cleanup record for the first. Its acquisition is released
/// immediately and converted to the nullable failure value.
fn body_guard_cleanup_conflict_fails_closed() -> R {
    let before = TEST_LOCK_RELEASES.load(Ordering::SeqCst);
    let scope = crate::domain::enter();
    let first = acquire_test_guard().ok_or("test lock token space exhausted")?;
    let first_raw = first.into_raw();
    let second = acquire_test_guard().ok_or("test lock token space exhausted")?;
    if second.into_raw() != 0 {
        return Err("a second live Guard overwrote the cleanup slot");
    }
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 1 {
        return Err("the rejected second Guard was not released immediately");
    }

    // SAFETY: conflict handling preserved the first slot and its token.
    let first = unsafe { <Guard<'static, TestLock> as BpfType>::from_raw(first_raw, 0) };
    drop(first);
    drop(scope);
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 2 {
        return Err("cleanup conflict handling lost or double-released a Guard");
    }
    Ok(())
}
fn smoke_bpf_kfunc_guard_cleanup_conflict_fails_closed_neg() -> TestResult {
    wrap(body_guard_cleanup_conflict_fails_closed())
}
kernel_test_in!(
    "bpf",
    smoke_bpf_kfunc_guard_cleanup_conflict_fails_closed_neg
);

/// Every registered kfunc that *takes* an `Owned` pointer must be reachable
/// from something that *returns* one, or the release is unreachable and the
/// verifier's linearity is vacuous.
fn body_registry_has_an_acquiring_kfunc() -> R {
    let reg = crate::kfunc::registry().ok_or("kfunc registry not installed")?;
    let acquires = reg
        .all()
        .iter()
        .filter(|e| e.ret.consumes_in_arg_position())
        .count();
    if acquires == 0 {
        return Err("no registered kfunc acquires a reference — the verifier's \
                    reference tracking has no production caller");
    }
    let releases = reg
        .all()
        .iter()
        .filter(|e| e.args.iter().any(|a| a.consumes_in_arg_position()))
        .count();
    if releases == 0 {
        return Err("no registered kfunc releases a reference — every acquire \
                    would be an unavoidable LeakedReference");
    }
    Ok(())
}
fn smoke_bpf_kfunc_registry_has_an_acquiring_kfunc_pos() -> TestResult {
    wrap(body_registry_has_an_acquiring_kfunc())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_registry_has_an_acquiring_kfunc_pos);

// ── layer 2: Owned<T> is linear on the kernel side ──────────────────

/// Acquire bumps the refcount; the release kfunc gives it back.
///
/// Called as ordinary Rust, not through a program: `kfunc!` leaves the
/// function an ordinary `fn`, and this is the half a BPF program cannot
/// observe.
fn body_owned_acquire_release_balances() -> R {
    let map = a_map()?;
    let before = Arc::strong_count(&map);
    let pins_before = map.bpf_pins();

    // SAFETY: `map` is a live `Arc<BpfMap>` held for the whole of this
    // function, so the handle names a live map at offset zero — the same
    // obligation the verifier discharges for a program.
    let handle = unsafe { Trusted::<BpfMap>::from_raw(Arc::as_ptr(&map) as u64, 0) };
    let owned = crate::map::narf_map_acquire(handle).ok_or("acquire returned null")?;

    if Arc::strong_count(&map) != before + 1 {
        return Err("acquiring did not take a reference");
    }
    if map.bpf_pins() != pins_before + 1 {
        return Err("acquiring did not record a BPF pin");
    }

    crate::map::narf_map_release(owned);

    if Arc::strong_count(&map) != before {
        return Err("releasing did not give the reference back");
    }
    if map.bpf_pins() != pins_before {
        return Err("releasing did not drop the BPF pin");
    }
    Ok(())
}
fn smoke_bpf_kfunc_owned_acquire_release_balances_pos() -> TestResult {
    wrap(body_owned_acquire_release_balances())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_owned_acquire_release_balances_pos);

/// The linearity itself: an `Owned<T>` that merely goes out of scope releases.
///
/// This is what makes the kernel side and the verifier's model impossible to
/// drift apart. The verifier says "an `Owned<T>` in argument position is
/// consumed"; on the kernel side, consuming it *is* dropping it, so a release
/// kfunc that forgot to do anything still releases — and a kfunc that took an
/// `Owned<T>` and did not mean to release could not be written.
fn body_owned_drop_releases() -> R {
    let map = a_map()?;
    let before = Arc::strong_count(&map);

    // SAFETY: as `body_owned_acquire_release_balances`.
    let handle = unsafe { Trusted::<BpfMap>::from_raw(Arc::as_ptr(&map) as u64, 0) };
    let owned = crate::map::narf_map_acquire(handle).ok_or("acquire returned null")?;
    if Arc::strong_count(&map) != before + 1 {
        return Err("acquiring did not take a reference");
    }
    drop(owned);
    if Arc::strong_count(&map) != before {
        return Err("dropping an Owned<BpfMap> did not release its reference — \
                    the type is not linear and a kfunc that returns early \
                    leaks a refcount");
    }
    if map.bpf_pins() != 0 {
        return Err("dropping an Owned<BpfMap> did not drop its BPF pin");
    }
    Ok(())
}
fn smoke_bpf_kfunc_owned_drop_releases_pos() -> TestResult {
    wrap(body_owned_drop_releases())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_owned_drop_releases_pos);

/// The other half of linearity: handing an `Owned<T>` *to a program* must not
/// release it.
///
/// `BpfType::into_raw` is what the acquiring shim calls on its way back to R0.
/// If that ran the `Drop`, every acquire would hand the program a reference it
/// had already given back — a use-after-free the verifier cannot see, because
/// from its side the program did everything right.
fn body_owned_into_raw_does_not_release() -> R {
    let map = a_map()?;
    let before = Arc::strong_count(&map);

    // SAFETY: as above.
    let handle = unsafe { Trusted::<BpfMap>::from_raw(Arc::as_ptr(&map) as u64, 0) };
    let owned = crate::map::narf_map_acquire(handle).ok_or("acquire returned null")?;
    let raw = owned.into_raw();

    if Arc::strong_count(&map) != before + 1 {
        return Err("into_raw released the reference it was handing to the \
                    program — every acquired handle would already be dangling");
    }
    if raw != Arc::as_ptr(&map) as u64 {
        return Err("into_raw did not produce the map's own address");
    }
    // Give it back the way the release shim does, so the smoke leaves no pin
    // behind for the next one to trip over.
    //
    // SAFETY: `raw` carries the reference `narf_map_acquire` took and
    // `into_raw` did not give back; this is exactly the register the verifier
    // would have proved still holds it at a release site.
    let owned = unsafe { Owned::<BpfMap>::from_raw(raw, 0) };
    crate::map::narf_map_release(owned);
    if Arc::strong_count(&map) != before {
        return Err("the round trip through into_raw/from_raw did not balance");
    }
    Ok(())
}
fn smoke_bpf_kfunc_owned_into_raw_does_not_release_pos() -> TestResult {
    wrap(body_owned_into_raw_does_not_release())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_owned_into_raw_does_not_release_pos);

/// The acquire is fallible, and the `Option` is not decoration.
///
/// A program that loops acquiring would otherwise overflow the refcount, which
/// is a real Linux CVE class (`bpf_map_inc` is bounded for the same reason).
/// The cap is what makes `Option<Owned<T>>` — and therefore the program's
/// null-check obligation — honest.
fn body_owned_acquire_is_bounded() -> R {
    let map = a_map()?;
    let before = Arc::strong_count(&map);
    // SAFETY: as above.
    let handle = || unsafe { Trusted::<BpfMap>::from_raw(Arc::as_ptr(&map) as u64, 0) };

    let mut held: Vec<Owned<BpfMap>> = Vec::with_capacity(MAX_BPF_PINS as usize);
    for _ in 0..MAX_BPF_PINS {
        let Some(o) = crate::map::narf_map_acquire(handle()) else {
            return Err("the acquire cap was hit before MAX_BPF_PINS references");
        };
        held.push(o);
    }
    if crate::map::narf_map_acquire(handle()).is_some() {
        return Err("acquiring past MAX_BPF_PINS succeeded — the refcount is \
                    unbounded and a looping program can overflow it");
    }
    if map.bpf_pins() != MAX_BPF_PINS {
        return Err("the pin count does not match the number of live acquires");
    }
    // `Vec::clear` drops each `Owned`, which releases — linearity again.
    held.clear();
    if map.bpf_pins() != 0 || Arc::strong_count(&map) != before {
        return Err("dropping the held references did not restore the counts");
    }
    Ok(())
}
fn smoke_bpf_kfunc_owned_acquire_is_bounded_neg() -> TestResult {
    wrap(body_owned_acquire_is_bounded())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_owned_acquire_is_bounded_neg);

// ── layer 3: the verifier enforces the rules on a real program ──────

/// Acquire, test, release — the whole idiom, through the real registry.
///
/// And it *runs*: the returned value distinguishes the acquired path from the
/// null one, and the refcount is back where it started afterwards. That last
/// assertion is what a verifier-only test cannot make.
fn body_prog_acquire_test_release() -> R {
    let map = a_map()?;
    let before = Arc::strong_count(&map);
    let prog = load(
        "acq_rel",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 3),
            mov_reg(1, 0),
            call(RELEASE),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .map_err(|_| "acquire/test/release did not verify")?;
    // The program itself holds an `Arc` for its whole life, which is what makes
    // the release provably never the last drop.
    let with_prog = Arc::strong_count(&map);
    if with_prog <= before {
        return Err("loading did not take the program's own map reference");
    }

    let out = prog
        .run_atomic([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the per-CPU stack provider declined the run")?;
    if out.value() != 1 {
        return Err("the program did not take the acquired path — acquire \
                    returned null at run time");
    }
    if Arc::strong_count(&map) != with_prog {
        return Err("a full run did not balance the map's refcount");
    }
    if map.bpf_pins() != 0 {
        return Err("a full run left a BPF pin behind");
    }
    // Running it a second time must balance too: a leak of one reference per
    // invocation is invisible in a single run and is what an attach site would
    // actually hit.
    prog.run_atomic([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the second run was declined")?;
    if Arc::strong_count(&map) != with_prog || map.bpf_pins() != 0 {
        return Err("a second run did not balance — the pair leaks one \
                    reference per invocation");
    }
    Ok(())
}
fn smoke_bpf_kfunc_prog_acquire_test_release_pos() -> TestResult {
    wrap(body_prog_acquire_test_release())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_acquire_test_release_pos);

/// Acquire and never release.
fn body_prog_leak_rejected() -> R {
    let map = a_map()?;
    let e = load(
        "leak",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 1),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .err()
    .ok_or("a program that never releases its acquired reference verified")?;
    match verify_error(&e) {
        Some(VerifyError::LeakedReference { .. }) => Ok(()),
        _ => Err("an unreleased reference was rejected, but not as LeakedReference"),
    }
}
fn smoke_bpf_kfunc_prog_leak_rejected_neg() -> TestResult {
    wrap(body_prog_leak_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_leak_rejected_neg);

/// Release twice.
fn body_prog_double_release_rejected() -> R {
    let map = a_map()?;
    let e = load(
        "double_rel",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 5),
            mov_reg(6, 0),
            mov_reg(1, 6),
            call(RELEASE),
            mov_reg(1, 6),
            call(RELEASE),
            mov_imm(0, 0),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .err()
    .ok_or("releasing the same reference twice verified")?;
    match verify_error(&e) {
        // Either diagnosis is the enforcement working: the release kills every
        // register holding the id, so the second read is of an uninitialised
        // register — and if it were not killed, the release itself would fail.
        Some(VerifyError::ReleaseOfUnacquired { .. } | VerifyError::UninitRegister { .. }) => {
            Ok(())
        }
        _ => Err("a double release was rejected for an unrelated reason"),
    }
}
fn smoke_bpf_kfunc_prog_double_release_rejected_neg() -> TestResult {
    wrap(body_prog_double_release_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_double_release_rejected_neg);

/// Use after release. The released register is not merely unreleasable — it is
/// unreadable, because `kill_ref` forgets every register that held the id.
fn body_prog_use_after_release_rejected() -> R {
    let map = a_map()?;
    let e = load(
        "uaf",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 6),
            mov_reg(6, 0),
            mov_reg(1, 6),
            call(RELEASE),
            mov_reg(1, 6),
            call(ACQUIRE),
            mov_imm(0, 0),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .err()
    .ok_or("using a released reference verified")?;
    match verify_error(&e) {
        Some(VerifyError::UninitRegister { .. } | VerifyError::KfuncSignature { .. }) => Ok(()),
        _ => Err("a use-after-release was rejected for an unrelated reason"),
    }
}
fn smoke_bpf_kfunc_prog_use_after_release_rejected_neg() -> TestResult {
    wrap(body_prog_use_after_release_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_use_after_release_rejected_neg);

/// Release something never acquired.
///
/// The map handle is the interesting witness: it is a real `PtrClass::Object`
/// pointer with the right `TypeKey`, and its `Static` domain is *stronger*
/// than `Owned`, so it passes the class, key, offset and domain checks. The
/// only thing that rejects it is `ref_id == NO_REF` — the clause that says
/// "this pointer is not a reference *you* took". Without it, a program could
/// underflow a map's refcount with two instructions.
fn body_prog_release_of_unacquired_rejected() -> R {
    let map = a_map()?;
    let e = load(
        "bogus_rel",
        &[ld_map(1), call(RELEASE), mov_imm(0, 0), EXIT],
        Context::Atomic,
        &map,
    )
    .err()
    .ok_or(
        "releasing a map handle that was never acquired verified — this is \
            a refcount underflow",
    )?;
    match verify_error(&e) {
        Some(VerifyError::ReleaseOfUnacquired { reg: 1, .. }) => Ok(()),
        _ => Err("releasing an unacquired pointer was rejected, but not as \
                  ReleaseOfUnacquired on R1"),
    }
}
fn smoke_bpf_kfunc_prog_release_of_unacquired_rejected_neg() -> TestResult {
    wrap(body_prog_release_of_unacquired_rejected())
}
kernel_test_in!(
    "bpf",
    smoke_bpf_kfunc_prog_release_of_unacquired_rejected_neg
);

/// The null-check obligation: `Option<Owned<T>>` used without testing.
fn body_prog_untested_null_rejected() -> R {
    let map = a_map()?;
    let e = load(
        "no_null_test",
        &[
            ld_map(1),
            call(ACQUIRE),
            mov_reg(1, 0),
            call(RELEASE),
            mov_imm(0, 0),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .err()
    .ok_or("a nullable acquired reference was used without a null test")?;
    match verify_error(&e) {
        Some(VerifyError::PossiblyNull { reg: 1, .. }) => Ok(()),
        _ => Err("an untested nullable result was rejected, but not as PossiblyNull"),
    }
}
fn smoke_bpf_kfunc_prog_untested_null_rejected_neg() -> TestResult {
    wrap(body_prog_untested_null_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_untested_null_rejected_neg);

/// An `Owned<T>` survives an await, because a refcount holds the object alive.
///
/// // LINUX-GAP: this is the *positive* half of `survives_await()`. NARF's
/// `ValidityDomain::Owned::survives_await()` is `true` by design — spec §3.2's
/// table reads "yes; must be released" — so an acquired reference held across
/// a sleep is accepted here where a `Trusted<T>` is not. Linux reaches the same
/// place through refcounted kptrs plus `KF_RCU_PROTECTED`; the difference is
/// that here it is one predicate on the domain rather than two mechanisms.
fn body_prog_owned_survives_await() -> R {
    let map = a_map()?;
    load(
        "owned_await",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 5),
            mov_reg(6, 0),
            call("narf_yield"),
            mov_reg(1, 6),
            call(RELEASE),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Sleepable,
        &map,
    )
    .map_err(|_| "an acquired reference did not survive an await")?;
    Ok(())
}
fn smoke_bpf_kfunc_prog_owned_survives_await_pos() -> TestResult {
    wrap(body_prog_owned_survives_await())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_owned_survives_await_pos);

/// Surviving an await does not excuse the release.
///
/// The pair with the smoke above: `survives_await()` and `requires_release()`
/// are separate questions about the same domain, and answering the first
/// "yes" must not answer the second.
fn body_prog_owned_across_await_still_leaks() -> R {
    let map = a_map()?;
    let e = load(
        "owned_await_leak",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 3),
            mov_reg(6, 0),
            call("narf_yield"),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Sleepable,
        &map,
    )
    .err()
    .ok_or(
        "a reference acquired before an await was never released, and the \
            program verified",
    )?;
    match verify_error(&e) {
        Some(VerifyError::LeakedReference { .. }) => Ok(()),
        _ => Err("an unreleased reference across an await was rejected, but \
                  not as LeakedReference"),
    }
}
fn smoke_bpf_kfunc_prog_owned_across_await_still_leaks_neg() -> TestResult {
    wrap(body_prog_owned_across_await_still_leaks())
}
kernel_test_in!(
    "bpf",
    smoke_bpf_kfunc_prog_owned_across_await_still_leaks_neg
);

/// A guard acquired and released through macro-derived descriptors verifies.
fn body_prog_guard_release_verifies() -> R {
    let before = TEST_LOCK_RELEASES.load(Ordering::SeqCst);
    let prog = load_no_maps(
        "guard_rel",
        &[
            call(GUARD_ACQUIRE),
            jeq_imm(0, 0, 3),
            mov_reg(1, 0),
            call(GUARD_RELEASE),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Atomic,
    )
    .map_err(|_| "a balanced Guard acquire/release did not verify")?;
    let out = prog
        .run_atomic([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the per-CPU stack provider declined the guard run")?;
    if out.value() != 1 {
        return Err("the guard program did not take its acquired path");
    }
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 1 {
        return Err("the macro-generated release shim did not drop the Guard exactly once");
    }
    Ok(())
}
fn smoke_bpf_kfunc_prog_guard_release_verifies_pos() -> TestResult {
    wrap(body_prog_guard_release_verifies())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_guard_release_verifies_pos);

/// Guard linearity is structural even though its domain does not itself
/// require release.
fn body_prog_guard_leak_rejected() -> R {
    let e = load_no_maps(
        "guard_leak",
        &[call(GUARD_ACQUIRE), jeq_imm(0, 0, 1), mov_imm(0, 1), EXIT],
        Context::Atomic,
    )
    .err()
    .ok_or("a program that leaked a Guard verified")?;
    match verify_error(&e) {
        Some(VerifyError::LeakedReference { .. }) => Ok(()),
        _ => Err("an unreleased Guard was rejected, but not as LeakedReference"),
    }
}
fn smoke_bpf_kfunc_prog_guard_leak_rejected_neg() -> TestResult {
    wrap(body_prog_guard_leak_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_guard_leak_rejected_neg);

/// A guard is consumable only by a release kfunc for the same lock class.
fn body_prog_guard_wrong_release_rejected() -> R {
    let e = load_no_maps(
        "guard_wrong_rel",
        &[
            call(GUARD_ACQUIRE),
            jeq_imm(0, 0, 3),
            mov_reg(1, 0),
            call(OTHER_GUARD_RELEASE),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Atomic,
    )
    .err()
    .ok_or("a Guard was accepted by the wrong lock class's release kfunc")?;
    match verify_error(&e) {
        Some(VerifyError::KfuncSignature { arg: 0, .. }) => Ok(()),
        _ => Err("a mismatched Guard release was rejected for an unrelated reason"),
    }
}
fn smoke_bpf_kfunc_prog_guard_wrong_release_rejected_neg() -> TestResult {
    wrap(body_prog_guard_wrong_release_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_guard_wrong_release_rejected_neg);

/// Guard sleep safety is independent of its release obligation: even a path
/// that releases after the await is invalid.
fn body_prog_guard_across_await_rejected() -> R {
    let e = load_no_maps(
        "guard_await",
        &[
            call(GUARD_ACQUIRE),
            jeq_imm(0, 0, 4),
            mov_reg(6, 0),
            call("narf_yield"),
            mov_reg(1, 6),
            call(GUARD_RELEASE),
            mov_imm(0, 0),
            EXIT,
        ],
        Context::Sleepable,
    )
    .err()
    .ok_or("a program held a Guard across an await and verified")?;
    match verify_error(&e) {
        Some(VerifyError::PointerCrossesAwait {
            domain: ValidityDomain::NonPreemptible,
            ..
        }) => Ok(()),
        _ => Err("a Guard crossing an await was rejected for an unrelated reason"),
    }
}
fn smoke_bpf_kfunc_prog_guard_across_await_rejected_neg() -> TestResult {
    wrap(body_prog_guard_across_await_rejected())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_guard_across_await_rejected_neg);

/// Runtime termination is an implicit control-flow exit. A guard held by a
/// path that exhausts fuel must be released even though the program never
/// reaches its explicit release kfunc.
fn body_prog_guard_out_of_fuel_releases() -> R {
    let before = TEST_LOCK_RELEASES.load(Ordering::SeqCst);
    let prog = load_no_maps(
        "guard_fuel",
        &[
            call(GUARD_ACQUIRE),
            jeq_imm(0, 0, 2),
            ja(-1),
            mov_imm(0, 0),
            EXIT,
        ],
        Context::Atomic,
    )
    .map_err(|_| "the guard/fuel cleanup program did not verify")?;
    let out = prog
        .run_atomic([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the per-CPU stack provider declined the guard/fuel run")?;
    if !matches!(
        out,
        crate::interp::Outcome::Trapped(crate::interp::Trap::OutOfFuel { .. })
    ) {
        return Err("the guard/fuel program did not terminate by fuel exhaustion");
    }
    if TEST_LOCK_RELEASES.load(Ordering::SeqCst) != before + 1 {
        return Err("abnormal BPF termination did not release the live Guard");
    }
    Ok(())
}
fn smoke_bpf_kfunc_prog_guard_out_of_fuel_releases_pos() -> TestResult {
    wrap(body_prog_guard_out_of_fuel_releases())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_prog_guard_out_of_fuel_releases_pos);

// ── the JIT covers the acquire/release path too ─────────────────────

/// The acquire/release pair now has a native lowering: `LD_IMM64 MapFd`
/// materialises the loader-resolved map handle, so a program that names a map
/// JITs end to end (the kfunc call sequence was already emitted — see
/// `crate::tests`' `narf_test_arg_mix`). This was a tripwire asserting the
/// *absence* of that lowering; now that it exists, the tripwire has become the
/// differential comparison it always said to add — native and interpreted must
/// agree, and both must balance the map's refcount and pins.
fn body_acquire_path_matches_the_interpreter() -> R {
    let map = a_map()?;
    let prog = load(
        "jit_probe",
        &[
            ld_map(1),
            call(ACQUIRE),
            jeq_imm(0, 0, 3),
            mov_reg(1, 0),
            call(RELEASE),
            mov_imm(0, 1),
            EXIT,
        ],
        Context::Atomic,
        &map,
    )
    .map_err(|_| "acquire/test/release did not verify")?;
    // The map handle no longer forces a fallback, so the whole path is native.
    // Where there is no backend at all there is nothing to compare — the
    // interpreter alone still has to balance, which the run below checks.
    let jited = prog.jited_len() != 0;
    if !jited && narf_bpf_jit::has_backend() {
        return Err("the acquire/release path names a map and should now JIT");
    }
    let baseline = Arc::strong_count(&map);

    // Native and interpreted must take the same path and leave the same balance.
    let native = prog
        .run_atomic([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the native run was declined")?;
    if native.value() != 1 {
        return Err("the native run did not take the acquired path");
    }
    if Arc::strong_count(&map) != baseline || map.bpf_pins() != 0 {
        return Err("the native run did not balance the map's refcount/pins");
    }
    let interp = prog
        .run_atomic_interpreted([0; crate::interp::MAX_CTX_WORDS], 0)
        .ok_or("the interpreted run was declined")?;
    if interp.value() != native.value() {
        return Err("native and interpreted acquire/release results differ");
    }
    if Arc::strong_count(&map) != baseline || map.bpf_pins() != 0 {
        return Err("the interpreted run did not balance the map's refcount/pins");
    }
    Ok(())
}
fn smoke_bpf_kfunc_acquire_path_matches_the_interpreter() -> TestResult {
    wrap(body_acquire_path_matches_the_interpreter())
}
kernel_test_in!("bpf", smoke_bpf_kfunc_acquire_path_matches_the_interpreter);
