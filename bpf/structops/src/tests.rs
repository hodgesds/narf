//! In-kernel smokes for the `struct_ops!` mechanism.
//!
//! Migrated with the framework out of `narf-bpf`. They register under the
//! `bpf/structops` subsystem, so `xtask test --subsystem bpf` (prefix match)
//! still runs them while `--subsystem bpf/structops` runs just these.
//!
//! Positive *and* negative per behaviour, per `feedback_tests_are_the_value`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadRequest};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, CapKind, CapType, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

// ── program-building helpers ─────────────────────────────────────────
//
// A minimal slice of `narf-bpf`'s own test helpers — enough to assemble and
// load the tiny programs these smokes bind into a struct_ops set.

// Minted once and cached: `Cap::bootstrap()` allocates an object-table slot per
// call, so calling it per test would leak a slot per smoke run.
fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = Box::leak(Box::new(Cap::<BpfProgLoad, Grant>::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

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

fn mov_imm(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

fn ldx(dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size: Size::Dw,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}

fn alu_reg(op: AluOp, dst: u8, src: u8) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Reg(r(src)),
    }
}

const EXIT: Decoded = Decoded::Exit;

fn load(name: &str, insns: Vec<Insn>, ctx: Context) -> Result<Arc<BpfProg>, &'static str> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from(name),
            insns,
            context: ctx,
            maps: Vec::new(),
        },
    )
    .map_err(|_| "load rejected")
}

// ── the demo trait: macro, adapter, cap-gated record ─────────────────

crate::struct_ops! {
    /// A minimal pluggable trait, exercising the `struct_ops!` macro, the
    /// `narf.structops` section, the cap-gated install path, and the generated
    /// adapter that dispatches through BPF programs.
    #[cap(IdleGovernor)]
    #[install(install_bpf_demo_governor)]
    #[desc(DEMO_GOVERNOR_OPS)]
    #[adapter(BpfDemoGovernor)]
    #[optional(init)]
    pub trait DemoGovernor {
        /// Pick an idle state for an expected idle duration.
        fn select_state(&self, expected_idle_ns: u64) -> u32;
        /// Optional one-time setup.
        fn init(&self) -> i32;
    }
}

/// A native in-tree implementation.
///
/// The point of the whole `struct_ops!` design is that the trait comes out of
/// the macro *unchanged*, so a Rust impl needs to know nothing about BPF. This
/// is that claim, compiled.
struct NativeDemoGovernor;

impl DemoGovernor for NativeDemoGovernor {
    fn select_state(&self, expected_idle_ns: u64) -> u32 {
        if expected_idle_ns > 1_000_000 {
            2
        } else {
            0
        }
    }
    fn init(&self) -> i32 {
        0
    }
}

fn smoke_bpf_structops_native_impl_still_works() -> TestResult {
    let g = NativeDemoGovernor;
    if g.select_state(10) != 0 || g.select_state(2_000_000) != 2 || g.init() != 0 {
        return TestResult::Fail("native impl of a struct_ops trait misbehaved");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_native_impl_still_works);

fn smoke_bpf_structops_descriptor_registered() -> TestResult {
    let all = crate::structops::descriptors();
    let Some(d) = all.iter().find(|d| d.name == "DemoGovernor") else {
        return TestResult::Fail("narf.structops section did not carry DemoGovernor");
    };
    if d.cap != CapKind::IdleGovernor {
        return TestResult::Fail("struct_ops descriptor carried the wrong CapKind");
    }
    if d.methods.len() != 2 {
        return TestResult::Fail("struct_ops descriptor has the wrong method count");
    }
    // `#[optional(init)]` must reach the descriptor, or a program set could
    // omit a required method and be installed anyway.
    if d.methods[0].optional || !d.methods[1].optional {
        return TestResult::Fail("#[optional] did not reach the method descriptors");
    }
    // The ctx tuple is the method's real argument list — one u64 here.
    if d.methods[0].ctx.len() != 1 {
        return TestResult::Fail("method ctx tuple was not derived from the signature");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_descriptor_registered);

/// The install authority for the demo trait.
///
/// `power::IdleGov` is the real marker for `CapKind::IdleGovernor`; declaring a
/// local one keeps this crate off a `narf-power` dependency it otherwise has no
/// use for. `CapType::KIND` is what `structops::install` compares, and both
/// markers name the same kind.
#[derive(Copy, Clone, Debug)]
struct IdleGovInstall;
impl CapType for IdleGovInstall {
    const KIND: CapKind = CapKind::IdleGovernor;
}

fn smoke_bpf_structops_install_requires_matching_cap() -> TestResult {
    use crate::structops::{ProgSet, StructOpsError};

    let insns = asm(&[mov_imm(0, 1), EXIT]);
    let Ok(prog) = load("gov", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };

    // Negative: the right shape, the wrong authority.
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let set = ProgSet::new().with("select_state", prog.clone());
    match crate::structops::install(&DEMO_GOVERNOR_OPS, &wrong, set) {
        Err(StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("install accepted a capability of the wrong kind"),
    }

    // Negative: right authority, missing a required method.
    let right = Cap::<IdleGovInstall, Grant>::bootstrap();
    match install_bpf_demo_governor(&right, ProgSet::new()) {
        Err(StructOpsError::MissingMethod("select_state")) => {}
        _ => return TestResult::Fail("install accepted a set missing a required method"),
    }

    // Positive: the optional method may be omitted.
    let set = ProgSet::new().with("select_state", prog);
    if install_bpf_demo_governor(&right, set).is_err() {
        return TestResult::Fail("install rejected a complete program set");
    }
    if !crate::structops::is_installed("DemoGovernor") {
        return TestResult::Fail("installed set was not recorded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_install_requires_matching_cap
);

// ── reaching a live slot via `#[commit(...)]` ────────────────────────
//
// `DemoGovernor` proves the macro, the adapter, and the cap-gated record. What
// it does *not* prove is the last seam: an installed program set becoming the
// implementation the subsystem's own hot path dispatches through. `LiveGovernor`
// closes that gap — it owns the exact `IrqSafeSpinLock<Option<Box<dyn Trait>>>`
// slot every pluggable subsystem owns (standing in for `power::IDLE_GOVERNOR` so
// the seam is exercised without a cross-crate dep), and `#[commit(...)]` names
// the committer that moves the verified adapter into it.

crate::struct_ops! {
    /// A pluggable trait that owns a live slot, exercising the `#[commit(...)]`
    /// seam end to end.
    #[cap(IdleGovernor)]
    #[install(install_bpf_live_governor)]
    #[desc(LIVE_GOVERNOR_OPS)]
    #[adapter(BpfLiveGovernor)]
    #[commit(commit_live_governor)]
    pub trait LiveGovernor {
        /// Pick an idle state for an expected idle duration.
        fn select_state(&self, expected_idle_ns: u64) -> u32;
    }
}

/// The live slot. The same shape `power::IDLE_GOVERNOR` has; `init()` or a
/// native impl could occupy it just as well as a BPF program set.
static LIVE_GOVERNOR: narf_lib::sync::IrqSafeSpinLock<Option<Box<dyn LiveGovernor>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The committer named by `#[commit(commit_live_governor)]`. Moves the verified
/// adapter into the live slot, exactly as `power::install_idle_governor_boxed`
/// moves a governor into its slot. Generic over the cap marker so any authority
/// of the right kind works, which is what lets the generated install fn stay
/// generic.
fn commit_live_governor<M: CapType>(
    cap: &Cap<M, Grant>,
    adapter: BpfLiveGovernor,
) -> Result<(), crate::structops::StructOpsError> {
    // The set was validated before the adapter was built; this is the same
    // last-moment liveness re-check the native install points perform.
    cap.check_live()?;
    *LIVE_GOVERNOR.lock() = Some(Box::new(adapter));
    Ok(())
}

/// The subsystem's hot-path query, dispatching through whatever is installed.
fn live_governor_select_state(expected_idle_ns: u64) -> Option<u32> {
    LIVE_GOVERNOR
        .lock()
        .as_ref()
        .map(|g| g.select_state(expected_idle_ns))
}

fn smoke_bpf_structops_commit_reaches_live_slot() -> TestResult {
    // r0 = ctx[0] * 2. A value the program computes, so the answer proves the
    // installed program — not a native default or a stale slot — served the
    // query, and that the argument reached it as ctx[0].
    let insns = asm(&[ldx(0, 1, 0), alu_reg(AluOp::Add, 0, 0), EXIT]);
    let Ok(prog) = load("livegov", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };

    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    let set = crate::structops::ProgSet::new().with("select_state", prog);
    if install_bpf_live_governor(&cap, set).is_err() {
        return TestResult::Fail("commit install rejected a complete program set");
    }

    // The record still happens — a committed trait is `is_installed` too.
    if !crate::structops::is_installed("LiveGovernor") {
        return TestResult::Fail("committed install did not record the set");
    }

    // The whole point: the subsystem's own query now dispatches through the
    // installed program.
    match live_governor_select_state(21) {
        Some(42) => {}
        Some(_) => return TestResult::Fail("live slot returned the wrong value"),
        None => return TestResult::Fail("commit did not populate the live slot"),
    }
    // A second call proves the slot stays populated and re-dispatches per call
    // rather than caching the first answer.
    if live_governor_select_state(50) != Some(100) {
        return TestResult::Fail("live slot did not re-dispatch on a second call");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_commit_reaches_live_slot
);

fn smoke_bpf_structops_commit_rejects_before_touching_slot() -> TestResult {
    // The negative: a set that fails validation must never reach the live slot.
    // Empty the slot first so a leftover install from another test can't make
    // this pass for the wrong reason.
    *LIVE_GOVERNOR.lock() = None;

    // Wrong authority kind — validated and rejected before any adapter is
    // built, so the committer never runs.
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let insns = asm(&[mov_imm(0, 1), EXIT]);
    let Ok(prog) = load("livegov_bad", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };
    let set = crate::structops::ProgSet::new().with("select_state", prog);
    match install_bpf_live_governor(&wrong, set) {
        Err(crate::structops::StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("committed install accepted the wrong cap kind"),
    }
    if live_governor_select_state(1).is_some() {
        return TestResult::Fail("a rejected install still reached the live slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_commit_rejects_before_touching_slot
);

// ── the generated adapter ────────────────────────────────────────────

fn smoke_bpf_structops_adapter_dispatches() -> TestResult {
    // The generated adapter is what Linux spends a code generator on. NARF's
    // struct_ops targets are trait slots with a Rust-level install point, so the
    // adapter is an ordinary `impl` — this test is that claim, executed.
    //
    // The program returns its first context word doubled, so the result proves
    // the argument reached it as ctx[0] rather than being zero or stale.
    let insns = asm(&[ldx(0, 1, 0), alu_reg(AluOp::Add, 0, 0), EXIT]);
    let Ok(prog) = load("gov", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };
    let set = crate::structops::ProgSet::new().with("select_state", prog);
    let gov = BpfDemoGovernor::new(set);

    if gov.select_state(21) != 42 {
        return TestResult::Fail("adapter did not pass the argument as ctx[0]");
    }
    if gov.select_state(0) != 0 {
        return TestResult::Fail("adapter returned a stale value");
    }
    // `init` is `#[optional]` and unbound, so it must fall back rather than
    // fabricate. Returning nonsense from a policy hook is worse than the default.
    if gov.init() != 0 {
        return TestResult::Fail("unbound optional method did not fall back");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_adapter_dispatches);

fn smoke_bpf_structops_adapter_is_the_trait() -> TestResult {
    // The adapter must be usable anywhere the trait is — that is the whole point
    // of the trait coming out of the macro unchanged. Exercised through a `&dyn`
    // so nothing can be specialised away.
    let insns = asm(&[mov_imm(0, 7), EXIT]);
    let Ok(prog) = load("gov7", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    let bpf = BpfDemoGovernor::new(crate::structops::ProgSet::new().with("select_state", prog));
    let native = NativeDemoGovernor;
    let both: [&dyn DemoGovernor; 2] = [&bpf, &native];
    if both[0].select_state(1) != 7 {
        return TestResult::Fail("BPF impl did not dispatch through &dyn");
    }
    // The native impl still works and still has no idea BPF exists.
    let _ = both[1].select_state(1);
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_adapter_is_the_trait);
