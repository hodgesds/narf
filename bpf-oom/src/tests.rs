//! In-kernel smokes for the BPF OOM policy.
//!
//! Registered under the `bpf/oom` subsystem, so `xtask test --subsystem bpf`
//! (prefix match) runs them while `--subsystem bpf/oom` runs just these.
//!
//! Every smoke scores **synthetic** candidates from a fake
//! [`CandidateSource`](crate::policy::CandidateSource) and records the kill
//! instead of delivering it. That is not a convenience: a suite that ranked
//! live tasks would SIGKILL whatever process happened to be resident when it
//! ran — including the shell running the suite. The fake source is what makes
//! the selection path testable at all, and it exercises the identical code:
//! `select_victim` cannot tell the two apart.
//!
//! Positive *and* negative per behaviour, per `feedback_tests_are_the_value`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadRequest};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_structops::{ProgSet, StructOpsError};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, CapKind, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::address_space::AddressSpace;

use crate::policy::{CandidateSource, OomCandidate};
use crate::{
    bootstrap_oom_policy_authority, install_bpf_oom_policy, BpfOomPolicy, BpfOomPolicyOps,
};

// ── program-building helpers ─────────────────────────────────────────

// Minted once and cached: `Cap::bootstrap()` allocates an object-table slot per
// call, so calling it per test would leak a slot per smoke run.
fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
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

/// `r{dst} = v` (64-bit).
fn mov_imm(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

/// `r{dst} = *(u64 *)(r{src} + off)` — how a program reads a context word.
fn ldx(dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size: Size::Dw,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}

/// `r{dst} op= imm` (64-bit).
fn alu_imm(op: AluOp, dst: u8, v: i32) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Imm(v),
    }
}

const EXIT: Decoded = Decoded::Exit;

fn load(name: &str, insns: Vec<Insn>, ctx: Context) -> Result<Arc<BpfProg>, &'static str> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: String::from(name),
            insns,
            context: ctx,
            maps: Vec::new(),
            map_indices: Vec::new(),
            load_references: Vec::new(),
        },
    )
    .map_err(|_| "load rejected")
}

/// A program returning the context word at `word` verbatim.
///
/// `badness` sees `(pid, rss_pages, oom_score_adj, total_pages)` in words 0..3,
/// so this is how a smoke says "rank by RSS" or "rank by pid" without a
/// jump-carrying program whose failure mode would be harder to read than the
/// behaviour it is meant to prove.
fn prog_returns_ctx(name: &str, word: i16) -> Result<Arc<BpfProg>, &'static str> {
    load(name, asm(&[ldx(0, 1, word * 8), EXIT]), Context::Atomic)
}

/// A program returning the constant `v`.
fn prog_returns_const(name: &str, v: i32) -> Result<Arc<BpfProg>, &'static str> {
    load(name, asm(&[mov_imm(0, v), EXIT]), Context::Atomic)
}

// ── the fake candidate source ────────────────────────────────────────

/// A synthetic task: `(pid, tid, rss_pages, oom_score_adj)`.
type FakeTask = (u64, u64, u64, i64);

struct FakeState {
    tasks: Vec<FakeTask>,
    /// One real address space, cloned into every candidate. Real because
    /// `OomVictim` demands an `Arc<AddressSpace>` and a fabricated one would be
    /// unsound the moment anything touched it; shared because the smokes rank
    /// candidates and never reap them, so per-candidate roots would be pure
    /// page-table churn.
    space: Option<Arc<AddressSpace>>,
    /// The tid the last selection killed, or `None`. Recorded rather than
    /// signalled — these tids name no real task.
    killed: Option<u64>,
    total_pages: u64,
}

struct FakeTasks {
    state: IrqSafeSpinLock<FakeState>,
}

static FAKE: FakeTasks = FakeTasks {
    state: IrqSafeSpinLock::new(FakeState {
        tasks: Vec::new(),
        space: None,
        killed: None,
        total_pages: 1_000_000,
    }),
};

impl CandidateSource for FakeTasks {
    fn candidates(&self) -> Vec<OomCandidate> {
        let s = self.state.lock();
        let Some(space) = s.space.as_ref() else {
            return Vec::new();
        };
        s.tasks
            .iter()
            .map(|&(pid, tid, rss_pages, oom_score_adj)| OomCandidate {
                pid,
                tid,
                rss_pages,
                oom_score_adj,
                address_space: Arc::clone(space),
            })
            .collect()
    }

    fn total_pages(&self) -> u64 {
        self.state.lock().total_pages
    }

    fn kill(&self, tid: u64) {
        self.state.lock().killed = Some(tid);
    }
}

/// Point the policy at `tasks` and clear the kill record.
///
/// Allocates one real user address space the first time and keeps it for the
/// rest of the boot — `new_for_user` costs a page-table root per call.
fn arm_fake(tasks: &[FakeTask]) -> Result<(), &'static str> {
    {
        let mut s = FAKE.state.lock();
        if s.space.is_none() {
            // SAFETY: `new_for_user` requires only that paging is enabled. The
            // in-kernel test suite runs long after MMU bring-up (it is driven
            // from the executor, which cannot start before paging), so the
            // contract holds. The returned AS is never activated or mapped —
            // it exists to satisfy `OomVictim`'s `Arc<AddressSpace>` — and it
            // is dropped only when this static's `Arc` count falls to zero.
            let space = unsafe { AddressSpace::new_for_user() }.map_err(|_| "no address space")?;
            s.space = Some(Arc::new(space));
        }
        s.tasks = tasks.to_vec();
        s.killed = None;
    }
    crate::register_candidate_source(&FAKE);
    Ok(())
}

/// The tid the last selection killed.
fn killed_tid() -> Option<u64> {
    FAKE.state.lock().killed
}

/// Put the live system back: native ranking, the real candidate source, and
/// the in-tree OOM policy in `memory`'s slot.
///
/// Every smoke ends here. A test that installed a program set left this crate's
/// killer in `memory`'s global slot pointed at *fake* tasks; leaving it there
/// would mean the next real memory-pressure event picks a victim that does not
/// exist. `narf_userspace::oom::install()` wins by last registration.
fn restore_live() {
    crate::clear_policy();
    crate::live::install();
    narf_userspace::oom::install();
}

// ── descriptor ───────────────────────────────────────────────────────

fn smoke_bpf_oom_descriptor_registered() -> TestResult {
    let all = narf_bpf_structops::descriptors();
    let Some(d) = all.iter().find(|d| d.name == "BpfOomPolicy") else {
        return TestResult::Fail("narf.structops section did not carry BpfOomPolicy");
    };
    if d.cap != CapKind::OomPolicy {
        return TestResult::Fail("descriptor carried the wrong CapKind");
    }
    if d.methods.len() != 3 {
        return TestResult::Fail("descriptor has the wrong method count");
    }
    // `badness` required; `veto` and `notify_kill` optional. If `badness` ever
    // became optional a set could install with nothing ranking anything.
    let Some(badness) = d.methods.iter().find(|m| m.name == "badness") else {
        return TestResult::Fail("descriptor is missing badness");
    };
    if badness.optional {
        return TestResult::Fail("badness must not be optional");
    }
    for name in ["veto", "notify_kill"] {
        match d.methods.iter().find(|m| m.name == name) {
            Some(m) if m.optional => {}
            Some(_) => return TestResult::Fail("an optional method is marked required"),
            None => return TestResult::Fail("descriptor is missing an optional method"),
        }
    }
    // The ctx tuple is the method's real argument list: four words for
    // `badness`, which is also exactly `MAX_CTX_WORDS` — a fifth argument would
    // be a compile error, not a silent truncation.
    if badness.ctx.len() != 4 {
        return TestResult::Fail("badness ctx tuple was not derived from the signature");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_descriptor_registered);

// ── the adapter ──────────────────────────────────────────────────────

fn smoke_bpf_oom_adapter_passes_all_four_ctx_words() -> TestResult {
    // Each program returns a different context word, so the answers prove the
    // adapter packed the arguments in signature order rather than zeroing,
    // repeating, or truncating the tail.
    for (word, expect) in [(0i16, 11u64), (1, 22), (2, 33), (3, 44)] {
        let Ok(p) = prog_returns_ctx("oom_ctx", word) else {
            return TestResult::Fail("load rejected the ctx program");
        };
        let ops = BpfOomPolicyOps::new(ProgSet::new().with("badness", p));
        if BpfOomPolicy::badness(&ops, 11, 22, 33, 44) != expect {
            return TestResult::Fail("adapter did not pass an argument in ctx order");
        }
    }
    // Unbound optionals fall back rather than fabricate: `veto` must read as
    // "no veto" (0) or an unbound optional would exclude every candidate.
    let Ok(p) = prog_returns_ctx("oom_ctx0", 1) else {
        return TestResult::Fail("load rejected the ctx program");
    };
    let ops = BpfOomPolicyOps::new(ProgSet::new().with("badness", p));
    if BpfOomPolicy::veto(&ops, 1, 2, 3) != 0 || BpfOomPolicy::notify_kill(&ops, 1, 2) != 0 {
        return TestResult::Fail("unbound optional method did not fall back");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_adapter_passes_all_four_ctx_words);

// ── the program decides the victim ───────────────────────────────────

fn smoke_bpf_oom_program_picks_the_victim() -> TestResult {
    // pid, tid, rss, adj. Ranking by RSS and ranking by pid disagree on
    // purpose: whichever wins names the program that ran.
    let tasks: [FakeTask; 3] = [(10, 110, 900, 0), (20, 120, 100, 0), (30, 130, 500, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    let cap = bootstrap_oom_policy_authority();

    // Rank by RSS: pid 10 (900 pages) is worst.
    let Ok(by_rss) = prog_returns_ctx("oom_by_rss", 1) else {
        return TestResult::Fail("load rejected the badness program");
    };
    if install_bpf_oom_policy(&cap, ProgSet::new().with("badness", by_rss)).is_err() {
        restore_live();
        return TestResult::Fail("install rejected a complete program set");
    }
    if !crate::policy_installed() {
        restore_live();
        return TestResult::Fail("commit did not populate the live slot");
    }
    match crate::policy::select_victim_for_test() {
        Some(v) if v.pid == 10 && v.tid == 110 && v.rss_pages == 900 => {}
        Some(_) => {
            restore_live();
            return TestResult::Fail("rank-by-RSS program did not select the largest task");
        }
        None => {
            restore_live();
            return TestResult::Fail("a ranking program found no victim");
        }
    }
    if killed_tid() != Some(110) {
        restore_live();
        return TestResult::Fail("the selected victim was not killed");
    }

    // Re-install a program ranking by pid: pid 30 now wins despite being
    // mid-sized. Proves the *program's* value decides — not RSS, not a cached
    // answer — and that a re-install swaps the live policy.
    let Ok(by_pid) = prog_returns_ctx("oom_by_pid", 0) else {
        restore_live();
        return TestResult::Fail("load rejected the second badness program");
    };
    if install_bpf_oom_policy(&cap, ProgSet::new().with("badness", by_pid)).is_err() {
        restore_live();
        return TestResult::Fail("re-install rejected a complete program set");
    }
    let picked = crate::policy::select_victim_for_test().map(|v| v.pid);
    restore_live();
    if picked != Some(30) {
        return TestResult::Fail("value did not flow: rank-by-pid did not select pid 30");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_program_picks_the_victim);

fn smoke_bpf_oom_veto_excludes_candidates() -> TestResult {
    let tasks: [FakeTask; 3] = [(10, 110, 900, 0), (20, 120, 100, 0), (30, 130, 500, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    let cap = bootstrap_oom_policy_authority();

    // badness = RSS (pid 10 would win), veto = pid - 30 (nonzero, i.e. vetoed,
    // for every pid but 30). The pid-30 task is mid-sized, so it can only be
    // selected if the veto actually excluded the two larger-ranked candidates.
    let Ok(by_rss) = prog_returns_ctx("oom_veto_rss", 1) else {
        return TestResult::Fail("load rejected the badness program");
    };
    let Ok(spare_30) = load(
        "oom_veto",
        asm(&[ldx(0, 1, 0), alu_imm(AluOp::Sub, 0, 30), EXIT]),
        Context::Atomic,
    ) else {
        return TestResult::Fail("load rejected the veto program");
    };
    let set = ProgSet::new()
        .with("badness", by_rss)
        .with("veto", spare_30);
    if install_bpf_oom_policy(&cap, set).is_err() {
        restore_live();
        return TestResult::Fail("install rejected a set binding an optional method");
    }
    let picked = crate::policy::select_victim_for_test().map(|v| v.pid);
    let killed = killed_tid();
    restore_live();
    if picked != Some(30) {
        return TestResult::Fail("veto did not exclude the higher-ranked candidates");
    }
    if killed != Some(130) {
        return TestResult::Fail("the surviving candidate was not the one killed");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_veto_excludes_candidates);

fn smoke_bpf_oom_unranked_falls_back_to_native() -> TestResult {
    let tasks: [FakeTask; 2] = [(10, 110, 900, 0), (20, 120, 100, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    let cap = bootstrap_oom_policy_authority();

    // A program returning 0 for everything is indistinguishable from one that
    // traps — the adapter maps both to `DEFAULT_RET`. Either way the policy
    // ranked nothing, and killing nothing would mean one buggy program can
    // switch the OOM killer off. Native badness must decide instead, and the
    // fallback must be *counted* rather than silent.
    let before = crate::native_fallback_count();
    let Ok(never) = prog_returns_const("oom_never", 0) else {
        return TestResult::Fail("load rejected the badness program");
    };
    if install_bpf_oom_policy(&cap, ProgSet::new().with("badness", never)).is_err() {
        restore_live();
        return TestResult::Fail("install rejected a complete program set");
    }
    let picked = crate::policy::select_victim_for_test().map(|v| v.pid);
    let killed = killed_tid();
    let fallbacks = crate::native_fallback_count() - before;
    restore_live();
    if picked != Some(10) {
        return TestResult::Fail("an unranked candidate set did not fall back to native badness");
    }
    if killed != Some(110) {
        return TestResult::Fail("the fallback victim was not the one killed");
    }
    if fallbacks != 1 {
        return TestResult::Fail("the native fallback was not accounted");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_unranked_falls_back_to_native);

fn smoke_bpf_oom_veto_survives_the_fallback() -> TestResult {
    // The other half of the contract: `badness == 0` is soft (fallback ranks
    // it), `veto` is hard (fallback must not). A policy that vetoes everything
    // and ranks nothing has to yield NO victim — otherwise a program protecting
    // a process would see that protection evaporate the moment the rest of its
    // ranking misfired, which is precisely when it matters most.
    let tasks: [FakeTask; 2] = [(10, 110, 900, 0), (20, 120, 100, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    let cap = bootstrap_oom_policy_authority();

    let before = crate::native_fallback_count();
    let (Ok(never), Ok(veto_all)) = (
        prog_returns_const("oom_veto_never", 0),
        prog_returns_const("oom_veto_all", 1),
    ) else {
        return TestResult::Fail("load rejected a program");
    };
    let set = ProgSet::new().with("badness", never).with("veto", veto_all);
    if install_bpf_oom_policy(&cap, set).is_err() {
        restore_live();
        return TestResult::Fail("install rejected a set binding an optional method");
    }
    let picked = crate::policy::select_victim_for_test().is_some();
    let killed = killed_tid().is_some();
    let fallbacks = crate::native_fallback_count() - before;
    restore_live();
    if picked || killed {
        return TestResult::Fail("the native fallback overrode a hard veto");
    }
    if fallbacks != 0 {
        return TestResult::Fail("a fallback was accounted with every candidate vetoed");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_veto_survives_the_fallback);

// ── the native fallback ──────────────────────────────────────────────

fn smoke_bpf_oom_native_fallback_ranks_and_honours_optout() -> TestResult {
    // No program bound: ranking must be the Linux-shaped badness
    // `narf_userspace::oom` computes, so installing this crate with no policy
    // is a behavioural no-op rather than a hole where the OOM killer was.
    //
    // pid 10 has the most RSS but opted out (`oom_score_adj == -1000`); pid 20
    // is smaller but carries a +500 bias against a 1,000,000-page machine
    // (+500,000), which must beat pid 30's raw 800 pages.
    let tasks: [FakeTask; 3] = [
        (10, 110, 900, -1000),
        (20, 120, 100, 500),
        (30, 130, 800, 0),
    ];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    crate::clear_policy();
    if crate::policy_installed() {
        restore_live();
        return TestResult::Fail("clear_policy left a policy bound");
    }
    let picked = crate::policy::select_victim_for_test().map(|v| v.pid);
    let killed = killed_tid();
    restore_live();
    match picked {
        Some(20) => {}
        Some(10) => return TestResult::Fail("native fallback selected a task that opted out"),
        Some(_) => return TestResult::Fail("native fallback ignored the oom_score_adj bias"),
        None => return TestResult::Fail("native fallback found no victim"),
    }
    if killed != Some(120) {
        return TestResult::Fail("native fallback did not kill the task it selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/oom",
    smoke_bpf_oom_native_fallback_ranks_and_honours_optout
);

fn smoke_bpf_oom_no_candidates_is_not_a_kill() -> TestResult {
    if arm_fake(&[]).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    crate::clear_policy();
    let picked = crate::policy::select_victim_for_test().is_some();
    let killed = killed_tid().is_some();
    restore_live();
    if picked || killed {
        return TestResult::Fail("an empty candidate set still produced a victim");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_no_candidates_is_not_a_kill);

// ── install-time rejection ───────────────────────────────────────────

fn smoke_bpf_oom_rejects_wrong_cap() -> TestResult {
    let tasks: [FakeTask; 1] = [(10, 110, 900, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    crate::clear_policy();

    // The right shape, the wrong authority: a program-load cap, not an
    // OOM-policy cap.
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let Ok(prog) = prog_returns_ctx("oom_badcap", 1) else {
        return TestResult::Fail("load rejected the badness program");
    };
    let outcome = install_bpf_oom_policy(&wrong, ProgSet::new().with("badness", prog));
    let leaked = crate::policy_installed();
    restore_live();
    match outcome {
        Err(StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("install accepted a capability of the wrong kind"),
    }
    if leaked {
        return TestResult::Fail("a rejected install still reached the live slot");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_rejects_wrong_cap);

fn smoke_bpf_oom_rejects_incomplete_and_unknown_sets() -> TestResult {
    if arm_fake(&[(10, 110, 900, 0)]).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    crate::clear_policy();
    let cap = bootstrap_oom_policy_authority();

    // Missing the required method: a set binding only optionals cannot rank.
    let Ok(p) = prog_returns_const("oom_incomplete", 1) else {
        return TestResult::Fail("load rejected the program");
    };
    let missing = install_bpf_oom_policy(&cap, ProgSet::new().with("veto", p.clone()));

    // Naming a method the trait does not declare.
    let unknown = install_bpf_oom_policy(
        &cap,
        ProgSet::new().with("badness", p.clone()).with("kill_it", p),
    );
    let leaked = crate::policy_installed();
    restore_live();

    match missing {
        Err(StructOpsError::MissingMethod("badness")) => {}
        _ => return TestResult::Fail("install accepted a set with no badness program"),
    }
    match unknown {
        Err(StructOpsError::UnknownMethod) => {}
        _ => return TestResult::Fail("install accepted a binding for an undeclared method"),
    }
    if leaked {
        return TestResult::Fail("a rejected install still reached the live slot");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_rejects_incomplete_and_unknown_sets);

fn smoke_bpf_oom_rejects_sleepable_program() -> TestResult {
    if arm_fake(&[(10, 110, 900, 0)]).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    crate::clear_policy();
    let cap = bootstrap_oom_policy_authority();

    // Selection runs from the memory-pressure path, which dispatches through
    // `run_atomic`: a sleepable program would decline every call and the policy
    // would look installed while ranking nothing. Rejected by type at install.
    let Ok(sleepy) = load(
        "oom_sleepy",
        asm(&[mov_imm(0, 5), EXIT]),
        Context::Sleepable,
    ) else {
        return TestResult::Fail("load rejected the sleepable program");
    };
    let outcome = install_bpf_oom_policy(&cap, ProgSet::new().with("badness", sleepy));
    let leaked = crate::policy_installed();
    restore_live();
    match outcome {
        Err(StructOpsError::WrongContext { method: "badness" }) => {}
        _ => return TestResult::Fail("install accepted a sleepable program"),
    }
    if leaked {
        return TestResult::Fail("a rejected install still reached the live slot");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_rejects_sleepable_program);

fn smoke_bpf_oom_commit_requires_a_candidate_source() -> TestResult {
    // Committing with no source would register a killer that can never find a
    // victim — an OOM killer that looks armed and silently does nothing, which
    // is strictly worse than not installing. The window with no source is as
    // narrow as it can be made: cleared here, restored before returning.
    crate::clear_policy();
    crate::policy::__clear_candidate_source_for_test();
    let cap = bootstrap_oom_policy_authority();
    let Ok(p) = prog_returns_ctx("oom_nosource", 1) else {
        restore_live();
        return TestResult::Fail("load rejected the badness program");
    };
    let outcome = install_bpf_oom_policy(&cap, ProgSet::new().with("badness", p));
    let leaked = crate::policy_installed();
    restore_live();
    match outcome {
        Err(StructOpsError::CommitFailed(_)) => {}
        _ => return TestResult::Fail("commit succeeded with no candidate source"),
    }
    if leaked {
        return TestResult::Fail("a failed commit still bound a policy");
    }
    if !crate::has_candidate_source() {
        return TestResult::Fail("the live candidate source was not restored");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_commit_requires_a_candidate_source);

// ── reaching memory's live slot ──────────────────────────────────────

fn smoke_bpf_oom_commit_reaches_memory_slot() -> TestResult {
    // The last seam: an installed program set becoming the policy `memory`'s
    // own pressure path dispatches through. Driven through
    // `narf_memory::oom::request_oom_relief`, which asks whatever killer is
    // registered — so a pid that only exists in the fake source coming back
    // proves this crate's killer, ranking with this crate's program, is the one
    // `memory` called.
    let tasks: [FakeTask; 2] = [(4242, 4243, 900, 0), (20, 120, 100, 0)];
    if arm_fake(&tasks).is_err() {
        return TestResult::Fail("could not arm the fake candidate source");
    }
    let cap = bootstrap_oom_policy_authority();
    let Ok(by_rss) = prog_returns_ctx("oom_live_rss", 1) else {
        return TestResult::Fail("load rejected the badness program");
    };
    if install_bpf_oom_policy(&cap, ProgSet::new().with("badness", by_rss)).is_err() {
        restore_live();
        return TestResult::Fail("install rejected a complete program set");
    }
    if !narf_memory::oom::is_armed() {
        restore_live();
        return TestResult::Fail("memory has no OOM policy installed");
    }
    let relieved = narf_memory::oom::request_oom_relief();
    restore_live();
    // The victim is now queued for the real reaper. That is safe and
    // deliberate: its address space is a fresh `new_for_user` root with nothing
    // mapped, so the reaper finds nothing to reap and drops it.
    match relieved {
        Some(4242) => TestResult::Pass,
        Some(_) => TestResult::Fail("memory dispatched to a different policy"),
        None => TestResult::Fail("memory's pressure path found no victim"),
    }
}
kernel_test_in!("bpf/oom", smoke_bpf_oom_commit_reaches_memory_slot);
