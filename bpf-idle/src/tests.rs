//! In-kernel smokes for the BPF idle governor.
//!
//! Registered under the `bpf/idle` subsystem, so `xtask test --subsystem bpf`
//! (prefix match) runs them while `--subsystem bpf/idle` runs just these.
//!
//! Unlike the framework smokes in `narf-bpf-structops` (which dispatch through a
//! stand-in slot), these drive `narf-power`'s *real* `IDLE_GOVERNOR` slot: the
//! proof that the `#[commit(...)]` seam reaches a live subsystem.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadRequest};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{Decoded, Insn, Reg, Source};
use narf_bpf_structops::{ProgSet, StructOpsError};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::install_bpf_idle_governor;

// ── program-building helpers ─────────────────────────────────────────

fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfProgLoad,
            Grant,
        >::bootstrap()));
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

const EXIT: Decoded = Decoded::Exit;

/// Load a program that returns the constant `idx` as its C-state choice.
fn load_returning(name: &str, idx: i32) -> Result<Arc<BpfProg>, &'static str> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: String::from(name),
            insns: asm(&[mov_imm(0, idx), EXIT]),
            context: Context::Atomic,
            maps: Vec::new(),
        },
    )
    .map_err(|_| "load rejected")
}

// ── smokes ───────────────────────────────────────────────────────────

fn smoke_bpf_idle_governor_drives_power_slot() -> TestResult {
    // Known state: C0 (id 0) + C1 (id 1), LinearScan idle, Performance dvfs.
    narf_power::init();

    // A program that always picks C1 (id 1).
    let Ok(c1) = load_returning("bpfidle_c1", 1) else {
        return TestResult::Fail("load rejected the C1 program");
    };
    let cap = narf_power::bootstrap_idle_governor_authority();
    if install_bpf_idle_governor(&cap, ProgSet::new().with("select_state", c1)).is_err() {
        return TestResult::Fail("install rejected a complete program set");
    }

    // power now names and dispatches through the BPF governor.
    if narf_power::current_idle_governor_name() != Some("bpf") {
        return TestResult::Fail("power slot does not name the bpf governor");
    }
    match narf_power::select_idle_state() {
        Ok(cs) if cs.id == 1 => {}
        Ok(_) => return TestResult::Fail("resolved the wrong C-state for the C1 program"),
        Err(_) => return TestResult::Fail("select_idle_state errored with the bpf governor"),
    }

    // Re-install a program that picks C0 (id 0). Proves the program's actual
    // return value reaches power's resolution — not a hardcoded default — and
    // that a re-install swaps the live policy.
    let Ok(c0) = load_returning("bpfidle_c0", 0) else {
        return TestResult::Fail("load rejected the C0 program");
    };
    if install_bpf_idle_governor(&cap, ProgSet::new().with("select_state", c0)).is_err() {
        return TestResult::Fail("re-install rejected a complete program set");
    }
    match narf_power::select_idle_state() {
        Ok(cs) if cs.id == 0 => {}
        _ => return TestResult::Fail("value did not flow: C0 program did not resolve to C0"),
    }

    // Restore the default idle governor so later tests / boot don't inherit the
    // BPF policy through the shared slot.
    narf_power::init();
    TestResult::Pass
}
kernel_test_in!("bpf/idle", smoke_bpf_idle_governor_drives_power_slot);

fn smoke_bpf_idle_governor_rejects_wrong_cap() -> TestResult {
    // Default idle governor after init is LinearScan ("linear-scan").
    narf_power::init();

    // The right shape, the wrong authority: a program-load cap, not an
    // idle-governor cap.
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let Ok(prog) = load_returning("bpfidle_bad", 1) else {
        return TestResult::Fail("load rejected the governor program");
    };
    match install_bpf_idle_governor(&wrong, ProgSet::new().with("select_state", prog)) {
        Err(StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("install accepted a capability of the wrong kind"),
    }

    // The rejection must happen before the committer touches power's slot.
    if narf_power::current_idle_governor_name() == Some("bpf") {
        return TestResult::Fail("a rejected install still reached the power slot");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/idle", smoke_bpf_idle_governor_rejects_wrong_cap);
