//! In-kernel smokes for the contract-bound BPF idle governor.

use alloc::string::String;
use alloc::vec::Vec;

use narf_bpf::prog::{BpfProgLoad, LoadRequest};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{Decoded, Insn, Reg, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{install_bpf_idle_governor, BpfIdleGovernorPrograms};

fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut slot = SLOT.lock();
    if slot.is_none() {
        *slot = Some(alloc::boxed::Box::leak(alloc::boxed::Box::new(
            Cap::bootstrap(),
        )));
    }
    slot.expect("just installed")
}

fn r(number: u8) -> Reg {
    Reg::new(number).expect("register in range")
}

fn asm(items: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(encode(*item).slots());
    }
    out
}

fn mov_imm(dst: u8, value: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(value),
        sign_extend: None,
    }
}

const EXIT: Decoded = Decoded::Exit;

fn returning(name: &str, value: i32) -> LoadRequest {
    LoadRequest {
        name: String::from(name),
        insns: asm(&[mov_imm(0, value), EXIT]),
        context: Context::Atomic,
        maps: Vec::new(),
        map_indices: Vec::new(),
        load_references: Vec::new(),
    }
}

fn programs(name: &str, value: i32) -> Result<BpfIdleGovernorPrograms, &'static str> {
    BpfIdleGovernorPrograms::new()
        .select_state(load_cap(), returning(name, value))
        .map_err(|_| "method-specific load rejected")
}

fn smoke_bpf_idle_governor_drives_power_slot() -> TestResult {
    narf_power::init();
    let cap = narf_power::bootstrap_idle_governor_authority();
    let c1_programs = match programs("bpfidle_c1", 1) {
        Ok(programs) => programs,
        Err(error) => return TestResult::Fail(error),
    };
    let c1_link = match install_bpf_idle_governor(&cap, c1_programs) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("install rejected a complete program set"),
    };
    if narf_power::current_idle_governor_name() != Some("bpf") {
        return TestResult::Fail("power slot does not name the bpf governor");
    }
    match narf_power::select_idle_state() {
        Ok(state) if state.id == 1 => {}
        _ => return TestResult::Fail("C1 program did not resolve to C1"),
    }

    let c0_programs = match programs("bpfidle_c0", 0) {
        Ok(programs) => programs,
        Err(error) => return TestResult::Fail(error),
    };
    let c0_link = match install_bpf_idle_governor(&cap, c0_programs) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("replacement install failed"),
    };
    drop(c1_link);
    match narf_power::select_idle_state() {
        Ok(state) if state.id == 0 => {}
        _ => return TestResult::Fail("stale link detached the C0 replacement"),
    }
    drop(c0_link);
    if narf_power::current_idle_governor_name() != Some("linear-scan") {
        return TestResult::Fail("link drop did not restore the native governor");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/idle", smoke_bpf_idle_governor_drives_power_slot);

fn smoke_bpf_idle_governor_rejects_wrong_cap() -> TestResult {
    narf_power::init();
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let programs = match programs("bpfidle_bad", 1) {
        Ok(programs) => programs,
        Err(error) => return TestResult::Fail(error),
    };
    match install_bpf_idle_governor(&wrong, programs) {
        Err(narf_bpf_structops::StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("install accepted the wrong capability kind"),
    }
    if narf_power::current_idle_governor_name() == Some("bpf") {
        return TestResult::Fail("rejected install reached the power slot");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/idle", smoke_bpf_idle_governor_rejects_wrong_cap);

fn no_op_entry() {}

fn smoke_bpf_idle_governor_revalidates_result() -> TestResult {
    narf_power::init();
    let power = narf_power::bootstrap_power_authority();
    if narf_power::register_cstate(
        &power,
        narf_power::CState {
            id: 2,
            exit_latency_us: 2_000,
            power_draw_mw: 1,
            target_residency_us: 2_000,
            entry: no_op_entry,
        },
    )
    .is_err()
    {
        return TestResult::Fail("failed to register constrained test state");
    }

    let cap = narf_power::bootstrap_idle_governor_authority();
    let constrained = match programs("bpfidle_constrained", 2) {
        Ok(programs) => programs,
        Err(error) => return TestResult::Fail(error),
    };
    let constrained_link = match install_bpf_idle_governor(&cap, constrained) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("constrained program failed to install"),
    };
    match narf_power::select_idle_state() {
        Ok(state) if state.id == 0 => {}
        _ => return TestResult::Fail("power accepted a state outside live constraints"),
    }
    drop(constrained_link);

    let too_wide = match programs("bpfidle_wide", 256) {
        Ok(programs) => programs,
        Err(error) => return TestResult::Fail(error),
    };
    let wide_link = match install_bpf_idle_governor(&cap, too_wide) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("wide-result program failed to install"),
    };
    match narf_power::select_idle_state() {
        Ok(state) if state.id == 0 => {}
        _ => return TestResult::Fail("invalid BPF result did not fall back to C0"),
    }
    drop(wide_link);
    narf_power::init();
    TestResult::Pass
}
kernel_test_in!("bpf/idle", smoke_bpf_idle_governor_revalidates_result);
