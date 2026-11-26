//! Navi31 ColdBoot sequence pins: stage order, failure, cancellation,
//! and the fail-closed mapping for stages whose owners do not exist yet.
//! The retained-owner path (a bound Navi31 card) is exercised by the boot
//! handoff, not here: it needs a real clock preflight, firmware registry
//! and VRAM inventory.
use super::*;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn report() -> Report {
    Report {
        chip: Rdna3Chip::Navi31,
        stages_completed: STAGES.len() as u8,
        next_stage: None,
        smu: Some(smu::SmuInfo {
            smu_version: 0x003d_0000,
            driver_if_version: smu::SMU_13_0_0_DRIVER_IF_VERSION,
        }),
        aperture: Some(gmc::Aperture {
            start: 0xc00000000,
            size: 2 << 20,
            source: 0xc00000000,
            destination: 0xc00001000,
        }),
    }
}
struct FakeBoot {
    log: Vec<Stage>,
    fail: Option<Stage>,
    stall: Option<Stage>,
}
impl Backend for FakeBoot {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        self.log.push(stage);
        if self.stall == Some(stage) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(stage) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(report())
    }
}
fn sequence(fail: Option<Stage>, stall: Option<Stage>) -> Sequence<FakeBoot> {
    Sequence {
        backend: FakeBoot {
            log: Vec::new(),
            fail,
            stall,
        },
        state: State::Prepared,
    }
}
fn navi31_boot_order_failure_and_cancellation() -> TestResult {
    let mut s = sequence(None, None);
    if run(s.run()) != Ok(report()) || s.backend.log != STAGES || s.state != State::MemoryReady {
        return TestResult::Fail("Navi31 firmware boot order/report");
    }
    for stage in STAGES {
        let mut s = sequence(Some(stage), None);
        if run(s.run()) != Err(Error::Invalid)
            || s.state != State::Failed(stage, Error::Invalid)
            || s.backend.log.last() != Some(&stage)
        {
            return TestResult::Fail("Navi31 boot did not fail closed at the failing stage");
        }
        let mut s = sequence(None, Some(stage));
        {
            let mut future = core::pin::pin!(s.run());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("stalled Navi31 boot completed");
            }
        }
        if s.state != State::Running(stage) || run(s.run()) != Err(Error::Busy) {
            return TestResult::Fail("cancelled Navi31 boot replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    navi31_boot_order_failure_and_cancellation
);

fn navi31_boot_report_names_completed_stages_and_next_stage() -> TestResult {
    // The report is the terminal state: every stage complete, none next.
    let r = report();
    if r.stages_completed != STAGES.len() as u8 || r.next_stage.is_some() {
        return TestResult::Fail("terminal Navi31 report does not complete every stage");
    }
    if r.smu
        .is_none_or(|s| s.driver_if_version != smu::SMU_13_0_0_DRIVER_IF_VERSION)
        || r.aperture.is_none()
    {
        return TestResult::Fail("Navi31 report lost the SMU versions or GMC aperture");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    navi31_boot_report_names_completed_stages_and_next_stage
);

fn navi31_boot_unavailable_stage_is_a_named_error_not_a_skip() -> TestResult {
    // Every stage without an owner fails closed with its own name on it.
    // A silent skip would let the sequence claim stages it never ran.
    for stage in [
        Stage::Ih,
        Stage::Dcn,
        Stage::Cp,
        Stage::Sdma,
        Stage::Submitter,
        Stage::Vcn,
        Stage::Thermal,
    ] {
        let error = Error::StageUnavailable(stage);
        if error == Error::Invalid || error == Error::Unsupported {
            return TestResult::Fail("unavailable Navi31 stage collapsed into a generic error");
        }
        if !matches!(error, Error::StageUnavailable(s) if s == stage) {
            return TestResult::Fail("unavailable Navi31 stage lost its stage name");
        }
    }
    // The four stages this lane implements are exactly the ones before Ih.
    if STAGES[..4] != [Stage::MemoryTraining, Stage::Psp, Stage::Smu, Stage::Gmc] {
        return TestResult::Fail("executable Navi31 stages are not the first four in order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    navi31_boot_unavailable_stage_is_a_named_error_not_a_skip
);
