//! Kernel tests for the APU platform singleton attach (#1698, #2467).
//!
//! Spec-fixture discipline: the SMU is `MockSmu`, scripted with the
//! literal message id and driver-IF versions from the Linux
//! driver-IF headers (`smu12_driver_if.h`,
//! `smu13_driver_if_v13_0_4.h`) — the same source the production
//! constants were written from — so the fake and the code cannot
//! agree on a wrong constant. The end-to-end attach fixture (publish
//! → monitor → snapshot → `gpu_temp_mc`) lives in
//! `amdgpu_smu_apu_telemetry_tests` beside the fake buffer and the
//! hand-built metrics tables; this file pins the version-detection
//! half of the attach (the step that refuses any SMU generation
//! outside 12 / 13.0.4 by the SMU's own answer).

use super::*;
use crate::amdgpu_smu::{
    detect_version, MockSmu, SmuVersion, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL,
    MP1_C2PMSG_RESP_REL, SMU_13_0_0_DRIVER_IF_VERSION, SMU_RESP_OK,
};
use narf_kernel_test::{kernel_test_in, TestResult};

const MP1_BASE: u32 = 0x16000;

/// Stage one `GetDriverIfVersion` answer: handshake idle, OK
/// response, the SMU's driver-IF version in ARG. The message id is
/// written out literally (0x03, `PPSMC_MSG_GET_DRIVER_IF_VERSION`,
/// the same id on SMU 12 and SMU 13) instead of reusing the
/// production constant, so the test checks the id rather than
/// echoing it.
fn stage_driver_if(smu: &mut MockSmu, mp1_base: u32, driver_if: u32) {
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;
    smu.stage_read(resp, 1);
    smu.stage_read(resp, SMU_RESP_OK);
    smu.stage_read(arg, driver_if);
}

fn apu_detect_version_phoenix_v13() -> TestResult {
    let mut smu = MockSmu::new();
    stage_driver_if(&mut smu, MP1_BASE, 0x07); // SMU_13_0_4_DRIVER_IF_VERSION
    match detect_version(&mut smu, MP1_BASE) {
        Some(SmuVersion::V13) => {}
        _ => return TestResult::Fail("driver-IF 0x07 must detect SMU 13.0.4 (Phoenix)"),
    }
    // The detection is one message: handshake clear, arg 0, id 0x03.
    let resp = MP1_BASE + MP1_C2PMSG_RESP_REL;
    let arg = MP1_BASE + MP1_C2PMSG_ARG_REL;
    let msg = MP1_BASE + MP1_C2PMSG_MSG_REL;
    let expected: [(u32, u32); 3] = [(resp, 0), (arg, 0), (msg, 0x03)];
    if smu.writes.as_slice() != expected.as_slice() {
        return TestResult::Fail("detect must send GetDriverIfVersion (0x03) with arg 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/apu_platform",
    apu_detect_version_phoenix_v13
);

fn apu_detect_version_renoir_v12() -> TestResult {
    let mut smu = MockSmu::new();
    stage_driver_if(&mut smu, MP1_BASE, 0x0F); // SMU12_DRIVER_IF_VERSION
    match detect_version(&mut smu, MP1_BASE) {
        Some(SmuVersion::V12) => TestResult::Pass,
        _ => TestResult::Fail("driver-IF 0x0F must detect SMU 12 (Renoir)"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/apu_platform",
    apu_detect_version_renoir_v12
);

fn apu_detect_version_refuses_smu_13_0_0() -> TestResult {
    // 0x3D is the SMU 13.0.0 driver-IF version (Navi31 discrete,
    // `SMU_13_0_0_DRIVER_IF_VERSION`): the attach must refuse it
    // rather than misreading the chip as Phoenix. Any generation
    // whose driver-IF is not 0x0F / 0x07 — Raphael answers 5 — is
    // refused the same way, by the same `None`.
    let mut smu = MockSmu::new();
    stage_driver_if(&mut smu, MP1_BASE, SMU_13_0_0_DRIVER_IF_VERSION);
    match detect_version(&mut smu, MP1_BASE) {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("driver-IF 0x3D must not resolve to an APU SMU version"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/apu_platform",
    apu_detect_version_refuses_smu_13_0_0
);

fn apu_detect_version_refuses_silent_smu() -> TestResult {
    // No staged reads: the handshake observes "busy" until the
    // bounded poll gives up, and detect returns None — a SMU that
    // never answers refuses the attach instead of hanging boot.
    let mut smu = MockSmu::new();
    match detect_version(&mut smu, MP1_BASE) {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("a silent SMU must not resolve to any version"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/apu_platform",
    apu_detect_version_refuses_silent_smu
);
