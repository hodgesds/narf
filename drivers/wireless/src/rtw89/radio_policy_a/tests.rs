use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_a_radio_programs_follow_b_layout_and_extend_a_identity() -> TestResult {
    // The A program list is the shared six-program layout in `ALL` order,
    // and every program's flags (with its dependencies) validate.
    if PROGRAMS != Program::ALL {
        return TestResult::Fail("A program list differs from the shared program layout");
    }
    for program in Program::ALL {
        if !programs_valid(program.flags()) {
            return TestResult::Fail("A program flags refused");
        }
    }
    if !programs_valid(BASE_FLAGS) {
        return TestResult::Fail("A base flags refused");
    }
    // Incomplete base flags and unmet dependencies stay refused.
    for flags in [
        0x0,
        0x2,
        0x6,
        BASE_FLAGS | Program::FirmwareRa.bit(),
        BASE_FLAGS | Program::Ht.bit(),
        BASE_FLAGS | Program::He.bit(),
        BASE_FLAGS | Program::Ampdu.bit(),
        BASE_FLAGS | Program::QosAll.bit() | Program::He.bit(),
    ] {
        if programs_valid(flags) {
            return TestResult::Fail("A program flags admitted without base or dependencies");
        }
    }
    // Every program extends the identity deterministically, each to a
    // distinct identity, and the extension binds the input identity.
    let identity = [7u8; 32];
    let mut extended = [[0u8; 32]; 6];
    for (index, program) in Program::ALL.into_iter().enumerate() {
        let next = extend(program, identity);
        if next == identity || extend(program, identity) != next {
            return TestResult::Fail("A program did not extend its identity deterministically");
        }
        if extended[..index].contains(&next) {
            return TestResult::Fail("two A programs extended to the same identity");
        }
        extended[index] = next;
    }
    if extend(Program::Wmm, [8u8; 32]) == extended[0] {
        return TestResult::Fail("A program extension ignored its input identity");
    }
    // The full program set extends once per program in the fixed order.
    let full = Program::Ampdu.flags() | Program::He.bit() | Program::QosAll.bit();
    if !programs_valid(full) {
        return TestResult::Fail("A full program flags refused");
    }
    let mut running = identity;
    for program in Program::ALL {
        if full & program.bit() != 0 {
            running = extend(program, running);
        }
    }
    if running == identity || Program::ALL.iter().any(|p| extend(*p, identity) == running) {
        return TestResult::Fail("A full program extension did not compose per program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_radio_programs_follow_b_layout_and_extend_a_identity
);
