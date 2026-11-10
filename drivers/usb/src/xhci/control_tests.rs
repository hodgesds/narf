//! Fixture tests for the control-transfer completion rules that can be
//! proven without a controller: which Transfer Events end a control TD
//! (Setup-stage errors included), how a stage event maps to a result,
//! and the stage deadline against a simulated clock. Events are built
//! from the xHCI 1.2 §6.4.2.1 Transfer Event layout, not from the
//! production encoders.

use super::bulk_owner::{ControlState, Error as OwnerError};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const SLOT: u8 = 5;
const GENERATION: u64 = 42;
const SETUP: u64 = 0x1000;
const DATA: u64 = 0x1010;
const STATUS: u64 = 0x1020;

fn transfer(slot: u8, pointer: u64, code: u8, residue: u32) -> [u32; 4] {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24 | residue,
        32 << 10 | 1 << 16 | u32::from(slot) << 24,
    ]
}

fn published() -> ControlState {
    let mut control = ControlState::new();
    control.begin(GENERATION, GENERATION).unwrap();
    control.expect_setup(SETUP).unwrap();
    control.expect(DATA).unwrap();
    control.expect(STATUS).unwrap();
    control
}

/// Defect 2: a USB Transaction Error (CC 4) reported against the Setup
/// Stage TRB is retained by the EP0 owner (never the lossy shared queue),
/// ends the TD for whichever stage is being awaited as `CmdFailed(4)`,
/// is a halting code (so Reset Endpoint recovery runs), and EP0 accepts
/// the next transfer once that recovery commits.
fn smoke_xhci_setup_stage_error_ends_control_td() -> TestResult {
    let error = transfer(SLOT, SETUP, 4, 8);
    for stage in [DATA, STATUS] {
        let mut control = published();
        if !control.record(SLOT, error) {
            return TestResult::Fail("Setup-stage error fell through to the lossy queue");
        }
        let taken = control
            .take_matching(&mut |event| Xhci::control_td_event_matches(event, SLOT, stage, SETUP));
        if taken != Ok(Some(error)) {
            return TestResult::Fail("Setup-stage error did not end the awaited stage");
        }
        if Xhci::control_stage_status(&error, true) != Err(XhciError::CmdFailed(4))
            || Xhci::control_stage_status(&error, false) != Err(XhciError::CmdFailed(4))
        {
            return TestResult::Fail("Setup-stage Transaction Error was not CmdFailed(4)");
        }
        if !Xhci::control_failure_halts(4) {
            return TestResult::Fail("Transaction Error did not select halted-EP0 recovery");
        }
        // Until recovery commits, the failed TD keeps EP0 claimed.
        if control.begin(GENERATION, GENERATION) != Err(OwnerError::Busy) {
            return TestResult::Fail("failed control TD released EP0 before recovery");
        }
        // `reset_endpoint` commit: Reset Endpoint + Set TR Dequeue proved
        // the pipe Stopped, so the claim reopens and the next TD's
        // receipts are accepted.
        control.force_reset();
        if control.begin(GENERATION, GENERATION) != Ok(())
            || control.expect_setup(0x1030) != Ok(())
            || control.expect(0x1040) != Ok(())
            || control.expect(0x1050) != Ok(())
        {
            return TestResult::Fail("EP0 was not reusable after Setup-stage error recovery");
        }
        // The old Setup TRB no longer names a receipt.
        if control.record(SLOT, error) {
            return TestResult::Fail("recovered TD's Setup error latched into the next TD");
        }
        let data = transfer(SLOT, 0x1040, 1, 0);
        let status = transfer(SLOT, 0x1050, 1, 0);
        if !control.record(SLOT, data)
            || !control.record(SLOT, status)
            || control.take_matching(&mut |event| {
                Xhci::control_td_event_matches(event, SLOT, 0x1040, 0x1030)
            }) != Ok(Some(data))
            || control.take_matching(&mut |event| {
                Xhci::control_td_event_matches(event, SLOT, 0x1050, 0x1030)
            }) != Ok(Some(status))
            || control.complete(GENERATION, GENERATION) != Ok(())
        {
            return TestResult::Fail("transfer after Setup-stage recovery did not complete");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_setup_stage_error_ends_control_td
);

/// The Setup receipt ends a TD only on failure. Stall (6) and Babble (3)
/// do; a foreign slot's event, an Event Data event, or a success code at
/// the Setup pointer never satisfy a stage wait, and a successful TD
/// completes without the Setup receipt ever being consumed.
fn smoke_xhci_setup_receipt_only_ends_td_on_error() -> TestResult {
    for code in [3u8, 6] {
        let event = transfer(SLOT, SETUP, code, 0);
        if !Xhci::control_td_event_matches(&event, SLOT, DATA, SETUP)
            || Xhci::control_stage_status(&event, true) != Err(XhciError::CmdFailed(code))
            || !Xhci::control_failure_halts(code)
        {
            return TestResult::Fail("halting Setup-stage code did not end the TD");
        }
    }
    let mut event_data = transfer(SLOT, SETUP, 4, 0);
    event_data[3] |= 1 << 2;
    if Xhci::control_td_event_matches(&transfer(SLOT + 1, SETUP, 4, 0), SLOT, DATA, SETUP)
        || Xhci::control_td_event_matches(&event_data, SLOT, DATA, SETUP)
        || Xhci::control_td_event_matches(&transfer(SLOT, SETUP, 1, 0), SLOT, DATA, SETUP)
        || Xhci::control_td_event_matches(&transfer(SLOT, SETUP, 13, 0), SLOT, DATA, SETUP)
        || Xhci::control_td_event_matches(&transfer(SLOT, STATUS, 1, 0), SLOT, DATA, SETUP)
    {
        return TestResult::Fail("foreign or non-error event ended a control stage");
    }
    // Stage results: Short Packet is success only for an IN data stage.
    let short = transfer(SLOT, DATA, 13, 4);
    if Xhci::control_stage_status(&short, true) != Ok(())
        || Xhci::control_stage_status(&short, false) != Err(XhciError::CmdFailed(13))
        || Xhci::control_stage_status(&transfer(SLOT, STATUS, 1, 0), false) != Ok(())
        || Xhci::control_failure_halts(13)
        || Xhci::control_failure_halts(1)
    {
        return TestResult::Fail("control stage completion-code mapping changed");
    }
    // A clean TD: Data + Status consumed, Setup receipt untouched.
    let mut control = published();
    let status = transfer(SLOT, STATUS, 1, 0);
    if !control.record(SLOT, short)
        || !control.record(SLOT, status)
        || control
            .take_matching(&mut |event| Xhci::control_td_event_matches(event, SLOT, DATA, SETUP))
            != Ok(Some(short))
        || control
            .take_matching(&mut |event| Xhci::control_td_event_matches(event, SLOT, STATUS, SETUP))
            != Ok(Some(status))
        || control.complete(GENERATION, GENERATION) != Ok(())
        || control.active()
    {
        return TestResult::Fail("unused Setup receipt blocked a successful control TD");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_setup_receipt_only_ends_td_on_error
);

/// One stage wait against a simulated clock: an executor round every
/// 10 ms, the device answering the Data stage at `answer_ms`. Drives the
/// production batch poller and EP0 owner; only the clock is simulated.
fn wait_data_stage(timeout_ms: u64, answer_ms: u64) -> Result<[u32; 4], ()> {
    let mut control = published();
    let data = transfer(SLOT, DATA, 13, 4);
    let mut now_ms = 0u64;
    loop {
        if now_ms == answer_ms {
            control.record(SLOT, data);
        }
        match event_wait::poll_batch(
            || {
                control.take_matching(&mut |event| {
                    Xhci::control_td_event_matches(event, SLOT, DATA, SETUP)
                })
            },
            || false,
            || now_ms >= timeout_ms,
        ) {
            Ok(Some(event)) => return Ok(event),
            Ok(None) => now_ms += 10,
            Err(_) => return Err(()),
        }
    }
}

/// Defect 1: a control-IN whose Data stage completes 400 ms after the
/// doorbell — later than the old shared 250 ms bound — succeeds under
/// the control-stage deadline, which is Linux's 5000 ms
/// (`USB_CTRL_GET_TIMEOUT`). Commands get the same 5000 ms
/// (`XHCI_CMD_DEFAULT_TIMEOUT`); the one-shot bulk/isoch poll keeps its
/// short bound, under which the same answer would still time out.
fn smoke_xhci_control_stage_outlives_legacy_250ms_deadline() -> TestResult {
    if event_wait::Wait::ControlStage.timeout_ms() != 5000
        || event_wait::Wait::Command.timeout_ms() != 5000
        || event_wait::Wait::Transfer.timeout_ms() != 250
    {
        return TestResult::Fail("wait-class deadlines changed");
    }
    let data = transfer(SLOT, DATA, 13, 4);
    if wait_data_stage(event_wait::Wait::ControlStage.timeout_ms(), 400) != Ok(data) {
        return TestResult::Fail("control stage completing at 400 ms timed out");
    }
    if wait_data_stage(event_wait::Wait::ControlStage.timeout_ms(), 4990) != Ok(data) {
        return TestResult::Fail("control stage completing inside 5000 ms timed out");
    }
    if wait_data_stage(event_wait::Wait::ControlStage.timeout_ms(), 5010) != Err(()) {
        return TestResult::Fail("control stage wait is unbounded");
    }
    if wait_data_stage(event_wait::Wait::Transfer.timeout_ms(), 400) != Err(()) {
        return TestResult::Fail("fixture no longer reproduces the 250 ms failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_stage_outlives_legacy_250ms_deadline
);
