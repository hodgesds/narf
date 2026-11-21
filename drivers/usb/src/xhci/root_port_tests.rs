//! Root port change acknowledgement. The controller raises a Port
//! Status Change Event only when a PORTSC change bit goes from 0 to 1
//! (xHCI 1.2 §4.19.2), so a supervisor woken by those events — not by a
//! periodic PORTSC poll — must clear every change bit it saw, or the
//! next connect or disconnect of that port raises no event at all.
//! Linux clears them through ClearPortFeature(C_*) →
//! `xhci_clear_port_change_bit`, writing the port back in its neutral
//! state (`xhci_port_state_to_neutral`: PED and PR never echoed).
use super::op::{
    PORTSC_CCS, PORTSC_CHG_MASK, PORTSC_CSC, PORTSC_PEC, PORTSC_PED, PORTSC_PLC, PORTSC_PP,
    PORTSC_PR, PORTSC_PRC,
};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_xhci_root_port_changes_are_acknowledged() -> TestResult {
    // A disconnect: CSC and PEC latched, the link went to RxDetect.
    let unplugged = PORTSC_PP | PORTSC_CSC | PORTSC_PEC | PORTSC_PLC | (5 << 5);
    let Some(write) = root_port_change_ack(unplugged) else {
        return TestResult::Fail(
            "root port change bits left set: the next connect raises no Port Status Change Event",
        );
    };
    if write & PORTSC_CHG_MASK != PORTSC_CSC | PORTSC_PEC | PORTSC_PLC {
        return TestResult::Fail("the ack did not clear exactly the change bits that were set");
    }
    if write & (PORTSC_PED | PORTSC_PR) != 0 || write & PORTSC_PP == 0 {
        return TestResult::Fail("the ack disabled, reset or powered off the port");
    }
    // An enabled port whose connect and reset completed: PED (RW1C)
    // must not be echoed, or the write disables the port.
    let connected = PORTSC_PP | PORTSC_CCS | PORTSC_PED | PORTSC_CSC | PORTSC_PRC;
    match root_port_change_ack(connected) {
        Some(write)
            if write & PORTSC_PED == 0 && write & PORTSC_CHG_MASK == PORTSC_CSC | PORTSC_PRC => {}
        _ => return TestResult::Fail("an enabled port's changes were not acknowledged safely"),
    }
    // Nothing changed: nothing to write.
    if root_port_change_ack(PORTSC_PP | PORTSC_CCS | PORTSC_PED).is_some() {
        return TestResult::Fail("a port without changes was written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/root_port",
    smoke_xhci_root_port_changes_are_acknowledged
);
