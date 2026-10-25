//! Fixture tests for the pure pieces of the recovery machinery:
//! the endpoint-command TRB encodings and the dequeue-cursor
//! canonicalization `reset_endpoint` relies on. The MMIO sequences
//! themselves reuse the already-proven submit/await machinery (the
//! `bulk_stop` Bus adapter) and are exercised by the live QEMU
//! gates; these tests pin the decisions that can be proven without
//! a controller.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Reset Endpoint / Set TR Dequeue Pointer TRB layout: dword 0..1
/// carry the dequeue pointer (bit 0 = DCS), dword 2 is zero, dword 3
/// packs type / slot / DCI — and crucially NOT the command-ring
/// cycle bit, which `submit_command_record` patches in.
fn smoke_xhci_endpoint_command_words() -> TestResult {
    let words = Xhci::endpoint_command_words(TRB_TYPE_RESET_ENDPOINT_CMD, 5, 3, 0);
    let expected: [u32; 4] = [0, 0, 0, (14 << 10) | (5 << 24) | (3 << 16)];
    if words != expected {
        return TestResult::Fail("Reset Endpoint TRB words mismatch");
    }
    let dequeue: u64 = 0x1234_5001;
    let words = Xhci::endpoint_command_words(TRB_TYPE_SET_TR_DEQUEUE_CMD, 5, 3, dequeue);
    let expected: [u32; 4] = [0x1234_5001, 0, 0, (16 << 10) | (5 << 24) | (3 << 16)];
    if words != expected {
        return TestResult::Fail("Set TR Dequeue Pointer TRB words mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_endpoint_command_words);

/// The canonical cursor: mid-ring cursors pass through untouched;
/// a cursor sitting on the Link TRB slot wraps to the ring start
/// with the cycle bit toggled (the same rule as `bulk_stop::Plan`).
fn smoke_xhci_canonical_cursor_wraps_at_link() -> TestResult {
    if Xhci::canonical_cursor(64, 17, 1) != (17, 1) {
        return TestResult::Fail("mid-ring cursor changed");
    }
    if Xhci::canonical_cursor(64, 63, 1) != (0, 0) {
        return TestResult::Fail("link-slot cursor did not wrap and toggle");
    }
    if Xhci::canonical_cursor(64, 63, 0) != (0, 1) {
        return TestResult::Fail("link-slot cursor toggle wrong from cycle 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_canonical_cursor_wraps_at_link
);
