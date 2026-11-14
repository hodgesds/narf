//! Fixture tests for the pure pieces of the isochronous path (#886):
//! the Isoch TRB encoding and the DCI→endpoint-index validation.
//! The MMIO/doorbell sequences and the cache maintenance itself
//! reuse the already-proven submit/await machinery and are exercised
//! by the live QEMU gates; these tests pin the decisions that can be
//! proven without a controller — the TRB words against xHCI 1.2
//! §6.4.1.3 Table 6-49, and the DCI range against §4.8.1.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Isoch TRB words, built from the spec table — not from the
/// production encoder: d0/d1 = 64-bit Data Buffer Pointer,
/// d2 = Transfer Length (bits 16:0; TD Size / Interrupter Target
/// zero for a single-packet one-shot), d3 = Cycle (bit 0) | IOC
/// (bit 5) | Type 5 (bits 15:10) | SIA (bit 31).
fn smoke_xhci_isoch_trb_words() -> TestResult {
    let phys: u64 = 0x1234_5678_9ABC_DEF0;
    let words = Xhci::isoch_trb_words(phys, 512, 0);
    let expected: [u32; 4] = [
        0x9ABC_DEF0,
        0x1234_5678,
        512,
        (5 << 10) | (1 << 5) | (1 << 31),
    ];
    if words != expected {
        return TestResult::Fail("Isoch TRB words mismatch at cycle 0");
    }
    let words = Xhci::isoch_trb_words(phys, 512, 1);
    let expected: [u32; 4] = [
        0x9ABC_DEF0,
        0x1234_5678,
        512,
        (5 << 10) | (1 << 5) | (1 << 31) | 1,
    ];
    if words != expected {
        return TestResult::Fail("Isoch TRB cycle bit not carried into d3");
    }
    // A full 4 KiB one-shot still leaves TD Size / Interrupter
    // Target clear in d2.
    let words = Xhci::isoch_trb_words(phys, 4096, 0);
    if words[2] != 4096 {
        return TestResult::Fail("Isoch TRB d2 carries bits above Transfer Length");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_isoch_trb_words);

/// DCI 0 and DCI 1 must fail before any `dci - 2` arithmetic: both
/// would otherwise alias DCI 2's endpoint slot. DCI 2..=31 map to
/// `eps` indices 0..=29 (xHCI §4.8.1; DCI 1 is the control endpoint,
/// which has no `eps` entry).
fn smoke_xhci_dci_ep_index() -> TestResult {
    for bad in [0u8, 1, 32, 255] {
        if dci_ep_index(bad) != Err(XhciError::CmdFailed(0xF9)) {
            return TestResult::Fail("out-of-range DCI was not rejected");
        }
    }
    if dci_ep_index(2) != Ok(0) || dci_ep_index(3) != Ok(1) || dci_ep_index(31) != Ok(29) {
        return TestResult::Fail("valid DCI mapped to the wrong endpoint index");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_dci_ep_index);

/// Pipeline depth (#2060): the xHCI isoch pool depth is the UVC
/// pump's `ISOC_DEPTH`, so the pipelined receive can actually
/// keep that many transfers in flight against hardware — the
/// pump clamps the advertised depth to the smaller of the two,
/// and a drift here would silently leave pump slots unused.
fn smoke_xhci_isoch_pipeline_depth_matches_uvc_scheduler() -> TestResult {
    if ISOCH_PIPELINE_DEPTH != narf_drivers_video::uvc::ISOC_DEPTH {
        return TestResult::Fail("xHCI isoch pool depth drifted from the UVC scheduler depth");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_pipeline_depth_matches_uvc_scheduler
);
