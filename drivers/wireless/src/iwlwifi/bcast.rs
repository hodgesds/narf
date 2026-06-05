//! iwlwifi BCAST_FILTER_CMD (host cmd 0xCD).
//!
//! After the FW ALIVE handshake the host needs to flush the
//! broadcast-frame filter cache so the firmware starts forwarding
//! beacons and probe-responses to host. Linux dispatches an empty
//! filter list — meaning "no extra filtering, deliver all broadcast".
//!
//! ## Reference (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/fw/api/filter.h` —
//!   `iwl_bcast_filter_cmd` layout.
//! - `drivers/net/wireless/intel/iwlwifi/mvm/rx.c::iwl_mvm_send_bcast_filter`
//!   — host-side dispatch + empty-list "flush" usage.
//!
//! Layout (v1):
//! ```text
//!   u8  disable             — 0 = enabled, 1 = bypass all
//!   u8  max_bcast_filters   — N filter records that follow
//!   u8  max_macs            — N MAC contexts to apply to
//!   u8  reserved
//!   [iwl_bcast_filter ; max_bcast_filters]
//!   [iwl_bcast_mac    ; max_macs]
//! ```
//!
//! For the flush case both arrays are empty, so the wire image is
//! 4 bytes: `[0, 0, 0, 0]`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

/// Host command id for BCAST_FILTER_CMD. From `fw/api/commands.h`.
pub const BCAST_FILTER_CMD: u8 = 0xCD;
/// Command group — legacy / default group 0.
pub const BCAST_FILTER_GROUP: u8 = 0x00;

/// Build the empty flush body: tells the firmware to drop any cached
/// filter and resume default forwarding to host.
pub fn build_flush_cmd() -> Vec<u8> {
    alloc::vec![0u8, 0u8, 0u8, 0u8]
}

/// Build a body that disables broadcast filtering entirely (`disable=1`).
/// Useful while bringing up scan: the host wants to see every beacon
/// regardless of any historical cached filter.
pub fn build_disable_cmd() -> Vec<u8> {
    alloc::vec![1u8, 0u8, 0u8, 0u8]
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_iwlwifi_bcast_flush_is_four_zero_bytes() -> TestResult {
        let body = build_flush_cmd();
        if body.len() != 4 {
            return TestResult::Fail("flush cmd should be 4 bytes");
        }
        if body != alloc::vec![0u8, 0u8, 0u8, 0u8] {
            return TestResult::Fail("flush cmd should be all-zero");
        }
        TestResult::Pass
    }

    fn smoke_iwlwifi_bcast_disable_sets_first_byte() -> TestResult {
        let body = build_disable_cmd();
        if body.len() != 4 {
            return TestResult::Fail("disable cmd should be 4 bytes");
        }
        if body[0] != 1 {
            return TestResult::Fail("disable cmd must set byte 0 = 1");
        }
        if body[1] != 0 || body[2] != 0 || body[3] != 0 {
            return TestResult::Fail("disable cmd tail must be zero");
        }
        TestResult::Pass
    }

    fn smoke_iwlwifi_bcast_cmd_id_values() -> TestResult {
        if BCAST_FILTER_CMD != 0xCD {
            return TestResult::Fail("BCAST_FILTER_CMD should be 0xCD");
        }
        if BCAST_FILTER_GROUP != 0 {
            return TestResult::Fail("group should be 0");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/bcast",
        smoke_iwlwifi_bcast_flush_is_four_zero_bytes
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/bcast",
        smoke_iwlwifi_bcast_disable_sets_first_byte
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/bcast",
        smoke_iwlwifi_bcast_cmd_id_values
    );
}
