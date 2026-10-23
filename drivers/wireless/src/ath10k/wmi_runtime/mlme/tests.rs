use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn smoke_ath10k_peer_assoc_vdev_up_match_complete_native_linux_generators() -> TestResult {
    for (dialect, open, secure, vdev_up) in [
        (Dialect::Main, OPEN_MAIN, SEC_MAIN, UP_MAIN),
        (Dialect::TenOne, OPEN_10X, SEC_10X, UP_10X),
        (Dialect::TenTwo, OPEN_102, SEC_102, UP_102),
        (Dialect::TenTwoFour, OPEN_102, SEC_102, UP_102),
        (Dialect::TenFour, OPEN_104, SEC_104, UP_104),
        (Dialect::Tlv, OPEN_TLV, SEC_TLV, UP_TLV),
    ] {
        let bssid = [2, 8, 9, 10, 11, 12];
        for (protected, capability, expected) in [(false, 0x421, open), (true, 0x431, secure)] {
            if peer(dialect, bssid, 7, capability, 0xfff, protected).as_deref() != Ok(expected) {
                return TestResult::Fail("complete PEER_ASSOC body differs from native Linux C");
            }
        }
        if up(dialect, bssid, 7).as_deref() != Ok(vdev_up) {
            return TestResult::Fail("VDEV_UP body differs from native Linux C");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_peer_assoc_vdev_up_match_complete_native_linux_generators
);

fn smoke_ath10k_legacy_b_and_single_ofdm_peer_rates_match_linux_padding() -> TestResult {
    for (dialect, b, ofdm) in [
        (Dialect::Main, B_MAIN, OFDM_MAIN),
        (Dialect::TenOne, B_10X, OFDM_10X),
        (Dialect::TenTwo, B_102, OFDM_102),
        (Dialect::TenTwoFour, B_102, OFDM_102),
        (Dialect::TenFour, B_104, OFDM_104),
        (Dialect::Tlv, B_TLV, OFDM_TLV),
    ] {
        for (rates, expected) in [(1, b), (16, ofdm)] {
            if peer(dialect, [2, 8, 9, 10, 11, 12], 7, 0x421, rates, false).as_deref()
                != Ok(expected)
            {
                return TestResult::Fail(
                    "single-rate phymode, TLV padding or native body differs from Linux",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_legacy_b_and_single_ofdm_peer_rates_match_linux_padding
);
