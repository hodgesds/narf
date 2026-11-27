//! Retirement smokes for the mt76 copy-mode family host (removed).
//!
//! The loadable frontend runs MCU/WFDMA in-module over the generic `WIFI`
//! family host (v2, `wireless/src/module_host.rs`); the private `mt76` v1
//! host (`module_host.rs` / `module_protocol.rs`) is gone. These smokes
//! pin the registry side of that removal: opening the retired family must
//! fail before any device-authority check, while the generic host answers.
use narf_bus::module_wireless;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The retired private family: no host answers it, so `open` fails `-95`
/// (unknown family) before any device-authority check.
fn smoke_mt76_copy_mode_family_unregistered() -> TestResult {
    if module_wireless::open(0, 0, 0x6d74_3736, 1) != Err(-95) {
        return TestResult::Fail("retired mt76 copy-mode family still answers open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/module",
    smoke_mt76_copy_mode_family_unregistered
);

/// The generic `WIFI` v2 host IS registered: `open` passes the family
/// lookup and fails only at device authority (`-19`) for the bogus
/// owner/token, proving the family — not the device — is what was found.
fn smoke_mt76_wifi_v2_family_registered() -> TestResult {
    if module_wireless::open(
        0,
        0,
        narf_wireless::module_host::FAMILY_WIFI,
        narf_wireless::module_host::VERSION,
    ) != Err(-19)
    {
        return TestResult::Fail("generic WIFI v2 family host is not registered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/module",
    smoke_mt76_wifi_v2_family_registered
);
