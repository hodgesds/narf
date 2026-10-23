// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 AI core identifiers. Live wrapper addresses come from EROM;
//! reset sequencing/readbacks/deadlines use brcmfmac::chip::Chip helpers.
//! Reference: Linux bcma.h and brcmfmac/chip.c (CM3 passive/active).

pub const CHIPCOMMON: u16 = 0x800;
pub const D11: u16 = 0x812;
pub const SOC_RAM: u16 = 0x80e;
pub const SDIO_DEVICE: u16 = 0x829;
pub const WLAN_ARM: u16 = 0x82a;
pub const SOC_RAM_BASE: u32 = 0;

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_cyw_cm3_and_sdio_cores_distinct() -> TestResult {
        if WLAN_ARM != 0x82a || SDIO_DEVICE != 0x829 || D11 != 0x812 || WLAN_ARM == SDIO_DEVICE {
            return TestResult::Fail("CM3 confused with SDIO or D11 core");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/core",
        smoke_cyw_cm3_and_sdio_cores_distinct
    );
}
