//! CYW43439 backplane core wrappers — reset / up sequencing.
//!
//! Each AXI-bridged backplane core (chip-common, WLAN-ARM, SOC-RAM)
//! owns a 4 KiB "wrapper" region whose `IOCTRL` and `RESETCTRL`
//! registers gate clock-routing and reset-deassertion respectively.
//! The host walks these wrappers through the F1 backplane window
//! (see [`super::backplane`]) to take the WLAN ARM core out of
//! reset after firmware staging.
//!
//! Reference: **CYW43439 datasheet Rev. 03 §6.5 ("Backplane access
//! through F1") Tables 6-8 and 6-9**.
//!
//! Cross-checked against `soypat/cyw43439` (MIT) and Embassy
//! `cyw43` (Apache-2.0 / MIT). **No GPL `brcmfmac` / `bcmdhd`
//! source consulted.**

use super::backplane::{CORE_OFFSET_IOCTRL, CORE_OFFSET_RESETCTRL};

/// Backplane addresses of the per-core wrapper regions on the
/// CYW43439 (datasheet §6.5).
pub mod wrapper {
    /// Chip-common core wrapper — top-level chip control.
    pub const CHIPCOMMON: u32 = 0x1800_0000;
    /// SOC-RAM core wrapper — owns the on-chip RAM the firmware
    /// loader writes into before deasserting WLAN-ARM reset.
    pub const SOC_RAM: u32 = 0x1810_4000;
    /// WLAN-ARM ("D11") core wrapper — runs the Wi-Fi MAC firmware.
    pub const WLAN_ARM: u32 = 0x1810_3000;
}

/// Backplane address of the SOC-RAM data region (where the firmware
/// blob is staged). Datasheet §6.6.
pub const SOC_RAM_BASE: u32 = 0x0000_0000;

// ── RESETCTRL bits (datasheet §6.5 Table 6-9) ─────────────────────

/// Bit 0: assert reset on the core.
pub const RESETCTRL_RESET: u32 = 0x1;

// ── IOCTRL bits (datasheet §6.5 Table 6-9) ────────────────────────

/// Bit 0: drive the core's clock-enable line.
pub const IOCTRL_CLOCK_EN: u32 = 0x1;
/// Bit 1: route the core to the FAST clock domain.
pub const IOCTRL_FGC: u32 = 0x2;
/// Bits the loader sets when bringing a core up: clock enable +
/// fast-glue clock.
pub const IOCTRL_BRINGUP_BITS: u32 = IOCTRL_CLOCK_EN | IOCTRL_FGC;

/// One write to a backplane wrapper register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperWrite {
    /// Backplane address (absolute) of the target register.
    pub address: u32,
    /// Value to write (32-bit).
    pub value: u32,
}

impl WrapperWrite {
    pub fn ioctrl(wrapper_base: u32, value: u32) -> Self {
        Self {
            address: wrapper_base + CORE_OFFSET_IOCTRL,
            value,
        }
    }

    pub fn resetctrl(wrapper_base: u32, value: u32) -> Self {
        Self {
            address: wrapper_base + CORE_OFFSET_RESETCTRL,
            value,
        }
    }
}

/// The four-step "bring core up" sequence per datasheet §6.5.
/// Returned in the order the host issues the writes.
pub fn bring_up_sequence(wrapper_base: u32) -> [WrapperWrite; 4] {
    [
        // 1. Clear RESETCTRL — deassert reset.
        WrapperWrite::resetctrl(wrapper_base, 0),
        // 2. Stamp IOCTRL with clock-enable + FGC.
        WrapperWrite::ioctrl(wrapper_base, IOCTRL_BRINGUP_BITS),
        // 3. Re-read IOCTRL would happen here in the real driver;
        //    represented as a settling write to keep the codec
        //    deterministic. Skipped — caller polls.
        WrapperWrite::ioctrl(wrapper_base, IOCTRL_BRINGUP_BITS),
        // 4. Final RESETCTRL clear once IOCTRL has stuck.
        WrapperWrite::resetctrl(wrapper_base, 0),
    ]
}

/// The two-step "park core in reset" sequence per datasheet §6.5.
pub fn reset_sequence(wrapper_base: u32) -> [WrapperWrite; 2] {
    [
        // 1. Stamp RESETCTRL with the assert bit.
        WrapperWrite::resetctrl(wrapper_base, RESETCTRL_RESET),
        // 2. Clear IOCTRL so no clocks reach the parked core.
        WrapperWrite::ioctrl(wrapper_base, 0),
    ]
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_wrapper_addresses_distinct() -> TestResult {
        // Sanity: the three wrapper regions must not alias.
        let bases = [wrapper::CHIPCOMMON, wrapper::WLAN_ARM, wrapper::SOC_RAM];
        for i in 0..bases.len() {
            for j in (i + 1)..bases.len() {
                if bases[i] == bases[j] {
                    return TestResult::Fail("wrapper bases alias");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/core",
        smoke_wrapper_addresses_distinct
    );

    fn smoke_bring_up_sequence_addresses() -> TestResult {
        let seq = bring_up_sequence(wrapper::WLAN_ARM);
        let expected_ioctrl = wrapper::WLAN_ARM + CORE_OFFSET_IOCTRL;
        let expected_resetctrl = wrapper::WLAN_ARM + CORE_OFFSET_RESETCTRL;
        // First and last writes hit RESETCTRL with 0.
        if seq[0].address != expected_resetctrl || seq[0].value != 0 {
            return TestResult::Fail("step 1 should clear RESETCTRL");
        }
        if seq[3].address != expected_resetctrl || seq[3].value != 0 {
            return TestResult::Fail("step 4 should clear RESETCTRL");
        }
        // Middle writes program IOCTRL with the bring-up bits.
        if seq[1].address != expected_ioctrl || seq[1].value != IOCTRL_BRINGUP_BITS {
            return TestResult::Fail("step 2 should write IOCTRL");
        }
        if seq[2].address != expected_ioctrl || seq[2].value != IOCTRL_BRINGUP_BITS {
            return TestResult::Fail("step 3 should re-write IOCTRL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/core",
        smoke_bring_up_sequence_addresses
    );

    fn smoke_reset_sequence() -> TestResult {
        let seq = reset_sequence(wrapper::SOC_RAM);
        if seq[0].value & RESETCTRL_RESET == 0 {
            return TestResult::Fail("reset step 1 should assert reset");
        }
        if seq[1].value != 0 {
            return TestResult::Fail("reset step 2 should clear IOCTRL");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/core", smoke_reset_sequence);
}
