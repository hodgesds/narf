// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI 1.8 V signalling switch.
//!
//! The voltage-switch sequence (CMD11 + host control 2 + clock stop/
//! restart) is described in SD Physical Layer Simplified Spec §3.6.1.
//! For SDIO the 1.8 V switch is triggered by the S18R/S18A handshake
//! during CMD5 negotiation.
//!
//! Adapted from Linux `drivers/mmc/host/sdhci.c:sdhci_start_signal_voltage_switch()`
//! (GPL-2.0-or-later).

#![allow(dead_code)]

use super::regs::{
    CAPS_CAN_VDD_180, CAPS_CAN_VDD_330, CTRL2_VDD_180, POWER_180, POWER_330, POWER_ON,
};

/// Voltage selection understood by the host's power regulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalVoltage {
    /// 3.3 V nominal (default after power-on reset).
    V3_3,
    /// 1.8 V — required for UHS-I SDR50/SDR104/DDR50 modes.
    V1_8,
}

/// Result of a voltage-capability check against SDHCI capabilities register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoltageSupport {
    /// Both 3.3 V and 1.8 V are supported.
    Both,
    /// Only 3.3 V is supported.
    ThreeThreeOnly,
    /// Only 1.8 V is supported (unusual).
    OneEightOnly,
}

/// Inspect the capabilities register value and report voltage support.
#[inline]
pub fn caps_voltage_support(caps: u32) -> VoltageSupport {
    let has_180 = caps & CAPS_CAN_VDD_180 != 0;
    let has_330 = caps & CAPS_CAN_VDD_330 != 0;
    match (has_180, has_330) {
        (true, true) => VoltageSupport::Both,
        (false, true) => VoltageSupport::ThreeThreeOnly,
        (true, false) => VoltageSupport::OneEightOnly,
        (false, false) => VoltageSupport::ThreeThreeOnly, // assume 3.3 V if nothing set
    }
}

/// Build the POWER_CONTROL byte for a given voltage selection.
///
/// Returns `0` if voltage not supported (callers should gate on capabilities).
#[inline]
pub fn power_ctrl_byte(voltage: SignalVoltage) -> u8 {
    match voltage {
        SignalVoltage::V3_3 => POWER_ON | POWER_330,
        SignalVoltage::V1_8 => POWER_ON | POWER_180,
    }
}

/// Build the HOST_CONTROL2 mask to set/clear the VDD 1.8 V signalling bit.
///
/// Returns the bits to OR into HOST_CONTROL2 (for V1_8) or AND-NOT
/// (for V3_3).
#[inline]
pub fn host_ctrl2_vdd_mask(voltage: SignalVoltage) -> u16 {
    match voltage {
        SignalVoltage::V1_8 => CTRL2_VDD_180,
        SignalVoltage::V3_3 => 0,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_caps_voltage_support_both() -> TestResult {
        let caps = CAPS_CAN_VDD_330 | CAPS_CAN_VDD_180;
        if caps_voltage_support(caps) != VoltageSupport::Both {
            return TestResult::Fail("expected Both when both bits set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/sdhci/voltage",
        smoke_caps_voltage_support_both
    );

    fn smoke_caps_voltage_support_330_only() -> TestResult {
        let caps = CAPS_CAN_VDD_330; // no 1.8 V
        if caps_voltage_support(caps) != VoltageSupport::ThreeThreeOnly {
            return TestResult::Fail("expected ThreeThreeOnly");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/sdhci/voltage",
        smoke_caps_voltage_support_330_only
    );

    fn smoke_power_ctrl_byte_values() -> TestResult {
        let b33 = power_ctrl_byte(SignalVoltage::V3_3);
        let b18 = power_ctrl_byte(SignalVoltage::V1_8);
        if b33 != (POWER_ON | POWER_330) {
            return TestResult::Fail("3.3 V power-ctrl byte mismatch");
        }
        if b18 != (POWER_ON | POWER_180) {
            return TestResult::Fail("1.8 V power-ctrl byte mismatch");
        }
        // 1.8 V byte must differ from 3.3 V byte.
        if b18 == b33 {
            return TestResult::Fail("1.8 V and 3.3 V power bytes must differ");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/voltage", smoke_power_ctrl_byte_values);
}
