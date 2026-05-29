// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI host controller state.
//!
//! `SdhciHost` wraps the host's MMIO base address and holds the
//! runtime state derived from the capabilities register and the
//! card-init sequence (RCA, OCR, bus-clock dividers).
//!
//! The clock-divider calculation follows the algorithm in Linux
//! `sdhci_calc_clk()` (GPL-2.0-or-later, adapted).

#![allow(dead_code)]

use crate::sdhci::regs::*;
use crate::sdhci::voltage::SignalVoltage;

/// SDHCI host state.
#[derive(Debug)]
pub struct SdhciHost {
    /// Physical base address of the SDHCI MMIO registers.
    pub mmio_base: u64,
    /// Host spec version (from HOST_VERSION[7:0]).
    pub spec_version: u8,
    /// Raw capabilities register value.
    pub caps: u32,
    /// Raw capabilities-1 register value.
    pub caps1: u32,
    /// Base clock frequency in Hz (extracted from CAPABILITIES).
    pub clock_base_hz: u32,
    /// Currently programmed SD clock frequency in Hz (0 = disabled).
    pub current_clock_hz: u32,
    /// Relative Card Address assigned by CMD3.
    pub rca: u16,
    /// Card OCR (from CMD5 R4 response).
    pub ocr: u32,
    /// Number of I/O functions the card reported.
    pub func_count: u8,
    /// Current signalling voltage.
    pub voltage: SignalVoltage,
    /// True once CMD7 has been issued and the card is in Transfer state.
    pub card_selected: bool,
}

impl SdhciHost {
    /// Construct a new host state from the MMIO base address, capabilities
    /// registers (read at probe time), and the spec version byte.
    pub fn new(mmio_base: u64, spec_version: u8, caps: u32, caps1: u32) -> Self {
        let clock_base_hz = Self::extract_clock_base(spec_version, caps);
        Self {
            mmio_base,
            spec_version,
            caps,
            caps1,
            clock_base_hz,
            current_clock_hz: 0,
            rca: 0,
            ocr: 0,
            func_count: 0,
            voltage: SignalVoltage::V3_3,
            card_selected: false,
        }
    }

    /// Extract the base clock frequency from CAPABILITIES.
    ///
    /// Spec 1.x / 2.0: bits [13:8] × 1 MHz.
    /// Spec 3.00+: bits [15:8] × 1 MHz.
    pub fn extract_clock_base(spec_version: u8, caps: u32) -> u32 {
        let mhz = if spec_version >= SPEC_300 as u8 {
            (caps & CAPS_CLOCK_V3_BASE_MASK) >> CAPS_CLOCK_BASE_SHIFT
        } else {
            (caps & CAPS_CLOCK_BASE_MASK) >> CAPS_CLOCK_BASE_SHIFT
        };
        mhz * 1_000_000
    }

    /// Calculate the clock-control register value to achieve
    /// approximately `target_hz` on a spec-2.00 host (10-bit divider
    /// split as d[9:8] in bits [7:6], d[7:0] in bits [15:8]).
    ///
    /// Returns the 16-bit CLOCK_CONTROL word (without INT_EN / CARD_EN
    /// bits, those are set after stability check).
    ///
    /// Derived from Linux `sdhci_calc_clk()` (GPL-2.0-or-later).
    pub fn calc_clk_div(&self, target_hz: u32) -> u16 {
        if self.clock_base_hz == 0 || target_hz == 0 {
            return 0;
        }
        // Find the smallest power-of-two (spec 2.00) or step-of-two
        // (spec 3.00) divisor that brings the clock ≤ target.
        // For simplicity, use the spec-2.00 path (power-of-two, ≤256):
        let mut div: u32 = 1;
        let max_div = if self.spec_version >= SPEC_300 as u8 {
            MAX_DIV_SPEC_300 as u32
        } else {
            MAX_DIV_SPEC_200 as u32
        };

        while self.clock_base_hz / div > target_hz {
            div <<= 1;
            if div > max_div {
                div = max_div;
                break;
            }
        }

        // Encode divisor into 10-bit field (spec 3.00 split encoding).
        // Low 8 bits → CLOCK_CONTROL[15:8].
        // High 2 bits → CLOCK_CONTROL[7:6].
        let d = (div >> 1) as u16; // "divide by 2*d" encoding
        let lo8 = (d & 0xFF) << 8;
        let hi2 = ((d >> 8) & 0x03) << 6;
        lo8 | hi2
    }

    /// Returns true if the host supports 1.8 V signalling.
    pub fn can_do_1_8v(&self) -> bool {
        self.caps & CAPS_CAN_VDD_180 != 0
    }

    /// Returns true if the host supports High-Speed mode.
    pub fn can_do_hispeed(&self) -> bool {
        self.caps & CAPS_CAN_DO_HISPD != 0
    }

    /// Returns the maximum block size exponent (512 << shift).
    pub fn max_block_size_shift(&self) -> u32 {
        (self.caps & CAPS_MAX_BLOCK_MASK) >> CAPS_MAX_BLOCK_SHIFT
    }

    /// Returns the maximum block size in bytes.
    pub fn max_block_size(&self) -> u32 {
        512 << self.max_block_size_shift()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Build a realistic CAPABILITIES value: base clock = 50 MHz,
    /// max block = 512 B, can-hispd, can-VDD-330, can-VDD-180.
    fn test_caps() -> (u32, u32) {
        let caps = (50u32 << CAPS_CLOCK_BASE_SHIFT)  // 50 MHz
            | CAPS_CAN_DO_HISPD
            | CAPS_CAN_VDD_330
            | CAPS_CAN_VDD_180
            | (0u32 << CAPS_MAX_BLOCK_SHIFT); // 512 B blocks
        (caps, 0)
    }

    fn smoke_host_clock_base_extraction() -> TestResult {
        let (caps, caps1) = test_caps();
        let host = SdhciHost::new(0xFE00_0000, SPEC_300 as u8, caps, caps1);
        // 50 MHz should extract correctly.
        if host.clock_base_hz != 50_000_000 {
            return TestResult::Fail("clock base extraction wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/host", smoke_host_clock_base_extraction);

    fn smoke_host_calc_clk_400khz() -> TestResult {
        let (caps, caps1) = test_caps();
        let host = SdhciHost::new(0, SPEC_300 as u8, caps, caps1);
        // At 50 MHz base, 400 kHz init clock needs divisor ≥ 125.
        // Nearest power-of-two ≥ 128 → actual = 50 MHz / 128 ≈ 390 kHz ≤ 400 kHz.
        let word = host.calc_clk_div(400_000);
        // The word is non-zero.
        if word == 0 {
            return TestResult::Fail("clock divider word is zero for 400 kHz");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/host", smoke_host_calc_clk_400khz);

    fn smoke_host_caps_flags() -> TestResult {
        let (caps, caps1) = test_caps();
        let host = SdhciHost::new(0, SPEC_300 as u8, caps, caps1);
        if !host.can_do_hispeed() {
            return TestResult::Fail("hispeed should be supported");
        }
        if !host.can_do_1_8v() {
            return TestResult::Fail("1.8 V should be supported");
        }
        if host.max_block_size() != 512 {
            return TestResult::Fail("max block size should be 512");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/host", smoke_host_caps_flags);
}
