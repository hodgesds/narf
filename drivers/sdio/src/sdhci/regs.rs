// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI MMIO register offsets and bit-field constants.
//!
//! Source: SD Host Controller Simplified Specification v4.20
//! (SD Association, public) — register map §2.
//!
//! Adapted from Linux `drivers/mmc/host/sdhci.h` (GPL-2.0-or-later).

#![allow(dead_code)]

// ── DMA / block setup (0x00–0x0F) ────────────────────────────────────
pub const DMA_ADDRESS: u32 = 0x00; // SDMA system-address
pub const ARGUMENT2: u32 = 0x00; // ADMA3 / 32-bit block count
pub const BLOCK_SIZE: u32 = 0x04;
pub const BLOCK_COUNT: u32 = 0x06;
pub const ARGUMENT: u32 = 0x08;
pub const TRANSFER_MODE: u32 = 0x0C;
pub const COMMAND: u32 = 0x0E;

// Transfer-mode bits
pub const TRNS_DMA: u16 = 0x0001;
pub const TRNS_BLK_CNT_EN: u16 = 0x0002;
pub const TRNS_AUTO_CMD12: u16 = 0x0004;
pub const TRNS_AUTO_CMD23: u16 = 0x0008;
pub const TRNS_READ: u16 = 0x0010;
pub const TRNS_MULTI: u16 = 0x0020;

// Command register bits
pub const CMD_RESP_MASK: u16 = 0x0003;
pub const CMD_CRC: u16 = 0x0008;
pub const CMD_INDEX: u16 = 0x0010;
pub const CMD_DATA: u16 = 0x0020;
pub const CMD_ABORTCMD: u16 = 0x00C0;
pub const CMD_RESP_NONE: u16 = 0x0000;
pub const CMD_RESP_LONG: u16 = 0x0001;
pub const CMD_RESP_SHORT: u16 = 0x0002;
pub const CMD_RESP_SHORT_BUSY: u16 = 0x0003;

/// Encode command index + flags into the 16-bit COMMAND register value.
#[inline]
pub const fn make_cmd(cmd_idx: u8, flags: u16) -> u16 {
    ((cmd_idx as u16) << 8) | (flags & 0xFF)
}

// ── Response / data (0x10–0x23) ───────────────────────────────────────
pub const RESPONSE: u32 = 0x10; // 4×u32: [0x10, 0x14, 0x18, 0x1C]
pub const BUFFER: u32 = 0x20;

// ── Present state (0x24) ──────────────────────────────────────────────
pub const PRESENT_STATE: u32 = 0x24;
pub const PS_CMD_INHIBIT: u32 = 0x0000_0001;
pub const PS_DATA_INHIBIT: u32 = 0x0000_0002;
pub const PS_DOING_WRITE: u32 = 0x0000_0100;
pub const PS_DOING_READ: u32 = 0x0000_0200;
pub const PS_SPACE_AVAIL: u32 = 0x0000_0400;
pub const PS_DATA_AVAIL: u32 = 0x0000_0800;
pub const PS_CARD_PRESENT: u32 = 0x0001_0000;
pub const PS_CD_STABLE: u32 = 0x0002_0000;
pub const PS_WRITE_PROTECT: u32 = 0x0008_0000;

// ── Host control (0x28–0x2B) ──────────────────────────────────────────
pub const HOST_CONTROL: u32 = 0x28;
pub const CTRL_LED: u8 = 0x01;
pub const CTRL_4BITBUS: u8 = 0x02;
pub const CTRL_HISPD: u8 = 0x04;
pub const CTRL_DMA_MASK: u8 = 0x18;
pub const CTRL_SDMA: u8 = 0x00;
pub const CTRL_ADMA32: u8 = 0x10;
pub const CTRL_ADMA64: u8 = 0x18;

// ── Power control (0x29) ──────────────────────────────────────────────
pub const POWER_CONTROL: u32 = 0x29;
pub const POWER_ON: u8 = 0x01;
pub const POWER_180: u8 = 0x0A; // 1.8 V
pub const POWER_300: u8 = 0x0C; // 3.0 V
pub const POWER_330: u8 = 0x0E; // 3.3 V

// ── Clock control (0x2C–0x2D) ─────────────────────────────────────────
pub const CLOCK_CONTROL: u32 = 0x2C;
pub const CLK_INT_EN: u16 = 0x0001; // internal clock enable
pub const CLK_INT_STABLE: u16 = 0x0002; // internal clock stable
pub const CLK_CARD_EN: u16 = 0x0004; // SD clock enable
pub const CLK_PLL_EN: u16 = 0x0008;
pub const CLK_PROG_MODE: u16 = 0x0020; // programmable clock mode
pub const CLK_DIVIDER_SHIFT: u32 = 8; // bits [15:8] (spec ≤2.00) / [7:6] hi bits
pub const CLK_DIVIDER_MASK: u16 = 0xFF00;

// ── Timeout / SW reset (0x2E–0x2F) ────────────────────────────────────
pub const TIMEOUT_CONTROL: u32 = 0x2E;
pub const SOFTWARE_RESET: u32 = 0x2F;
pub const RESET_ALL: u8 = 0x01;
pub const RESET_CMD: u8 = 0x02;
pub const RESET_DATA: u8 = 0x04;

// ── Interrupt status / enable / signal (0x30–0x38) ────────────────────
pub const INT_STATUS: u32 = 0x30;
pub const INT_ENABLE: u32 = 0x34;
pub const SIGNAL_ENABLE: u32 = 0x38;

pub const INT_RESPONSE: u32 = 0x0000_0001;
pub const INT_DATA_END: u32 = 0x0000_0002;
pub const INT_BLK_GAP: u32 = 0x0000_0004;
pub const INT_DMA_END: u32 = 0x0000_0008;
pub const INT_SPACE_AVAIL: u32 = 0x0000_0010;
pub const INT_DATA_AVAIL: u32 = 0x0000_0020;
pub const INT_CARD_INSERT: u32 = 0x0000_0040;
pub const INT_CARD_REMOVE: u32 = 0x0000_0080;
pub const INT_CARD_INT: u32 = 0x0000_0100;
pub const INT_RETUNE: u32 = 0x0000_1000;
pub const INT_ERROR: u32 = 0x0000_8000;
pub const INT_TIMEOUT: u32 = 0x0001_0000;
pub const INT_CRC: u32 = 0x0002_0000;
pub const INT_END_BIT: u32 = 0x0004_0000;
pub const INT_INDEX: u32 = 0x0008_0000;
pub const INT_DATA_TIMEOUT: u32 = 0x0010_0000;
pub const INT_DATA_CRC: u32 = 0x0020_0000;
pub const INT_DATA_END_BIT: u32 = 0x0040_0000;
pub const INT_BUS_POWER: u32 = 0x0080_0000;
pub const INT_AUTO_CMD_ERR: u32 = 0x0100_0000;
pub const INT_ADMA_ERROR: u32 = 0x0200_0000;

/// Normal-interrupt enable mask (cmd + data + card-interrupt).
pub const INT_CMD_MASK: u32 = INT_RESPONSE | INT_TIMEOUT | INT_CRC | INT_END_BIT | INT_INDEX;
pub const INT_DATA_MASK: u32 = INT_DATA_END
    | INT_DMA_END
    | INT_DATA_AVAIL
    | INT_SPACE_AVAIL
    | INT_DATA_TIMEOUT
    | INT_DATA_CRC
    | INT_DATA_END_BIT
    | INT_ADMA_ERROR;
pub const INT_ALL_MASK: u32 = 0xFFFF_FFFF;

// ── Host Control 2 (0x3E) ──────────────────────────────────────────────
pub const HOST_CONTROL2: u32 = 0x3E;
pub const CTRL2_UHS_MASK: u16 = 0x0007;
pub const CTRL2_UHS_SDR12: u16 = 0x0000;
pub const CTRL2_UHS_SDR25: u16 = 0x0001;
pub const CTRL2_UHS_SDR50: u16 = 0x0002;
pub const CTRL2_UHS_SDR104: u16 = 0x0003;
pub const CTRL2_UHS_DDR50: u16 = 0x0004;
pub const CTRL2_VDD_180: u16 = 0x0008; // 1.8 V signalling
pub const CTRL2_EXEC_TUNING: u16 = 0x0040;
pub const CTRL2_TUNED_CLK: u16 = 0x0080;

// ── Capabilities (0x40–0x47) ───────────────────────────────────────────
pub const CAPABILITIES: u32 = 0x40;
pub const CAPS_TIMEOUT_CLK_MASK: u32 = 0x0000_003F;
pub const CAPS_CLOCK_BASE_MASK: u32 = 0x0000_3F00;
pub const CAPS_CLOCK_BASE_SHIFT: u32 = 8;
pub const CAPS_CLOCK_V3_BASE_MASK: u32 = 0x0000_FF00;
pub const CAPS_MAX_BLOCK_MASK: u32 = 0x0003_0000;
pub const CAPS_MAX_BLOCK_SHIFT: u32 = 16;
pub const CAPS_CAN_DO_HISPD: u32 = 0x0020_0000;
pub const CAPS_CAN_DO_SDMA: u32 = 0x0040_0000;
pub const CAPS_CAN_VDD_330: u32 = 0x0100_0000;
pub const CAPS_CAN_VDD_300: u32 = 0x0200_0000;
pub const CAPS_CAN_VDD_180: u32 = 0x0400_0000;

pub const CAPABILITIES_1: u32 = 0x44;
pub const CAPS1_SUPPORT_SDR50: u32 = 0x0000_0001;
pub const CAPS1_SUPPORT_SDR104: u32 = 0x0000_0002;
pub const CAPS1_SUPPORT_DDR50: u32 = 0x0000_0004;

// ── Host version (0xFE–0xFF) ───────────────────────────────────────────
pub const HOST_VERSION: u32 = 0xFE;
pub const SPEC_VER_MASK: u16 = 0x00FF;
pub const SPEC_100: u16 = 0;
pub const SPEC_200: u16 = 1;
pub const SPEC_300: u16 = 2;
pub const SPEC_400: u16 = 3;

/// Maximum divisor for spec ≤ 2.00 (256) and spec 3.00+ (2046).
pub const MAX_DIV_SPEC_200: u16 = 256;
pub const MAX_DIV_SPEC_300: u16 = 2046;

// ── PCI SDHCI identification ───────────────────────────────────────────
/// PCI class code for SDHCI: base 0x08 (generic), sub 0x05 (SD host), iface 0x00.
pub const PCI_CLASS_SDHCI: u32 = 0x0805_00;
pub const PCI_SDHCI_BAR: u8 = 0; // BAR0 by SDHCI spec

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sdhci_reg_decode_key_offsets() -> TestResult {
        // Spot-check the six most-critical offsets against the SDHCI spec table.
        let pairs: &[(u32, u32)] = &[
            (PRESENT_STATE, 0x24),
            (HOST_CONTROL, 0x28),
            (POWER_CONTROL, 0x29),
            (CLOCK_CONTROL, 0x2C),
            (SOFTWARE_RESET, 0x2F),
            (INT_STATUS, 0x30),
            (INT_ENABLE, 0x34),
            (SIGNAL_ENABLE, 0x38),
            (CAPABILITIES, 0x40),
            (HOST_VERSION, 0xFE),
        ];
        for &(got, want) in pairs {
            if got != want {
                return TestResult::Fail("sdhci register offset mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/sdhci/regs",
        smoke_sdhci_reg_decode_key_offsets
    );

    fn smoke_make_cmd_encoding() -> TestResult {
        // CMD52 index=52 (0x34) with short response + CRC + INDEX bits.
        let flags = CMD_RESP_SHORT | CMD_CRC | CMD_INDEX;
        let word = make_cmd(52, flags);
        if (word >> 8) & 0x3F != 52 {
            return TestResult::Fail("cmd index not in bits [13:8]");
        }
        if word & CMD_RESP_SHORT == 0 {
            return TestResult::Fail("resp-short bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/regs", smoke_make_cmd_encoding);

    fn smoke_int_mask_no_overlap() -> TestResult {
        // CMD mask and DATA mask must not share bits (distinct IRQ sources).
        if INT_CMD_MASK & INT_DATA_MASK != 0 {
            return TestResult::Fail("cmd and data interrupt masks overlap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/regs", smoke_int_mask_no_overlap);
}
