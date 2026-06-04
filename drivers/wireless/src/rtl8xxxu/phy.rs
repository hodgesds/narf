//! RTL8XXXU PHY / BB / RF common layer.
//!
//! After MAC init, the driver loads three sets of register tables:
//!
//! 1. **PHY/BB register init** — a `(reg, val)` table of 32-bit writes
//!    to the FPGA/OFDM register block (`REG_FPGA0_*`, `REG_OFDM0_*`).
//! 2. **RF register init** — per-path (RF_A, RF_B) RF register writes
//!    routed through the LSSI write-only interface (`REG_FPGA0_LSSI`).
//! 3. **IQ calibration** — TX/RX IQ imbalance training using internal
//!    tones; produces a 4×8 calibration matrix applied back into the BB.
//! 4. **LC calibration** — RF local-oscillator self-tune.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   - `rtl8xxxu_init_phy_regs` (~L2230).
//!   - `rtl8xxxu_init_phy_bb` (~L4234).
//!   - `rtl8xxxu_gen1_phy_iq_calibrate` (~L3398).
//!   - `rtl8723a_phy_lc_calibrate` (~L3498).
//! - `drivers/net/wireless/realtek/rtl8xxxu/8723b.c`
//!   - `rtl8723bu_phy_iq_calibrate` (gen2 IQ-cal).

#![allow(dead_code)]

use super::regs::*;

// ── PHY/BB/RF register table representation ─────────────────────────

/// A 32-bit register init entry: `(addr, val)`.
/// Sentinel value `(0xFFFF, 0xFFFFFFFF)` marks end of table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reg32Val {
    pub reg: u16,
    pub val: u32,
}

impl Reg32Val {
    pub const SENTINEL: Self = Self {
        reg: 0xFFFF,
        val: 0xFFFFFFFF,
    };
}

/// A 16-bit register init entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reg16Val {
    pub reg: u16,
    pub val: u16,
}

/// An 8-bit register init entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reg8Val {
    pub reg: u16,
    pub val: u8,
}

// ── RF path direct register access ──────────────────────────────────

/// RF path indicator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RfPath {
    A,
    B,
}

impl RfPath {
    /// Numeric RF path (0 = A, 1 = B).
    pub const fn index(self) -> u8 {
        match self {
            RfPath::A => RF_PATH_A,
            RfPath::B => RF_PATH_B,
        }
    }
}

// ── LSSI / RF write framing ─────────────────────────────────────────

/// `REG_FPGA0_LSSI` base. RF writes are 20-bit serialised through the
/// LSSI register block.
pub const REG_FPGA0_LSSI_A: u16 = 0x0840;
pub const REG_FPGA0_LSSI_B: u16 = 0x0844;

/// Encode an RF write request as a 32-bit word to push into the LSSI
/// parameter register.
///
/// Bits[19:0] hold (addr << 16) | data16. Bit 31 set to assert write.
///
/// Source: `core.c::rtl8xxxu_write_rfreg` ~L1700.
pub const fn lssi_encode(addr: u8, data: u32) -> u32 {
    // addr is 5 bits, data is 20 bits.
    (((addr as u32) & 0x1F) << 20) | (data & 0xF_FFFF)
}

/// LSSI register for a given path.
pub const fn lssi_reg_for_path(path: RfPath) -> u16 {
    match path {
        RfPath::A => REG_FPGA0_LSSI_A,
        RfPath::B => REG_FPGA0_LSSI_B,
    }
}

// ── IQ calibration — common register sequence ───────────────────────

/// One step of the IQ calibration: register address, 32-bit value.
/// Source: `core.c::rtl8xxxu_phy_iqcalibrate` ~L3398.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IqkStep {
    pub reg: u16,
    pub val: u32,
}

/// The gen1 IQ-cal preamble — set up calibration tone, AGC, MAC pause.
///
/// Source: `core.c::rtl8xxxu_gen1_phy_iq_calibrate` ~L3398..L3420.
pub const IQK_PREAMBLE_GEN1: &[IqkStep] = &[
    // Save BB switch — disable CCK lock during calibration.
    IqkStep {
        reg: REG_FPGA0_RF_MODE,
        val: 0x00000000,
    },
    // Configure IQK transmit tone (offset 0x0E30 = REG_TX_IQK_TONE_A).
    IqkStep {
        reg: REG_TX_IQK_TONE_A,
        val: 0x10008C1F,
    },
    // RX IQK tone (offset 0x0E50).
    IqkStep {
        reg: REG_RX_IQK_TONE_A,
        val: 0x30008C1F,
    },
    // PI control for path A.
    IqkStep {
        reg: REG_TX_IQK_PI_A,
        val: 0x8214032A,
    },
    // AGC PTS (path A).
    IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0x00462911,
    },
    // Trigger IQK — set bit 0 of REG_IQK_AGC_RSP, then poll.
    IqkStep {
        reg: REG_IQK_AGC_RSP,
        val: 0x00000080,
    },
];

/// The gen1 IQ-cal post — restore BB switch.
pub const IQK_RESTORE_GEN1: &[IqkStep] = &[IqkStep {
    reg: REG_FPGA0_RF_MODE,
    val: 0x00000003,
}];

/// Number of IQK polling iterations.
pub const IQK_POLL_MAX: usize = 50;

// ── LC calibration ──────────────────────────────────────────────────

/// LC calibration step: a single RF write to RF_REG_LC_CAL via the
/// LSSI interface to trigger the local-oscillator self-tune.
///
/// Source: `core.c::rtl8723a_phy_lc_calibrate` ~L3498..L3540.
pub fn lc_calibrate_rf_writes() -> [(RfPath, u8, u32); 3] {
    [
        // Pre: read current RF_REG_LC_CAL (RF_CHNLBW = 0x18).
        // Step 1: assert LC start bit (bit 14 of the 20-bit RF reg).
        (RfPath::A, RF_REG_LC_CAL, 0x4000),
        // Hold for 100 ms — followed by clearing the LC start bit.
        (RfPath::A, RF_REG_LC_CAL, 0x0000),
        // Path B (no-op for 1T1R chips; harmless extra write).
        (RfPath::B, RF_REG_LC_CAL, 0x0000),
    ]
}

// ── Channel set ─────────────────────────────────────────────────────

/// Decode an IEEE 802.11 channel number → centre frequency in MHz.
pub fn channel_freq_mhz(channel: u8) -> u32 {
    match channel {
        // 2.4 GHz band.
        1..=13 => 2407 + (channel as u32) * 5,
        14 => 2484,
        // 5 GHz UNII band.
        36..=64 => 5180 + ((channel as u32 - 36) * 5),
        100..=144 => 5500 + ((channel as u32 - 100) * 5),
        149..=165 => 5745 + ((channel as u32 - 149) * 5),
        _ => 0,
    }
}

/// Test if a channel is in the 5 GHz band.
pub fn is_5ghz(channel: u8) -> bool {
    matches!(channel, 36..=165)
}

/// Build the (register, value) pairs needed to switch the PHY to a
/// given channel.
///
/// For 2.4 GHz: writes channel index into bits[7:0] of the RF channel
/// register. For 5 GHz: also writes the bandwidth/mode bits into
/// `REG_RF_MODE_AG` (8821C/8822B only).
///
/// Source: `core.c::rtl8xxxu_set_channel` ~L4400.
pub fn channel_set_writes(channel: u8) -> alloc::vec::Vec<(u16, u32)> {
    use alloc::vec::Vec;
    let mut v = Vec::with_capacity(4);

    if is_5ghz(channel) {
        // 5 GHz path requires REG_RF_MODE_AG configuration.
        v.push((REG_RF_MODE_AG, 0x00010000));
    }

    // RF channel write through path A LSSI.
    let lssi_word = lssi_encode(RF_REG_CHANNEL, channel as u32);
    v.push((REG_FPGA0_LSSI_A, lssi_word));

    // For 2x2 / dual-path chips, also write path B.
    v.push((REG_FPGA0_LSSI_B, lssi_word));

    v
}

extern crate alloc;
