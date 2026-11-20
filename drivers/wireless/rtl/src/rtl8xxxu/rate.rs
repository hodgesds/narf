//! RTL8XXXU rate control and MCS index encoding.
//!
//! The TX descriptor's DW4 "data rate" field is an 8-bit index into a
//! chip-wide rate table. The Linux driver uses these names:
//!
//! | Index   | Modulation                  |
//! |---------|-----------------------------|
//! | 0       | DSSS 1M                     |
//! | 1       | DSSS 2M                     |
//! | 2       | DSSS 5.5M                   |
//! | 3       | DSSS 11M                    |
//! | 4       | OFDM 6M                     |
//! | 5       | OFDM 9M                     |
//! | 6       | OFDM 12M                    |
//! | 7       | OFDM 18M                    |
//! | 8       | OFDM 24M                    |
//! | 9       | OFDM 36M                    |
//! | 10      | OFDM 48M                    |
//! | 11      | OFDM 54M                    |
//! | 12..19  | HT MCS0..MCS7               |
//! | 20..27  | HT MCS8..MCS15 (path B)     |
//! | 28..43  | VHT MCS0..MCS9 1SS/2SS      |
//!
//! Source: `rtl8xxxu.h::DESC_RATE_*` enum near L470.
//!
//! ## Basic-rate fallback
//!
//! When the AP's basic-rate set excludes the chosen MCS, the driver
//! falls back to a lower OFDM rate. The chip can do this autonomously
//! once `TXDESC32_USE_DRIVER_RATE` is cleared. This module produces the
//! descriptor bits and the rate-table index.

#![allow(dead_code)]

/// The 8-bit rate index used in the TX descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RateIdx(pub u8);

impl RateIdx {
    pub const DSSS_1M: Self = Self(0);
    pub const DSSS_2M: Self = Self(1);
    pub const DSSS_5_5M: Self = Self(2);
    pub const DSSS_11M: Self = Self(3);
    pub const OFDM_6M: Self = Self(4);
    pub const OFDM_9M: Self = Self(5);
    pub const OFDM_12M: Self = Self(6);
    pub const OFDM_18M: Self = Self(7);
    pub const OFDM_24M: Self = Self(8);
    pub const OFDM_36M: Self = Self(9);
    pub const OFDM_48M: Self = Self(10);
    pub const OFDM_54M: Self = Self(11);

    /// HT MCS index (path A, 0..7). Returns rate-table index 12..19.
    pub const fn ht_mcs(mcs: u8) -> Self {
        Self(12 + (mcs & 0x07))
    }

    /// HT MCS index path B (8..15). Returns rate-table index 20..27.
    pub const fn ht_mcs_path_b(mcs: u8) -> Self {
        Self(20 + (mcs & 0x07))
    }

    /// VHT MCS for a given spatial stream count + MCS index.
    /// `nss` 1..2, `mcs` 0..9. Returns 28 + (nss-1)*10 + mcs.
    pub const fn vht_mcs(nss: u8, mcs: u8) -> Self {
        let nss_clamp = if nss == 0 { 1 } else { nss };
        Self(28 + (nss_clamp - 1) * 10 + (mcs & 0x0F))
    }

    /// `true` if this is an HT (or higher) rate.
    pub const fn is_ht(self) -> bool {
        self.0 >= 12
    }

    /// `true` if this is a VHT rate.
    pub const fn is_vht(self) -> bool {
        self.0 >= 28
    }

    /// Approximate rate in 100 kbps for telemetry.
    pub const fn rate_kbps(self) -> u32 {
        match self.0 {
            0 => 1_000,
            1 => 2_000,
            2 => 5_500,
            3 => 11_000,
            4 => 6_000,
            5 => 9_000,
            6 => 12_000,
            7 => 18_000,
            8 => 24_000,
            9 => 36_000,
            10 => 48_000,
            11 => 54_000,
            // HT MCS 0..7 (20 MHz, long GI): 6.5/13/19.5/26/39/52/58.5/65 Mbps.
            12 => 6_500,
            13 => 13_000,
            14 => 19_500,
            15 => 26_000,
            16 => 39_000,
            17 => 52_000,
            18 => 58_500,
            19 => 65_000,
            // HT MCS 8..15 (2 SS, 20 MHz LGI).
            20..=27 => (self.0 as u32 - 19) * 13_000,
            // VHT 1SS MCS0..9.
            28..=37 => 6_500 * (self.0 as u32 - 27),
            // VHT 2SS MCS0..9.
            38..=47 => 13_000 * (self.0 as u32 - 37),
            _ => 0,
        }
    }

    /// Basic-rate fallback for the given current rate.
    /// Returns the next lower mandatory OFDM rate, or DSSS 1M as last
    /// resort.
    pub const fn fallback(self) -> Self {
        match self.0 {
            // Stay at minimum.
            0 => Self::DSSS_1M,
            // OFDM falls back to next lower OFDM rate.
            5 => Self::OFDM_6M,
            7 => Self::OFDM_6M,
            9 => Self::OFDM_12M,
            10 => Self::OFDM_24M,
            11 => Self::OFDM_24M,
            // HT MCS falls back to OFDM 24M.
            12..=27 => Self::OFDM_24M,
            // VHT falls back to HT MCS3 (≈ 26 Mbps).
            28..=47 => Self::ht_mcs(3),
            // Default: drop one index.
            n => Self(n - 1),
        }
    }
}

/// Pack the rate index into the TX descriptor DW4 field at bits[6:0].
pub fn pack_dw4_rate(rate: RateIdx) -> u32 {
    rate.0 as u32 & 0x7F
}

/// Encode `(retry_limit, short_gi)` flags into DW4.
pub fn pack_dw4_flags(retry_limit: u8, short_gi: bool) -> u32 {
    use super::regs::{TXDESC32_RETRY_LIMIT_ENABLE, TXDESC32_RETRY_LIMIT_SHIFT, TXDESC32_SHORT_GI};
    let mut v = 0;
    if short_gi {
        v |= TXDESC32_SHORT_GI;
    }
    if retry_limit > 0 {
        v |= TXDESC32_RETRY_LIMIT_ENABLE;
        v |= (retry_limit as u32) << TXDESC32_RETRY_LIMIT_SHIFT;
    }
    v
}
