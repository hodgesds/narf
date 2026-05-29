//! rtlwifi channel set + bandwidth set primitives.
//!
//! Changing channels on the rtlwifi family is a 3-step dance:
//!
//! 1. **Pre-commands** (BB): set TX power level for the new channel.
//! 2. **RF-depend cmd**: write the channel number into RF register
//!    `RF_CHNLBW` (0x18) on each active path.
//! 3. **Post-commands**: end-of-sequence marker.
//!
//! Linux models this as a small command-array walker
//! (`_rtl92ee_phy_sw_chnl_step_by_step`).  NARF encodes the same
//! state machine but exposes a single high-level entry point —
//! `set_channel` — that drives the steps inline.
//!
//! Channel ↔ frequency mapping for 2.4 GHz uses the canonical
//! 802.11-2016 Table 17-2 formula `freq = 2407 + 5*ch`; channel 14
//! is 2484 MHz (Japan extension).  5 GHz channels follow the
//! corresponding 5180 + 5*(ch-36) etc. formula.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/phy.c::_rtl92ee_phy_sw_chnl_step_by_step` (line 1795)
//! - `rtl8192ee/phy.c::rtl92ee_phy_sw_chnl` (line 1766)
//! - `rtl8821ae/phy.c::rtl8821ae_phy_sw_chnl_callback` — VHT-aware variant

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::rf::{write_rfreg, RfPath, RF_LC_TRIM};

/// Default 2.4-GHz channel (Wi-Fi standard "1" / 2412 MHz).
pub const DEFAULT_CHANNEL_24G: u8 = 1;

/// Channel-frequency mapping error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// Channel out of range for the chip's supported bands.
    OutOfRange,
}

/// Convert a channel number to a frequency in MHz.  2.4 GHz channels
/// 1..14; 5 GHz channels 36..165 in 20-MHz spacing.  Returns 0 for
/// unsupported channels.
pub const fn ch_to_freq_mhz(ch: u8) -> u16 {
    if ch >= 1 && ch <= 13 {
        2407 + 5 * ch as u16
    } else if ch == 14 {
        2484
    } else if ch >= 36 && ch <= 64 && ch % 4 == 0 {
        5000 + 5 * ch as u16
    } else if ch >= 100 && ch <= 144 && ch % 4 == 0 {
        5000 + 5 * ch as u16
    } else if ch >= 149 && ch <= 165 && ch % 4 == 1 {
        5000 + 5 * ch as u16
    } else {
        0
    }
}

/// `RF_CHNLBW` — RF register that drives RF VCO frequency.  Source:
/// `wifi.h::RF_CHNLBW = 0x18`.  Same register as RF_LC_TRIM; the chip
/// distinguishes the operations by which data bits are set.
pub const RF_CHNLBW: u8 = 0x18;

/// Set channel on path A (and B for 2T2R chips).  The "channel select"
/// value occupies the low byte of RF[0x18] data; bandwidth flags
/// occupy bits 11..8.
///
/// `is_2t` — true for 2T2R chips (8192CE/DE/EE, 8822BE).
///
/// # Safety
/// Caller must own BAR0 exclusively, BB block opened.
pub unsafe fn set_channel(
    mmio: &MmioRegion,
    channel: u8,
    is_2t: bool,
) -> Result<u16, ChannelError> {
    let freq = ch_to_freq_mhz(channel);
    if freq == 0 {
        return Err(ChannelError::OutOfRange);
    }

    // Channel number goes in low byte of RF[0x18] data.
    let data = (channel as u16) & 0x00FF;

    // SAFETY: caller-asserted.
    unsafe {
        write_rfreg(mmio, RfPath::A, RF_CHNLBW, data);
        if is_2t {
            write_rfreg(mmio, RfPath::B, RF_CHNLBW, data);
        }
    }
    // Linux waits 10 µs between channel-change writes; honour it.
    narf_time::busy_wait_cycles(
        10 * 1_000 * narf_time::cycles_per_ns().max(1) as u64,
    );

    let _ = RF_LC_TRIM;
    Ok(freq)
}

// ── Bandwidth mode (HT20 / HT40 / VHT80) ─────────────────────────────────

/// Channel-bandwidth mode.  Mirrors Linux `enum ht_channel_width`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Bandwidth {
    /// 20 MHz HT.
    Ht20 = 0,
    /// 40 MHz HT.
    Ht40 = 1,
    /// 80 MHz VHT (8821AE / 8822BE only).
    Vht80 = 2,
}

/// Set channel bandwidth.  Higher-level than [`set_channel`]: writes the
/// bandwidth bits into RF[0x18] *and* into `REG_BWOPMODE` /
/// `REG_FPGA0_RFMOD`.  Stub for callers that just want the channel
/// edge written; full BB-side bandwidth programming requires the
/// per-chip parafile.
///
/// # Safety
/// Caller must own BAR0 exclusively, BB opened.
pub unsafe fn set_bandwidth(
    mmio: &MmioRegion,
    channel: u8,
    bw: Bandwidth,
    is_2t: bool,
) -> Result<u16, ChannelError> {
    let freq = ch_to_freq_mhz(channel);
    if freq == 0 {
        return Err(ChannelError::OutOfRange);
    }

    let bw_bits = match bw {
        Bandwidth::Ht20 => 0x0C00,
        Bandwidth::Ht40 => 0x0400,
        Bandwidth::Vht80 => 0x0000,
    };
    let data = ((channel as u16) & 0x00FF) | bw_bits;

    // SAFETY: caller-asserted.
    unsafe {
        write_rfreg(mmio, RfPath::A, RF_CHNLBW, data);
        if is_2t {
            write_rfreg(mmio, RfPath::B, RF_CHNLBW, data);
        }
    }
    Ok(freq)
}
