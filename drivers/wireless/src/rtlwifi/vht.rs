//! 802.11ac (VHT) enable for RTL8821AE + RTL8822BE.
//!
//! Both chips are Wi-Fi 5 silicon, but the BB / MAC paths only carry
//! VHT after specific bits are flipped:
//!
//! - `REG_BWOPMODE` (0x0603) — selects 20/40/80 MHz operating mode at
//!   MAC level.
//! - `REG_FPGA0_RFMOD` bit[27] — enables VHT-rate decode in the BB
//!   block (must be set after the BB parafile loads).
//! - `REG_CR` low byte must include `CR_PROTOCOL_EN` so the 802.11ac
//!   MAC sublayer is online.
//!
//! NARF carries these as named primitives.  The full VHT-rate set,
//! MCS selection, and beamforming-feedback handling stay in the
//! per-chip `phy.c` / `dm.c` files in Linux and is not needed for
//! basic association.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8821ae/reg.h:280` — `REG_BWOPMODE`
//! - `rtl8821ae/phy.c::rtl8821ae_phy_set_bw_mode` — VHT mode programming
//! - `rtl8821ae/sw.c::rtl8821ae_init_sw_vars` — VHT capability bits

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::regs::*;

/// `REG_BWOPMODE` — MAC-level bandwidth operating mode.  `reg.h:280`.
pub const REG_BWOPMODE: u64 = 0x0603;

/// True for chips that ship a VHT-capable BB block.
pub const fn has_vht(did: u16) -> bool {
    matches!(did, RTL_DEV_8821AE | RTL_DEV_8822BE)
}

/// VHT operating modes selectable through `REG_BWOPMODE`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VhtMode {
    /// 20 MHz only.
    Bw20 = 0x00,
    /// 40 MHz capable.
    Bw40 = 0x01,
    /// 80 MHz capable (VHT only).
    Bw80 = 0x02,
}

/// Enable VHT operation on the chip.  No-ops for non-VHT chips.
///
/// # Safety
/// Caller must own BAR0 exclusively, BB block opened.
pub unsafe fn enable_vht(mmio: &MmioRegion, did: u16, mode: VhtMode) {
    if !has_vht(did) {
        return;
    }
    // SAFETY: caller-asserted.
    unsafe {
        // Latch the operating mode at MAC level.
        mmio.write8(REG_BWOPMODE, mode as u8);
        // Also OR-in the protocol-engine bit of CR if it's missing.
        let cr = mmio.read16(REG_CR);
        mmio.write16(REG_CR, cr | CR_PROTOCOL_EN);
    }
}

/// VHT MCS rate index.  Encodes the spatial-stream count + MCS pair as
/// the byte used in TX-rate selection.  Source: `rtl8821ae/def.h:147..157`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VhtMcs {
    Vht1ssMcs0 = 0x90,
    Vht1ssMcs9 = 0x99,
    Vht2ssMcs0 = 0x9A,
    Vht2ssMcs9 = 0xA3,
}

/// Pick the maximum VHT MCS for the chip's antenna count.
pub const fn max_mcs_for(did: u16) -> Option<VhtMcs> {
    match did {
        // 1T1R — 1 spatial stream.
        RTL_DEV_8821AE => Some(VhtMcs::Vht1ssMcs9),
        // 2T2R — 2 spatial streams.
        RTL_DEV_8822BE => Some(VhtMcs::Vht2ssMcs9),
        _ => None,
    }
}
