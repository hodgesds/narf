// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE operational MAC while packet DMA is still parked.
//!
//! Linux `rtl8192ce/hw.c::_rtl92ce_init_mac` after the power prefix
//! ([`super::power`]) and LLT ([`super::llt`]), `_rtl92ce_hw_configure` and
//! the `rtl92ce_hw_init` station-address step. Deferred to the retained
//! packet owner, as for the other native chips: `REG_CR = 0x2ff` and the
//! ring bases (`Prepared`). Omitted with reason: `_rtl92ce_gen_refresh_led_state`
//! (LED only), `_rtl92ce_enable_aspm_back_door` (ASPM stays disabled by probe;
//! separate ASPM continuation) and `rtl92ce_enable_hw_security_config` (the
//! shared software CCMP path is used, so `REG_SECCFG` stays 0). The BT-CSR
//! `_rtl92ce_hw_configure` variants are not issued: BT-coexist boards are
//! never admitted.

use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `rtl92c_init_sw_vars` `receive_config`: APPFCS | AMF | ADF | APP_MIC |
/// APP_ICV | AICV | ACRC32 | AB | AM | APM | APP_PHYST_RXFF | HTC_LOC_CTRL.
pub const RCR: u32 = 0xf000_6b0e;
/// `RCR_ACRC32 | RCR_AICV`, cleared from the RCR read back after
/// `rtl92c_phy_mac_config` in `rtl92ce_hw_init`.
pub const RCR_ACRC32_AICV: u32 = (1 << 8) | (1 << 9);
/// `transmit_config`: CFENDFORM | BIT(12) | BIT(13).
pub const TCR: u32 = 0x0000_3200;

pub const REG_HIMR: u16 = 0x0120;
pub const REG_HISR: u16 = 0x0124;
pub const REG_HIMRE: u16 = 0x0128;
pub const REG_HISRE: u16 = 0x012c;
pub const REG_TRXDMA_CTRL: u16 = 0x010c;
pub const REG_TRXFF_BNDY: u16 = 0x0114;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
pub const REG_INT_MIG: u16 = 0x0304;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_APSD_CTRL: u16 = 0x0600;
pub const REG_TCR: u16 = 0x0604;
pub const REG_RCR: u16 = 0x0608;
pub const REG_MACID: u16 = 0x0610;
pub const REG_SECCFG: u16 = 0x0680;

fn w8(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    Ok(io.write8(reg, value)?)
}
fn w16(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    Ok(io.write16(reg, value)?)
}
fn w32(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    Ok(io.write32(reg, value)?)
}
fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    if io.read8(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn dword(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write32(reg, value)?;
    if io.read32(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}

/// `_rtl92ce_init_mac` after the LLT, ring bases excluded. `is_92c` is
/// `IS_92C_SERIAL(version)` (selects `REG_PCIE_CTRL_REG + 3`). The
/// `REG_APSD_CTRL` BIT7 wait continues Linux's shared `retry` counter, which
/// the APFM power poll left at its own count; at most 200 reads here.
pub async fn init_mac(io: &impl Io, is_92c: bool) -> Result<(), Error> {
    // W1C status clear; not an acknowledgement of serviced work.
    w32(io, REG_HISR, u32::MAX)?;
    w8(io, REG_HISRE, 0xff)?;
    w16(io, REG_TRXFF_BNDY + 2, 0x27ff)?;
    let old = u16::from_le_bytes([io.read8(REG_TRXDMA_CTRL)?, io.read8(REG_TRXDMA_CTRL + 1)?]);
    w16(io, REG_TRXDMA_CTRL, (old & 0xf) | 0xf771)?;
    byte(io, REG_FWHW_TXQ_CTRL + 1, 0x1f)?;
    dword(io, REG_RCR, RCR)?;
    dword(io, REG_TCR, TCR)?;
    w8(io, 0x04d0, 0x00)?;
    byte(io, REG_PCIE_CTRL_REG + 3, if is_92c { 0x77 } else { 0x22 })?;
    dword(io, REG_INT_MIG, 0)?;
    let value = io.read8(REG_APSD_CTRL)?;
    w8(io, REG_APSD_CTRL, value & !(1 << 6))?;
    for _ in 0..200 {
        if io.read8(REG_APSD_CTRL)? & (1 << 7) == 0 {
            break;
        }
        io.delay_us(0).await;
    }
    dword(io, REG_MCUTST_1, 0)
}

/// `rtl92ce_hw_init` after `rtl92c_phy_mac_config`: RCR read back with
/// `RCR_ACRC32 | RCR_AICV` cleared. Returns the new `receive_config`.
pub fn trim_receive_config(io: &impl Io) -> Result<u32, Error> {
    let rcr = io.read32(REG_RCR)? & !RCR_ACRC32_AICV;
    dword(io, REG_RCR, rcr)?;
    Ok(rcr)
}

/// `_rtl92ce_hw_configure` (non-BT). Plain writes exactly as Linux.
pub fn hw_configure(io: &impl Io) -> Result<(), Error> {
    w8(io, 0x0480, 0x8)?; // REG_INIRTS_RATE_SEL
    w8(io, 0x0603, 0x04)?; // REG_BWOPMODE = BW_OPMODE_20MHZ
    w32(io, 0x0440, 0x0fff)?; // REG_RRSR: RATE_ALL_CCK | RATE_ALL_OFDM_AG
    w8(io, 0x051b, 0x09)?; // REG_SLOT
    w8(io, 0x045c, 0x0)?; // REG_AMPDU_MIN_SPACE
    w16(io, REG_FWHW_TXQ_CTRL, 0x1f80)?;
    w16(io, 0x042a, 0x0707)?; // REG_RL
    w32(io, 0x04cc, 0x0201_2802)?; // REG_BAR_MODE_CTRL
    w8(io, 0x0423, 0xff)?; // REG_HWSEQ_CTRL
    w32(io, 0x0430, 0x0100_0000)?; // REG_DARFRC
    w32(io, 0x0434, 0x0706_0504)?;
    w32(io, 0x0438, 0x0100_0000)?; // REG_RARFRC
    w32(io, 0x043c, 0x0706_0504)?;
    w32(io, 0x0458, 0xb972_a841)?; // REG_AGGLEN_LMT
    w8(io, 0x055a, 0x2)?; // REG_ATIMWND
    w8(io, 0x055d, 0xff)?; // REG_BCN_MAX_ERR
    w8(io, 0x0550, 0x1f)?; // REG_BCN_CTRL = reg_bcn_ctrl_val
    w8(io, 0x0541, 0xff)?; // REG_TBTT_PROHIBIT + 1 (twice in Linux)
    w8(io, 0x0541, 0xff)?;
    w8(io, 0x0512, 0x1c)?; // REG_PIFS
    w8(io, 0x051a, 0x16)?; // REG_AGGR_BREAK_TIME
    w16(io, 0x0546, 0x0020)?; // REG_NAV_PROT_LEN (twice in Linux)
    w16(io, 0x0546, 0x0020)?;
    w32(io, 0x0460, 0x0008_6666)?; // REG_FAST_EDCA_CTRL
    w8(io, 0x0640, 0x40)?; // REG_ACKTO
    w16(io, 0x0428, 0x1010)?; // REG_SPEC_SIFS
    w16(io, 0x063a, 0x1010)?; // REG_MAC_SPEC_SIFS
    w16(io, 0x0514, 0x1010)?; // REG_SIFS_CTX
    w16(io, 0x0516, 0x1010)?; // REG_SIFS_TRX
    w32(io, 0x0620, 0xffff_ffff)?; // REG_MAR
    w32(io, 0x0624, 0xffff_ffff)
}

/// Software crypto (`REG_SECCFG` 0) and `HW_VAR_ETHER_ADDR`.
pub fn station_identity(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    byte(io, REG_SECCFG, 0)?;
    for (offset, value) in mac.iter().copied().enumerate() {
        byte(io, REG_MACID + offset as u16, value)?;
    }
    Ok(())
}
