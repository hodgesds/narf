// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE operational MAC while packet DMA is still parked.
//!
//! Linux `rtl8723be/hw.c::_rtl8723be_init_mac` after the power prefix and
//! `RTL8723_NIC_ENABLE_FLOW` (run at probe, `power::power_on_with`),
//! `_rtl8723be_hw_configure` and the `rtl8723be_hw_init` station-address
//! step. Deferred to the retained packet owner, as for the other native
//! chips: `REG_CR = 0xff` / `REG_CR = 0x2ff`, the LLT ([`super::llt`], which
//! Linux runs between them) and the ring bases. `btc_power_on_setting`
//! (BT coexistence, issued by Linux right after the enable flow) belongs to
//! the coexistence owner. Omitted with reason: `_rtl8723be_gen_refresh_led_state`
//! (LED only), `_rtl8723be_enable_aspm_back_door` (ASPM stays disabled by
//! probe) and `rtl8723be_enable_hw_security_config` (the shared software
//! CCMP path is used, so `REG_SECCFG` stays 0).

use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `rtl8723be_init_sw_vars` `receive_config`: APPFCS | APP_MIC | APP_ICV |
/// APP_PHYST_RXFF | HTC_LOC_CTRL | AMF | ACF | ADF | AICV | AB | AM | APM.
pub const RCR: u32 = 0xf000_7a0e;
/// `RCR_ACRC32 | RCR_AICV`, cleared from the RCR read back after
/// `rtl8723be_phy_mac_config` in `rtl8723be_hw_init`.
pub const RCR_ACRC32_AICV: u32 = (1 << 8) | (1 << 9);
/// `transmit_config`: CFENDFORM | BIT(15) | BIT(24) | BIT(25).
pub const TCR: u32 = 0x0300_8200;

pub const REG_SYS_CLKR: u16 = 0x0008;
pub const REG_GPIO_MUXCFG: u16 = 0x0040;
pub const REG_MULTI_FUNC_CTRL: u16 = 0x0068;
pub const REG_APS_FSMCO: u16 = 0x0004;
pub const REG_HIMR: u16 = 0x00b0;
pub const REG_HISR: u16 = 0x00b4;
pub const REG_HIMRE: u16 = 0x00b8;
pub const REG_HISRE: u16 = 0x00bc;
pub const REG_SYS_CFG: u16 = 0x00f0;
pub const REG_TRXDMA_CTRL: u16 = 0x010c;
pub const REG_FWIMR: u16 = 0x0130;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_RXDMA_CONTROL: u16 = 0x0286;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
pub const REG_INT_MIG: u16 = 0x0304;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_HWSEQ_CTRL: u16 = 0x0423;
pub const REG_SECONDARY_CCA_CTRL: u16 = 0x0577;
pub const REG_TCR: u16 = 0x0604;
pub const REG_RCR: u16 = 0x0608;
pub const REG_MACID: u16 = 0x0610;
pub const REG_SECCFG: u16 = 0x0680;
pub const REG_RXFLTMAP2: u16 = 0x06a4;

fn w8(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    Ok(io.write8(reg, value)?)
}
fn w16(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    Ok(io.write16(reg, value)?)
}
fn w32(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    Ok(io.write32(reg, value)?)
}
fn rmw8(io: &impl Io, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = io.read8(reg)?;
    w8(io, reg, (value & !clear) | set)
}
/// `rtl_set_bbreg(hw, reg, mask, data)`: dword read-modify-write with the
/// data shifted to the mask's lowest set bit.
pub fn set_bbreg(io: &impl Io, reg: u16, mask: u32, data: u32) -> Result<(), Error> {
    let shift = mask.trailing_zeros();
    let value = (io.read32(reg)? & !mask) | ((data << shift) & mask);
    w32(io, reg, value)
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

/// `_rtl8723be_init_mac` from `REG_MULTI_FUNC_CTRL |= BIT3` to just before
/// `REG_CR = 0xff` (the `mdelay(2)` after it is kept with the owner).
pub fn init_mac_pre_cr(io: &impl Io) -> Result<(), Error> {
    rmw8(io, REG_MULTI_FUNC_CTRL, 0, 1 << 3)?;
    rmw8(io, REG_APS_FSMCO, 0, 1 << 4)
}

/// `_rtl8723be_init_mac` between `REG_CR = 0xff` and `REG_CR = 0x2ff`.
pub async fn init_mac_clocks(io: &impl Io) -> Result<(), Error> {
    rmw8(io, REG_HWSEQ_CTRL, 0, 0x7f)?;
    io.delay_us(2000).await;
    if io.read8(REG_SYS_CFG + 3)? & 1 != 0 {
        rmw8(io, 0x7c, 0, 1 << 6)?;
    }
    rmw8(io, REG_SYS_CLKR, 0, 1 << 3)?;
    rmw8(io, REG_GPIO_MUXCFG + 1, 1 << 4, 0)
}

/// `_rtl8723be_init_mac` after the LLT, ring bases excluded.
pub fn init_mac_post_llt(io: &impl Io) -> Result<(), Error> {
    // W1C status clear; not an acknowledgement of serviced work.
    w32(io, REG_HISR, u32::MAX)?;
    w32(io, REG_HISRE, u32::MAX)?;
    // Enable FW Beamformer Interrupt.
    rmw8(io, REG_FWIMR + 3, 0, 1 << 6)?;
    let old = u16::from_le_bytes([io.read8(REG_TRXDMA_CTRL)?, io.read8(REG_TRXDMA_CTRL + 1)?]);
    w16(io, REG_TRXDMA_CTRL, (old & 0xf) | 0xf5b1)?;
    byte(io, REG_FWHW_TXQ_CTRL + 1, 0x1f)?;
    dword(io, REG_RCR, RCR)?;
    w16(io, REG_RXFLTMAP2, 0xffff)?;
    dword(io, REG_TCR, TCR)?;
    rmw8(io, REG_PCIE_CTRL_REG + 3, 0, 0x77)?;
    dword(io, REG_INT_MIG, 0)?;
    dword(io, REG_MCUTST_1, 0)?;
    w8(io, REG_SECONDARY_CCA_CTRL, 0x3)?;
    // DPDT / fixed board settings (Kordan, 20130114).
    set_bbreg(io, 0x64, 1 << 20, 0)?;
    set_bbreg(io, 0x64, 1 << 24, 0)?;
    set_bbreg(io, 0x40, 1 << 4, 0)?;
    set_bbreg(io, 0x40, 1 << 3, 1)?;
    set_bbreg(io, 0x4c, (1 << 24) | (1 << 23), 0x2)?;
    set_bbreg(io, 0x944, 0x3, 0x3)?;
    set_bbreg(io, 0x930, 0xff, 0x77)?;
    set_bbreg(io, 0x38, 1 << 11, 1)?;
    rmw8(io, REG_RXDMA_CONTROL, 1 << 2, 0)
}

/// `rtl8723be_hw_init` after `rtl8723be_phy_mac_config`: RCR read back with
/// `RCR_ACRC32 | RCR_AICV` cleared. Returns the new `receive_config`.
pub fn trim_receive_config(io: &impl Io) -> Result<u32, Error> {
    let rcr = io.read32(REG_RCR)? & !RCR_ACRC32_AICV;
    dword(io, REG_RCR, rcr)?;
    Ok(rcr)
}

/// `_rtl8723be_hw_configure`. Plain writes exactly as Linux.
pub fn hw_configure(io: &impl Io) -> Result<(), Error> {
    w32(io, 0x0440, 0x0fff)?; // REG_RRSR: RATE_ALL_CCK | RATE_ALL_OFDM_AG
    w32(io, 0x0444 + 4, 0xffff_f000)?; // REG_ARFR0 + 4
    w32(io, 0x044c + 4, 0x003f_f000)?; // REG_ARFR1 + 4
    w16(io, REG_FWHW_TXQ_CTRL, 0x1f00)?;
    w8(io, 0x0456, 0x70)?; // REG_AMPDU_MAX_TIME
    w16(io, 0x042a, 0x0707)?; // REG_RL
    w32(io, 0x0430, 0x0100_0000)?; // REG_DARFRC
    w32(io, 0x0434, 0x0706_0504)?;
    w32(io, 0x0438, 0x0100_0000)?; // REG_RARFRC
    w32(io, 0x043c, 0x0706_0504)?;
    w8(io, 0x0550, 0x1d)?; // REG_BCN_CTRL = reg_bcn_ctrl_val
    w8(io, 0x0541, 0xff)?; // REG_TBTT_PROHIBIT + 1
    w16(io, 0x0546, 0x0040)?; // REG_NAV_PROT_LEN
    w32(io, 0x0460, 0x0308_6666)?; // REG_FAST_EDCA_CTRL
    w8(io, 0x04c7, 0x80)?; // REG_HT_SINGLE_AMPDU
    w8(io, 0x060c, 0x20)?; // REG_RX_PKT_LIMIT
    w8(io, 0x04ca, 0x1f) // REG_MAX_AGGR_NUM
}

/// Software crypto (`REG_SECCFG` 0) and `HW_VAR_ETHER_ADDR`.
pub fn station_identity(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    byte(io, REG_SECCFG, 0)?;
    for (offset, value) in mac.iter().copied().enumerate() {
        byte(io, REG_MACID + offset as u16, value)?;
    }
    Ok(())
}
