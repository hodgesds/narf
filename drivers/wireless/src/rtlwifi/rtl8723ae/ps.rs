// SPDX-License-Identifier: GPL-2.0-or-later
//! AE MAC station/cache helpers only. No RF-sleep/reclamation admission.
//! rtl8723ae/hw.c source register/cache operations, including its extra
//! DWORD BCN_CTRL clear in _set_media_status (absent from CE).
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};
pub const REG_CR: u16 = 0x0100;
/// `MSR` (`REG_CR + 2`).
pub const REG_MSR: u16 = 0x0102;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_BCNTCFG: u16 = 0x0510;
pub const REG_TXPAUSE: u16 = 0x0522;
pub const REG_TBTT_PROHIBIT: u16 = 0x0540;
pub const REG_BCN_CTRL: u16 = 0x0550;
pub const REG_APSD_CTRL: u16 = 0x0600;
pub const REG_BCN_PSR_RPT: u16 = 0x06a8;

pub const MSR_NOLINK: u8 = 0;
pub const MSR_INFRA: u8 = 2;

/// `_rtl8723e_hw_configure` `REG_BCN_CTRL` / `rtlpci->reg_bcn_ctrl_val`.
pub const BCN_CTRL_INIT: u8 = 0x1f;

/// `rtlpci->reg_bcn_ctrl_val` with `_rtl8723e_set_bcn_ctrl_reg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BcnCtrl(pub u8);

impl Default for BcnCtrl {
    fn default() -> Self {
        Self(BCN_CTRL_INIT)
    }
}

impl BcnCtrl {
    pub fn set(&mut self, io: &impl Io, set_bits: u8, clear_bits: u8) -> Result<(), Error> {
        self.0 |= set_bits;
        self.0 &= !clear_bits;
        io.write8(REG_BCN_CTRL, self.0)?;
        Ok(())
    }
}

/// `_rtl8723e_set_media_status` for a station (`linked` = `link_state >=
/// MAC80211_LINKED`) or `NL80211_IFTYPE_UNSPECIFIED` (`linked` false).
pub fn set_media_status(io: &impl Io, bcn: &mut BcnCtrl, linked: bool) -> Result<(), Error> {
    let msr = io.read8(REG_MSR)? & 0xfc;
    let mode = if linked { MSR_INFRA } else { MSR_NOLINK };
    io.write32(REG_BCN_CTRL, 0)?;
    // _rtl8723e_stop_tx_beacon.
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0x64)?;
    let tbtt = io.read8(REG_TBTT_PROHIBIT + 2)?;
    io.write8(REG_TBTT_PROHIBIT + 2, tbtt & !1)?;
    // _rtl8723e_enable_bcn_sub_func.
    bcn.set(io, 0, 1 << 1)?;
    io.write8(REG_MSR, msr | mode)?;
    io.write8(REG_BCNTCFG + 1, 0x66)?;
    Ok(())
}

/// `HW_VAR_AID`.
pub fn set_aid(io: &impl Io, aid: u16) -> Result<(), Error> {
    let old = io.read16(REG_BCN_PSR_RPT)? & 0xc000;
    io.write16(REG_BCN_PSR_RPT, old | aid)?;
    Ok(())
}
