// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE station-side hardware pieces of the packet owner:
//! media status, AID, beacon control, leisure-PS RF saving, false-alarm
//! statistics and the card-disable power-off.
//!
//! - [`set_media_status`] — `rtl8192ce/hw.c::_rtl92ce_set_media_status`
//!   for `NL80211_IFTYPE_STATION` (linked ⇒ `MSR_INFRA`, otherwise
//!   `MSR_NOLINK`) and `NL80211_IFTYPE_UNSPECIFIED`: both stop TX beacons
//!   (`_rtl92ce_stop_tx_beacon`) and enable the beacon sub-function
//!   (`_rtl92ce_enable_bcn_sub_func`), then `MSR` and `REG_BCNTCFG + 1 =
//!   0x66`. LED control is not issued (no LED owner).
//! - [`set_aid`] — `HW_VAR_AID` (`REG_BCN_PSR_RPT` keeps `[15:14]`).
//! - [`BcnCtrl`] — `_rtl92ce_set_bcn_ctrl_reg` over `reg_bcn_ctrl_val`
//!   (`_rtl92ce_hw_configure` leaves `0x1f`).
//! - [`RfSaving`] — `rtl8192c/dm_common.c::rtl92c_dm_rf_saving` (88C only:
//!   `HW_VAR_H2C_FW_PWRMODE` forces `RF_NORMAL` before a non-active mode,
//!   `rtl92c_dm_dynamic_bb_powersaving` evaluates the 30/25 hysteresis).
//! - [`false_alarm`] — `rtl92c_dm_false_alarm_counter_statistics`.
//! - [`poweroff_adapter`] — `_rtl92ce_poweroff_adapter` (non-BT; ASPM is
//!   not enabled by this owner, so `enable_aspm` is not issued).

use super::fw;
use super::phy::{self, Path};
use super::version::Version;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_RF_CTRL: u16 = 0x001f;
pub const REG_AFE_PLL_CTRL: u16 = 0x0028;
pub const REG_GPIO_IO_SEL: u16 = 0x0042;
pub const REG_GPIO_PIN_CTRL: u16 = 0x0044;
pub const REG_LEDCFG0: u16 = 0x004c;
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

/// `_rtl92ce_hw_configure` `REG_BCN_CTRL` / `rtlpci->reg_bcn_ctrl_val`.
pub const BCN_CTRL_INIT: u8 = 0x1f;

/// `rtlpci->reg_bcn_ctrl_val` with `_rtl92ce_set_bcn_ctrl_reg`.
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

/// `_rtl92ce_set_media_status` for a station (`linked` = `link_state >=
/// MAC80211_LINKED`) or `NL80211_IFTYPE_UNSPECIFIED` (`linked` false).
pub fn set_media_status(io: &impl Io, bcn: &mut BcnCtrl, linked: bool) -> Result<(), Error> {
    let msr = io.read8(REG_MSR)? & 0xfc;
    let mode = if linked { MSR_INFRA } else { MSR_NOLINK };
    // _rtl92ce_stop_tx_beacon.
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0x64)?;
    let tbtt = io.read8(REG_TBTT_PROHIBIT + 2)?;
    io.write8(REG_TBTT_PROHIBIT + 2, tbtt & !1)?;
    // _rtl92ce_enable_bcn_sub_func.
    bcn.set(io, 0, 1 << 1)?;
    io.write8(REG_MSR, msr | mode)?;
    io.write8(REG_BCNTCFG + 1, 0x66)?;
    Ok(())
}

/// `HW_VAR_AID`.
pub fn set_aid(io: &impl Io, aid: u16) -> Result<(), Error> {
    // rtl_read_word as two byte reads (the transport has no 16-bit read).
    let old =
        u16::from_le_bytes([io.read8(REG_BCN_PSR_RPT)?, io.read8(REG_BCN_PSR_RPT + 1)?]) & 0xc000;
    io.write16(REG_BCN_PSR_RPT, old | aid)?;
    Ok(())
}

/// `enum dm_rf_e`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RfState {
    #[default]
    Normal,
    Save,
    Max,
}

/// `rtlpriv->reg_init`/`reg_874`/`reg_c70`/`reg_85c`/`reg_a74` and
/// `dm_pstable.pre_rfstate` (`RF_MAX` from `rtl92c_dm_init`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RfSaving {
    saved: Option<[u32; 4]>,
    pub pre: RfState,
}

const RFPGA0_XCD_SWITCHCONTROL: u16 = 0x085c;
const RFPGA0_XCD_RFINTERFACESW: u16 = 0x0874;
const ROFDM0_AGCPARAMETER1: u16 = 0x0c70;

impl RfSaving {
    /// `rtl92c_dm_init_dynamic_bb_powersaving`: `pre_rfstate = RF_MAX`.
    pub const fn new() -> Self {
        Self {
            saved: None,
            pre: RfState::Max,
        }
    }

    /// `rtl92c_dm_rf_saving(hw, force_normal)` with `rssi_val_min`.
    pub fn run(
        &mut self,
        io: &impl Io,
        force_normal: bool,
        rssi_val_min: i64,
    ) -> Result<(), Error> {
        let saved = match self.saved {
            Some(saved) => saved,
            None => {
                let s = [
                    (phy::get_bb(io, RFPGA0_XCD_RFINTERFACESW, phy::MASKDWORD)? & 0x1c_c000) >> 14,
                    (phy::get_bb(io, ROFDM0_AGCPARAMETER1, phy::MASKDWORD)? & (1 << 3)) >> 3,
                    (phy::get_bb(io, RFPGA0_XCD_SWITCHCONTROL, phy::MASKDWORD)? & 0xff00_0000)
                        >> 24,
                    (phy::get_bb(io, 0x0a74, phy::MASKDWORD)? & 0xf000) >> 12,
                ];
                self.saved = Some(s);
                s
            }
        };
        let cur = if force_normal {
            RfState::Normal
        } else if rssi_val_min != 0 {
            match self.pre {
                RfState::Normal if rssi_val_min >= 30 => RfState::Save,
                RfState::Normal => RfState::Normal,
                _ if rssi_val_min <= 25 => RfState::Normal,
                _ => RfState::Save,
            }
        } else {
            RfState::Max
        };
        if self.pre != cur {
            if cur == RfState::Save {
                phy::set_bb(io, RFPGA0_XCD_RFINTERFACESW, 0x1c_0000, 0x2)?;
                phy::set_bb(io, ROFDM0_AGCPARAMETER1, 1 << 3, 0)?;
                phy::set_bb(io, RFPGA0_XCD_SWITCHCONTROL, 0xff00_0000, 0x63)?;
                phy::set_bb(io, RFPGA0_XCD_RFINTERFACESW, 0xc000, 0x2)?;
                phy::set_bb(io, 0x0a74, 0xf000, 0x3)?;
                phy::set_bb(io, 0x0818, 1 << 28, 0)?;
                phy::set_bb(io, 0x0818, 1 << 28, 1)?;
            } else {
                phy::set_bb(io, RFPGA0_XCD_RFINTERFACESW, 0x1c_c000, saved[0])?;
                phy::set_bb(io, ROFDM0_AGCPARAMETER1, 1 << 3, saved[1])?;
                phy::set_bb(io, RFPGA0_XCD_SWITCHCONTROL, 0xff00_0000, saved[2])?;
                phy::set_bb(io, 0x0a74, 0xf000, saved[3])?;
                phy::set_bb(io, 0x0818, 1 << 28, 0)?;
            }
            self.pre = cur;
        }
        Ok(())
    }
}

impl Default for RfSaving {
    fn default() -> Self {
        Self::new()
    }
}

/// `struct false_alarm_statistics` fields this owner reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FalseAlarm {
    pub ofdm: u32,
    pub cck: u32,
    pub all: u32,
}

/// `rtl92c_dm_false_alarm_counter_statistics`: read the OFDM/CCK counters,
/// then reset them (`ROFDM1_LSTF` BIT27 pulse, `RCCK0_FALSEALARMREPORT`
/// `[15:14]` 0 then 2). `cnt_all` excludes the fast-fsync and SB-search
/// counts, as Linux.
pub fn false_alarm(io: &impl Io) -> Result<FalseAlarm, Error> {
    let r1 = phy::get_bb(io, 0x0da0, phy::MASKDWORD)?;
    let parity = r1 >> 16;
    let r2 = phy::get_bb(io, 0x0da4, phy::MASKDWORD)?;
    let (rate_illegal, crc8) = (r2 & 0xffff, r2 >> 16);
    let mcs = phy::get_bb(io, 0x0da8, phy::MASKDWORD)? & 0xffff;
    let r4 = phy::get_bb(io, 0x0cf0, phy::MASKDWORD)?;
    let (fsync, sb) = (r4 & 0xffff, r4 >> 16);
    let ofdm = parity + rate_illegal + crc8 + mcs + fsync + sb;
    phy::set_bb(io, 0x0a2c, 1 << 14, 1)?;
    let mut cck = phy::get_bb(io, 0x0a5c, 0xff)?;
    cck += (phy::get_bb(io, 0x0a58, 0xff00_0000)? & 0xff) << 8;
    let all = parity + rate_illegal + crc8 + mcs + cck;
    phy::set_bb(io, 0x0d00, 0x0800_0000, 1)?;
    phy::set_bb(io, 0x0d00, 0x0800_0000, 0)?;
    phy::set_bb(io, 0x0a2c, 0x0000_c000, 0)?;
    phy::set_bb(io, 0x0a2c, 0x0000_c000, 2)?;
    Ok(FalseAlarm { ofdm, cck, all })
}

/// `_rtl92ce_poweroff_adapter` for a non-BT board. The RF write is
/// `rtl_set_rfreg(RF90_PATH_A, 0, RFREG_OFFSET_MASK, 0)` (no read first).
/// Linux's `rtl92c_firmware_selfreset` runs when `REG_MCUFWDL` BIT7 (RAM
/// code running) is set.
pub async fn poweroff_adapter(io: &impl Io, version: Version) -> Result<(), Error> {
    io.write8(REG_TXPAUSE, 0xff)?;
    phy::rf_write(io, Path::A, 0, 0)?;
    io.write8(REG_RF_CTRL, 0)?;
    io.write8(REG_APSD_CTRL, 0x40)?;
    io.write8(fw::REG_SYS_FUNC_EN, 0xe2)?;
    io.write8(fw::REG_SYS_FUNC_EN, 0xe0)?;
    if io.read8(fw::REG_MCUFWDL)? & (1 << 7) != 0 {
        fw::selfreset(io).await?;
    }
    io.write8(fw::REG_SYS_FUNC_EN + 1, 0x51)?;
    io.write8(fw::REG_MCUFWDL, 0)?;
    io.write32(REG_GPIO_PIN_CTRL, 0)?;
    let pin = io.read8(REG_GPIO_PIN_CTRL)?;
    io.write32(REG_GPIO_PIN_CTRL, 0x00ff_0000 | (u32::from(pin) << 8))?;
    io.write16(REG_GPIO_IO_SEL, 0x0790)?;
    io.write16(REG_LEDCFG0, 0x8080)?;
    io.write8(REG_AFE_PLL_CTRL, 0x80)?;
    if !version.is_umc_b_cut() {
        io.write8(super::power::REG_SPS0_CTRL, 0x23)?;
    }
    io.write32(super::power::REG_AFE_XTAL_CTRL, 0x0e)?;
    io.write8(super::power::REG_RSV_CTRL, 0x0e)?;
    io.write8(super::power::REG_APS_FSMCO + 1, 0x10)?;
    Ok(())
}
