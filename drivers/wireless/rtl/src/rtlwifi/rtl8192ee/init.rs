// SPDX-License-Identifier: GPL-2.0-or-later
//! The `rtl92ee_hw_init` tail after the firmware download.
//!
//! Linux order (`rtl8192ee/hw.c::rtl92ee_hw_init`) from
//! `rtl92ee_phy_mac_config`: MAC/BB/RF tables and the RF channel tail
//! ([`super::phy::configure`]); `_rtl92ee_hw_configure` ([`hw_configure`]);
//! `rtl_cam_reset_all_entry` (`REG_CAMCMD = BIT31 | BIT30`);
//! `HW_VAR_ETHER_ADDR` (`REG_MACID`); the IQK
//! (`rtl92ee_phy_iq_calibrate(false)`, `iqk_initialized` is false on a fresh
//! owner); the PA-bias rule from the physical EFUSE byte `0x1FA`
//! (`efuse_one_byte_read`: BIT0 clear ⇒ RF A `0x15[3:0] = 5`, BIT1 clear ⇒
//! RF B, a timed-out read yields `0xff`); `REG_NAV_UPPER = 235`; the LDPC
//! RX-hang fix (`REG_SYS_SWR_CTRL2 = 0x75`, `REG_SYS_SWR_CTRL1[19:12] =
//! 0x7e`); `0x4fc = 0`.
//!
//! Deliberately not issued: `rtl92ee_enable_hw_security_config` (this
//! station uses software crypto — Linux's `sw_crypto` early return),
//! `_rtl92ee_enable_aspm_back_door` / `enable_aspm` (ASPM stays disabled,
//! as for the other retained rtlwifi chips), `rtl92ee_bt_hw_init` (BT
//! boards are refused before any write). `rtl92ee_dm_init` is software
//! state only (DIG/RA/CCA/EDCA/power-tracking/ATC bookkeeping) and belongs
//! to the DM owner.

use super::adapter::Adapter;
use super::headerfile::Condition;
use super::iqk;
use super::phy::{self, set_rf, Path};
use super::txpower::Efuse;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_SYS_SWR_CTRL1: u16 = 0x0010;
pub const REG_SYS_SWR_CTRL2: u16 = 0x0014;
pub const REG_EFUSE_CTRL: u16 = 0x0030;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_RETRY_LIMIT: u16 = 0x042a;
pub const REG_DARFRC: u16 = 0x0430;
pub const REG_RARFRC: u16 = 0x0438;
pub const REG_RRSR: u16 = 0x0440;
pub const REG_ARFR0: u16 = 0x0444;
pub const REG_ARFR1: u16 = 0x044c;
pub const REG_FAST_EDCA_CTRL: u16 = 0x0460;
pub const REG_PROT_MODE_CTRL: u16 = 0x04c8;
pub const REG_BAR_MODE_CTRL: u16 = 0x04cc;
pub const REG_PIFS: u16 = 0x0512;
pub const REG_AGGR_BREAK_TIME: u16 = 0x051a;
pub const REG_SLOT: u16 = 0x051b;
pub const REG_TBTT_PROHIBIT: u16 = 0x0540;
pub const REG_NAV_PROT_LEN: u16 = 0x0546;
pub const REG_BCN_CTRL: u16 = 0x0550;
pub const REG_BCN_CTRL_1: u16 = 0x0551;
pub const REG_ATIMWND: u16 = 0x055a;
pub const REG_BCN_MAX_ERR: u16 = 0x055d;
pub const REG_MACID: u16 = 0x0610;
pub const REG_NAV_UPPER: u16 = 0x0652;
pub const REG_CAMCMD: u16 = 0x0670;
pub const REG_MAR: u16 = 0x0620;
pub const REG_ACKTO: u16 = 0x0640;
pub const REG_SPEC_SIFS: u16 = 0x0428;
pub const REG_MAC_SPEC_SIFS: u16 = 0x063a;
pub const REG_SIFS_CTX: u16 = 0x0514;
pub const REG_SIFS_TRX: u16 = 0x0516;
pub const REG_RX_PKT_LIMIT: u16 = 0x060c;
pub const REG_MAX_AGGR_NUM: u16 = 0x04ca;
/// `RATE_ALL_CCK | RATE_ALL_OFDM_AG`.
pub const RRSR_INIT: u32 = 0x0000_000f | 0x0000_0ff0;
/// `efuse_one_byte_read` address of the PA-bias flags.
pub const EFUSE_PA_BIAS: u16 = 0x01fa;

/// `_rtl92ee_hw_configure` in Linux order.
pub fn hw_configure(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_RRSR, RRSR_INIT)?;
    io.write32(REG_ARFR0, 0x0000_0010)?;
    io.write32(REG_ARFR0 + 4, 0x3e0f_f000)?;
    io.write32(REG_ARFR1, 0x0000_0010)?;
    io.write32(REG_ARFR1 + 4, 0x000f_f000)?;
    io.write8(REG_SLOT, 0x09)?;
    io.write16(REG_FWHW_TXQ_CTRL, 0x1f80)?;
    io.write16(REG_RETRY_LIMIT, 0x0707)?;
    io.write32(REG_BAR_MODE_CTRL, 0x0201_ffff)?;
    io.write32(REG_DARFRC, 0x0100_0000)?;
    io.write32(REG_DARFRC + 4, 0x0706_0504)?;
    io.write32(REG_RARFRC, 0x0100_0000)?;
    io.write32(REG_RARFRC + 4, 0x0706_0504)?;
    io.write8(REG_ATIMWND, 0x2)?;
    io.write8(REG_BCN_MAX_ERR, 0xff)?;
    io.write8(REG_BCN_CTRL, 0x1d)?;
    io.write8(REG_BCN_CTRL_1, 0)?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0xff)?;
    io.write8(REG_PIFS, 0)?;
    io.write8(REG_AGGR_BREAK_TIME, 0x16)?;
    io.write16(REG_NAV_PROT_LEN, 0x0040)?;
    io.write16(REG_PROT_MODE_CTRL, 0x08ff)?;
    io.write32(REG_FAST_EDCA_CTRL, 0x0308_6666)?;
    io.write8(REG_ACKTO, 0x40)?;
    io.write16(REG_SPEC_SIFS, 0x100a)?;
    io.write16(REG_MAC_SPEC_SIFS, 0x100a)?;
    io.write16(REG_SIFS_CTX, 0x100a)?;
    io.write16(REG_SIFS_TRX, 0x100a)?;
    io.write8(0x4c7, 0x80)?;
    io.write8(REG_RX_PKT_LIMIT, 0x20)?;
    io.write16(REG_MAX_AGGR_NUM, 0x1717)?;
    io.write32(REG_MAR, 0xffff_ffff)?;
    io.write32(REG_MAR + 4, 0xffff_ffff)?;
    Ok(())
}

/// `efuse_one_byte_read` (no access gate, at most 100 busy polls; a
/// timed-out read yields `0xff` as Linux).
pub fn efuse_one_byte(io: &impl Io, addr: u16) -> Result<u8, Error> {
    io.write8(REG_EFUSE_CTRL + 1, addr as u8)?;
    let v = io.read8(REG_EFUSE_CTRL + 2)?;
    io.write8(REG_EFUSE_CTRL + 2, ((addr >> 8) as u8 & 0x03) | (v & 0xfc))?;
    io.write8(REG_EFUSE_CTRL + 3, 0x72)?;
    let mut polls = 0;
    while io.read8(REG_EFUSE_CTRL + 3)? & 0x80 == 0 && polls < 100 {
        polls += 1;
    }
    if polls < 100 {
        Ok(io.read8(REG_EFUSE_CTRL)?)
    } else {
        Ok(0xff)
    }
}

/// Retained facts of a configured RTL8192EE radio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    pub phy: phy::Report,
    pub power: Efuse,
    /// `rtlphy->rfreg_chnlval`.
    pub chnlval: [u32; 2],
    pub backup_rf_0x1a: u32,
    pub iqk: iqk::Report,
    pub pa_bias_flags: u8,
}

/// The `rtl92ee_hw_init` steps after the firmware download, for one
/// provisioned, non-BT board.
pub async fn configure(io: &impl Io, adapter: &Adapter, logical: &[u8]) -> Result<Radio, Error> {
    if adapter.bt_coexist {
        return Err(Error::State);
    }
    let power = Efuse::from_logical(logical)?;
    let condition = Condition::from_adapter(adapter);
    let (report, chnlval, backup_rf_0x1a) =
        phy::configure(io, &condition, adapter.crystal_cap).await?;
    hw_configure(io)?;
    io.write32(REG_CAMCMD, (1 << 31) | (1 << 30))?;
    for (i, b) in adapter.mac.iter().copied().enumerate() {
        io.write8(REG_MACID + i as u16, b)?;
    }
    let iqk = iqk::calibrate(io).await?;
    let pa_bias_flags = efuse_one_byte(io, EFUSE_PA_BIAS)?;
    if pa_bias_flags & 1 == 0 {
        set_rf(io, Path::A, 0x15, 0x0f, 0x05).await?;
    }
    if pa_bias_flags & 2 == 0 {
        set_rf(io, Path::B, 0x15, 0x0f, 0x05).await?;
    }
    io.write8(REG_NAV_UPPER, 30000u32.div_ceil(128) as u8)?;
    let swr = io.read32(REG_SYS_SWR_CTRL1)?;
    io.write8(REG_SYS_SWR_CTRL2, 0x75)?;
    io.write32(REG_SYS_SWR_CTRL1, (swr & 0xfff0_0fff) | (0x7e << 12))?;
    io.write32(0x4fc, 0)?;
    Ok(Radio {
        phy: report,
        power,
        chnlval,
        backup_rf_0x1a,
        iqk,
        pa_bias_flags,
    })
}
