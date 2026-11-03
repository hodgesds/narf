// SPDX-License-Identifier: GPL-2.0-or-later
//! The `rtl92ce_hw_init` tail after the firmware download.
//!
//! Linux order (`rtl8192ce/hw.c::rtl92ce_hw_init`): `rtl92c_phy_mac_config`,
//! the RCR trim, `rtl92c_phy_bb_config`, `rtl92c_phy_rf_config`, the UMC
//! A-cut 88C / UMC B-cut RF fixups, the `rfreg_chnlval` reads and CCK/OFDM
//! enable ([`super::phy::configure`]); `_rtl92ce_hw_configure`
//! (`mac::hw_configure`); `rtl_cam_reset_all_entry`; software crypto and
//! `HW_VAR_ETHER_ADDR` (`mac::station_identity`); then with `rfpwr_state ==
//! ERFON`: `rtl92c_phy_set_rfpath_switch(1)` (with `is_hal_stop` true),
//! `rtl92c_phy_iq_calibrate(false)` (`iqk_initialized` is false on a fresh
//! owner), `rtl92c_dm_check_txpower_tracking` (no access: `dm.txpower_
//! tracking` is only set by `rtl92c_dm_init`, which runs later) and
//! `rtl92c_phy_lc_calibrate`; then the physical EFUSE byte `0x1FA`
//! (`efuse_read_1byte`): BIT0 clear ⇒ RF A `0x15[3:0] = 5`, BIT1 clear on
//! 92C ⇒ RF B, BIT4 clear ⇒ the "under 1.5V" `0x16` writes.
//!
//! Not issued: `_rtl92ce_enable_aspm_back_door` / `enable_aspm` (ASPM stays
//! disabled), `rtl8192ce_bt_hw_init` (BT boards are refused before any
//! write). `rtl92c_dm_init` is software state for the DM owner. No APK runs
//! (Linux runs none on this family).

use super::adapter::Adapter;
use super::iqk;
use super::phy::{self, set_rf, Path};
use super::txpower::Efuse;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_EFUSE_CTRL: u16 = 0x0030;
pub const REG_CAMCMD: u16 = 0x0670;
/// `efuse_read_1byte` address of the PA-bias / regulator flags.
pub const EFUSE_PA_BIAS: u16 = 0x01fa;
/// `EFUSE_REAL_CONTENT_LEN`.
pub const EFUSE_REAL_CONTENT_LEN: u16 = 512;

/// `efuse.c::efuse_read_1byte` (up to 1000 polls of `EFUSE_CTRL+3`
/// BIT(7); the data byte is read even after a timeout, as Linux).
pub fn efuse_read_1byte(io: &impl Io, addr: u16) -> Result<u8, Error> {
    if addr >= EFUSE_REAL_CONTENT_LEN {
        return Ok(0xff);
    }
    io.write8(REG_EFUSE_CTRL + 1, addr as u8)?;
    let v = io.read8(REG_EFUSE_CTRL + 2)?;
    io.write8(REG_EFUSE_CTRL + 2, ((addr >> 8) as u8 & 0x03) | (v & 0xfc))?;
    let v = io.read8(REG_EFUSE_CTRL + 3)?;
    io.write8(REG_EFUSE_CTRL + 3, v & 0x7f)?;
    let mut v = io.read8(REG_EFUSE_CTRL + 3)?;
    let mut k = 0u32;
    while v & 0x80 == 0 {
        v = io.read8(REG_EFUSE_CTRL + 3)?;
        k += 1;
        if k == 1000 {
            break;
        }
    }
    Ok(io.read8(REG_EFUSE_CTRL)?)
}

/// Retained facts of a configured RTL8192CE / RTL8188CE radio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    pub version: super::version::Version,
    pub phy: phy::Report,
    pub power: Efuse,
    /// `rtlphy->rfreg_chnlval`.
    pub chnlval: [u32; 2],
    pub iqk: iqk::Report,
    pub efuse_0x1fa: u8,
}

/// The `rtl92ce_hw_init` steps after the firmware download, for one
/// provisioned, non-BT board whose version was qualified by the adapter
/// decode.
pub async fn configure(io: &impl Io, adapter: &Adapter) -> Result<Radio, Error> {
    if adapter.bt_coexistence() {
        return Err(Error::State);
    }
    let version = adapter.version;
    let power = Efuse::from_hwinfo(&adapter.hwinfo)?;
    let (report, chnlval) = phy::configure(io, version).await?;
    super::mac::hw_configure(io)?;
    io.write32(REG_CAMCMD, (1 << 31) | (1 << 30))?;
    super::mac::station_identity(io, &adapter.mac)?;
    phy::rfpath_switch_main(io, version)?;
    let iqk = iqk::calibrate(io, version).await?;
    phy::lc_calibrate(io, version).await?;
    let flags = efuse_read_1byte(io, EFUSE_PA_BIAS)?;
    if flags & 1 == 0 {
        set_rf(io, Path::A, 0x15, 0x0f, 0x05).await?;
    }
    if flags & 2 == 0 && version.is_92c_serial() {
        set_rf(io, Path::B, 0x15, 0x0f, 0x05).await?;
    }
    if flags & (1 << 4) == 0 {
        let v = io.read8(0x16)? & 0x0f;
        io.write8(0x16, v | 0x80)?;
        io.delay_us(10).await;
        io.write8(0x16, v | 0x90)?;
    }
    Ok(Radio {
        version,
        phy: report,
        power,
        chnlval,
        iqk,
        efuse_0x1fa: flags,
    })
}
