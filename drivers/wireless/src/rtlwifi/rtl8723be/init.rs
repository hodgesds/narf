// SPDX-License-Identifier: GPL-2.0-or-later
//! The `rtl8723be_hw_init` tail after the firmware download.
//!
//! Linux order (`rtl8723be/hw.c`): the `_rtl8723be_init_mac` post-LLT
//! segment (Linux issues it before the download; the retained owner keeps
//! it after the ring publication, as for RTL8821AE), then from
//! `rtl8723be_hw_init`: `rtl8723be_phy_mac_config`, the RCR trim,
//! `rtl8723be_phy_bb_config`, `rtl8723be_phy_rf_config`, the
//! `rfreg_chnlval` reads, `_rtl8723be_hw_configure`,
//! `rtl_cam_reset_all_entry`, software crypto and `HW_VAR_ETHER_ADDR`,
//! then the `ERFON` block: `rtl8723be_phy_set_rfpath_switch(hw, 1)`,
//! `rtl8723be_phy_iq_calibrate(hw, false)` unless the board is `ANT_X1`
//! ([`super::iqk::required`]), `rtl8723be_phy_lc_calibrate`,
//! `REG_NAV_UPPER = (30000 + 127) / 128` and the conditional
//! `REG_RXDMA_CONTROL` BIT2 release.
//!
//! Not issued here: `_rtl8723be_enable_aspm_back_door` / `enable_aspm`
//! (ASPM stays disabled), `rtl8723be_bt_hw_init` (the coexistence owner,
//! before the `ERFON` block), `rtl8723be_dm_check_txpower_tracking` (a
//! no-op on the first `hw_init`: `dm.txpower_tracking` is only set by the
//! trailing `rtl8723be_dm_init`), `REG_PCIE_CTRL_REG + 1 = 0` (the packet
//! owner releases PCIe DMA, as for RTL8821AE) and `rtl8723be_dm_init`.

use super::adapter::Adapter;
use super::phy::{self, Condition};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `REG_CAMCMD` (`rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)`).
pub const REG_CAMCMD: u16 = 0x0670;
pub const REG_RXDMA_CONTROL: u16 = 0x0286;
pub const REG_NAV_UPPER: u16 = 0x0652;
/// `(WIFI_NAV_UPPER_US + HAL_92C_NAV_UPPER_UNIT - 1) / HAL_92C_NAV_UPPER_UNIT`.
pub const NAV_UPPER: u8 = 235;

/// Retained facts of a configured RTL8723BE radio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    pub adapter: Adapter,
    /// `rtlphy->cck_high_power`.
    pub cck_high_power: bool,
    /// `rtlphy->rfreg_chnlval`.
    pub chnlval: [u32; 2],
    /// `rtlpci->receive_config` after the `rtl8723be_phy_mac_config` trim.
    pub receive_config: u32,
    /// Path-A EFUSE power facts (`_rtl8723be_read_txpower_info_from_hwpg`).
    pub efuse: super::txpower::Efuse,
    /// The PHY_REG_PG by-rate store.
    pub by_rate: super::txpower::ByRate,
    /// The `ERFON` IQK outcome (`None` on `ANT_X1` boards, where Linux skips it).
    pub iqk: Option<super::iqk::Report>,
}

/// The `rtl8723be_hw_init` steps after the firmware download for one
/// provisioned board.
pub async fn configure(
    io: &impl Io,
    adapter: &Adapter,
    efuse: super::txpower::Efuse,
) -> Result<Radio, Error> {
    super::mac::init_mac_post_llt(io)?;
    phy::mac_config(io, &Condition::from_adapter(adapter))?;
    let receive_config = super::mac::trim_receive_config(io)?;
    let cck_high_power = phy::bb_config(io, adapter).await?;
    phy::rf_config(io, adapter).await?;
    let chnlval = phy::read_chnlval(io).await?;
    super::mac::hw_configure(io)?;
    io.write32(REG_CAMCMD, (1 << 31) | (1 << 30))?;
    super::mac::station_identity(io, &adapter.mac)?;
    super::channel::set_rfpath_switch(io, true)?;
    let iqk = if super::iqk::required(adapter) {
        Some(super::iqk::calibrate(io).await?)
    } else {
        None
    };
    super::channel::lc_calibrate(io).await?;
    io.write8(REG_NAV_UPPER, NAV_UPPER)?;
    let rxdma = io.read8(REG_RXDMA_CONTROL)?;
    if rxdma & (1 << 2) != 0 {
        io.write8(REG_RXDMA_CONTROL, rxdma & !(1 << 2))?;
    }
    Ok(Radio {
        adapter: *adapter,
        cck_high_power,
        chnlval,
        receive_config,
        efuse,
        by_rate: super::txpower::ByRate::from_table(),
        iqk,
    })
}
