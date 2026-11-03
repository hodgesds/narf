// SPDX-License-Identifier: GPL-2.0-or-later
//! The `rtl8723be_hw_init` tail after the firmware download.
//!
//! Linux order (`rtl8723be/hw.c`): the `_rtl8723be_init_mac` post-LLT
//! segment (Linux issues it before the download; the retained owner keeps
//! it after the ring publication, as for RTL8821AE), then from
//! `rtl8723be_hw_init`: `rtl8723be_phy_mac_config`, the RCR trim,
//! `rtl8723be_phy_bb_config`, `rtl8723be_phy_rf_config`, the
//! `rfreg_chnlval` reads, `_rtl8723be_hw_configure`,
//! `rtl_cam_reset_all_entry`, software crypto and `HW_VAR_ETHER_ADDR`.
//! Not issued here: `_rtl8723be_enable_aspm_back_door` / `enable_aspm`
//! (ASPM stays disabled), `rtl8723be_bt_hw_init` and the `ERFON`
//! RF-path / IQK / LCK block (later owner steps).

use super::adapter::Adapter;
use super::phy::{self, Condition};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `REG_CAMCMD` (`rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)`).
pub const REG_CAMCMD: u16 = 0x0670;

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
}

/// The `rtl8723be_hw_init` steps after the firmware download for one
/// provisioned board.
pub async fn configure(io: &impl Io, adapter: &Adapter) -> Result<Radio, Error> {
    super::mac::init_mac_post_llt(io)?;
    phy::mac_config(io, &Condition::from_adapter(adapter))?;
    let receive_config = super::mac::trim_receive_config(io)?;
    let cck_high_power = phy::bb_config(io, adapter).await?;
    phy::rf_config(io, adapter).await?;
    let chnlval = phy::read_chnlval(io).await?;
    super::mac::hw_configure(io)?;
    io.write32(REG_CAMCMD, (1 << 31) | (1 << 30))?;
    super::mac::station_identity(io, &adapter.mac)?;
    Ok(Radio {
        adapter: *adapter,
        cck_high_power,
        chnlval,
        receive_config,
    })
}
