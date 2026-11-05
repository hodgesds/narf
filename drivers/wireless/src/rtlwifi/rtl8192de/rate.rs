// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE station rate table (`rtl92d_update_hal_rate_table`).
//!
//! Exact Linux `rtl8192d/hw_common.c`: the peer's supported rates
//! (2.4 GHz `supp_rates[0]`, 5 GHz `supp_rates[1] << 4`) plus the HT
//! MCS masks (`rx_mask[1] << 20 | rx_mask[0] << 12`), masked per
//! wireless mode (A `0x00000ff0`, B `0x0000000d` / `0x0000000f`, G
//! `0x00000ff5`, N `0x000ff005` on 1T / `0x0f0ff005` on 2T, default
//! `0x000ff0ff` on 1T2R / `0x0f0ff0ff`), capped to `0x0fffffff`, with
//! short-GI setting BIT(28) when HT is on and the matching SGI cap is
//! set. The result is written to `REG_ARFR0` (`ratr_index` is always
//! 0 on this path).
//!
//! Linux also computes a `shortgi_rate` nibble word from the masked
//! value and then never uses it; that dead computation is not ported.
//!
//! Not this step: `rtl92d_update_hal_rate_mask` — the H2C rate-mask
//! path carrying the multi-station rate-id / MAC-id — which is a
//! later step; `rtl92d_update_hal_rate_tbl` dispatches to it when
//! `useramask` is set.

use super::{Band, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `REG_ARFR0` (`rtl8192d/reg.h`).
pub const REG_ARFR0: u16 = 0x0444;

/// `enum wireless_mode` (`wifi.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirelessMode {
    Unknown,
    A,
    B,
    G,
    N24g,
    N5g,
}

/// The station rate-table inputs (`struct ieee80211_sta` + `rtl_mac`
/// + `rtl_phy` fields `rtl92d_update_hal_rate_table` reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaRates {
    /// `supp_rates[0]` (2.4 GHz) / `supp_rates[1]` (5 GHz).
    pub supp_rates: [u16; 2],
    /// `ht_cap.mcs.rx_mask[0]` / `[1]`.
    pub mcs_rx_mask: [u8; 2],
    pub mode: WirelessMode,
    pub ht_enable: bool,
    pub bw40: bool,
    pub sgi20: bool,
    pub sgi40: bool,
}

/// The `REG_ARFR0` word for `sta` on `band` with `rf_type`, exactly
/// `rtl92d_update_hal_rate_table` (N modes force `nmode`).
pub fn rate_table_value(sta: &StaRates, band: Band, rf_type: RfType) -> u32 {
    let mut ratr_value = match band {
        Band::On5Ghz => u32::from(sta.supp_rates[1]) << 4,
        Band::On2Ghz => u32::from(sta.supp_rates[0]),
    };
    ratr_value |= (u32::from(sta.mcs_rx_mask[1]) << 20) | (u32::from(sta.mcs_rx_mask[0]) << 12);
    let mut nmode = sta.ht_enable;
    match sta.mode {
        WirelessMode::A => ratr_value &= 0x0000_0ff0,
        WirelessMode::B => {
            if ratr_value & 0x0000_000c != 0 {
                ratr_value &= 0x0000_000d;
            } else {
                ratr_value &= 0x0000_000f;
            }
        }
        WirelessMode::G => ratr_value &= 0x0000_0ff5,
        WirelessMode::N24g | WirelessMode::N5g => {
            nmode = true;
            let mask = match rf_type {
                RfType::OneT1R => 0x000f_f005,
                RfType::TwoT2R => 0x0f0f_f005,
            };
            ratr_value &= mask;
        }
        WirelessMode::Unknown => {
            if rf_type == RfType::OneT1R {
                ratr_value &= 0x000f_f0ff;
            } else {
                ratr_value &= 0x0f0f_f0ff;
            }
        }
    }
    ratr_value &= 0x0fff_ffff;
    if nmode && ((sta.bw40 && sta.sgi40) || (!sta.bw40 && sta.sgi20)) {
        ratr_value |= 0x1000_0000;
    }
    ratr_value
}

/// `rtl92d_update_hal_rate_table`: write the `REG_ARFR0` word.
pub fn update_hal_rate_table(
    io: &impl Io,
    sta: &StaRates,
    band: Band,
    rf_type: RfType,
) -> Result<(), Error> {
    io.write32(REG_ARFR0, rate_table_value(sta, band, rf_type))?;
    Ok(())
}
