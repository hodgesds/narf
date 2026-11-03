// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE 2.4 GHz channel switch and 20/40 MHz bandwidth.
//!
//! `core.c::rtl_op_config` order: `current_chan_bw` and `cur_40_prime_sc`
//! set and the wide channel stored (HT40+ = primary + 2 with
//! `PRIME_CHNL_OFFSET_LOWER`, HT40- = primary - 2 with
//! `PRIME_CHNL_OFFSET_UPPER`), then `rtl92c_phy_sw_chnl` (TX power at the
//! new width, the `RF_CHNLBW` step and its 10 ms delay — the callback stops
//! there; the post-common list is empty), then `rtl92c_phy_set_bw_mode`
//! (`rtl92ce_phy_set_bw_mode_callback`). `set_channel_access` between the
//! two is the MAC owner's.

use super::phy::{
    self, PRIME_CHNL_OFFSET_DONT_CARE, PRIME_CHNL_OFFSET_LOWER, PRIME_CHNL_OFFSET_UPPER,
};
use super::txpower::{self, Efuse};
use super::version::Version;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `nl80211_channel_type` on 2.4 GHz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelType {
    Ht20,
    Ht40Plus,
    Ht40Minus,
}

/// The `rtl_op_config` channel state for one primary channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operating {
    pub primary: u8,
    pub wide: u8,
    pub bw40: bool,
    pub prime_sc: u8,
}

impl Operating {
    /// 2.4 GHz channels 1..=14; a 40 MHz pair must keep the wide channel in
    /// 3..=11 (both halves inside 1..=13). Linux clamps `wide_chan <= 0` to
    /// 1, which never forms a valid pair; such requests are refused.
    pub fn new(primary: u8, kind: ChannelType) -> Result<Self, Error> {
        if !(1..=14).contains(&primary) {
            return Err(Error::State);
        }
        let (wide, bw40, prime_sc) = match kind {
            ChannelType::Ht20 => (primary, false, PRIME_CHNL_OFFSET_DONT_CARE),
            ChannelType::Ht40Plus => (primary + 2, true, PRIME_CHNL_OFFSET_LOWER),
            ChannelType::Ht40Minus => (primary.wrapping_sub(2), true, PRIME_CHNL_OFFSET_UPPER),
        };
        if bw40 && !(3..=11).contains(&wide) {
            return Err(Error::State);
        }
        Ok(Self {
            primary,
            wide,
            bw40,
            prime_sc,
        })
    }
}

/// `switch_channel` then `set_bw_mode` at the wide channel (station path:
/// `act_scanning` false).
pub async fn configure(
    io: &impl Io,
    version: Version,
    efuse: &Efuse,
    pwrgroup_cnt: u8,
    op: &Operating,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    txpower::set_level(
        io,
        efuse,
        version.rf_type(),
        pwrgroup_cnt,
        op.wide,
        op.bw40,
        false,
    )?;
    phy::sw_chnl_rf(io, version, op.wide, op.bw40, chnlval).await?;
    phy::set_bw_mode(io, op.bw40, op.prime_sc, chnlval).await
}
