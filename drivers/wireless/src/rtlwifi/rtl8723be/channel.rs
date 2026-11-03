// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE RF-path switch, LC calibration, bandwidth and channel RF
//! programming.
//!
//! Exact Linux `rtl8723be/{phy,rf}.c` register effects:
//!
//! - `_rtl8723be_phy_set_rfpath_switch` (`0x92C = 1` main / left antenna,
//!   `2` aux), reached through `rtl8723be_phy_set_rfpath_switch`.
//! - `_rtl8723be_phy_lc_calibrate(hw, false)`: `0xd03[6:4]` decides between
//!   the continuous-TX save (RF 0x00 MASK12BITS RMW) and `REG_TXPAUSE =
//!   0xff`; the discarded `RF 0x18` read, `RF 0xb0 = 0xdfbe0`, `RF 0x18
//!   MASK12BITS = 0x8c0a`, 50 ms, `RF 0xb0 = 0xdffe0`, then the restore.
//!   `rtl8723be_phy_lc_calibrate`'s scan wait never runs: the retained owner
//!   is not scanning while it calibrates.
//! - `rtl8723be_phy_set_bw_mode_callback` + `rtl8723be_phy_rf6052_set_bandwidth`.
//! - The `CMDID_RF_WRITEREG` step of `_rtl8723be_phy_sw_chnl_step_by_step`
//!   (`RF_CHNLBW[9:0] = channel` on path A, `num_total_rfpath` 1, then
//!   10 ms). The preceding `CMDID_SET_TXPOWEROWER_LEVEL` step belongs to the
//!   admitted-power owner and is issued by the caller first.

use super::phy::{get_rf, set_bb, set_rf, Path, MASKDWORD, RFREG_OFFSET_MASK, RF_CHNLBW};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_RRSR: u16 = 0x0440;
pub const REG_TXPAUSE: u16 = 0x0522;
pub const REG_BWOPMODE: u16 = 0x0603;
/// `BW_OPMODE_20MHZ`.
pub const BW_OPMODE_20MHZ: u8 = 1 << 2;
pub const RFPGA0_RFMOD: u16 = 0x0800;
pub const RFPGA1_RFMOD: u16 = 0x0900;
pub const RCCK0_SYSTEM: u16 = 0x0a00;
pub const ROFDM1_LSTF: u16 = 0x0d00;
pub const BRFMOD: u32 = 0x1;
pub const BCCK_SIDEBAND: u32 = 0x10;
pub const MASK12BITS: u32 = 0xfff;
/// `0x92C`: the S0/S1 antenna select `_rtl8723be_phy_set_rfpath_switch` writes.
pub const REG_RFPATH_SWITCH: u16 = 0x092c;
/// `HAL_PRIME_CHNL_OFFSET_LOWER`.
pub const PRIME_CHNL_OFFSET_LOWER: u8 = 1;

/// `rtl8723be_phy_set_rfpath_switch(hw, bmain)`.
pub fn set_rfpath_switch(io: &impl Io, main: bool) -> Result<(), Error> {
    set_bb(io, REG_RFPATH_SWITCH, MASKDWORD, if main { 1 } else { 2 })
}

/// `_rtl8723be_phy_lc_calibrate(hw, false)`.
pub async fn lc_calibrate(io: &impl Io) -> Result<(), Error> {
    let tmpreg = io.read8(0xd03)?;
    let continuous = tmpreg & 0x70 != 0;
    let mut rf_a_mode = 0;
    if continuous {
        io.write8(0xd03, tmpreg & 0x8f)?;
        rf_a_mode = get_rf(io, Path::A, 0x00, MASK12BITS).await?;
        set_rf(
            io,
            Path::A,
            0x00,
            MASK12BITS,
            (rf_a_mode & 0x8ffff) | 0x10000,
        )
        .await?;
    } else {
        io.write8(REG_TXPAUSE, 0xff)?;
    }
    get_rf(io, Path::A, 0x18, MASK12BITS).await?;
    set_rf(io, Path::A, 0xb0, RFREG_OFFSET_MASK, 0xdfbe0).await?;
    set_rf(io, Path::A, 0x18, MASK12BITS, 0x8c0a).await?;
    io.delay_us(50_000).await;
    set_rf(io, Path::A, 0xb0, RFREG_OFFSET_MASK, 0xdffe0).await?;
    if continuous {
        io.write8(0xd03, tmpreg)?;
        set_rf(io, Path::A, 0x00, MASK12BITS, rf_a_mode).await?;
    } else {
        io.write8(REG_TXPAUSE, 0x00)?;
    }
    Ok(())
}

/// `rtl8723be_phy_set_bw_mode_callback` with `rtl8723be_phy_rf6052_set_bandwidth`.
/// `prime_sc` is `mac->cur_40_prime_sc` (only read at 40 MHz). Updates the
/// retained `rfreg_chnlval[0]`.
pub async fn set_bw_mode(
    io: &impl Io,
    forty: bool,
    prime_sc: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    let opmode = io.read8(REG_BWOPMODE)?;
    let prsr_rsc = io.read8(REG_RRSR + 2)?;
    if forty {
        io.write8(REG_BWOPMODE, opmode & !BW_OPMODE_20MHZ)?;
        io.write8(REG_RRSR + 2, (prsr_rsc & 0x90) | (prime_sc << 5))?;
        set_bb(io, RFPGA0_RFMOD, BRFMOD, 0x1)?;
        set_bb(io, RFPGA1_RFMOD, BRFMOD, 0x1)?;
        set_bb(io, RCCK0_SYSTEM, BCCK_SIDEBAND, u32::from(prime_sc >> 1))?;
        set_bb(io, ROFDM1_LSTF, 0xc00, u32::from(prime_sc))?;
        let sc = if prime_sc == PRIME_CHNL_OFFSET_LOWER {
            2
        } else {
            1
        };
        set_bb(io, 0x818, (1 << 26) | (1 << 27), sc)?;
        chnlval[0] = (chnlval[0] & 0xffff_f3ff) | (1 << 10);
    } else {
        io.write8(REG_BWOPMODE, opmode | BW_OPMODE_20MHZ)?;
        set_bb(io, RFPGA0_RFMOD, BRFMOD, 0x0)?;
        set_bb(io, RFPGA1_RFMOD, BRFMOD, 0x0)?;
        chnlval[0] = (chnlval[0] & 0xffff_f3ff) | (1 << 10) | (1 << 11);
    }
    set_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await
}

/// The `CMDID_RF_WRITEREG` stage of `_rtl8723be_phy_sw_chnl_step_by_step`
/// for a 2.4 GHz channel 1..=14 and its 10 ms command delay.
pub async fn switch_channel_rf(
    io: &impl Io,
    channel: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::State);
    }
    chnlval[0] = (chnlval[0] & 0xffff_fc00) | u32::from(channel);
    set_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await?;
    io.delay_us(10_000).await;
    Ok(())
}

/// One permitted RTL8723BE operating point: the switched channel
/// (`rtlphy->current_channel`, the wide channel at 40 MHz), the width, the
/// 40 MHz `cur_40_prime_sc` and the path-A TXAGC indices for every
/// [`super::txpower::RATES`] entry. Minted only through [`Grant::bounded`],
/// which caps every index at the Linux `_rtl8723be_get_txpower_index` value
/// for this board, width and channel; the caller (the signed per-board
/// envelope) supplies the measured indices. The indices are computed at the
/// operating width (Linux's `switch_channel` runs before `set_bw_mode` and
/// therefore uses the previous width; the operating width is the one the
/// envelope measures).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    identity: [u8; 32],
    channel: u8,
    forty: bool,
    prime_sc: u8,
    indices: [u8; 20],
}

impl Grant {
    /// `indices` must not exceed the Linux index of any rate. At 40 MHz the
    /// channel is the wide channel 3..=12 with `prime_sc` 1 (lower) or 2
    /// (upper); at 20 MHz any channel 1..=14 with `prime_sc` 0.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bounded(
        identity: [u8; 32],
        efuse: &super::txpower::Efuse,
        by_rate: &super::txpower::ByRate,
        regulatory: u8,
        channel: u8,
        forty: bool,
        prime_sc: u8,
        indices: [u8; 20],
    ) -> Result<Self, Error> {
        let shape = if forty {
            (3..=12).contains(&channel) && matches!(prime_sc, 1 | 2)
        } else {
            (1..=14).contains(&channel) && prime_sc == 0
        };
        let linux = super::txpower::linux_indices(efuse, by_rate, regulatory, forty, channel);
        if !shape || indices.iter().zip(linux).any(|(i, l)| *i > l) {
            return Err(Error::State);
        }
        Ok(Self {
            identity,
            channel,
            forty,
            prime_sc,
            indices,
        })
    }

    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub const fn channel(&self) -> u8 {
        self.channel
    }
    pub const fn forty(&self) -> bool {
        self.forty
    }
    pub const fn prime_sc(&self) -> u8 {
        self.prime_sc
    }
    pub const fn indices(&self) -> &[u8; 20] {
        &self.indices
    }
}

/// `rtl_op_config` channel change for a [`Grant`]: `rtl8723be_phy_sw_chnl`
/// (the granted TXAGC indices in place of `rtl8723be_phy_set_txpower_level`,
/// then the RF channel step) and `rtl8723be_phy_set_bw_mode`.
pub async fn configure(io: &impl Io, grant: &Grant, chnlval: &mut [u32; 2]) -> Result<(), Error> {
    super::txpower::set_indices(io, grant.indices())?;
    switch_channel_rf(io, grant.channel(), chnlval).await?;
    set_bw_mode(io, grant.forty(), grant.prime_sc(), chnlval).await
}
