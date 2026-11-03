// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE 2.4 GHz band, channel, 20 MHz bandwidth and TXAGC programming.
//!
//! Exact register effects of, in the Linux order (`rtl8821ae_hw_init` band
//! select, then `core.c::rtl_op_config` → `switch_channel` → `set_bw_mode`):
//!
//! - `phy.c::rtl8821ae_phy_switch_wirelessband(BAND_ON_2_4G)` with
//!   `phy_get_tx_swing_8812A` (written to both `RA_TXSCALE` and `RB_TXSCALE`
//!   as Linux does even on this 1T1R chip). The software-only DM swing/OFDM
//!   index bookkeeping has no hardware effect and is not kept.
//! - `rtl8821ae_phy_sw_chnl_callback` (2.4 GHz: `RFC_AREA` 0x96a, RF 0x18
//!   band bits cleared, channel byte) and `rtl8821ae_phy_set_txpower_level`
//!   (per-rate byte RMW of `RTXAGC_A_*`, then `RA_TXPWRTRAING`).
//! - `rtl8821ae_phy_set_bw_mode_callback(HT_CHANNEL_WIDTH_20)` incl.
//!   `_rtl8821ae_phy_set_reg_bw`, `0x483` sub-channel 0, `rtl8812ae_fixspur`
//!   (no effect on 8821A) and `rtl8821ae_phy_rf6052_set_bandwidth` (paths A
//!   and B, as Linux).
//!
//! TXAGC values come only from an admitted [`super::envelope::Permission`].
//! Deviation: Linux computes the training levels in `u32` and lets
//! `MCS7 - 24` wrap; here every level saturates at the Linux floor 2.

use super::envelope::Permission;
use super::phy::{get_bb, set_bb, RHSSIREAD};
use super::txpower;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const RTXPATH: u16 = 0x080c;
pub const ROFDMCCKEN: u16 = 0x0808;
pub const BOFDMEN_BCCKEN: u32 = 0x3000_0000;
pub const RCCK_RX: u16 = 0x0a04;
pub const RA_RFE_PINMUX: u16 = 0x0cb0;
pub const RA_TXSCALE: u16 = 0x0c1c;
pub const RB_TXSCALE: u16 = 0x0e1c;
pub const REG_CCK_CHECK: u16 = 0x0454;
pub const RFC_AREA: u16 = 0x0860;
pub const RRFMOD: u16 = 0x08ac;
pub const RADC_BUF_CLK: u16 = 0x08c4;
pub const RL1PEAKTH: u16 = 0x0848;
pub const REG_TRXPTCL_CTL: u16 = 0x0668;
pub const REG_DATA_SC: u16 = 0x0483;
pub const RTXAGC_A_CCK11_CCK1: u16 = 0x0c20;
pub const RA_TXPWRTRAING: u16 = 0x0c54;
pub const RF_CHNLBW: u32 = 0x18;
/// `RB_LSSIWRITE_8821A`, `RB_PIREAD_8821A`, `RB_SIREAD_8821A`.
pub const RB_LSSIWRITE: u16 = 0x0e90;
pub const RB_PIREAD: u16 = 0x0d44;
pub const RB_SIREAD: u16 = 0x0d48;

/// `_rtl8821ae_phy_rf_serial_{read,write}` + `rtl8821ae_phy_set_rf_reg` on
/// path B (Linux addresses path B even though `num_total_rfpath == 1`).
async fn set_rf_b(io: &impl Io, offset: u32, mask: u32, value: u32) -> Result<(), Error> {
    let pi = get_bb(io, 0x0e00, 0x4)? != 0;
    set_bb(io, RHSSIREAD, 0xff, offset & 0xff)?;
    io.delay_us(20).await;
    let old = get_bb(io, if pi { RB_PIREAD } else { RB_SIREAD }, 0x000f_ffff)?;
    let data = (old & !mask) | (value << mask.trailing_zeros());
    let word = (((offset & 0xff) << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, RB_LSSIWRITE, u32::MAX, word)
}

/// `rtl8821ae_phy_switch_wirelessband(hw, BAND_ON_2_4G)`.
pub fn switch_band_2g(io: &impl Io, swing: u32) -> Result<(), Error> {
    get_bb(io, RTXPATH, 0xf0)?;
    get_bb(io, RCCK_RX, 0x0f00_0000)?;
    set_bb(io, ROFDMCCKEN, BOFDMEN_BCCKEN, 0x3)?;
    set_bb(io, RA_RFE_PINMUX, 0xf000, 0x7)?;
    set_bb(io, RA_RFE_PINMUX, 0xf0, 0x7)?;
    set_bb(io, RA_TXSCALE, 0xf00, 0)?;
    set_bb(io, RTXPATH, 0xf0, 0x1)?;
    set_bb(io, RCCK_RX, 0x0f00_0000, 0x1)?;
    io.write8(REG_CCK_CHECK, 0)?;
    set_bb(io, RA_TXSCALE, 0xffe0_0000, swing)?;
    set_bb(io, RB_TXSCALE, 0xffe0_0000, swing)?;
    Ok(())
}

/// `rtl8821ae_phy_sw_chnl_callback` for a 2.4 GHz channel, path A.
pub async fn sw_chnl(io: &impl Io, channel: u8) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::State);
    }
    set_bb(io, RFC_AREA, 0x1ffe_0000, 0x96a)?;
    let band_bits = (1 << 18) | (1 << 17) | (1 << 16) | (1 << 9) | (1 << 8);
    super::phy::set_rf(io, RF_CHNLBW, band_bits, 0).await?;
    super::phy::set_rf(io, RF_CHNLBW, 0xff, u32::from(channel)).await
}

/// `rtl8821ae_phy_set_txpower_level` on path A from an admitted permission.
pub fn set_txpower(io: &impl Io, permission: &Permission) -> Result<(), Error> {
    for rate in txpower::station_rates() {
        let at = RTXAGC_A_CCK11_CCK1 + u16::from(rate / 4) * 4;
        let mask = 0xffu32 << (u32::from(rate % 4) * 8);
        set_bb(io, at, mask, u32::from(permission.index(rate)))?;
    }
    // _rtl8821ae_phy_txpower_training_by_path: MCS7 - 10, -18, -24, floor 2.
    let mut level = i32::from(permission.index(19));
    let mut data = 0u32;
    for (i, step) in [10, 8, 6].into_iter().enumerate() {
        level -= step;
        data |= (level.max(2) as u32) << (i * 8);
    }
    set_bb(io, RA_TXPWRTRAING, 0x00ff_ffff, data)
}

/// `rtl8821ae_phy_set_bw_mode_callback` for `HT_CHANNEL_WIDTH_20`, 1T1R.
pub async fn set_bw20(io: &impl Io) -> Result<(), Error> {
    let bw = io.read32(REG_TRXPTCL_CTL)? as u16;
    io.write16(REG_TRXPTCL_CTL, bw & 0xfe7f)?;
    io.write8(REG_DATA_SC, 0)?;
    set_bb(io, RRFMOD, 0x0030_03c3, 0x0030_0200)?;
    set_bb(io, RADC_BUF_CLK, 1 << 30, 0)?;
    set_bb(io, RL1PEAKTH, 0x03c0_0000, 8)?;
    // rtl8812ae_fixspur: 8812A-only; no register effect on 8821A.
    super::phy::set_rf(io, RF_CHNLBW, (1 << 11) | (1 << 10), 3).await?;
    set_rf_b(io, RF_CHNLBW, (1 << 11) | (1 << 10), 3).await
}

/// Band select, channel switch with admitted TX power, then 20 MHz.
///
/// Only the 2.4 GHz 20 MHz operating point is programmed here; a 40/80 MHz
/// or 5 GHz permission (whose TXAGC is computed at its wide channel) is
/// refused until its band switch and bandwidth programming exist.
pub async fn configure(io: &impl Io, permission: &Permission) -> Result<(), Error> {
    if permission.operating() != super::envelope::Operating::legacy20(permission.channel()) {
        return Err(Error::State);
    }
    switch_band_2g(io, permission.swing())?;
    sw_chnl(io, permission.channel()).await?;
    set_txpower(io, permission)?;
    set_bw20(io).await
}

/// `rtl8821ae/dm.c` `txscaling_tbl` (`TXSCALE_TABLE_SIZE` 37, -12 dB to
/// +6 dB in 0.5 dB steps).
pub const TXSCALING: [u32; 37] = [
    0x081, 0x088, 0x090, 0x099, 0x0a2, 0x0ac, 0x0b6, 0x0c0, 0x0cc, 0x0d8, 0x0e5, 0x0f2, 0x101,
    0x110, 0x120, 0x131, 0x143, 0x156, 0x16a, 0x180, 0x197, 0x1af, 0x1c8, 0x1e3, 0x200, 0x21e,
    0x23e, 0x261, 0x285, 0x2ab, 0x2d3, 0x2fe, 0x32b, 0x35c, 0x38e, 0x3c4, 0x3fe,
];

/// `rtl8821ae_dm_initialize_txpower_tracking_thermalmeter`
/// `default_ofdm_index`: the table index of the programmed BB swing, 24
/// (0 dB) when it is not a table entry.
pub fn default_ofdm_index(swing: u32) -> u8 {
    TXSCALING
        .iter()
        .position(|&v| v == swing)
        .map_or(24, |i| i as u8)
}

/// `rtl8821ae_dm_txpwr_track_set_pwr` `pwr_tracking_limit` for
/// `rtl8821ae_hw_rate_to_mrate(tx_rate)` (`MGN_*`).
pub fn pwr_tracking_limit(mgn: u8) -> u8 {
    // Linux tests `MGN_1M..=MGN_11M` first as a numeric range, which also
    // covers MGN_6M (0x0c) and MGN_9M (0x12); kept.
    match mgn {
        0x02..=0x16 => 32,
        0x17..=0x60 => 30,
        0x6c => 28,
        0x80..=0x82 => 34,
        0x83..=0x84 => 30,
        0x85..=0x87 => 28,
        0x90..=0x92 => 34,
        0x93..=0x94 => 30,
        0x95..=0x96 => 28,
        0x97 => 26,
        0x98 => 24,
        0x99 => 22,
        _ => 24,
    }
}

/// `rtl8821ae_c2h_ra_report_handler` → `rtl8821ae_dm_update_init_rate`
/// → `rtl8821ae_dm_txpwr_track_set_pwr(MIX_MODE, RF90_PATH_A)` without
/// thermal tracking (`absolute_ofdm_swing_idx` 0, `modify_txagc_flag_path_a`
/// false): the final index is `default_ofdm_index`; within the rate's
/// limit Linux rewrites `RA_TXSCALE[31:21]` with its table value (the swing
/// already programmed). Above the limit Linux would lower the swing and
/// re-run `rtl8821ae_phy_set_txpower_level_by_path` with a remnant; no
/// admitted profile reaches that (only VHT1SS MCS8/9 have a limit below
/// 24), so it is refused.
pub fn update_init_rate(io: &impl Io, swing: u32, hw_rate: u8) -> Result<(), Error> {
    let index = default_ofdm_index(swing);
    let limit = pwr_tracking_limit(super::c2h::hw_rate_to_mrate(hw_rate));
    if index > limit {
        return Err(Error::Packet);
    }
    set_bb(io, RA_TXSCALE, 0xffe0_0000, TXSCALING[usize::from(index)])
}
