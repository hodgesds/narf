// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE TX power from the factory (EFUSE) map and the factory
//! power-group table.
//!
//! - [`TxPowerInfo::from_prom`] — `_rtl92d_readpowervalue_fromprom`
//!   (`rtl8192d/hw_common.c`): the per-group CCK / HT40-1S / HT40-2S
//!   diff / HT20 diff / OFDM diff / HT40-max / HT20-max nibbles over
//!   the 12 channel groups, plus the 5G TSSI triplet. The 2G/5G
//!   default follows the EFUSE address (`eeaddr > 0x7b` ⇒ 5G).
//! - [`Efuse::from_hwinfo`] — `_rtl92d_read_txpower_info`: the
//!   per-channel `[path][channel]` expansion
//!   (`rtl92d_get_chnlgroup_fromarray`), `ht40_2s = max(ht40_1s -
//!   2sdiff, 0)`, regulatory `RF_OPT1[2:0]`, thermal `[4:0]` clamped
//!   to `0x06..=0x1c` (else `0x12`), crystal cap (`0xff` ⇒ 0),
//!   IQK/LCK deltas (`0→5, 1→4, 2→3, else 0`; LCK minus one when
//!   nonzero), `internal_pa_5g` from the TSSI 5G bytes' BIT(6) on D/E
//!   cuts only, `eeprom_c9` / `eeprom_cc` (`0xff` ⇒ 0 for C9).
//! - [`set_level`] — `rtl92d_phy_set_txpower_level`
//!   (`rtl8192d/phy_common.c`): the channel-place remap, CCK only on
//!   2.4 GHz, OFDM from `ht40_1s` for `RF_1T1R` / `ht40_2s` for
//!   `RF_2T2R`, then `rtl92d_phy_rf6052_set_cck_txpower` and
//!   `rtl92d_phy_rf6052_set_ofdm_txpower` (`rtl8192d/rf_common.c`):
//!   `rtl92d_phy_get_power_base`, `_rtl92d_get_txpower_writeval_by_
//!   regulatory`, `_rtl92d_write_ofdm_power_reg` incl. the `0xc90` /
//!   `0xc98` byte tail (`-8, -8, -6`). The `mcs_offset` the regulatory
//!   paths read is the factory table [`super::phy::PgStore`].
//!
//! Deliberate difference from the sibling 92CE port: Linux's
//! `rtl_set_bbreg` does not re-mask the shifted value, so the CCK
//! write carries the third AGC byte (path-A CCK 11M) at bits 24–31 of
//! `RTXAGC_B_CCK11_A_CCK2_11`; the 92CE port's `0xff00ffff` mask
//! zeroes it, which Linux does not do. [`linux_indices`] keeps that
//! byte here.
//!
//! `dynamic_txhighpower_lvl` never applies on this family (BT boards
//! are never admitted), so those subtractions are absent. The 5 GHz
//! envelope rows are a later step; the per-rate indices here are the
//! Linux bytes, not envelope-admitted ones.

use super::channel::{chnlgroup_fromarray, rightchnlplace};
use super::phy::{
    self, PgStore, RTXAGC_A_CCK1_MCS32, RTXAGC_A_MCS03_MCS00, RTXAGC_A_MCS07_MCS04,
    RTXAGC_A_MCS11_MCS08, RTXAGC_A_MCS15_MCS12, RTXAGC_A_RATE18_06, RTXAGC_A_RATE54_24,
    RTXAGC_B_CCK11_A_CCK2_11, RTXAGC_B_CCK1_55_MCS32, RTXAGC_B_MCS03_MCS00, RTXAGC_B_MCS07_MCS04,
    RTXAGC_B_MCS11_MCS08, RTXAGC_B_MCS15_MCS12, RTXAGC_B_RATE18_06, RTXAGC_B_RATE54_24,
};
use super::{Band, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `reg.h` EEPROM offsets.
pub const EEPROM_CCK_TX_PWR_INX_2G: usize = 0x61;
pub const EEPROM_HT40_1S_TX_PWR_INX_2G: usize = 0x67;
pub const EEPROM_HT40_2S_TX_PWR_INX_DIFF_2G: usize = 0x6d;
pub const EEPROM_HT20_TX_PWR_INX_DIFF_2G: usize = 0x70;
pub const EEPROM_OFDM_TX_PWR_INX_DIFF_2G: usize = 0x73;
pub const EEPROM_HT40_MAX_PWR_OFFSET_2G: usize = 0x76;
pub const EEPROM_HT20_MAX_PWR_OFFSET_2G: usize = 0x79;
pub const EEPROM_IQK_DELTA: usize = 0xbc;
pub const EEPROM_LCK_DELTA: usize = 0xbc;
pub const EEPROM_XTAL_K: usize = 0xbd;
pub const EEPROM_TSSI_A_5G: usize = 0xbe;
pub const EEPROM_TSSI_B_5G: usize = 0xbf;
pub const EEPROM_TSSI_AB_5G: usize = 0xc0;
pub const EEPROM_THERMAL_METER: usize = 0xc3;
pub const EEPROM_RF_OPT1: usize = 0xc4;
pub const EEPROM_RF_OPT6: usize = 0xc9;
pub const EEPROM_RF_OPT7: usize = 0xcc;

pub const EEPROM_DEFAULT_TXPOWERLEVEL_2G: u8 = 0x2c;
pub const EEPROM_DEFAULT_TXPOWERLEVEL_5G: u8 = 0x22;
pub const EEPROM_DEFAULT_HT40_2SDIFF: u8 = 0x0;
pub const EEPROM_DEFAULT_HT20_DIFF: u8 = 2;
pub const EEPROM_DEFAULT_LEGACYHTTXPOWERDIFF: u8 = 0x4;
pub const EEPROM_DEFAULT_HT40_PWRMAXOFFSET: u8 = 0;
pub const EEPROM_DEFAULT_HT20_PWRMAXOFFSET: u8 = 0;
pub const EEPROM_DEFAULT_TSSI: u8 = 0x0;
pub const EEPROM_DEFAULT_THERMALMETER: u8 = 0x12;
pub const EEPROM_DEFAULT_CRYSTALCAP: u8 = 0x0;

/// `RF6052_MAX_TX_PWR`.
pub const MAX_TX_PWR: u8 = 0x3f;

/// `CHANNEL_MAX_NUMBER` (`wifi.h`): 14 + 24 + 21.
pub const CHANNEL_MAX_NUMBER: usize = 59;
/// `CHANNEL_MAX_NUMBER_2G`.
pub const CHANNEL_MAX_NUMBER_2G: usize = 14;
/// `CHANNEL_GROUP_MAX` (`wifi.h`).
pub const CHANNEL_GROUP_MAX: usize = 12;
/// `CHANNEL_GROUP_MAX_2G`.
pub const CHANNEL_GROUP_MAX_2G: usize = 3;

/// `struct txpower_info` (`rtl8192d/def.h`): per-group factory values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPowerInfo {
    pub cck_index: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ht40_1sindex: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ht40_2sindexdiff: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ht20indexdiff: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ofdmindexdiff: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ht40maxoffset: [[u8; CHANNEL_GROUP_MAX]; 2],
    pub ht20maxoffset: [[u8; CHANNEL_GROUP_MAX]; 2],
    /// 5GL / 5GM / 5GH.
    pub tssi_a: [u8; 3],
    pub tssi_b: [u8; 3],
}

impl TxPowerInfo {
    /// `_rtl92d_readpowervalue_fromprom` over the `HWSET_MAX_SIZE`
    /// (256-byte) EFUSE map. `autoload_fail` takes the defaults branch.
    pub fn from_prom(efuse: &[u8], autoload_fail: bool) -> Result<Self, Error> {
        if efuse.len() <= EEPROM_RF_OPT7 {
            return Err(Error::Descriptor);
        }
        let mut out = Self {
            cck_index: [[0; CHANNEL_GROUP_MAX]; 2],
            ht40_1sindex: [[0; CHANNEL_GROUP_MAX]; 2],
            ht40_2sindexdiff: [[0; CHANNEL_GROUP_MAX]; 2],
            ht20indexdiff: [[0; CHANNEL_GROUP_MAX]; 2],
            ofdmindexdiff: [[0; CHANNEL_GROUP_MAX]; 2],
            ht40maxoffset: [[0; CHANNEL_GROUP_MAX]; 2],
            ht20maxoffset: [[0; CHANNEL_GROUP_MAX]; 2],
            tssi_a: [0; 3],
            tssi_b: [0; 3],
        };
        if autoload_fail {
            for group in 0..CHANNEL_GROUP_MAX {
                for rfpath in 0..2 {
                    if group < CHANNEL_GROUP_MAX_2G {
                        out.cck_index[rfpath][group] = EEPROM_DEFAULT_TXPOWERLEVEL_2G;
                        out.ht40_1sindex[rfpath][group] = EEPROM_DEFAULT_TXPOWERLEVEL_2G;
                    } else {
                        out.ht40_1sindex[rfpath][group] = EEPROM_DEFAULT_TXPOWERLEVEL_5G;
                    }
                    out.ht40_2sindexdiff[rfpath][group] = EEPROM_DEFAULT_HT40_2SDIFF;
                    out.ht20indexdiff[rfpath][group] = EEPROM_DEFAULT_HT20_DIFF;
                    out.ofdmindexdiff[rfpath][group] = EEPROM_DEFAULT_LEGACYHTTXPOWERDIFF;
                    out.ht40maxoffset[rfpath][group] = EEPROM_DEFAULT_HT40_PWRMAXOFFSET;
                    out.ht20maxoffset[rfpath][group] = EEPROM_DEFAULT_HT20_PWRMAXOFFSET;
                }
            }
            for i in 0..3 {
                out.tssi_a[i] = EEPROM_DEFAULT_TSSI;
                out.tssi_b[i] = EEPROM_DEFAULT_TSSI;
            }
            return Ok(out);
        }
        for rfpath in 0..2 {
            for group in 0..CHANNEL_GROUP_MAX_2G {
                let eeaddr = EEPROM_CCK_TX_PWR_INX_2G + rfpath * 3 + group;
                out.cck_index[rfpath][group] = if efuse[eeaddr] == 0xff {
                    if eeaddr > 0x7b {
                        EEPROM_DEFAULT_TXPOWERLEVEL_5G
                    } else {
                        EEPROM_DEFAULT_TXPOWERLEVEL_2G
                    }
                } else {
                    efuse[eeaddr]
                };
            }
        }
        for rfpath in 0..2 {
            for group in 0..CHANNEL_GROUP_MAX {
                let offset1 = group / 3;
                let offset2 = group % 3;
                let eeaddr = EEPROM_HT40_1S_TX_PWR_INX_2G + rfpath * 3 + offset2 + offset1 * 21;
                out.ht40_1sindex[rfpath][group] = if efuse[eeaddr] == 0xff {
                    if eeaddr > 0x7b {
                        EEPROM_DEFAULT_TXPOWERLEVEL_5G
                    } else {
                        EEPROM_DEFAULT_TXPOWERLEVEL_2G
                    }
                } else {
                    efuse[eeaddr]
                };
            }
        }
        for group in 0..CHANNEL_GROUP_MAX {
            for rfpath in 0..2 {
                let offset1 = group / 3;
                let offset2 = group % 3;
                let offset = offset2 + offset1 * 21;
                let diff = |base: usize, default: u8| {
                    let v = efuse[base + offset];
                    if v != 0xff {
                        (v >> (rfpath * 4)) & 0xf
                    } else {
                        default
                    }
                };
                out.ht40_2sindexdiff[rfpath][group] = diff(
                    EEPROM_HT40_2S_TX_PWR_INX_DIFF_2G,
                    EEPROM_DEFAULT_HT40_2SDIFF,
                );
                out.ht20indexdiff[rfpath][group] =
                    diff(EEPROM_HT20_TX_PWR_INX_DIFF_2G, EEPROM_DEFAULT_HT20_DIFF);
                out.ofdmindexdiff[rfpath][group] = diff(
                    EEPROM_OFDM_TX_PWR_INX_DIFF_2G,
                    EEPROM_DEFAULT_LEGACYHTTXPOWERDIFF,
                );
                out.ht40maxoffset[rfpath][group] = diff(
                    EEPROM_HT40_MAX_PWR_OFFSET_2G,
                    EEPROM_DEFAULT_HT40_PWRMAXOFFSET,
                );
                out.ht20maxoffset[rfpath][group] = diff(
                    EEPROM_HT20_MAX_PWR_OFFSET_2G,
                    EEPROM_DEFAULT_HT20_PWRMAXOFFSET,
                );
            }
        }
        if efuse[EEPROM_TSSI_A_5G] != 0xff {
            out.tssi_a[0] = efuse[EEPROM_TSSI_A_5G] & 0x3f;
            out.tssi_b[0] = efuse[EEPROM_TSSI_B_5G] & 0x3f;
            out.tssi_a[1] = efuse[EEPROM_TSSI_AB_5G] & 0x3f;
            out.tssi_b[1] =
                (efuse[EEPROM_TSSI_AB_5G] & 0xc0) >> 6 | (efuse[EEPROM_TSSI_AB_5G + 1] & 0x0f) << 2;
            out.tssi_a[2] = (efuse[EEPROM_TSSI_AB_5G + 1] & 0xf0) >> 4
                | (efuse[EEPROM_TSSI_AB_5G + 2] & 0x03) << 4;
            out.tssi_b[2] = (efuse[EEPROM_TSSI_AB_5G + 2] & 0xfc) >> 2;
        } else {
            for i in 0..3 {
                out.tssi_a[i] = EEPROM_DEFAULT_TSSI;
                out.tssi_b[i] = EEPROM_DEFAULT_TSSI;
            }
        }
        Ok(out)
    }
}

/// `rtlefuse` TX-power fields, `[path][channel place - 1]` over the 59
/// places of [`super::channel::CHANNEL_ALL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efuse {
    pub cck: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub ht40_1s: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub ht40_2s: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub ht20_diff: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub legacy_ht_diff: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub pwrgroup_ht20: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub pwrgroup_ht40: [[u8; CHANNEL_MAX_NUMBER]; 2],
    pub regulatory: u8,
    pub thermalmeter: u8,
    pub crystalcap: u8,
    pub delta_iqk: u8,
    pub delta_lck: u8,
    pub internal_pa_5g: [bool; 2],
    pub eeprom_c9: u8,
    pub eeprom_cc: u8,
    pub txpwr_fromeprom: bool,
    pub tssi_a: [u8; 3],
    pub tssi_b: [u8; 3],
}

impl Efuse {
    /// `_rtl92d_read_txpower_info(hw, autoload_fail, hwinfo)`.
    /// `d_or_e_cut` is the EFUSE chip-version cut (D/E cuts read
    /// `internal_pa_5g` from the TSSI 5G bytes' BIT(6)); the cut
    /// decode is [`super::version::read_cut`].
    pub fn from_hwinfo(hw: &[u8], autoload_fail: bool, d_or_e_cut: bool) -> Result<Self, Error> {
        let pwrinfo = TxPowerInfo::from_prom(hw, autoload_fail)?;
        let mut out = Self {
            cck: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht40_1s: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht40_2s: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht20_diff: [[0; CHANNEL_MAX_NUMBER]; 2],
            legacy_ht_diff: [[0; CHANNEL_MAX_NUMBER]; 2],
            pwrgroup_ht20: [[0; CHANNEL_MAX_NUMBER]; 2],
            pwrgroup_ht40: [[0; CHANNEL_MAX_NUMBER]; 2],
            regulatory: 0,
            thermalmeter: 0,
            crystalcap: 0,
            delta_iqk: 0,
            delta_lck: 0,
            internal_pa_5g: [false; 2],
            eeprom_c9: 0,
            eeprom_cc: 0,
            txpwr_fromeprom: false,
            tssi_a: pwrinfo.tssi_a,
            tssi_b: pwrinfo.tssi_b,
        };
        let mut tempval = [0u8; 2];
        if !autoload_fail {
            out.regulatory = hw[EEPROM_RF_OPT1] & 0x7;
            out.thermalmeter = hw[EEPROM_THERMAL_METER] & 0x1f;
            out.crystalcap = hw[EEPROM_XTAL_K];
            tempval[0] = hw[EEPROM_IQK_DELTA] & 0x03;
            tempval[1] = (hw[EEPROM_LCK_DELTA] & 0x0c) >> 2;
            out.txpwr_fromeprom = true;
            if d_or_e_cut {
                out.internal_pa_5g[0] = (hw[EEPROM_TSSI_A_5G] & (1 << 6)) >> 6 == 0;
                out.internal_pa_5g[1] = (hw[EEPROM_TSSI_B_5G] & (1 << 6)) >> 6 == 0;
            }
            out.eeprom_c9 = hw[EEPROM_RF_OPT6];
            out.eeprom_cc = hw[EEPROM_RF_OPT7];
        } else {
            out.regulatory = 0;
            out.thermalmeter = EEPROM_DEFAULT_THERMALMETER;
            out.crystalcap = EEPROM_DEFAULT_CRYSTALCAP;
            tempval = [3, 3];
        }
        if out.thermalmeter < 0x06 || out.thermalmeter > 0x1c {
            out.thermalmeter = EEPROM_DEFAULT_THERMALMETER;
        }
        if out.crystalcap == 0xff {
            out.crystalcap = 0;
        }
        if out.regulatory > 3 {
            out.regulatory = 0;
        }
        for v in tempval.iter_mut() {
            *v = match *v {
                0 => 5,
                1 => 4,
                2 => 3,
                _ => 0,
            };
        }
        out.delta_iqk = tempval[0];
        if tempval[1] > 0 {
            out.delta_lck = tempval[1] - 1;
        }
        if out.eeprom_c9 == 0xff {
            out.eeprom_c9 = 0;
        }
        for rfpath in 0..2 {
            for ch in 0..CHANNEL_MAX_NUMBER {
                let group = chnlgroup_fromarray(ch as u8);
                if ch < CHANNEL_MAX_NUMBER_2G {
                    out.cck[rfpath][ch] = pwrinfo.cck_index[rfpath][group];
                }
                out.ht40_1s[rfpath][ch] = pwrinfo.ht40_1sindex[rfpath][group];
                out.ht20_diff[rfpath][ch] = pwrinfo.ht20indexdiff[rfpath][group];
                out.legacy_ht_diff[rfpath][ch] = pwrinfo.ofdmindexdiff[rfpath][group];
                out.pwrgroup_ht20[rfpath][ch] = pwrinfo.ht20maxoffset[rfpath][group];
                out.pwrgroup_ht40[rfpath][ch] = pwrinfo.ht40maxoffset[rfpath][group];
                let pwr = pwrinfo.ht40_1sindex[rfpath][group];
                let diff = pwrinfo.ht40_2sindexdiff[rfpath][group];
                out.ht40_2s[rfpath][ch] = pwr.saturating_sub(diff);
            }
        }
        Ok(out)
    }
}

fn replicate(v: u32) -> u32 {
    (v << 24) | (v << 16) | (v << 8) | v
}

fn clamp_bytes(v: u32) -> u32 {
    let mut b = v.to_le_bytes();
    for x in &mut b {
        if *x > MAX_TX_PWR {
            *x = MAX_TX_PWR;
        }
    }
    u32::from_le_bytes(b)
}

/// The clamped `tx_agc[path]` words of
/// `rtl92d_phy_rf6052_set_cck_txpower` (`scanning` = `mac->act_scanning`).
fn cck_agc(
    efuse: &Efuse,
    mcs_offset: &[[u32; 16]; phy::MAX_PG_GROUP],
    level: [u8; 2],
    scanning: bool,
) -> [u32; 2] {
    let mut agc = [0u32; 2];
    if scanning {
        agc = [0x3f3f_3f3f; 2];
        if efuse.regulatory != 0 {
            for (a, l) in agc.iter_mut().zip(level) {
                *a = replicate(u32::from(l));
            }
        }
    } else {
        for (a, l) in agc.iter_mut().zip(level) {
            *a = replicate(u32::from(l));
        }
        if efuse.regulatory == 0 {
            agc[0] = agc[0].wrapping_add(mcs_offset[0][6].wrapping_add(mcs_offset[0][7] << 8));
            agc[1] = agc[1].wrapping_add(mcs_offset[0][14].wrapping_add(mcs_offset[0][15] << 24));
        }
    }
    agc.map(clamp_bytes)
}

/// `rtl92d_phy_rf6052_set_cck_txpower` (`scanning` = `mac->act_scanning`).
/// Unlike the 92CE port, the second write passes `agc[0] >> 8` unmasked:
/// Linux's `rtl_set_bbreg` does not re-mask the shifted value, so the
/// path-A CCK 11M byte lands at bits 24–31.
pub fn set_cck(
    io: &impl Io,
    efuse: &Efuse,
    mcs_offset: &[[u32; 16]; phy::MAX_PG_GROUP],
    level: [u8; 2],
    scanning: bool,
) -> Result<(), Error> {
    let agc = cck_agc(efuse, mcs_offset, level, scanning);
    phy::set_bb(io, RTXAGC_A_CCK1_MCS32, 0xff00, agc[0] & 0xff)?;
    phy::set_bb(io, RTXAGC_B_CCK11_A_CCK2_11, 0xffff_ff00, agc[0] >> 8)?;
    phy::set_bb(io, RTXAGC_B_CCK11_A_CCK2_11, 0xff, agc[1] >> 24)?;
    phy::set_bb(
        io,
        RTXAGC_B_CCK1_55_MCS32,
        0xffff_ff00,
        agc[1] & 0x00ff_ffff,
    )
}

/// `rtl92d_phy_get_power_base`: `(ofdmbase, mcsbase)` per path.
/// `place` is the remapped channel place (`channel - 1` indexes the
/// per-channel arrays).
pub fn power_base(efuse: &Efuse, level: [u8; 2], place: u8, bw40: bool) -> ([u32; 2], [u32; 2]) {
    let c = usize::from(place - 1);
    let mut ofdm = [0u32; 2];
    let mut mcs = [0u32; 2];
    for i in 0..2 {
        ofdm[i] = replicate(u32::from(level[i]) + u32::from(efuse.legacy_ht_diff[i][c]));
        let mut p = level[i];
        if !bw40 {
            p = p.wrapping_add(efuse.ht20_diff[i][c]);
        }
        mcs[i] = replicate(u32::from(p));
    }
    (ofdm, mcs)
}

/// `_rtl92d_get_pwr_diff_limit` for rate `index`, path `rf`.
fn pwr_diff_limit(
    efuse: &Efuse,
    mcs_offset: &[[u32; 16]; phy::MAX_PG_GROUP],
    place: u8,
    bw40: bool,
    index: usize,
    rf: usize,
) -> [u8; 4] {
    let c = usize::from(place - 1);
    let mcs = mcs_offset[0][index + if rf != 0 { 8 } else { 0 }];
    core::array::from_fn(|i| {
        let mut d = ((mcs >> (i * 8)) & 0x7f) as u8;
        let limit = if bw40 {
            efuse.pwrgroup_ht40[rf][c]
        } else {
            efuse.pwrgroup_ht20[rf][c]
        };
        if d > limit {
            d = limit;
        }
        d
    })
}

/// `_rtl92d_get_txpower_writeval_by_regulatory` for rate `index` (0..6).
/// Regulatory 1 applies the factory table only once all
/// `MAX_PG_GROUP` groups are loaded. (Linux also sets a group when
/// `pwrgroup_cnt == 1` that the `< MAX_PG_GROUP` break then discards;
/// that store is provably dead here — `1 < MAX_PG_GROUP` — so it is
/// omitted rather than ported as written.)
pub fn writeval(
    efuse: &Efuse,
    mcs_offset: &[[u32; 16]; phy::MAX_PG_GROUP],
    pwrgroup_cnt: u8,
    place: u8,
    bw40: bool,
    index: usize,
    base: ([u32; 2], [u32; 2]),
) -> [u32; 2] {
    let mut out = [0u32; 2];
    let mut chnlgroup: usize;
    for (rf, slot) in out.iter_mut().enumerate() {
        let b = if index < 2 { base.0[rf] } else { base.1[rf] };
        let col = index + if rf != 0 { 8 } else { 0 };
        *slot = match efuse.regulatory {
            1 => {
                if pwrgroup_cnt < phy::MAX_PG_GROUP as u8 {
                    0
                } else {
                    chnlgroup = super::channel::chnlgroup_bypg(place - 1);
                    if bw40 {
                        chnlgroup += 4;
                    } else {
                        chnlgroup += 1;
                    }
                    mcs_offset[chnlgroup][col]
                }
            }
            2 => 0,
            3 => {
                let limit = pwr_diff_limit(efuse, mcs_offset, place, bw40, index, rf);
                u32::from_le_bytes(limit)
            }
            // 0 and every other value: "RTK better performance".
            _ => mcs_offset[0][col],
        };
        *slot = slot.wrapping_add(b);
    }
    out
}

/// `_rtl92d_write_ofdm_power_reg` regoffset tables.
const REG_A: [u16; 6] = [
    RTXAGC_A_RATE18_06,
    RTXAGC_A_RATE54_24,
    RTXAGC_A_MCS03_MCS00,
    RTXAGC_A_MCS07_MCS04,
    RTXAGC_A_MCS11_MCS08,
    RTXAGC_A_MCS15_MCS12,
];
const REG_B: [u16; 6] = [
    RTXAGC_B_RATE18_06,
    RTXAGC_B_RATE54_24,
    RTXAGC_B_MCS03_MCS00,
    RTXAGC_B_MCS07_MCS04,
    RTXAGC_B_MCS11_MCS08,
    RTXAGC_B_MCS15_MCS12,
];

/// `_rtl92d_write_ofdm_power_reg`'s per-byte `0x7f` mask and clamp.
fn ofdm_bytes(v: u32) -> [u8; 4] {
    core::array::from_fn(|i| (((v & (0x7f << (i * 8))) >> (i * 8)) as u8).min(MAX_TX_PWR))
}

/// `_rtl92d_write_ofdm_power_reg`.
pub fn write_ofdm(
    io: &impl Io,
    rf_type: RfType,
    index: usize,
    value: [u32; 2],
) -> Result<(), Error> {
    for (rf, v) in value.into_iter().enumerate() {
        write_ofdm_bytes(io, rf_type, index, rf, ofdm_bytes(v))?;
    }
    Ok(())
}

/// One path's `_rtl92d_write_ofdm_power_reg` dword and, after the RF
/// type's last MCS register, the three tail bytes (`-8, -8, -6`).
fn write_ofdm_bytes(
    io: &impl Io,
    rf_type: RfType,
    index: usize,
    rf: usize,
    pwr: [u8; 4],
) -> Result<(), Error> {
    let regoffset = if rf == 0 { REG_A[index] } else { REG_B[index] };
    phy::set_bb(io, regoffset, phy::MASKDWORD, u32::from_le_bytes(pwr))?;
    let tail = match rf_type {
        RfType::TwoT2R => regoffset == RTXAGC_A_MCS15_MCS12 || regoffset == RTXAGC_B_MCS15_MCS12,
        RfType::OneT1R => regoffset == RTXAGC_A_MCS07_MCS04 || regoffset == RTXAGC_B_MCS07_MCS04,
    };
    if tail {
        let base = if rf == 0 { 0x0c90 } else { 0x0c98 };
        let mut w = pwr[3];
        for i in 0..3 {
            w = if i != 2 {
                w.saturating_sub(8)
            } else {
                w.saturating_sub(6)
            };
            io.write8(base + i, w)?;
        }
    }
    Ok(())
}

/// `rtl92d_phy_rf6052_set_ofdm_txpower` (`place` = remapped channel).
pub fn set_ofdm(
    io: &impl Io,
    efuse: &Efuse,
    rf_type: RfType,
    pg: &PgStore,
    level: [u8; 2],
    place: u8,
    bw40: bool,
) -> Result<(), Error> {
    let base = power_base(efuse, level, place, bw40);
    for index in 0..6 {
        let v = writeval(
            efuse,
            &pg.mcs_offset,
            pg.pwrgroup_cnt,
            place,
            bw40,
            index,
            base,
        );
        write_ofdm(io, rf_type, index, v)?;
    }
    Ok(())
}

/// The `_rtl92d_get_txpower_index` levels plus the
/// `_rtl92d_ccxpower_index_check` record (path-A indices, 2.4 GHz only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerLevels {
    pub cck: [u8; 2],
    pub ofdm: [u8; 2],
    /// `cur_cck_txpwridx` / `cur_ofdm24g_txpwridx` (2.4 GHz only).
    pub current: Option<(u8, u8)>,
    /// False when `txpwr_fromeprom` is clear: nothing was written.
    pub from_eeprom: bool,
}

/// `rtl92d_phy_set_txpower_level(channel)` at the current width.
/// `place` handling, CCK/OFDM selection and the 2.4 GHz record follow
/// `_rtl92d_get_txpower_index` / `_rtl92d_ccxpower_index_check`.
// Eight args (one over the lint limit): the parameters span device
// config (`rf_type`, `pg`), channel context (`channel`, `band`,
// `bw40`) and mode (`scanning`), so no single natural bundle exists;
// bundling would churn the production `channel.rs` call site and five
// test sites for no behavioral gain. Revisit if the signature grows.
#[allow(clippy::too_many_arguments)]
pub fn set_level(
    io: &impl Io,
    efuse: &Efuse,
    rf_type: RfType,
    pg: &PgStore,
    channel: u8,
    band: Band,
    bw40: bool,
    scanning: bool,
) -> Result<PowerLevels, Error> {
    if !efuse.txpwr_fromeprom {
        return Ok(PowerLevels {
            cck: [0; 2],
            ofdm: [0; 2],
            current: None,
            from_eeprom: false,
        });
    }
    let place = rightchnlplace(channel);
    if place == 0 || place as usize > CHANNEL_MAX_NUMBER {
        return Err(Error::State);
    }
    let c = usize::from(place - 1);
    let cck = match band {
        Band::On2Ghz => [efuse.cck[0][c], efuse.cck[1][c]],
        Band::On5Ghz => [0; 2],
    };
    let ofdm = match rf_type {
        RfType::OneT1R => [efuse.ht40_1s[0][c], efuse.ht40_1s[1][c]],
        RfType::TwoT2R => [efuse.ht40_2s[0][c], efuse.ht40_2s[1][c]],
    };
    let current = match band {
        Band::On2Ghz => Some((cck[0], ofdm[0])),
        Band::On5Ghz => None,
    };
    if band == Band::On2Ghz {
        set_cck(io, efuse, &pg.mcs_offset, cck, scanning)?;
    }
    set_ofdm(io, efuse, rf_type, pg, ofdm, place, bw40)?;
    Ok(PowerLevels {
        cck,
        ofdm,
        current,
        from_eeprom: true,
    })
}

/// Station rates in full order: CCK 0..=3, OFDM 4..=11, MCS0-15 12..=27.
pub const RATES: usize = 28;

/// The station rates of `rf_type` (full order): CCK, OFDM and MCS0-7 on
/// `RF_1T1R`, plus MCS8-15 on `RF_2T2R`.
pub fn rates(rf_type: RfType) -> core::ops::Range<u8> {
    match rf_type {
        RfType::OneT1R => 0..20,
        RfType::TwoT2R => 0..28,
    }
}

/// The per-path, per-rate TXAGC bytes `rtl92d_phy_set_txpower_level`
/// writes on the station path (`act_scanning` false) at the wide
/// `channel` and width: `[path][full-order rate]`. Path-A CCK 11M keeps
/// its Linux byte here (see the module note). The upper bound the
/// per-board envelope lowers (`rtl8192de/envelope.rs`).
pub fn linux_indices(
    efuse: &Efuse,
    rf_type: RfType,
    pg: &PgStore,
    channel: u8,
    band: Band,
    bw40: bool,
) -> Result<[[u8; RATES]; 2], Error> {
    if !efuse.txpwr_fromeprom {
        return Ok([[0; RATES]; 2]);
    }
    let place = rightchnlplace(channel);
    if place == 0 || place as usize > CHANNEL_MAX_NUMBER {
        return Err(Error::State);
    }
    let c = usize::from(place - 1);
    let cck = match band {
        Band::On2Ghz => [efuse.cck[0][c], efuse.cck[1][c]],
        Band::On5Ghz => [0; 2],
    };
    let level = match rf_type {
        RfType::OneT1R => [efuse.ht40_1s[0][c], efuse.ht40_1s[1][c]],
        RfType::TwoT2R => [efuse.ht40_2s[0][c], efuse.ht40_2s[1][c]],
    };
    let mut out = [[0u8; RATES]; 2];
    if band == Band::On2Ghz {
        let a = cck_agc(efuse, &pg.mcs_offset, cck, false);
        let a0 = a[0].to_le_bytes();
        let a1 = a[1].to_le_bytes();
        out[0][..4].copy_from_slice(&[a0[0], a0[1], a0[2], a0[3]]);
        out[1][..4].copy_from_slice(&a1);
    }
    let base = power_base(efuse, level, place, bw40);
    for index in 0..6 {
        let v = writeval(
            efuse,
            &pg.mcs_offset,
            pg.pwrgroup_cnt,
            place,
            bw40,
            index,
            base,
        );
        for (rf, word) in v.into_iter().enumerate() {
            let at = 4 + index * 4;
            out[rf][at..at + 4].copy_from_slice(&ofdm_bytes(word));
        }
    }
    Ok(out)
}
