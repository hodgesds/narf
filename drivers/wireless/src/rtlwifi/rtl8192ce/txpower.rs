// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE 2.4 GHz TX power from the factory map.
//!
//! - [`Efuse::from_hwinfo`] — `rtl8192ce/hw.c::_rtl92ce_read_txpower_info_
//!   from_hwpg` with `autoload_fail` false (the adapter decode refuses an
//!   autoload failure): per-field `0xff` defaults, the three
//!   `rtl92c_get_chnl_group` areas (index `i < 3` ⇒ 0, `i < 9` ⇒ 1, else 2
//!   over the 0-based channel index), `ht40_2s = max(ht40_1s - 2sdiff, 0)`,
//!   HT20 diff nibbles sign-extended with `| 0xF0`, regulatory
//!   `RF_OPTION1[2:0]`, thermal `[4:0]`.
//! - [`set_level`] — `rtl92c_phy_set_txpower_level` (`txpwr_fromeprom` is
//!   set by `rtl_get_hwinfo`): `_rtl92c_get_txpower_index` (CCK; OFDM from
//!   `ht40_1s` for `RF_1T1R`, `ht40_2s` for `RF_2T2R`), then
//!   `rtl92ce_phy_rf6052_set_cck_txpower` and
//!   `rtl92ce_phy_rf6052_set_ofdm_txpower` (`rtl92c_phy_get_power_base`,
//!   `_rtl92c_get_txpower_writeval_by_regulatory`,
//!   `_rtl92c_write_ofdm_power_reg` incl. the `0xc90`/`0xc98` byte tail).
//!   Both paths' registers are written on an 88C part too, as Linux.
//!
//! Linux reads the per-rate differences from `rtlphy->mcs_offset`, which
//! no `rtl8192c`/`rtl8192ce` code writes (the PHY_REG_PG walk stores into
//! `mcs_txpwrlevel_origoffset`); it stays zero, so [`MCS_OFFSET`] is the
//! all-zero table and every regulatory mode reduces to the power base.
//! `dynamic_txhighpower_lvl` is never `TXHIGHPWRLEVEL_BT1/BT2` on this
//! family (BT boards are never admitted), so those subtractions are absent.

use super::phy::{self, set_bb, MASKDWORD, MAX_PG_GROUP};
use super::version::RfType;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `reg.h` EEPROM offsets.
pub const EEPROM_TXPOWERCCK: usize = 0x5a;
pub const EEPROM_TXPOWERHT40_1S: usize = 0x60;
pub const EEPROM_TXPOWERHT40_2SDIFF: usize = 0x66;
pub const EEPROM_TXPOWERHT20DIFF: usize = 0x69;
pub const EEPROM_TXPOWER_OFDMDIFF: usize = 0x6c;
pub const EEPROM_TXPWR_GROUP: usize = 0x6f;
pub const EEPROM_TSSI_A: usize = 0x76;
pub const EEPROM_TSSI_B: usize = 0x77;
pub const EEPROM_THERMAL_METER: usize = 0x78;
pub const RF_OPTION1: usize = 0x79;

pub const EEPROM_DEFAULT_TXPOWERLEVEL: u8 = 0x22;
pub const EEPROM_DEFAULT_HT40_2SDIFF: u8 = 0x0;
pub const EEPROM_DEFAULT_HT20_DIFF: u8 = 2;
pub const EEPROM_DEFAULT_LEGACYHTTXPOWERDIFF: u8 = 0x3;
pub const EEPROM_DEFAULT_TSSI: u8 = 0x0;
pub const EEPROM_DEFAULT_THERMALMETER: u8 = 0x12;

/// `RF6052_MAX_TX_PWR`.
pub const MAX_TX_PWR: u8 = 0x3f;

/// `rtlphy->mcs_offset` as Linux leaves it on this family (never written).
pub const MCS_OFFSET: [[u32; 16]; MAX_PG_GROUP] = [[0; 16]; MAX_PG_GROUP];

/// `rtl92c_get_chnl_group` (0-based channel index).
pub const fn chnl_group(index: u8) -> usize {
    if index < 3 {
        0
    } else if index < 9 {
        1
    } else {
        2
    }
}

/// `rtlefuse` TX-power fields, `[path][channel - 1]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efuse {
    pub cck: [[u8; 14]; 2],
    pub ht40_1s: [[u8; 14]; 2],
    pub ht40_2s: [[u8; 14]; 2],
    /// Sign-extended nibbles (`| 0xF0` when BIT(3)), used with u8 wrapping.
    pub ht20_diff: [[u8; 14]; 2],
    pub legacy_ht_diff: [[u8; 14]; 2],
    pub pwrgroup_ht20: [[u8; 14]; 2],
    pub pwrgroup_ht40: [[u8; 14]; 2],
    /// `legacy_ht_txpowerdiff` (`txpwr_legacyhtdiff[A][7]`).
    pub legacy_ht_txpowerdiff: u8,
    pub regulatory: u8,
    pub tssi: [u8; 2],
    pub thermal: u8,
    pub apk_thermalmeterignore: bool,
}

impl Efuse {
    /// `_rtl92ce_read_txpower_info_from_hwpg(autoload_fail = false)` over the
    /// 128-byte `HWSET_MAX_SIZE` map.
    pub fn from_hwinfo(hw: &[u8]) -> Result<Self, Error> {
        if hw.len() <= RF_OPTION1 {
            return Err(Error::Descriptor);
        }
        let mut area_cck = [[0u8; 3]; 2];
        let mut area_1s = [[0u8; 3]; 2];
        for rf in 0..2 {
            for i in 0..3 {
                let c = hw[EEPROM_TXPOWERCCK + rf * 3 + i];
                let h = hw[EEPROM_TXPOWERHT40_1S + rf * 3 + i];
                if c != 0xff && h != 0xff {
                    area_cck[rf][i] = c;
                    area_1s[rf][i] = h;
                } else {
                    area_cck[rf][i] = EEPROM_DEFAULT_TXPOWERLEVEL;
                    area_1s[rf][i] = EEPROM_DEFAULT_TXPOWERLEVEL;
                }
            }
        }
        let mut area_2sdf = [[0u8; 3]; 2];
        for i in 0..3 {
            let v = match hw[EEPROM_TXPOWERHT40_2SDIFF + i] {
                0xff => EEPROM_DEFAULT_HT40_2SDIFF,
                v => v,
            };
            area_2sdf[0][i] = v & 0xf;
            area_2sdf[1][i] = (v & 0xf0) >> 4;
        }
        let mut out = Self {
            cck: [[0; 14]; 2],
            ht40_1s: [[0; 14]; 2],
            ht40_2s: [[0; 14]; 2],
            ht20_diff: [[0; 14]; 2],
            legacy_ht_diff: [[0; 14]; 2],
            pwrgroup_ht20: [[0; 14]; 2],
            pwrgroup_ht40: [[0; 14]; 2],
            legacy_ht_txpowerdiff: 0,
            regulatory: 0,
            tssi: [0; 2],
            thermal: 0,
            apk_thermalmeterignore: false,
        };
        for rf in 0..2 {
            for i in 0..14u8 {
                let g = chnl_group(i);
                let c = usize::from(i);
                out.cck[rf][c] = area_cck[rf][g];
                out.ht40_1s[rf][c] = area_1s[rf][g];
                out.ht40_2s[rf][c] = area_1s[rf][g].saturating_sub(area_2sdf[rf][g]);
            }
        }
        let mut limit_ht40 = [0u8; 3];
        let mut limit_ht20 = [0u8; 3];
        for i in 0..3 {
            let (a, b) = (hw[EEPROM_TXPWR_GROUP + i], hw[EEPROM_TXPWR_GROUP + 3 + i]);
            if a != 0xff && b != 0xff {
                limit_ht40[i] = a;
                limit_ht20[i] = b;
            }
        }
        for i in 0..14u8 {
            let g = chnl_group(i);
            let c = usize::from(i);
            out.pwrgroup_ht20[0][c] = limit_ht20[g] & 0xf;
            out.pwrgroup_ht40[0][c] = limit_ht40[g] & 0xf;
            out.pwrgroup_ht20[1][c] = (limit_ht20[g] & 0xf0) >> 4;
            out.pwrgroup_ht40[1][c] = (limit_ht40[g] & 0xf0) >> 4;
        }
        for i in 0..14u8 {
            let g = chnl_group(i);
            let c = usize::from(i);
            let v = match hw[EEPROM_TXPOWERHT20DIFF + g] {
                0xff => EEPROM_DEFAULT_HT20_DIFF,
                v => v,
            };
            for (rf, nibble) in [(0, v & 0xf), (1, (v >> 4) & 0xf)] {
                out.ht20_diff[rf][c] = if nibble & (1 << 3) != 0 {
                    nibble | 0xf0
                } else {
                    nibble
                };
            }
            let v = match hw[EEPROM_TXPOWER_OFDMDIFF + g] {
                0xff => EEPROM_DEFAULT_LEGACYHTTXPOWERDIFF,
                v => v,
            };
            out.legacy_ht_diff[0][c] = v & 0xf;
            out.legacy_ht_diff[1][c] = (v >> 4) & 0xf;
        }
        out.legacy_ht_txpowerdiff = out.legacy_ht_diff[0][7];
        out.regulatory = match hw[RF_OPTION1] {
            0xff => 0,
            v => v & 0x7,
        };
        let (ta, tb) = (hw[EEPROM_TSSI_A], hw[EEPROM_TSSI_B]);
        out.tssi = if ta != 0xff && tb != 0xff {
            [ta, tb]
        } else {
            [EEPROM_DEFAULT_TSSI; 2]
        };
        let t = match hw[EEPROM_THERMAL_METER] {
            0xff => EEPROM_DEFAULT_THERMALMETER,
            v => v,
        };
        out.thermal = t & 0x1f;
        out.apk_thermalmeterignore = out.thermal == 0x1f;
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

/// `rtl92ce_phy_rf6052_set_cck_txpower` (`scanning` = `mac->act_scanning`).
pub fn set_cck(io: &impl Io, efuse: &Efuse, level: [u8; 2], scanning: bool) -> Result<(), Error> {
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
            agc[0] = agc[0].wrapping_add(MCS_OFFSET[0][6].wrapping_add(MCS_OFFSET[0][7] << 8));
            agc[1] = agc[1].wrapping_add(MCS_OFFSET[0][14].wrapping_add(MCS_OFFSET[0][15] << 24));
        }
    }
    let agc = agc.map(clamp_bytes);
    set_bb(io, phy::RTXAGC_A_CCK1_MCS32, 0xff00, agc[0] & 0xff)?;
    set_bb(
        io,
        phy::RTXAGC_B_CCK11_A_CCK2_11,
        0xffff_ff00,
        (agc[0] >> 8) & 0xff00_ffff,
    )?;
    set_bb(io, phy::RTXAGC_B_CCK11_A_CCK2_11, 0xff, agc[1] >> 24)?;
    set_bb(
        io,
        phy::RTXAGC_B_CCK1_55_MCS32,
        0xffff_ff00,
        agc[1] & 0x00ff_ffff,
    )
}

/// `rtl92c_phy_get_power_base`: `(ofdmbase, mcsbase)` per path.
pub fn power_base(efuse: &Efuse, level: [u8; 2], channel: u8, bw40: bool) -> ([u32; 2], [u32; 2]) {
    let c = usize::from(channel - 1);
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

/// `_rtl92c_get_txpower_writeval_by_regulatory` for rate `index` (0..6).
pub fn writeval(
    efuse: &Efuse,
    pwrgroup_cnt: u8,
    channel: u8,
    bw40: bool,
    index: usize,
    base: ([u32; 2], [u32; 2]),
) -> [u32; 2] {
    let c = usize::from(channel - 1);
    let mut out = [0u32; 2];
    let mut chnlgroup = 0usize;
    for (rf, slot) in out.iter_mut().enumerate() {
        let b = if index < 2 { base.0[rf] } else { base.1[rf] };
        let col = index + if rf != 0 { 8 } else { 0 };
        *slot = match efuse.regulatory {
            1 => {
                if bw40 {
                    b
                } else {
                    if pwrgroup_cnt == 1 {
                        chnlgroup = 0;
                    }
                    if pwrgroup_cnt >= 3 {
                        chnlgroup = match channel {
                            0..=3 => 0,
                            4..=9 => 1,
                            _ => 2,
                        };
                        if pwrgroup_cnt == 4 {
                            chnlgroup += 1;
                        }
                    }
                    MCS_OFFSET[chnlgroup][col].wrapping_add(b)
                }
            }
            2 => b,
            3 => {
                let limit = if bw40 {
                    efuse.pwrgroup_ht40[rf][c]
                } else {
                    efuse.pwrgroup_ht20[rf][c]
                };
                let mut customer = 0u32;
                for i in (0..4).rev() {
                    let d = ((MCS_OFFSET[0][col] & (0x7f << (i * 8))) >> (i * 8)) as u8;
                    customer = (customer << 8) | u32::from(d.min(limit));
                }
                customer.wrapping_add(b)
            }
            // 0 and every other value: "RTK better performance".
            _ => MCS_OFFSET[0][col].wrapping_add(b),
        };
    }
    out
}

/// `_rtl92c_write_ofdm_power_reg` regoffset tables.
const REG_A: [u16; 6] = [
    phy::RTXAGC_A_RATE18_06,
    phy::RTXAGC_A_RATE54_24,
    phy::RTXAGC_A_MCS03_MCS00,
    phy::RTXAGC_A_MCS07_MCS04,
    phy::RTXAGC_A_MCS11_MCS08,
    phy::RTXAGC_A_MCS15_MCS12,
];
const REG_B: [u16; 6] = [
    phy::RTXAGC_B_RATE18_06,
    phy::RTXAGC_B_RATE54_24,
    phy::RTXAGC_B_MCS03_MCS00,
    phy::RTXAGC_B_MCS07_MCS04,
    phy::RTXAGC_B_MCS11_MCS08,
    phy::RTXAGC_B_MCS15_MCS12,
];

/// `_rtl92c_write_ofdm_power_reg`.
pub fn write_ofdm(
    io: &impl Io,
    rf_type: RfType,
    index: usize,
    value: [u32; 2],
) -> Result<(), Error> {
    for (rf, v) in value.into_iter().enumerate() {
        let mut pwr = [0u8; 4];
        for (i, p) in pwr.iter_mut().enumerate() {
            *p = (((v & (0x7f << (i * 8))) >> (i * 8)) as u8).min(MAX_TX_PWR);
        }
        let regoffset = if rf == 0 { REG_A[index] } else { REG_B[index] };
        set_bb(io, regoffset, MASKDWORD, u32::from_le_bytes(pwr))?;
        let tail = match rf_type {
            RfType::T2R2 => {
                regoffset == phy::RTXAGC_A_MCS15_MCS12 || regoffset == phy::RTXAGC_B_MCS15_MCS12
            }
            RfType::T1R1 => {
                regoffset == phy::RTXAGC_A_MCS07_MCS04 || regoffset == phy::RTXAGC_B_MCS07_MCS04
            }
        };
        if tail {
            let base = if rf == 0 { 0x0c90 } else { 0x0c98 };
            let mut w = pwr[3];
            for i in 0..3 {
                w = w.saturating_sub(6);
                io.write8(base + i, w)?;
            }
        }
    }
    Ok(())
}

/// `rtl92ce_phy_rf6052_set_ofdm_txpower`.
pub fn set_ofdm(
    io: &impl Io,
    efuse: &Efuse,
    rf_type: RfType,
    pwrgroup_cnt: u8,
    level: [u8; 2],
    channel: u8,
    bw40: bool,
) -> Result<(), Error> {
    let base = power_base(efuse, level, channel, bw40);
    for index in 0..6 {
        let v = writeval(efuse, pwrgroup_cnt, channel, bw40, index, base);
        write_ofdm(io, rf_type, index, v)?;
    }
    Ok(())
}

/// `rtl92c_phy_set_txpower_level(channel)` at the current width.
pub fn set_level(
    io: &impl Io,
    efuse: &Efuse,
    rf_type: RfType,
    pwrgroup_cnt: u8,
    channel: u8,
    bw40: bool,
    scanning: bool,
) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::State);
    }
    let c = usize::from(channel - 1);
    let cck = [efuse.cck[0][c], efuse.cck[1][c]];
    let ofdm = match rf_type {
        RfType::T1R1 => [efuse.ht40_1s[0][c], efuse.ht40_1s[1][c]],
        RfType::T2R2 => [efuse.ht40_2s[0][c], efuse.ht40_2s[1][c]],
    };
    set_cck(io, efuse, cck, scanning)?;
    set_ofdm(io, efuse, rf_type, pwrgroup_cnt, ofdm, channel, bw40)
}
