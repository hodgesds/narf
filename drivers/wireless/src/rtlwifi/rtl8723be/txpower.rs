// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE TX power: EFUSE power areas, the PHY_REG_PG by-rate store and
//! `rtl8723be_phy_set_txpower_level`.
//!
//! Exact Linux `rtl8723be/{hw,phy}.c`:
//!
//! - [`Efuse::from_logical`] — `_rtl8723be_read_power_value_fromprom` /
//!   `_rtl8723be_read_txpower_info_from_hwpg` for RF path A, the only path
//!   `rtl8723be_phy_set_txpower_level` programs: six CCK and five BW40 bases
//!   from `EEPROM_TX_PWR_INX` (`0xff` ⇒ `0x2d`), then the first diff byte
//!   (`bw20_diff` high nibble, `0xff` ⇒ 2; `ofdm_diff` low nibble, `0xff` ⇒
//!   4; 4-bit sign extension; `bw40_diff[0] = 0`). `_rtl8723be_get_chnl_group`
//!   (0 below channel 3, 1 below 9, else 2). A map with `0x11 == 0xff` (the
//!   `YJ,add,120316` autoload-fail branch) is refused: that branch leaves
//!   `bw40_diff[0][0]` uninitialised in Linux.
//! - [`ByRate::from_table`] — `_rtl8723be_phy_init_tx_power_by_rate`,
//!   `_rtl8723be_phy_config_bb_with_pgheaderfile` (raw row data by
//!   `_rtl8723be_get_rate_section_index`; the table has no delay rows) and
//!   `phy_txpower_by_rate_config` (BCD bases, `_phy_convert_txpower_dbm_to_relative_value`
//!   absolute differences) for path A. Rows for other paths only feed bases
//!   path A never reads.
//! - [`index`] — `_rtl8723be_get_txpower_index` (u8 wrapping sums, by-rate
//!   diff unless `eeprom_regulatory == 2`, `MAX_POWER_INDEX` clamp).
//! - [`set_indices`] / [`set_level`] — `_rtl8723be_phy_set_txpower_index`
//!   byte RMWs of the path-A TXAGC registers for CCK, OFDM and MCS0-7, in
//!   the `rtl8723be_phy_set_txpower_level` order.
//!
//! The Linux index is an upper bound only: the owner programs indices from
//! a [`super::channel::Grant`], never [`set_level`] directly.

use super::phy::set_bb;
use super::tables;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const RTXAGC_A_RATE18_06: u16 = 0x0e00;
pub const RTXAGC_A_RATE54_24: u16 = 0x0e04;
pub const RTXAGC_A_CCK1_MCS32: u16 = 0x0e08;
pub const RTXAGC_B_CCK11_A_CCK2_11: u16 = 0x086c;
pub const RTXAGC_A_MCS03_MCS00: u16 = 0x0e10;
pub const RTXAGC_A_MCS07_MCS04: u16 = 0x0e14;
pub const RTXAGC_A_MCS11_MCS08: u16 = 0x0e18;
pub const RTXAGC_A_MCS15_MCS12: u16 = 0x0e1c;
pub const RTXAGC_B_RATE18_06: u16 = 0x0830;
pub const RTXAGC_B_RATE54_24: u16 = 0x0834;
pub const RTXAGC_B_CCK1_55_MCS32: u16 = 0x0838;
pub const RTXAGC_B_MCS03_MCS00: u16 = 0x083c;
pub const RTXAGC_B_MCS07_MCS04: u16 = 0x0848;
pub const RTXAGC_B_MCS11_MCS08: u16 = 0x084c;
pub const RTXAGC_B_MCS15_MCS12: u16 = 0x0868;
/// `EEPROM_TX_PWR_INX`.
pub const EEPROM_TX_PWR_INX: usize = 0x10;
/// `MAX_POWER_INDEX`.
pub const MAX_POWER_INDEX: u8 = 0x3f;

/// `DESC92C_RATE*` codes `rtl8723be_phy_set_txpower_level` programs, in
/// its order: CCK 1/2/5.5/11, OFDM 6..54, HT MCS0..7.
pub const RATES: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];
const RATE6M: u8 = 4;
const RATE54M: u8 = 11;
const RATEMCS0: u8 = 12;

/// Path-A EFUSE power facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efuse {
    /// `pw2g.index_cck_base[0]` (six groups).
    pub cck_base: [u8; 6],
    /// `pw2g.index_bw40_base[0]` (five groups read; Linux leaves the sixth
    /// unset and `_rtl8723be_get_chnl_group` never selects it).
    pub bw40_base: [u8; 5],
    /// `txpwr_ht20diff[0][TX_1S]`.
    pub ht20_diff: u8,
    /// `txpwr_ht40diff[0][TX_1S]` (always 0 for `cnt == 0`).
    pub ht40_diff: u8,
    /// `txpwr_legacyhtdiff[0][TX_1S]`.
    pub legacy_ht_diff: u8,
}

const fn sign4(v: u8) -> u8 {
    if v & 0x08 != 0 {
        v | 0xf0
    } else {
        v
    }
}

/// `_rtl8723be_get_chnl_group`.
pub const fn chnl_group(channel: u8) -> usize {
    if channel < 3 {
        0
    } else if channel < 9 {
        1
    } else {
        2
    }
}

impl Efuse {
    /// Path A of `_rtl8723be_read_power_value_fromprom` over the logical map.
    pub fn from_logical(map: &[u8]) -> Result<Self, Error> {
        let addr = EEPROM_TX_PWR_INX;
        if map.len() < addr + 12 || map[addr + 1] == 0xff {
            return Err(Error::State);
        }
        let base = |v: u8| if v == 0xff { 0x2d } else { v };
        let mut cck_base = [0; 6];
        for (i, b) in cck_base.iter_mut().enumerate() {
            *b = base(map[addr + i]);
        }
        let mut bw40_base = [0; 5];
        for (i, b) in bw40_base.iter_mut().enumerate() {
            *b = base(map[addr + 6 + i]);
        }
        let diff = map[addr + 11];
        let (ht20_diff, legacy_ht_diff) = if diff == 0xff {
            (0x02, 0x04)
        } else {
            (sign4((diff & 0xf0) >> 4), sign4(diff & 0x0f))
        };
        Ok(Self {
            cck_base,
            bw40_base,
            ht20_diff,
            ht40_diff: 0,
            legacy_ht_diff,
        })
    }

    /// `rtlefuse->txpwrlevel_cck[0][channel - 1]`.
    pub fn cck(&self, channel: u8) -> u8 {
        self.cck_base[chnl_group(channel)]
    }

    /// `rtlefuse->txpwrlevel_ht40_1s[0][channel - 1]`.
    pub fn ht40_1s(&self, channel: u8) -> u8 {
        self.bw40_base[chnl_group(channel)]
    }
}

/// `_rtl8723be_get_rate_section_index`.
pub fn rate_section_index(regaddr: u32) -> usize {
    match regaddr {
        0x0e00 | 0x0830 => 0,
        0x0e04 | 0x0834 => 1,
        0x0e08 | 0x0838 => 2,
        0x086c => 3,
        0x0e10 | 0x083c => 4,
        0x0e14 | 0x0848 => 5,
        0x0e18 | 0x084c => 6,
        0x0e1c | 0x0868 => 7,
        _ => {
            let r = regaddr & 0xfff;
            if (0xc20..=0xc4c).contains(&r) {
                ((r - 0xc20) / 4) as usize
            } else if (0xe20..=0xe4c).contains(&r) {
                ((r - 0xe20) / 4) as usize
            } else {
                0
            }
        }
    }
}

/// Path-A `tx_power_by_rate_offset[BAND_ON_2_4G][RF90_PATH_A][txnum]`
/// after `phy_txpower_by_rate_config` (`RF_1TX`, `RF_2TX`; twelve
/// sections as Linux sizes them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByRate {
    pub offset: [[u32; 12]; 2],
}

const fn bcd(raw: u32) -> u8 {
    let raw = (raw & 0xff) as u8;
    (raw >> 4) * 10 + (raw & 0xf)
}

/// `_phy_convert_txpower_dbm_to_relative_value`.
pub fn to_relative(data: u32, start: u32, end: u32, base: u8) -> u32 {
    let mut out = 0u32;
    for i in (0..4u32).rev() {
        let v = if (start..=end).contains(&i) {
            let exact =
                ((data >> (i * 8)) & 0xf) as u8 + (((data >> (i * 8 + 4)) & 0xf) as u8) * 10;
            exact.abs_diff(base)
        } else {
            ((data >> (i * 8)) & 0xff) as u8
        };
        out = (out << 8) | u32::from(v);
    }
    out
}

impl ByRate {
    /// The by-rate store over `RTL8723BEPHY_REG_ARRAY_PG` and its
    /// relative-value conversion (provisioned maps only, as Linux).
    pub fn from_table() -> Self {
        Self::from_rows(&tables::PHY_REG_PG)
    }

    pub fn from_rows(rows: &[[u32; 6]]) -> Self {
        let mut offset = [[0u32; 12]; 2];
        for &[band, path, txnum, regaddr, _mask, data] in rows {
            // _rtl8723be_store_tx_power_by_rate (v1 < 0xcdcdcdcd; band,
            // path and txnum checks); only path A is retained.
            if band == 0 && path == 0 && txnum < 2 {
                offset[txnum as usize][rate_section_index(regaddr)] = data;
            }
        }
        let cck = bcd(offset[0][3] >> 24);
        let ofdm = bcd(offset[0][1] >> 24);
        let ht1 = bcd(offset[0][5] >> 24);
        let ht2 = bcd(offset[1][7] >> 24);
        let o = &mut offset;
        o[0][2] = to_relative(o[0][2], 1, 1, cck);
        o[0][3] = to_relative(o[0][3], 1, 3, cck);
        o[0][0] = to_relative(o[0][0], 0, 3, ofdm);
        o[0][1] = to_relative(o[0][1], 0, 3, ofdm);
        o[0][4] = to_relative(o[0][4], 0, 3, ht1);
        o[0][5] = to_relative(o[0][5], 0, 3, ht1);
        o[1][6] = to_relative(o[1][6], 0, 3, ht2);
        o[1][7] = to_relative(o[1][7], 0, 3, ht2);
        Self { offset }
    }

    /// `_rtl8723be_get_txpower_by_rate` for path A and a [`RATES`] code.
    pub fn diff(&self, rate: u8) -> u8 {
        let section = match rate {
            0 => 2,
            1..=3 => 3,
            4..=7 => 0,
            8..=11 => 1,
            12..=15 => 4,
            _ => 5,
        };
        let shift = match rate {
            4 | 8 | 12 | 16 => 0,
            0 | 1 | 5 | 9 | 13 | 17 => 8,
            2 | 6 | 10 | 14 | 18 => 16,
            _ => 24,
        };
        ((self.offset[0][section] >> shift) & 0xff) as u8
    }
}

/// `_rtl8723be_get_txpower_index(hw, RF90_PATH_A, rate, bw, channel)`.
pub fn index(
    efuse: &Efuse,
    by_rate: &ByRate,
    regulatory: u8,
    rate: u8,
    forty: bool,
    channel: u8,
) -> u8 {
    let channel = if (1..=14).contains(&channel) {
        channel
    } else {
        1
    };
    let mut tx = if rate < RATE6M {
        efuse.cck(channel)
    } else {
        efuse.ht40_1s(channel)
    };
    if (RATE6M..=RATE54M).contains(&rate) {
        tx = tx.wrapping_add(efuse.legacy_ht_diff);
    }
    if rate >= RATEMCS0 {
        tx = tx.wrapping_add(if forty {
            efuse.ht40_diff
        } else {
            efuse.ht20_diff
        });
    }
    if regulatory != 2 {
        tx = tx.wrapping_add(by_rate.diff(rate));
    }
    tx.min(MAX_POWER_INDEX)
}

/// The Linux indices for every [`RATES`] entry.
pub fn linux_indices(
    efuse: &Efuse,
    by_rate: &ByRate,
    regulatory: u8,
    forty: bool,
    channel: u8,
) -> [u8; 20] {
    let mut out = [0; 20];
    for (o, rate) in out.iter_mut().zip(RATES) {
        *o = index(efuse, by_rate, regulatory, rate, forty, channel);
    }
    out
}

/// `_rtl8723be_phy_set_txpower_index` target for a path-A rate:
/// (register, byte lane).
pub const fn txagc(rate: u8) -> (u16, u32) {
    match rate {
        0 => (RTXAGC_A_CCK1_MCS32, 1),
        1 => (RTXAGC_B_CCK11_A_CCK2_11, 1),
        2 => (RTXAGC_B_CCK11_A_CCK2_11, 2),
        3 => (RTXAGC_B_CCK11_A_CCK2_11, 3),
        4..=7 => (RTXAGC_A_RATE18_06, (rate - 4) as u32),
        8..=11 => (RTXAGC_A_RATE54_24, (rate - 8) as u32),
        12..=15 => (RTXAGC_A_MCS03_MCS00, (rate - 12) as u32),
        _ => (RTXAGC_A_MCS07_MCS04, (rate - 16) as u32),
    }
}

/// The `_rtl8723be_phy_set_txpower_index` writes for every [`RATES`] entry.
pub fn set_indices(io: &impl Io, indices: &[u8; 20]) -> Result<(), Error> {
    for (rate, value) in RATES.into_iter().zip(indices) {
        let (reg, lane) = txagc(rate);
        set_bb(io, reg, 0xff << (lane * 8), u32::from(*value))?;
    }
    Ok(())
}

/// `rtl8723be_phy_set_txpower_level` (`txpwr_fromeprom` is set for every
/// provisioned map). Reference only: see the module note.
pub fn set_level(
    io: &impl Io,
    efuse: &Efuse,
    by_rate: &ByRate,
    regulatory: u8,
    forty: bool,
    channel: u8,
) -> Result<(), Error> {
    set_indices(
        io,
        &linux_indices(efuse, by_rate, regulatory, forty, channel),
    )
}
