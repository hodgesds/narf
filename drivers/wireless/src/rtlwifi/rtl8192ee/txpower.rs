// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE TX power from the factory map and the TXAGC writes.
//!
//! - [`Efuse::from_logical`] is `_rtl8192ee_read_power_value_fromprom` +
//!   `_rtl92ee_read_txpower_info_from_hwpg` (2.4 GHz fields, paths A/B):
//!   per path 6 CCK and 5 BW40 group bases from `EEPROM_TX_PWR_INX`
//!   (`0xff` ⇒ `0x2D`), the four-count signed-nibble diffs, then the 5 GHz
//!   block is skipped (42 bytes per path in total). Channel 14 CCK uses
//!   group 5, its BW40 group 4. Thermal meter `0xBA` (`0xff` ⇒ `0x1A` and
//!   `apk_thermalmeterignore`), regulatory `0xC1[2:0]` (`0xff` ⇒ 0).
//!   A map whose `EEPROM_TX_PWR_INX + 1` byte is `0xff` is Linux's
//!   autoload-fail branch: `txpwr_fromeprom` stays false and Linux never
//!   writes TXAGC. That board is refused here (no invented defaults).
//! - [`index`] is `_rtl92ee_get_txpower_index` (u8 wrapping sums, clamp to
//!   `MAX_POWER_INDEX` 0x3f; by-rate diff unless regulatory 2) over
//!   `_rtl92ee_get_txpower_by_rate` with the Linux section/shift tables,
//!   including its quirks (path A 1M reads byte 0 of `0xe08`, path B 11M
//!   reads byte 3 of `0x86c`).
//! - [`set_level`] is `rtl92ee_phy_set_txpower_level` for both paths:
//!   CCK, OFDM, MCS0-7, MCS8-15 in that order, each a byte RMW of the
//!   `_rtl92ee_set_txpower_index` register.

use super::phy::{set_bb, ByRate, RF_1TX, RF_2TX};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const EEPROM_TX_PWR_INX: usize = 0x10;
pub const EEPROM_THERMAL_METER: usize = 0xba;
pub const EEPROM_RF_BOARD_OPTION: usize = 0xc1;
pub const EEPROM_DEFAULT_THERMALMETER: u8 = 0x1a;
/// Bytes of one path's power block (2.4 GHz 18 + 5 GHz 24).
pub const PATH_STRIDE: usize = 42;
pub const MAX_POWER_INDEX: u8 = 0x3f;
pub const MAX_TX_COUNT: usize = 4;

/// `DESC92C_RATE*`.
pub const RATE_1M: u8 = 0x00;
pub const RATE_11M: u8 = 0x03;
pub const RATE_6M: u8 = 0x04;
pub const RATE_54M: u8 = 0x0b;
pub const RATE_MCS0: u8 = 0x0c;
pub const RATE_MCS8: u8 = 0x14;
pub const RATE_MCS15: u8 = 0x1b;

/// `HT_CHANNEL_WIDTH_20` / `HT_CHANNEL_WIDTH_20_40`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    W20,
    W40,
}

/// `rtl_efuse` 2.4 GHz TX power fields for paths A/B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efuse {
    pub cck: [[u8; 14]; 2],
    pub ht40_1s: [[u8; 14]; 2],
    pub cck_diff: [[u8; MAX_TX_COUNT]; 2],
    pub legacy_ht_diff: [[u8; MAX_TX_COUNT]; 2],
    pub ht20_diff: [[u8; MAX_TX_COUNT]; 2],
    pub ht40_diff: [[u8; MAX_TX_COUNT]; 2],
    pub thermal_meter: u8,
    pub apk_thermal_meter_ignore: bool,
    pub regulatory: u8,
}

/// `_rtl92ee_get_chnl_group` (2.4 GHz).
pub fn chnl_group(channel: u8) -> usize {
    match channel {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        12..=14 => 4,
        _ => 0,
    }
}

fn nibble(v: u8) -> u8 {
    if v & 0x08 != 0 {
        v | 0xf0
    } else {
        v
    }
}

impl Efuse {
    pub fn from_logical(map: &[u8]) -> Result<Self, Error> {
        let at = |i: usize| map.get(i).copied().ok_or(Error::State);
        if at(EEPROM_TX_PWR_INX + 1)? == 0xff {
            return Err(Error::State);
        }
        let mut out = Self {
            cck: [[0; 14]; 2],
            ht40_1s: [[0; 14]; 2],
            cck_diff: [[0; MAX_TX_COUNT]; 2],
            legacy_ht_diff: [[0; MAX_TX_COUNT]; 2],
            ht20_diff: [[0; MAX_TX_COUNT]; 2],
            ht40_diff: [[0; MAX_TX_COUNT]; 2],
            thermal_meter: 0,
            apk_thermal_meter_ignore: false,
            regulatory: 0,
        };
        for rf in 0..2 {
            let mut addr = EEPROM_TX_PWR_INX + rf * PATH_STRIDE;
            let mut cck_base = [0u8; 6];
            let mut bw40_base = [0u8; 6];
            for b in cck_base.iter_mut() {
                let v = at(addr)?;
                addr += 1;
                *b = if v == 0xff { 0x2d } else { v };
            }
            for b in bw40_base.iter_mut().take(5) {
                let v = at(addr)?;
                addr += 1;
                *b = if v == 0xff { 0x2d } else { v };
            }
            let (mut bw20, mut bw40, mut ofdm, mut cck) = ([0u8; 4], [0u8; 4], [0u8; 4], [0u8; 4]);
            for i in 0..MAX_TX_COUNT {
                let v = at(addr)?;
                if i == 0 {
                    bw40[0] = 0;
                    bw20[0] = if v == 0xff { 0x02 } else { nibble(v >> 4) };
                    ofdm[0] = if v == 0xff { 0x04 } else { nibble(v & 0x0f) };
                    cck[0] = 0;
                    addr += 1;
                } else {
                    bw40[i] = if v == 0xff { 0xfe } else { nibble(v >> 4) };
                    bw20[i] = if v == 0xff { 0xfe } else { nibble(v & 0x0f) };
                    addr += 1;
                    let v = at(addr)?;
                    ofdm[i] = if v == 0xff { 0xfe } else { nibble(v >> 4) };
                    cck[i] = if v == 0xff { 0xfe } else { nibble(v & 0x0f) };
                    addr += 1;
                }
            }
            for ch in 1..=14u8 {
                let i = usize::from(ch - 1);
                let group = chnl_group(ch);
                out.cck[rf][i] = if ch == 14 {
                    cck_base[5]
                } else {
                    cck_base[group]
                };
                out.ht40_1s[rf][i] = bw40_base[group];
            }
            out.cck_diff[rf] = cck;
            out.legacy_ht_diff[rf] = ofdm;
            out.ht20_diff[rf] = bw20;
            out.ht40_diff[rf] = bw40;
        }
        let thermal = at(EEPROM_THERMAL_METER)?;
        if thermal == 0xff {
            out.apk_thermal_meter_ignore = true;
            out.thermal_meter = EEPROM_DEFAULT_THERMALMETER;
        } else {
            out.thermal_meter = thermal;
        }
        let option = at(EEPROM_RF_BOARD_OPTION)?;
        out.regulatory = if option == 0xff { 0 } else { option & 0x07 };
        Ok(out)
    }
}

/// `_rtl92ee_phy_get_ratesection_intxpower_byrate`.
pub fn rate_section(path: usize, rate: u8) -> usize {
    match rate {
        0x00 => 2,
        0x01 | 0x02 => {
            if path == 0 {
                3
            } else {
                2
            }
        }
        0x03 => 3,
        0x04..=0x07 => 0,
        0x08..=0x0b => 1,
        0x0c..=0x0f => 4,
        0x10..=0x13 => 5,
        0x14..=0x17 => 6,
        0x18..=0x1b => 7,
        _ => 0,
    }
}

/// `_rtl92ee_get_txpower_by_rate`.
pub fn by_rate_diff(by_rate: &ByRate, path: usize, rate: u8) -> u8 {
    let section = rate_section(path, rate);
    let tx_num = if (RATE_MCS8..=RATE_MCS15).contains(&rate) {
        RF_2TX
    } else {
        RF_1TX
    };
    let shift = if rate <= RATE_11M {
        u32::from(rate) * 8
    } else {
        u32::from((rate - RATE_6M) % 4) * 8
    };
    (by_rate.offset[path][tx_num][section] >> shift) as u8
}

/// `_rtl92ee_get_txpower_index`.
pub fn index(efuse: &Efuse, by_rate: &ByRate, path: usize, rate: u8, bw: Width, channel: u8) -> u8 {
    let idx = if (1..=14).contains(&channel) {
        usize::from(channel - 1)
    } else {
        0
    };
    let cck = rate <= RATE_11M;
    let mut tx_power = if cck {
        efuse.cck[path][idx]
    } else if rate >= RATE_6M {
        efuse.ht40_1s[path][idx]
    } else {
        0
    };
    if (RATE_6M..=RATE_54M).contains(&rate) && !cck {
        tx_power = tx_power.wrapping_add(efuse.legacy_ht_diff[path][0]);
    }
    let ht = (RATE_MCS0..=RATE_MCS15).contains(&rate);
    let ht2 = (RATE_MCS8..=RATE_MCS15).contains(&rate);
    let diffs = match bw {
        Width::W20 => &efuse.ht20_diff[path],
        Width::W40 => &efuse.ht40_diff[path],
    };
    if ht {
        tx_power = tx_power.wrapping_add(diffs[0]);
    }
    if ht2 {
        tx_power = tx_power.wrapping_add(diffs[1]);
    }
    if efuse.regulatory != 2 {
        tx_power = tx_power.wrapping_add(by_rate_diff(by_rate, path, rate));
    }
    tx_power.min(MAX_POWER_INDEX)
}

/// `_rtl92ee_set_txpower_index`: (register, byte lane).
pub fn txagc(path: usize, rate: u8) -> Option<(u16, u32)> {
    const A: [u16; 6] = [0xe00, 0xe04, 0xe10, 0xe14, 0xe18, 0xe1c];
    const B: [u16; 6] = [0x830, 0x834, 0x83c, 0x848, 0x84c, 0x868];
    if rate > RATE_MCS15 {
        return None;
    }
    Some(match (path, rate) {
        (0, 0x00) => (0xe08, 1),
        (0, 0x01..=0x03) => (0x86c, u32::from(rate)),
        (1, 0x00..=0x02) => (0x838, u32::from(rate) + 1),
        (1, 0x03) => (0x86c, 0),
        (0 | 1, _) => {
            let group = usize::from((rate - RATE_6M) / 4);
            let reg = if path == 0 { A[group] } else { B[group] };
            (reg, u32::from((rate - RATE_6M) % 4))
        }
        _ => return None,
    })
}

/// The rates of `rtl92ee_phy_set_txpower_level` per path, in write order.
pub fn rates() -> impl Iterator<Item = u8> {
    RATE_1M..=RATE_MCS15
}

/// `rtl92ee_phy_set_txpower_level(channel)` at `current_chan_bw`.
pub fn set_level(
    io: &impl Io,
    efuse: &Efuse,
    by_rate: &ByRate,
    bw: Width,
    channel: u8,
) -> Result<(), Error> {
    for path in 0..2 {
        for rate in rates() {
            let power = index(efuse, by_rate, path, rate, bw, channel);
            let (reg, lane) = txagc(path, rate).ok_or(Error::State)?;
            set_bb(io, reg, 0xff << (lane * 8), u32::from(power))?;
        }
    }
    Ok(())
}

/// `rtl92ee_phy_set_txpower_level`'s write order and registers with the
/// envelope-admitted per-path indices instead of the Linux index
/// (`rtl8192ee/envelope.rs`; unadmitted rates are written 0).
pub fn set_indices(io: &impl Io, indices: &[[u8; 28]; 2]) -> Result<(), Error> {
    for (path, row) in indices.iter().enumerate() {
        for rate in rates() {
            let (reg, lane) = txagc(path, rate).ok_or(Error::State)?;
            let power = row[usize::from(rate)].min(MAX_POWER_INDEX);
            set_bb(io, reg, 0xff << (lane * 8), u32::from(power))?;
        }
    }
    Ok(())
}
