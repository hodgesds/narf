// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE 2.4 GHz path-A TX power index computation.
//!
//! Exact Linux arithmetic, restricted to what a 1T1R 2.4 GHz 20 MHz station
//! programs:
//!
//! - `rtl8821ae/hw.c::_rtl8821ae_read_power_value_fromprom` /
//!   `_rtl8821ae_read_txpower_info_from_hwpg` (path A: CCK/BW40 bases from
//!   `EEPROM_TX_PWR_INX`, 4-bit signed BW20/OFDM diffs, `EEPROM_RF_BOARD_OPTION`
//!   regulatory selector). Linux substitutes `0x2D` defaults for an
//!   unprogrammed map or group; here such a board yields no factory power.
//! - `phy.c::_rtl8821ae_phy_config_bb_with_pgheaderfile` →
//!   `_rtl8821ae_store_tx_power_by_rate`, `_rtl8821ae_phy_store_txpower_by_rate_base`
//!   and `_rtl8821ae_phy_convert_txpower_dbm_to_relative_value` (including the
//!   absolute-difference "relative" value Linux computes).
//! - `_rtl8812ae_phy_set_txpower_limit` (minimum of duplicate rows, clamp to
//!   `MAX_POWER_INDEX`), `_rtl8812ae_phy_convert_txpower_limit_to_power_index`
//!   (including its 2.4 GHz VHT base-index carry-over) and
//!   `_rtl8812ae_phy_get_txpower_limit` with `TXPWR_LMT_WW` (minimum across
//!   FCC/MKK/ETSI/WW).
//! - `_rtl8821ae_phy_get_txpower_by_rate` and `_rtl8821ae_get_txpower_index`
//!   (remnant swing indices are 0: thermal tracking is not part of this owner).
//!
//! Deviation: Linux keeps the index in a `u8` and lets a negative sum wrap to
//! a large value that is then clamped to `MAX_POWER_INDEX`; such a result is
//! refused here instead of becoming the maximum gain.

use super::power_limit::{Band, Bandwidth, Regulation, Section};
use super::tables;

/// `MAX_POWER_INDEX`.
pub const MAX_POWER_INDEX: u8 = 63;
/// `EEPROM_TX_PWR_INX` / `EEPROM_RF_BOARD_OPTION` (`reg.h`).
pub const EEPROM_TX_PWR_INX: usize = 0x10;
pub const EEPROM_RF_BOARD_OPTION: usize = 0xc1;

/// Full Linux TXAGC rate order (`DESC_RATE1M` .. `DESC_RATEVHT2SS_MCS9`):
/// CCK 0..=3, OFDM 4..=11, MCS0-15 12..=27, VHT1SS 28..=37, VHT2SS 38..=47.
/// The register is `0xc20 + 4 * (rate / 4)`, byte `rate % 4`.
pub const CCK: core::ops::RangeInclusive<u8> = 0..=3;
pub const OFDM: core::ops::RangeInclusive<u8> = 4..=11;
pub const HT_1S: core::ops::RangeInclusive<u8> = 12..=19;
pub const VHT_1S: core::ops::RangeInclusive<u8> = 28..=37;

/// Rates a 2.4 GHz 1T1R station programs (`rtl8821ae_phy_set_txpower_level_by_path`).
pub fn station_rates() -> impl Iterator<Item = u8> {
    CCK.chain(OFDM).chain(HT_1S).chain(VHT_1S)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Unprogrammed or out-of-range factory power bytes.
    FactoryPower,
    /// Not a 2.4 GHz channel 1..=14 or not a station rate.
    Channel,
    /// Linux arithmetic would wrap below zero.
    Underflow,
}

/// Path-A 2.4 GHz factory power (`struct txpower_info_2g`, TX_1S only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    pub cck_base: [u8; 6],
    pub bw40_base: [u8; 5],
    /// `bw20_diff[A][0]` (high nibble of `0x1b`, 4-bit signed).
    pub bw20_diff: i8,
    /// `ofdm_diff[A][0]` (low nibble of `0x1b`, 4-bit signed).
    pub ofdm_diff: i8,
    /// `rtlefuse->eeprom_regulatory`.
    pub regulatory: u8,
}

fn nibble(value: u8) -> i8 {
    if value & 8 != 0 {
        (value | 0xf0) as i8
    } else {
        value as i8
    }
}

impl Factory {
    pub fn from_logical(map: &[u8]) -> Result<Self, Error> {
        let at = EEPROM_TX_PWR_INX;
        let bytes = map.get(at..at + 12).ok_or(Error::FactoryPower)?;
        // Linux: hwinfo[EEPROM_TX_PWR_INX + 1] == 0xff ⇒ autoload_fail.
        if bytes[1] == 0xff || bytes[..11].iter().any(|b| *b > MAX_POWER_INDEX) {
            return Err(Error::FactoryPower);
        }
        let diff = bytes[11];
        if diff == 0xff {
            return Err(Error::FactoryPower);
        }
        let option = *map.get(EEPROM_RF_BOARD_OPTION).ok_or(Error::FactoryPower)?;
        Ok(Self {
            cck_base: bytes[..6].try_into().unwrap(),
            bw40_base: bytes[6..11].try_into().unwrap(),
            bw20_diff: nibble(diff >> 4),
            ofdm_diff: nibble(diff & 0xf),
            regulatory: if option == 0xff { 0 } else { option & 7 },
        })
    }
}

/// `_rtl8821ae_get_chnl_group` for 2.4 GHz.
pub fn channel_group(channel: u8) -> u8 {
    match channel {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        _ => 4,
    }
}

fn bcd(raw: u32) -> u8 {
    let raw = (raw & 0xff) as u8;
    (raw >> 4) * 10 + (raw & 0xf)
}

/// `_phy_convert_txpower_dbm_to_relative_value`.
fn relative(data: &mut u32, start: u8, end: u8, base: u8) {
    let mut out = 0u32;
    for i in (0..4u8).rev() {
        let byte = (*data >> (u32::from(i) * 8)) as u8;
        let value = if i >= start && i <= end {
            let value = (byte & 0xf) + (byte >> 4) * 10;
            value.abs_diff(base)
        } else {
            byte
        };
        out = (out << 8) | u32::from(value);
    }
    *data = out;
}

/// 2.4 GHz path-A power-by-rate state after `_rtl8821ae_phy_txpower_by_rate_configuration`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByRate {
    /// `tx_power_by_rate_offset[BAND_ON_2_4G][RF90_PATH_A][txnum][section]`.
    pub offset: [[u32; 12]; 2],
    /// `txpwr_by_rate_base_24g[RF90_PATH_A][txnum][0..6]`.
    pub base: [[u8; 6]; 2],
}

impl ByRate {
    /// Walk `RTL8821AE_PHY_REG_ARRAY_PG` (no conditional or delay rows for
    /// this chip), store, derive bases and convert to relative values.
    pub fn from_table() -> Self {
        let mut offset = [[0u32; 12]; 2];
        for row in tables::PHY_REG_PG {
            let [band, path, txnum, addr, _mask, data] = *row;
            // Linux clamps a bad band to 2.4 GHz and paths/txnum to the last.
            if band != 0 || path != 0 {
                continue;
            }
            let addr = addr & 0xfff;
            let section = if (0xc20..=0xc4c).contains(&addr) {
                (addr - 0xc20) / 4
            } else if (0xe20..=0xe4c).contains(&addr) {
                (addr - 0xe20) / 4
            } else {
                0
            };
            offset[txnum.min(1) as usize][section as usize] = data;
        }
        let mut base = [[0u8; 6]; 2];
        base[0][0] = bcd(offset[0][0] >> 24);
        base[0][1] = bcd(offset[0][2] >> 24);
        base[0][2] = bcd(offset[0][4] >> 24);
        base[1][3] = bcd(offset[1][6] >> 24);
        base[0][4] = bcd(offset[0][8] >> 24);
        base[1][5] = bcd(offset[1][11] >> 8);
        relative(&mut offset[0][0], 0, 3, base[0][0]);
        relative(&mut offset[0][1], 0, 3, base[0][1]);
        relative(&mut offset[0][2], 0, 3, base[0][1]);
        relative(&mut offset[0][3], 0, 3, base[0][2]);
        relative(&mut offset[0][4], 0, 3, base[0][2]);
        relative(&mut offset[1][5], 0, 3, base[1][3]);
        relative(&mut offset[1][6], 0, 3, base[1][3]);
        relative(&mut offset[0][7], 0, 3, base[0][4]);
        relative(&mut offset[0][8], 0, 3, base[0][4]);
        relative(&mut offset[0][9], 0, 1, base[0][4]);
        relative(&mut offset[0][9], 2, 3, base[1][5]);
        relative(&mut offset[1][10], 0, 3, base[1][5]);
        relative(&mut offset[1][11], 0, 3, base[1][5]);
        Self { offset, base }
    }

    /// `_rtl8812ae_phy_get_txpower_limit` (2.4 GHz, `TXPWR_LMT_WW`, 20 MHz)
    /// after limit-to-power-index conversion.
    pub fn limit(&self, rate: u8, channel: u8) -> i8 {
        // (limit section, base txnum/index) from the conversion loop. VHT
        // (section 4) inherits section 3's base index with RF_1TX, which is
        // never stored, so its base is 0 exactly as in Linux.
        let (section, ntx, base) = match rate {
            0..=3 => (Section::Cck, 1, self.base[0][0]),
            4..=11 => (Section::Ofdm, 1, self.base[0][1]),
            12..=19 => (Section::Ht, 1, self.base[0][2]),
            20..=27 => (Section::Ht, 2, self.base[1][3]),
            28..=37 => (Section::Vht, 1, self.base[0][3]),
            _ => (Section::Vht, 2, self.base[0][3]),
        };
        let mut world = MAX_POWER_INDEX as i8;
        for regulation in [Regulation::Fcc, Regulation::Mkk, Regulation::Etsi] {
            let raw = tables::TXPWR_LMT
                .iter()
                .filter(|row| {
                    row.regulation == regulation
                        && row.band == Band::B2g
                        // OFDM limits exist only for 20 MHz (forced in Linux).
                        && row.bandwidth == Bandwidth::Bw20
                        && row.section == section
                        && row.ntx == ntx
                        && row.channel == channel
                })
                .map(|row| row.limit.min(MAX_POWER_INDEX))
                .fold(MAX_POWER_INDEX, u8::min);
            let converted = if raw == MAX_POWER_INDEX {
                MAX_POWER_INDEX as i8
            } else {
                (raw as i8).wrapping_sub(base as i8)
            };
            world = world.min(converted);
        }
        world
    }

    /// `_rtl8821ae_phy_get_txpower_by_rate` for 2.4 GHz path A.
    pub fn by_rate(&self, rate: u8, channel: u8, regulatory: u8) -> i8 {
        let two = (20..=27).contains(&rate) || (40..=47).contains(&rate);
        let section = usize::from(rate / 4);
        let shift = u32::from(rate % 4) * 8;
        let mut diff = (self.offset[usize::from(two)][section] >> shift) as u8 as i8;
        if regulatory != 2 {
            let limit = self.limit(rate, channel);
            if matches!(rate, 36 | 37 | 46 | 47) {
                if limit < 0 && diff < limit.wrapping_neg() {
                    diff = limit.wrapping_neg();
                }
            } else if limit < 0 {
                diff = limit;
            } else {
                diff = diff.min(limit);
            }
        }
        diff
    }

    /// `_rtl8821ae_get_txpower_index` for 2.4 GHz path A at 20 MHz.
    pub fn index(&self, factory: &Factory, rate: u8, channel: u8) -> Result<u8, Error> {
        if !(1..=14).contains(&channel) || !station_rates().any(|r| r == rate) {
            return Err(Error::Channel);
        }
        let group = usize::from(channel_group(channel));
        let mut power = i16::from(if CCK.contains(&rate) {
            if channel == 14 {
                factory.cck_base[5]
            } else {
                factory.cck_base[group]
            }
        } else {
            factory.bw40_base[group]
        });
        if OFDM.contains(&rate) {
            power += i16::from(factory.ofdm_diff);
        }
        if HT_1S.contains(&rate) || VHT_1S.contains(&rate) {
            power += i16::from(factory.bw20_diff);
        }
        if factory.regulatory != 2 {
            let diff = i16::from(self.by_rate(rate, channel, factory.regulatory));
            if matches!(rate, 36 | 37) {
                power -= diff;
            } else {
                power += diff;
            }
        }
        if power < 0 {
            return Err(Error::Underflow);
        }
        Ok(power.min(i16::from(MAX_POWER_INDEX)) as u8)
    }
}
