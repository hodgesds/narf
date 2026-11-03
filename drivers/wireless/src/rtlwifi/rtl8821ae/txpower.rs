// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE path-A TX power index computation.
//!
//! Exact Linux arithmetic, restricted to what a 1T1R station programs at
//! 2.4 GHz 20/40 MHz and 5 GHz 20/40/80 MHz:
//!
//! - `rtl8821ae/hw.c::_rtl8821ae_read_power_value_fromprom` /
//!   `_rtl8821ae_read_txpower_info_from_hwpg` (path A: 2.4 GHz CCK/BW40
//!   bases from `EEPROM_TX_PWR_INX`, 4-bit signed BW20/OFDM diffs; 5 GHz
//!   14 BW40 group bases at `0x22`, BW20/OFDM diffs at `0x30`, BW80 diff at
//!   `0x36`; BW80 base `(group + next group) / 2` per `channel5g_80m`;
//!   `TX_1S` BW40 diffs are 0 in both bands; `EEPROM_RF_BOARD_OPTION`
//!   regulatory selector). Linux substitutes `0x2D` defaults for an
//!   unprogrammed map or 2.4 GHz group and `0xFE` for an unprogrammed 5 GHz
//!   group; here such a board/group yields no factory power.
//! - The index is computed at the *wide* channel `core.c::rtl_op_config`
//!   stores in `rtlphy->current_channel` (40 MHz: primary ± 2; 80 MHz: the
//!   80 MHz center), which also selects the limit row.
//! - `phy.c::_rtl8821ae_phy_config_bb_with_pgheaderfile` →
//!   `_rtl8821ae_store_tx_power_by_rate`, `_rtl8821ae_phy_store_txpower_by_rate_base`
//!   and `_rtl8821ae_phy_convert_txpower_dbm_to_relative_value` (including the
//!   absolute-difference "relative" value Linux computes).
//! - `_rtl8812ae_phy_set_txpower_limit` (minimum of duplicate rows, clamp to
//!   `MAX_POWER_INDEX`), `_rtl8812ae_phy_cross_reference_ht_and_vht_txpower_limit`
//!   (5 GHz 20/40 MHz HT 1T <-> VHT 1T, HT 2T <-> VHT 2T fill-in),
//!   `_rtl8812ae_phy_convert_txpower_limit_to_power_index` (including its
//!   2.4 GHz VHT base-index carry-over) and `_rtl8812ae_phy_get_txpower_limit`
//!   with `TXPWR_LMT_WW` (minimum across FCC/MKK/ETSI/WW; OFDM forced to the
//!   20 MHz rows; 5 GHz HT at 80 MHz reads the 40 MHz rows).
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
    /// Not a channel of the band/width or not a station rate of the band.
    Channel,
    /// Linux arithmetic would wrap below zero.
    Underflow,
}

/// `core.c` `channel5g` (`CHANNEL_MAX_NUMBER_5G`): the per-channel index of
/// the 5 GHz efuse levels and limit rows (20 MHz primaries and 40/80 MHz
/// wide channels).
pub const CHANNEL5G: [u8; 49] = [
    36, 38, 40, 42, 44, 46, 48, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 116,
    118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159,
    161, 165, 167, 169, 171, 173, 175, 177,
];
/// `core.c` `channel5g_80m`.
pub const CHANNEL5G_80M: [u8; 7] = [42, 58, 106, 122, 138, 155, 171];
/// 5 GHz path-A efuse block (`struct txpower_info_5g`, after the 2.4 GHz
/// path-A block).
pub const EEPROM_5G_BW40_BASE: usize = 0x22;
pub const EEPROM_5G_DIFF: usize = 0x30;
pub const EEPROM_5G_BW80_DIFF: usize = 0x36;

/// Path-A 5 GHz factory power (`struct txpower_info_5g`, TX_1S only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory5g {
    /// `index_bw40_base[A][0..14]` raw; a group above `MAX_POWER_INDEX`
    /// (unprogrammed `0xff`, which Linux turns into `0xFE`) is refused when
    /// a channel selects it.
    pub bw40_base: [u8; 14],
    /// `bw20_diff[A][0]` (high nibble of `0x30`).
    pub bw20_diff: i8,
    /// `ofdm_diff[A][0]` (low nibble of `0x30`).
    pub ofdm_diff: i8,
    /// `bw80_diff[A][0]` (high nibble of `0x36`); `None` when unprogrammed.
    pub bw80_diff: Option<i8>,
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
    /// 5 GHz block; `None` when its diff byte is unprogrammed.
    pub five_ghz: Option<Factory5g>,
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
        let five_ghz = match (
            map.get(EEPROM_5G_BW40_BASE..EEPROM_5G_BW40_BASE + 14),
            map.get(EEPROM_5G_DIFF),
            map.get(EEPROM_5G_BW80_DIFF),
        ) {
            (Some(base), Some(&diff), Some(&bw80)) if diff != 0xff => Some(Factory5g {
                bw40_base: base.try_into().unwrap(),
                bw20_diff: nibble(diff >> 4),
                ofdm_diff: nibble(diff & 0xf),
                bw80_diff: (bw80 != 0xff).then(|| nibble(bw80 >> 4)),
            }),
            _ => None,
        };
        Ok(Self {
            cck_base: bytes[..6].try_into().unwrap(),
            bw40_base: bytes[6..11].try_into().unwrap(),
            bw20_diff: nibble(diff >> 4),
            ofdm_diff: nibble(diff & 0xf),
            regulatory: if option == 0xff { 0 } else { option & 7 },
            five_ghz,
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

/// `_rtl8821ae_get_chnl_group` for 5 GHz (`None` where Linux WARNs).
pub fn channel_group_5g(channel: u8) -> Option<u8> {
    Some(match channel {
        36..=42 => 0,
        44..=48 => 1,
        50..=58 => 2,
        60..=64 => 3,
        100..=106 => 4,
        108..=114 => 5,
        116..=122 => 6,
        124..=130 => 7,
        132..=138 => 8,
        140..=144 => 9,
        149..=155 => 10,
        157..=161 => 11,
        165..=171 => 12,
        173..=177 => 13,
        _ => return None,
    })
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

/// Linux limit rate section (0 CCK, 1 OFDM, 2 HT 1T, 3 HT 2T, 4 VHT 1T,
/// 5 VHT 2T) for a full-order rate (`_rtl8812ae_phy_get_txpower_limit`).
fn limit_section(rate: u8) -> u8 {
    match rate {
        0..=3 => 0,
        4..=11 => 1,
        12..=19 => 2,
        20..=27 => 3,
        28..=37 => 4,
        _ => 5,
    }
}

fn section_key(section: u8) -> (Section, u8) {
    match section {
        0 => (Section::Cck, 1),
        1 => (Section::Ofdm, 1),
        2 => (Section::Ht, 1),
        3 => (Section::Ht, 2),
        4 => (Section::Vht, 1),
        _ => (Section::Vht, 2),
    }
}

/// `txpwr_limit_{2_4g,5g}[regulation][bw][section][channel][A]` as stored
/// by `_rtl8812ae_phy_set_txpower_limit` (minimum of duplicate rows, each
/// clamped to `MAX_POWER_INDEX`; `MAX_POWER_INDEX` when no row).
fn stored_limit(
    regulation: Regulation,
    band: Band,
    bandwidth: Bandwidth,
    section: u8,
    channel: u8,
) -> u8 {
    let (section, ntx) = section_key(section);
    tables::TXPWR_LMT
        .iter()
        .filter(|row| {
            row.regulation == regulation
                && row.band == band
                && row.bandwidth == bandwidth
                && row.section == section
                && row.ntx == ntx
                && row.channel == channel
        })
        .map(|row| row.limit.min(MAX_POWER_INDEX))
        .fold(MAX_POWER_INDEX, u8::min)
}

/// Path-A power-by-rate state after `_rtl8821ae_phy_txpower_by_rate_configuration`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByRate {
    /// `tx_power_by_rate_offset[BAND_ON_2_4G][RF90_PATH_A][txnum][section]`.
    pub offset: [[u32; 12]; 2],
    /// `txpwr_by_rate_base_24g[RF90_PATH_A][txnum][0..6]`.
    pub base: [[u8; 6]; 2],
    /// `tx_power_by_rate_offset[BAND_ON_5G][RF90_PATH_A][txnum][section]`.
    pub offset_5g: [[u32; 12]; 2],
    /// `txpwr_by_rate_base_5g[RF90_PATH_A][txnum][0..5]`.
    pub base_5g: [[u8; 5]; 2],
}

impl ByRate {
    /// Walk `RTL8821AE_PHY_REG_ARRAY_PG` (no conditional or delay rows for
    /// this chip), store, derive bases and convert to relative values.
    pub fn from_table() -> Self {
        let mut offsets = [[[0u32; 12]; 2]; 2];
        for row in tables::PHY_REG_PG {
            let [band, path, txnum, addr, _mask, data] = *row;
            // Linux clamps a bad band to 2.4 GHz and paths/txnum to the last.
            if band > 1 || path != 0 {
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
            offsets[band as usize][txnum.min(1) as usize][section as usize] = data;
        }
        let [mut offset, mut offset_5g] = offsets;
        let mut base = [[0u8; 6]; 2];
        base[0][0] = bcd(offset[0][0] >> 24);
        base[0][1] = bcd(offset[0][2] >> 24);
        base[0][2] = bcd(offset[0][4] >> 24);
        base[1][3] = bcd(offset[1][6] >> 24);
        base[0][4] = bcd(offset[0][8] >> 24);
        base[1][5] = bcd(offset[1][11] >> 8);
        let mut base_5g = [[0u8; 5]; 2];
        base_5g[0][0] = bcd(offset_5g[0][2] >> 24);
        base_5g[0][1] = bcd(offset_5g[0][4] >> 24);
        base_5g[1][2] = bcd(offset_5g[1][6] >> 24);
        base_5g[0][3] = bcd(offset_5g[0][8] >> 24);
        base_5g[1][4] = bcd(offset_5g[1][11] >> 8);
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
        relative(&mut offset_5g[0][1], 0, 3, base_5g[0][0]);
        relative(&mut offset_5g[0][2], 0, 3, base_5g[0][0]);
        relative(&mut offset_5g[0][3], 0, 3, base_5g[0][1]);
        relative(&mut offset_5g[0][4], 0, 3, base_5g[0][1]);
        relative(&mut offset_5g[1][5], 0, 3, base_5g[1][2]);
        relative(&mut offset_5g[1][6], 0, 3, base_5g[1][2]);
        relative(&mut offset_5g[0][7], 0, 3, base_5g[0][3]);
        relative(&mut offset_5g[0][8], 0, 3, base_5g[0][3]);
        relative(&mut offset_5g[0][9], 0, 1, base_5g[0][3]);
        relative(&mut offset_5g[0][9], 2, 3, base_5g[1][4]);
        relative(&mut offset_5g[1][10], 0, 3, base_5g[1][4]);
        relative(&mut offset_5g[1][11], 0, 3, base_5g[1][4]);
        Self {
            offset,
            base,
            offset_5g,
            base_5g,
        }
    }

    /// Base subtracted from a section's limit by
    /// `_rtl8812ae_phy_convert_txpower_limit_to_power_index`. 2.4 GHz VHT
    /// (sections 4/5) inherits section 3's base index with `RF_1TX`, which
    /// is never stored, so its base is 0 exactly as in Linux; 5 GHz CCK has
    /// no rows and is never converted.
    fn limit_base(&self, band: Band, section: u8) -> u8 {
        match (band, section) {
            (Band::B2g, 0) => self.base[0][0],
            (Band::B2g, 1) => self.base[0][1],
            (Band::B2g, 2) => self.base[0][2],
            (Band::B2g, 3) => self.base[1][3],
            (Band::B2g, _) => self.base[0][3],
            (_, 1) => self.base_5g[0][0],
            (_, 2) => self.base_5g[0][1],
            (_, 3) => self.base_5g[1][2],
            (_, 4) => self.base_5g[0][3],
            (_, 5) => self.base_5g[1][4],
            _ => 0,
        }
    }

    /// `_rtl8812ae_phy_get_txpower_limit` (`TXPWR_LMT_WW`) after cross
    /// reference and limit-to-power-index conversion. `channel` is the wide
    /// channel (`rtlphy->current_channel`); `bandwidth` is
    /// `rtlphy->current_chan_bw`.
    pub fn limit_at(&self, band: Band, bandwidth: Bandwidth, rate: u8, channel: u8) -> i8 {
        let section = limit_section(rate);
        let valid = match band {
            Band::B2g => (1..=14).contains(&channel),
            Band::B5g => CHANNEL5G.contains(&channel),
        };
        if !valid || bandwidth == Bandwidth::Bw160 {
            return MAX_POWER_INDEX as i8;
        }
        // OFDM limits exist only for 20 MHz; 5 GHz HT at 80 MHz reads 40 MHz.
        let bandwidth = if section == 1 {
            Bandwidth::Bw20
        } else if band == Band::B5g && matches!(section, 2 | 3) && bandwidth == Bandwidth::Bw80 {
            Bandwidth::Bw40
        } else {
            bandwidth
        };
        let base = self.limit_base(band, section);
        let mut world = MAX_POWER_INDEX as i8;
        // WW13 has no rows for this chip: its entry stays MAX_POWER_INDEX.
        for regulation in [Regulation::Fcc, Regulation::Mkk, Regulation::Etsi] {
            let stored = |s| stored_limit(regulation, band, bandwidth, s, channel);
            let mut raw = stored(section);
            // `_rtl8812ae_phy_cross_reference_ht_and_vht_txpower_limit`:
            // 5 GHz 20/40 MHz, in section order 2, 3, 4, 5 (so 4 sees the
            // already cross-referenced 2, and 5 the cross-referenced 3).
            if band == Band::B5g
                && matches!(bandwidth, Bandwidth::Bw20 | Bandwidth::Bw40)
                && raw == MAX_POWER_INDEX
            {
                raw = match section {
                    2 | 3 => stored(section + 2),
                    4 | 5 => stored(section - 2),
                    _ => raw,
                };
            }
            let converted = if raw == MAX_POWER_INDEX {
                MAX_POWER_INDEX as i8
            } else {
                (raw as i8).wrapping_sub(base as i8)
            };
            world = world.min(converted);
        }
        world
    }

    /// 2.4 GHz 20 MHz [`Self::limit_at`].
    pub fn limit(&self, rate: u8, channel: u8) -> i8 {
        self.limit_at(Band::B2g, Bandwidth::Bw20, rate, channel)
    }

    /// `_rtl8821ae_phy_get_txpower_by_rate` for path A.
    pub fn by_rate_at(
        &self,
        band: Band,
        bandwidth: Bandwidth,
        rate: u8,
        channel: u8,
        regulatory: u8,
    ) -> i8 {
        let two = (20..=27).contains(&rate) || (40..=47).contains(&rate);
        let section = usize::from(rate / 4).min(11);
        let shift = u32::from(rate % 4) * 8;
        let table = match band {
            Band::B2g => &self.offset,
            Band::B5g => &self.offset_5g,
        };
        let mut diff = (table[usize::from(two)][section] >> shift) as u8 as i8;
        if regulatory != 2 {
            let limit = self.limit_at(band, bandwidth, rate, channel);
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

    /// 2.4 GHz 20 MHz [`Self::by_rate_at`].
    pub fn by_rate(&self, rate: u8, channel: u8, regulatory: u8) -> i8 {
        self.by_rate_at(Band::B2g, Bandwidth::Bw20, rate, channel, regulatory)
    }

    /// `_rtl8821ae_get_txpower_index` for path A at 2.4 GHz 20 MHz.
    pub fn index(&self, factory: &Factory, rate: u8, channel: u8) -> Result<u8, Error> {
        self.index_at(factory, Band::B2g, Bandwidth::Bw20, rate, channel)
    }

    /// `_rtl8821ae_get_txpower_index` for path A. `channel` is the wide
    /// channel Linux passes (`rtlphy->current_channel`).
    pub fn index_at(
        &self,
        factory: &Factory,
        band: Band,
        bandwidth: Bandwidth,
        rate: u8,
        channel: u8,
    ) -> Result<u8, Error> {
        if !station_rates().any(|r| r == rate) || bandwidth == Bandwidth::Bw160 {
            return Err(Error::Channel);
        }
        let ht = HT_1S.contains(&rate) || VHT_1S.contains(&rate);
        let mut power = match band {
            Band::B2g => {
                if !(1..=14).contains(&channel) || bandwidth == Bandwidth::Bw80 {
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
                // txpwr_ht40diff[TX_1S] is 0 (hw.c), so only 20 MHz adds.
                if ht && bandwidth == Bandwidth::Bw20 {
                    power += i16::from(factory.bw20_diff);
                }
                power
            }
            Band::B5g => {
                if CCK.contains(&rate) || !CHANNEL5G.contains(&channel) {
                    return Err(Error::Channel);
                }
                let five = factory.five_ghz.ok_or(Error::FactoryPower)?;
                let base = |group: u8| {
                    let value = five.bw40_base[usize::from(group)];
                    if value > MAX_POWER_INDEX {
                        Err(Error::FactoryPower)
                    } else {
                        Ok(i16::from(value))
                    }
                };
                let group = channel_group_5g(channel).ok_or(Error::Channel)?;
                let mut power = base(group)?;
                if OFDM.contains(&rate) {
                    power += i16::from(five.ofdm_diff);
                }
                if ht {
                    match bandwidth {
                        Bandwidth::Bw20 => power += i16::from(five.bw20_diff),
                        // txpwr_5g_bw40diff[TX_1S] is 0 (hw.c).
                        Bandwidth::Bw40 => {}
                        _ => {
                            // txpwr_5g_bw80base: (group + next group) / 2.
                            if !CHANNEL5G_80M.contains(&channel) {
                                return Err(Error::Channel);
                            }
                            let diff = five.bw80_diff.ok_or(Error::FactoryPower)?;
                            power = (base(group)? + base(group + 1)?) / 2 + i16::from(diff);
                        }
                    }
                }
                power
            }
        };
        if factory.regulatory != 2 {
            let diff =
                i16::from(self.by_rate_at(band, bandwidth, rate, channel, factory.regulatory));
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
