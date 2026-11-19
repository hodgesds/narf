// SPDX-License-Identifier: GPL-2.0-or-later
//! 5GHz channel facts shared by the C21/C22 `set_channel` programs and the
//! factory TX power ceilings. Pure Linux 7.3-rc4 tables only:
//! `main.h::IS_CH_5G_BAND_{1,2,3,4}`, `phy.c::rtw_get_channel_group`,
//! `phy.c::rtw_phy_get_5g_tx_power_index` over `main.h::rtw_5g_txpwr_idx`,
//! `rtw8822c.c::rtw8822c_set_channel_bb` (5GHz RXAGC/SCOTRK) and
//! `rtw8821c.c::rtw8821c_set_channel_bb` (5GHz TXSCALE/CLKTRK).
//!
//! Nothing here admits a channel: admission stays with the signed
//! per-channel records and the installed regulatory domain.

/// `IS_CH_5G_BAND(channel)`: 1 = 36..=48, 2 = 52..=64, 3 = 100..=144,
/// 4 = 149..=177; None outside the 5GHz bands.
pub(super) const fn band(channel: u8) -> Option<u8> {
    match channel {
        36..=48 => Some(1),
        52..=64 => Some(2),
        100..=144 => Some(3),
        149..=177 => Some(4),
        _ => None,
    }
}

/// `rtw_get_channel_group` for a 5GHz channel number listed by Linux
/// (20/40/80MHz centers and primaries). Unlisted numbers return None where
/// Linux would WARN and fall back to group 0.
pub(super) const fn group(channel: u8) -> Option<usize> {
    Some(match channel {
        36 | 38 | 40 | 42 => 0,
        44 | 46 | 48 | 50 => 1,
        52 | 54 | 56 | 58 => 2,
        60 | 62 | 64 => 3,
        100 | 102 | 104 | 106 => 4,
        108 | 110 | 112 | 114 => 5,
        116 | 118 | 120 | 122 => 6,
        124 | 126 | 128 | 130 => 7,
        132 | 134 | 136 | 138 => 8,
        140 | 142 | 144 => 9,
        149 | 151 | 153 | 155 => 10,
        157 | 159 | 161 => 11,
        165 | 167 | 169 | 171 => 12,
        173 | 175 | 177 => 13,
        _ => return None,
    })
}

/// A 5GHz 20MHz primary: a multiple-of-four channel in a Linux band with a
/// Linux channel group (36..=64, 100..=144, 149..=177 step 4 from 149).
pub(super) const fn primary(channel: u8) -> bool {
    band(channel).is_some()
        && group(channel).is_some()
        && if channel >= 149 {
            (channel - 149) % 4 == 0
        } else {
            channel % 4 == 0
        }
}

/// `ieee80211_channel_to_frequency` for a 5GHz channel.
pub(super) const fn frequency(channel: u8) -> Option<u16> {
    match band(channel) {
        Some(_) => Some(5000 + 5 * channel as u16),
        None => None,
    }
}

/// `rtw8822c_set_channel_bb` 5GHz REG_RXAGCCTL{0,} BITS_RXAGC_OFDM.
pub(super) const fn rxagc_ofdm8822c(channel: u8) -> Option<u32> {
    match band(channel) {
        Some(1 | 2) => Some(1),
        Some(3) => Some(2),
        Some(4) => Some(3),
        _ => None,
    }
}

/// `rtw8822c_set_channel_bb` 5GHz REG_SCOTRK (0xc30[11:0]).
pub(super) const fn scotrk8822c(channel: u8) -> Option<u32> {
    Some(match channel {
        36..=51 => 0x494,
        52..=55 => 0x493,
        56..=111 => 0x453,
        112..=119 => 0x452,
        120..=172 => 0x412,
        173..=177 => 0x411,
        _ => return None,
    })
}

/// `rtw8821c_set_channel_bb` 5GHz REG_TXSCALE_A (0xc1c[11:8]).
pub(super) const fn txscale8821c(channel: u8) -> Option<u32> {
    match channel {
        36..=64 => Some(1),
        100..=144 => Some(2),
        149..=u8::MAX => Some(3),
        _ => None,
    }
}

/// `rtw8821c_set_channel_bb` 5GHz REG_CLKTRK (0x860[28:17]). Linux leaves
/// the register unchanged for 5GHz numbers outside these ranges; such a
/// channel is not a supported primary here.
pub(super) const fn clktrk8821c(channel: u8) -> Option<u32> {
    Some(match channel {
        36..=48 => 0x494,
        52..=64 => 0x453,
        100..=116 => 0x452,
        118..=177 => 0x412,
        _ => return None,
    })
}

/// Sign-extend one 4-bit `rtw_*_pwr_idx_diff` field.
const fn nibble(v: u8) -> i8 {
    ((v << 4) as i8) >> 4
}

/// One RF path's `struct rtw_5g_txpwr_idx` (bytes 18..42 of the 42-byte
/// `rtw_txpwr_idx` record after `rtw_2g_txpwr_idx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Power5g {
    bw40_base: [u8; 14],
    /// `ht_1s_diff` (ofdm low nibble, bw20 high nibble).
    ht_1s: u8,
    /// `ht_2s_diff` (bw20 low nibble, bw40 high nibble).
    ht_2s: u8,
    /// `vht_1s_diff` (bw160 low nibble, bw80 high nibble).
    vht_1s: u8,
    /// `vht_2s_diff`.
    vht_2s: u8,
}

impl Power5g {
    /// Parse one path record without Linux's erased-value substitution.
    pub(super) fn parse(path: &[u8]) -> Option<Self> {
        let block = path.get(18..42)?;
        Some(Self {
            bw40_base: block[..14].try_into().ok()?,
            ht_1s: block[14],
            ht_2s: block[15],
            vht_1s: block[20],
            vht_2s: block[21],
        })
    }
    fn base(&self, group: usize) -> Option<u8> {
        self.bw40_base
            .get(group)
            .copied()
            .filter(|b| *b != 0xff && *b <= 63)
    }
    fn add(base: u8, diffs: &[i8], factor: i8) -> Option<u8> {
        let mut v = i16::from(base);
        for d in diffs {
            v += i16::from(*d) * i16::from(factor);
        }
        u8::try_from(v).ok().filter(|v| *v <= 127)
    }
    /// `rtw_phy_get_5g_tx_power_index` for OFDM6..54: `bw40_base[group] +
    /// ht_1s_diff.ofdm * txgi_factor`.
    pub(super) fn ofdm(&self, group: usize, factor: i8) -> Option<u8> {
        Self::add(self.base(group)?, &[nibble(self.ht_1s & 15)], factor)
    }
    /// HT/VHT MCS at 20MHz: `+ ht_1s_diff.bw20` (+ `ht_2s_diff.bw20` for
    /// two spatial streams).
    pub(super) fn bw20(&self, group: usize, two: bool, factor: i8) -> Option<u8> {
        let one = nibble(self.ht_1s >> 4);
        let diffs: &[i8] = if two {
            &[one, nibble(self.ht_2s & 15)]
        } else {
            &[one]
        };
        Self::add(self.base(group)?, diffs, factor)
    }
    /// HT/VHT MCS at 40MHz: `bw40_base` (+ `ht_2s_diff.bw40` for two).
    pub(super) fn bw40(&self, group: usize, two: bool, factor: i8) -> Option<u8> {
        let diffs: &[i8] = if two { &[nibble(self.ht_2s >> 4)] } else { &[] };
        Self::add(self.base(group)?, diffs, factor)
    }
    /// VHT at 80MHz: average of `bw40_base[group]` and `[group + 1]` plus
    /// `vht_1s_diff.bw80` (+ `vht_2s_diff.bw80` for two). Linux integer
    /// division truncates.
    pub(super) fn bw80(&self, group: usize, two: bool, factor: i8) -> Option<u8> {
        let avg = ((u16::from(self.base(group)?) + u16::from(self.base(group + 1)?)) / 2) as u8;
        let one = nibble(self.vht_1s >> 4);
        let diffs: &[i8] = if two {
            &[one, nibble(self.vht_2s >> 4)]
        } else {
            &[one]
        };
        Self::add(avg, diffs, factor)
    }
}

/// Center channel of a 5GHz 40MHz pair: both halves 20MHz primaries of one
/// IEEE 802.11 Annex E 40MHz block (36/40, 44/48, ..., 157/161; class
/// 116/117, 119/120, 122/123, 126/127), the secondary exactly 4 channels
/// from the primary. 165/169 and 173/177 are not admitted.
pub(super) const fn center40(first: u8, secondary: u8) -> Option<u8> {
    let low = if first < secondary { first } else { secondary };
    let base = if low >= 149 { 149 } else { 36 };
    if !primary(first)
        || !primary(secondary)
        || first.abs_diff(secondary) != 4
        || low > 157
        || (low - base) % 8 != 0
    {
        return None;
    }
    Some(low + 2)
}

/// Channel width of one `rtw_set_channel` program with the
/// `rtw_update_channel` primary sub-channel index: 40MHz `RTW_SC_20_UPPER`
/// (1) / `_LOWER` (2); 80MHz additionally `RTW_SC_20_UPMOST` (3) /
/// `_LOWEST` (4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Width {
    Twenty,
    Forty(u8),
    Eighty(u8),
}

impl Width {
    pub(super) const fn mhz(self) -> u8 {
        match self {
            Self::Twenty => 20,
            Self::Forty(_) => 40,
            Self::Eighty(_) => 80,
        }
    }
    /// `primary_ch_idx` (0 at 20MHz).
    pub(super) const fn sc(self) -> u8 {
        match self {
            Self::Twenty => 0,
            Self::Forty(sc) | Self::Eighty(sc) => sc,
        }
    }
    /// Well-formed sub-channel index for the width.
    pub(super) const fn valid(self) -> bool {
        match self {
            Self::Twenty => true,
            Self::Forty(sc) => matches!(sc, 1 | 2),
            Self::Eighty(sc) => matches!(sc, 1..=4),
        }
    }
    /// `mac.c::rtw_set_channel_mac` REG_DATA_SC (0x483): `BIT_TXSC_20M`
    /// = sc and, at 80MHz, `BIT_TXSC_40M` = `RTW_SC_40_UPPER` (9) for
    /// sc 1/3 else `RTW_SC_40_LOWER` (10).
    pub(super) const fn data_sc(self) -> u8 {
        match self {
            Self::Twenty => 0,
            Self::Forty(sc) => sc,
            Self::Eighty(sc) => {
                let sc40: u8 = if matches!(sc, 1 | 3) { 9 } else { 10 };
                sc | sc40 << 4
            }
        }
    }
    /// `rtw_set_channel_mac` REG_WMAC_TRXPTCL_CTL BIT_RFMOD field (0x668
    /// bits 8:7): 40MHz bit7, 80MHz bit8.
    pub(super) const fn rfmod(self) -> u32 {
        match self {
            Self::Twenty => 0,
            Self::Forty(_) => 1,
            Self::Eighty(_) => 2,
        }
    }
}

/// `main.c::rtw_update_channel` sub-channel index of `primary` inside the
/// 40MHz pair centered at `center`.
pub(super) const fn sc40(primary: u8, center: u8) -> u8 {
    if primary > center {
        1
    } else {
        2
    }
}

/// `center` is the center channel of a [`center40`] pair.
pub(super) const fn is_center40(center: u8) -> bool {
    center >= 38 && center40(center - 2, center + 2).is_some()
}

/// Center channel of the 5GHz 80MHz block holding `primary`: IEEE 802.11
/// Annex E class 128 centers 42, 58, 106, 122, 138 and 155 (blocks
/// 36..=48, 52..=64, 100..=112, 116..=128, 132..=144, 149..=161).
pub(super) const fn center80(channel: u8) -> Option<u8> {
    if !primary(channel) {
        return None;
    }
    let center = match channel {
        36..=48 => 42,
        52..=64 => 58,
        100..=112 => 106,
        116..=128 => 122,
        132..=144 => 138,
        149..=161 => 155,
        _ => return None,
    };
    Some(center)
}

/// `center` is a [`center80`] block center.
pub(super) const fn is_center80(center: u8) -> bool {
    matches!(center, 42 | 58 | 106 | 122 | 138 | 155)
}

/// `rtw_update_channel` 80MHz sub-channel index of `primary` in the block
/// centered at `center`: above the center by 10MHz `RTW_SC_20_UPPER` (1),
/// by 30MHz `RTW_SC_20_UPMOST` (3); below by 10MHz `RTW_SC_20_LOWER` (2),
/// by 30MHz `RTW_SC_20_LOWEST` (4).
pub(super) const fn sc80(primary: u8, center: u8) -> u8 {
    match (primary > center, primary.abs_diff(center) == 2) {
        (true, true) => 1,
        (true, false) => 3,
        (false, true) => 2,
        (false, false) => 4,
    }
}

/// The four 20MHz primaries of the 80MHz block centered at `center`.
pub(super) const fn constituents80(center: u8) -> [u8; 4] {
    [center - 6, center - 2, center + 2, center + 6]
}
