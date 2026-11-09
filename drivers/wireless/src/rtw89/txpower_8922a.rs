// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! 8922A TX-power profile: TSSI + gain-offset efuse parse.
//!
//! Mirrors Linux `rtw89/rtw8922a.c`
//! `rtw8922a_efuse_parsing_tssi` and
//! `rtw8922a_efuse_parsing_gain_offset`
//! (torvalds/linux @ 05441d6). This is the profile half of
//! the TX-power program: the per-path calibration values
//! read out of efuse, in typed form, with no RF writes.
//! The consumer half is now `radio_power_be::Plan` (by-rate
//! TX-power tables, regulatory limits, shape, diff/ref/SAR,
//! from the container's firmware TXPWR elements) and
//! `efuse_be::BeFactory::power_trim` (thermal / PA-bias /
//! pad-bias trim parse from the PHY-cap window). Still open:
//! periodic thermal / TSSI tracking, TSSI compensation loops,
//! and the RFK reruns (follow-ups of #1878).
//!
//! Inputs are the raw efuse field values, not an efuse
//! map struct: NARF's 8922A efuse support stops at block
//! geometry (`chip_8922a::EFUSE_BLOCKS`), so the caller
//! supplies the parsed field bytes. The parse itself is
//! total: every input byte maps to exactly one profile
//! entry, so there is no failure case to report.

/// RF paths on 8922A (`RF_PATH_NUM_8922A` = 2).
pub(super) const PATHS: usize = 2;
/// `TSSI_CCK_CH_GROUP_NUM` (`core.h:7039`).
pub(super) const TSSI_CCK_GROUPS: usize = 6;
/// `TSSI_MCS_2G_CH_GROUP_NUM` (`core.h:7040`).
pub(super) const TSSI_MCS_2G_GROUPS: usize = 5;
/// `TSSI_MCS_5G_CH_GROUP_NUM` (`core.h:7041`).
pub(super) const TSSI_MCS_5G_GROUPS: usize = 14;
/// `TSSI_MCS_CH_GROUP_NUM` = 2G + 5G (`core.h:7043`).
pub(super) const TSSI_MCS_GROUPS: usize = TSSI_MCS_2G_GROUPS + TSSI_MCS_5G_GROUPS;
/// `TSSI_MCS_6G_CH_GROUP_NUM` (`core.h:7042`).
pub(super) const TSSI_MCS_6G_GROUPS: usize = 32;
/// `RTW89_GAIN_OFFSET_NR` (`core.h:139..152`): 13 entries.
pub(super) const GAIN_OFFSETS: usize = 13;

/// Gain-offset table indices, in Linux enum order
/// (`core.h` `rtw89_gain_offset`).
pub(super) const GAIN_2G_CCK: usize = 0;
/// 2.4 GHz OFDM gain offset.
pub(super) const GAIN_2G_OFDM: usize = 1;
/// 5 GHz low-subband gain offset.
pub(super) const GAIN_5G_LOW: usize = 2;
/// 5 GHz mid-subband gain offset.
pub(super) const GAIN_5G_MID: usize = 3;
/// 5 GHz high-subband gain offset.
pub(super) const GAIN_5G_HIGH: usize = 4;
/// 6 GHz L0 gain offset.
pub(super) const GAIN_6G_L0: usize = 5;
/// 6 GHz L1 gain offset.
pub(super) const GAIN_6G_L1: usize = 6;
/// 6 GHz M0 gain offset.
pub(super) const GAIN_6G_M0: usize = 7;
/// 6 GHz M1 gain offset.
pub(super) const GAIN_6G_M1: usize = 8;
/// 6 GHz H0 gain offset.
pub(super) const GAIN_6G_H0: usize = 9;
/// 6 GHz H1 gain offset.
pub(super) const GAIN_6G_H1: usize = 10;
/// 6 GHz UH0 gain offset.
pub(super) const GAIN_6G_UH0: usize = 11;
/// 6 GHz UH1 gain offset.
pub(super) const GAIN_6G_UH1: usize = 12;

/// Raw efuse fields for one path: the thermal byte, the
/// `rtw8922a_tssi_offset` groups (`rtw8922a.h:13..19`),
/// and the 6 GHz TSSI array. `bw40_tssi` covers the 2.4
/// GHz groups; `bw40_1s_tssi_5g` the 5 GHz groups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PathEfuse {
    /// `path_{a,b}_therm`.
    pub(super) therm: u8,
    /// `cck_tssi[6]`.
    pub(super) cck_tssi: [u8; TSSI_CCK_GROUPS],
    /// `bw40_tssi[5]` (2.4 GHz MCS groups).
    pub(super) bw40_tssi: [u8; TSSI_MCS_2G_GROUPS],
    /// `bw40_1s_tssi_5g[14]` (5 GHz MCS groups).
    pub(super) bw40_1s_tssi_5g: [u8; TSSI_MCS_5G_GROUPS],
    /// `bw40_1s_tssi_6g_{a,b}[32]`.
    pub(super) bw40_1s_tssi_6g: [u8; TSSI_MCS_6G_GROUPS],
}

/// Parsed TSSI profile, mirroring the fields Linux
/// `rtw8922a_efuse_parsing_tssi` fills in `rtw89_tssi_info`
/// (`core.h:7048..7064`). Efuse bytes are copied
/// bit-preserving into i8 slots (Linux memcpys u8 arrays
/// into s8 arrays); trim groups, `bw_diff_5g`, and the
/// tracking/alignment state are not part of this parse.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct TssiProfile {
    /// Thermal byte per path.
    thermal: [u8; PATHS],
    /// CCK TSSI offsets per path, per channel group.
    tssi_cck: [[i8; TSSI_CCK_GROUPS]; PATHS],
    /// MCS TSSI offsets per path: groups 0..5 are 2.4 GHz,
    /// groups 5..19 are 5 GHz (Linux concatenates the two
    /// arrays in that order).
    tssi_mcs: [[i8; TSSI_MCS_GROUPS]; PATHS],
    /// 6 GHz MCS TSSI offsets per path.
    tssi_6g_mcs: [[i8; TSSI_MCS_6G_GROUPS]; PATHS],
}

impl TssiProfile {
    /// Parse the per-path efuse fields into the profile.
    pub(super) fn parse(paths: [PathEfuse; PATHS]) -> Self {
        let mut profile = Self::default();
        for (p, path) in paths.iter().enumerate() {
            profile.thermal[p] = path.therm;
            for (g, v) in path.cck_tssi.iter().enumerate() {
                profile.tssi_cck[p][g] = *v as i8;
            }
            for (g, v) in path.bw40_tssi.iter().enumerate() {
                profile.tssi_mcs[p][g] = *v as i8;
            }
            for (g, v) in path.bw40_1s_tssi_5g.iter().enumerate() {
                profile.tssi_mcs[p][TSSI_MCS_2G_GROUPS + g] = *v as i8;
            }
            for (g, v) in path.bw40_1s_tssi_6g.iter().enumerate() {
                profile.tssi_6g_mcs[p][g] = *v as i8;
            }
        }
        profile
    }

    /// Thermal byte for `path`, or `None` out of range.
    pub(super) fn thermal(&self, path: usize) -> Option<u8> {
        self.thermal.get(path).copied()
    }

    /// CCK TSSI offset for `path` and channel group, or
    /// `None` out of range.
    pub(super) fn cck(&self, path: usize, group: usize) -> Option<i8> {
        self.tssi_cck.get(path)?.get(group).copied()
    }

    /// MCS TSSI offset for `path` and channel group
    /// (0..5 = 2.4 GHz, 5..19 = 5 GHz), or `None` out of
    /// range.
    pub(super) fn mcs(&self, path: usize, group: usize) -> Option<i8> {
        self.tssi_mcs.get(path)?.get(group).copied()
    }

    /// 6 GHz MCS TSSI offset for `path` and channel
    /// group, or `None` out of range.
    pub(super) fn mcs_6g(&self, path: usize, group: usize) -> Option<i8> {
        self.tssi_6g_mcs.get(path)?.get(group).copied()
    }
}

/// Parsed gain-offset profile, mirroring Linux
/// `rtw8922a_efuse_parsing_gain_offset` filling
/// `rtw89_phy_efuse_gain` (`core.h:7406..7412`).
/// Offsets are S(8, 0) values after the transform below.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct GainProfile {
    /// Transformed offsets per path, in enum order
    /// (`GAIN_*` indices).
    offset: [[i8; GAIN_OFFSETS]; PATHS],
    /// Linux `offset_valid`: false when every raw byte
    /// is 0xFF, or every raw byte is 0x00 — both mean
    /// the efuse fields were never programmed.
    offset_valid: bool,
}

impl GainProfile {
    /// Parse the raw per-path gain bytes (13 per path, in
    /// enum order: 2G CCK/OFDM, 5G low/mid/high, 6G
    /// L0/L1/M0/M1/H0/H1/UH0/UH1).
    ///
    /// Transform (Linux literal): a byte with the sign
    /// bit set converts from sign-bit + U(7, 2) to S(8, 2)
    /// via `(t ^ 0x7f) + 1` in wrapping u8 arithmetic —
    /// equivalently, the two's-complement negation of the
    /// 7-bit magnitude. Bytes without the sign bit pass
    /// through unchanged. Validity is judged on the RAW
    /// bytes, before the transform, as in Linux.
    pub(super) fn parse(raw: [[u8; GAIN_OFFSETS]; PATHS]) -> Self {
        let mut profile = Self::default();
        let mut all_ff = true;
        let mut all_00 = true;
        for (p, path) in raw.iter().enumerate() {
            for (g, t) in path.iter().enumerate() {
                if *t != 0xFF {
                    all_ff = false;
                }
                if *t != 0x00 {
                    all_00 = false;
                }
                profile.offset[p][g] = if t & 0x80 != 0 {
                    (t ^ 0x7F).wrapping_add(1) as i8
                } else {
                    *t as i8
                };
            }
        }
        profile.offset_valid = !all_ff && !all_00;
        profile
    }

    /// True when the efuse gain fields were programmed
    /// (not all-0xFF and not all-0x00).
    pub(super) fn offset_valid(&self) -> bool {
        self.offset_valid
    }

    /// Transformed offset for `path` and `GAIN_*` index,
    /// or `None` out of range.
    pub(super) fn offset(&self, path: usize, index: usize) -> Option<i8> {
        self.offset.get(path)?.get(index).copied()
    }
}
