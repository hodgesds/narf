// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A TSSI H2C body (torvalds/linux @ cbbddb6).
//!
//! `rtw89_fw_h2c_rf_tssi` (fw.c:9086) sends `struct rtw89_h2c_rf_tssi`
//! (fw.h:5111, 300 bytes): the channel/cut header, the efuse-to-DE
//! values (`rtw89_phy_rfk_tssi_fill_fwcmd_efuse_to_de`, phy.c:4779) and
//! the thermal table (`rtw89_phy_rfk_tssi_fill_fwcmd_tmeter_tbl`,
//! phy.c:4842), then `tssi_mode` and `rfe_type`.
//!
//! The efuse DE values come from the BE TSSI profile
//! (`txpower_8922a::TssiProfile`, the `rtw8922a_efuse_parsing_tssi`
//! parse). The trim DE comes from `tssi_trim`/`tssi_trim_6g` — but
//! RTL8922A has no phycap trim parse at this commit
//! (`rtw8922a_phycap_parsing`, rtw8922a.c:1035..1037, covers only
//! thermal/pa-bias/pad-bias trims; the C chip's equivalent,
//! `rtw8852c_phycap_parsing_tssi`, has no 8922A counterpart), so the
//! trim tables are zero by construction and the caller passes them
//! explicitly (zero) until an upstream trim source exists. The thermal
//! table reuses the container TXPWR_TRK element
//! (`c_tssi::Tracking`, fw.c `rtw89_build_txpwr_trk_tbl_from_elm`)
//! with the 8922A multiplier of 1 (phy.c:4931).
//!
//! The `curr_tssi_ofdm_de_diff_*` slots are never written by either
//! Linux fill helper at this commit, so this builder zeroes them and
//! says so rather than copying uninitialized skb bytes.

use super::super::{
    operating_channel_c::{Band, Profile, TSSI_EXTRA},
    txpower_8922a::TssiProfile,
};
use super::c_tssi::Tracking;

/// `enum rtw89_tssi_mode` (core.h:7023..7024).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum TssiMode {
    Normal,
    Scan,
}

impl TssiMode {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Scan => 1,
        }
    }
}

/// Inputs to the TSSI H2C body: the efuse DE profile, the (currently
/// zero) trim tables, the container TXPWR_TRK element, and the chip
/// facts the header carries.
pub(in super::super) struct Inputs<'a> {
    /// `rtw89_tssi_info` DE profile (`rtw8922a_efuse_parsing_tssi`).
    pub profile: &'a TssiProfile,
    /// `tssi_trim[path][group]` (`TSSI_TRIM_CH_GROUP_NUM` = 8).
    /// Zero for RTL8922A at this commit (no phycap trim parse).
    pub trim: [[i8; 8]; 2],
    /// `tssi_trim_6g[path][group]` (`TSSI_TRIM_CH_GROUP_NUM_6G` = 16).
    /// Zero for RTL8922A at this commit (no phycap trim parse).
    pub trim_6g: [[i8; 16]; 2],
    /// TXPWR_TRK thermal rows (firmware element id 18).
    pub tracking: &'a Tracking,
    /// `rtwdev->efuse.rfe_type`.
    pub rfe_type: u8,
    /// `hal->cv`.
    pub cv: u8,
}

/// Resolve one TSSI group index against its table: a plain group reads
/// its slot; an extra group (`TSSI_EXTRA`, phy.c
/// `PHY_TSSI_EXTRA_GROUP`) averages slots `idx` and `idx + 1`.
/// Out-of-range slots read 0; the group functions are total over the
/// admitted profiles, so this only guards a caller-side mismatch.
fn resolve(table: &[i8], group: u32) -> i8 {
    resolve_opt(|i| table.get(i).copied(), group)
}

/// [`resolve`] over a per-index getter (for the profile's `Option`
/// accessors, which do not expose their slices).
fn resolve_opt(get: impl Fn(usize) -> Option<i8>, group: u32) -> i8 {
    let idx = (group & !TSSI_EXTRA) as usize;
    if group & TSSI_EXTRA != 0 {
        let first = i16::from(get(idx).unwrap_or(0));
        let second = i16::from(get(idx + 1).unwrap_or(0));
        ((first + second) / 2) as i8
    } else {
        get(idx).unwrap_or(0)
    }
}

/// `phy_tssi_get_ofdm_trim_de` (phy.c:4707): the trim DE for `profile`
/// on `path`, from the trim tables via the (6G) trim group.
fn trim_de(profile: Profile, path: usize, inputs: &Inputs<'_>) -> i8 {
    let (_, _, group) = profile.tssi_groups();
    match profile.band() {
        Band::Ghz6 => resolve(&inputs.trim_6g[path], group),
        _ => resolve(&inputs.trim[path], group),
    }
}

/// `phy_tssi_get_ofdm_de` (phy.c:4637): the OFDM DE for `profile` on
/// `path`, from the MCS tables via the (6G) OFDM group.
fn ofdm_de(profile: Profile, path: usize, inputs: &Inputs<'_>) -> i8 {
    let (_, group, _) = profile.tssi_groups();
    match profile.band() {
        Band::Ghz6 => resolve_opt(|i| inputs.profile.mcs_6g(path, i), group),
        _ => resolve_opt(|i| inputs.profile.mcs(path, i), group),
    }
}

/// The thermal table (`ftable`) for one path
/// (`rtw89_phy_rfk_tssi_fill_fwcmd_tmeter_tbl`, phy.c:4933..4975):
/// the first 64 offsets walk the up row (clamped at its last entry),
/// the last 64 walk the negated down row from index 1 (clamped the
/// same way), then each 4-byte group is byte-reversed into the table.
/// The 8922A multiplier is 1, so no sign flip. A 0xFF thermal byte
/// leaves the table zeroed (the caller sets `pg_thermal` to 0x38).
fn ftable(up: &[i8; 30], down: &[i8; 30], out: &mut [u8; 128]) {
    let mut thm_ofst = [0i8; 128];
    let mut i = 0usize;
    for slot in thm_ofst.iter_mut().take(64) {
        *slot = if i < 30 {
            let value = up[i];
            i += 1;
            value
        } else {
            up[29]
        };
    }
    let mut i = 1usize;
    for slot in thm_ofst.iter_mut().skip(64).rev() {
        *slot = if i < 30 {
            let value = down[i].wrapping_neg();
            i += 1;
            value
        } else {
            down[29].wrapping_neg()
        };
    }
    for (word, chunk) in out.chunks_exact_mut(4).enumerate() {
        let base = word * 4;
        chunk[0] = thm_ofst[base + 3] as u8;
        chunk[1] = thm_ofst[base + 2] as u8;
        chunk[2] = thm_ofst[base + 1] as u8;
        chunk[3] = thm_ofst[base] as u8;
    }
}

/// Build the 300-byte `struct rtw89_h2c_rf_tssi` body for `profile`
/// in `mode` (`rtw89_fw_h2c_rf_tssi` + its two fill helpers).
/// `hwtx_en` is true for RTL8922A; the `curr_tssi_*_de` slots are 0
/// with the `_20m`/`_40m`/`_80m`/`_160m`/`_320m` slots carrying the
/// trim-adjusted DE, exactly as the 8922A branch of the efuse fill.
pub(in super::super) fn build(profile: Profile, mode: TssiMode, inputs: &Inputs<'_>) -> [u8; 300] {
    let mut out = [0u8; 300];
    out[0..2].copy_from_slice(&300u16.to_le_bytes());
    out[2] = 0;
    out[3] = profile.center();
    out[4] = profile.width() as u8;
    out[5] = profile.band() as u8;
    out[6] = 1;
    out[7] = inputs.cv;
    let cck_group = profile.tssi_cck_group();
    for path in 0..2usize {
        let trim = trim_de(profile, path, inputs);
        let cck = inputs
            .profile
            .cck(path, (cck_group & !TSSI_EXTRA) as usize)
            .unwrap_or(0);
        let ofdm = ofdm_de(profile, path, inputs);
        // Linux `u32_get_bits(de + trim_de, 0xff)`: the low byte of the
        // two's-complement sum.
        let cck_val = (i16::from(cck) + i16::from(trim)) as u8;
        let ofdm_val = (i16::from(ofdm) + i16::from(trim)) as u8;
        out[8 + path] = 0;
        out[10 + path] = cck_val;
        out[12 + path] = cck_val;
        out[14 + path] = cck as u8;
        out[16 + path] = 0;
        out[18 + path] = ofdm_val;
        out[20 + path] = ofdm_val;
        out[22 + path] = ofdm_val;
        out[24 + path] = ofdm_val;
        out[26 + path] = ofdm_val;
        out[28 + path] = ofdm as u8;
        // diff_20m/80m/160m/320m (30..38) stay 0: unwritten by Linux.
        out[38 + path] = trim as u8;
        let thermal = inputs.profile.thermal(path).unwrap_or(0xff);
        if thermal == 0xff {
            out[40 + path] = 0x38;
        } else {
            out[40 + path] = thermal;
            let (up, down) = inputs.tracking.rows(profile.subband(), path as u8);
            let mut table = [0u8; 128];
            ftable(up, down, &mut table);
            out[42 + path * 128..42 + (path + 1) * 128].copy_from_slice(&table);
        }
    }
    out[298] = mode.as_u8();
    out[299] = inputs.rfe_type;
    out
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_tssi_tests.rs"]
mod tests;
