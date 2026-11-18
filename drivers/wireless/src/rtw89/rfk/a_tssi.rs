// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A channel TSSI: rtw8852a_rfk.c `rtw8852a_tssi` for the
//! non-DBCC PHY_0 (`_kpath` = RF_AB), both paths, on one typed
//! [`Profile`].
//!
//! The thermal rows come only from the container's TXPWR_TRK element
//! (fw.c `rtw89_build_txpwr_trk_tbl_from_elm`), with A's actual2G/5G
//! required bitmap0xfff0. NARF carries no copy of the static
//! `rtw89_8852a_trk_cfg`, so a container without the element is
//! refused rather than calibrated from invented rows. `thermal` in
//! [`Calibration`] is the efuse thermal (`path_a/b_therm`); it feeds
//! the tmeter table only.
//!
//! `run` programs through `_tssi_set_efuse_to_de`; `finish_tail` composes
//! source `_tssi_high_power` and `_tssi_pre_tx` from exact retained power
//! queries. Only the latter issues a complete receipt. Native supplies
//! live retained EWMA separately from factory thermal. The tail retains
//! actual PMAC counters and optional TXAGC observations, never defaults
//! them to a fabricated measurement. Scan's partial path remains separate.
//!
//! DE groups are A-local: `Profile::tssi_groups()` is the C-flavored
//! shared helper, and its trim table carries EXTRA arms for 49-51 and
//! 113-115 that Linux A `_tssi_get_trim_group` does not have (A
//! returns group 0 there). The A tables below are transcribed from
//! rtw8852a_rfk.c `_tssi_get_cck_group` / `_tssi_get_ofdm_group` /
//! `_tssi_get_trim_group`; the channel argument is `channel.center()`
//! (Linux `chan->channel` is the center channel, chan.c:138).
use super::super::{
    factory_a::Calibration,
    operating_channel_c::{Band, Profile, TSSI_EXTRA},
};
#[path = "a_tracking.rs"]
mod tracking;
pub(in crate::rtw89) use tracking::Tracking;
#[path = "a_tssi_tail.rs"]
pub(in crate::rtw89) mod tail;
use super::{Access, Error, Interface, Kind};
#[path = "a_tssi_tables.rs"]
mod tables;
use tables::*;

const B_DPD_OFT_ADDR: u32 = 0xf8000000; // Linux reg.h: GENMASK(31, 27)
const B_DPD_OFT_EN: u32 = 0x10000000; // Linux reg.h: BIT(28)
const B_P0_RFCTM_VAL: u32 = 0x3f00000; // Linux reg.h: GENMASK(25, 20)
const B_P0_TMETER: u32 = 0xfc00; // Linux reg.h: GENMASK(15, 10)
const B_P0_TMETER_DIS: u32 = 0x10000; // Linux reg.h: BIT(16)
const B_P0_TMETER_TRK: u32 = 0x1000000; // Linux reg.h: BIT(24)
const B_P1_RFCTM_VAL: u32 = 0x3f00000; // Linux reg.h: GENMASK(25, 20)
const B_P1_TMETER: u32 = 0xfc00; // Linux reg.h: GENMASK(15, 10)
const B_P1_TMETER_DIS: u32 = 0x10000; // Linux reg.h: BIT(16)
const B_P1_TMETER_TRK: u32 = 0x1000000; // Linux reg.h: BIT(24)
const B_TSSI_THER: u32 = 0x3f000000; // Linux reg.h: GENMASK(29, 24)
const B_TXGAIN_SCALE_EN: u32 = 0x80000; // Linux reg.h: BIT(19)
const B_TXGAIN_SCALE_OFT: u32 = 0xff000000; // Linux reg.h: GENMASK(31, 24)
const RR_TXPOW: u32 = 0x7f; // Linux reg.h: 0x7f
const RR_TXPOW_TXA: u32 = 0x100; // Linux reg.h: BIT(8)
const RR_TXPOW_TXG: u32 = 0x2; // Linux reg.h: BIT(1)
const R_DPD_OFT_ADDR: u32 = 0x5804; // Linux reg.h: 0x5804
const R_DPD_OFT_EN: u32 = 0x5800; // Linux reg.h: 0x5800
const R_P0_RFCTM: u32 = 0x5864; // Linux reg.h: 0x5864
const R_P0_RFCTM_RDY: u32 = 0x4000000; // Linux reg.h: BIT(26)
const R_P0_TMETER: u32 = 0x5810; // Linux reg.h: 0x5810
const R_P0_TSSI_BASE: u32 = 0x5c00; // Linux reg.h: 0x5C00
const R_P1_RFCTM: u32 = 0x7864; // Linux reg.h: 0x7864
const R_P1_RFCTM_RDY: u32 = 0x4000000; // Linux reg.h: BIT(26)
const R_P1_TMETER: u32 = 0x7810; // Linux reg.h: 0x7810
const R_TSSI_THER: u32 = 0x1c10; // Linux reg.h: 0x1C10
const R_TSSI_THOF: u32 = 0x7c00; // Linux reg.h: 0x7C00
const R_TXGAIN_SCALE: u32 = 0x58f0; // Linux reg.h: 0x58F0

/// `__DE_MASK` in `_tssi_set_efuse_to_de`.
const DE_MASK: u32 = 0x003ff000;
/// `_tssi_de_cck_long/short`.
const DE_CCK: [[u32; 2]; 2] = [[0x5858, 0x5860], [0x7858, 0x7860]];
/// `_tssi_de_mcs_{20m,40m,80m,80m_80m,5m,10m}`.
const DE_MCS: [[u32; 6]; 2] = [
    [0x5838, 0x5840, 0x5848, 0x5850, 0x5828, 0x5830],
    [0x7838, 0x7840, 0x7848, 0x7850, 0x7828, 0x7830],
];
/// Per path: (TMETER, RFCTM, thermal-offset base).
const PATH_REGS: [(u32, u32, u32); 2] = [
    (R_P0_TMETER, R_P0_RFCTM, R_P0_TSSI_BASE),
    (R_P1_TMETER, R_P1_RFCTM, R_TSSI_THOF),
];
/// Per-path TMETER / RFCTM field masks (P0 and P1 values are identical
/// in reg.h; the per-path names are kept for readability).
const TMETER_MASK: [u32; 2] = [B_P0_TMETER, B_P1_TMETER];
const TMETER_DIS: [u32; 2] = [B_P0_TMETER_DIS, B_P1_TMETER_DIS];
const TMETER_TRK: [u32; 2] = [B_P0_TMETER_TRK, B_P1_TMETER_TRK];
const RFCTM_VAL: [u32; 2] = [B_P0_RFCTM_VAL, B_P1_RFCTM_VAL];
const RFCTM_RDY: [u32; 2] = [R_P0_RFCTM_RDY, R_P1_RFCTM_RDY];
/// `_tssi_track` TX gain scale table (only entries 0..7 are indexed:
/// `gain_offset & 7`).
const TX_GAIN_SCALE: [u32; 16] = [
    0x400, 0x40e, 0x41d, 0x427, 0x43c, 0x44c, 0x45c, 0x46c, 0x400, 0x39d, 0x3ab, 0x3b8, 0x3c6,
    0x3d4, 0x3e2, 0x3f1,
];

/// `_tssi_set_tmeter_tbl` offset words (same construction as the C
/// port's `thermal_words`: down rows negated for j < 32, up rows from
/// index 1 upward for j >= 32, packed little-endian).
fn thermal_words(up: &[i8; 30], down: &[i8; 30]) -> [u32; 16] {
    let mut offsets = [0i8; 64];
    for (j, slot) in offsets.iter_mut().take(32).enumerate() {
        *slot = down[j.min(29)].wrapping_neg();
    }
    for (i, j) in (32..64).rev().enumerate() {
        offsets[j] = up[(i + 1).min(29)];
    }
    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(offsets.chunks_exact(4)) {
        *word = u32::from_le_bytes([
            chunk[0] as u8,
            chunk[1] as u8,
            chunk[2] as u8,
            chunk[3] as u8,
        ]);
    }
    words
}

/// `TSSI_EXTRA_GET_GROUP_IDX1/2` averaging (`(a + b) / 2` in C `int`).
fn group_de(values: &[i8], group: u32) -> Result<i32, Error> {
    let at = |index: u32| {
        values
            .get(index as usize)
            .map(|&v| i32::from(v))
            .ok_or(Error::Table)
    };
    if group & TSSI_EXTRA != 0 {
        let first = group & !TSSI_EXTRA;
        Ok((at(first)? + at(first + 1)?) / 2)
    } else {
        at(group)
    }
}

/// Linux A `_tssi_get_cck_group`.
const fn a_cck_group(ch: u8) -> u32 {
    match ch {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        12..=13 => 4,
        14 => 5,
        _ => 0,
    }
}

/// Linux A `_tssi_get_ofdm_group`: 2G groups 0..4, 5G 20MHz groups
/// 5..18 with 3-channel extra groups between them (36..40 -> 5,
/// 41..43 -> extra 5, ...). No extra group after a run ending a UNII
/// segment (64, 144, 177).
const fn a_ofdm_group(ch: u8) -> u32 {
    const RUNS: [(u8, u8, u32); 14] = [
        (36, 40, 5),
        (44, 48, 6),
        (52, 56, 7),
        (60, 64, 8),
        (100, 104, 9),
        (108, 112, 10),
        (116, 120, 11),
        (124, 128, 12),
        (132, 136, 13),
        (140, 144, 14),
        (149, 153, 15),
        (157, 161, 16),
        (165, 169, 17),
        (173, 177, 18),
    ];
    match ch {
        1..=2 => return 0,
        3..=5 => return 1,
        6..=8 => return 2,
        9..=11 => return 3,
        12..=14 => return 4,
        _ => {}
    }
    let mut i = 0;
    while i < RUNS.len() {
        let (lo, hi, g) = RUNS[i];
        if ch >= lo && ch <= hi {
            return g;
        }
        if ch > hi && ch <= hi + 3 && !matches!(hi, 64 | 144 | 177) {
            return TSSI_EXTRA | g;
        }
        i += 1;
    }
    0
}

/// Linux A `_tssi_get_trim_group`: no EXTRA arms (unlike the shared
/// C-flavored helper, which averages for 49..=51 and 113..=115; A
/// returns group 0 there).
const fn a_trim_group(ch: u8) -> u32 {
    match ch {
        1..=8 => 0,
        9..=14 => 1,
        36..=48 => 2,
        52..=64 => 3,
        100..=112 => 4,
        116..=128 => 5,
        132..=144 => 6,
        149..=177 => 7,
        _ => 0,
    }
}

/// Results retained by one partial A TSSI program, before high-power/pre-TX.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// Thermal-offset words written at 0x5c00/0x7c00.
    pub thermal: [[u32; 16]; 2],
    /// (CCK, MCS) DE values per path (10-bit two's complement fields).
    pub de: [[i32; 2]; 2],
    /// `rtwdev->is_tssi_mode[path]` after `_tssi_enable`.
    pub tssi_mode: [bool; 2],
    /// `base_thermal[path]` after `_tssi_enable` (live thermal at
    /// enable time; supplied by the caller, separate from factory thermal).
    pub base_thermal: [u8; 2],
    /// `extra_ofst[path]` from `_tssi_track`.
    pub extra_ofst: [i8; 2],
    /// `tssi_tracking_check[path]`, set only by `_tssi_high_power`
    /// (TX-power follow-on); false until then, so `track` is a no-op.
    pub tracking_check: [bool; 2],
}

/// One A channel TSSI owner.
#[derive(Default)]
pub(in super::super) struct Tssi {
    results: Results,
    programmed: bool,
    complete: Option<tail::Report>,
    profile: Option<Profile>,
    default_txagc: [Option<u8>; 2],
}

impl<I: Interface> Access<'_, I> {
    /// One path of the `rtw8852a_tssi` loop (`full`) or of the
    /// `rtw8852a_tssi_scan` loop (rf_setting, set_sys, tmeter, pak
    /// only). `thermal` is the efuse thermal for the tmeter table.
    async fn a_tssi_path(
        &mut self,
        path: u8,
        channel: Profile,
        thermal: u8,
        tracking: &Tracking,
        full: bool,
    ) -> Result<[u32; 16], Error> {
        let a = path == 0;
        let two = channel.band() == Band::Ghz2;
        let (tmeter, rfctm, base) = PATH_REGS[usize::from(path)];
        let p = usize::from(path);
        // `_tssi_rf_setting`.
        match channel.band() {
            Band::Ghz2 => self.wr(path, RR_TXPOW, RR_TXPOW_TXG, 0x1).await?,
            Band::Ghz5 => self.wr(path, RR_TXPOW, RR_TXPOW_TXA, 0x1).await?,
            Band::Ghz6 => return Err(Error::Policy),
        }
        // `_tssi_set_sys`.
        self.table(TSSI_SYS_DEFS).await?;
        self.table(if two {
            TSSI_SYS_DEFS_2G
        } else {
            TSSI_SYS_DEFS_5G
        })
        .await?;
        if full {
            // `_tssi_ini_txpwr_ctrl_bb` / `_he_tb` / `_tssi_set_dck`.
            self.table(if a {
                TSSI_TXPWR_CTRL_BB_DEFS_A
            } else {
                TSSI_TXPWR_CTRL_BB_DEFS_B
            })
            .await?;
            self.table(if two {
                TSSI_TXPWR_CTRL_BB_DEFS_2G
            } else {
                TSSI_TXPWR_CTRL_BB_DEFS_5G
            })
            .await?;
            self.table(if a {
                TSSI_TXPWR_CTRL_BB_HE_TB_DEFS_A
            } else {
                TSSI_TXPWR_CTRL_BB_HE_TB_DEFS_B
            })
            .await?;
            self.table(if a { TSSI_DCK_DEFS_A } else { TSSI_DCK_DEFS_B })
                .await?;
        }
        // `_tssi_set_tmeter_tbl`.
        self.wm(tmeter, TMETER_DIS[p], 0)?;
        self.wm(tmeter, TMETER_TRK[p], 1)?;
        let words = if thermal == 0xff {
            self.wm(tmeter, TMETER_MASK[p], 32)?;
            self.wm(rfctm, RFCTM_VAL[p], 32)?;
            [0; 16]
        } else {
            self.wm(tmeter, TMETER_MASK[p], u32::from(thermal))?;
            self.wm(rfctm, RFCTM_VAL[p], u32::from(thermal))?;
            let (up, down) = tracking.rows(channel.subband(), path);
            thermal_words(up, down)
        };
        for (i, &word) in words.iter().enumerate() {
            self.0.admit()?;
            self.0.write32(0x10000 + base + 4 * i as u32, word)?;
        }
        self.wm(rfctm, RFCTM_RDY[p], 1)?;
        self.wm(rfctm, RFCTM_RDY[p], 0)?;
        if full {
            // `_tssi_set_dac_gain_tbl` / `_tssi_slope_cal_org` /
            // `_tssi_set_rf_gap_tbl` / `_tssi_set_slope`.
            self.table(if a {
                TSSI_DAC_GAIN_TBL_DEFS_A
            } else {
                TSSI_DAC_GAIN_TBL_DEFS_B
            })
            .await?;
            self.table(if a {
                TSSI_SLOPE_CAL_ORG_DEFS_A
            } else {
                TSSI_SLOPE_CAL_ORG_DEFS_B
            })
            .await?;
            self.table(if a {
                TSSI_RF_GAP_TBL_DEFS_A
            } else {
                TSSI_RF_GAP_TBL_DEFS_B
            })
            .await?;
            self.table(if a {
                TSSI_SLOPE_DEFS_A
            } else {
                TSSI_SLOPE_DEFS_B
            })
            .await?;
        }
        // `_tssi_pak` (Linux `default:` arm is the 2G table).
        match channel.subband() {
            0 => {
                self.table(if a {
                    TSSI_PAK_DEFS_A_2G
                } else {
                    TSSI_PAK_DEFS_B_2G
                })
                .await?
            }
            1 => {
                self.table(if a {
                    TSSI_PAK_DEFS_A_5G_1
                } else {
                    TSSI_PAK_DEFS_B_5G_1
                })
                .await?
            }
            3 => {
                self.table(if a {
                    TSSI_PAK_DEFS_A_5G_3
                } else {
                    TSSI_PAK_DEFS_B_5G_3
                })
                .await?
            }
            4 => {
                self.table(if a {
                    TSSI_PAK_DEFS_A_5G_4
                } else {
                    TSSI_PAK_DEFS_B_5G_4
                })
                .await?
            }
            _ => {
                self.table(if a {
                    TSSI_PAK_DEFS_A_2G
                } else {
                    TSSI_PAK_DEFS_B_2G
                })
                .await?
            }
        }
        Ok(words)
    }

    /// `_tssi_set_efuse_to_de` for one path; returns (CCK, MCS) DE.
    fn a_tssi_de(
        &mut self,
        path: u8,
        channel: Profile,
        cal: &Calibration,
    ) -> Result<[i32; 2], Error> {
        let p = usize::from(path);
        let ch = channel.center();
        let trim = group_de(&cal.tssi_trim[p], a_trim_group(ch))?;
        let cck = i32::from(cal.tssi_cck[p][a_cck_group(ch) as usize]) + trim;
        for &address in &DE_CCK[p] {
            self.wm(address, DE_MASK, cck as u32)?;
        }
        let ofdm = group_de(&cal.tssi_mcs[p], a_ofdm_group(ch))?;
        // `s8 ofdm_de + s8 trim_de` in `s32`.
        let mcs = ofdm + trim;
        for &address in &DE_MCS[p] {
            self.wm(address, DE_MASK, mcs as u32)?;
        }
        Ok([cck, mcs])
    }
}

impl Tssi {
    pub fn results(&self) -> Option<&Results> {
        self.programmed.then_some(&self.results)
    }
    pub fn complete(&self) -> Option<tail::Report> {
        self.programmed.then_some(self.complete).flatten()
    }

    /// rtw8852a_rfk.c `rtw8852a_tssi(PHY_0)`: `_tssi_disable`, the
    /// per-path rf_setting/set_sys/txpwr-ctrl-bb/he-tb/dck/tmeter/
    /// dac-gain/slope-cal-org/rf-gap/slope/pak programs,
    /// `_tssi_enable` (track, TXAGC offset moving average, enable;
    /// `is_tssi_mode` set) and `_tssi_set_efuse_to_de`. Ends there:
    /// `_tssi_high_power` and `_tssi_pre_tx` are follow-ons (see the
    /// module doc). 8852A is Wi-Fi 6: a 6GHz channel is refused with
    /// `Error::Policy`. Linux has no coexistence notification here;
    /// the I/O-free `Kind::Tssi` bracket only keeps RFK exclusivity.
    ///
    /// # Safety
    /// Actual RTL8852A PHY0 (non-DBCC) after the BB/RF retune to THIS
    /// `channel`, its RX DCK and IQK; `calibration` is this device's
    /// A factory snapshot, `tracking` this container's TXPWR_TRK, and
    /// `thermal` the current averaged thermal per path (for
    /// `base_thermal`). Interface enforces current admission at every
    /// access; no concurrent PHY/packet/reset/PM owner.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        thermal: [u8; 2],
    ) -> Result<(), Error> {
        // SAFETY: forwarded caller contract.
        unsafe { self.program(io, channel, calibration, tracking, thermal, true) }.await
    }

    /// rtw8852a_rfk.c `rtw8852a_tssi_scan(PHY_0)`, run by core.c
    /// `__rtw89_set_channel` -> `rtw8852a_rfk_band_changed` after the
    /// channel help exit when the band changed: returns without I/O
    /// unless both paths are in TSSI mode, else `_tssi_disable`, per
    /// path rf_setting/set_sys/tmeter/pak, then `_tssi_enable` and
    /// `_tssi_set_efuse_to_de` for the new channel. Returns whether
    /// it ran.
    ///
    /// # Safety
    /// Same as [`Self::run`], on the channel just programmed by the
    /// channel owner. `tssi_mode` is the retained TSSI enable state.
    pub async unsafe fn scan(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        thermal: [u8; 2],
        tssi_mode: [bool; 2],
    ) -> Result<bool, Error> {
        if !tssi_mode[0] || !tssi_mode[1] {
            return Ok(false);
        }
        // SAFETY: forwarded caller contract.
        unsafe { self.program(io, channel, calibration, tracking, thermal, false) }.await?;
        Ok(true)
    }

    async unsafe fn program(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        thermal: [u8; 2],
        full: bool,
    ) -> Result<(), Error> {
        if channel.band() == Band::Ghz6 {
            return Err(Error::Policy);
        }
        self.programmed = false;
        self.complete = None;
        self.profile = Some(channel);
        let extra_ofst = self.results.extra_ofst;
        let tracking_check = self.results.tracking_check;
        self.results = Results::default();
        self.results.extra_ofst = extra_ofst;
        self.results.tracking_check = tracking_check;
        io.admit()?;
        io.begin(Kind::Tssi).await?;
        let mut access = Access(io);
        // `_tssi_disable`.
        access.table(TSSI_DISABLE_DEFS).await?;
        for path in 0..2u8 {
            self.results.thermal[usize::from(path)] = access
                .a_tssi_path(
                    path,
                    channel,
                    calibration.thermal[usize::from(path)],
                    tracking,
                    full,
                )
                .await?;
        }
        // `_tssi_enable`: per path track + TXAGC offset moving average
        // + enable tables; `base_thermal` from the live thermal.
        for path in 0..2u8 {
            let a = path == 0;
            access
                .table(if a {
                    TSSI_TRACK_DEFS_A
                } else {
                    TSSI_TRACK_DEFS_B
                })
                .await?;
            access
                .table(if a {
                    TSSI_TXAGC_OFST_MV_AVG_DEFS_A
                } else {
                    TSSI_TXAGC_OFST_MV_AVG_DEFS_B
                })
                .await?;
            access
                .table(if a {
                    TSSI_ENABLE_DEFS_A
                } else {
                    TSSI_ENABLE_DEFS_B
                })
                .await?;
            self.results.base_thermal[usize::from(path)] = thermal[usize::from(path)];
            self.results.tssi_mode[usize::from(path)] = true;
        }
        for path in 0..2u8 {
            self.results.de[usize::from(path)] = access.a_tssi_de(path, channel, calibration)?;
        }
        access.0.admit()?;
        access.0.end(Kind::Tssi).await?;
        self.programmed = true;
        Ok(())
    }

    /// rtw8852a_rfk.c `_tssi_track`: scale the TX gain by the thermal
    /// delta against `base_thermal`. No-op unless both paths are in
    /// TSSI mode with `tracking_check` set (the latter only happens in
    /// `_tssi_high_power`, a follow-on). No BTC bracket: Linux calls
    /// this from `rtw8852a_rfk_track` without one.
    ///
    /// # Safety
    /// Same retained owner after [`Self::run`]; no concurrent
    /// RFK/PHY/reset/PM owner. The current thermal is read back from
    /// `R_TSSI_THER` per path.
    pub async unsafe fn track(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if !self.results.tssi_mode[0] || !self.results.tssi_mode[1] {
            return Ok(());
        }
        let mut access = Access(io);
        for path in 0..2u8 {
            let p = usize::from(path);
            if !self.results.tracking_check[p] {
                continue;
            }
            let cur_ther = access.bb(R_TSSI_THER + (u32::from(path) << 13), B_TSSI_THER)? as u8;
            if cur_ther == 0 || self.results.base_thermal[p] == 0 {
                continue;
            }
            let delta_ther = i32::from(cur_ther) - i32::from(self.results.base_thermal[p]);
            let gain_offset = ((delta_ther as i8) as i32 * 15 / 10) as i8;
            self.results.extra_ofst[p] = gain_offset;
            let gain_offset_int = (i32::from(gain_offset) >> 3).clamp(-16, 15);
            let gain_offset_float = (i32::from(gain_offset) & 7) as usize;
            access.wm(R_DPD_OFT_EN + (u32::from(path) << 13), B_DPD_OFT_EN, 0x1)?;
            access.wm(
                R_TXGAIN_SCALE + (u32::from(path) << 13),
                B_TXGAIN_SCALE_EN,
                0x1,
            )?;
            access.wm(
                R_DPD_OFT_ADDR + (u32::from(path) << 13),
                B_DPD_OFT_ADDR,
                gain_offset_int as u32,
            )?;
            access.wm(
                R_TXGAIN_SCALE + (u32::from(path) << 13),
                B_TXGAIN_SCALE_OFT,
                TX_GAIN_SCALE[gain_offset_float],
            )?;
        }
        Ok(())
    }
}
