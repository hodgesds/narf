// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C channel TSSI: rtw8852c_rfk.c `rtw8852c_tssi(PHY_0)` for the
//! non-DBCC RF_AB pair on one typed [`Profile`]. RTL8852C has no PMAC
//! alignment measurement: `_tssi_set_aligk_default` loads the fixed
//! per-band defaults, so the whole flow is table programs, the firmware
//! TXPWR_TRK thermal-offset rows and the factory DE values.
//!
//! The thermal rows come only from the container's TXPWR_TRK element
//! (fw.c `rtw89_build_txpwr_trk_tbl_from_elm`, all 2/5/6 GHz types
//! required for RTL8852C). NARF carries no copy of the static
//! `rtw89_8852c_trk_cfg`, so a container without the element is refused
//! rather than calibrated from invented rows.
use super::super::{
    factory_c::Calibration,
    operating_channel_c::{Band, Profile, Width, TSSI_EXTRA},
    radio_assets::Assets,
};
use super::{Access, Entry, Error, Interface, Kind};
#[path = "c_tssi_tables.rs"]
mod tables;
use tables::*;

/// core.h `DELTA_SWINGIDX_SIZE`.
const SWING: usize = 30;
/// `_TSSI_DE_MASK`.
const DE_MASK: u32 = 0x003f_f000;
/// `_tssi_de_cck_long/short`, `_tssi_de_mcs_{20m,40m,80m,80m_80m,5m,10m}`.
const DE_CCK: [[u32; 2]; 2] = [[0x5858, 0x5860], [0x7858, 0x7860]];
const DE_MCS: [[u32; 6]; 2] = [
    [0x5838, 0x5840, 0x5848, 0x5850, 0x5828, 0x5830],
    [0x7838, 0x7840, 0x7848, 0x7850, 0x7828, 0x7830],
];
/// Per path: (R_Px_TMETER, R_Px_RFCTM, thermal-offset base,
/// R_Px_TSSI_ADC_CLK).
const PATH_REGS: [(u32, u32, u32, u32); 2] = [
    (0x5810, 0x5864, 0x5c00, 0x566c),
    (0x7810, 0x7864, 0x7c00, 0x766c),
];
const B_TMETER_DIS: u32 = 1 << 16;
const B_TMETER_TRK: u32 = 1 << 24;
const B_TMETER: u32 = 0xfc00;
const B_RFCTM_VAL: u32 = 0x03f0_0000;
const RFCTM_RDY: u32 = 1 << 26;
const B_TSSI_ADC_CLK: u32 = 0x3_0000;

/// The RTL8852C TXPWR_TRK rows: `delta[type][subband]` for the sixteen
/// `enum rtw89_fw_txpwr_trk_type` types (6G: 4 subbands, 5G: 3, 2G: 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct Tracking {
    delta: [[[i8; SWING]; 4]; 16],
}

impl Tracking {
    /// The first TXPWR_TRK element (id 18) of the container.
    pub(in super::super) fn from_assets(assets: &Assets) -> Result<Self, Error> {
        let element = assets
            .elements()
            .iter()
            .find(|element| element.id == 18)
            .ok_or(Error::Table)?;
        Self::parse(&element.bytes)
    }
    /// fw.c `rtw89_build_txpwr_trk_tbl_from_elm` for `support_bands`
    /// 2/5/6 GHz: every type 0..15 is needed; types are consumed in bit
    /// order (6G 4, 5G 3, 2G 1 subband rows of 30), bits above 15 end the
    /// walk, and the rows must fit the element.
    pub(in super::super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let head: [u8; 4] = bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Table)?;
        let bitmap = u32::from_le_bytes(head);
        if bitmap & 0xffff != 0xffff {
            return Err(Error::Table);
        }
        let contents = bytes.get(8..).ok_or(Error::Table)?;
        let mut delta = [[[0i8; SWING]; 4]; 16];
        let mut offset = 0usize;
        for (kind, rows) in delta.iter_mut().enumerate() {
            let subbands = match kind {
                0..=3 => 4,
                4..=7 => 3,
                _ => 1,
            };
            for row in rows.iter_mut().take(subbands) {
                let data = contents
                    .get(offset * SWING..(offset + 1) * SWING)
                    .ok_or(Error::Table)?;
                for (out, &input) in row.iter_mut().zip(data) {
                    *out = input as i8;
                }
                offset += 1;
            }
        }
        Ok(Self { delta })
    }
    /// `_tssi_set_tmeter_tbl` row selection by `chan->subband_type`:
    /// (up, down) for `path`. Shared with the BE TSSI H2C fill, which
    /// is the same Linux function (`rtw89_phy_rfk_tssi_fill_fwcmd_\
    /// tmeter_tbl`) with the 8922A multiplier.
    pub(in super::super) fn rows(&self, subband: u8, path: u8) -> (&[i8; SWING], &[i8; SWING]) {
        // (up type, down type) for path A / path B.
        let (types, index) = match subband {
            1 => ([(7, 6), (5, 4)], 0),
            3 => ([(7, 6), (5, 4)], 1),
            4 => ([(7, 6), (5, 4)], 2),
            5 | 6 => ([(3, 2), (1, 0)], 0),
            7 | 8 => ([(3, 2), (1, 0)], 1),
            9 | 10 => ([(3, 2), (1, 0)], 2),
            11 | 12 => ([(3, 2), (1, 0)], 3),
            // `default:` / RTW89_CH_2G.
            _ => ([(11, 10), (9, 8)], 0),
        };
        let (up, down) = types[usize::from(path)];
        (&self.delta[up][index], &self.delta[down][index])
    }
}

/// `_tssi_set_tmeter_tbl` offset words (`RTW8852C_TSSI_GET_VAL`).
fn thermal_words(up: &[i8; SWING], down: &[i8; SWING]) -> [u32; 16] {
    let mut offsets = [0i8; 64];
    for (j, slot) in offsets.iter_mut().take(32).enumerate() {
        *slot = down[j.min(SWING - 1)].wrapping_neg();
    }
    for (i, j) in (32..64).rev().enumerate() {
        offsets[j] = up[(i + 1).min(SWING - 1)];
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

/// Results retained by one C TSSI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// Thermal-offset words written at 0x5c00/0x7c00.
    pub thermal: [[u32; 16]; 2],
    /// (CCK, MCS) DE values per path (10-bit two's complement fields).
    pub de: [[i32; 2]; 2],
    /// `rtwdev->is_tssi_mode[path]` after `_tssi_enable`.
    pub tssi_mode: [bool; 2],
}

/// One C channel TSSI owner.
#[derive(Default)]
pub(in super::super) struct Tssi {
    results: Results,
    calibrated: bool,
}

impl<I: Interface> Access<'_, I> {
    /// One path of the `rtw8852c_tssi` loop (`full`) or of the
    /// `rtw8852c_tssi_scan` loop (sys, DCK, tmeter, slope-cal-org and
    /// alignment default only).
    async fn c_tssi_path(
        &mut self,
        path: u8,
        channel: Profile,
        thermal: u8,
        tracking: &Tracking,
        full: bool,
    ) -> Result<[u32; 16], Error> {
        let a = path == 0;
        let two = channel.band() == Band::Ghz2;
        let pick = |cond: bool, x: &'static [Entry], y: &'static [Entry]| if cond { x } else { y };
        let (tmeter, rfctm, base, adc) = PATH_REGS[usize::from(path)];
        // `_tssi_set_sys`.
        self.table(&TSSI_SYS_DEFS).await?;
        let clk = match channel.width() {
            Width::Mhz80 => 1,
            Width::Mhz160 => 2,
            // Linux `_tssi_set_sys` switches on 80 / 80+80 / 160 only;
            // its `default:` arm leaves the ADC clock at 0, so 320MHz
            // takes 0 like 20/40MHz.
            Width::Mhz20 | Width::Mhz40 | Width::Mhz320 => 0,
        };
        self.wm(adc, B_TSSI_ADC_CLK, clk)?;
        self.table(match (a, two) {
            (true, true) => &TSSI_SYS_DEFS_2G_A[..],
            (true, false) => &TSSI_SYS_DEFS_5G_A[..],
            (false, true) => &TSSI_SYS_DEFS_2G_B[..],
            (false, false) => &TSSI_SYS_DEFS_5G_B[..],
        })
        .await?;
        // `_tssi_ini_txpwr_ctrl_bb` / `_he_tb`.
        if full {
            self.table(pick(
                a,
                &TSSI_TXPWR_CTRL_BB_DEFS_A,
                &TSSI_TXPWR_CTRL_BB_DEFS_B,
            ))
            .await?;
            self.table(pick(
                a,
                &TSSI_TXPWR_CTRL_BB_HE_TB_DEFS_A,
                &TSSI_TXPWR_CTRL_BB_HE_TB_DEFS_B,
            ))
            .await?;
        }
        // `_tssi_set_dck`.
        self.table(pick(a, &TSSI_DCK_DEFS_A, &TSSI_DCK_DEFS_B))
            .await?;
        self.table(match (a, two) {
            (true, true) => &TSSI_DCK_DEFS_2G_A[..],
            (true, false) => &TSSI_DCK_DEFS_5G_A[..],
            (false, true) => &TSSI_DCK_DEFS_2G_B[..],
            (false, false) => &TSSI_DCK_DEFS_5G_B[..],
        })
        .await?;
        // `_tssi_set_bbgain_split`.
        if full {
            self.table(pick(a, &TSSI_SET_BBGAIN_SPLIT_A, &TSSI_SET_BBGAIN_SPLIT_B))
                .await?;
        }
        // `_tssi_set_tmeter_tbl`.
        self.wm(tmeter, B_TMETER_DIS, 0)?;
        self.wm(tmeter, B_TMETER_TRK, 1)?;
        let words = if thermal == 0xff {
            self.wm(tmeter, B_TMETER, 32)?;
            self.wm(rfctm, B_RFCTM_VAL, 32)?;
            [0; 16]
        } else {
            self.wm(tmeter, B_TMETER, u32::from(thermal))?;
            self.wm(rfctm, B_RFCTM_VAL, u32::from(thermal))?;
            let (up, down) = tracking.rows(channel.subband(), path);
            thermal_words(up, down)
        };
        for (i, &word) in words.iter().enumerate() {
            self.0.admit()?;
            self.0.write32(0x10000 + base + 4 * i as u32, word)?;
        }
        self.wm(rfctm, RFCTM_RDY, 1)?;
        self.wm(rfctm, RFCTM_RDY, 0)?;
        // `_tssi_slope_cal_org`.
        self.table(match (a, two) {
            (true, true) => &TSSI_SLOPE_CAL_ORG_DEFS_2G_A[..],
            (true, false) => &TSSI_SLOPE_CAL_ORG_DEFS_5G_A[..],
            (false, true) => &TSSI_SLOPE_CAL_ORG_DEFS_2G_B[..],
            (false, false) => &TSSI_SLOPE_CAL_ORG_DEFS_5G_B[..],
        })
        .await?;
        // `_tssi_set_aligk_default`.
        self.table(match (a, channel.band()) {
            (true, Band::Ghz2) => &TSSI_SET_ALIGK_DEFAULT_DEFS_2G_A[..],
            (true, Band::Ghz6) => &TSSI_SET_ALIGK_DEFAULT_DEFS_6G_A[..],
            (true, Band::Ghz5) => &TSSI_SET_ALIGK_DEFAULT_DEFS_5G_A[..],
            (false, Band::Ghz2) => &TSSI_SET_ALIGK_DEFAULT_DEFS_2G_B[..],
            (false, Band::Ghz6) => &TSSI_SET_ALIGK_DEFAULT_DEFS_6G_B[..],
            (false, Band::Ghz5) => &TSSI_SET_ALIGK_DEFAULT_DEFS_5G_B[..],
        })
        .await?;
        // `_tssi_set_slope` / `_tssi_run_slope`.
        if full {
            self.table(pick(a, &TSSI_SLOPE_DEFS_A, &TSSI_SLOPE_DEFS_B))
                .await?;
            self.table(pick(a, &TSSI_RUN_SLOPE_DEFS_A, &TSSI_RUN_SLOPE_DEFS_B))
                .await?;
        }
        Ok(words)
    }
    /// `_tssi_set_efuse_to_de` for one path; returns (CCK, MCS) DE.
    pub(super) fn c_tssi_de(
        &mut self,
        path: u8,
        channel: Profile,
        cal: &Calibration,
    ) -> Result<[i32; 2], Error> {
        let p = usize::from(path);
        let (_, ofdm_group, trim_group) = channel.tssi_groups();
        let six = channel.band() == Band::Ghz6;
        let trim = if six {
            group_de(&cal.tssi_trim_6g[p], trim_group)?
        } else {
            group_de(&cal.tssi_trim[p], trim_group)?
        };
        // `_tssi_get_cck_group(chan->channel)` regardless of band.
        let cck_group = channel.tssi_cck_group();
        let cck = i32::from(cal.tssi_cck[p][cck_group as usize]) + trim;
        for &address in &DE_CCK[p] {
            self.wm(address, DE_MASK, cck as u32)?;
        }
        let ofdm = if six {
            group_de(&cal.tssi_6g_mcs[p], ofdm_group)?
        } else {
            group_de(&cal.tssi_mcs[p], ofdm_group)?
        };
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
        self.calibrated.then_some(&self.results)
    }
    /// rtw8852c_rfk.c `rtw8852c_tssi(PHY_0)`: `_tssi_disable` (A, B),
    /// the per-path sys/txpwr-ctrl/DCK/bbgain/tmeter/slope/alignment-default
    /// programs, `_tssi_enable` (track, TXAGC offset moving average,
    /// enable; `is_tssi_mode` set) and `_tssi_set_efuse_to_de`. Linux has
    /// no coexistence notification here; the I/O-free `Kind::Tssi`
    /// bracket only keeps RFK exclusivity.
    ///
    /// # Safety
    /// Actual RTL8852C PHY0 (non-DBCC) after the BB/RF retune to THIS
    /// `channel`, its RX DCK and IQK; `calibration` is this device's C
    /// factory snapshot and `tracking` this container's TXPWR_TRK.
    /// Interface enforces current admission at every access; no concurrent
    /// PHY/packet/reset/PM owner.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
    ) -> Result<(), Error> {
        // SAFETY: forwarded caller contract.
        unsafe { self.program(io, channel, calibration, tracking, true) }.await
    }

    /// rtw8852c_rfk.c `rtw8852c_tssi_scan(PHY_0)`, run by core.c
    /// `__rtw89_set_channel` -> `rtw8852c_rfk_band_changed` after the
    /// channel help exit when the band changed (or no entity was active):
    /// returns without I/O unless both paths are in TSSI mode, else
    /// `_tssi_disable`, per path `_tssi_set_sys`, `_tssi_set_dck`,
    /// `_tssi_set_tmeter_tbl`, `_tssi_slope_cal_org`,
    /// `_tssi_set_aligk_default`, then `_tssi_enable` and
    /// `_tssi_set_efuse_to_de` for the new channel. Returns whether it ran.
    ///
    /// # Safety
    /// Same as [`Self::run`], on the channel just programmed by
    /// `rfk::c_channel::Channel::set_channel`.
    pub async unsafe fn scan(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        tssi_mode: [bool; 2],
    ) -> Result<bool, Error> {
        if !tssi_mode[0] || !tssi_mode[1] {
            return Ok(false);
        }
        // SAFETY: forwarded caller contract.
        unsafe { self.program(io, channel, calibration, tracking, false) }.await?;
        Ok(true)
    }

    async unsafe fn program(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        full: bool,
    ) -> Result<(), Error> {
        self.calibrated = false;
        self.results = Results::default();
        io.admit()?;
        io.begin(Kind::Tssi).await?;
        let mut access = Access(io);
        access.table(&TSSI_DISABLE_DEFS_A).await?;
        access.table(&TSSI_DISABLE_DEFS_B).await?;
        for path in 0..2u8 {
            self.results.thermal[usize::from(path)] = access
                .c_tssi_path(
                    path,
                    channel,
                    calibration.thermal[usize::from(path)],
                    tracking,
                    full,
                )
                .await?;
        }
        for path in 0..2usize {
            let a = path == 0;
            access
                .table(if a {
                    &TSSI_TRACK_DEFS_A[..]
                } else {
                    &TSSI_TRACK_DEFS_B[..]
                })
                .await?;
            access
                .table(if a {
                    &TSSI_TXAGC_OFST_MV_AVG_DEFS_A[..]
                } else {
                    &TSSI_TXAGC_OFST_MV_AVG_DEFS_B[..]
                })
                .await?;
            access
                .table(if a {
                    &TSSI_ENABLE_DEFS_A[..]
                } else {
                    &TSSI_ENABLE_DEFS_B[..]
                })
                .await?;
            self.results.tssi_mode[path] = true;
        }
        for path in 0..2u8 {
            self.results.de[usize::from(path)] = access.c_tssi_de(path, channel, calibration)?;
        }
        access.0.admit()?;
        access.0.end(Kind::Tssi).await?;
        self.calibrated = true;
        Ok(())
    }
}
