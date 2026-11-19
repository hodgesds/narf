// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B channel TSSI: rtw8851b_rfk.c `rtw8851b_tssi(PHY_0)`,
//! `rtw8851b_tssi_scan` (`rfk_band_changed`) and the scan-end
//! `rtw8851b_tssi_default_txagc` (`rfk_scan`) on RF path A
//! (`RTW8851B_TSSI_PATH_NR` 1) for one typed B [`Profile`]. RTL8851B has no
//! PMAC alignment measurement: `_tssi_alignment_default` loads the fixed
//! per-band rows and `tssi_info->alignment_done` is never set, so
//! `_tssi_alimentk_done` reprograms nothing.
//!
//! The thermal-offset rows come only from the container's TXPWR_TRK
//! element (fw.c `rtw89_build_txpwr_trk_tbl_from_elm` with RTL8851B's
//! 2/5GHz `needed_bitmap`). NARF carries no copy of the static
//! `rtw89_8851b_trk_cfg` fallback, so a container without the element is
//! refused rather than calibrated from invented rows.
use super::super::{factory_51::Calibration, operating_channel::Profile, radio_assets::Assets};
use super::{Access, Error, Interface, Kind};
#[path = "n51_tssi_tables.rs"]
mod tables;
use tables::*;

/// core.h `DELTA_SWINGIDX_SIZE`.
const SWING: usize = 30;
/// `_TSSI_DE_MASK`.
const DE_MASK: u32 = 0x003f_f000;
/// `_tssi_de_cck_long/short`, `_tssi_de_mcs_{20m,40m,80m,80m_80m,5m,10m}`.
const DE_CCK: [u32; 2] = [0x5858, 0x5860];
const DE_MCS: [u32; 6] = [0x5838, 0x5840, 0x5848, 0x5850, 0x5828, 0x5830];
/// rtw8851b_rfk.c `TSSI_EXTRA_GROUP_BIT` (also B's `tssi_groups` bit).
const TSSI_EXTRA: u32 = 1 << 31;

const R_P0_TMETER: u32 = 0x5810;
const B_P0_TMETER: u32 = 0xfc00;
const B_P0_TMETER_DIS: u32 = 1 << 16;
const B_P0_TMETER_TRK: u32 = 1 << 24;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_RFC: u32 = 0x1800_0000;
const B_P0_TSSI_OFT_EN: u32 = 1 << 28;
const B_P0_TSSI_OFT: u32 = 0xff;
const R_P0_TSSI_AVG: u32 = 0x5820;
const B_P0_TSSI_EN: u32 = 1 << 31;
const R_P0_RFCTM: u32 = 0x5864;
const B_P0_RFCTM_VAL: u32 = 0x03f0_0000;
const R_P0_RFCTM_RDY: u32 = 1 << 26;
const R_P0_TSSI_MV_AVG: u32 = 0x58e4;
const B_P0_TSSI_MV_CLR: u32 = 1 << 14;
const R_P0_TSSI_BASE: u32 = 0x5c00;
const RR_TXGA_V1: u32 = 0x10055;
const RR_TXGA_V1_TRK_EN: u32 = 1 << 7;

/// fw.h `RTW89_DEFAULT_NEEDED_FW_TXPWR_TRK_{5GHZ,2GHZ}` (types 4..=15).
const NEEDED: u32 = 0xfff0;
/// `RTW89_FW_TXPWR_TRK_TYPE_{5GA_N,5GA_P,2GA_N,2GA_P}`.
const T5GA_N: usize = 6;
const T5GA_P: usize = 7;
const T2GA_N: usize = 10;
const T2GA_P: usize = 11;

/// The RTL8851B TXPWR_TRK rows: `delta[type][subband]` for the types
/// the element carries (6G: 4 subband rows, 5G: 3, 2G/CCK: 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct Tracking {
    delta: [[[i8; SWING]; 4]; 16],
}

impl Tracking {
    /// The first aid-matched TXPWR_TRK element (id 18) of the container.
    pub(in super::super) fn from_assets(assets: &Assets) -> Result<Self, Error> {
        let element = assets
            .elements()
            .iter()
            .find(|element| element.id == 18)
            .ok_or(Error::Table)?;
        Self::parse(&element.bytes)
    }
    /// fw.c `rtw89_build_txpwr_trk_tbl_from_elm` for RTL8851B
    /// `support_bands` 2/5GHz: the 5G and 2G (incl. CCK) types are needed;
    /// present types are consumed in bit order (6G 4, 5G 3, 2G 1 subband
    /// rows of 30), a bit above 15 ends the walk, and every consumed row
    /// must lie inside the element (Linux checks against the union size).
    pub(in super::super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let head: [u8; 4] = bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Table)?;
        let mut bitmap = u32::from_le_bytes(head);
        if bitmap & NEEDED != NEEDED {
            return Err(Error::Table);
        }
        let contents = bytes.get(8..).ok_or(Error::Table)?;
        let mut delta = [[[0i8; SWING]; 4]; 16];
        let mut offset = 0usize;
        let mut kind = 0usize;
        while bitmap != 0 {
            if bitmap & 1 != 0 {
                let subbands = match kind {
                    0..=3 => 4,
                    4..=7 => 3,
                    8..=15 => 1,
                    _ => break,
                };
                for row in delta[kind].iter_mut().take(subbands) {
                    let data = contents
                        .get(offset * SWING..(offset + 1) * SWING)
                        .ok_or(Error::Table)?;
                    for (out, &input) in row.iter_mut().zip(data) {
                        *out = input as i8;
                    }
                    offset += 1;
                }
            }
            kind += 1;
            bitmap >>= 1;
        }
        Ok(Self { delta })
    }
    /// `_tssi_set_tmeter_tbl` path-A (up, down) rows by
    /// `chan->subband_type`.
    fn rows(&self, subband: u8) -> (&[i8; SWING], &[i8; SWING]) {
        let (up, down, index) = match subband {
            1 => (T5GA_P, T5GA_N, 0),
            3 => (T5GA_P, T5GA_N, 1),
            4 => (T5GA_P, T5GA_N, 2),
            // `default:` / RTW89_CH_2G.
            _ => (T2GA_P, T2GA_N, 0),
        };
        (&self.delta[up][index], &self.delta[down][index])
    }
}

/// `_tssi_set_tmeter_tbl` offset words (`RTW8851B_TSSI_GET_VAL`).
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

/// `_tssi_get_ofdm_de` / `_tssi_get_ofdm_trim_de`: an extra group is the
/// C `(s8 + s8) / 2` average truncated back to `s8`.
fn group_de(values: &[i8], group: u32) -> Result<i8, Error> {
    let at = |index: u32| {
        values
            .get(index as usize)
            .map(|&v| i32::from(v))
            .ok_or(Error::Table)
    };
    if group & TSSI_EXTRA != 0 {
        let first = group & !TSSI_EXTRA;
        Ok(((at(first)? + at(first + 1)?) / 2) as i8)
    } else {
        Ok(at(group)? as i8)
    }
}

/// Results retained by one RTL8851B TSSI program.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// Thermal-offset words written at `R_P0_TSSI_BASE`.
    pub thermal: [u32; 16],
    /// (CCK, MCS) DE values (`s32`, written into the 10-bit field).
    pub de: [i32; 2],
    /// `rtwdev->is_tssi_mode[RF_PATH_A]` after `_tssi_enable`.
    pub tssi_mode: bool,
}

/// One RTL8851B channel TSSI owner.
#[derive(Default)]
pub(in super::super) struct Tssi {
    results: Results,
    calibrated: bool,
}

impl<I: Interface> Access<'_, I> {
    /// `_tssi_disable`.
    fn n51_tssi_disable(&mut self) -> Result<(), Error> {
        self.wm(R_P0_TSSI_AVG, B_P0_TSSI_EN, 0)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 1)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0)?;
        self.wm(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_CLR, 1)
    }
    /// `_tssi_enable` (`is_tssi_mode[A]` is set by the caller).
    async fn n51_tssi_enable(&mut self) -> Result<(), Error> {
        self.table(&TSSI_TRACK_DEFS_A).await?;
        self.table(&TSSI_MV_AVG_DEFS_A).await?;
        self.wm(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_CLR, 0)?;
        self.wm(R_P0_TSSI_AVG, B_P0_TSSI_EN, 0)?;
        self.wm(R_P0_TSSI_AVG, B_P0_TSSI_EN, 1)?;
        self.wr(0, RR_TXGA_V1, RR_TXGA_V1_TRK_EN, 1).await?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_RFC, 3)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT, 0xc0)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0)?;
        self.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 1)
    }
    /// `_tssi_set_tmeter_tbl(A)`; returns the offset words.
    fn n51_tssi_tmeter(
        &mut self,
        channel: Profile,
        thermal: u8,
        tracking: &Tracking,
    ) -> Result<[u32; 16], Error> {
        self.wm(R_P0_TMETER, B_P0_TMETER_DIS, 0)?;
        self.wm(R_P0_TMETER, B_P0_TMETER_TRK, 1)?;
        let words = if thermal == 0xff {
            self.wm(R_P0_TMETER, B_P0_TMETER, 32)?;
            self.wm(R_P0_RFCTM, B_P0_RFCTM_VAL, 32)?;
            [0; 16]
        } else {
            self.wm(R_P0_TMETER, B_P0_TMETER, u32::from(thermal))?;
            self.wm(R_P0_RFCTM, B_P0_RFCTM_VAL, u32::from(thermal))?;
            let (up, down) = tracking.rows(channel.subband());
            thermal_words(up, down)
        };
        for (i, &word) in words.iter().enumerate() {
            self.0.admit()?;
            self.0
                .write32(0x10000 + R_P0_TSSI_BASE + 4 * i as u32, word)?;
        }
        self.wm(R_P0_RFCTM, R_P0_RFCTM_RDY, 1)?;
        self.wm(R_P0_RFCTM, R_P0_RFCTM_RDY, 0)?;
        Ok(words)
    }
    /// `_tssi_set_efuse_to_de` (path A); returns (CCK, MCS) DE.
    fn n51_tssi_de(&mut self, channel: Profile, cal: &Calibration) -> Result<[i32; 2], Error> {
        let [cck_group, ofdm_group, trim_group] = channel.tssi_groups();
        let trim = group_de(&cal.tssi_trim, trim_group as u32)?;
        let cck = i32::from(*cal.tssi_cck.get(cck_group).ok_or(Error::Table)?) + i32::from(trim);
        for &address in &DE_CCK {
            self.wm(address, DE_MASK, cck as u32)?;
        }
        let ofdm = group_de(&cal.tssi_mcs, ofdm_group as u32)?;
        // `s8 ofdm_de + s8 trim_de` in `s32`.
        let mcs = i32::from(ofdm) + i32::from(trim);
        for &address in &DE_MCS {
            self.wm(address, DE_MASK, mcs as u32)?;
        }
        Ok([cck, mcs])
    }
}

impl Tssi {
    pub fn results(&self) -> Option<&Results> {
        self.calibrated.then_some(&self.results)
    }
    /// rtw8851b_rfk.c `rtw8851b_tssi(PHY_0)`: `BTC_WRFKT_IQK` ONESHOT
    /// START, `_tssi_disable`, path A sys / init txpwr (+HE TB) / DCK /
    /// tmeter / DAC gain / slope-cal-org / alignment default / slope,
    /// `_tssi_enable`, `_tssi_set_efuse_to_de`, ONESHOT STOP.
    ///
    /// # Safety
    /// Actual RTL8851B PHY_0 after the BB/RF program for THIS `channel`,
    /// its RX DCK and IQK; `calibration` is this device's RTL8851B factory
    /// snapshot and `tracking` this container's TXPWR_TRK. Interface
    /// enforces current admission at every access; no concurrent
    /// PHY/packet/reset/PM owner.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
    ) -> Result<(), Error> {
        self.calibrated = false;
        self.results = Results::default();
        io.admit()?;
        io.begin(Kind::IqkPath).await?;
        let mut access = Access(io);
        let two = !channel.is_5ghz();
        access.n51_tssi_disable()?;
        access.table(&TSSI_SYS_DEFS).await?;
        access
            .table(if two {
                &TSSI_SYS_A_DEFS_2G
            } else {
                &TSSI_SYS_A_DEFS_5G
            })
            .await?;
        access.table(&TSSI_INIT_TXPWR_DEFS_A).await?;
        access.table(&TSSI_INIT_TXPWR_HE_TB_DEFS_A).await?;
        access.table(&TSSI_DCK_DEFS_A).await?;
        self.results.thermal = access.n51_tssi_tmeter(channel, calibration.thermal, tracking)?;
        access.table(&TSSI_DAC_GAIN_DEFS_A).await?;
        access
            .table(if two {
                &TSSI_SLOPE_A_DEFS_2G
            } else {
                &TSSI_SLOPE_A_DEFS_5G
            })
            .await?;
        access
            .table(if two {
                &TSSI_ALIGN_A_2G_DEFS[..]
            } else {
                &TSSI_ALIGN_A_5G_DEFS[..]
            })
            .await?;
        access.table(&TSSI_SLOPE_DEFS_A).await?;
        access.n51_tssi_enable().await?;
        self.results.tssi_mode = true;
        self.results.de = access.n51_tssi_de(channel, calibration)?;
        access.0.admit()?;
        access.0.end(Kind::IqkPath).await?;
        self.calibrated = true;
        Ok(())
    }

    /// rtw8851b_rfk.c `rtw8851b_tssi_scan(PHY_0)`, run by core.c
    /// `__rtw89_set_channel` -> `rtw8851b_rfk_band_changed` (no TSSI-mode
    /// gate on RTL8851B, no BTC notification): `_tssi_disable`, path A
    /// sys / tmeter / slope-cal-org / alignment default, `_tssi_enable`,
    /// `_tssi_set_efuse_to_de` for the new channel.
    ///
    /// # Safety
    /// Same as [`Self::run`], on the channel just programmed.
    pub async unsafe fn scan(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
    ) -> Result<(), Error> {
        self.calibrated = false;
        self.results = Results::default();
        io.admit()?;
        let mut access = Access(io);
        let two = !channel.is_5ghz();
        access.n51_tssi_disable()?;
        access.table(&TSSI_SYS_DEFS).await?;
        access
            .table(if two {
                &TSSI_SYS_A_DEFS_2G
            } else {
                &TSSI_SYS_A_DEFS_5G
            })
            .await?;
        self.results.thermal = access.n51_tssi_tmeter(channel, calibration.thermal, tracking)?;
        access
            .table(if two {
                &TSSI_SLOPE_A_DEFS_2G
            } else {
                &TSSI_SLOPE_A_DEFS_5G
            })
            .await?;
        access
            .table(if two {
                &TSSI_ALIGN_A_2G_DEFS[..]
            } else {
                &TSSI_ALIGN_A_5G_DEFS[..]
            })
            .await?;
        access.n51_tssi_enable().await?;
        self.results.tssi_mode = true;
        self.results.de = access.n51_tssi_de(channel, calibration)?;
        self.calibrated = true;
        Ok(())
    }

    /// rtw8851b_rfk.c `rtw8851b_wifi_scan_notify` ->
    /// `rtw8851b_tssi_default_txagc(enable = !scan_start)`: a scan start is
    /// a no-op; scan end rewrites `B_P0_TSSI_OFT` 0xc0 and toggles
    /// `B_P0_TSSI_OFT_EN` 0 -> 1 (`_tssi_alimentk_done` writes nothing
    /// because RTL8851B never sets `alignment_done`).
    ///
    /// # Safety
    /// Retained RTL8851B PHY_0 owner after a completed [`Self::run`].
    pub async unsafe fn scan_notify(
        io: &mut impl Interface,
        scan_start: bool,
    ) -> Result<(), Error> {
        if scan_start {
            return Ok(());
        }
        io.admit()?;
        let mut access = Access(io);
        access.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT, 0xc0)?;
        access.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0)?;
        access.wm(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 1)
    }
}
