// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A per-channel TX power program (`rtw8922a_set_txpwr`, PHY_0)
//! built only from the container's firmware TXPWR elements.
//!
//! The element selection and the limit/RU readers are the shared
//! phy.c/fw.c rules in [`super::radio_power_c`] (`select`,
//! `Rules::for_channel`, `tx_shape`, `SixGhzPower`): fw.c
//! `rtw89_fw_load_txpwr_*` loads the same element IDs (BYRATE 9,
//! LMT 10/11/12, LMT_RU 13/14/15, TX_SHAPE_LMT 16, REGD 20) for every
//! generation, and phy.c `rtw89_phy_read_txpwr_limit{,_ru}` is
//! generation-independent. What is BE-specific — and lives here — is
//! the *set* side, phy_be.c `rtw89_phy_set_txpwr_byrate_be` /
//! `_offset_be` / `_limit_be` / `_limit_ru_be` plus rtw8922a.c
//! `rtw8922a_set_tx_shape` / `_set_txpwr_diff` / `_set_txpwr_ref` /
//! `_set_txpwr_sar_diff`, in `rtw8922a_set_txpwr` order:
//!
//! * By-rate: phy_be.c `rtw89_byr_spec_be` — CCK 4 (bw <= 40 only),
//!   OFDM 8, MCS 14/15 in two 2-entry arms (non-OFDMA and OFDMA),
//!   MCS 0..13 and HEDCM 0..3 per OFDMA kind — walked for every
//!   bandwidth 20..320 MHz (`RTW89_CHANNEL_WIDTH_320` = 4) and NSS
//!   1..2, packed 4 MAC units per word from `R_BE_PWR_BY_RATE`
//!   (0x11E00). 107 words; the last lands on
//!   `R_BE_PWR_BY_RATE_MAX` (0x11FA8).
//! * Offset: 8 rate offsets (HE, VHT, HT, OFDM, CCK, DLRU_EHT,
//!   DLRU_HE, EHT — core.h `rtw89_rate_offset_indexes`) packed 4 bits
//!   each into `R_BE_PWR_RATE_OFST_CTRL` (0x11A30).
//! * Shape: `rtw8922a_set_tx_shape` is only the OFDM triangular bit
//!   (`rtw8922a_bb_tx_triangular`: `R_BEDGE3` 0x6C04,
//!   `B_BEDGE_CFG` GENMASK(1, 0), on iff the OFDM shape index is
//!   nonzero). There is no BE DFIR program and no BE TSSI bandedge
//!   table in `set_txpwr` — the AX `TSSI_DBW` program does not apply.
//! * Limits: phy_be.c `struct rtw89_txpwr_limit_be` (76 bytes:
//!   cck_20m/40m, ofdm, mcs_20m[16], mcs_40m[8], mcs_80m[4],
//!   mcs_160m[2], mcs_320m, mcs_40m_0p5/2p5/4p5/6p5; each
//!   [nonbf, bf]) per ntx from `R_BE_PWR_LMT` (0x11FAC), 19 words
//!   per page; the 320 MHz fill is 6GHz-only in practice because
//!   `Rules::limit` returns 0 for bw 4 outside 6GHz
//!   (`RTW89_6G_BW_NUM` = 5).
//! * RU limits: phy_be.c `struct rtw89_txpwr_limit_ru_be` (80 bytes:
//!   ru26/ru52/ru106/ru52_26/ru106_26, 16 sections each) per ntx from
//!   `R_BE_PWR_RULMT_START` (0x12048), 20 words per page.
//! * Diff/ref: `rtw8922a_set_txpwr_diff` from the antenna-gain power
//!   offset (`rtw89_phy_ant_gain_pwr_offset`; 0 with no DAG source,
//!   as on the C plan) and the cut version (`hal.cv == CHIP_CAV`
//!   raises the reference to 16 RF units); `rtw8922a_set_txpwr_ref`
//!   zeroes the OFDM/CCK reference fields of `R_BE_PWR_REF_CTRL`.
//! * SAR: `rtw8922a_set_txpwr_sar_diff` (PHY_0 only) with no SAR
//!   source, so both paths take `RTW89_SAR_TXPWR_MAC_MAX` (63) as
//!   `mac_to_rf` 126 into `R_P0/P1_TXPWRB_BE` — the same no-SAR
//!   stance as the C plan.
//!
//! The regulatory state is the same default this tree can assert
//! elsewhere: regd `RTW89_WW` (no country programmed) on 2.4/5 GHz,
//! the explicit regd.c 6GHz context (`SixGhzPower`) with the TPE
//! constraint on 6GHz, no SAR source, no antenna-gain (DAG) tables,
//! no DA-limit elements. A container without the needed elements is
//! refused rather than defaulted: 8922A has no static
//! `rtw8922a_table.c` copy in NARF (Linux carries the tables NULL,
//! "load parm from fw").
//!
//! The by-rate tables are read per bandwidth: fw.c
//! `rtw89_fw_load_txpwr_byrate` loads into `byr[band][bw]`, and the
//! BE setter reads each (bw, nss) pair — unlike the AX setter, which
//! reads bw 0 only. The offset table is read at bw 0 in both.
//!
//! This is register configuration only: it makes no conducted-power,
//! regulatory or SAR claim for any board. The periodic thermal /
//! TSSI tracking loop and the RFK reruns (IQK/DPK/TSSI) are NOT
//! here: they need the BE TSSI system/slope tables and the
//! `rtw89_phy_rfk_*_and_wait` machinery, which are follow-ups
//! (#1878 follow-up issues). The one-shot `rtw8922a_tssi_reset`
//! pulse is included ([`tssi_reset_program`]) because it is a pure
//! register program on the RX-path control this power program
//! already touches.
#![allow(dead_code)]

// The consumer is `prepared_8922a::Prepared8922a::set_txpwr`,
// which builds the plan per admitted station
// (`station_8922a::Station::txpwr_plan`) and emits it over the
// BAR2 register port; the BE policy board (`Board::new_be`,
// channel qualification) remains a follow-up of #1878, and the
// allow above stays until that board lands.

use super::operating_channel_c::Band;
use super::radio_assets::{Assets, Element};
use super::radio_power_c::{
    rf_to_mac, select, tx_shape, Rules, SixGhzPower, ID_BYRATE, MIN_VALID_POWER_CONSTRAINT, RS_CCK,
    RS_HEDCM, RS_MCS, RS_OFDM, RS_OFFSET,
};
use super::rfk::Error;

/// `rtw89_phy_gen_be.cr_base` (phy_be.c): BE PHY CRs live at
/// 0x20000 + CR. MAC TXPWR CRs (`R_BE_PWR_*`) are plain absolute
/// addresses (PHY_0, `rtw89_mac_reg_by_idx` identity for MAC_0).
const PHY: u32 = 0x2_0000;
/// `R_BE_PWR_BY_RATE` (reg.h:8529).
const R_BE_PWR_BY_RATE: u32 = 0x11E00;
/// `R_BE_PWR_BY_RATE_MAX` (reg.h:8530): the last by-rate word.
const R_BE_PWR_BY_RATE_MAX: u32 = 0x11FA8;
/// `R_BE_PWR_LMT` (reg.h:8531).
const R_BE_PWR_LMT: u32 = 0x11FAC;
/// `R_BE_PWR_LMT_MAX` (reg.h:8532): the last limit word.
const R_BE_PWR_LMT_MAX: u32 = 0x12040;
/// `R_BE_PWR_RULMT_START` (reg.h:8484).
const R_BE_PWR_RULMT_START: u32 = 0x12048;
/// `R_BE_PWR_RULMT_END` (reg.h:8485): the last RU-limit word.
const R_BE_PWR_RULMT_END: u32 = 0x120E4;
/// `R_BE_PWR_RATE_OFST_CTRL` (reg.h:8482).
const R_BE_PWR_RATE_OFST_CTRL: u32 = 0x11A30;
/// `R_BE_PWR_REF_CTRL` (reg.h:8468).
const R_BE_PWR_REF_CTRL: u32 = 0x11A20;
/// `B_BE_PWR_REF_CTRL_OFDM` (reg.h:8469): GENMASK(9, 1).
const B_BE_PWR_REF_CTRL_OFDM: u32 = 0x3fe;
/// `B_BE_PWR_REF_CTRL_CCK` (reg.h:8470): GENMASK(18, 10).
const B_BE_PWR_REF_CTRL_CCK: u32 = 0x7_fc00;
/// `R_BEDGE3` (reg.h:10065; also `super::eht::R_BEDGE3`).
const R_BEDGE3: u32 = 0x6C04;
/// `B_BEDGE_CFG` (reg.h:10070): GENMASK(1, 0).
const B_BEDGE_CFG: u32 = 0x3;
/// `R_TXAGC_REF_DBM_P0` (reg.h:10537).
const R_TXAGC_REF_DBM_P0: u32 = 0xE628;
/// `B_TXAGC_OFDM_REF_DBM_P0` (reg.h:10538): GENMASK(8, 0).
const B_TXAGC_OFDM_REF_DBM_P0: u32 = 0x1ff;
/// `B_TXAGC_CCK_REF_DBM_P0` (reg.h:10539): GENMASK(17, 9).
const B_TXAGC_CCK_REF_DBM_P0: u32 = 0x3_fe00;
/// `R_TSSI_K_P0` (reg.h:10540).
const R_TSSI_K_P0: u32 = 0xE6A0;
/// `B_TSSI_K_OFDM_P0` (reg.h:10541): GENMASK(29, 20).
const B_TSSI_K_OFDM_P0: u32 = 0x3ff0_0000;
/// `R_P0_TXPWRB_BE` (reg.h:10528).
const R_P0_TXPWRB_BE: u32 = 0xE61C;
/// `R_P1_TXPWRB_BE` (reg.h:10529).
const R_P1_TXPWRB_BE: u32 = 0xE71C;
/// `B_TXPWRB_MAX_BE` (reg.h:10532): GENMASK(20, 12).
const B_TXPWRB_MAX_BE: u32 = 0x1ff000;
/// `R_TXPWR_RSTA` (reg.h:10523).
const R_TXPWR_RSTA: u32 = 0xE60C;
/// `B_TXPWR_RSTA` (reg.h:10524): BIT(16).
const B_TXPWR_RSTA: u32 = 1 << 16;
/// `R_TXPWR_RSTB` (reg.h:10542).
const R_TXPWR_RSTB: u32 = 0xE70C;
/// `B_TXPWR_RSTB` (reg.h:10543): BIT(16).
const B_TXPWR_RSTB: u32 = 1 << 16;

/// `enum rtw89_chip_gen` is AX/BE; `enum rtw89_cv`: `CHIP_CAV` = 0
/// (core.h:200..201).
const CHIP_CAV: u8 = 0;
/// `rtw8922a_set_txpwr_diff`: `tssi_k_base` = 0x12.
const TSSI_K_BASE: i16 = 0x12;
/// `RTW89_SAR_TXPWR_MAC_MAX` (no SAR source).
const SAR_MAC_MAX: i8 = 63;
/// `rtw89_phy_txpwr_mac_to_rf` (factor mac 1, rf 2: << 1).
const fn mac_to_rf(v: i8) -> i16 {
    (v as i16) << 1
}
/// `rtw89_phy_txpwr_bb_to_rf` (factor bb 3, rf 2: arithmetic >> 1).
const fn bb_to_rf(v: i16) -> i16 {
    v >> 1
}

/// Linux channel bandwidths (`enum rtw89_channel_width`):
/// 20/40/80/160/320 MHz = 0..4 (`RTW89_CHANNEL_WIDTH_320` = 4,
/// core.h:959; `RTW89_2G_BW_NUM` = 2, `RTW89_5G_BW_NUM` = 4,
/// `RTW89_6G_BW_NUM` = 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bw {
    Mhz20 = 0,
    Mhz40 = 1,
    Mhz80 = 2,
    Mhz160 = 3,
    Mhz320 = 4,
}

impl Bw {
    /// Bandwidths a band admits (`RTW89_*_BW_NUM`).
    fn legal(self, band: Band) -> bool {
        let n = match band {
            Band::Ghz2 => 2,
            Band::Ghz5 => 4,
            Band::Ghz6 => 5,
        };
        (self as u8) < n
    }
}

/// One BE TX-power channel: band, primary and center channels, and
/// the Linux bandwidth enum. The center channel is the
/// `rtw89_chan.channel` the limit fills use; the primary is
/// `primary_channel` (OFDM limit reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Channel {
    band: Band,
    primary: u8,
    center: u8,
    bw: Bw,
}

impl Channel {
    /// `None` on a zero primary or a bandwidth the band does not
    /// admit (320 MHz is 6GHz-only; 80/160 MHz are not 2.4GHz
    /// widths). The center channel is unchecked: phy.c
    /// `rtw89_channel_to_idx` maps unknown channels to 0, as Linux
    /// does after its warning.
    pub(super) fn new(band: Band, primary: u8, center: u8, bw: Bw) -> Option<Self> {
        if primary == 0 || !bw.legal(band) {
            return None;
        }
        Some(Self {
            band,
            primary,
            center,
            bw,
        })
    }
    pub(super) fn band(&self) -> Band {
        self.band
    }
    pub(super) fn primary(&self) -> u8 {
        self.primary
    }
    pub(super) fn center(&self) -> u8 {
        self.center
    }
    pub(super) fn bw(&self) -> Bw {
        self.bw
    }
}

/// One loaded `struct rtw89_txpwr_byrate` (core.h:830..838), in RF
/// units as fw.c loaded it: `mcs[ofdma][nss][16]` is the BE width
/// (`__RTW89_RATE_MCS_NUM` = 16); `offset` is the full
/// `__RTW89_RATE_OFFSET_NUM` = 8.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Byr {
    cck: [i8; 4],
    ofdm: [i8; 8],
    mcs: [[[i8; 16]; 2]; 2],
    hedcm: [[[i8; 4]; 2]; 2],
    offset: [i8; 8],
}

/// fw.c `rtw89_fw_load_txpwr_byrate` into `byr[band][bw]`, with
/// fw.c `fw_txpwr_byrate_entry_valid` bounds (MCS <= 16 entries,
/// NSS < 2 here — Linux allows < `RTW89_NSS_NUM` but this plan stores
/// only the NSS 0..1 the BE setter reads — OFDMA < 2; HEDCM <= 4
/// entries, NSS < 2, OFDMA < 2; OFFSET <= 8 entries). Later entries
/// overwrite, as in Linux. The entry layout is fw.h
/// `struct rtw89_fw_txpwr_byrate_entry` (11 bytes: band, nss, rs,
/// shf, len, data LE32, bw, ofdma).
fn load_byrate(byrate: super::radio_power_c::Conf<'_>) -> [[Byr; 5]; 3] {
    let mut byr = [[Byr {
        cck: [0; 4],
        ofdm: [0; 8],
        mcs: [[[0; 16]; 2]; 2],
        hedcm: [[[0; 4]; 2]; 2],
        offset: [0; 8],
    }; 5]; 3];
    for e in byrate.entries(11) {
        let (eb, nss, rs, shf, len, bw, ofdma) = (e[0], e[1], e[2], e[3], e[4], e[9], e[10]);
        let (shf, len) = (usize::from(shf), usize::from(len));
        let bound = match rs {
            RS_CCK => 4,
            RS_OFDM => 8,
            // Linux fw.c validity allows MCS NSS < `RTW89_NSS_NUM` (4);
            // this plan stores only the NSS 0..1 the BE setter reads
            // (`RTW89_NSS_2` = 1), so NSS 2/3 rows are skipped, as the
            // C plan skips them — never stored, never an error.
            RS_MCS if nss < 2 && ofdma < 2 => 16,
            RS_HEDCM if nss < 2 && ofdma < 2 => 4,
            RS_OFFSET => 8,
            _ => continue,
        };
        if eb >= 3 || bw >= 5 || shf + len > bound {
            continue;
        }
        let mut data = u32::from_le_bytes([e[5], e[6], e[7], e[8]]);
        let head = &mut byr[usize::from(eb)][usize::from(bw)];
        for i in 0..len {
            let v = (data & 0xff) as i8;
            data >>= 8;
            let at = shf + i;
            let (n, o) = (usize::from(nss), usize::from(ofdma));
            match rs {
                RS_CCK => head.cck[at] = v,
                RS_OFDM => head.ofdm[at] = v,
                RS_MCS => head.mcs[o][n][at] = v,
                RS_HEDCM => head.hedcm[o][n][at] = v,
                _ => head.offset[at] = v,
            }
        }
    }
    byr
}

/// phy.c `rtw89_phy_read_txpwr_byrate`: CCK always reads the 2.4GHz
/// band; the value is converted RF -> MAC (`>> 1`).
fn read_byrate(
    byr: &[[Byr; 5]; 3],
    band: Band,
    bw: u8,
    rs: u8,
    ofdma: usize,
    nss: usize,
    idx: usize,
) -> i8 {
    let band = if rs == RS_CCK { Band::Ghz2 } else { band };
    let head = &byr[band as usize][usize::from(bw)];
    let v = match rs {
        RS_CCK => head.cck[idx],
        RS_OFDM => head.ofdm[idx],
        RS_MCS => head.mcs[ofdma][nss][idx],
        RS_HEDCM => head.hedcm[ofdma][nss][idx],
        _ => head.offset[idx],
    };
    rf_to_mac(v)
}

/// One phy_be.c `rtw89_byr_spec_be` row.
struct ByrSpec {
    rs: u8,
    ofdma: usize,
    start: usize,
    num: usize,
    no_over_bw40: bool,
    no_multi_nss: bool,
}

/// phy_be.c `rtw89_byr_spec_be`, in Linux order: CCK 4 (bw <= 40,
/// nss 0), OFDM 8 (nss 0), MCS 14/15 non-OFDMA (nss 0), MCS 14/15
/// OFDMA (nss 0), MCS 0..13 non-OFDMA, HEDCM non-OFDMA, MCS 0..13
/// OFDMA, HEDCM OFDMA.
const BYR_SPEC: [ByrSpec; 8] = [
    ByrSpec {
        rs: RS_CCK,
        ofdma: 0,
        start: 0,
        num: 4,
        no_over_bw40: true,
        no_multi_nss: true,
    },
    ByrSpec {
        rs: RS_OFDM,
        ofdma: 0,
        start: 0,
        num: 8,
        no_over_bw40: false,
        no_multi_nss: true,
    },
    ByrSpec {
        rs: RS_MCS,
        ofdma: 0,
        start: 14,
        num: 2,
        no_over_bw40: false,
        no_multi_nss: true,
    },
    ByrSpec {
        rs: RS_MCS,
        ofdma: 1,
        start: 14,
        num: 2,
        no_over_bw40: false,
        no_multi_nss: true,
    },
    ByrSpec {
        rs: RS_MCS,
        ofdma: 0,
        start: 0,
        num: 14,
        no_over_bw40: false,
        no_multi_nss: false,
    },
    ByrSpec {
        rs: RS_HEDCM,
        ofdma: 0,
        start: 0,
        num: 4,
        no_over_bw40: false,
        no_multi_nss: false,
    },
    ByrSpec {
        rs: RS_MCS,
        ofdma: 1,
        start: 0,
        num: 14,
        no_over_bw40: false,
        no_multi_nss: false,
    },
    ByrSpec {
        rs: RS_HEDCM,
        ofdma: 1,
        start: 0,
        num: 4,
        no_over_bw40: false,
        no_multi_nss: false,
    },
];

/// phy_be.c `rtw89_phy_set_txpwr_byrate_be` stream length in words:
/// bw 20/40 stream 88 bytes (22 words), bw 80/160/320 stream 84
/// bytes (21 words): 22 + 22 + 21 + 21 + 21 = 107.
pub(super) const BYRATE_WORDS: usize = 107;
/// `struct rtw89_txpwr_limit_be` page size (phy.h:518).
pub(super) const LIMIT_PAGE_BYTES: usize = 76;
/// `struct rtw89_txpwr_limit_ru_be` page size (phy.h:547).
pub(super) const LIMIT_RU_PAGE_BYTES: usize = 80;

// The register windows close exactly on the Linux end addresses:
// by-rate 0x11E00 + 107 words ends at R_BE_PWR_BY_RATE_MAX,
// limits 0x11FAC + 2 pages of 76 bytes end at R_BE_PWR_LMT_MAX,
// RU limits 0x12048 + 2 pages of 80 bytes end at R_BE_PWR_RULMT_END.
const _: () = assert!(R_BE_PWR_BY_RATE + 4 * (BYRATE_WORDS as u32 - 1) == R_BE_PWR_BY_RATE_MAX);
const _: () = assert!(R_BE_PWR_LMT + 2 * LIMIT_PAGE_BYTES as u32 - 4 == R_BE_PWR_LMT_MAX);
const _: () =
    assert!(R_BE_PWR_RULMT_START + 2 * LIMIT_RU_PAGE_BYTES as u32 - 4 == R_BE_PWR_RULMT_END);

/// Limit and RU-limit pages per ntx (BE geometry).
type Pages = ([[i8; LIMIT_PAGE_BYTES]; 2], [[i8; LIMIT_RU_PAGE_BYTES]; 2]);

/// Test view of a plan: (by-rate words, offset, limit pages, RU pages, shape).
#[cfg(any(test, feature = "kernel-test"))]
pub(super) type PlanParts = (
    [u32; BYRATE_WORDS],
    [i8; 8],
    [[i8; LIMIT_PAGE_BYTES]; 2],
    [[i8; LIMIT_RU_PAGE_BYTES]; 2],
    [u8; 2],
);

/// One BE TX power program for one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    channel: Channel,
    /// Loaded by-rate tables `byr[band][bw]`, RF units.
    byr: [[Byr; 5]; 3],
    /// Rate offsets `__RTW89_RATE_OFFSET_NUM` = 8, MAC units, read
    /// at bw 0 (HE, VHT, HT, OFDM, CCK, DLRU_EHT, DLRU_HE, EHT).
    offset: [i8; 8],
    /// `struct rtw89_txpwr_limit_be` per ntx (1TX, 2TX).
    limit: [[i8; LIMIT_PAGE_BYTES]; 2],
    /// `struct rtw89_txpwr_limit_ru_be` per ntx.
    ru: [[i8; LIMIT_RU_PAGE_BYTES]; 2],
    /// `rtw89_get_tx_shape_idx(band, RS_CCK / RS_OFDM)`.
    shape: [u8; 2],
    /// 6GHz only: the regd.c power context and the TPE constraint (dBm).
    six: Option<(SixGhzPower, Option<i8>)>,
    /// 6GHz with a TPE only: the limit/RU pages without it, which the
    /// signed record identity binds (a TPE only lowers `min3`).
    untpe: Option<Pages>,
}

impl Plan {
    pub(super) fn channel(&self) -> Channel {
        self.channel
    }
    /// Test view: (by-rate words, offset, limit pages, RU pages, shape).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn parts(&self) -> PlanParts {
        (
            self.byrate_words(),
            self.offset,
            self.limit,
            self.ru,
            self.shape,
        )
    }
    pub(super) fn from_assets(assets: &Assets, rfe: u8, channel: Channel) -> Result<Self, Error> {
        Self::from_elements(assets.elements(), rfe, channel)
    }
    /// 2.4/5GHz under regd WW; a 6GHz channel is refused here (it
    /// needs [`Self::from_elements_6ghz`] and its regulatory context).
    pub(super) fn from_elements(
        elements: &[Element],
        rfe: u8,
        channel: Channel,
    ) -> Result<Self, Error> {
        if channel.band() == Band::Ghz6 {
            return Err(Error::Policy);
        }
        Self::build(elements, rfe, channel, None)
    }
    pub(super) fn from_assets_6ghz(
        assets: &Assets,
        rfe: u8,
        channel: Channel,
        power: SixGhzPower,
        tpe: Option<i8>,
    ) -> Result<Self, Error> {
        Self::from_elements_6ghz(assets.elements(), rfe, channel, power, tpe)
    }
    /// A typed 6GHz channel under `power`; `tpe` is the regd.c
    /// intersected TPE constraint (dBm), valid only for
    /// `RTW89_REG_6GHZ_POWER_STD`
    /// (`rtw89_reg_6ghz_tpe_recalc`; below -10 dBm is `-EINVAL`).
    pub(super) fn from_elements_6ghz(
        elements: &[Element],
        rfe: u8,
        channel: Channel,
        power: SixGhzPower,
        tpe: Option<i8>,
    ) -> Result<Self, Error> {
        if channel.band() != Band::Ghz6
            || (tpe.is_some() && power.power() != 2)
            || tpe.is_some_and(|c| c < MIN_VALID_POWER_CONSTRAINT)
        {
            return Err(Error::Policy);
        }
        let mut plan = Self::build(elements, rfe, channel, Some((power, tpe)))?;
        if tpe.is_some() {
            let bare = Self::build(elements, rfe, channel, Some((power, None)))?;
            plan.untpe = Some((bare.limit, bare.ru));
        }
        Ok(plan)
    }
    fn build(
        elements: &[Element],
        rfe: u8,
        channel: Channel,
        six: Option<(SixGhzPower, Option<i8>)>,
    ) -> Result<Self, Error> {
        if rfe == 255 {
            return Err(Error::Policy);
        }
        let byrate = select(elements, ID_BYRATE, rfe)?.ok_or(Error::Table)?;
        let rules = Rules::for_channel(elements, rfe, channel.band(), six)?;
        let byr = load_byrate(byrate);
        let mut offset = [0i8; 8];
        for (i, o) in offset.iter_mut().enumerate() {
            *o = read_byrate(&byr, channel.band(), 0, RS_OFFSET, 0, 0, i);
        }
        let shape = tx_shape(elements, rfe, channel.band(), six.map(|(p, _)| p))?;
        Ok(Self {
            channel,
            byr,
            offset,
            limit: [
                Self::limit_page(&rules, channel, 0),
                Self::limit_page(&rules, channel, 1),
            ],
            ru: [
                Self::ru_page(&rules, channel, 0),
                Self::ru_page(&rules, channel, 1),
            ],
            shape,
            six,
            untpe: None,
        })
    }
    /// phy_be.c `rtw89_phy_set_txpwr_byrate_be`: the 107-word
    /// stream for this channel's band, in Linux order.
    fn byrate_words(&self) -> [u32; BYRATE_WORDS] {
        let mut words = [0u32; BYRATE_WORDS];
        let mut at = 0usize;
        let mut byte = [0i8; 4];
        let mut n = 0usize;
        let mut push = |v: i8, words: &mut [u32; BYRATE_WORDS], at: &mut usize, n: &mut usize| {
            byte[*n] = v;
            *n += 1;
            if *n == 4 {
                words[*at] = u32::from_le_bytes([
                    byte[0] as u8,
                    byte[1] as u8,
                    byte[2] as u8,
                    byte[3] as u8,
                ]);
                *at += 1;
                *n = 0;
            }
        };
        for bw in 0..=4u8 {
            for nss in 0..=1usize {
                for spec in BYR_SPEC.iter() {
                    if bw > 1 && spec.no_over_bw40 {
                        continue;
                    }
                    if nss > 0 && spec.no_multi_nss {
                        continue;
                    }
                    for j in 0..spec.num {
                        let v = read_byrate(
                            &self.byr,
                            self.channel.band(),
                            bw,
                            spec.rs,
                            spec.ofdma,
                            nss,
                            spec.start + j,
                        );
                        push(v, &mut words, &mut at, &mut n);
                    }
                }
            }
        }
        // The spec table is const: the stream is exactly 428 bytes.
        debug_assert!(at == BYRATE_WORDS && n == 0);
        words
    }
    /// `u8 ch` arithmetic as in phy.c (`ch - 2` etc. truncated to u8).
    fn ch_offset(ch: u8, delta: i16) -> u8 {
        (i16::from(ch) + delta) as u8
    }
    /// phy_be.c `rtw89_phy_fill_limit_be`: the
    /// `struct rtw89_txpwr_limit_be` page for one ntx. Field offsets
    /// are the struct order (phy.h:520..538): cck_20m 0, cck_40m 2,
    /// ofdm 4, mcs_20m 6 (16x2), mcs_40m 38 (8x2), mcs_80m 54 (4x2),
    /// mcs_160m 62 (2x2), mcs_320m 66, mcs_40m_0p5 68, 2p5 70,
    /// 4p5 72, 6p5 74.
    fn limit_page(rules: &Rules<'_>, channel: Channel, ntx: u8) -> [i8; LIMIT_PAGE_BYTES] {
        let mut page = [0i8; LIMIT_PAGE_BYTES];
        let ch = channel.center();
        let pri = channel.primary();
        let mut put = |at: usize, v: [i8; 2]| page[at..at + 2].copy_from_slice(&v);
        let bf = |bw: u8, d: i16| {
            [
                rules.limit(bw, ntx, RS_MCS, 0, Self::ch_offset(ch, d)),
                rules.limit(bw, ntx, RS_MCS, 1, Self::ch_offset(ch, d)),
            ]
        };
        let min2 = |a: [i8; 2], b: [i8; 2]| [a[0].min(b[0]), a[1].min(b[1])];
        const CCK20: usize = 0;
        const CCK40: usize = 2;
        const OFDM: usize = 4;
        const MCS20: usize = 6;
        const MCS40: usize = 38;
        const MCS80: usize = 54;
        const MCS160: usize = 62;
        const MCS320: usize = 66;
        const P0P5: usize = 68;
        const P2P5: usize = 70;
        const P4P5: usize = 72;
        const P6P5: usize = 74;
        match channel.bw() {
            Bw::Mhz20 => {
                put(CCK20, rules.limit_bf(0, ntx, RS_CCK, ch));
                put(CCK40, rules.limit_bf(1, ntx, RS_CCK, ch));
                put(OFDM, rules.limit_bf(0, ntx, RS_OFDM, ch));
                put(MCS20, bf(0, 0));
            }
            Bw::Mhz40 => {
                put(
                    CCK20,
                    rules.limit_bf(0, ntx, RS_CCK, Self::ch_offset(ch, -2)),
                );
                put(CCK40, rules.limit_bf(1, ntx, RS_CCK, ch));
                put(OFDM, rules.limit_bf(0, ntx, RS_OFDM, pri));
                put(MCS20, bf(0, -2));
                put(MCS20 + 2, bf(0, 2));
                put(MCS40, bf(1, 0));
            }
            Bw::Mhz80 => {
                put(OFDM, rules.limit_bf(0, ntx, RS_OFDM, pri));
                for (i, d) in [-6, -2, 2, 6].into_iter().enumerate() {
                    put(MCS20 + 2 * i, bf(0, d));
                }
                put(MCS40, bf(1, -4));
                put(MCS40 + 2, bf(1, 4));
                put(MCS80, bf(2, 0));
                put(P0P5, min2(bf(1, -4), bf(1, 4)));
            }
            Bw::Mhz160 => {
                put(OFDM, rules.limit_bf(0, ntx, RS_OFDM, pri));
                for (i, d) in [-14, -10, -6, -2, 2, 6, 10, 14].into_iter().enumerate() {
                    put(MCS20 + 2 * i, bf(0, d));
                }
                for (i, d) in [-12, -4, 4, 12].into_iter().enumerate() {
                    put(MCS40 + 2 * i, bf(1, d));
                }
                put(MCS80, bf(2, -8));
                put(MCS80 + 2, bf(2, 8));
                put(MCS160, bf(3, 0));
                put(P0P5, min2(bf(1, -4), bf(1, 4)));
                put(P2P5, min2(bf(1, -8), bf(1, 8)));
            }
            Bw::Mhz320 => {
                put(OFDM, rules.limit_bf(0, ntx, RS_OFDM, pri));
                for (i, d) in [
                    -30, -26, -22, -18, -14, -10, -6, -2, 2, 6, 10, 14, 18, 22, 26, 30,
                ]
                .into_iter()
                .enumerate()
                {
                    put(MCS20 + 2 * i, bf(0, d));
                }
                for (i, d) in [-28, -20, -12, -4, 4, 12, 20, 28].into_iter().enumerate() {
                    put(MCS40 + 2 * i, bf(1, d));
                }
                for (i, d) in [-24, -8, 8, 24].into_iter().enumerate() {
                    put(MCS80 + 2 * i, bf(2, d));
                }
                put(MCS160, bf(3, -16));
                put(MCS160 + 2, bf(3, 16));
                put(MCS320, bf(4, 0));
                put(P0P5, min2(bf(1, -28), bf(1, -20)));
                put(P2P5, min2(bf(1, -12), bf(1, -4)));
                put(P4P5, min2(bf(1, 4), bf(1, 12)));
                put(P6P5, min2(bf(1, 20), bf(1, 28)));
            }
        }
        page
    }
    /// phy_be.c `rtw89_phy_fill_limit_ru_be`: the
    /// `struct rtw89_txpwr_limit_ru_be` page for one ntx
    /// (ru26/ru52/ru106/ru52_26/ru106_26, 16 sections each).
    fn ru_page(rules: &Rules<'_>, channel: Channel, ntx: u8) -> [i8; LIMIT_RU_PAGE_BYTES] {
        let ch = channel.center();
        let deltas: &[i16] = match channel.bw() {
            Bw::Mhz20 => &[0],
            Bw::Mhz40 => &[-2, 2],
            Bw::Mhz80 => &[-6, -2, 2, 6],
            Bw::Mhz160 => &[-14, -10, -6, -2, 2, 6, 10, 14],
            Bw::Mhz320 => &[
                -30, -26, -22, -18, -14, -10, -6, -2, 2, 6, 10, 14, 18, 22, 26, 30,
            ],
        };
        let mut page = [0i8; LIMIT_RU_PAGE_BYTES];
        for ru in 0..5u8 {
            for (i, &d) in deltas.iter().enumerate() {
                page[usize::from(ru) * 16 + i] = rules.limit_ru(ru, ntx, Self::ch_offset(ch, d));
            }
        }
        page
    }
    /// 6GHz only: the regd.c context and TPE constraint of this plan.
    pub(super) fn six_ghz(&self) -> Option<(SixGhzPower, Option<i8>)> {
        self.six
    }

    /// Bind the exact power program into a signed-record digest.
    /// The by-rate stream words are hashed (they are the pure
    /// function of the loaded by-rate tables this program programs);
    /// a 6GHz plan binds its regd.c context and the pre-TPE pages
    /// (a TPE only lowers `min3`, so the record measured without it
    /// covers every TPE-constrained plan).
    pub fn bind(&self, hash: &mut narf_crypto::sha256::Sha256) {
        if let Some((six, _)) = self.six {
            hash.update(b"BE 6GHz fw TXPWR elements;regd6/reg_6ghz_power;no SAR/DAG;TPE excluded");
            hash.update(&[six.regd(), six.power()]);
        } else {
            hash.update(b"BE WW0 fw TXPWR elements;no SAR/DAG/TPE;rtw8922a_set_txpwr");
        }
        hash.update(&[
            self.channel.band() as u8,
            self.channel.primary(),
            self.channel.center(),
            self.channel.bw() as u8,
        ]);
        for w in self.byrate_words() {
            hash.update(&w.to_le_bytes());
        }
        let (limit, ru) = self
            .untpe
            .as_ref()
            .map_or((&self.limit, &self.ru), |(l, r)| (l, r));
        for row in [
            &self.offset[..],
            &limit[0][..],
            &limit[1][..],
            &ru[0][..],
            &ru[1][..],
        ] {
            for &v in row {
                hash.update(&v.to_le_bytes());
            }
        }
        hash.update(&self.shape);
    }

    /// `rtw8922a_set_txpwr(chan, PHY_0)` as (absolute address, mask,
    /// value) writes in Linux order; MAC TXPWR CRs plain, BE PHY CRs
    /// in the 0x20000 window. `ant_gain_offset` is
    /// `rtw89_phy_ant_gain_pwr_offset` (0 with no DAG source, as on
    /// the C plan); `cv` is the `hal.cv` cut version from
    /// `Prepared8922a::chip_version()` (`CHIP_CAV` raises the
    /// reference). Values are field values in the crate's `modify32`
    /// convention (the consumer shifts them into `mask`).
    pub(super) fn visit(
        &self,
        ant_gain_offset: i16,
        cv: u8,
        mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pack = |b: &[i8]| u32::from_le_bytes([b[0] as u8, b[1] as u8, b[2] as u8, b[3] as u8]);
        // rtw89_phy_set_txpwr_byrate_be.
        for (i, w) in self.byrate_words().iter().enumerate() {
            emit(R_BE_PWR_BY_RATE + 4 * i as u32, u32::MAX, *w)?;
        }
        // rtw89_phy_set_txpwr_offset_be.
        let mut offset = 0u32;
        for (i, &v) in self.offset.iter().enumerate() {
            // Linux pack order: CCK, OFDM, HT, VHT, HE, EHT, DLRU_HE,
            // DLRU_EHT (rate_offset_indexes 4, 3, 2, 1, 0, 7, 6, 5).
            let idx = [4usize, 3, 2, 1, 0, 7, 6, 5][i];
            offset |= (v as u8 as u32 & 0xf) << (4 * idx);
        }
        emit(R_BE_PWR_RATE_OFST_CTRL, u32::MAX, offset)?;
        // rtw8922a_set_tx_shape: OFDM triangular bit only.
        emit(PHY + R_BEDGE3, B_BEDGE_CFG, u32::from(self.shape[1] != 0))?;
        // rtw89_phy_set_txpwr_limit_be.
        for (p, page) in self.limit.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_BE_PWR_LMT + 76 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        // rtw89_phy_set_txpwr_limit_ru_be.
        for (p, page) in self.ru.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_BE_PWR_RULMT_START + 80 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        // rtw8922a_set_txpwr_diff.
        let mag = ant_gain_offset.saturating_abs();
        let mut pwr_ref: i16 = if cv == CHIP_CAV { 16 } else { 0 };
        pwr_ref <<= 2;
        let pwr_ref_ofst = pwr_ref - bb_to_rf(mag);
        let (dec_a, dec_b) = if ant_gain_offset > 0 {
            (pwr_ref, pwr_ref_ofst)
        } else {
            (pwr_ref_ofst, pwr_ref)
        };
        let tssi_ofst = mag + TSSI_K_BASE;
        let (k_a, k_b) = if ant_gain_offset > 0 {
            (TSSI_K_BASE, tssi_ofst)
        } else {
            (tssi_ofst, TSSI_K_BASE)
        };
        for (path_ofst, dec, k) in [(0u32, dec_a, k_a), (0x100, dec_b, k_b)] {
            emit(
                PHY + R_TXAGC_REF_DBM_P0 + path_ofst,
                B_TXAGC_OFDM_REF_DBM_P0,
                dec as u32,
            )?;
            emit(
                PHY + R_TXAGC_REF_DBM_P0 + path_ofst,
                B_TXAGC_CCK_REF_DBM_P0,
                dec as u32,
            )?;
            emit(PHY + R_TSSI_K_P0 + path_ofst, B_TSSI_K_OFDM_P0, k as u32)?;
        }
        // rtw8922a_set_txpwr_ref.
        emit(R_BE_PWR_REF_CTRL, B_BE_PWR_REF_CTRL_OFDM, 0)?;
        emit(R_BE_PWR_REF_CTRL, B_BE_PWR_REF_CTRL_CCK, 0)?;
        // rtw8922a_set_txpwr_sar_diff (PHY_0): no SAR source,
        // `mac_to_rf(63)` = 126 on both paths.
        let sar_rf = mac_to_rf(SAR_MAC_MAX) as u32;
        emit(PHY + R_P0_TXPWRB_BE, B_TXPWRB_MAX_BE, sar_rf)?;
        emit(PHY + R_P1_TXPWRB_BE, B_TXPWRB_MAX_BE, sar_rf)?;
        Ok(())
    }

    /// `rtw8922a_set_txpwr_ctrl` = `rtw8922a_set_txpwr_ref(PHY_0)`
    /// only: phy.c `rtw89_phy_dm_init` runs it once at init. The
    /// landed [`Self::visit`] also ends with it.
    pub(super) fn visit_ctrl(
        mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        emit(R_BE_PWR_REF_CTRL, B_BE_PWR_REF_CTRL_OFDM, 0)?;
        emit(R_BE_PWR_REF_CTRL, B_BE_PWR_REF_CTRL_CCK, 0)?;
        Ok(())
    }
}

/// `rtw8922a_tssi_reset` (rtw8922a.c:1961..1978), non-MLO arm
/// (single-link; the `MLO_1_PLUS_1_1RF` branch is the MLO lane's):
/// pulse `R_TXPWR_RSTA` then `R_TXPWR_RSTB` 0 -> 1. The caller runs
/// it after RX-path selection (`rtw8922a_ctrl_rx_path_tmac`).
/// (address, mask, value) in the crate's `modify32` convention,
/// BE PHY window (0x20000 + CR).
const fn tssi_reset_program() -> [(u32, u32, u32); 4] {
    [
        (PHY + R_TXPWR_RSTA, B_TXPWR_RSTA, 0),
        (PHY + R_TXPWR_RSTA, B_TXPWR_RSTA, 1),
        (PHY + R_TXPWR_RSTB, B_TXPWR_RSTB, 0),
        (PHY + R_TXPWR_RSTB, B_TXPWR_RSTB, 1),
    ]
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_power_be/tests.rs"]
mod tests;
