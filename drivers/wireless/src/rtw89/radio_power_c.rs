// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C per-channel TX power program (`rtw8852c_set_txpwr`, PHY_0)
//! built only from the container's firmware TXPWR elements.
//!
//! Selection is fw.c `rtw89_fw_recognize_txpwr_from_elm`: elements whose
//! `aid` differs from `hal.aid` (0 on AX) never reach this module
//! (`radio_assets` keeps aid 0 only); an element whose `rfe_type` equals
//! the efuse RFE is taken (the last one wins if several match); a default
//! (`RTW89_TXPWR_CONF_DFLT_RFE_TYPE` = 0) element is taken only while the
//! stored configuration is unset or itself default, so the last default
//! wins absent an exact match. Entries are fw.c `rtw89_fw_load_txpwr_*`:
//! an entry wider than the Linux struct is accepted only with an all-zero
//! extension, invalid entries are skipped, later entries overwrite.
//!
//! The program is phy.c `rtw89_phy_set_txpwr_byrate_ax`,
//! `rtw89_phy_set_txpwr_offset_ax`, rtw8852c.c `rtw8852c_set_tx_shape`,
//! phy.c `rtw89_phy_set_txpwr_limit_ax`, `rtw89_phy_set_txpwr_limit_ru_ax`,
//! rtw8852c.c `rtw8852c_set_txpwr_diff` and `rtw8852c_set_txpwr_sar_diff`
//! for the Linux default regulatory state this owner can assert: regd
//! `RTW89_WW` (no country programmed), no SAR source
//! (`RTW89_SAR_TXPWR_MAC_MAX`), no antenna-gain (DAG) tables, no 6GHz TPE.
//! RTL8852C has no static `rtw8852c_table.c` copy in NARF, so a container
//! without the needed elements is refused rather than defaulted.
//!
//! 6GHz (`Plan::from_elements_6ghz`) is the same program for a typed 6GHz
//! profile under an explicit regd.c 6GHz context (`SixGhzPower`): the
//! country's `txpwr_regd[RTW89_BAND_6G]` from the container's REGD element
//! (fw.c `rtw89_recognize_regd_from_elm`; NARF carries no static
//! `rtw89_regd_map`, so a container without one admits no 6GHz), the
//! `reg_6ghz_power` type of the BSS and, for Standard Power, the TPE
//! constraint (`rtw89_phy_get_tpe_constraint`). TXPWR_LMT_6GHZ /
//! LMT_RU_6GHZ are read as phy.c `rtw89_phy_read_txpwr_limit{,_ru}` for
//! `RTW89_BAND_6G` (`[regd][reg6]`, falling back to `[WW][DFLT]` when 0).
//!
//! This is register configuration only: it makes no conducted-power,
//! regulatory or SAR claim for any board.
use super::operating_channel_c::{Band, Profile, Width};
use super::radio_assets::{Assets, Element};
use super::rfk::Error;

/// `RTW89_FW_ELEMENT_ID_*`.
pub(super) const ID_BYRATE: u32 = 9;
pub(super) const ID_LMT_2GHZ: u32 = 10;
pub(super) const ID_LMT_5GHZ: u32 = 11;
pub(super) const ID_LMT_6GHZ: u32 = 12;
pub(super) const ID_LMT_RU_2GHZ: u32 = 13;
pub(super) const ID_LMT_RU_5GHZ: u32 = 14;
pub(super) const ID_LMT_RU_6GHZ: u32 = 15;
pub(super) const ID_TX_SHAPE_LMT: u32 = 16;
pub(super) const ID_REGD: u32 = 20;
/// `RTW89_WW`.
pub(super) const WW: u8 = 0;
/// `RTW89_REGD_NUM`, `RTW89_NTX_NUM`, `RTW89_BF_NUM`, `RTW89_RS_LMT_NUM`,
/// `RTW89_RU_NUM`, `RTW89_BAND_NUM`, `RTW89_BYR_BW_NUM`,
/// `NUM_OF_RTW89_REG_6GHZ_POWER`.
pub(super) const REGD_NUM: u8 = 16;
pub(super) const NTX_NUM: u8 = 2;
pub(super) const BF_NUM: u8 = 2;
pub(super) const RS_LMT_NUM: u8 = 3;
pub(super) const RU_NUM: u8 = 8;
pub(super) const BAND_NUM: u8 = 3;
pub(super) const BYR_BW_NUM: u8 = 5;
pub(super) const REG_6GHZ_POWER_NUM: u8 = 3;
/// `RTW89_6G_BW_NUM` (`RTW89_CHANNEL_WIDTH_320 + 1`), `RTW89_6G_CH_NUM`.
pub(super) const BW_6G_NUM: u8 = 5;
pub(super) const CH_6G_NUM: u8 = 120;
/// `enum rtw89_regulation_type` members regd.c treats specially.
const ETSI: u8 = 1;
const UK: u8 = 14;
/// `RTW89_REGD_MAX_COUNTRY_NUM` (U8_MAX).
const MAX_COUNTRY_NUM: u32 = 255;
/// `RTW89_MIN_VALID_POWER_CONSTRAINT` (dBm).
pub(super) const MIN_VALID_POWER_CONSTRAINT: i8 = -10;
/// `enum rtw89_rate_section`.
pub(super) const RS_CCK: u8 = 0;
pub(super) const RS_OFDM: u8 = 1;
pub(super) const RS_MCS: u8 = 2;
pub(super) const RS_HEDCM: u8 = 3;
pub(super) const RS_OFFSET: u8 = 4;
/// `RTW89_SAR_TXPWR_MAC_MAX` (no SAR source) and `txpwr_factor_rf - mac`.
pub(super) const SAR_MAC_MAX: i8 = 63;

/// MAC CRs (`R_AX_PWR_*`) and PHY CRs (NARF PHY window = 0x10000 + CR).
const R_AX_PWR_RATE_OFST_CTRL: u32 = 0xd204;
const R_AX_PWR_BY_RATE: u32 = 0xd2c0;
const R_AX_PWR_LMT: u32 = 0xd2ec;
const R_AX_PWR_RU_LMT: u32 = 0xd33c;
const R_AX_BANDEDGE_CFG: u32 = 0xd94c;
const PHY: u32 = 0x1_0000;

/// One selected `struct rtw89_txpwr_conf`. Shared with the BE plan,
/// which iterates the same selected configuration.
#[derive(Clone, Copy)]
pub(super) struct Conf<'a> {
    rfe: u8,
    size: usize,
    data: &'a [u8],
}

impl<'a> Conf<'a> {
    /// `rtw89_for_each_in_txpwr_conf` + `__fw_txpwr_entry_acceptable`:
    /// yields the first `known` bytes (zero padded) of each acceptable entry.
    /// Shared with the BE plan, which iterates the same fw.c entries.
    pub(super) fn entries(self, known: usize) -> impl Iterator<Item = [u8; 16]> + 'a {
        self.data.chunks_exact(self.size).filter_map(move |e| {
            if e.len() > known && e[known..].iter().any(|&v| v != 0) {
                return None;
            }
            let mut out = [0; 16];
            let n = e.len().min(known);
            out[..n].copy_from_slice(&e[..n]);
            Some(out)
        })
    }
}

/// fw.c `rtw89_fw_recognize_txpwr_from_elm` over the container order.
/// Malformed headers (size inconsistent with `num_ents * ent_sz`) fail
/// closed instead of being iterated. Shared with the BE plan
/// (`radio_power_be`), which selects the same fw.c elements.
pub(super) fn select(elements: &[Element], id: u32, rfe: u8) -> Result<Option<Conf<'_>>, Error> {
    let mut conf: Option<Conf<'_>> = None;
    for elm in elements.iter().filter(|e| e.id == id) {
        let h = elm.bytes.get(..8).ok_or(Error::Table)?;
        let size = usize::from(h[3]);
        let n = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if size == 0
            || size > 16
            || n.checked_mul(size).and_then(|v| v.checked_add(8)) != Some(elm.bytes.len())
        {
            return Err(Error::Table);
        }
        let elm_rfe = h[2];
        // `RTW89_TXPWR_CONF_DFLT_RFE_TYPE` = 0.
        if elm_rfe == rfe || (elm_rfe == 0 && conf.is_none_or(|c| c.rfe == 0)) {
            conf = Some(Conf {
                rfe: elm_rfe,
                size,
                data: &elm.bytes[8..],
            });
        }
    }
    Ok(conf)
}

/// phy.c `rtw89_channel_to_idx` (unknown channels map to 0 as Linux
/// after its warning); 6GHz is `rtw89_channel_6g_to_idx`.
fn channel_to_idx(band: Band, channel: u8) -> u8 {
    if band == Band::Ghz6 {
        return match channel {
            1..=29 => (channel - 1) / 2,
            33..=61 => (channel - 3) / 2,
            65..=93 => (channel - 5) / 2,
            97..=125 => (channel - 7) / 2,
            129..=157 => (channel - 9) / 2,
            161..=189 => (channel - 11) / 2,
            193..=221 => (channel - 13) / 2,
            225..=253 => (channel - 15) / 2,
            _ => 0,
        };
    }
    match channel {
        1..=14 => channel - 1,
        36..=64 => (channel - 36) / 2,
        100..=144 => (channel - 100) / 2 + 15,
        149..=177 => (channel - 149) / 2 + 38,
        _ => 0,
    }
}

/// `u8 ch` arithmetic as in phy.c (`ch - 2` etc. truncated to u8).
fn offset(ch: u8, delta: i16) -> u8 {
    (i16::from(ch) + delta) as u8
}

/// `rtw89_phy_txpwr_rf_to_mac` (factor rf 2, mac 1: arithmetic >> 1).
/// Shared with the BE plan: 8922A carries the same factors
/// (`chip_8922a::{TXPWR_FACTOR_BB, TXPWR_FACTOR_RF, TXPWR_FACTOR_MAC}`
/// = 3/2/1).
pub(super) fn rf_to_mac(v: i8) -> i8 {
    v >> 1
}

/// The regd.c 6GHz power context of one 6GHz plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SixGhzPower {
    /// `rtw89_regd_get(rtwdev, RTW89_BAND_6G)` (UK follows ETSI).
    regd: u8,
    /// `enum rtw89_reg_6ghz_power` (VLP 0 = DFLT, LPI 1, STD 2).
    power: u8,
}

impl SixGhzPower {
    /// regd.c 6GHz policy for `country` (the host regulatory alpha2) and
    /// the AP power type (`None` = `IEEE80211_REG_UNSET_AP`), as Linux
    /// applies it on a PCIe device without the rtw89 ACPI DSM functions
    /// (every `rtw89_acpi_evaluate_dsm` fails): `rtw89_regd_setup_6ghz`
    /// allows 6GHz, `block_6ghz`/`block_6ghz_sp` stay clear and
    /// `rtw89_regd_setup_policy_6ghz_vlp` blocks VLP for US and CA.
    ///
    /// * The map is the last REGD element with at most
    ///   `RTW89_REGD_MAX_COUNTRY_NUM` entries (`rtw89_regd_entcpy`: an
    ///   out-of-range rule reads as `RTW89_NA`); without one, 6GHz is
    ///   refused (`Table`), since NARF has no static `rtw89_regd_map`.
    /// * `rtw89_regd_find_reg_by_name`: an unknown country is
    ///   `rtw89_ww_regd`, whose index is `RTW89_REGD_MAX_COUNTRY_NUM`, so
    ///   `regd_is_6ghz_blocked` disables every 6GHz channel (`Policy`);
    ///   a 6GHz rule of `RTW89_NA` is `regd_is_6ghz_not_applicable`.
    /// * `rtw89_reg_6ghz_power_recalc`: VLP/LPI/SP map to
    ///   `RTW89_REG_6GHZ_POWER_{VLP,LPI,STD}`, an unset type to DFLT
    ///   (never blocked); a blocked type is `-EINVAL` (`Policy`).
    pub(super) fn new(
        elements: &[Element],
        country: [u8; 2],
        ap: Option<narf_wireless::reg::PowerType6Ghz>,
    ) -> Result<Self, Error> {
        use narf_wireless::reg::PowerType6Ghz;
        let mut map: Option<(usize, &[u8])> = None;
        for elm in elements.iter().filter(|e| e.id == ID_REGD) {
            let h = elm.bytes.get(..8).ok_or(Error::Table)?;
            let size = usize::from(h[3]);
            let n = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            if n > MAX_COUNTRY_NUM {
                // "regd element ignore and take another/common".
                continue;
            }
            if size == 0
                || (n as usize)
                    .checked_mul(size)
                    .and_then(|v| v.checked_add(8))
                    .is_none_or(|v| v > elm.bytes.len())
            {
                return Err(Error::Table);
            }
            map = Some((size, &elm.bytes[8..8 + n as usize * size]));
        }
        let (size, entries) = map.ok_or(Error::Table)?;
        let rule = entries
            .chunks_exact(size)
            .find(|e| e.len() >= 2 && e[..2] == country)
            .ok_or(Error::Policy)?
            // `rule_6ghz` defaults to RTW89_NA when the entry is shorter.
            .get(4)
            .copied()
            .unwrap_or(NA);
        if rule >= REGD_NUM || rule == NA {
            return Err(Error::Policy);
        }
        let regd = if rule == UK { ETSI } else { rule };
        let power = match ap {
            Some(PowerType6Ghz::Vlp) if country == *b"US" || country == *b"CA" => {
                return Err(Error::Policy);
            }
            Some(PowerType6Ghz::Vlp) | None => 0,
            Some(PowerType6Ghz::Lpi) => 1,
            Some(PowerType6Ghz::Sp) => 2,
        };
        Ok(Self { regd, power })
    }
    pub(super) fn regd(self) -> u8 {
        self.regd
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test(regd: u8, power: u8) -> Self {
        Self { regd, power }
    }
    pub(super) fn power(self) -> u8 {
        self.power
    }
}

/// `RTW89_NA`.
const NA: u8 = 4;

/// phy.c `rtw89_phy_get_tpe_constraint` for a valid 6GHz TPE (regd.c
/// constraint in dBm): `rtw89_phy_txpwr_dbm_without_tolerance` then
/// `rtw89_phy_txpwr_dbm_to_mac` (factor 1, clamped to -64..63). Without
/// a TPE it is `dbm_to_mac(S8_MAX)` = 63, the existing SAR-free bound.
/// Shared with the BE plan (same phy.c function reads both gens).
pub(super) fn tpe_mac(constraint: Option<i8>) -> i8 {
    let Some(dbm) = constraint else {
        return SAR_MAC_MAX;
    };
    let dbm = if dbm <= 0 { dbm.saturating_sub(2) } else { dbm };
    (i16::from(dbm) << 1).clamp(-64, 63) as i8
}

/// The selected per-band configurations. Shared with the BE plan
/// (`radio_power_be`): phy.c `rtw89_phy_read_txpwr_limit{,_ru}` is
/// generation-independent, so the BE limit/RU pages read through the
/// same rules with BE page geometry.
pub(super) struct Rules<'a> {
    band: Band,
    lmt: Conf<'a>,
    ru: Conf<'a>,
    /// 6GHz only: the regd.c power context.
    six: Option<SixGhzPower>,
    /// `rtw89_phy_get_tpe_constraint` in MAC units (63 without a TPE).
    cstr: i8,
}

impl<'a> Rules<'a> {
    /// Select the band's TXPWR_LMT / LMT_RU configurations for `rfe`
    /// (fw.c `rtw89_fw_recognize_txpwr_from_elm`); `six` is the 6GHz
    /// regd.c context with its TPE constraint, `None` off 6GHz.
    pub(super) fn for_channel(
        elements: &'a [Element],
        rfe: u8,
        band: Band,
        six: Option<(SixGhzPower, Option<i8>)>,
    ) -> Result<Rules<'a>, Error> {
        let (lmt_id, ru_id) = match band {
            Band::Ghz2 => (ID_LMT_2GHZ, ID_LMT_RU_2GHZ),
            Band::Ghz5 => (ID_LMT_5GHZ, ID_LMT_RU_5GHZ),
            Band::Ghz6 => (ID_LMT_6GHZ, ID_LMT_RU_6GHZ),
        };
        Ok(Self {
            band,
            lmt: select(elements, lmt_id, rfe)?.ok_or(Error::Table)?,
            ru: select(elements, ru_id, rfe)?.ok_or(Error::Table)?,
            six: six.map(|(p, _)| p),
            cstr: tpe_mac(six.and_then(|(_, t)| t)),
        })
    }
    /// Channel count of these rules' band (2.4GHz: 14; 5GHz: 53;
    /// 6GHz: `RTW89_6G_CH_NUM`).
    fn ch_num(&self) -> u8 {
        match self.band {
            Band::Ghz2 => 14,
            Band::Ghz5 => 53,
            Band::Ghz6 => CH_6G_NUM,
        }
    }
    fn bw_num(&self) -> u8 {
        match self.band {
            Band::Ghz2 => 2,
            Band::Ghz5 => 4,
            Band::Ghz6 => BW_6G_NUM,
        }
    }
    /// phy.c `rtw89_phy_read_txpwr_limit` without DAG or SAR:
    /// `min3(rf_to_mac(lmt), 63, cstr)`; 2.4/5GHz read regd WW (no
    /// country, no TPE), 6GHz `[regd][reg6]` else `[WW][DFLT]`.
    /// Shared with the BE plan (same phy.c reader feeds the BE pages).
    pub(super) fn limit(&self, bw: u8, ntx: u8, rs: u8, bf: u8, ch: u8) -> i8 {
        if bw >= self.bw_num() {
            return 0;
        }
        let idx = channel_to_idx(self.band, ch);
        let (ch_num, bw_num) = (self.ch_num(), self.bw_num());
        if let Some(six) = self.six {
            let (mut own, mut ww) = (0i8, 0i8);
            for e in self.lmt.entries(8) {
                // fw_txpwr_lmt_6ghz_entry_valid.
                if e[0] >= bw_num
                    || e[1] >= NTX_NUM
                    || e[2] >= RS_LMT_NUM
                    || e[3] >= BF_NUM
                    || e[4] >= REGD_NUM
                    || e[5] >= REG_6GHZ_POWER_NUM
                    || e[6] >= ch_num
                {
                    continue;
                }
                if (e[0], e[1], e[2], e[3], e[6]) != (bw, ntx, rs, bf, idx) {
                    continue;
                }
                if (e[4], e[5]) == (six.regd, six.power) {
                    own = e[7] as i8;
                }
                if (e[4], e[5]) == (WW, 0) {
                    ww = e[7] as i8;
                }
            }
            let v = if own != 0 { own } else { ww };
            return rf_to_mac(v).min(SAR_MAC_MAX).min(self.cstr);
        }
        let mut v = 0i8;
        for e in self.lmt.entries(7) {
            // fw_txpwr_lmt_{2,5}ghz_entry_valid.
            if e[0] >= bw_num
                || e[1] >= NTX_NUM
                || e[2] >= RS_LMT_NUM
                || e[3] >= BF_NUM
                || e[4] >= REGD_NUM
                || e[5] >= ch_num
            {
                continue;
            }
            if e[0] == bw && e[1] == ntx && e[2] == rs && e[3] == bf && e[4] == WW && e[5] == idx {
                v = e[6] as i8;
            }
        }
        rf_to_mac(v).min(SAR_MAC_MAX)
    }
    /// `[nonbf, bf]` limits for one (bw, rs, ch). Shared with the BE
    /// plan (same phy.c reader feeds the BE pages).
    pub(super) fn limit_bf(&self, bw: u8, ntx: u8, rs: u8, ch: u8) -> [i8; 2] {
        [
            self.limit(bw, ntx, rs, 0, ch),
            self.limit(bw, ntx, rs, 1, ch),
        ]
    }
    /// phy.c `rtw89_phy_read_txpwr_limit_ru` (same default state).
    /// Shared with the BE plan (same phy.c reader feeds the BE RU pages).
    pub(super) fn limit_ru(&self, ru: u8, ntx: u8, ch: u8) -> i8 {
        let idx = channel_to_idx(self.band, ch);
        let ch_num = self.ch_num();
        if let Some(six) = self.six {
            let (mut own, mut ww) = (0i8, 0i8);
            for e in self.ru.entries(6) {
                // fw_txpwr_lmt_ru_6ghz_entry_valid.
                if e[0] >= RU_NUM
                    || e[1] >= NTX_NUM
                    || e[2] >= REGD_NUM
                    || e[3] >= REG_6GHZ_POWER_NUM
                    || e[4] >= ch_num
                {
                    continue;
                }
                if (e[0], e[1], e[4]) != (ru, ntx, idx) {
                    continue;
                }
                if (e[2], e[3]) == (six.regd, six.power) {
                    own = e[5] as i8;
                }
                if (e[2], e[3]) == (WW, 0) {
                    ww = e[5] as i8;
                }
            }
            let v = if own != 0 { own } else { ww };
            return rf_to_mac(v).min(SAR_MAC_MAX).min(self.cstr);
        }
        let mut v = 0i8;
        for e in self.ru.entries(5) {
            // fw_txpwr_lmt_ru_{2,5}ghz_entry_valid.
            if e[0] >= RU_NUM || e[1] >= NTX_NUM || e[2] >= REGD_NUM || e[3] >= ch_num {
                continue;
            }
            if e[0] == ru && e[1] == ntx && e[2] == WW && e[3] == idx {
                v = e[4] as i8;
            }
        }
        rf_to_mac(v).min(SAR_MAC_MAX)
    }
    /// phy.c `rtw89_phy_fill_txpwr_limit_{20,40,80,160}m_ax` for one ntx:
    /// the `struct rtw89_txpwr_limit_ax` page (cck_20m, cck_40m, ofdm,
    /// mcs_20m[8], mcs_40m[4], mcs_80m[2], mcs_160m, mcs_40m_0p5,
    /// mcs_40m_2p5; each [nonbf, bf]).
    fn page(&self, profile: Profile, ntx: u8) -> [i8; 40] {
        let mut page = [0i8; 40];
        let ch = profile.center();
        let pri = profile.primary();
        let mut put = |at: usize, v: [i8; 2]| page[at..at + 2].copy_from_slice(&v);
        let mcs = |bw: u8, d: i16| self.limit_bf(bw, ntx, RS_MCS, offset(ch, d));
        let min2 = |a: [i8; 2], b: [i8; 2]| [a[0].min(b[0]), a[1].min(b[1])];
        const CCK20: usize = 0;
        const CCK40: usize = 2;
        const OFDM: usize = 4;
        const MCS20: usize = 6;
        const MCS40: usize = 22;
        const MCS80: usize = 30;
        const MCS160: usize = 34;
        const P0P5: usize = 36;
        const P2P5: usize = 38;
        match profile.width() {
            Width::Mhz20 => {
                put(CCK20, self.limit_bf(0, ntx, RS_CCK, ch));
                put(CCK40, self.limit_bf(1, ntx, RS_CCK, ch));
                put(OFDM, self.limit_bf(0, ntx, RS_OFDM, ch));
                put(MCS20, mcs(0, 0));
            }
            Width::Mhz40 => {
                put(CCK20, self.limit_bf(0, ntx, RS_CCK, offset(ch, -2)));
                put(CCK40, self.limit_bf(1, ntx, RS_CCK, ch));
                put(OFDM, self.limit_bf(0, ntx, RS_OFDM, pri));
                put(MCS20, mcs(0, -2));
                put(MCS20 + 2, mcs(0, 2));
                put(MCS40, mcs(1, 0));
            }
            Width::Mhz80 => {
                put(OFDM, self.limit_bf(0, ntx, RS_OFDM, pri));
                for (i, d) in [-6, -2, 2, 6].into_iter().enumerate() {
                    put(MCS20 + 2 * i, mcs(0, d));
                }
                put(MCS40, mcs(1, -4));
                put(MCS40 + 2, mcs(1, 4));
                put(MCS80, mcs(2, 0));
                put(P0P5, min2(mcs(1, -4), mcs(1, 4)));
            }
            Width::Mhz160 => {
                put(OFDM, self.limit_bf(0, ntx, RS_OFDM, pri));
                for (i, d) in [-14, -10, -6, -2, 2, 6, 10, 14].into_iter().enumerate() {
                    put(MCS20 + 2 * i, mcs(0, d));
                }
                for (i, d) in [-12, -4, 4, 12].into_iter().enumerate() {
                    put(MCS40 + 2 * i, mcs(1, d));
                }
                put(MCS80, mcs(2, -8));
                put(MCS80 + 2, mcs(2, 8));
                put(MCS160, mcs(3, 0));
                put(P0P5, min2(mcs(1, -4), mcs(1, 4)));
                put(P2P5, min2(mcs(1, -8), mcs(1, 8)));
            }
            // Linux phy.c `rtw89_phy_fill_txpwr_limit_ax` memsets the
            // limit struct to 0 and switches on 20/40/80/160 only: there
            // is no 320MHz fill at cbbddb6, so a 320MHz page stays zero.
            Width::Mhz320 => {}
        }
        page
    }
    /// phy.c `rtw89_phy_fill_txpwr_limit_ru_{20,40,80,160}m_ax`:
    /// `struct rtw89_txpwr_limit_ru_ax` {ru26[8], ru52[8], ru106[8]}.
    fn ru_page(&self, profile: Profile, ntx: u8) -> [i8; 24] {
        let ch = profile.center();
        // Linux phy.c `rtw89_phy_fill_txpwr_limit_ru_ax` switches on
        // 20/40/80/160 only: there is no 320MHz RU fill at cbbddb6, so
        // a 320MHz RU page stays zero (empty deltas fill nothing).
        let deltas: &[i16] = match profile.width() {
            Width::Mhz20 => &[0],
            Width::Mhz40 => &[-2, 2],
            Width::Mhz80 => &[-6, -2, 2, 6],
            Width::Mhz160 => &[-14, -10, -6, -2, 2, 6, 10, 14],
            Width::Mhz320 => &[],
        };
        let mut page = [0i8; 24];
        for ru in 0..3u8 {
            for (i, &d) in deltas.iter().enumerate() {
                page[usize::from(ru) * 8 + i] = self.limit_ru(ru, ntx, offset(ch, d));
            }
        }
        page
    }
}

/// fw.c `rtw89_fw_load_tx_shape_lmt`; core.h `rtw89_get_tx_shape_idx`
/// with `reg6_pwr` = `RTW89_REG_6GHZ_POWER_DFLT` off 6GHz (regd WW
/// there); on 6GHz the 6GHz regd and `reg_6ghz_power`. Returns
/// `[CCK, OFDM]` shape indices. Shared with the BE plan, whose
/// `rtw8922a_set_tx_shape` reads only the OFDM index.
pub(super) fn tx_shape(
    elements: &[Element],
    rfe: u8,
    band: Band,
    six: Option<SixGhzPower>,
) -> Result<[u8; 2], Error> {
    let shape_conf = select(elements, ID_TX_SHAPE_LMT, rfe)?.ok_or(Error::Table)?;
    let b = band as u8;
    let (shape_regd, shape_reg6) = six.map_or((WW, 0), |p| (p.regd, p.power));
    let mut shape = [0u8; 2];
    for e in shape_conf.entries(5) {
        if e[0] >= BAND_NUM || e[1] >= 2 || e[2] >= REGD_NUM || e[4] >= REG_6GHZ_POWER_NUM {
            continue;
        }
        if e[0] == b && e[2] == shape_regd && e[4] == shape_reg6 {
            shape[usize::from(e[1])] = e[3];
        }
    }
    Ok(shape)
}

/// `rtw89_8852c_tssi_dbw_table` (rtw8852c_table.c), FLAT/LOW/MID/HIGH.
const TSSI_DBW: [[u8; 15]; 4] = [
    [0; 15],
    [
        0x1d, 0x1d, 0x1d, 0x2f, 0xf, 0xf, 0x2f, 0x38, 0x28, 0x18, 0x8, 0x8, 0x18, 0x28, 0x38,
    ],
    [
        0x24, 0x24, 0x24, 0x3b, 0x13, 0x13, 0x3b, 0x46, 0x32, 0x1e, 0xa, 0xa, 0x1e, 0x32, 0x46,
    ],
    [
        0x2a, 0x2a, 0x2a, 0x46, 0x17, 0x17, 0x46, 0x53, 0x3b, 0x24, 0xc, 0xc, 0x24, 0x3b, 0x53,
    ],
];
/// phy.c `rtw89_tssi_bandedge_regs_{flat,level}`.
const BANDEDGE_FLAT: [(u32, u32); 15] = [
    (0xd91c, 0xff00_0000),
    (0xd920, 0xff),
    (0xd920, 0xff00),
    (0xd920, 0xff_0000),
    (0xd920, 0xff00_0000),
    (0xd924, 0xff),
    (0xd924, 0xff00),
    (0xd914, 0xff00_0000),
    (0xd918, 0xff),
    (0xd918, 0xff00),
    (0xd918, 0xff_0000),
    (0xd918, 0xff00_0000),
    (0xd91c, 0xff),
    (0xd91c, 0xff00),
    (0xd91c, 0xff_0000),
];
const BANDEDGE_LEVEL: [(u32, u32); 15] = [
    (0xd910, 0xff),
    (0xd910, 0xff00),
    (0xd910, 0xff_0000),
    (0xd910, 0xff00_0000),
    (0xd914, 0xff),
    (0xd914, 0xff00),
    (0xd914, 0xff_0000),
    (0xd908, 0xff),
    (0xd908, 0xff00),
    (0xd908, 0xff_0000),
    (0xd908, 0xff00_0000),
    (0xd90c, 0xff),
    (0xd90c, 0xff00),
    (0xd90c, 0xff_0000),
    (0xd90c, 0xff00_0000),
];
/// phy.c `rtw89_tssi_fastmode_regs_{flat,level}`.
const FASTMODE_FLAT: [(u32, u32); 4] = [
    (0xd934, 0xff_0000),
    (0xd934, 0xff00_0000),
    (0xd938, 0xff),
    (0xd934, 0xff00),
];
const FASTMODE_LEVEL: [(u32, u32); 4] = [
    (0xd930, 0xff_0000),
    (0xd930, 0xff00_0000),
    (0xd934, 0xff),
    (0xd930, 0xff00),
];
/// rtw8852c.c `rtw8852c_bb_set_tx_shape_dfir` parameters and addresses.
const DFIR_FLAT: [u32; 8] = [
    0x003D23FF, 0x0029B354, 0x000FC1C8, 0x00FDB053, 0x00F86F9A, 0x00FAEF92, 0x00FE5FCC, 0x00FFDFF5,
];
const DFIR_SHARP: [u32; 8] = [
    0x003D83FF, 0x002C636A, 0x0013F204, 0x00008090, 0x00F87FB0, 0x00F99F83, 0x00FDBFBA, 0x00003FF5,
];
const DFIR_SHARP_14: [u32; 8] = [
    0x003B13FF, 0x001C42DE, 0x00FDB0AD, 0x00F60F6E, 0x00FD8F92, 0x0002D011, 0x0001C02C, 0x00FFF00A,
];
const DFIR_ADDR: [u32; 8] = [
    0x45BC, 0x45CC, 0x45D0, 0x45D4, 0x45D8, 0x45C0, 0x45C4, 0x45C8,
];

/// Test view: (byrate, offset, limit pages, RU pages, shape).
#[cfg(any(test, feature = "kernel-test"))]
pub(super) type Parts<'a> = (
    &'a [i8; 44],
    &'a [i8; 5],
    &'a [[i8; 40]; 2],
    &'a [[i8; 24]; 2],
    [u8; 2],
);

/// Limit and RU-limit pages per ntx.
type Pages = ([[i8; 40]; 2], [[i8; 24]; 2]);

/// One C TX power program for one typed channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    channel: Profile,
    /// nss0 {CCK 4, OFDM 8, MCS 12, HEDCM 4}, nss1 {MCS 12, HEDCM 4}; MAC units.
    byrate: [i8; 44],
    /// `RTW89_RATE_OFFSET_NUM_AX` (HE, VHT, HT, OFDM, CCK); MAC units.
    offset: [i8; 5],
    /// `struct rtw89_txpwr_limit_ax` per ntx (1TX, 2TX).
    limit: [[i8; 40]; 2],
    /// `struct rtw89_txpwr_limit_ru_ax` per ntx.
    ru: [[i8; 24]; 2],
    /// `rtw89_get_tx_shape_idx(band, RS_CCK / RS_OFDM)`.
    shape: [u8; 2],
    /// 6GHz only: the regd.c power context and the TPE constraint (dBm).
    six: Option<(SixGhzPower, Option<i8>)>,
    /// 6GHz with a TPE only: the limit/RU pages without it, which the
    /// signed record identity binds (a TPE only lowers `min3`).
    untpe: Option<Pages>,
}

impl Plan {
    pub(super) fn channel(&self) -> Profile {
        self.channel
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn parts(&self) -> Parts<'_> {
        (
            &self.byrate,
            &self.offset,
            &self.limit,
            &self.ru,
            self.shape,
        )
    }
    pub(super) fn from_assets(assets: &Assets, rfe: u8, channel: Profile) -> Result<Self, Error> {
        Self::from_elements(assets.elements(), rfe, channel)
    }
    /// 2.4/5GHz under regd WW; a 6GHz profile is refused here (it needs
    /// [`Self::from_elements_6ghz`] and its regulatory context).
    pub(super) fn from_elements(
        elements: &[Element],
        rfe: u8,
        channel: Profile,
    ) -> Result<Self, Error> {
        if channel.band() == Band::Ghz6 {
            return Err(Error::Policy);
        }
        Self::build(elements, rfe, channel, None)
    }
    pub(super) fn from_assets_6ghz(
        assets: &Assets,
        rfe: u8,
        channel: Profile,
        power: SixGhzPower,
        tpe: Option<i8>,
    ) -> Result<Self, Error> {
        Self::from_elements_6ghz(assets.elements(), rfe, channel, power, tpe)
    }
    /// A typed 6GHz profile under `power`; `tpe` is the regd.c intersected
    /// TPE constraint (dBm), valid only for `RTW89_REG_6GHZ_POWER_STD`
    /// (`rtw89_reg_6ghz_tpe_recalc`; below -10 dBm is `-EINVAL`).
    pub(super) fn from_elements_6ghz(
        elements: &[Element],
        rfe: u8,
        channel: Profile,
        power: SixGhzPower,
        tpe: Option<i8>,
    ) -> Result<Self, Error> {
        if channel.band() != Band::Ghz6
            || (tpe.is_some() && power.power != 2)
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
    /// RTL8851B (rtw8851b.c `rtw8851b_set_txpwr`, PHY_0) from the same
    /// firmware TXPWR elements and fw.c selection as RTL8852C: the typed
    /// B 2.4/5GHz 20/40/80MHz profile is restated as the identical C
    /// geometry (center checked) and built by the same generic AX
    /// `rtw89_phy_read_txpwr_{byrate,limit,limit_ru}` rules under regd WW
    /// with no SAR/DAG. RTL8851B's static `rtw89_8851b_dflt_parms`
    /// (rtw8851b_table.c) is not carried, so a container missing BYRATE,
    /// the band's TXPWR_LMT / LMT_RU or TX_SHAPE_LMT is refused. Only
    /// [`Self::visit_51`] may emit the result.
    pub(super) fn from_elements_51(
        elements: &[Element],
        rfe: u8,
        channel: super::operating_channel::Profile,
    ) -> Result<Self, Error> {
        use super::operating_channel::Width as BWidth;
        let primary = channel.primary();
        let c = match (channel.width(), channel.is_5ghz()) {
            (BWidth::Mhz20, false) => Profile::new20(Band::Ghz2, primary),
            (BWidth::Mhz20, true) => Profile::new20(Band::Ghz5, primary),
            (BWidth::Mhz40, false) => Profile::new_2ghz_40(primary, channel.secondary_above()),
            (BWidth::Mhz40, true) => Profile::new_wide(Band::Ghz5, primary, Width::Mhz40),
            (BWidth::Mhz80, true) => Profile::new_wide(Band::Ghz5, primary, Width::Mhz80),
            // rtw8851b.c `support_bandwidths` has no 160MHz (nor 2.4GHz 80).
            _ => None,
        }
        .filter(|c| c.center() == channel.center() && c.primary() == primary)
        .ok_or(Error::Policy)?;
        Self::build(elements, rfe, c, None)
    }
    /// RTL8852A (rtw8852a.c `rtw8852a_set_txpwr`, PHY_0) from the same
    /// firmware TXPWR elements and fw.c selection as RTL8852C: the typed
    /// B 2.4/5GHz 20/40/80MHz profile is restated as the identical C
    /// geometry (center checked) and built by the same generic AX
    /// `rtw89_phy_read_txpwr_{byrate,limit,limit_ru}` rules under regd WW
    /// with no SAR/DAG. `rtw8852a_set_txpwr` has no shape step (and
    /// `.cfg_txrx_path` is NULL), so the plan's `shape` is measured but
    /// never emitted by [`Self::visit_a`]; a container missing BYRATE,
    /// the band's TXPWR_LMT / LMT_RU or TX_SHAPE_LMT is still refused
    /// (the container is the shared firmware file). Only
    /// [`Self::visit_a`] may emit the result.
    pub(super) fn from_elements_a(
        elements: &[Element],
        rfe: u8,
        channel: super::operating_channel::Profile,
    ) -> Result<Self, Error> {
        use super::operating_channel::Width as BWidth;
        let primary = channel.primary();
        let c = match (channel.width(), channel.is_5ghz()) {
            (BWidth::Mhz20, false) => Profile::new20(Band::Ghz2, primary),
            (BWidth::Mhz20, true) => Profile::new20(Band::Ghz5, primary),
            (BWidth::Mhz40, false) => Profile::new_2ghz_40(primary, channel.secondary_above()),
            (BWidth::Mhz40, true) => Profile::new_wide(Band::Ghz5, primary, Width::Mhz40),
            (BWidth::Mhz80, true) => Profile::new_wide(Band::Ghz5, primary, Width::Mhz80),
            // rtw8852a.c `support_bandwidths` has no 160MHz (nor 2.4GHz 80).
            _ => None,
        }
        .filter(|c| c.center() == channel.center() && c.primary() == primary)
        .ok_or(Error::Policy)?;
        Self::build(elements, rfe, c, None)
    }
    /// `rtw8851b_set_txpwr(chan, PHY_0)` then `rtw8851b_set_txpwr_ctrl`
    /// as (absolute address, mask, value) writes in Linux order, for a
    /// [`Self::from_elements_51`] plan. `rf_path_num` 1 bounds phy.c
    /// `rtw89_phy_set_txpwr_byrate_ax` to nss 0 (CCK, OFDM, MCS, HEDCM: 7
    /// words) and `_limit_ax` / `_limit_ru_ax` to the 1TX page;
    /// `rtw8851b_set_tx_shape` is the 2.4GHz `rtw8851b_bb_set_tx_shape_dfir`
    /// (full-word R_TXFIR0.. writes, same tables as B) and the OFDM
    /// `R_DCFO_OPT` B_TXSHAPE_TRIANGULAR_CFG; `rtw8851b_set_txpwr_ref`
    /// writes only the path-A 0x5804/0x5808 reference words.
    pub(super) fn visit_51(
        &self,
        mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pack = |b: &[i8]| u32::from_le_bytes([b[0] as u8, b[1] as u8, b[2] as u8, b[3] as u8]);
        for (i, w) in self.byrate[..28].chunks_exact(4).enumerate() {
            emit(R_AX_PWR_BY_RATE + 4 * i as u32, u32::MAX, pack(w))?;
        }
        let mut offset = 0;
        for (i, &v) in self.offset.iter().enumerate() {
            offset |= (v as u8 as u32 & 0xf) << (4 * i);
        }
        emit(R_AX_PWR_RATE_OFST_CTRL, 0xf_ffff, offset)?;
        if self.channel.band() == Band::Ghz2 {
            let b = super::operating_channel::Profile::new(
                narf_wireless::association::channel::Band::Ghz2,
                self.channel.center(),
            )
            .ok_or(Error::Policy)?;
            for (i, v) in b.cck_fir(self.shape[0]).into_iter().enumerate() {
                emit(PHY + 0x2300 + 4 * i as u32, u32::MAX, v)?;
            }
        }
        emit(PHY + 0x4494, 0x0300_0000, u32::from(self.shape[1]))?;
        for (i, w) in self.limit[0].chunks_exact(4).enumerate() {
            emit(R_AX_PWR_LMT + 4 * i as u32, u32::MAX, pack(w))?;
        }
        for (i, w) in self.ru[0].chunks_exact(4).enumerate() {
            emit(R_AX_PWR_RU_LMT + 4 * i as u32, u32::MAX, pack(w))?;
        }
        reference_51(emit)
    }
    /// `rtw8852a_set_txpwr(chan, PHY_0)` then `rtw8852a_set_txpwr_ctrl`
    /// as (absolute address, mask, value) writes in Linux order, for a
    /// [`Self::from_elements_a`] plan. `rf_path_num` 2 bounds phy.c
    /// `rtw89_phy_set_txpwr_byrate_ax` to nss 0..1 (CCK, OFDM, MCS,
    /// HEDCM: 11 words) and `_limit_ax` / `_limit_ru_ax` to both TX
    /// pages. There is no shape step: `rtw8852a_set_txpwr` is byrate +
    /// offset + limit + limit_ru only (unlike C, which adds
    /// `set_tx_shape`, `set_txpwr_diff` and `set_txpwr_sar_diff`), and
    /// no bandedge/TSSI configuration is emitted.
    /// `rtw8852a_set_txpwr_ref` (ref 0) writes the same words as B's
    /// reference control on both paths (`rtw8852a_bb_cal_txpwr_ref`:
    /// base_cw_0db 0x27, tssi_16dbm_cw 0x12c, so (172 << 18) | (312 << 9)),
    /// so the visit ends with [`super::radio_power::reference`].
    pub(super) fn visit_a(
        &self,
        mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pack = |b: &[i8]| u32::from_le_bytes([b[0] as u8, b[1] as u8, b[2] as u8, b[3] as u8]);
        for (i, w) in self.byrate.chunks_exact(4).enumerate() {
            emit(R_AX_PWR_BY_RATE + 4 * i as u32, u32::MAX, pack(w))?;
        }
        let mut offset = 0;
        for (i, &v) in self.offset.iter().enumerate() {
            offset |= (v as u8 as u32 & 0xf) << (4 * i);
        }
        emit(R_AX_PWR_RATE_OFST_CTRL, 0xf_ffff, offset)?;
        for (p, page) in self.limit.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_AX_PWR_LMT + 40 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        for (p, page) in self.ru.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_AX_PWR_RU_LMT + 24 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        super::radio_power::reference(&mut emit)
    }
    fn build(
        elements: &[Element],
        rfe: u8,
        channel: Profile,
        six: Option<(SixGhzPower, Option<i8>)>,
    ) -> Result<Self, Error> {
        if rfe == 255 {
            return Err(Error::Policy);
        }
        let band = channel.band();
        let byrate = select(elements, ID_BYRATE, rfe)?.ok_or(Error::Table)?;
        let rules = Rules::for_channel(elements, rfe, band, six)?;
        let b = band as u8;

        // fw.c `rtw89_fw_load_txpwr_byrate` into `byr[band][bw]`; AX reads
        // only bw 0 / ofdma 0, CCK always from the 2.4GHz band.
        let mut cck = [0i8; 4];
        let mut ofdm = [0i8; 8];
        let mut mcs = [[0i8; 16]; 2];
        let mut hedcm = [[0i8; 4]; 2];
        let mut offs = [0i8; 8];
        for e in byrate.entries(11) {
            let (eb, nss, rs, shf, len, bw, ofdma) = (e[0], e[1], e[2], e[3], e[4], e[9], e[10]);
            let (shf, len) = (usize::from(shf), usize::from(len));
            // fw_txpwr_byrate_entry_valid.
            let bound = match rs {
                RS_CCK => 4,
                RS_OFDM => 8,
                RS_MCS if nss < 2 && ofdma < 2 => 16,
                RS_HEDCM if nss < 2 && ofdma < 2 => 4,
                RS_OFFSET => 8,
                _ => continue,
            };
            if eb >= BAND_NUM || bw >= BYR_BW_NUM || shf + len > bound {
                continue;
            }
            let wanted = if rs == RS_CCK { 0 } else { b };
            if eb != wanted || bw != 0 || ofdma != 0 {
                continue;
            }
            for i in 0..len {
                let v = if i < 4 { e[5 + i] as i8 } else { 0 };
                let at = shf + i;
                let n = usize::from(nss);
                match rs {
                    RS_CCK => cck[at] = v,
                    RS_OFDM => ofdm[at] = v,
                    RS_MCS => mcs[n][at] = v,
                    RS_HEDCM => hedcm[n][at] = v,
                    _ => offs[at] = v,
                }
            }
        }
        let mut rate = [0i8; 44];
        let mut at = 0;
        for row in [
            &cck[..],
            &ofdm[..],
            &mcs[0][..12],
            &hedcm[0][..],
            &mcs[1][..12],
            &hedcm[1][..],
        ] {
            for &v in row {
                rate[at] = rf_to_mac(v);
                at += 1;
            }
        }
        let mut offset = [0i8; 5];
        for (o, &v) in offset.iter_mut().zip(offs.iter()) {
            *o = rf_to_mac(v);
        }

        let shape = tx_shape(elements, rfe, band, six.map(|(p, _)| p))?;
        Ok(Self {
            channel,
            byrate: rate,
            offset,
            limit: [rules.page(channel, 0), rules.page(channel, 1)],
            ru: [rules.ru_page(channel, 0), rules.ru_page(channel, 1)],
            shape,
            six,
            untpe: None,
        })
    }
    /// 6GHz only: the regd.c context and TPE constraint of this plan.
    pub(super) fn six_ghz(&self) -> Option<(SixGhzPower, Option<i8>)> {
        self.six
    }

    /// Bind the exact power program into a signed-record digest.
    pub fn bind(&self, hash: &mut narf_crypto::sha256::Sha256) {
        // 2.4/5GHz bytes are unchanged. A 6GHz plan binds its regd.c
        // context and the pre-TPE pages (a TPE only lowers `min3`, so the
        // record measured without it covers every TPE-constrained plan).
        if let Some((six, _)) = self.six {
            hash.update(b"C 6GHz fw TXPWR elements;regd6/reg_6ghz_power;no SAR/DAG;TPE excluded");
            hash.update(&[six.regd, six.power]);
        } else {
            hash.update(b"C WW0 fw TXPWR elements;no SAR/DAG/TPE;rtw8852c_set_txpwr");
        }
        hash.update(&[
            self.channel.band() as u8,
            self.channel.primary(),
            self.channel.center(),
            self.channel.width() as u8,
        ]);
        let (limit, ru) = self
            .untpe
            .as_ref()
            .map_or((&self.limit, &self.ru), |(l, r)| (l, r));
        for row in [
            &self.byrate[..],
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

    /// `rtw8852c_set_txpwr(chan, PHY_0)` as (absolute address, mask, value)
    /// writes in Linux order; MAC CRs plain, BB CRs in the 0x10000 window.
    pub(super) fn visit(
        &self,
        mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pack = |b: &[i8]| u32::from_le_bytes([b[0] as u8, b[1] as u8, b[2] as u8, b[3] as u8]);
        // rtw89_phy_set_txpwr_byrate_ax.
        for (i, w) in self.byrate.chunks_exact(4).enumerate() {
            emit(R_AX_PWR_BY_RATE + 4 * i as u32, u32::MAX, pack(w))?;
        }
        // rtw89_phy_set_txpwr_offset_ax.
        let mut offset = 0;
        for (i, &v) in self.offset.iter().enumerate() {
            offset |= (v as u8 as u32 & 0xf) << (4 * i);
        }
        emit(R_AX_PWR_RATE_OFST_CTRL, 0xf_ffff, offset)?;
        // rtw8852c_set_tx_shape.
        if self.channel.band() == Band::Ghz2 {
            let param = if self.channel.center() == 14 {
                &DFIR_SHARP_14
            } else if self.shape[0] == 0 {
                &DFIR_FLAT
            } else {
                &DFIR_SHARP
            };
            for (a, &v) in DFIR_ADDR.iter().zip(param.iter()) {
                emit(PHY + a, 0xff_ffff, v)?;
            }
        }
        // rtw89_phy_tssi_ctrl_set_bandedge_cfg(MAC_0, shape[OFDM]).
        let cfg = self.shape[1];
        if let Some(data) = TSSI_DBW.get(usize::from(cfg)) {
            let (edge, fast) = if cfg == 0 {
                (&BANDEDGE_FLAT, &FASTMODE_FLAT)
            } else {
                (&BANDEDGE_LEVEL, &FASTMODE_LEVEL)
            };
            for (&(a, m), &v) in edge.iter().zip(data.iter()) {
                emit(a, m, u32::from(v))?;
            }
            emit(R_AX_BANDEDGE_CFG, 0xc000_0000, u32::from(cfg))?;
            for &(a, m) in fast {
                emit(a, m, u32::from(data[0]))?;
            }
        }
        emit(PHY + 0x58f8, 1 << 31, 1)?;
        emit(PHY + 0x78f8, 1 << 31, 1)?;
        // rtw89_phy_set_txpwr_limit_ax / _limit_ru_ax.
        for (p, page) in self.limit.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_AX_PWR_LMT + 40 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        for (p, page) in self.ru.iter().enumerate() {
            for (i, w) in page.chunks_exact(4).enumerate() {
                emit(
                    R_AX_PWR_RU_LMT + 24 * p as u32 + 4 * i as u32,
                    u32::MAX,
                    pack(w),
                )?;
            }
        }
        // rtw8852c_set_txpwr_diff: no DAG -> rtw8852c_set_txpwr_ref(0),
        // identical words to B's reference control.
        super::radio_power::reference(&mut emit)?;
        // rtw8852c_set_txpwr_sar_diff(PHY_0): mac_to_rf(63) = 126.
        let sar_rf = (i32::from(SAR_MAC_MAX) << 1) as u32;
        emit(PHY + 0x56cc, 0x1ff, sar_rf)?;
        emit(PHY + 0x76cc, 0x1ff, sar_rf)?;
        Ok(())
    }
}

/// rtw8851b.c `rtw8851b_set_txpwr_ctrl` = `rtw8851b_set_txpwr_ref(PHY_0)`:
/// `R_AX_PWR_RATE_CTRL` B_AX_PWR_REF 0, then the path-A OFDM / CCK words
/// (`0x5800 + 4` / `+ 8`) with `rtw8851b_bb_cal_txpwr_ref(0)` = TSSI 172,
/// PWR 312, REF 0. phy.c `rtw89_phy_dm_init` runs it once at init; the
/// landed `Plan::visit_51` also ends with it.
pub(super) fn reference_51(
    mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>,
) -> Result<(), Error> {
    emit(0xd200, 0x0fff_fc00, 0)?;
    for a in [PHY + 0x5804, PHY + 0x5808] {
        emit(a, 0x07ff_ffff, (172 << 18) | (312 << 9))?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_power_c/tests.rs"]
mod tests;
