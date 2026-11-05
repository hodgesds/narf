// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RA v1 mask computation for 8922A stations.
//!
//! Mirrors Linux `rtw89/phy.c` `rtw89_phy_ra_sta_update`
//! (torvalds/linux @ 05441d6): given a peer's advertised
//! capabilities, compute the 63-bit rate-adaptation mask and
//! the RA parameters that [`super::ra_v1::build_ra_v1`] encodes
//! into the 6-word BE RA v1 H2C command. The encoder exists
//! on main; this module is the computation it was waiting
//! for (station_8922a.rs docs name it as the RA lane's fill).
//!
//! Bit layout of the mask (Linux `phy.h` RA_MASK_*):
//! bits 0..3 CCK, 4..11 OFDM, then per-mode NSS groups at
//! 12 + 12*k (HT), 12 + 12*k (VHT, wider per-group fields),
//! 12 + 12*k (HE), and the EHT layout below. The command
//! splits the mask as w1 = bits 0..31, w2 bits 30..0 =
//! bits 32..62; the v1 upper halves (w4 bits 31..16, w5)
//! stay zero because Linux `rtw89_fw_h2c_ra` writes no
//! upper mask — the computed mask is 63 bits, never more.
//!
//! Deliberate differences from Linux (all fail-closed):
//! - No cfg-mask override (`rtw89_phy_ra_mask_cfg`) and no
//!   rate-pattern override: NARF has no mac80211 bitrate
//!   mask or rate-pattern state to apply. The computed mask
//!   is the capability mask, not a user-clamped one.
//! - No CSI tail (`fixed_csi_rate_en`, `ra_csi_rate_en`,
//!   `csi_*` fields): the CSI update path is a separate
//!   command variant, not the station update.
//! - The 8852C-only GI/LTF special case (160 MHz +
//!   SU/MU 4xHE0.8) is not applied: 8922A always takes the
//!   generic arm, `fix_giltf` = 2XHE08.
//! - NSS counts above 4 and NSS totals of zero are rejected
//!   instead of shifting out of range (Linux would shift a
//!   u64 by >= 64, which is UB in C and a panic in Rust).
//! - `upd_mask` / `upd_bw_nss` are caller inputs, mirroring
//!   Linux `rtw89_phy_ra_update_sta_link`, which sets them
//!   from what changed (rates changed → mask; BW/NSS
//!   changed → BW/NSS) rather than from the capabilities.

use super::{ra_v1, station_8922a::Band};

/// Errors from RA mask computation / command fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// TX NSS outside 1..=4, RX NSS zero, or an EHT NSS
    /// nibble above 4.
    BadNss,
    /// Width outside 20/40/80/160/320 MHz.
    BadWidth,
}

/// `RTW89_RA_MODE_*` (`core.h:4531..4536`).
const MODE_CCK: u8 = 1 << 0;
const MODE_OFDM: u8 = 1 << 1;
const MODE_HT: u8 = 1 << 2;
const MODE_VHT: u8 = 1 << 3;
const MODE_HE: u8 = 1 << 4;
const MODE_EHT: u8 = 1 << 5;

/// `RTW89_CHANNEL_WIDTH_*` (`core.h:954..958`).
const BW_20: u8 = 0;
const BW_40: u8 = 1;
const BW_80: u8 = 2;
const BW_160: u8 = 3;
const BW_320: u8 = 4;

/// `RTW89_GILTF_2XHE08` (`core.h:4559`).
const GILTF_2XHE08: u8 = 3;

/// GENMASK(hi, lo) as a const expression, so the
/// `RA_MASK_*` widths below are computed, not hand-hexed
/// (hand-hexing these was already caught wrong once).
const fn mask_range(hi: u32, lo: u32) -> u64 {
    (1u64 << (hi + 1)) - (1u64 << lo)
}

/// `RA_MASK_*` (`phy.h:31..58`).
const MASK_CCK: u64 = mask_range(3, 0);
const MASK_OFDM: u64 = mask_range(11, 4);
const MASK_SUBCCK: u64 = 0x5;
const MASK_SUBOFDM: u64 = 0x10;
const MASK_HT: [u64; 4] = [
    mask_range(19, 12),
    mask_range(31, 24),
    mask_range(43, 36),
    mask_range(55, 48),
];
const MASK_VHT: [u64; 4] = [
    mask_range(21, 12),
    mask_range(33, 24),
    mask_range(45, 36),
    mask_range(57, 48),
];
const MASK_HE: [u64; 4] = [
    mask_range(23, 12),
    mask_range(35, 24),
    mask_range(47, 36),
    mask_range(59, 48),
];
const MASK_EHT: [u64; 4] = [
    mask_range(27, 12),
    mask_range(43, 28),
    mask_range(59, 44),
    mask_range(62, 60),
];
const MASK_EHT_MCS0_11: [u64; 4] = [
    mask_range(23, 12),
    mask_range(39, 28),
    mask_range(55, 44),
    mask_range(62, 60),
];

/// RSSI floor table (`phy.c` `rtw89_phy_ra_mask_rssi`).
const RSSI_FLOOR_TABLE: [u8; 7] = [30, 44, 48, 52, 56, 60, 100];
/// RSSI floor masks by level (`phy.c`, literal).
const RSSI_FLOOR_MASKS: [u64; 6] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFF0,
    0xFFFF_FFFF_FFFF_EFE0,
    0xFFFF_FFFF_FFFF_CFC0,
    0xFFFF_FFFF_FFFF_8F80,
    0xFFFF_FFFF_FFFF_0F00,
];

/// HT capabilities relevant to RA (`ht_cap`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct HtCaps {
    /// `ht_cap.mcs.rx_mask[4]`.
    pub(super) rx_mask: [u8; 4],
    /// Short-GI 20 MHz.
    pub(super) sgi20: bool,
    /// Short-GI 40 MHz.
    pub(super) sgi40: bool,
    /// RX STBC.
    pub(super) rx_stbc: bool,
    /// LDPC coding.
    pub(super) ldpc: bool,
}

/// VHT capabilities relevant to RA (`vht_cap`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct VhtCaps {
    /// `vht_mcs.rx_mcs_map` (2 bits per NSS, NSS0 first).
    pub(super) rx_mcs_map: u16,
    /// Short-GI 80 MHz.
    pub(super) sgi80: bool,
    /// Short-GI 160 MHz.
    pub(super) sgi160: bool,
    /// RX STBC.
    pub(super) rx_stbc: bool,
    /// RX LDPC.
    pub(super) rx_ldpc: bool,
}

/// HE capabilities relevant to RA (`he_cap`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct HeCaps {
    /// `he_mcs_nss_supp.rx_mcs_80`.
    pub(super) rx_mcs_80: u16,
    /// `he_mcs_nss_supp.rx_mcs_160`.
    pub(super) rx_mcs_160: u16,
    /// `he_mcs_nss_supp.rx_mcs_80p80`.
    pub(super) rx_mcs_80p80: u16,
    /// 80+80 MHz channel-width set in 5 GHz.
    pub(super) has_80p80: bool,
    /// STBC RX under 80 MHz.
    pub(super) stbc_under_80: bool,
    /// LDPC coding in payload.
    pub(super) ldpc_in_payload: bool,
    /// DCM max constellation RX 16-QAM.
    pub(super) dcm_16qam: bool,
    /// Partial-bandwidth extended range.
    pub(super) partial_bw_er: bool,
}

/// EHT capabilities relevant to RA (`eht_cap`).
///
/// Each `bw_*` array holds the raw `rx_tx_max_nss` bytes for
/// one bandwidth; the RX NSS count for NSS group `i` is the
/// low nibble (`IEEE80211_EHT_MCS_NSS_RX` = 0x0f), exactly
/// as Linux `get_eht_mcs_ra_mask` reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct EhtCaps {
    /// `eht_mcs_nss_supp.bw._80.rx_tx_max_nss[3]`.
    pub(super) bw_80: [u8; 3],
    /// `eht_mcs_nss_supp.bw._160.rx_tx_max_nss[3]`.
    pub(super) bw_160: [u8; 3],
    /// `eht_mcs_nss_supp.bw._320.rx_tx_max_nss[3]`.
    pub(super) bw_320: [u8; 3],
    /// `eht_mcs_nss_supp.only_20mhz.rx_tx_max_nss[4]`.
    pub(super) only_20mhz: [u8; 4],
    /// AP interface whose HE width-set advertises 20 MHz
    /// only (Linux `vif->type == AP` + width-set check).
    /// Without this, a 20 MHz link falls through to the
    /// 80 MHz table, as in Linux.
    pub(super) ap_20mhz_only: bool,
}

/// Everything `rtw89_phy_ra_sta_update` reads from the peer
/// and the channel, minus mac80211-only state (cfg mask,
/// rate pattern, CSI) which this module documents as out
/// of scope.
///
/// Legacy `supp_rates` follows Linux's bitmap convention:
/// on 2.4 GHz the bits ARE the mask bits (CCK 0..3, OFDM
/// 4..11); on 5/6 GHz the bitmap is shifted left by 4, so
/// bit 0 of the bitmap lands on OFDM bit 4 of the mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StationCaps {
    /// Operating band.
    pub(super) band: Band,
    /// Operating width in MHz (20/40/80/160/320).
    pub(super) width_mhz: u32,
    /// Legacy supported-rates bitmap (see above).
    pub(super) supp_rates: u16,
    /// HT caps, if the peer advertises HT.
    pub(super) ht: Option<HtCaps>,
    /// VHT caps, if the peer advertises VHT.
    pub(super) vht: Option<VhtCaps>,
    /// HE caps, if the peer advertises HE.
    pub(super) he: Option<HeCaps>,
    /// EHT caps, if the peer advertises EHT. When both HE
    /// and EHT caps are present, EHT wins, as in Linux's
    /// else-if chain.
    pub(super) eht: Option<EhtCaps>,
    /// Peer RX NSS.
    pub(super) rx_nss: u8,
    /// Device TX NSS cap (8922A: 2).
    pub(super) tx_nss: u8,
    /// Average RSSI (raw units; Linux halves it).
    pub(super) rssi: u8,
    /// `hal.no_mcs_12_13` (8922A: true — the EHT
    /// high-rate tables are then the MCS0_11 variants).
    pub(super) no_mcs_12_13: bool,
    /// ER capability from the station link.
    pub(super) er_cap: bool,
}

/// Computed RA parameters, before command encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Computed {
    /// 63-bit rate mask (bits 0..62).
    pub(super) mask: u64,
    /// `RTW89_RA_MODE_*` bitmask.
    pub(super) mode: u8,
    /// `RTW89_CHANNEL_WIDTH_*` code.
    pub(super) bw_cap: u8,
    /// Short-GI for the operating width.
    pub(super) sgi: bool,
    /// STBC capability.
    pub(super) stbc: bool,
    /// LDPC capability.
    pub(super) ldpc: bool,
    /// `min(rx_nss, tx_nss) - 1`.
    pub(super) ss_num: u8,
    /// DCM capability (HE only).
    pub(super) dcm: bool,
    /// ER capability.
    pub(super) er: bool,
    /// Fixed GI/LTF enabled (HE/EHT only).
    pub(super) fix_giltf_en: bool,
    /// Fixed GI/LTF value (HE/EHT: 2XHE08).
    pub(super) fix_giltf: u8,
    /// Partial-bandwidth SU ER (HE only).
    pub(super) partial_bw_er: bool,
}

/// GENMASK(h, 0).
fn genmask_hi(h: u32) -> u64 {
    if h >= 63 {
        u64::MAX
    } else {
        (1u64 << (h + 1)) - 1
    }
}

/// Linux `get_mcs_ra_mask`: 2-bit MCS cap per NSS group,
/// groups at 12 + 12*i. Cap 2 → full `highest` range, cap 1
/// → `highest - gap`, cap 0 → `highest - gap*2`, cap 3
/// (not supported) → nothing.
fn mcs_ra_mask(mcs_map: u16, highest: u32, gap: u32) -> u64 {
    let mut mask = 0u64;
    for i in 0..4 {
        let cap = (mcs_map >> (2 * i)) & 0x3;
        let nss_shift = 12 + 12 * i;
        let top = match cap {
            2 => highest,
            1 => highest - gap,
            0 => highest - gap * 2,
            _ => continue,
        };
        mask |= genmask_hi(top) << nss_shift;
    }
    mask
}

/// Linux `get_he_ra_mask`: 160 MHz uses the 80+80 map when
/// advertised, else the 160 map; every other width uses
/// the 80 map. MCS11 / MCS9 / MCS7.
fn he_ra_mask(he: &HeCaps, width_mhz: u32) -> u64 {
    let map = if width_mhz == 160 {
        if he.has_80p80 {
            he.rx_mcs_80p80
        } else {
            he.rx_mcs_160
        }
    } else {
        he.rx_mcs_80
    };
    mcs_ra_mask(map, 11, 2)
}

/// Linux `get_eht_mcs_ra_mask`: group `i` admits MCS
/// `start_mcs + 2*i` on each of its `nss` streams, at
/// 12 + 16*j. Streams above the 63-bit mask are dropped
/// by the u64 shift, exactly as in Linux, and the later
/// NSS-cap trim removes bit 63 (no EHT table covers it).
fn eht_mcs_ra_mask(max_nss: &[u8], start_mcs: u32, n_nss: usize) -> Result<u64, Error> {
    let mut mask = 0u64;
    for i in 0..n_nss {
        let nss = max_nss[i] & 0x0F;
        if nss == 0 {
            continue;
        }
        if nss > 4 {
            return Err(Error::BadNss);
        }
        let val = genmask_hi(start_mcs + 2 * i as u32);
        for j in 0..nss {
            mask |= val << (12 + 16 * j as u32);
        }
    }
    Ok(mask)
}

/// Linux `get_eht_ra_mask`: bandwidth selects the table;
/// 20 MHz on an AP advertising 20 MHz only uses the
/// 20 MHz-only table with MCS 7/9/11/13, everything else
/// uses MCS 9/11/13.
fn eht_ra_mask(eht: &EhtCaps, width_mhz: u32) -> Result<u64, Error> {
    match width_mhz {
        320 => eht_mcs_ra_mask(&eht.bw_320, 9, 3),
        160 => eht_mcs_ra_mask(&eht.bw_160, 9, 3),
        20 if eht.ap_20mhz_only => eht_mcs_ra_mask(&eht.only_20mhz, 7, 4),
        _ => eht_mcs_ra_mask(&eht.bw_80, 9, 3),
    }
}

/// Linux `rtw89_phy_ra_mask_rssi` with `ratr_state` 0
/// (the value the station-update call site passes, so the
/// +3 floor lift never applies). Note the Linux quirk
/// this replicates: an RSSI at or above the top table
/// entry (100, halved) finds no level, so the level stays
/// 0 and the mask is all-ones, same as a very strong
/// signal. Level is always 0..=5 here (the loop breaks
/// at i = 5 for any halved RSSI below 100).
fn rssi_floor(rssi: u8) -> u64 {
    let rssi = rssi >> 1;
    let mut level = 0usize;
    for (i, threshold) in RSSI_FLOOR_TABLE.iter().enumerate() {
        if rssi < *threshold {
            level = i;
            break;
        }
    }
    RSSI_FLOOR_MASKS[level]
}

/// Linux `rtw89_phy_ra_mask_recover`: if the masked result
/// lost all non-legacy rates, restore them from the backup;
/// if it is entirely zero, restore the legacy rates.
fn recover(mask: u64, bak: u64) -> u64 {
    let mut mask = mask;
    if mask & !(MASK_CCK | MASK_OFDM) == 0 {
        mask |= bak & !(MASK_CCK | MASK_OFDM);
    }
    if mask == 0 {
        mask |= bak & (MASK_CCK | MASK_OFDM);
    }
    mask
}

/// Compute the RA mask and parameters for `caps`.
/// Mirrors `rtw89_phy_ra_sta_update` minus the cfg-mask
/// and rate-pattern overrides (see module docs).
pub(super) fn compute(caps: &StationCaps) -> Result<Computed, Error> {
    if caps.tx_nss == 0 || caps.tx_nss > 4 || caps.rx_nss == 0 {
        return Err(Error::BadNss);
    }
    let bw_cap = match caps.width_mhz {
        20 => BW_20,
        40 => BW_40,
        80 => BW_80,
        160 => BW_160,
        320 => BW_320,
        _ => return Err(Error::BadWidth),
    };
    let mut mask = 0u64;
    let mut mode = 0u8;
    let mut high_masks: &[u64; 4] = &MASK_HT;
    let mut stbc = false;
    let mut ldpc = false;
    let mut fix_giltf_en = false;
    let mut fix_giltf = 0u8;
    let mut dcm = false;
    let mut partial_bw_er = false;

    if let Some(eht) = &caps.eht {
        mode |= MODE_EHT;
        mask |= eht_ra_mask(eht, caps.width_mhz)?;
        high_masks = if caps.no_mcs_12_13 {
            &MASK_EHT_MCS0_11
        } else {
            &MASK_EHT
        };
        fix_giltf_en = true;
        fix_giltf = GILTF_2XHE08;
    } else if let Some(he) = &caps.he {
        mode |= MODE_HE;
        mask |= he_ra_mask(he, caps.width_mhz);
        high_masks = &MASK_HE;
        if he.stbc_under_80 {
            stbc = true;
        }
        if he.ldpc_in_payload {
            ldpc = true;
        }
        fix_giltf_en = true;
        fix_giltf = GILTF_2XHE08;
        dcm = he.dcm_16qam;
        partial_bw_er = he.partial_bw_er;
    } else if let Some(vht) = &caps.vht {
        mode |= MODE_VHT;
        let (highest, gap) = if caps.width_mhz == 20 { (8, 1) } else { (9, 1) };
        mask |= mcs_ra_mask(vht.rx_mcs_map, highest, gap);
        high_masks = &MASK_VHT;
        if vht.rx_stbc {
            stbc = true;
        }
        if vht.rx_ldpc {
            ldpc = true;
        }
    } else if let Some(ht) = &caps.ht {
        mode |= MODE_HT;
        mask |= (ht.rx_mask[0] as u64) << 12
            | (ht.rx_mask[1] as u64) << 24
            | (ht.rx_mask[2] as u64) << 36
            | (ht.rx_mask[3] as u64) << 48;
        high_masks = &MASK_HT;
        if ht.rx_stbc {
            stbc = true;
        }
        if ht.ldpc {
            ldpc = true;
        }
    }

    match caps.band {
        Band::Ghz2 => {
            mask |= caps.supp_rates as u64;
            if caps.supp_rates & 0xF != 0 {
                mode |= MODE_CCK;
            }
            if caps.supp_rates & 0xFF0 != 0 {
                mode |= MODE_OFDM;
            }
        }
        Band::Ghz5 | Band::Ghz6 => {
            mask |= (caps.supp_rates as u64) << 4;
            mode |= MODE_OFDM;
        }
    }

    let bak = mask;
    // Numeric comparison, as Linux writes it: mode >= HT
    // (4) is true for every mode carrying an HT-or-newer
    // bit, false for legacy-only modes (1, 2, 3).
    if mode >= MODE_HT {
        let mut cap = 0u64;
        for i in 0..caps.tx_nss as usize {
            cap |= high_masks[i];
        }
        if mode & MODE_OFDM != 0 {
            cap |= MASK_SUBOFDM;
        }
        if mode & MODE_CCK != 0 {
            cap |= MASK_SUBCCK;
        }
        mask &= cap;
    } else if mode & MODE_OFDM != 0 {
        mask &= MASK_OFDM | MASK_SUBCCK;
    }

    if mode != MODE_CCK {
        mask &= rssi_floor(caps.rssi);
    }
    mask = recover(mask, bak);

    let sgi = match caps.width_mhz {
        160 => caps.vht.map(|v| v.sgi160).unwrap_or(false),
        80 => caps.vht.map(|v| v.sgi80).unwrap_or(false),
        40 => caps.ht.map(|h| h.sgi40).unwrap_or(false),
        _ => caps.ht.map(|h| h.sgi20).unwrap_or(false),
    };
    let ss_num = caps.rx_nss.min(caps.tx_nss) - 1;
    Ok(Computed {
        mask,
        mode,
        bw_cap,
        sgi,
        stbc,
        ldpc,
        ss_num,
        dcm,
        er: caps.er_cap,
        fix_giltf_en,
        fix_giltf,
        partial_bw_er,
    })
}

/// Fill the BE RA v1 command for one station: compute the
/// mask and parameters, then encode them with
/// [`ra_v1::build_ra_v1`].
///
/// `macid` is the station MACID (w0 field, 8 bits);
/// `phy_idx` is the PHY index Linux reports as `band_num`.
/// `upd_mask` / `upd_bw_nss` are the caller's change flags
/// (see module docs); a fresh station update passes both
/// false, and the update path passes them per what changed.
/// CSI fields stay clear: this is the station update, not
/// the CSI variant. The v1 upper mask halves stay zero:
/// Linux writes no upper mask in `rtw89_fw_h2c_ra`.
pub(super) fn build(
    caps: &StationCaps,
    macid: u8,
    phy_idx: u8,
    upd_mask: bool,
    upd_bw_nss: bool,
) -> Result<[u32; 6], Error> {
    let c = compute(caps)?;
    let band = match caps.band {
        Band::Ghz2 => 0,
        Band::Ghz5 => 1,
        Band::Ghz6 => 2,
    };
    let info = ra_v1::RaV1Info {
        is_dis: false,
        mode: c.mode,
        bw_cap: c.bw_cap,
        mac_id: macid,
        dcm: c.dcm,
        er: c.er,
        init_rate_lv: 0,
        upd_all: false,
        sgi: c.sgi,
        ldpc: c.ldpc,
        stbc: c.stbc,
        ss_num: c.ss_num,
        // w0 GILTF: Linux never assigns ra->giltf in the
        // station update (memset zero survives); the fixed
        // GI/LTF lives in w3's fix_giltf fields below.
        giltf: 0,
        upd_bw_nss,
        upd: upd_mask,
        ramask_lo32: c.mask as u32,
        ramask_hi31: (c.mask >> 32) as u32 & 0x7FFF_FFFF,
        bfee_csi_ctl: false,
        band_num: phy_idx,
        ra_csi_rate_en: false,
        fixed_csi_rate_en: false,
        cr_tbl_sel: false,
        fix_giltf_en: c.fix_giltf_en,
        fix_giltf: c.fix_giltf,
        partial_bw_su_er: c.partial_bw_er,
        fixed_csi_rate_l: 0,
        is_noisy: false,
        psra_en: false,
        macid_msb: 0,
        band,
        new_dbgreg: false,
        mode_eht: c.mode,
        bw_eht: c.bw_cap,
        ramask_uhl16: 0,
        ramask_uhh16: 0,
    };
    Ok(ra_v1::build_ra_v1(&info))
}
