// SPDX-License-Identifier: GPL-2.0-or-later
//! BE rate-adaptation H2C command, version 1 (`rtw89_h2c_ra_v1`).
//!
//! Linux `rtw89/fw.h:420..472` (torvalds/linux @ cbbddb6): the v1
//! command is the v0 command (`w0..w3`) plus `w4` and `w5`, packed.
//! The v1 reinterpretation of `w3` bits 15..31 uses the `_V1` names
//! (`PARTIAL_BW_SU_ER`, `FIXED_CSI_RATE_L`, `IS_NOISY`, `PSRA_EN`,
//! `MACID_MSB`, `BAND`, `NEW_DBGREG`); the v0 names for those bits
//! (`FIXED_CSI_MCS_SS_IDX`, `FIXED_CSI_MODE`, `FIXED_CSI_GI_LTF`,
//! `FIXED_CSI_BW`) describe the same bit positions for AX and are NOT
//! used here. `w3` bits 0..14 are shared between v0 and v1.
//!
//! This builder produces the 6 command words; the caller serializes
//! them little-endian behind the 8-byte H2C header (`txrx::H2cBuilder`).
//! The EHT fields (`mode_eht`, `bw_eht`, the upper RA-mask halves)
//! are the v1 extension that the `eht` row will consume — this module
//! only encodes them, it does not enable EHT operation.

/// Rate-adaptation parameters for one station (BE v1 command).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RaV1Info {
    /// W0 bit 0: disable rate adaptation.
    pub(super) is_dis: bool,
    /// W0 bits 5..1: mode (HT/VHT/HE/EHT selector).
    pub(super) mode: u8,
    /// W0 bits 7..6: bandwidth capability.
    pub(super) bw_cap: u8,
    /// W0 bits 15..8: MAC-ID (low 8 bits; high bits in w3).
    pub(super) mac_id: u8,
    /// W0 bit 16: DCM.
    pub(super) dcm: bool,
    /// W0 bit 17: ER (extended range).
    pub(super) er: bool,
    /// W0 bits 19..18: initial rate level.
    pub(super) init_rate_lv: u8,
    /// W0 bit 20: update all.
    pub(super) upd_all: bool,
    /// W0 bit 21: short guard interval.
    pub(super) sgi: bool,
    /// W0 bit 22: LDPC.
    pub(super) ldpc: bool,
    /// W0 bit 23: STBC.
    pub(super) stbc: bool,
    /// W0 bits 26..24: spatial-stream count.
    pub(super) ss_num: u8,
    /// W0 bits 29..27: GI/LTF.
    pub(super) giltf: u8,
    /// W0 bit 30: update bandwidth/NSS mask.
    pub(super) upd_bw_nss: bool,
    /// W0 bit 31: update.
    pub(super) upd: bool,
    /// W1: RA mask, low 32 bits.
    pub(super) ramask_lo32: u32,
    /// W2 bits 30..0: RA mask, high 31 bits.
    pub(super) ramask_hi31: u32,
    /// W2 bit 31: BFEE CSI control.
    pub(super) bfee_csi_ctl: bool,
    /// W3 bits 7..0: band number.
    pub(super) band_num: u8,
    /// W3 bit 8: RA CSI rate enable.
    pub(super) ra_csi_rate_en: bool,
    /// W3 bit 9: fixed CSI rate enable.
    pub(super) fixed_csi_rate_en: bool,
    /// W3 bit 10: CR table select.
    pub(super) cr_tbl_sel: bool,
    /// W3 bit 11: fixed GI/LTF enable.
    pub(super) fix_giltf_en: bool,
    /// W3 bits 14..12: fixed GI/LTF.
    pub(super) fix_giltf: u8,
    /// W3 bit 15 (v1): partial-bandwidth SU ER.
    pub(super) partial_bw_su_er: bool,
    /// W3 bits 23..16 (v1): fixed CSI rate, low part.
    pub(super) fixed_csi_rate_l: u8,
    /// W3 bit 24 (v1): noisy-environment flag.
    pub(super) is_noisy: bool,
    /// W3 bit 25 (v1): PSRA enable.
    pub(super) psra_en: bool,
    /// W3 bits 28..27 (v1): MAC-ID high bits.
    pub(super) macid_msb: u8,
    /// W3 bits 30..29 (v1): band.
    pub(super) band: u8,
    /// W3 bit 31 (v1): new debug register.
    pub(super) new_dbgreg: bool,
    /// W4 bits 6..0 (v1): EHT mode.
    pub(super) mode_eht: u8,
    /// W4 bits 10..8 (v1): EHT bandwidth.
    pub(super) bw_eht: u8,
    /// W4 bits 31..16 (v1): RA mask, upper-high 16 bits.
    pub(super) ramask_uhl16: u16,
    /// W5 bits 15..0 (v1): RA mask, upper-high-high 16 bits.
    pub(super) ramask_uhh16: u16,
}

fn bit(b: bool, shift: u32) -> u32 {
    if b {
        1 << shift
    } else {
        0
    }
}

/// Build the 6-word BE RA v1 command (`fw.h:420..472`).
pub(super) fn build_ra_v1(info: &RaV1Info) -> [u32; 6] {
    let w0 = bit(info.is_dis, 0)
        | ((info.mode as u32 & 0x1F) << 1)
        | ((info.bw_cap as u32 & 0x3) << 6)
        | ((info.mac_id as u32) << 8)
        | bit(info.dcm, 16)
        | bit(info.er, 17)
        | ((info.init_rate_lv as u32 & 0x3) << 18)
        | bit(info.upd_all, 20)
        | bit(info.sgi, 21)
        | bit(info.ldpc, 22)
        | bit(info.stbc, 23)
        | ((info.ss_num as u32 & 0x7) << 24)
        | ((info.giltf as u32 & 0x7) << 27)
        | bit(info.upd_bw_nss, 30)
        | bit(info.upd, 31);
    let w1 = info.ramask_lo32;
    let w2 = (info.ramask_hi31 & 0x7FFF_FFFF) | bit(info.bfee_csi_ctl, 31);
    let w3 = (info.band_num as u32)
        | bit(info.ra_csi_rate_en, 8)
        | bit(info.fixed_csi_rate_en, 9)
        | bit(info.cr_tbl_sel, 10)
        | bit(info.fix_giltf_en, 11)
        | ((info.fix_giltf as u32 & 0x7) << 12)
        | bit(info.partial_bw_su_er, 15)
        | ((info.fixed_csi_rate_l as u32) << 16)
        | bit(info.is_noisy, 24)
        | bit(info.psra_en, 25)
        | ((info.macid_msb as u32 & 0x3) << 27)
        | ((info.band as u32 & 0x3) << 29)
        | bit(info.new_dbgreg, 31);
    let w4 = (info.mode_eht as u32 & 0x7F)
        | ((info.bw_eht as u32 & 0x7) << 8)
        | ((info.ramask_uhl16 as u32) << 16);
    let w5 = info.ramask_uhh16 as u32;
    [w0, w1, w2, w3, w4, w5]
}
