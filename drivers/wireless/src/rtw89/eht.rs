// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8922A EHT operation: width programming and EHT PHY programs.
//!
//! Mirrors Linux `rtw89/rtw8922a.c` (torvalds/linux @ cbbddb6) for the
//! pieces of EHT/320MHz operation that exist independently of a 8922A
//! station owner: the channel-width programming tables
//! (`rtw8922a_set_channel_mac`, `rtw8922a_chan_to_rf18_val`), the BB
//! bandwidth class (`rtw8922a_set_lna_tia_gain`), the EHT arms of
//! `rtw8922a_bb_postinit` and `rtw8922a_cfg_rx_nss_limit`, and the EHT
//! RX CRC counter block. The 8922A station owner exists now
//! (`station_8922a.rs` admission via `prepared_8922a.rs`) and composes
//! the `EhtStation` facet, the MCS/NSS maps, and the TXWD_INFO EHT
//! fields below; the width tables and PHY programs in this module are
//! still fixture-pinned with no production caller yet — the channel
//! programming that would consume them is the remaining step, not a
//! missing owner.
//!
//! Deliberate narrowings, each a grounded absence, not an oversight:
//! - The RFMOD width table has NO 320MHz arm. `rtw8922a_set_channel_mac`
//!   switches on 160/80/40/20-default only, so a 320MHz channel takes
//!   the default arm there. `BE_WMAC_RFMOD_320M` (4) is defined in
//!   `reg.h` but has no user anywhere in the local reference, so no
//!   320MHz RFMOD mapping is claimed here; `rfmod_value` returns
//!   `None` for 320MHz. Whether 320MHz RFMOD goes through a separate
//!   path or is an upstream gap is a follow-up for a reader with the
//!   full `phy.c`/`mac.c`, not a guess to encode.
//! - The TX sub-carrier bitmap (`txsb`) values are NOT encoded: they
//!   come from `rtw89_phy_get_txsb` (`phy.c`), which is not in the
//!   local reference. Only the width-to-RFMOD table and the SIFS
//!   value pairs from `set_channel_mac` are claimed.
//! - EHT MCS/NSS capability maps ARE encoded below (`eht_cap`,
//!   mirroring `rtw89_init_eht_cap` in `core.c` @ 05441d6 — the
//!   sparse-clone reference, which supersedes the step-1 note
//!   that `core.c` was not in the local reference). The
//!   `max_mpdu_len` = 7991 scalar is already carried by
//!   `chip_8922a`.
//! - The TXWD_INFO EHT fields (`BE_TXD_INFO4_SW_EHT_NLTF_SWITCH` /
//!   `SW_EHT_NLTF`, `BE_TXD_INFO7_UL_EHT_USR_PRES` in `txrx.h`) are
//!   encoded by `txrx_be::eht_info_fields` as the EHT contribution
//!   to the TXWD_INFO block (to be OR'd into the complete info
//!   block by the future BE transport fill, which also carries
//!   info0/1/2/4 from Linux's v2 builders); they are not part of
//!   the TXWD body `txrx_be.rs` encodes.
//! - The BB bandwidth class carries no Linux numeric value: the
//!   `RTW89_BB_BW_20_40` / `RTW89_BB_BW_80_160_320` enum lives in a
//!   header outside the local reference, so only the class
//!   distinction (width <= 40MHz vs wider) is modeled.

use super::irq::Regs;
use super::power;

/// EHT operating widths for RTL8922A, in Linux
/// `enum rtw89_channel_width` order for the widths this chip uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Width {
    Mhz20,
    Mhz40,
    Mhz80,
    Mhz160,
    Mhz320,
}

impl Width {
    /// Width in MHz.
    pub(super) const fn mhz(self) -> u32 {
        match self {
            Width::Mhz20 => 20,
            Width::Mhz40 => 40,
            Width::Mhz80 => 80,
            Width::Mhz160 => 160,
            Width::Mhz320 => 320,
        }
    }
}

// ── `rtw8922a_set_channel_mac` width tables ───────────────────────────

/// `R_BE_WMAC_RFMOD` (`reg.h:6625`); the C1 alias is `0x14010`.
pub(super) const R_BE_WMAC_RFMOD: u32 = 0x10010;
/// `B_BE_WMAC_RFMOD_MASK` (`reg.h:6628`): GENMASK(2, 0).
pub(super) const B_BE_WMAC_RFMOD_MASK: u32 = 0x7;
/// `R_BE_TX_SUB_BAND_VALUE` (`reg.h:6648`); the C1 alias is `0x14088`.
pub(super) const R_BE_TX_SUB_BAND_VALUE: u32 = 0x10088;
/// `R_BE_PREBKF_CFG_1` (`reg.h:6823`); the C1 alias is `0x1433C`.
pub(super) const R_BE_PREBKF_CFG_1: u32 = 0x1033C;
/// `B_BE_SIFS_MACTXEN_T1_MASK` (`reg.h:6828`): GENMASK(6, 0).
pub(super) const B_BE_SIFS_MACTXEN_T1_MASK: u32 = 0x7F;
/// `R_BE_MUEDCA_EN` (`reg.h:6869`); the C1 alias is `0x14370`.
pub(super) const R_BE_MUEDCA_EN: u32 = 0x10370;
/// `B_BE_SIFS_MACTXEN_TB_T1_MASK` (`reg.h:6873`): GENMASK(22, 16).
pub(super) const B_BE_SIFS_MACTXEN_TB_T1_MASK: u32 = 0x7F << 16;

/// RFMOD value for a width (`rtw8922a.c:1071..1093`):
/// 20MHz -> 0, 40MHz -> 1, 80MHz -> 2, 160MHz -> 3
/// (`BE_WMAC_RFMOD_20M/40M/80M/160M`, `reg.h:6629..6632`).
/// 320MHz returns `None`: the Linux switch has no 320MHz arm (see the
/// module docs); `BE_WMAC_RFMOD_320M` is defined but unused
/// in-reference, so no value is claimed for it.
pub(super) const fn rfmod_value(width: Width) -> Option<u32> {
    match width {
        Width::Mhz20 => Some(0),
        Width::Mhz40 => Some(1),
        Width::Mhz80 => Some(2),
        Width::Mhz160 => Some(3),
        Width::Mhz320 => None,
    }
}

/// SIFS MACTXEN value pair for a width (`rtw8922a.c:1121..1136`):
/// 40/80/160/320MHz -> (0x41, 0x41); 20MHz -> (0x3f, 0x3e).
/// The first element programs `R_BE_PREBKF_CFG_1` under
/// `B_BE_SIFS_MACTXEN_T1_MASK`; the second programs `R_BE_MUEDCA_EN`
/// under `B_BE_SIFS_MACTXEN_TB_T1_MASK`.
pub(super) const fn sifs_values(width: Width) -> (u32, u32) {
    match width {
        Width::Mhz20 => (0x3F, 0x3E),
        Width::Mhz40 | Width::Mhz80 | Width::Mhz160 | Width::Mhz320 => (0x41, 0x41),
    }
}

// ── `rtw8922a_chan_to_rf18_val` bandwidth field ───────────────────────

/// `RR_CFGCH_BW_V2` (`reg.h:8617`): GENMASK(12, 10).
pub(super) const RR_CFGCH_BW_V2: u32 = 0x7 << 10;

/// Bandwidth code for a width (`rtw8922a.c:2699..2718`):
/// 20MHz -> 0, 40MHz -> 1, 80MHz -> 2, 160MHz -> 3, 320MHz -> 4
/// (`CFGCH_BW_V2_20M/40M/80M/160M/320M`, `reg.h:8618..8622`).
pub(super) const fn cfgch_bw_code(width: Width) -> u32 {
    match width {
        Width::Mhz20 => 0,
        Width::Mhz40 => 1,
        Width::Mhz80 => 2,
        Width::Mhz160 => 3,
        Width::Mhz320 => 4,
    }
}

/// Bandwidth field positioned inside `RR_CFGCH_BW_V2`.
pub(super) const fn cfgch_bw_field(width: Width) -> u32 {
    (cfgch_bw_code(width) << 10) & RR_CFGCH_BW_V2
}

// ── BB bandwidth class ─────────────────────────────────────────────────

/// BB gain-bandwidth class (`rtw8922a_set_lna_tia_gain`,
/// `rtw8922a.c:1330..1331`): widths at or below 40MHz take the narrow
/// class; wider widths take the wide class. Linux numeric values for
/// `RTW89_BB_BW_20_40` / `RTW89_BB_BW_80_160_320` are not in the local
/// reference, so this is a NARF-side distinction, not a transcription.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BbBwClass {
    Narrow20_40,
    Wide80_160_320,
}

/// BB bandwidth class for a width.
pub(super) const fn bb_bw_class(width: Width) -> BbBwClass {
    match width {
        Width::Mhz20 | Width::Mhz40 => BbBwClass::Narrow20_40,
        Width::Mhz80 | Width::Mhz160 | Width::Mhz320 => BbBwClass::Wide80_160_320,
    }
}

// ── EHT PHY programs ───────────────────────────────────────────────────

/// One masked register write: (register, mask, positioned value), in
/// the crate's `modify32` convention — `value` is already shifted into
/// the mask field, and applying it preserves every bit outside `mask`.
pub(super) type ProgramEntry = (u32, u32, u32);

/// `R_SLOPE` (`reg.h:10048`).
pub(super) const R_SLOPE: u32 = 0x6B6C;
/// `B_EHT_RATE_TH` (`reg.h:10049`): GENMASK(31, 28).
pub(super) const B_EHT_RATE_TH: u32 = 0xF << 28;
/// `R_BEDGE` (`reg.h:10059`).
pub(super) const R_BEDGE: u32 = 0x6BFC;
/// `B_EHT_MCS14` (`reg.h:10060`): BIT(31).
pub(super) const B_EHT_MCS14: u32 = 1 << 31;
/// `R_BEDGE2` (`reg.h:10062`).
pub(super) const R_BEDGE2: u32 = 0x6C00;
/// `B_EHT_MCS15` (`reg.h:10063`): BIT(31).
pub(super) const B_EHT_MCS15: u32 = 1 << 31;
/// `R_BEDGE3` (`reg.h:10065`).
pub(super) const R_BEDGE3: u32 = 0x6C04;
/// `B_EHTTB_EN` (`reg.h:10069`): BIT(15).
pub(super) const B_EHTTB_EN: u32 = 1 << 15;

/// EHT arms of `rtw8922a_bb_postinit` (`rtw8922a.c:1829..1834`),
/// in Linux's program order, with field values positioned into their
/// masks: EHT rate threshold 0xA, EHT MCS14 enable, EHT MCS15 enable,
/// EHT trigger-based PPDU disabled (0). The surrounding non-EHT arms
/// of `bb_postinit` (HE/HT/VHT thresholds, SU puncturing, magnitude
/// terms) are not this row's scope.
pub(super) const BB_POSTINIT_EHT: [ProgramEntry; 4] = [
    (R_SLOPE, B_EHT_RATE_TH, 0xA << 28),
    (R_BEDGE, B_EHT_MCS14, 1 << 31),
    (R_BEDGE2, B_EHT_MCS15, 1 << 31),
    (R_BEDGE3, B_EHTTB_EN, 0),
];

/// `R_BRK_EHT` (`reg.h:8894`).
pub(super) const R_BRK_EHT: u32 = 0x0474;
/// `B_RXEHT_NSS_MAX` (`reg.h:8895`): GENMASK(4, 2).
pub(super) const B_RXEHT_NSS_MAX: u32 = 0x7 << 2;
/// `R_BRK_RXEHT` (`reg.h:8896`).
pub(super) const R_BRK_RXEHT: u32 = 0x0478;
/// `B_RXEHTTB_NSS_MAX` (`reg.h:8898`): GENMASK(16, 14).
pub(super) const B_RXEHTTB_NSS_MAX: u32 = 0x7 << 14;
/// `B_RXEHT_N_USER_MAX` (`reg.h:8897`): GENMASK(31, 24).
pub(super) const B_RXEHT_N_USER_MAX: u32 = 0xFF << 24;
/// `HE_N_USER_MAX_8922A` (`rtw8922a.c:23`).
pub(super) const HE_N_USER_MAX_8922A: u32 = 4;

/// EHT arms of `rtw8922a_cfg_rx_nss_limit` (`rtw8922a.c:1937..1953`):
/// for 1 or 2 RX spatial streams, the RX EHT NSS max and the EHT
/// trigger-based NSS max take `rx_nss - 1`, and the RX EHT user max
/// takes `HE_N_USER_MAX_8922A` (4). Any other stream count returns
/// `None`, matching Linux's `-EINVAL` arm. The HT/VHT/HE arms of the
/// same function are not this row's scope.
pub(super) const fn rx_nss_eht_program(rx_nss: u8) -> Option<[ProgramEntry; 3]> {
    match rx_nss {
        1 => Some([
            (R_BRK_EHT, B_RXEHT_NSS_MAX, 0),
            (R_BRK_RXEHT, B_RXEHTTB_NSS_MAX, 0),
            (R_BRK_RXEHT, B_RXEHT_N_USER_MAX, HE_N_USER_MAX_8922A << 24),
        ]),
        2 => Some([
            (R_BRK_EHT, B_RXEHT_NSS_MAX, 1 << 2),
            (R_BRK_RXEHT, B_RXEHTTB_NSS_MAX, 1 << 14),
            (R_BRK_RXEHT, B_RXEHT_N_USER_MAX, HE_N_USER_MAX_8922A << 24),
        ]),
        _ => None,
    }
}

/// Apply a masked-write program in order: each entry reads its
/// register, preserves every bit outside the mask, and writes the
/// positioned value into the mask field.
pub(super) fn apply_program(
    io: &mut impl Regs,
    program: &[ProgramEntry],
) -> Result<(), power::Error> {
    for (address, mask, value) in program {
        let old = io.read32(*address)?;
        io.write32(*address, (old & !mask) | (value & mask))?;
    }
    Ok(())
}

// ── EHT RX CRC counters ───────────────────────────────────────────────

/// `R_CNT_EHT_CRC` (`reg.h:9443`); the BE4 alias is `0x22F00`.
pub(super) const R_CNT_EHT_CRC: u32 = 0x2F00;
/// `B_CNT_EHT_CRC_OK` (`reg.h:9445`): GENMASK(15, 0).
pub(super) const B_CNT_EHT_CRC_OK: u32 = 0xFFFF;
/// `B_CNT_EHT_CRC_ERR` (`reg.h:9446`): GENMASK(31, 16).
pub(super) const B_CNT_EHT_CRC_ERR: u32 = 0xFFFF << 16;

// ── EHT operation profile ──────────────────────────────────────────────

/// What EHT operation means for this chip, as far as this row grounds
/// it: 320MHz operation is supported (the CFGCH, SIFS, and BB-class
/// tables above all carry an explicit 320MHz arm), and the EHT
/// maximum MPDU length is `chip_8922a::MAX_EHT_MPDU_CAP` (7991,
/// `rtw8922a.c:3222`). MCS/NSS capability maps are deliberately NOT
/// part of this struct: they live in `EhtCap` below, computed by
/// `eht_cap` from the same `rtw89_init_eht_cap` source. The profile is
/// exposed to the owner via `Prepared8922a::eht_profile()`; the width
/// programming that would consume it (channel programming) has no
/// production caller yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EhtOperation {
    /// 320MHz EHT operation is supported on this chip.
    pub(super) width_320: bool,
    /// EHT maximum MPDU length in bytes.
    pub(super) max_mpdu_len: usize,
}

/// EHT operation profile for RTL8922A.
pub(super) const EHT_8922A: EhtOperation = EhtOperation {
    width_320: true,
    max_mpdu_len: super::chip_8922a::MAX_EHT_MPDU_CAP,
};

// ── EHT capability (`rtw89_init_eht_cap`, `core.c:6255`) ──────────────
//
// Mirrors Linux `rtw89_init_eht_cap` (torvalds/linux @ 05441d6) field
// for field. Constant source: `include/linux/ieee80211-eht.h`
// (P802.11be_D2.0 §9.4.2.313.2). The function is band-parameterized
// exactly like Linux: the only band-dependent behavior is the 320MHz
// gate, which requires BOTH the 6GHz band AND the 320MHz bit in the
// chip's `support_bandwidths`.
//
// 8922A distinction, stated so the two 320MHz claims in this file are
// not misread as contradictory: step 1's width programming DOES carry
// a 320MHz arm (CFGCH code 4, SIFS pairs, BB class), but the
// advertised EHT capability does NOT carry 320MHz MCS/NSS —
// `rtw8922a.c:3263` lists `support_bandwidths` as 20/40/80/160 with
// no 320MHz bit, so Linux's gate leaves the 320 entries unset and
// the 320MHz PHY bits clear. Programmed widths and advertised
// capabilities are different things; this function models the
// advertisement, faithfully including its absence.

/// `IEEE80211_EHT_MCS_NSS_RX` (`ieee80211-eht.h:47`): GENMASK(3, 0).
pub(super) const EHT_MCS_NSS_RX_MASK: u8 = 0x0F;
/// `IEEE80211_EHT_MCS_NSS_TX` (`ieee80211-eht.h:48`): GENMASK(7, 4).
pub(super) const EHT_MCS_NSS_TX_MASK: u8 = 0xF0;
/// `IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_MASK` (`ieee80211-eht.h:192`):
/// GENMASK(7, 6).
pub(super) const EHT_MAC_CAP0_MAX_MPDU_MASK: u8 = 0xC0;
/// `IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_3895` (`ieee80211-eht.h:193`).
pub(super) const EHT_MAX_MPDU_3895: usize = 3895;
/// `IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_7991` (`ieee80211-eht.h:194`).
pub(super) const EHT_MAX_MPDU_7991: usize = 7991;
/// `IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_11454` (`ieee80211-eht.h:195`).
pub(super) const EHT_MAX_MPDU_11454: usize = 11454;
/// `IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ` (`ieee80211-eht.h:205`).
pub(super) const EHT_PHY_CAP0_320MHZ_IN_6GHZ: u8 = 0x02;
/// `IEEE80211_EHT_PHY_CAP0_NDP_4_EHT_LFT_32_GI` (`ieee80211-eht.h:207`).
pub(super) const EHT_PHY_CAP0_NDP_4_EHT_LFT_32_GI: u8 = 0x08;
/// `IEEE80211_EHT_PHY_CAP0_SU_BEAMFORMEE` (`ieee80211-eht.h:210`).
pub(super) const EHT_PHY_CAP0_SU_BEAMFORMEE: u8 = 0x40;
/// `IEEE80211_EHT_PHY_CAP0_BEAMFORMEE_SS_80MHZ_MASK`
/// (`ieee80211-eht.h:213`): bit 7 of byte 0.
pub(super) const EHT_PHY_CAP0_BF_SS_80_MASK: u8 = 0x80;
/// `IEEE80211_EHT_PHY_CAP1_BEAMFORMEE_SS_80MHZ_MASK`
/// (`ieee80211-eht.h:214`): GENMASK(1, 0) of byte 1.
pub(super) const EHT_PHY_CAP1_BF_SS_80_MASK: u8 = 0x03;
/// `IEEE80211_EHT_PHY_CAP1_BEAMFORMEE_SS_160MHZ_MASK`
/// (`ieee80211-eht.h:216`): GENMASK(4, 2) of byte 1.
pub(super) const EHT_PHY_CAP1_BF_SS_160_MASK: u8 = 0x1C;
/// `IEEE80211_EHT_PHY_CAP1_BEAMFORMEE_SS_320MHZ_MASK`
/// (`ieee80211-eht.h:217`): GENMASK(7, 5) of byte 1.
pub(super) const EHT_PHY_CAP1_BF_SS_320_MASK: u8 = 0xE0;
/// `IEEE80211_EHT_PHY_CAP3_CODEBOOK_4_2_SU_FDBK`
/// (`ieee80211-eht.h:227`).
pub(super) const EHT_PHY_CAP3_CODEBOOK_4_2_SU: u8 = 0x08;
/// `IEEE80211_EHT_PHY_CAP3_CODEBOOK_7_5_MU_FDBK`
/// (`ieee80211-eht.h:228`).
pub(super) const EHT_PHY_CAP3_CODEBOOK_7_5_MU: u8 = 0x10;
/// `IEEE80211_EHT_PHY_CAP3_TRIG_SU_BF_FDBK` (`ieee80211-eht.h:229`).
pub(super) const EHT_PHY_CAP3_TRIG_SU_BF: u8 = 0x20;
/// `IEEE80211_EHT_PHY_CAP3_TRIG_MU_BF_PART_BW_FDBK`
/// (`ieee80211-eht.h:230`).
pub(super) const EHT_PHY_CAP3_TRIG_MU_BF_PART_BW: u8 = 0x40;
/// `IEEE80211_EHT_PHY_CAP4_POWER_BOOST_FACT_SUPP`
/// (`ieee80211-eht.h:235`).
pub(super) const EHT_PHY_CAP4_POWER_BOOST_FACT_SUPP: u8 = 0x04;
/// `IEEE80211_EHT_PHY_CAP4_MAX_NC_MASK` (`ieee80211-eht.h:237`):
/// GENMASK(7, 4) of byte 4.
pub(super) const EHT_PHY_CAP4_MAX_NC_MASK: u8 = 0xF0;
/// `IEEE80211_EHT_PHY_CAP5_COMMON_NOMINAL_PKT_PAD_MASK`
/// (`ieee80211-eht.h:243`): GENMASK(5, 4) of byte 5.
pub(super) const EHT_PHY_CAP5_PKT_PAD_MASK: u8 = 0x30;
/// `IEEE80211_EHT_PHY_CAP5_COMMON_NOMINAL_PKT_PAD_20US`
/// (`ieee80211-eht.h:247`).
pub(super) const EHT_PHY_CAP5_PKT_PAD_20US: u8 = 3;

/// Beamformee spatial-stream count Linux hardcodes in
/// `rtw89_init_eht_cap` (`int sts = 8`).
pub(super) const EHT_BEAMFORMEE_STS: u8 = 8;

/// Inputs to `eht_cap`, mirroring the Linux values the function
/// reads: the band, the chip's 320MHz bandwidth bit, the firmware
/// phycap gates (`hal->no_eht`, `hal->no_mcs_12_13`), the NSS pair,
/// and the maximum MPDU length in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EhtCapInputs {
    /// True for the 6GHz band (`NL80211_BAND_6GHZ`).
    pub(super) six_ghz: bool,
    /// True when the chip's `support_bandwidths` carries
    /// `BIT(NL80211_CHAN_WIDTH_320)`.
    pub(super) support_320mhz_bandwidth: bool,
    /// Firmware phycap protocol below 11BE (`hal->no_eht`).
    pub(super) no_eht: bool,
    /// Variant + phycap QAM gate (`hal->no_mcs_12_13`).
    pub(super) no_mcs_12_13: bool,
    /// Receive spatial streams (`hal->rx_nss`).
    pub(super) rx_nss: u8,
    /// Transmit spatial streams (`hal->tx_nss`).
    pub(super) tx_nss: u8,
    /// Maximum MPDU length in bytes (3895, 7991, or 11454).
    pub(super) max_mpdu_len: usize,
}

/// EHT MCS/NSS support for one bandwidth: the packed
/// `rx_tx_mcs{9,11,13}_max_nss` byte per MCS group
/// (`ieee80211_eht_mcs_nss_supp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EhtMcsNss {
    /// MCS 0..9 maximum NSS byte.
    pub(super) mcs9: u8,
    /// MCS 0..11 maximum NSS byte.
    pub(super) mcs11: u8,
    /// MCS 0..13 maximum NSS byte (0 when MCS 12/13 unsupported).
    pub(super) mcs13: u8,
}

/// Advertised EHT capability for one station, as Linux's
/// `rtw89_init_eht_cap` builds it: MAC/PHY capability bytes plus
/// the per-bandwidth MCS/NSS maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EhtCap {
    /// `eht_cap_elem.mac_cap_info[0..2]`.
    pub(super) mac_cap_info: [u8; 2],
    /// `eht_cap_elem.phy_cap_info[0..9]`.
    pub(super) phy_cap_info: [u8; 9],
    /// 80MHz MCS/NSS map.
    pub(super) mcs_nss_80: EhtMcsNss,
    /// 160MHz MCS/NSS map.
    pub(super) mcs_nss_160: EhtMcsNss,
    /// 320MHz MCS/NSS map (all zero when 320MHz is not gated in).
    pub(super) mcs_nss_320: EhtMcsNss,
}

/// Compute the advertised EHT capability, mirroring Linux
/// `rtw89_init_eht_cap` exactly: `None` when EHT is gated off
/// (`no_eht`, Linux's early return) or when the MPDU length is not
/// one of the three encoded values (fail-closed: no wrong MPDU cap
/// is ever advertised). NSS bytes are masked exactly as Linux's
/// `u8_encode_bits` masks them.
pub(super) const fn eht_cap(i: EhtCapInputs) -> Option<EhtCap> {
    if i.no_eht {
        return None;
    }
    let mpdu_enc: u8 = match i.max_mpdu_len {
        EHT_MAX_MPDU_3895 => 0,
        EHT_MAX_MPDU_7991 => 1,
        EHT_MAX_MPDU_11454 => 2,
        _ => return None,
    };
    let support_320mhz = i.six_ghz && i.support_320mhz_bandwidth;
    let sts_minus_1: u8 = EHT_BEAMFORMEE_STS - 1;

    let mut phy0: u8 = EHT_PHY_CAP0_NDP_4_EHT_LFT_32_GI | EHT_PHY_CAP0_SU_BEAMFORMEE;
    phy0 |= (sts_minus_1 & 1) << 7;
    if support_320mhz {
        phy0 |= EHT_PHY_CAP0_320MHZ_IN_6GHZ;
    }
    let mut phy1: u8 = ((sts_minus_1 >> 1) & 0x03) | ((sts_minus_1 << 2) & 0x1C);
    if support_320mhz {
        phy1 |= (sts_minus_1 << 5) & 0xE0;
    }

    let val: u8 = (i.rx_nss & 0x0F) | ((i.tx_nss & 0x0F) << 4);
    let val_mcs13: u8 = if i.no_mcs_12_13 { 0 } else { val };
    let mcs_80_160 = EhtMcsNss {
        mcs9: val,
        mcs11: val,
        mcs13: val_mcs13,
    };
    let mcs_320 = if support_320mhz {
        mcs_80_160
    } else {
        EhtMcsNss {
            mcs9: 0,
            mcs11: 0,
            mcs13: 0,
        }
    };

    Some(EhtCap {
        mac_cap_info: [(mpdu_enc << 6) & EHT_MAC_CAP0_MAX_MPDU_MASK, 0],
        phy_cap_info: [
            phy0,
            phy1,
            0,
            EHT_PHY_CAP3_CODEBOOK_4_2_SU
                | EHT_PHY_CAP3_CODEBOOK_7_5_MU
                | EHT_PHY_CAP3_TRIG_SU_BF
                | EHT_PHY_CAP3_TRIG_MU_BF_PART_BW,
            EHT_PHY_CAP4_POWER_BOOST_FACT_SUPP | ((1 << 4) & EHT_PHY_CAP4_MAX_NC_MASK),
            (EHT_PHY_CAP5_PKT_PAD_20US << 4) & EHT_PHY_CAP5_PKT_PAD_MASK,
            0,
            0,
            0,
        ],
        mcs_nss_80: mcs_80_160,
        mcs_nss_160: mcs_80_160,
        mcs_nss_320: mcs_320,
    })
}

/// Capability inputs for the in-tree 8922A target (the 8922AE
/// variant): BE generation, firmware EHT present, MCS 12/13 gated
/// off by the variant (`rtw8922ae_vs_variant.no_mcs_12_13`),
/// 2TX/2RX (`rtw8922a.c:3281..3282`), 7991-byte MPDU cap, and no
/// 320MHz bandwidth bit (`rtw8922a.c:3263`). The output is
/// band-independent for this chip (the 320 gate can never open),
/// so the `six_ghz` slot is false by convention; tests assert all
/// three bands agree.
pub(super) const EHT_CAP_8922AE_INPUTS: EhtCapInputs = EhtCapInputs {
    six_ghz: false,
    support_320mhz_bandwidth: false,
    no_eht: false,
    no_mcs_12_13: true,
    rx_nss: 2,
    tx_nss: 2,
    max_mpdu_len: super::chip_8922a::MAX_EHT_MPDU_CAP,
};

// ── EHT station owner facet ────────────────────────────────────────────
//
// The EHT side of station ownership for 8922A: the advertised
// capability plus the per-station EHT TX parameters that program
// the TXWD_INFO EHT fields. This is the facet the 8922A station
// owner composes (`station_8922a::admit` via
// `prepared_8922a::admit_station`, which calls
// `EhtStation::new_8922ae`); it does NOT do admission, DMA control,
// or the firmware/RF/power profile itself. Fail-closed
// defaults: TX EHT overrides off, so a facet that has negotiated
// nothing programs no EHT TX override (info dwords (0, 0)).

/// EHT state owned per 8922A station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EhtStation {
    /// Advertised EHT capability for this station.
    pub(super) cap: EhtCap,
    /// TXWD_INFO4 software NLTF override enabled.
    pub(super) nltf_switch: bool,
    /// TXWD_INFO4 software NLTF value (2 bits).
    pub(super) nltf: u8,
    /// TXWD_INFO7 UL EHT user present (trigger-based UL).
    pub(super) ul_eht_usr_pres: bool,
}

impl EhtStation {
    /// Fail-closed EHT station facet for the 8922AE variant:
    /// capability from `EHT_CAP_8922AE_INPUTS`, TX EHT overrides
    /// off. `None` only if the capability itself cannot be built
    /// (gated EHT or an unmapped MPDU length).
    pub(super) const fn new_8922ae() -> Option<Self> {
        match eht_cap(EHT_CAP_8922AE_INPUTS) {
            Some(cap) => Some(Self {
                cap,
                nltf_switch: false,
                nltf: 0,
                ul_eht_usr_pres: false,
            }),
            None => None,
        }
    }

    /// EHT contribution to the BE TXWD_INFO block for this
    /// station: (info4 bits, info7 bits), via
    /// `txrx_be::eht_info_fields`. `None` only on an out-of-range
    /// NLTF value, which fail-closed construction never produces.
    pub(super) const fn txwd_info_eht(&self) -> Option<(u32, u32)> {
        super::txrx_be::eht_info_fields(self.nltf_switch, self.nltf, self.ul_eht_usr_pres)
    }
}
