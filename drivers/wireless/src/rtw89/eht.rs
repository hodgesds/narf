// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8922A EHT operation: width programming and EHT PHY programs.
//!
//! Mirrors Linux `rtw89/rtw8922a.c` (torvalds/linux @ cbbddb6) for the
//! pieces of EHT/320MHz operation that exist independently of a 8922A
//! station owner: the channel-width programming tables
//! (`rtw8922a_set_channel_mac`, `rtw8922a_chan_to_rf18_val`), the BB
//! bandwidth class (`rtw8922a_set_lna_tia_gain`), the EHT arms of
//! `rtw8922a_bb_postinit` and `rtw8922a_cfg_rx_nss_limit`, and the EHT
//! RX CRC counter block. This module programs nothing on its own: there
//! is no production caller yet, because the 8922A station owner (DMA
//! control sequence, station admission, firmware/RF/power profile) is
//! still the remainder of the `rtl8922a` row. Like the negotiated-TTLM
//! engine, this is implemented-but-not-advertised: the tables are
//! fixture-pinned now so the future owner wires up verified values.
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
//! - EHT MCS/NSS capability maps are NOT encoded: they come from
//!   `rtw89_init_eht_cap` (`core.c`), which is not in the local
//!   reference. The only capability scalar claimed here is
//!   `max_mpdu_len` = 7991, already carried by `chip_8922a`.
//! - The TXWD_INFO EHT fields (`BE_TXD_INFO4_SW_EHT_NLTF_SWITCH` /
//!   `SW_EHT_NLTF`, `BE_TXD_INFO7_UL_EHT_USR_PRES` in `txrx.h`) belong
//!   to the TXWD_INFO block, not the TXWD body `txrx_be.rs` encodes,
//!   so they are not touched here; the BE DMA transport fills the
//!   info block when it lands.
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
/// part of this struct: they need `rtw89_init_eht_cap` (`core.c`),
/// which is not in the local reference. No production caller consumes
/// this profile yet; the future 8922A station owner advertises it
/// once admission exists.
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
