//! CONNAC2 6 GHz station operation (MT7922 / MT7921 6E parts).
//!
//! Admission, channel and power type come from the shared
//! `narf_wireless::association::JoinPlan::prepare_6ghz` / `SixGhzPlan`; this
//! owner supplies the station's 6 GHz profile and the native records:
//!
//! - Capability gate: the NIC `MT_NIC_CAP_6G` TLV (`phy->cap.has_6ghz`,
//!   Linux v7.2 mt7921/mcu.c:595). `mt7921_set_stream_he_caps`
//!   (mt7921/main.c:209-224) registers 6 GHz only under `has_5ghz`.
//! - Local HE 6 GHz Band Capabilities: `mt7921_init_he_caps` 6 GHz branch
//!   (mt7921/main.c:165-189), derived from the 5 GHz HT A-MPDU density and
//!   VHT maximum A-MPDU exponent / MPDU length / antenna-pattern bits.
//! - `STA_REC_HE_6G` (mt76_connac_mcu.c:904-911) and the 6 GHz WTBL HT/VHT
//!   factors (`mt76_connac_mcu_wtbl_ht_tlv`, mt76_connac_mcu.c:977-997).
//! - BSS basic `phymode`/`phymode_ext` (`mt76_connac_get_phy_mode`
//!   mt76_connac_mcu.c:1381-1383, `mt76_connac_mcu_uni_add_bss` :1603).
//! - The regulatory power type as CLC `env_6g` (`mt7921_regd_set_6ghz_
//!   power_type`, mt7921/main.c:766-806; `__mt7921_mcu_set_clc`
//!   mt7921/mcu.c:1331).
use super::firmware_transport::{Error, RadioInfo};
use narf_wireless::association::six_ghz::{He6GhzCapability, SixGhzLocal};
use narf_wireless::reg::{PowerType6Ghz, RegulatoryDomain};

/// mt76_connac_mcu.h `STA_REC_HE_6G`.
pub(crate) const STA_REC_HE_6G: u16 = 0x17;
/// `mt76_connac_get_phy_mode` for `NL80211_BAND_6GHZ`:
/// `PHY_MODE_A | PHY_MODE_AN | PHY_MODE_AC | PHY_MODE_AX_5G`.
pub(crate) const PHY_MODE_6G: u8 = 0x01 | 0x10 | 0x20 | 0x80;
/// `PHY_MODE_AX_6G` in the BSS basic `phymode_ext`.
pub(crate) const PHY_MODE_AX_6G: u8 = 1;

/// `enum mt792x_reg_power_type` (mt792x.h:83), the CLC `env_6g` byte.
pub(crate) const MT_AP_UNSET: u8 = 0;
pub(crate) const MT_AP_LPI: u8 = 2;
pub(crate) const MT_AP_SP: u8 = 3;
pub(crate) const MT_AP_VLP: u8 = 4;

/// `mt7921_regd_set_6ghz_power_type`: the bss_conf power type of the one
/// active station interface (`IEEE80211_REG_*_AP` -> `MT_AP_*`).
pub(crate) fn env_6g(power: PowerType6Ghz) -> u8 {
    match power {
        PowerType6Ghz::Lpi => MT_AP_LPI,
        PowerType6Ghz::Sp => MT_AP_SP,
        PowerType6Ghz::Vlp => MT_AP_VLP,
    }
}

/// 6 GHz needs the firmware's `MT_NIC_CAP_6G`, the 5 GHz band (the 6 GHz
/// sband is registered inside `has_5ghz`) and the 5 GHz HE profile, whose
/// capabilities `mt7921_init_he_caps` reuses unchanged for 6 GHz.
pub(crate) fn qualified(info: RadioInfo) -> bool {
    info.capabilities.has_6ghz
        && info.capabilities.phy.bands & 2 != 0
        && super::he::qualified(info, true)
}

/// HE 6 GHz Band Capabilities Information (`mt7921_init_he_caps`).
pub(crate) fn capability(info: RadioInfo) -> Result<He6GhzCapability, Error> {
    if !qualified(info) {
        return Err(Error::UnsupportedFirmware);
    }
    use narf_wireless::association::six_ghz::{
        CAP_MAX_AMPDU_LEN_EXP, CAP_MAX_MPDU_LEN, CAP_MIN_MPDU_START, CAP_RX_ANTPAT_CONS,
        CAP_TX_ANTPAT_CONS,
    };
    // HT Capabilities body octet 2: A-MPDU Parameters, density in B2..B4.
    let density = u16::from(super::vht::ht_capability(info)[2] >> 2 & 7);
    let vht = super::vht::capability(info).ok_or(Error::UnsupportedFirmware)?;
    let vht = u32::from_le_bytes([vht[0], vht[1], vht[2], vht[3]]);
    let mut cap = density & CAP_MIN_MPDU_START;
    // IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK (B23..B25).
    cap |= ((vht >> 23 & 7) as u16) << 3 & CAP_MAX_AMPDU_LEN_EXP;
    // IEEE80211_VHT_CAP_MAX_MPDU_MASK (B0..B1).
    cap |= ((vht & 3) as u16) << 6 & CAP_MAX_MPDU_LEN;
    if vht & (1 << 29) != 0 {
        cap |= CAP_TX_ANTPAT_CONS; // IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN
    }
    if vht & (1 << 28) != 0 {
        cap |= CAP_RX_ANTPAT_CONS; // IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN
    }
    Ok(He6GhzCapability::new(cap))
}

/// The station's 6 GHz profile against the regulatory rule covering the
/// BSS primary (`freq_reg_info`). No rule means no 6 GHz authority.
pub(crate) fn local(
    info: RadioInfo,
    domain: &RegulatoryDomain,
    primary_mhz: u32,
) -> Result<SixGhzLocal, Error> {
    let rule = domain
        .rule_for(primary_mhz)
        .ok_or(Error::Authority)?
        .clone();
    let he = super::he::local_he(info, true, true)?;
    SixGhzLocal::new(he, capability(info)?, rule).map_err(|_| Error::UnsupportedFirmware)
}

/// `struct sta_rec_he_6g_capa` carrying the peer's (`sta->deflink.
/// he_6ghz_capa`) capability; sent only with `MT76_STA_INFO_STATE_ASSOC`.
pub(crate) fn sta_he_6g(peer: He6GhzCapability) -> [u8; 8] {
    let [lo, hi] = peer.bits().to_le_bytes();
    [STA_REC_HE_6G as u8, 0, 8, 0, lo, hi, 0, 0]
}

/// `mt76_connac_mcu_wtbl_ht_tlv` for a 6 GHz peer (no HT/VHT capability,
/// `he_6ghz_capa` set): WTBL_HT `{ht, ldpc 0, af, mm}` from the band
/// capability, WTBL_VHT `{vht}`; `af` keeps the larger of the HT and VHT
/// factors, and the VHT factor of an absent VHT capability is 0.
pub(crate) fn wtbl_ht_factors(peer: He6GhzCapability) -> (u8, u8) {
    (peer.max_ampdu_len_exp(), peer.min_mpdu_start())
}

/// `mt76_connac_mcu_sta_amsdu_tlv` `max_mpdu_size`: mac80211
/// `ieee80211_update_from_he_6ghz_capa` takes `agg.max_amsdu_len` from the
/// band capability's Maximum MPDU Length (7991 or 11454 set the flag).
pub(crate) fn large_mpdu(peer: He6GhzCapability) -> bool {
    peer.max_mpdu_len() >= 1
}

/// UNI_BSS_INFO_RLM for the 6 GHz channel (`mt76_connac_mcu_uni_set_chctx`:
/// control/centre channel, CMD_CBW width, `ht_op_info` 4 above 20 MHz,
/// SCA/SCB, `band = NL80211_BAND_6GHZ`).
pub(crate) fn rlm(primary: u8, center: u8, width: u8, tx_streams: u8, chains: u8) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes[4..8].copy_from_slice(&[2, 0, 16, 0]);
    bytes[8] = primary;
    bytes[9] = center;
    bytes[11] = width;
    bytes[12] = tx_streams;
    bytes[13] = chains;
    bytes[14] = 1;
    bytes[15] = if width != 0 { 4 } else { 0 };
    bytes[16] = match primary.cmp(&center) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Greater => 3,
        core::cmp::Ordering::Equal => 0,
    };
    bytes[17] = super::channel::Band::Ghz6.nl80211();
    bytes
}
