// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Assoc PPE pads from peer association IEs (issue #1882).
//!
//! Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_assoc_cmac_tbl_g7`
//! (torvalds/linux, `/tmp/linux-rtw89-api/fw.c` in the lane
//! reference): the G7 assoc CMAC table's w5 nominal-packet-padding
//! fields come from the peer's PPE thresholds, EHT first and HE
//! as the fallback, and stay zero when the peer advertised neither
//! EHT nor HE caps (Linux `memset(pads, 0, ...)`). The two helpers
//! transcribed here are `__get_sta_eht_pkt_padding` and
//! `__get_sta_he_pkt_padding` (`fw.c:4376..4430` and
//! `fw.c:4227..4282`); the element layouts and size helpers come
//! from `include/linux/ieee80211.h` (TI mirror blob 457b4fba):
//! `ieee80211_he_capa_size_ok` / `ieee80211_he_mcs_nss_size` /
//! `ieee80211_he_ppe_size` and `ieee80211_eht_capa_size_ok` /
//! `ieee80211_eht_mcs_nss_size` / `ieee80211_eht_ppe_size`.
//!
//! Input contract: `ies` is the peer association request's element
//! blob — concatenated `[id, len, ...]` elements starting at the
//! first IE (SSID), exactly as mac80211 hands the driver the assoc
//! frame's variable part, NOT including the 4 fixed bytes
//! (capability info + listen interval). `nss` is the admitted
//! link's spatial-stream count (1-based, as in
//! `station_8922a::Request::nss`); Linux reads the PPET block for
//! `min(peer rx_nss, hal tx_nss) - 1`, and the admitted NSS is
//! that minimum.
//!
//! Fail-closed: any malformed, truncated, or unusable element
//! yields zero pads for that element's path — the same outcome as
//! a peer with no EHT/HE caps. A malformed EHT element falls back
//! to the HE element (Linux: `has_eht` is only set when the EHT
//! element passes its size checks, so a bad EHT element still
//! takes the HE path); a PPE field that does not carry a block for
//! the requested NSS counts as malformed for the same reason. The
//! result is always five 2-bit pads in 20/40/80/160/320 MHz order
//! (`RTW89_PPE_BW_NUM`, `core.h:995`).
//!
//! RU-index note: the PPE Thresholds RU Index Bitmask enumerates
//! RU sizes in increasing order — 242/484/996/2x996-tone for HE
//! (IEEE 802.11-20/xxxxr0: 4 bits, "RU 242, 484, 996 and 2*996"),
//! extended for EHT (NSTS 4 bits, RU bitmask 5 bits in the final
//! header). Linux rtw89 indexes the pads by RU index (`pads[i]`
//! from `ru_bitmap & BIT(i)`), i.e. 242-tone ~ 20 MHz, 484 ~ 40,
//! 996 ~ 80, 2x996 ~ 160, fifth RU ~ 320; this module transcribes
//! that mapping exactly, it does not re-derive it.

/// Element id for Extension elements (`WLAN_EID_EXTENSION`,
/// `ieee80211.h`).
const WLAN_EID_EXTENSION: u8 = 255;
/// HE Capabilities extension id (`WLAN_EID_EXT_HE_CAPABILITY`,
/// `ieee80211.h`).
const WLAN_EID_EXT_HE_CAPABILITY: u8 = 35;
/// EHT Capabilities extension id (`WLAN_EID_EXT_EHT_CAPABILITY`,
/// `ieee80211.h`).
const WLAN_EID_EXT_EHT_CAPABILITY: u8 = 108;

/// HE MAC Capabilities Info length (`struct ieee80211_he_cap_elem`,
/// `ieee80211.h`): 6 bytes.
const HE_MAC_CAP_LEN: usize = 6;
/// HE PHY Capabilities Info length (`struct ieee80211_he_cap_elem`,
/// `ieee80211.h`): 11 bytes.
const HE_PHY_CAP_LEN: usize = 11;
/// HE PHY CAP0 40 MHz in 2.4 GHz bit
/// (`IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G`).
const HE_PHY_CAP0_WIDTH_40MHZ_IN_2G: u8 = 0x02;
/// HE PHY CAP0 40/80 MHz in 5 GHz bit
/// (`IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G`).
const HE_PHY_CAP0_WIDTH_40MHZ_80MHZ_IN_5G: u8 = 0x04;
/// HE PHY CAP0 160 MHz in 5 GHz bit
/// (`IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G`).
const HE_PHY_CAP0_WIDTH_160MHZ_IN_5G: u8 = 0x08;
/// HE PHY CAP0 80+80 MHz in 5 GHz bit
/// (`IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G`).
const HE_PHY_CAP0_WIDTH_80PLUS80_MHZ_IN_5G: u8 = 0x10;
/// HE PHY CAP6 PPE Threshold Present bit
/// (`IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT`).
const HE_PHY_CAP6_PPE_THRESHOLD_PRESENT: u8 = 0x80;
/// HE PHY CAP9 Nominal Packet Padding mask
/// (`IEEE80211_HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK`): bits 7:6.
const HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK: u8 = 0xC0;
/// HE PPE Thresholds NSS mask (`IEEE80211_PPE_THRES_NSS_MASK`):
/// bits 2:0 of the header byte.
const PPE_THRES_NSS_MASK: u8 = 0x07;
/// HE PPE Thresholds RU Index Bitmask mask
/// (`IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK`): bits 6:3.
const PPE_THRES_RU_INDEX_BITMASK_MASK: u8 = 0x78;
/// Bits per PPET value (`IEEE80211_PPE_THRES_INFO_PPET_SIZE`).
const PPE_THRES_INFO_PPET_SIZE: u32 = 3;
/// HE PPE Thresholds header size in bits
/// (`IEEE80211_HE_PPE_THRES_INFO_HEADER_SIZE`): 3 NSS + 4 RU bits.
const HE_PPE_THRES_INFO_HEADER_SIZE: u32 = 7;

/// EHT MAC Capabilities Info length
/// (`struct ieee80211_eht_cap_elem_fixed`, `ieee80211.h`): 2 bytes.
const EHT_MAC_CAP_LEN: usize = 2;
/// EHT PHY Capabilities Info length
/// (`struct ieee80211_eht_cap_elem_fixed`, `ieee80211.h`): 9 bytes.
const EHT_PHY_CAP_LEN: usize = 9;
/// EHT PHY CAP0 320 MHz in 6 GHz bit
/// (`IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ`).
const EHT_PHY_CAP0_320MHZ_IN_6GHZ: u8 = 0x02;
/// EHT PHY CAP5 PPE Threshold Present bit
/// (`IEEE80211_EHT_PHY_CAP5_PPE_THRESHOLD_PRESENT`).
const EHT_PHY_CAP5_PPE_THRESHOLD_PRESENT: u8 = 0x08;
/// EHT PHY CAP5 Common Nominal Packet Padding mask
/// (`IEEE80211_EHT_PHY_CAP5_COMMON_NOMINAL_PKT_PAD_MASK`):
/// bits 5:4.
const EHT_PHY_CAP5_COMMON_NOMINAL_PKT_PAD_MASK: u8 = 0x30;
/// EHT PPE Thresholds NSS mask (`IEEE80211_EHT_PPE_THRES_NSS_MASK`):
/// bits 3:0 of the header halfword.
const EHT_PPE_THRES_NSS_MASK: u16 = 0x000F;
/// EHT PPE Thresholds RU Index Bitmask mask
/// (`IEEE80211_EHT_PPE_THRES_RU_INDEX_BITMASK_MASK`): bits 8:4.
const EHT_PPE_THRES_RU_INDEX_BITMASK_MASK: u16 = 0x01F0;
/// Bits per EHT PPET value (`IEEE80211_EHT_PPE_THRES_INFO_PPET_SIZE`).
const EHT_PPE_THRES_INFO_PPET_SIZE: u32 = 3;
/// EHT PPE Thresholds header size in bits
/// (`IEEE80211_EHT_PPE_THRES_INFO_HEADER_SIZE`): 4 NSS + 5 RU bits.
const EHT_PPE_THRES_INFO_HEADER_SIZE: u32 = 9;

/// Number of pad widths (`RTW89_PPE_BW_NUM`, `core.h:995`):
/// 20/40/80/160/320 MHz.
const PPE_BW_NUM: usize = 5;
/// Nominal padding 0 us (`RTW89_PE_DURATION_0`, `core.h:998`).
const PE_DURATION_0: u8 = 0;
/// Nominal padding 8 us (`RTW89_PE_DURATION_8`, `core.h:999`).
const PE_DURATION_8: u8 = 1;
/// Nominal padding 16 us (`RTW89_PE_DURATION_16`, `core.h:1000`).
/// HE PPET16 outcome only.
const PE_DURATION_16: u8 = 2;
/// Nominal padding 16/20 us (`RTW89_PE_DURATION_16_20`,
/// `core.h:1001`). EHT PPET16 outcome only.
const PE_DURATION_16_20: u8 = 3;

/// Parse the peer's association IEs into the five Assoc PPE pads
/// (20/40/80/160/320 MHz order, 2 bits each), exactly as Linux
/// rtw89 fills the G7 assoc CMAC table's w5. EHT caps win over HE
/// caps; no EHT/HE caps — or any malformed element — yields
/// `[0; 5]`, which keeps meaning "no EHT/HE peer" exactly as
/// before this parser existed.
pub(super) fn parse_assoc_ppe(ies: &[u8], nss: u8) -> [u8; 5] {
    let he = find_ext_element(ies, WLAN_EID_EXT_HE_CAPABILITY)
        .filter(|payload| payload.len() >= HE_MAC_CAP_LEN + HE_PHY_CAP_LEN);
    let eht = find_ext_element(ies, WLAN_EID_EXT_EHT_CAPABILITY)
        .filter(|payload| payload.len() >= EHT_MAC_CAP_LEN + EHT_PHY_CAP_LEN);
    if let (Some(he), Some(eht)) = (he, eht) {
        if let Some(pads) = eht_pads(he, eht, nss) {
            return pads;
        }
    }
    if let Some(he) = he {
        if let Some(pads) = he_pads(he, nss) {
            return pads;
        }
    }
    [0; PPE_BW_NUM]
}

/// First Extension element with `ext_id` in the IE blob, as the
/// payload after the extension-id byte (`element->data[1..]`,
/// `for_each_element_extid` in `ieee80211.h`). `None` when absent
/// or when a truncated element ends the walk — a truncated element
/// cannot be skipped, because its length cannot be trusted.
fn find_ext_element(mut ies: &[u8], ext_id: u8) -> Option<&[u8]> {
    while ies.len() >= 2 {
        let id = ies[0];
        let len = ies[1] as usize;
        let element = ies.get(2..2 + len)?;
        ies = &ies[2 + len..];
        if id == WLAN_EID_EXTENSION && !element.is_empty() && element[0] == ext_id {
            return Some(&element[1..]);
        }
    }
    None
}

/// HE MCS/NSS set size in bytes (`ieee80211_he_mcs_nss_size`):
/// 4 for the <=80 MHz set, +4 for 160 MHz, +4 for 80+80 MHz.
fn he_mcs_nss_size(phy_cap0: u8) -> usize {
    let mut count = 4;
    if phy_cap0 & HE_PHY_CAP0_WIDTH_160MHZ_IN_5G != 0 {
        count += 4;
    }
    if phy_cap0 & HE_PHY_CAP0_WIDTH_80PLUS80_MHZ_IN_5G != 0 {
        count += 4;
    }
    count
}

/// EHT MCS/NSS set size in bytes (`ieee80211_eht_mcs_nss_size`,
/// `from_ap = false`: the peer is a non-AP STA sending an
/// association request). 3 bytes per width set (<=80, 160, 320
/// MHz); a 20 MHz-only peer carries 4 (the <=80 set plus its
/// 20 MHz-only map).
fn eht_mcs_nss_size(he_phy_cap0: u8, eht_phy_cap0: u8) -> usize {
    if he_phy_cap0 & HE_PHY_CAP0_WIDTH_40MHZ_IN_2G != 0 {
        return 3;
    }
    let mut count = 0;
    if he_phy_cap0 & HE_PHY_CAP0_WIDTH_40MHZ_80MHZ_IN_5G != 0 {
        count += 3;
    }
    if he_phy_cap0 & HE_PHY_CAP0_WIDTH_160MHZ_IN_5G != 0 {
        count += 3;
    }
    if eht_phy_cap0 & EHT_PHY_CAP0_320MHZ_IN_6GHZ != 0 {
        count += 3;
    }
    if count != 0 {
        count
    } else {
        4
    }
}

/// Read `count` bits (<= 16) starting at bit `at` from an
/// LSB-first bit field (`le16` + shift in Linux). `None` when the
/// read would run past the field.
fn read_bits(field: &[u8], at: u32, count: u32) -> Option<u32> {
    let first = (at / 8) as usize;
    let shift = at % 8;
    let bytes = (shift + count).div_ceil(8) as usize;
    let mut value: u32 = 0;
    for i in 0..bytes {
        value |= u32::from(*field.get(first + i)?) << (i * 8);
    }
    Some((value >> shift) & ((1u32 << count) - 1))
}

/// Derive the five pads from one PPE Thresholds field, following
/// `__get_sta_he_pkt_padding` / `__get_sta_eht_pkt_padding`
/// exactly: the field is NSS-major blocks of per-RU (PPET16,
/// PPET8) pairs, 3 bits each, and only the block for the requested
/// NSS index is read. `header_size` is the header length in bits,
/// `ru_bitmap` the extracted RU Index Bitmask (bit `i` = RU
/// index `i`), `nss_count` the number of NSS blocks in the field
/// (`(header NSS field) + 1`), and `eht` selects the EHT
/// PPET16 outcome (`RTW89_PE_DURATION_16_20`) over the HE one
/// (`RTW89_PE_DURATION_16`). `None` when the field is too short
/// for all its NSS blocks or has no block for `nss_idx`.
fn derive_pads(
    field: &[u8],
    header_size: u32,
    ru_bitmap: u32,
    nss_count: u32,
    nss_idx: u32,
    eht: bool,
) -> Option<[u8; PPE_BW_NUM]> {
    if nss_idx >= nss_count {
        return None;
    }
    let ru_count = ru_bitmap.count_ones();
    let total_bits = header_size + ru_count * nss_count * PPE_THRES_INFO_PPET_SIZE * 2;
    if field.len() * 8 < total_bits as usize {
        return None;
    }
    let mut pads = [0u8; PPE_BW_NUM];
    let mut at = header_size + ru_count * nss_idx * PPE_THRES_INFO_PPET_SIZE * 2;
    for (i, pad) in pads.iter_mut().enumerate() {
        if ru_bitmap & (1u32 << i) == 0 {
            *pad = PE_DURATION_8;
            continue;
        }
        let ppe16 = read_bits(field, at, PPE_THRES_INFO_PPET_SIZE)?;
        at += PPE_THRES_INFO_PPET_SIZE;
        let ppe8 = read_bits(field, at, PPE_THRES_INFO_PPET_SIZE)?;
        at += PPE_THRES_INFO_PPET_SIZE;
        *pad = if ppe16 != 7 && ppe8 == 7 {
            if eht {
                PE_DURATION_16_20
            } else {
                PE_DURATION_16
            }
        } else if ppe8 != 7 {
            PE_DURATION_8
        } else {
            PE_DURATION_0
        };
    }
    Some(pads)
}

/// EHT pads from the peer's HE + EHT Capabilities payloads
/// (`__get_sta_eht_pkt_padding`). `None` when the EHT element
/// cannot be located or trusted (the caller then tries HE).
fn eht_pads(he: &[u8], eht: &[u8], nss: u8) -> Option<[u8; PPE_BW_NUM]> {
    let he_phy = &he[HE_MAC_CAP_LEN..HE_MAC_CAP_LEN + HE_PHY_CAP_LEN];
    let eht_phy = &eht[EHT_MAC_CAP_LEN..EHT_MAC_CAP_LEN + EHT_PHY_CAP_LEN];
    let ppe_present = eht_phy[5] & EHT_PHY_CAP5_PPE_THRESHOLD_PRESENT != 0;
    if !ppe_present {
        let pad = (eht_phy[5] & EHT_PHY_CAP5_COMMON_NOMINAL_PKT_PAD_MASK) >> 4;
        return Some([pad; PPE_BW_NUM]);
    }
    let mcs = eht_mcs_nss_size(he_phy[0], eht_phy[0]);
    let field = eht.get(EHT_MAC_CAP_LEN + EHT_PHY_CAP_LEN + mcs..)?;
    if field.len() < 2 {
        return None;
    }
    let header = u16::from_le_bytes([field[0], field[1]]);
    let ru_bitmap = (header & EHT_PPE_THRES_RU_INDEX_BITMASK_MASK) >> 4;
    let nss_count = u32::from(header & EHT_PPE_THRES_NSS_MASK) + 1;
    let nss_idx = u32::from(nss.checked_sub(1)?);
    derive_pads(
        field,
        EHT_PPE_THRES_INFO_HEADER_SIZE,
        u32::from(ru_bitmap),
        nss_count,
        nss_idx,
        true,
    )
}

/// HE pads from the peer's HE Capabilities payload
/// (`__get_sta_he_pkt_padding`). `None` when the HE element
/// cannot be located or trusted.
fn he_pads(he: &[u8], nss: u8) -> Option<[u8; PPE_BW_NUM]> {
    let he_phy = &he[HE_MAC_CAP_LEN..HE_MAC_CAP_LEN + HE_PHY_CAP_LEN];
    let ppe_present = he_phy[6] & HE_PHY_CAP6_PPE_THRESHOLD_PRESENT != 0;
    if !ppe_present {
        let pad = (he_phy[9] & HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK) >> 6;
        return Some([pad; PPE_BW_NUM]);
    }
    let mcs = he_mcs_nss_size(he_phy[0]);
    let field = he.get(HE_MAC_CAP_LEN + HE_PHY_CAP_LEN + mcs..)?;
    if field.is_empty() {
        return None;
    }
    let header = field[0];
    let ru_bitmap = (header & PPE_THRES_RU_INDEX_BITMASK_MASK) >> 3;
    let nss_count = u32::from(header & PPE_THRES_NSS_MASK) + 1;
    let nss_idx = u32::from(nss.checked_sub(1)?);
    derive_pads(
        field,
        HE_PPE_THRES_INFO_HEADER_SIZE,
        u32::from(ru_bitmap),
        nss_count,
        nss_idx,
        false,
    )
}
