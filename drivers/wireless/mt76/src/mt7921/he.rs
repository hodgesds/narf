//! CONNAC2 HE (802.11ax) station profile and native records.
//!
//! Local capability: Linux mt7921/main.c `mt7921_init_he_caps` (station
//! iftype, 2.4/5GHz). Peer record: mt76_connac_mcu.c
//! `mt76_connac_mcu_sta_he_tlv` / `mt76_connac_mcu_sta_he_tlv_v2` as sent by
//! `mt76_connac_mcu_sta_tlv` from `mt7921_mcu_sta_update`. BSS record:
//! `mt76_connac_mcu_uni_add_bss` + `mt76_connac_mcu_uni_bss_he_tlv`. MU EDCA:
//! mt7921/mcu.c `mt7921_mcu_set_tx` (`MCU_CE_CMD_SET_MU_EDCA_PARMS`).
//! Negotiation itself is the shared `narf_wireless::association::he` owner.
use super::firmware_transport::{Error, RadioInfo};
use alloc::{vec, vec::Vec};
use narf_wireless::association::{
    he::{HeNegotiation, LocalHe},
    phy::{self, LocalPhy},
};

/// `STA_REC_HE` (mt76_connac_mcu.h enum, index 14).
pub(crate) const STA_REC_HE: u16 = 14;
/// `STA_REC_HE_V2`.
pub(crate) const STA_REC_HE_V2: u16 = 0x19;
/// `PHY_TYPE_BIT_HE` in STA_REC_PHY.phy_type.
pub(crate) const PHY_TYPE_BIT_HE: u8 = 1 << 6;
/// `PHY_MODE_AX_24G` / `PHY_MODE_AX_5G` in the BSS basic phymode.
pub(crate) const PHY_MODE_AX_24G: u8 = 1 << 6;
pub(crate) const PHY_MODE_AX_5G: u8 = 1 << 7;
/// `MCU_CE_CMD_SET_MU_EDCA_PARMS`.
pub(crate) const SET_MU_EDCA_PARMS: u8 = 0xb0;
/// mac80211 `IEEE80211_MAX_AMPDU_BUF_HE`; mt792x_core.c sets
/// `max_rx_aggregation_subframes` to it.
pub(crate) const MAX_AMPDU_BUF_HE: u16 = 256;

// IEEE80211_HE_* (include/linux/ieee80211-he.h).
const PHY0_160_5G: u8 = 0x08;
const PHY0_80P80_5G: u8 = 0x10;
const PHY0_RU_MAPPING: u8 = 0x20 | 0x40;
const PHY6_PPE_PRESENT: u8 = 0x80;

/// The firmware must report HE in the NIC PHY TLV, and the HT companion
/// (and, on 5GHz, VHT) must be qualified as for the VHT profile.
pub(crate) fn qualified(info: RadioInfo, five: bool) -> bool {
    let caps = info.capabilities.phy;
    caps.he
        && caps.ht
        && (1..=2).contains(&caps.spatial_streams)
        && if five {
            super::vht::qualified(info)
        } else {
            caps.bands & 1 != 0
        }
}

/// `mt76_connac_gen_ppe_thresh(he_ppet, nss, band)`.
pub(crate) fn ppe_thresholds(nss: u8, five: bool) -> Vec<u8> {
    const PATTERN: [u8; 3] = [0x1c, 0xc7, 0x71];
    let ru_mask: u8 = if five { 0xf } else { 0x3 };
    let bits = 3 * usize::from(nss) * ru_mask.count_ones() as usize * 2;
    let size = bits.div_ceil(8);
    let mut out = vec![(nss - 1) | (ru_mask << 3)];
    for i in 0..size - 1 {
        out.push(PATTERN[i % 3]);
    }
    out.push(PATTERN[(size - 1) % 3] & (0xff >> (8 - (bits - 1) % 8)));
    out
}

/// The station-iftype HE capability exactly as `mt7921_init_he_caps`.
pub(crate) fn local_he(info: RadioInfo, five: bool, allow160: bool) -> Result<LocalHe, Error> {
    let nss = info.capabilities.phy.spatial_streams;
    // IEEE80211_HE_MCS_SUPPORT_0_11 for each chain, NOT_SUPPORTED above.
    let map = if nss == 2 { 0xfffa } else { 0xfffe };
    let wide = five && allow160 && super::vht::wide160(info);
    let mac = [
        0x01,        // MAC_CAP0_HTC_HE
        0x08,        // MAC_CAP1_TF_MAC_PAD_DUR_16US (station)
        0,           //
        0x02 | 0x18, // MAC_CAP3_OMI_CONTROL | MAX_AMPDU_LEN_EXP_EXT_3
        0x40,        // MAC_CAP4_AMSDU_IN_AMPDU
        0,
    ];
    let mut phy = [0u8; 11];
    phy[0] = if five { 0x04 | 0x40 } else { 0x02 | 0x20 }; // width set | RU mapping
    phy[1] = 0x20 | 0x10 | 0x40; // LDPC | DEVICE_CLASS_A | LTF_GI_0_8US
    phy[2] = 0x02 | 0x04 | 0x08 | 0x40 | 0x80; // NDP4x | STBC TX/RX<=80 | UL MU
    phy[3] = 0x02 | 0x10; // DCM max const TX/RX QPSK
    phy[4] = 0x01 | 0x0c; // SU beamformee | BFEE STS<=80 = 4
    phy[5] = 0x40 | 0x80; // NG16 SU/MU feedback
    phy[6] = 0x01 | 0x02 | 0x10 | 0x20; // codebooks | trig CQI | partial BW ER
    phy[7] = 0x02 | 0x04; // power boost | SU/MU 4xLTF 0.8us
    phy[8] = 0x02 | 0x40; // 20MHz-in-40MHz 2G | DCM max RU 484
    phy[9] = 0x3f; // >16 SIG-B, non-trig CQI, 1024QAM<242 TX/RX, full-BW SU via MU
    if wide {
        phy[4] |= 0x60; // BEAMFORMEE_MAX_STS_ABOVE_80MHZ_4
        phy[8] |= 0x04 | 0x08; // 20/80MHz in 160MHz HE PPDU
    }
    let mut he = LocalHe::new(mac, phy, map, map).map_err(|_| Error::UnsupportedFirmware)?;
    if wide {
        he = he
            .with_160mhz(map, map)
            .map_err(|_| Error::UnsupportedFirmware)?;
    }
    // Station sets PPE_THRESHOLD_PRESENT, so no nominal packet padding.
    he.with_ppe_thresholds(&ppe_thresholds(nss, five))
        .map_err(|_| Error::UnsupportedFirmware)
}

/// Opt an HT/VHT profile into HE when the firmware reports it.
pub(crate) fn with_he(
    local: LocalPhy,
    info: RadioInfo,
    five: bool,
    allow160: bool,
) -> Result<LocalPhy, Error> {
    if !qualified(info, five) {
        return Ok(local);
    }
    local
        .with_he(local_he(info, five, allow160)?)
        .map_err(|_| Error::UnsupportedFirmware)
}

/// HE MU EDCA Parameter Set (element ID extension 38, IEEE802.11ax 9.4.2.250)
/// in mac80211 AC order (VO, VI, BE, BK) as `ieee80211_sta_wmm_params` keeps
/// `mu_edca_param_rec`; each record is the raw ACI/AIFSN, ECWmin/max and timer.
fn mu_edca(ies: &[u8]) -> Result<Option<[[u8; 3]; 4]>, Error> {
    let mut found = None;
    let mut rest = ies;
    while rest.len() >= 2 {
        let end = 2 + usize::from(rest[1]);
        let element = rest.get(..end).ok_or(Error::Bounds)?;
        if element[0] == 255 && element.get(2) == Some(&38) {
            if element.len() != 16 || found.is_some() {
                return Err(Error::Bounds);
            }
            let r = |n: usize| [element[4 + n * 3], element[5 + n * 3], element[6 + n * 3]];
            // Element order is BE, BK, VI, VO.
            found = Some([r(3), r(2), r(0), r(1)]);
        }
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        return Err(Error::Bounds);
    }
    Ok(found)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    five: bool,
    /// Peer HE MAC/PHY capability after mac80211
    /// `_ieee80211_he_cap_ie_to_sta_he_cap` width-set masking.
    peer_mac: [u8; 6],
    peer_phy: [u8; 11],
    /// Peer RX maps intersected with local TX (`ieee80211_he_mcs_intersection`).
    rx80: u16,
    rx160: u16,
    /// `sta->deflink.bandwidth == IEEE80211_STA_RX_BW_160`.
    bw160: bool,
    width: u8,
    /// Local (sband) TX maps for `mt76_connac_mcu_uni_bss_he_tlv`.
    local_tx: [u16; 3],
    pe_duration: u8,
    rts_threshold: u16,
    bss_color: u8,
    color_enabled: bool,
    rx_streams: u8,
    rx_ldpc: bool,
    rx_stbc: bool,
    mu_edca: Option<[[u8; 3]; 4]>,
}

impl Profile {
    pub(crate) fn negotiated(n: &phy::Negotiated, ies: &[u8], five: bool) -> Result<Self, Error> {
        Self::from_he(n.he().ok_or(Error::UnsupportedFirmware)?, ies, five)
    }
    /// The profile of one shared HE negotiation: the 2.4/5 GHz PHY plan's,
    /// or a 6 GHz plan's `SixGhzPlan::he()` (6 GHz HE capabilities equal
    /// the 5 GHz ones in `mt7921_init_he_caps`, so `five` is set).
    pub(crate) fn from_he(he: &HeNegotiation, ies: &[u8], five: bool) -> Result<Self, Error> {
        let local = he.local_capability();
        // capability_body(): extension ID, MAC(6), PHY(11), maps.
        let local = narf_wireless::association::he::HeCapability::parse(
            local.get(1..).ok_or(Error::Bounds)?,
        )
        .map_err(|_| Error::Bounds)?;
        let own = local.mcs_nss();
        let own160 = local.phy_capability()[0] & PHY0_160_5G != 0;
        let peer = he.peer_capability();
        let theirs = peer.mcs_nss();
        let mut peer_phy = peer.phy_capability();
        let peer160 = peer_phy[0] & PHY0_160_5G != 0;
        if !own160 {
            peer_phy[0] &= !PHY0_160_5G;
        }
        // No CONNAC2 member advertises 80+80 (mt7921/main.c).
        peer_phy[0] &= !PHY0_80P80_5G;
        let width = match he.width() {
            phy::Width::Twenty => 0,
            phy::Width::Forty => 1,
            phy::Width::Eighty => 2,
            phy::Width::OneSixty => 3,
        };
        if he.discontiguous() || width == 3 && !(own160 && peer160) {
            return Err(Error::UnsupportedFirmware);
        }
        let rx_streams = if he.rx_mcs_map() >> 2 & 3 != 3 { 2 } else { 1 };
        let operation = he.operation();
        Ok(Self {
            five,
            peer_mac: peer.mac_capability(),
            peer_phy,
            rx80: phy::intersect_maps(own.tx80, theirs.rx80),
            rx160: if own160 && peer160 {
                phy::intersect_maps(own.tx160, theirs.rx160)
            } else {
                0xffff
            },
            bw160: width == 3,
            width,
            // The sband iftype data is zero-allocated: an absent160/80+80
            // map is sent as 0, not 0xffff (mt7921_init_he_caps).
            local_tx: [own.tx80, if own160 { own.tx160 } else { 0 }, 0],
            pe_duration: operation.default_pe_duration(),
            rts_threshold: operation.txop_rts_threshold(),
            bss_color: operation.bss_color(),
            color_enabled: !operation.bss_color_disabled(),
            rx_streams,
            rx_ldpc: he.rx_ldpc(),
            rx_stbc: he.rx_stbc(),
            mu_edca: mu_edca(ies)?,
        })
    }
    pub(crate) fn width(self) -> u8 {
        self.width
    }
    pub(crate) fn five(self) -> bool {
        self.five
    }
    pub(crate) fn bss_color(self) -> Option<u8> {
        self.color_enabled.then_some(self.bss_color)
    }
    pub(crate) fn has_mu_edca(self) -> bool {
        self.mu_edca.is_some()
    }
    /// `PHY_MODE_AX_24G`/`PHY_MODE_AX_5G` (`mt76_connac_get_phy_mode`).
    pub(crate) fn phy_mode(self) -> u8 {
        if self.five {
            PHY_MODE_AX_5G
        } else {
            PHY_MODE_AX_24G
        }
    }
    fn max_nss_mcs(self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[..2].copy_from_slice(&self.rx80.to_le_bytes());
        if self.bw160 {
            out[2..4].copy_from_slice(&self.rx160.to_le_bytes());
        }
        out
    }
    /// 28-byte `struct sta_rec_he` (`mt76_connac_mcu_sta_he_tlv`).
    pub(crate) fn sta(self) -> Vec<u8> {
        let (m, p) = (self.peer_mac, self.peer_phy);
        let mut cap = 0u32;
        let mut set = |bit: u32, on: bool| {
            if on {
                cap |= 1 << bit;
            }
        };
        set(0, m[0] & 0x01 != 0); // HTC
        set(2, m[2] & 0x08 != 0); // BSR
        set(3, m[3] & 0x02 != 0); // OM
        set(4, m[4] & 0x40 != 0); // AMSDU_IN_AMPDU
        set(1, m[4] & 0x04 != 0); // BQR
        set(18, p[0] & PHY0_RU_MAPPING != 0); // BW20_RU242
        set(6, p[1] & 0x20 != 0); // LDPC
        set(13, p[1] & 0x40 != 0); // SU_PPDU_1LTF_8US_GI
        set(17, p[2] & 0x02 != 0); // NDP_4LTF_3DOT2MS_GI
        set(9, p[2] & 0x04 != 0); // LE_EQ_80M_TX_STBC
        set(10, p[2] & 0x08 != 0); // LE_EQ_80M_RX_STBC
        set(8, p[6] & 0x20 != 0); // PARTIAL_BW_EXT_RANGE
        set(14, p[7] & 0x04 != 0); // SU_MU_PPDU_4LTF_8US_GI
        set(11, p[7] & 0x40 != 0); // GT_80M_TX_STBC
        set(12, p[7] & 0x80 != 0); // GT_80M_RX_STBC
        set(16, p[8] & 0x01 != 0); // ER_SU_PPDU_4LTF_8US_GI
        set(15, p[8] & 0x10 != 0); // ER_SU_PPDU_1LTF_8US_GI
        set(7, p[9] & 0x02 != 0); // TRIG_CQI_FK
        set(19, p[9] & 0x04 != 0); // TX_1024QAM_UNDER_RU242
        set(20, p[9] & 0x08 != 0); // RX_1024QAM_UNDER_RU242
        let mut out = vec![0u8; 28];
        out[..2].copy_from_slice(&STA_REC_HE.to_le_bytes());
        out[2] = 28;
        out[4..8].copy_from_slice(&cap.to_le_bytes());
        out[8] = (m[1] & 0x0c) >> 2; // t_frame_dur
        out[9] = (m[3] & 0x18) >> 3; // max_ampdu_exp
        out[10] = (p[0] & 0xfe) >> 1; // bw_set
        out[11] = (p[1] & 0x10) >> 4; // device_class
        out[12] = p[3] & 0x03; // dcm_tx_mode
        out[13] = (p[3] & 0x04) >> 2; // dcm_tx_max_nss
        out[14] = (p[3] & 0x18) >> 3; // dcm_rx_mode
        out[15] = (p[3] & 0x20) >> 5; // dcm_rx_max_nss
        out[16] = (p[8] & 0xc0) >> 6; // dcm_max_ru
        out[17] = p[1] & 0x0f; // punc_pream_rx
        out[18] = 2; // pkt_ext
        out[20..26].copy_from_slice(&self.max_nss_mcs());
        out
    }
    /// 28-byte `struct sta_rec_he_v2` (`mt76_connac_mcu_sta_he_tlv_v2`).
    pub(crate) fn sta_v2(self) -> Vec<u8> {
        let mut out = vec![0u8; 28];
        out[..2].copy_from_slice(&STA_REC_HE_V2.to_le_bytes());
        out[2] = 28;
        out[4..10].copy_from_slice(&self.peer_mac);
        out[10..21].copy_from_slice(&self.peer_phy);
        out[21] = 2; // IEEE80211_HE_PHY_CAP9_NOMINAL_PKT_PADDING_16US
        out[22..28].copy_from_slice(&self.max_nss_mcs());
        out
    }
    /// `mt76_connac_mcu_uni_add_bss` HE request: UNI_BSS_INFO_HE_BASIC (5)
    /// from the local sband TX maps plus UNI_BSS_INFO_BSS_COLOR (4), whose
    /// color is applied only while the BSS is enabled.
    pub(crate) fn bss(self, enable: bool) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[4..8].copy_from_slice(&[5, 0, 16, 0]);
        let rts = if self.rts_threshold == 0 {
            1023 // DEFAULT_HE_DURATION_RTS_THRES
        } else {
            self.rts_threshold
        };
        out[8..10].copy_from_slice(&rts.to_le_bytes());
        out[10] = if self.pe_duration == 0 {
            4 // DEFAULT_HE_PE_DURATION
        } else {
            self.pe_duration
        };
        for (n, map) in self.local_tx.iter().enumerate() {
            out[12 + n * 2..14 + n * 2].copy_from_slice(&map.to_le_bytes());
        }
        out[20..24].copy_from_slice(&[4, 0, 8, 0]);
        if enable && self.color_enabled {
            out[24] = 1;
            out[25] = self.bss_color;
        }
        out
    }
    /// 72-byte `struct mt7921_mcu_mu_tx` for BSS 0 / WMM set 0. mac80211
    /// sets `mu_edca` for every AC or none; without the element the
    /// all-zero record is still sent, as Linux breaks before any copy.
    pub(crate) fn mu_edca_request(self, qos: bool) -> [u8; 72] {
        const TO_ACI: [usize; 4] = [1, 0, 2, 3];
        let mut out = [0u8; 72];
        out[5] = u8::from(qos);
        if let Some(records) = self.mu_edca {
            for (ac, rec) in records.iter().enumerate() {
                let e = 8 + TO_ACI[ac] * 8;
                out[e] = rec[1] & 0xf;
                out[e + 1] = (rec[1] & 0xf0) >> 4;
                out[e + 2] = rec[0];
                out[e + 4] = rec[2];
            }
        }
        out
    }
    pub(crate) fn rx_limits(self) -> HeRx {
        HeRx {
            streams: self.rx_streams,
            ldpc: self.rx_ldpc,
            stbc: self.rx_stbc,
        }
    }
}

/// Local HE receive promises for native P-RXV admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HeRx {
    pub streams: u8,
    pub ldpc: bool,
    pub stbc: bool,
}

/// `mt76_connac2_mac_fill_rx_rate` HE modes: HE_SU (8), HE_EXT_SU (9) and
/// HE_MU (11) can be addressed to a station; HE_TB (10) is an uplink
/// trigger-based PPDU and is never accepted. The rate field carries
/// MCS (bits 0..3), DCM (bit 4) and ER-SU 106-tone (bit 5); GI is 0..2.
pub(crate) fn receive_allowed(selected_width: u8, v: u32, rx: HeRx) -> bool {
    let mode = (v >> 24) & 15;
    let width = (v >> 12) & 7;
    let rate = v & 127;
    let mcs = rate & 15;
    let nsts = ((v >> 7) & 7) + 1;
    let stbc = (v >> 22) & 3;
    let gi = (v >> 15) & 3;
    if !matches!(mode, 8 | 9 | 11)
        || v & (1 << 11) != 0 && !rx.ldpc
        || width > u32::from(selected_width)
        || mcs > 11
        || rate & 0x40 != 0
        || gi > 2
        || rate & 0x20 != 0 && mode != 9
    {
        return false;
    }
    let nss = if stbc == 0 {
        nsts
    } else if rx.stbc && stbc == 1 && nsts == 2 {
        1
    } else {
        return false;
    };
    if mode == 9 && (width != 0 || mcs > 2 || nss != 1) {
        return false; // HE ER SU: 20MHz, MCS0-2, one stream.
    }
    nss <= u32::from(rx.streams)
}
