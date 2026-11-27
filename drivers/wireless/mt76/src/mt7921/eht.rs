//! CONNAC3 EHT (802.11be) station profile and native records (MT7925 only).
//!
//! Local capability: Linux mt7925/main.c `mt7925_init_eht_caps` (station
//! iftype, 2.4/5/6 GHz). Peer record: mt7925/mcu.c
//! `mt7925_mcu_sta_eht_tlv` (`STA_REC_EHT`, 0x22) as sent by
//! `mt7925_mcu_sta_update`. The MLD TLV (`sta_eht_mld_tlv`) and the
//! per-link BSS EHT TLV are slice (6)'s; this owner emits only the
//! single-link station record and the capability the TLV layer consumes.
//! Negotiation itself is the shared `narf_wireless::association::eht` owner.
//!
//! 320 MHz is refused: `is_320mhz_supported` is `mt76_chip(dev) == 0x7927`
//! (`mt76_connac.h`), so an MT7925 never advertises it, and a 320 MHz
//! peer selection fails closed here.
use super::firmware_transport::{Error, RadioInfo};
use alloc::{vec, vec::Vec};
use narf_wireless::association::{
    eht::{EhtNegotiation, LocalEht},
    he::HeNegotiation,
    phy::{self, LocalPhy},
};

/// `STA_REC_EHT` (mt76_connac_mcu.h enum, index 0x22).
pub(crate) const STA_REC_EHT: u16 = 0x22;
/// `PHY_TYPE_BIT_BE` in STA_REC_PHY.phy_type.
pub(crate) const PHY_TYPE_BIT_BE: u8 = 1 << 7;

// IEEE80211_EHT_PHY_CAP6_MCS15_SUPP_MASK bits (include/linux/ieee80211-eht.h).
const MCS15_20MHZ: u8 = 0x08;
const MCS15_80MHZ: u8 = 0x10;
const MCS15_160MHZ: u8 = 0x20;

/// The firmware must report HE in the NIC PHY TLV, and the HT companion
/// (and, on 5 GHz, VHT) must be qualified as for the HE profile. There
/// is no EHT bit in the NIC PHY TLV: upstream `dev->has_eht` is true for
/// MT7925 by construction (`mt7925_regd_be_ctrl` clears it only on an
/// ACPI MTCL BE-disable, which NARF does not implement), so the gate is
/// the chip id, as for `vht::wide160`.
pub(crate) fn qualified(info: RadioInfo, five: bool) -> bool {
    info.chip_id == 0x7925 && super::he::qualified(info, five)
}

/// The station-iftype EHT capability exactly as `mt7925_init_eht_caps`
/// for an MT7925 (`is_320mhz_supported` is false: 0x7925 != 0x7927).
/// No PPE thresholds are advertised (`mt7925_mcu_set_eht_pp` is the
/// MCU-side PPE programming, slice (6)'s).
pub(crate) fn local_eht(info: RadioInfo, five: bool, allow160: bool) -> Result<LocalEht, Error> {
    let nss = info.capabilities.phy.spatial_streams;
    // `(nss << 4) | nss` per range: 0x22 for two streams, 0x11 for one.
    // The wide map's first octet covers MCS 0-9 (MCS 0-7 and 8-9 share
    // it); the other two cover MCS 10-11 and 12-13.
    let set = [(nss << 4) | nss; 3];
    let mac = [
        0x03, // MAC_CAP0_EPCS_PRIO_ACCESS | OM_CONTROL
        0x00,
    ];
    let wide = five && allow160 && super::vht::wide160(info);
    let sts = u32::from(nss) - 1;
    let mut phy = [0u8; 9];
    // NDP 4x EHT-LTF 3.2us GI | SU beamformer | SU beamformee |
    // beamformee SS <=80 MHz (sts > 3 ? sts - 1 : 3, bit 0 -> bits 3..5).
    phy[0] = 0x80 | 0x20 | 0x40 | 0x08;
    // Beamformee SS <=80 MHz (bits 1..2 -> bits 0..2) | SS 160 MHz (bits 2..4).
    phy[1] = 0x0d;
    // Sounding dimensions <=80 MHz | 160 MHz (sts - 1 in each).
    phy[2] = ((sts & 0x7) | ((sts & 0x7) << 3)) as u8;
    // NG16 SU/MU feedback, codebooks 4/2 and 7/5, triggered SU/MU
    // beamforming feedback, partial-BW feedback, triggered CQI.
    phy[3] = 0xfe;
    // Max Nc (min(sts - 1, 2) in bits 4..7).
    phy[4] = ((sts.min(2) & 0xf) << 4) as u8;
    // Non-triggered CQI, common nominal packet padding 16us, max
    // supported EHT-LTF 4x.
    phy[5] = 0x61;
    // Max supported EHT-LTF (bits 0..2) | MCS 14/15 support up to the
    // radio's max width: 0x1 (20 MHz) in 2.4 GHz, 0x3 (80 MHz) on
    // 80 MHz-only 5 GHz, 0x7 (160 MHz) on 160 MHz 5 GHz.
    let mcs15 = if !five {
        0x1
    } else if wide {
        0x7
    } else {
        0x3
    };
    phy[6] = 0x04 | (mcs15 << 3);
    // Non-OFDMA UL MU-MIMO 80/160 MHz, MU beamformer 80/160 MHz.
    phy[7] = 0x36;
    let mut eht = LocalEht::new(mac, phy, set).map_err(|_| Error::UnsupportedFirmware)?;
    if wide {
        eht = eht
            .with_160mhz(set)
            .map_err(|_| Error::UnsupportedFirmware)?;
    }
    Ok(eht)
}

/// Opt an HE profile into EHT when the firmware reports it. Must be
/// called after `he::with_he`: `LocalPhy::with_eht` requires HE.
pub(crate) fn with_eht(
    local: LocalPhy,
    info: RadioInfo,
    five: bool,
    allow160: bool,
) -> Result<LocalPhy, Error> {
    if !qualified(info, five) {
        return Ok(local);
    }
    local
        .with_eht(local_eht(info, five, allow160)?)
        .map_err(|_| Error::UnsupportedFirmware)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    /// Peer EHT MAC capability.
    peer_mac: [u8; 2],
    /// Peer EHT PHY capability.
    peer_phy: [u8; 9],
    /// Peer Supported EHT-MCS And NSS Set, zero-padded to 9 octets:
    /// <=80 (0..3), 160 (3..6), 320 (6..9, always zero here).
    peer_mcs: [u8; 9],
    /// Length of the peer set: 4 for a 20 MHz-only STA, otherwise
    /// 3 (<=80), 6 (160) or 9 (320 — never, 320 is refused).
    peer_mcs_len: u8,
    /// Local EHT PHY octet 6 (MCS 14/15 support bits).
    local_phy6: u8,
    /// Per-range local RX max NSS (MCS 0-7, 8-9, 10-11, 12-13).
    rx_nss: [u8; 4],
    /// LDPC / STBC promises, inherited from the HE negotiation: EHT
    /// carries no LDPC/STBC of its own.
    rx_ldpc: bool,
    rx_stbc: bool,
    /// `sta->deflink.bandwidth == IEEE80211_STA_RX_BW_160`.
    bw160: bool,
    width: u8,
}

impl Profile {
    pub(crate) fn negotiated(n: &phy::Negotiated) -> Result<Self, Error> {
        Self::from_eht(
            n.eht().ok_or(Error::UnsupportedFirmware)?,
            n.he().ok_or(Error::UnsupportedFirmware)?,
        )
    }
    /// The profile of one shared EHT negotiation: the 2.4/5 GHz PHY
    /// plan's, or a 6 GHz plan's `SixGhzPlan::eht()` with its `he()`.
    pub(crate) fn from_eht(e: &EhtNegotiation, he: &HeNegotiation) -> Result<Self, Error> {
        // A 6 GHz 320 MHz selection (`width()` OneSixty with `bw320`)
        // is refused: this driver never advertises 320 MHz.
        if e.width320() {
            return Err(Error::UnsupportedFirmware);
        }
        let width = match e.width() {
            phy::Width::Twenty => 0,
            phy::Width::Forty => 1,
            phy::Width::Eighty => 2,
            phy::Width::OneSixty => 3,
        };
        let peer = e.peer_capability();
        let mut peer_mcs = [0u8; 9];
        let set = peer.mcs_nss();
        peer_mcs[..set.len()].copy_from_slice(set);
        // `local_capability()`: extension ID, MAC(2), PHY(9), maps —
        // PHY octet 6 is at index 9.
        let local = e.local_capability();
        let local_phy6 = *local.get(9).ok_or(Error::Bounds)?;
        Ok(Self {
            peer_mac: peer.mac_capability(),
            peer_phy: peer.phy_capability(),
            peer_mcs,
            peer_mcs_len: set.len() as u8,
            local_phy6,
            rx_nss: e.rx_max_nss(),
            rx_ldpc: he.rx_ldpc(),
            rx_stbc: he.rx_stbc(),
            bw160: width == 3,
            width,
        })
    }
    pub(crate) fn width(self) -> u8 {
        self.width
    }
    /// The profile at the station's new channel `width` after it followed
    /// the AP (`csa`); 160 MHz needs the peer's 160 MHz set.
    pub(crate) fn retuned(mut self, width: u8) -> Self {
        self.width = if width == 3 && self.peer_mcs_len < 6 {
            2
        } else {
            width
        };
        self.bw160 = self.width == 3;
        self
    }
    /// 40-byte `struct sta_rec_eht` (`mt7925_mcu_sta_eht_tlv`). The
    /// 20 MHz-only map (4 octets) is copied only at 20 MHz — upstream
    /// copies the peer's `only_20mhz` union member there, which for a
    /// wide peer overlaps the first four set octets. The 320 MHz map
    /// stays zero: 320 MHz is refused.
    pub(crate) fn sta(self) -> Vec<u8> {
        let mut out = vec![0u8; 40];
        out[..2].copy_from_slice(&STA_REC_EHT.to_le_bytes());
        out[2] = 40;
        out[4] = 0xff; // tid_bitmap
        out[6..8].copy_from_slice(&self.peer_mac);
        out[8..16].copy_from_slice(&self.peer_phy[..8]);
        out[16] = self.peer_phy[8]; // phy_cap_ext
        if self.width == 0 {
            out[24..28].copy_from_slice(&self.peer_mcs[..4]);
        }
        out[28..31].copy_from_slice(&self.peer_mcs[..3]);
        out[31..34].copy_from_slice(&self.peer_mcs[3..6]);
        out
    }
    /// mac80211 `agg.max_amsdu_len` from the peer's EHT MAC Maximum
    /// MPDU Length (`IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_MASK` = 0xc0:
    /// 0 = 3895, 1 = 7991, 2 = 11454, otherwise 3895).
    /// `ieee80211_eht_cap_ie_to_sta_eht_cap` applies it on 2.4 GHz only
    /// (`net/mac80211/eht.c:80-102`), where it replaces the HT value;
    /// the field is reserved elsewhere.
    pub(crate) fn max_amsdu_len_24(self) -> u16 {
        match (self.peer_mac[0] & 0xc0) >> 6 {
            2 => 11454,
            1 => 7991,
            _ => 3895,
        }
    }
    pub(crate) fn rx_limits(self) -> EhtRx {
        let mcs15 = match self.width {
            0 | 1 => self.local_phy6 & MCS15_20MHZ != 0,
            2 => self.local_phy6 & MCS15_80MHZ != 0,
            _ => self.local_phy6 & MCS15_160MHZ != 0,
        };
        EhtRx {
            nss: self.rx_nss,
            ldpc: self.rx_ldpc,
            stbc: self.rx_stbc,
            mcs15,
        }
    }
}

/// Local EHT receive promises for native P-RXV admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EhtRx {
    /// Per-range local RX max NSS (MCS 0-7, 8-9, 10-11, 12-13).
    pub nss: [u8; 4],
    pub ldpc: bool,
    pub stbc: bool,
    /// The local side advertised EHT MCS 14/15 for the negotiated width.
    pub mcs15: bool,
}

/// `mt7925_mac_fill_rx_rate` EHT modes: EHT_SU (13) and EHT_MU (15) can
/// be addressed to a station; EHT_TRIG (14) is an uplink trigger-based
/// PPDU and is never accepted. MCS is masked to 4 bits and validated
/// <= 13 there; MCS 14/15 are DCM-only, so they are admitted only with
/// the DCM bit, a local MCS 14/15 advertisement and one stream. The
/// rate field carries MCS (bits 0..3), DCM (bit 4) and ER-SU 106-tone
/// (bit 5, HE-only); GI is 0..2.
pub(crate) fn receive_allowed(selected_width: u8, v: u32, rx: EhtRx) -> bool {
    let mode = (v >> 24) & 15;
    let width = (v >> 12) & 7;
    let rate = v & 127;
    let mcs = rate & 15;
    let dcm = rate & 0x10 != 0;
    let nsts = ((v >> 7) & 7) + 1;
    let stbc = (v >> 22) & 3;
    let gi = (v >> 15) & 3;
    if !matches!(mode, 13 | 15)
        || v & (1 << 11) != 0 && !rx.ldpc
        || width > u32::from(selected_width)
        || gi > 2
        || rate & 0x40 != 0
        || rate & 0x20 != 0
    {
        return false;
    }
    if mcs > 13 && (!dcm || !rx.mcs15 || nsts != 1) {
        return false; // MCS 14/15 without DCM, advertisement, or one stream.
    }
    let nss = if stbc == 0 {
        nsts
    } else if rx.stbc && stbc == 1 && nsts == 2 {
        1
    } else {
        return false;
    };
    if mcs <= 13 {
        let range = match mcs {
            0..=7 => 0,
            8 | 9 => 1,
            10 | 11 => 2,
            _ => 3,
        };
        if nss > u32::from(rx.nss[range]) {
            return false;
        }
    }
    true
}
