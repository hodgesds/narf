//! Bounded5-GHz CONNAC2 VHT RX/TX1/2 profile and native records.
//! Linux mt7921_init_work/mt76_init_sband register <=80-MHz VHT, with
//! contiguous160 only for actual MT7922. NIC TLVs must still report
//! HT/VHT/5GHz/NSS. max_bw stays an opaque byte.
use super::{
    association::TxPermission,
    firmware_transport::{Error, RadioInfo},
};
use alloc::{vec, vec::Vec};
use narf_wireless::association::phy::{
    self, ApElements, HtGi, HtWidth, LocalHt, LocalPhy, LocalVht,
};

pub(crate) fn qualified(info: RadioInfo) -> bool {
    let caps = info.capabilities.phy;
    caps.ht && caps.vht && caps.bands & 2 != 0 && (1..=2).contains(&caps.spatial_streams)
}
pub(crate) fn local(info: RadioInfo) -> Result<LocalPhy, Error> {
    if !qualified(info) {
        return Err(Error::UnsupportedFirmware);
    }
    let ht = local_ht(info);
    let vht = local_vht(info, true)?;
    if wide160(info) {
        LocalPhy::vht160(ht, vht).map_err(|_| Error::UnsupportedFirmware)
    } else {
        LocalPhy::vht80(ht, vht).map_err(|_| Error::UnsupportedFirmware)
    }
}
pub(crate) fn local80(info: RadioInfo) -> Result<LocalPhy, Error> {
    if !qualified(info) {
        return Err(Error::UnsupportedFirmware);
    }
    LocalPhy::vht80(local_ht(info), local_vht(info, false)?).map_err(|_| Error::UnsupportedFirmware)
}
pub(crate) fn wide160(info: RadioInfo) -> bool {
    qualified(info) && info.chip_id == 0x7922
}
fn local_vht(info: RadioInfo, allow160: bool) -> Result<LocalVht, Error> {
    let mut vht = LocalVht::new(rx_map(info), rx_map(info), true, true, 0)
        .map_err(|_| Error::UnsupportedFirmware)?
        .with_ldpc(info.capabilities.phy.rx_ldpc, info.capabilities.phy.tx_ldpc)
        .with_rx_stbc(info.capabilities.phy.rx_stbc)
        .with_tx_stbc(tx_stbc(info))
        // mt792x_core.c sets SUPPORTS_VHT_EXT_NSS_BW for every family member.
        .with_extended_nss_bw(true)
        // mt7921/init.c: SU and MU beamformee with BEAMFORMEE_STS field 3
        // (four space-time streams). Sounding feedback is firmware-owned;
        // the host hands it the peer beamformer facts in STA_REC_VHT.
        .with_beamforming(phy::VhtBeamforming {
            su_beamformee_sts: Some(4),
            su_beamformer_sounding: None,
            mu_beamformee: true,
        })
        .map_err(|_| Error::UnsupportedFirmware)?;
    if allow160 && wide160(info) {
        vht = vht.with_160mhz(true, true);
    }
    Ok(vht)
}
fn local_ht(info: RadioInfo) -> LocalHt {
    let mut tx = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if info.capabilities.phy.spatial_streams == 2 {
        tx[1] = 255;
    }
    let rx = tx;
    LocalHt::new(
        rx,
        tx,
        HtWidth::TwentyForty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: true,
            tx40: true,
        },
        0,
        7,
    )
    .expect("fixed implemented HT companion profile")
    .with_ldpc(info.capabilities.phy.rx_ldpc, info.capabilities.phy.tx_ldpc)
    .with_rx_stbc(info.capabilities.phy.rx_stbc)
    .with_tx_stbc(tx_stbc(info))
    .with_greenfield(true, true)
}
/// mt76_init_stream_cap (mac80211.c): HT TX_STBC and VHT TXSTBC are
/// advertised exactly when more than one TX stream exists; firmware rate
/// control then applies STBC to a peer whose RX STBC field survives
/// mac80211's own-TX-STBC masking (ht.c/vht.c *_cap_ie_to_sta_*_cap).
fn tx_stbc(info: RadioInfo) -> bool {
    info.capabilities.phy.spatial_streams > 1
}
pub(crate) fn ht_capability(info: RadioInfo) -> [u8; 26] {
    local_ht(info).capability_body()
}
pub(crate) fn ht_fallback(info: RadioInfo, wide: bool) -> Result<LocalPhy, Error> {
    if !info.capabilities.phy.ht || !(1..=2).contains(&info.capabilities.phy.spatial_streams) {
        return Err(Error::UnsupportedFirmware);
    }
    if wide {
        LocalPhy::ht40(local_ht(info)).map_err(|_| Error::UnsupportedFirmware)
    } else {
        let mut tx = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        if info.capabilities.phy.spatial_streams == 2 {
            tx[1] = 255;
        }
        let rx = tx;
        let ht = LocalHt::new(
            rx,
            tx,
            HtWidth::Twenty,
            HtGi {
                rx20: true,
                tx20: true,
                rx40: false,
                tx40: false,
            },
            0,
            7,
        )
        .map_err(|_| Error::UnsupportedFirmware)?
        .with_ldpc(info.capabilities.phy.rx_ldpc, info.capabilities.phy.tx_ldpc)
        .with_rx_stbc(info.capabilities.phy.rx_stbc)
        .with_tx_stbc(tx_stbc(info));
        let ht = ht.with_greenfield(true, true);
        LocalPhy::ht20(ht).map_err(|_| Error::UnsupportedFirmware)
    }
}
pub(crate) fn capability(info: RadioInfo) -> Option<[u8; 12]> {
    qualified(info)
        .then(|| local_vht(info, true).map(|vht| vht.capability_body()).ok())
        .flatten()
}
fn rx_map(info: RadioInfo) -> u16 {
    if info.capabilities.phy.spatial_streams == 2 {
        0xfffa
    } else {
        0xfffe
    }
}

/// The radio map describes MCS0..9, but one spatial stream has no valid
/// MCS9 encoding at20MHz. Keep this native selection constraint separate
/// from the local advertised RX/TX maps and from the AP's original facts.
/// Linux rc80211_minstrel_ht::minstrel_get_valid_vht_rates applies the same
/// width/NSS matrix; no LDPC exception exists for one stream.
fn width_map(width: phy::Width, streams: u8) -> u16 {
    match (width, streams) {
        (phy::Width::Twenty, 2) => 0xfff5,
        (phy::Width::Twenty, _) => 0xfffd,
        (_, 2) => 0xfffa,
        (_, _) => 0xfffe,
    }
}
fn supports_basic(map: u16, basic: u16) -> bool {
    (0..8).all(|n| {
        let have = map >> (n * 2) & 3;
        let need = basic >> (n * 2) & 3;
        need == 3 || have != 3 && have >= need
    })
}
fn streams(map: u16) -> u8 {
    if map >> 2 & 3 != 3 {
        2
    } else {
        1
    }
}
fn transmit_map(width: phy::Width, map: u16, ht_capability: u16) -> u16 {
    let nss = if matches!(ht_capability & 12, 4 | 12) {
        streams(map)
    } else {
        1
    };
    phy::intersect_maps(map, width_map(width, nss))
}
fn check_basic(width: phy::Width, tx: u16, rx: u16, operation: [u8; 5]) -> Result<(), Error> {
    let basic = u16::from_le_bytes([operation[3], operation[4]]);
    if !supports_basic(
        phy::intersect_maps(tx, width_map(width, streams(tx))),
        basic,
    ) || !supports_basic(
        phy::intersect_maps(rx, width_map(width, streams(rx))),
        basic,
    ) {
        return Err(Error::UnsupportedFirmware);
    }
    Ok(())
}
pub(crate) fn check_offer(offer: &phy::Offer) -> Result<(), Error> {
    if let Some(vht) = offer.vht() {
        check_basic(
            offer.width(),
            transmit_map(
                offer.width(),
                vht.tx_mcs_map(),
                offer.ht().peer_capability(),
            ),
            vht.rx_mcs_map(),
            vht.operation_body(),
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    ap: ApElements,
    capability: u32,
    peer_rx: u16,
    peer_tx: u16,
    width: u8,
    center: u8,
    rx_streams: u8,
    tx_streams: u8,
    rx_ldpc: bool,
    rx_stbc: bool,
    rx_greenfield: bool,
    /// Peer VHT Maximum MPDU Length field (bits 0..1).
    peer_mpdu: u8,
}
impl Profile {
    pub(crate) fn negotiated(
        n: &phy::Negotiated,
        offer: &phy::Offer,
        ies: &[u8],
    ) -> Result<Self, Error> {
        let vht = n.vht().ok_or(Error::UnsupportedFirmware)?;
        // HT protection modes 1-3 are firmware-owned on CONNAC2 (see
        // ht20::DYNAMIC_OPERATION); nothing native depends on mode 0.
        let width = match n.width() {
            phy::Width::Twenty => 0,
            phy::Width::Forty => 1,
            phy::Width::Eighty => 2,
            phy::Width::OneSixty => 3,
        };
        let peer_rx = transmit_map(n.width(), vht.tx_mcs_map(), n.ht().peer_capability());
        // A narrowed response must still meet both original and response
        // basic requirements at the actual width. Never silently strip a
        // required MCS9 while capping a20MHz native rate-control map.
        check_basic(n.width(), peer_rx, vht.rx_mcs_map(), vht.operation_body())?;
        check_basic(
            n.width(),
            peer_rx,
            vht.rx_mcs_map(),
            offer
                .vht()
                .ok_or(Error::UnsupportedFirmware)?
                .operation_body(),
        )?;
        let rx_streams = if vht.rx_mcs_map() >> 2 & 3 != 3 { 2 } else { 1 };
        let rx_valid = width_map(n.width(), rx_streams);
        let offered = offer.vht().ok_or(Error::UnsupportedFirmware)?;
        Ok(Self {
            ap: ApElements::parse(ies).map_err(|_| Error::Bounds)?,
            // Peer receive aggregation limit and transmit SGI intersection.
            // The native LDPC flag is local TX use of the AP's independently
            // bounded RX bit; the peer RXSTBC field survives only with local
            // TXSTBC (mac80211 ieee80211_vht_cap_ie_to_sta_vht_cap), which is
            // what STA_REC_VHT hands firmware rate control.
            capability: (vht.peer_capability() & (7 << 23))
                | if vht.tx_stbc() {
                    vht.peer_capability() & (7 << 8)
                } else {
                    0
                }
                // Local SU/MU beamformee keeps the peer's SU beamformer,
                // sounding dimensions and MU beamformer bits; hardware
                // EXT_NSS_BW support keeps its Extended NSS BW field.
                | (vht.peer_capability() & ((1 << 11) | (7 << 16) | (1 << 19) | (3 << 30)))
                | (u32::from(vht.tx_sgi80()) << 5)
                | (u32::from(vht.tx_ldpc()) << 4)
                | if width == 3 {
                    4 | (u32::from(vht.tx_sgi160()) << 6)
                } else {
                    0
                },
            peer_rx,
            peer_tx: phy::intersect_maps(
                phy::intersect_maps(
                    phy::intersect_maps(vht.rx_mcs_map(), vht.peer_tx_mcs_map()),
                    offered.peer_tx_mcs_map(),
                ),
                rx_valid,
            ),
            width,
            center: n.center_channel(),
            rx_streams,
            tx_streams: streams(peer_rx)
                .max(super::ht20::Profile::from_shared(n.ht(), width).transmit_streams()),
            rx_ldpc: vht.rx_ldpc(),
            rx_stbc: vht.rx_stbc(),
            rx_greenfield: n.ht().rx_greenfield(),
            peer_mpdu: (vht.peer_capability() & 3) as u8,
        })
    }
    pub(crate) fn width(self) -> u8 {
        self.width
    }
    pub(crate) fn center(self) -> u8 {
        self.center
    }
    /// mac80211 vht.c `agg.max_amsdu_len` (overrides the HT value).
    pub(crate) fn max_amsdu_len(self) -> u16 {
        match self.peer_mpdu {
            2 => 11454,
            1 => 7991,
            _ => 3895,
        }
    }
    pub(crate) fn ampdu_factor(self) -> u8 {
        ((self.capability >> 23) & 7) as u8
    }
    pub(crate) fn matches(self, ies: &[u8]) -> bool {
        ApElements::parse(ies).is_ok_and(|ap| super::ht20::same_ap_phy(&self.ap, &ap))
    }
    pub(crate) fn state(self) -> u8 {
        self.width | ((self.tx_streams - 1) << 4)
    }
    pub(crate) fn transmit_streams(self) -> u8 {
        self.tx_streams
    }
    pub(crate) fn sta(self) -> Vec<u8> {
        let mut bytes = vec![10, 0, 16, 0]; // CONNAC2 retains the four-byte tail.
        bytes.extend_from_slice(&self.capability.to_le_bytes());
        bytes.extend_from_slice(&self.peer_rx.to_le_bytes());
        bytes.extend_from_slice(&self.peer_tx.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }
    pub(crate) fn wtbl(self) -> [u8; 12] {
        [
            3,
            0,
            12,
            0,
            u8::from(self.capability & (1 << 4) != 0),
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]
    }
    pub(crate) fn rlm(self, primary: u8, chains: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[4..8].copy_from_slice(&[2, 0, 16, 0]);
        bytes[8] = primary;
        bytes[9] = self.center;
        bytes[11] = self.width;
        bytes[12] = self.tx_streams;
        bytes[13] = chains;
        bytes[14] = 1;
        bytes[15] = if self.width != 0 { 4 } else { 0 };
        bytes[16] = if primary < self.center {
            1
        } else if primary > self.center {
            3
        } else {
            0
        };
        bytes[17] = 1;
        bytes
    }
    pub(crate) fn permits(self, p: TxPermission) -> bool {
        self.width == p.native_width() && self.center == p.center_channel()
    }
    pub(crate) fn receive_allowed(self, phy: Option<u32>) -> bool {
        receive_allowed(
            self.width,
            phy,
            true,
            RxLimits {
                streams: self.rx_streams,
                ldpc: self.rx_ldpc,
                stbc: self.rx_stbc,
                greenfield: self.rx_greenfield,
                cck: false,
            },
        )
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RxLimits {
    pub streams: u8,
    pub ldpc: bool,
    pub stbc: bool,
    pub greenfield: bool,
    pub cck: bool,
}
pub(crate) fn receive_allowed(
    selected_width: u8,
    phy: Option<u32>,
    vht: bool,
    limits: RxLimits,
) -> bool {
    let Some(v) = phy else {
        return true;
    };
    let mode = (v >> 24) & 15;
    let width = (v >> 12) & 7;
    let rate = v & 127;
    let nsts = ((v >> 7) & 7) + 1;
    let stbc = (v >> 22) & 3;
    if v & (1 << 11) != 0 && !limits.ldpc || width > u32::from(selected_width) {
        return false;
    }
    // RXSTBC1 promises one data stream encoded into exactly two space-time
    // streams. NSTS is not data NSS. Larger/reserved STBC encodings need a
    // distinct local promise and decoder; no TX capability is inferred.
    let nss = if stbc == 0 {
        nsts
    } else if limits.stbc && stbc == 1 && nsts == 2 {
        1
    } else {
        return false;
    };
    match mode {
        // mt76_get_rate removes bit2 (short preamble) from CCK codes0..7.
        // This legacy mode remains valid for a typed HT peer on2.4GHz;
        // neither a5GHz station nor VHT can acquire it through PHY fallback.
        0 => {
            limits.cck
                && !vht
                && rate < 8
                && nsts == 1
                && width == 0
                && (v >> 15) & 3 == 0
                && v & (1 << 11) == 0
                && stbc == 0
        }
        1 => {
            width == 0
                && (8..=15).contains(&rate)
                && (v >> 15) & 3 == 0
                && v & (1 << 11) == 0
                && stbc == 0
        }
        // Native OFDM hardware codes8..15; basic6Mbps is11.
        2 | 3 => {
            (mode != 3 || limits.greenfield)
                && nss <= u32::from(limits.streams)
                && nss == rate / 8 + 1
                && rate < u32::from(limits.streams) * 8
                && width <= 1
                && (v >> 15) & 3 <= 1
        }
        4 => {
            vht && nss <= u32::from(limits.streams)
                && rate <= (if width == 0 { 8 } else { 9 })
                && (v >> 15) & 3 <= 1
        }
        _ => false, // no HE or unimplemented optional mode.
    }
}
