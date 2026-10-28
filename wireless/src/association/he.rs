// SPDX-License-Identifier: GPL-2.0-or-later
//! HE (IEEE802.11ax-2021) Capabilities/Operation facts and station
//! negotiation for the 2.4/5GHz `JoinPlan` PHY path.
//!
//! Wire layout: IEEE802.11ax-2021 9.4.2.248 (HE Capabilities, element ID
//! extension 35) and 9.4.2.249 (HE Operation, extension 36); Linux
//! include/linux/ieee80211-he.h (`ieee80211_he_mcs_nss_size`,
//! `ieee80211_he_ppe_size`, `ieee80211_he_oper_size`). Negotiation mirrors
//! mac80211 he.c `_ieee80211_he_cap_ie_to_sta_he_cap` /
//! `ieee80211_he_mcs_intersection` and mlme.c `ieee80211_determine_ap_chan`,
//! `ieee80211_verify_peer_he_mcs_support` and
//! `ieee80211_verify_sta_he_mcs_support` (STRICT behaviour). These profiles
//! describe implementation limits; they grant no radio, key, BA or port rights.
use super::phy::{intersect_maps, Width};
use super::{channel, Error};
use alloc::vec::Vec;

/// Element ID extension of HE Capabilities (IEEE802.11ax-2021 Table 9-92).
pub const EXT_HE_CAPABILITIES: u8 = 35;
/// Element ID extension of HE Operation.
pub const EXT_HE_OPERATION: u8 = 36;

const PHY0_40_2G: u8 = 0x02;
const PHY0_40_80_5G: u8 = 0x04;
const PHY0_160_5G: u8 = 0x08;
const PHY0_80P80_5G: u8 = 0x10;
const PHY1_LDPC: u8 = 0x20;
const PHY2_STBC_TX: u8 = 0x04;
const PHY2_STBC_RX: u8 = 0x08;
const PHY3_SU_BEAMFORMER: u8 = 0x80;
const PHY4_SU_BEAMFORMEE: u8 = 0x01;
const PHY4_MU_BEAMFORMER: u8 = 0x02;
const PHY6_PPE_PRESENT: u8 = 0x80;
const MAC0_HTC_HE: u8 = 0x01;
const MAC0_TWT_REQ: u8 = 0x02;
const MAC0_TWT_RES: u8 = 0x04;

const OP_VHT_INFO: u32 = 0x0000_4000;
const OP_CO_HOSTED: u32 = 0x0000_8000;
const OP_ER_SU_DISABLE: u32 = 0x0001_0000;
const OP_6GHZ_INFO: u32 = 0x0002_0000;
const OP_TWT_REQUIRED: u32 = 0x0000_0008;

/// Longest PPE Thresholds field: four RU sizes x eight NSS x two 3-bit
/// values plus the 7-bit header (IEEE802.11ax-2021 9.4.2.248.5).
pub const MAX_PPE: usize = 25;
/// Longest HE Capabilities body including the extension ID octet.
pub const MAX_CAPABILITY: usize = 1 + 6 + 11 + 12 + MAX_PPE;

/// `ieee80211_he_ppe_size`: PPE Thresholds length from its header octet.
fn ppe_size(header: u8) -> usize {
    let ru = (header & 0x78).count_ones() as usize;
    let nss = usize::from(header & 7) + 1;
    (ru * nss * 6 + 7).div_ceil(8)
}
fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}
fn nss1(map: u16) -> bool {
    map & 3 != 3
}
/// Each NSS required by `basic` is present with at least that MCS ceiling.
fn covers(map: u16, basic: u16) -> bool {
    (0..8).all(|n| {
        let (have, need) = (map >> (n * 2) & 3, basic >> (n * 2) & 3);
        need == 3 || have != 3 && have >= need
    })
}

/// Supported HE-MCS and NSS Set maps (IEEE802.11ax-2021 Figure 9-788k).
/// Each map uses the VHT encoding (0=MCS0-7, 1=0-9, 2=0-11, 3=absent).
/// Absent widths are all-`0xffff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeMcsNss {
    pub rx80: u16,
    pub tx80: u16,
    pub rx160: u16,
    pub tx160: u16,
    pub rx80p80: u16,
    pub tx80p80: u16,
}

/// A parsed HE Capabilities element body (after the extension ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeCapability {
    mac: [u8; 6],
    phy: [u8; 11],
    mcs: HeMcsNss,
    ppe: [u8; MAX_PPE],
    ppe_len: u8,
}
impl HeCapability {
    /// Parse a complete element body without the extension-ID octet. The
    /// MCS/NSS set size follows the Channel Width Set (B3/B4) and the PPE
    /// field follows PHY B55; the body must end exactly there.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < 17 + 4 {
            return Err(Error::InvalidBss);
        }
        let mac: [u8; 6] = body[..6].try_into().map_err(|_| Error::InvalidBss)?;
        let phy: [u8; 11] = body[6..17].try_into().map_err(|_| Error::InvalidBss)?;
        fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
            if rest.len() < len {
                return Err(Error::InvalidBss);
            }
            let (out, tail) = rest.split_at(len);
            *rest = tail;
            Ok(out)
        }
        let mut rest = &body[17..];
        let base = take(&mut rest, 4)?;
        let mut mcs = HeMcsNss {
            rx80: le16(&base[..2]),
            tx80: le16(&base[2..]),
            rx160: 0xffff,
            tx160: 0xffff,
            rx80p80: 0xffff,
            tx80p80: 0xffff,
        };
        if phy[0] & PHY0_160_5G != 0 {
            let m = take(&mut rest, 4)?;
            mcs.rx160 = le16(&m[..2]);
            mcs.tx160 = le16(&m[2..]);
        }
        if phy[0] & PHY0_80P80_5G != 0 {
            let m = take(&mut rest, 4)?;
            mcs.rx80p80 = le16(&m[..2]);
            mcs.tx80p80 = le16(&m[2..]);
        }
        let mut ppe = [0; MAX_PPE];
        let mut ppe_len = 0;
        if phy[6] & PHY6_PPE_PRESENT != 0 {
            let header = *rest.first().ok_or(Error::InvalidBss)?;
            let field = take(&mut rest, ppe_size(header))?;
            ppe[..field.len()].copy_from_slice(field);
            ppe_len = field.len() as u8;
        }
        if !rest.is_empty() {
            return Err(Error::InvalidBss);
        }
        Ok(Self {
            mac,
            phy,
            mcs,
            ppe,
            ppe_len,
        })
    }
    pub fn mac_capability(&self) -> [u8; 6] {
        self.mac
    }
    pub fn phy_capability(&self) -> [u8; 11] {
        self.phy
    }
    pub fn mcs_nss(&self) -> HeMcsNss {
        self.mcs
    }
    pub fn ppe_thresholds(&self) -> &[u8] {
        &self.ppe[..usize::from(self.ppe_len)]
    }
    /// Serialize as an element body including the extension-ID octet.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_CAPABILITY);
        out.push(EXT_HE_CAPABILITIES);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.phy);
        out.extend_from_slice(&self.mcs.rx80.to_le_bytes());
        out.extend_from_slice(&self.mcs.tx80.to_le_bytes());
        if self.phy[0] & PHY0_160_5G != 0 {
            out.extend_from_slice(&self.mcs.rx160.to_le_bytes());
            out.extend_from_slice(&self.mcs.tx160.to_le_bytes());
        }
        if self.phy[0] & PHY0_80P80_5G != 0 {
            out.extend_from_slice(&self.mcs.rx80p80.to_le_bytes());
            out.extend_from_slice(&self.mcs.tx80p80.to_le_bytes());
        }
        out.extend_from_slice(self.ppe_thresholds());
        out
    }
    /// Maps for a selected width and segment form.
    fn maps(&self, width: Width, discontiguous: bool) -> (u16, u16) {
        match (width, discontiguous) {
            (Width::OneSixty, false) => (self.mcs.rx160, self.mcs.tx160),
            (Width::OneSixty, true) => (self.mcs.rx80p80, self.mcs.tx80p80),
            _ => (self.mcs.rx80, self.mcs.tx80),
        }
    }
}

/// Local HE implementation facts supplied by a native driver (its station
/// iftype HE capability, e.g. mt76/rtw89/iwlwifi/ath11k sband data). The
/// caller's MAC/PHY octets are copied verbatim except the Channel Width
/// Set 160/80+80 bits and PPE Thresholds Present, which are owned by the
/// checked `with_160mhz`/`with_80p80`/`with_ppe_thresholds` opt-ins so the
/// encoded MCS/NSS and PPE sizes cannot disagree with the PHY bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalHe(HeCapability);
impl LocalHe {
    /// `rx80`/`tx80` must include single-stream HE-MCS0..7 (IEEE802.11ax
    /// 27.1.1). PHY B0/B7 (reserved), B3/B4 (owned by the opt-ins), B55
    /// (PPE present, owned by `with_ppe_thresholds`) and B33 (MU
    /// beamformer, reserved for a non-AP STA) must be clear.
    pub fn new(mac: [u8; 6], phy: [u8; 11], rx80: u16, tx80: u16) -> Result<Self, Error> {
        if !nss1(rx80)
            || !nss1(tx80)
            || phy[0] & (0x01 | 0x80 | PHY0_160_5G | PHY0_80P80_5G) != 0
            || phy[4] & PHY4_MU_BEAMFORMER != 0
            || phy[6] & PHY6_PPE_PRESENT != 0
        {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self(HeCapability {
            mac,
            phy,
            mcs: HeMcsNss {
                rx80,
                tx80,
                rx160: 0xffff,
                tx160: 0xffff,
                rx80p80: 0xffff,
                tx80p80: 0xffff,
            },
            ppe: [0; MAX_PPE],
            ppe_len: 0,
        }))
    }
    /// Advertise contiguous160 (PHY B3) with its own maps. Requires the
    /// 40/80MHz-in-5GHz bit (B2), as a160 STA supports80 (Table 9-322b).
    pub fn with_160mhz(mut self, rx160: u16, tx160: u16) -> Result<Self, Error> {
        if !nss1(rx160) || !nss1(tx160) || self.0.phy[0] & PHY0_40_80_5G == 0 {
            return Err(Error::UnsupportedRates);
        }
        self.0.phy[0] |= PHY0_160_5G;
        self.0.mcs.rx160 = rx160;
        self.0.mcs.tx160 = tx160;
        Ok(self)
    }
    /// Advertise 80+80 (PHY B4) with its own maps; needs `with_160mhz`.
    pub fn with_80p80(mut self, rx: u16, tx: u16) -> Result<Self, Error> {
        if !nss1(rx) || !nss1(tx) || self.0.phy[0] & PHY0_160_5G == 0 {
            return Err(Error::UnsupportedRates);
        }
        self.0.phy[0] |= PHY0_80P80_5G;
        self.0.mcs.rx80p80 = rx;
        self.0.mcs.tx80p80 = tx;
        Ok(self)
    }
    /// Advertise a complete PPE Thresholds field (sets PHY B55). Its length
    /// must equal `ieee80211_he_ppe_size` of the header octet.
    pub fn with_ppe_thresholds(mut self, ppe: &[u8]) -> Result<Self, Error> {
        let header = *ppe.first().ok_or(Error::UnsupportedRates)?;
        if ppe.len() != ppe_size(header) || ppe.len() > MAX_PPE || header & 0x78 == 0 {
            return Err(Error::UnsupportedRates);
        }
        self.0.phy[6] |= PHY6_PPE_PRESENT;
        self.0.ppe = [0; MAX_PPE];
        self.0.ppe[..ppe.len()].copy_from_slice(ppe);
        self.0.ppe_len = ppe.len() as u8;
        Ok(self)
    }
    pub(super) fn width160(&self) -> bool {
        self.0.phy[0] & PHY0_160_5G != 0
    }
    /// The local HE Capabilities body including the extension-ID octet.
    pub fn capability_body(&self) -> Vec<u8> {
        self.0.body()
    }
    pub fn capability(&self) -> &HeCapability {
        &self.0
    }
}

/// A parsed HE Operation body (after the extension ID), 9.4.2.249.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeOperation {
    params: u32,
    basic: u16,
    vht: Option<[u8; 3]>,
    co_hosted: Option<u8>,
    /// 6 GHz Operation Information (`ieee80211_he_6ghz_oper`).
    six_ghz: Option<[u8; 5]>,
}
impl HeOperation {
    /// Exact `ieee80211_he_oper_size` length. Reserved bits are ignored on
    /// reception (IEEE802.11-2020 9.2.2). 6 GHz Operation Information is
    /// parsed into `six_ghz_operation()`; the 2.4/5 GHz `ApElements` path
    /// refuses an element that carries it, and `six_ghz::admit` requires it.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < 6 {
            return Err(Error::InvalidBss);
        }
        let params = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let basic = le16(&body[4..6]);
        let expected = 6
            + if params & OP_VHT_INFO != 0 { 3 } else { 0 }
            + usize::from(params & OP_CO_HOSTED != 0)
            + if params & OP_6GHZ_INFO != 0 { 5 } else { 0 };
        if body.len() != expected {
            return Err(Error::InvalidBss);
        }
        let vht = (params & OP_VHT_INFO != 0).then(|| [body[6], body[7], body[8]]);
        let six_ghz = (params & OP_6GHZ_INFO != 0).then(|| {
            let at = expected - 5;
            [
                body[at],
                body[at + 1],
                body[at + 2],
                body[at + 3],
                body[at + 4],
            ]
        });
        let co_hosted = (params & OP_CO_HOSTED != 0)
            .then(|| body[expected - 1 - if six_ghz.is_some() { 5 } else { 0 }]);
        Ok(Self {
            params,
            basic,
            vht,
            co_hosted,
            six_ghz,
        })
    }
    /// The 6 GHz Operation Information field, when present.
    pub fn six_ghz_operation(&self) -> Option<super::six_ghz::He6GhzOperation> {
        self.six_ghz
            .map(super::six_ghz::He6GhzOperation::from_bytes)
    }
    pub fn default_pe_duration(&self) -> u8 {
        (self.params & 7) as u8
    }
    pub fn twt_required(&self) -> bool {
        self.params & OP_TWT_REQUIRED != 0
    }
    /// TXOP Duration RTS Threshold in32us units (1023 = disabled).
    pub fn txop_rts_threshold(&self) -> u16 {
        (self.params >> 4 & 0x3ff) as u16
    }
    pub fn er_su_disabled(&self) -> bool {
        self.params & OP_ER_SU_DISABLE != 0
    }
    pub fn bss_color(&self) -> u8 {
        (self.params >> 24 & 0x3f) as u8
    }
    pub fn partial_bss_color(&self) -> bool {
        self.params & 0x4000_0000 != 0
    }
    pub fn bss_color_disabled(&self) -> bool {
        self.params & 0x8000_0000 != 0
    }
    /// Basic HE-MCS And NSS Set: tuples every member must TX and RX.
    pub fn basic_mcs_nss(&self) -> u16 {
        self.basic
    }
    pub fn vht_operation_information(&self) -> Option<[u8; 3]> {
        self.vht
    }
    pub fn max_co_hosted_bssid_indicator(&self) -> Option<u8> {
        self.co_hosted
    }
}

const FLAG_LDPC: u8 = 1;
const FLAG_STBC: u8 = 2;
const FLAG_SU_BFEE: u8 = 4;
const FLAG_SU_BFER: u8 = 8;
const FLAG_MU_BFEE: u8 = 16;
const FLAG_HTC: u8 = 32;
const FLAG_TWT: u8 = 64;

/// Directional HE facts for the selected HE operating width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeNegotiation {
    local: LocalHe,
    peer: HeCapability,
    operation: HeOperation,
    width: Width,
    discontiguous: bool,
    tx: u16,
    /// Directional features still permitted by the original offer.
    allowed: u8,
}
impl HeNegotiation {
    /// HE PPDU bandwidth: the shared selection narrowed to both sides' HE
    /// Channel Width Set (mac80211 `ieee80211_sta_cap_rx_bw`).
    pub fn width(&self) -> Width {
        self.width
    }
    /// True when `width()` is an 80+80 selection.
    pub fn discontiguous(&self) -> bool {
        self.discontiguous
    }
    /// Local TX map at `width()` intersected with the AP's RX map.
    pub fn tx_mcs_map(&self) -> u16 {
        self.tx
    }
    /// The local RX promise at `width()`.
    pub fn rx_mcs_map(&self) -> u16 {
        self.local.0.maps(self.width, self.discontiguous).0
    }
    /// The AP's RX/TX maps at `width()`.
    pub fn peer_mcs_maps(&self) -> (u16, u16) {
        self.peer.maps(self.width, self.discontiguous)
    }
    pub fn peer_capability(&self) -> &HeCapability {
        &self.peer
    }
    pub fn operation(&self) -> &HeOperation {
        &self.operation
    }
    pub fn local_capability(&self) -> Vec<u8> {
        self.local.capability_body()
    }
    fn local_phy(&self, byte: usize, bit: u8) -> bool {
        self.local.0.phy[byte] & bit != 0
    }
    fn peer_phy(&self, byte: usize, bit: u8) -> bool {
        self.peer.phy[byte] & bit != 0
    }
    pub fn rx_ldpc(&self) -> bool {
        self.local_phy(1, PHY1_LDPC)
    }
    pub fn tx_ldpc(&self) -> bool {
        self.allowed & FLAG_LDPC != 0 && self.rx_ldpc() && self.peer_phy(1, PHY1_LDPC)
    }
    pub fn rx_stbc(&self) -> bool {
        self.local_phy(2, PHY2_STBC_RX)
    }
    /// Local STBC TX (<=80MHz) and the AP's STBC RX (<=80MHz).
    pub fn tx_stbc(&self) -> bool {
        self.allowed & FLAG_STBC != 0
            && self.local_phy(2, PHY2_STBC_TX)
            && self.peer_phy(2, PHY2_STBC_RX)
    }
    pub fn su_beamformee(&self) -> bool {
        self.allowed & FLAG_SU_BFEE != 0
            && self.local_phy(4, PHY4_SU_BEAMFORMEE)
            && self.peer_phy(3, PHY3_SU_BEAMFORMER)
    }
    pub fn su_beamformer(&self) -> bool {
        self.allowed & FLAG_SU_BFER != 0
            && self.local_phy(3, PHY3_SU_BEAMFORMER)
            && self.peer_phy(4, PHY4_SU_BEAMFORMEE)
    }
    pub fn mu_beamformee(&self) -> bool {
        self.allowed & FLAG_MU_BFEE != 0
            && self.su_beamformee()
            && self.peer_phy(4, PHY4_MU_BEAMFORMER)
    }
    /// Both sides support the HE variant HT Control field.
    pub fn htc_he(&self) -> bool {
        self.allowed & FLAG_HTC != 0
            && self.local.0.mac[0] & MAC0_HTC_HE != 0
            && self.peer.mac[0] & MAC0_HTC_HE != 0
    }
    /// Local TWT requester and AP TWT responder (individual TWT).
    pub fn twt_requester(&self) -> bool {
        self.allowed & FLAG_TWT != 0
            && self.local.0.mac[0] & MAC0_TWT_REQ != 0
            && self.peer.mac[0] & MAC0_TWT_RES != 0
    }
    fn flags(&self) -> u8 {
        [
            (self.tx_ldpc(), FLAG_LDPC),
            (self.tx_stbc(), FLAG_STBC),
            (self.su_beamformee(), FLAG_SU_BFEE),
            (self.su_beamformer(), FLAG_SU_BFER),
            (self.mu_beamformee(), FLAG_MU_BFEE),
            (self.htc_he(), FLAG_HTC),
            (self.twt_requester(), FLAG_TWT),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .fold(0, |flags, (_, flag)| flags | flag)
    }
    /// Bound a response by the original offer: no wider HE width, no TX map
    /// entry or directional feature the scan offer did not already allow.
    pub(super) fn narrow_to(&mut self, old: &HeNegotiation) -> Result<(), Error> {
        let rank = |w: Width| match w {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => 3,
        };
        if rank(self.width) > rank(old.width) {
            return Err(Error::UnsupportedRates);
        }
        if self.width == old.width && self.discontiguous == old.discontiguous {
            self.tx = intersect_maps(self.tx, old.tx);
        }
        self.allowed = old.flags();
        if !nss1(self.tx) || !covers(self.tx, old.operation.basic) {
            return Err(Error::UnsupportedRates);
        }
        Ok(())
    }
}

/// Whether one width pair of the local RX/TX maps covers the AP's basic
/// set (mac80211 `ieee80211_verify_sta_he_mcs_support`, STRICT).
fn local_covers(local: &HeCapability, basic: u16) -> bool {
    [
        (local.mcs.rx80, local.mcs.tx80),
        (local.mcs.rx160, local.mcs.tx160),
        (local.mcs.rx80p80, local.mcs.tx80p80),
    ]
    .iter()
    .any(|(rx, tx)| covers(*rx, basic) && covers(*tx, basic))
}

/// Negotiate HE on an already selected HT/VHT channel. `Ok(None)` disables
/// HE exactly where mac80211 falls back to VHT/HT: no local HE, an AP
/// without HE, a 5GHz BSS without negotiated VHT, mandatory single-stream
/// MCS0..7 missing from the AP, or a Basic HE-MCS/NSS set the AP itself or
/// this station cannot both transmit and receive. Malformed elements are
/// rejected earlier by the element parser.
#[allow(clippy::too_many_arguments)]
pub(super) fn negotiate(
    local: Option<LocalHe>,
    cap: Option<HeCapability>,
    op: Option<HeOperation>,
    primary: u8,
    vht: Option<[u8; 5]>,
    vht_selected: bool,
    width: Width,
    discontiguous: bool,
) -> Result<Option<HeNegotiation>, Error> {
    let (Some(local), Some(peer), Some(operation)) = (local, cap, op) else {
        return Ok(None);
    };
    let band = channel::band(primary).ok_or(Error::InvalidBss)?;
    if let Some(info) = operation.vht {
        // A 2.4GHz HE AP has no VHT channel; on 5GHz the embedded VHT
        // Operation Information must agree with the VHT Operation element
        // that already chose the channel (mac80211 compares the chandefs).
        if band == channel::Band::Ghz2 || vht.is_some_and(|v| v[..3] != info) {
            return Err(Error::InvalidBss);
        }
    }
    if band == channel::Band::Ghz5 && !vht_selected {
        return Ok(None);
    }
    if !nss1(peer.mcs.rx80)
        || !nss1(peer.mcs.tx80)
        || !covers(peer.mcs.rx80, operation.basic)
        || !covers(peer.mcs.tx80, operation.basic)
        || !local_covers(&local.0, operation.basic)
    {
        return Ok(None);
    }
    let (lphy, pphy) = (local.0.phy[0], peer.phy[0]);
    let both = |bit: u8| lphy & pphy & bit != 0;
    let (he_width, he_discontiguous) = match band {
        channel::Band::Ghz2 => match width {
            Width::Forty if both(PHY0_40_2G) => (Width::Forty, false),
            _ => (Width::Twenty, false),
        },
        channel::Band::Ghz5 if !both(PHY0_40_80_5G) => (Width::Twenty, false),
        // `channel::band` never yields 6 GHz; see `six_ghz::admit`.
        channel::Band::Ghz6 => return Err(Error::InvalidBss),
        channel::Band::Ghz5 => match (width, discontiguous) {
            (Width::OneSixty, false) if both(PHY0_160_5G) => (Width::OneSixty, false),
            (Width::OneSixty, true) if both(PHY0_80P80_5G) => (Width::OneSixty, true),
            (Width::OneSixty, _) => (Width::Eighty, false),
            (other, _) => (other, false),
        },
    };
    let (_, local_tx) = local.0.maps(he_width, he_discontiguous);
    let (peer_rx, _) = peer.maps(he_width, he_discontiguous);
    let tx = intersect_maps(local_tx, peer_rx);
    if !nss1(tx) {
        return Ok(None);
    }
    Ok(Some(HeNegotiation {
        local,
        peer,
        operation,
        width: he_width,
        discontiguous: he_discontiguous,
        tx,
        allowed: 0xff,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "he_tests.rs"]
mod tests;
