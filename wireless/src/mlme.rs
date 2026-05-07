//! IEEE 802.11 MAC Layer Management Entity (MLME) framing.
//!
//! Spec: IEEE Std 802.11-2020, §9 (Frame Formats). Public IEEE
//! standard. No GPL Linux `net/mac80211/` source consulted.
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//!
//! Today's surface is the parser/builder for the management frames a
//! station emits/consumes during association: Beacon, Probe Request /
//! Response, Authentication, Association Request / Response,
//! Deauthentication, Disassociation. Data-frame tagging + QoS fields
//! land alongside the first vendor-clean-room driver.
//!
//! ## Frame layout (§9.2.4)
//!
//! Every 802.11 frame starts with a Frame Control word + Duration +
//! Address fields:
//!
//! ```text
//!   0..2 : Frame Control (LE)
//!   2..4 : Duration / ID
//!   4..10:  Address1 (RA / DA)
//!   10..16: Address2 (TA / SA)
//!   16..22: Address3 (BSSID)
//!   22..24: Sequence Control (SeqNum<<4 | Frag)
//!   24..N : Frame body (management-frame fixed fields + IEs)
//! ```
//!
//! Frame Control bits (§9.2.4.1):
//!
//! ```text
//!   0..2  : Protocol Version (always 0 today)
//!   2..4  : Type        — 0 mgmt, 1 ctrl, 2 data, 3 extended
//!   4..8  : Subtype     — meaning depends on Type
//!   8     : ToDS
//!   9     : FromDS
//!   10    : MoreFrag
//!   11    : Retry
//!   12    : PowerMgmt
//!   13    : MoreData
//!   14    : Protected (WEP/WPA/WPA2/WPA3)
//!   15    : +HTC / Order
//! ```

use alloc::vec::Vec;

/// 802.11 frame Type field (§9.2.4.1.3).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameType {
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3,
}

/// Management-frame subtypes we care about (§9.2.4.1.3, table 9-1).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MgmtSubtype {
    AssociationRequest = 0x0,
    AssociationResponse = 0x1,
    ReassociationRequest = 0x2,
    ReassociationResponse = 0x3,
    ProbeRequest = 0x4,
    ProbeResponse = 0x5,
    Beacon = 0x8,
    Atim = 0x9,
    Disassociation = 0xA,
    Authentication = 0xB,
    Deauthentication = 0xC,
    Action = 0xD,
}

impl MgmtSubtype {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x0 => Self::AssociationRequest,
            0x1 => Self::AssociationResponse,
            0x2 => Self::ReassociationRequest,
            0x3 => Self::ReassociationResponse,
            0x4 => Self::ProbeRequest,
            0x5 => Self::ProbeResponse,
            0x8 => Self::Beacon,
            0x9 => Self::Atim,
            0xA => Self::Disassociation,
            0xB => Self::Authentication,
            0xC => Self::Deauthentication,
            0xD => Self::Action,
            _ => return None,
        })
    }
}

/// Frame Control word (§9.2.4.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: FrameType,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_frag: bool,
    pub retry: bool,
    pub power_mgmt: bool,
    pub more_data: bool,
    pub protected: bool,
    pub order: bool,
}

impl FrameControl {
    pub fn mgmt(subtype: MgmtSubtype) -> Self {
        Self {
            protocol_version: 0,
            frame_type: FrameType::Management,
            subtype: subtype as u8,
            to_ds: false,
            from_ds: false,
            more_frag: false,
            retry: false,
            power_mgmt: false,
            more_data: false,
            protected: false,
            order: false,
        }
    }

    pub fn encode(&self) -> u16 {
        ((self.protocol_version as u16) & 0x3)
            | (((self.frame_type as u16) & 0x3) << 2)
            | (((self.subtype as u16) & 0xF) << 4)
            | ((self.to_ds as u16) << 8)
            | ((self.from_ds as u16) << 9)
            | ((self.more_frag as u16) << 10)
            | ((self.retry as u16) << 11)
            | ((self.power_mgmt as u16) << 12)
            | ((self.more_data as u16) << 13)
            | ((self.protected as u16) << 14)
            | ((self.order as u16) << 15)
    }

    pub fn decode(raw: u16) -> Self {
        Self {
            protocol_version: (raw & 0x3) as u8,
            frame_type: match (raw >> 2) & 0x3 {
                0 => FrameType::Management,
                1 => FrameType::Control,
                2 => FrameType::Data,
                _ => FrameType::Extension,
            },
            subtype: ((raw >> 4) & 0xF) as u8,
            to_ds: (raw >> 8) & 0x1 != 0,
            from_ds: (raw >> 9) & 0x1 != 0,
            more_frag: (raw >> 10) & 0x1 != 0,
            retry: (raw >> 11) & 0x1 != 0,
            power_mgmt: (raw >> 12) & 0x1 != 0,
            more_data: (raw >> 13) & 0x1 != 0,
            protected: (raw >> 14) & 0x1 != 0,
            order: (raw >> 15) & 0x1 != 0,
        }
    }
}

/// 6-byte MAC address.
pub type MacAddr = [u8; 6];

/// Decoded 802.11 management frame header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MgmtHeader {
    pub fc: FrameControl,
    pub duration: u16,
    pub addr1: MacAddr,
    pub addr2: MacAddr,
    pub addr3: MacAddr,
    pub seq_ctrl: u16,
}

impl MgmtHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let raw = self.fc.encode();
        out.push((raw & 0xFF) as u8);
        out.push((raw >> 8) as u8);
        out.push((self.duration & 0xFF) as u8);
        out.push((self.duration >> 8) as u8);
        out.extend_from_slice(&self.addr1);
        out.extend_from_slice(&self.addr2);
        out.extend_from_slice(&self.addr3);
        out.push((self.seq_ctrl & 0xFF) as u8);
        out.push((self.seq_ctrl >> 8) as u8);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        let fc = FrameControl::decode(u16::from_le_bytes([buf[0], buf[1]]));
        let duration = u16::from_le_bytes([buf[2], buf[3]]);
        let mut addr1 = [0u8; 6];
        let mut addr2 = [0u8; 6];
        let mut addr3 = [0u8; 6];
        addr1.copy_from_slice(&buf[4..10]);
        addr2.copy_from_slice(&buf[10..16]);
        addr3.copy_from_slice(&buf[16..22]);
        let seq_ctrl = u16::from_le_bytes([buf[22], buf[23]]);
        Some(Self {
            fc,
            duration,
            addr1,
            addr2,
            addr3,
            seq_ctrl,
        })
    }
}

// ── Information Element (IE / TLV) helpers (§9.4.2) ───────────────

/// Common Element IDs (§9.4.2 table 9-92). Not exhaustive — extended
/// as the MLME consumer set grows.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElementId {
    Ssid = 0,
    SupportedRates = 1,
    DsParameterSet = 3,
    Tim = 5,
    Country = 7,
    HtCapabilities = 45,
    RsnInformation = 48,
    ExtendedRates = 50,
    HtOperation = 61,
    VhtCapabilities = 191,
    VhtOperation = 192,
    VendorSpecific = 221,
}

/// Single Information Element. `id` + `body` carry the spec's
/// "Element ID + Length + Variable-length body" layout (§9.4.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InformationElement<'a> {
    pub id: u8,
    pub body: &'a [u8],
}

/// Iterate IEs out of `buf`. Stops on truncation.
pub fn iter_ies(buf: &[u8]) -> IeIter<'_> {
    IeIter { buf }
}

#[derive(Clone, Debug)]
pub struct IeIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for IeIter<'a> {
    type Item = InformationElement<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 2 {
            return None;
        }
        let id = self.buf[0];
        let len = self.buf[1] as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let body = &self.buf[2..2 + len];
        self.buf = &self.buf[2 + len..];
        Some(InformationElement { id, body })
    }
}

/// Encode an IE: `[ID, len, body...]`.
pub fn write_ie(out: &mut Vec<u8>, id: ElementId, body: &[u8]) {
    out.push(id as u8);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

// ── Management-frame builders ─────────────────────────────────────

/// Construct a Probe Request frame body. The caller supplies the
/// requested SSID (empty for wildcard) and a `SupportedRates` IE
/// payload (typical mandatory rates: `[0x82, 0x84, 0x8B, 0x96]` for
/// 1/2/5.5/11 Mbps).
pub fn build_probe_request_body(ssid: &[u8], supported_rates: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + ssid.len() + 2 + supported_rates.len());
    write_ie(&mut body, ElementId::Ssid, ssid);
    write_ie(&mut body, ElementId::SupportedRates, supported_rates);
    body
}

/// Construct an Authentication frame body for Open System (algorithm
/// 0, sequence 1, status 0). Subsequent transactions in WPA3-SAE use
/// algorithm 3 with multi-step exchanges; that lands when SAE is wired.
pub fn build_open_auth_request() -> Vec<u8> {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&0u16.to_le_bytes()); // Algorithm = Open
    body.extend_from_slice(&1u16.to_le_bytes()); // Sequence = 1
    body.extend_from_slice(&0u16.to_le_bytes()); // Status = success placeholder
    body
}

/// Decoded Authentication frame fixed-fields.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AuthFields {
    pub algorithm: u16,
    pub sequence: u16,
    pub status: u16,
}

impl AuthFields {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        Some(Self {
            algorithm: u16::from_le_bytes([buf[0], buf[1]]),
            sequence: u16::from_le_bytes([buf[2], buf[3]]),
            status: u16::from_le_bytes([buf[4], buf[5]]),
        })
    }
}

/// Decoded Beacon / Probe-Response fixed-fields (§9.3.3.3 + §9.3.3.10).
/// Both share a 12-byte fixed header: timestamp / interval / capability.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BeaconFixedFields {
    pub timestamp: u64,
    pub beacon_interval_tu: u16,
    pub capability_info: u16,
}

impl BeaconFixedFields {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let ts = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let bi = u16::from_le_bytes([buf[8], buf[9]]);
        let cap = u16::from_le_bytes([buf[10], buf[11]]);
        Some(Self {
            timestamp: ts,
            beacon_interval_tu: bi,
            capability_info: cap,
        })
    }
}

/// Convenience: scan a Beacon body and pull out `(SSID, channel)`.
/// SSID comes from element id 0; channel from the DS Parameter Set
/// (id 3, single-byte body).
pub fn beacon_ssid_channel(body: &[u8]) -> Option<(&[u8], Option<u8>)> {
    if body.len() < 12 {
        return None;
    }
    let mut ssid: Option<&[u8]> = None;
    let mut channel: Option<u8> = None;
    for ie in iter_ies(&body[12..]) {
        if ie.id == ElementId::Ssid as u8 {
            ssid = Some(ie.body);
        }
        if ie.id == ElementId::DsParameterSet as u8 && ie.body.len() == 1 {
            channel = Some(ie.body[0]);
        }
    }
    Some((ssid?, channel))
}
