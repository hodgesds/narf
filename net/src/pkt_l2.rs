//! IEEE 802.1Q VLAN tag + 802.1AB LLDP — clean-room.
//!
//! References (public-only):
//! - **IEEE 802.1Q-2018** — Bridges and Bridged Networks (the
//!   modern public Industrial-Connection edition). §9.6 (TPID
//!   0x8100 for the Customer VLAN tag and 0x88A8 for the
//!   Service VLAN tag / S-tag — "QinQ"). §9.6.2 TCI layout
//!   (PCP / DEI / VID).
//!   <https://standards.ieee.org/ieee/802.1Q/6844/>
//! - **IEEE 802.1AB-2016** — Station and Media Access Control
//!   Connectivity Discovery (LLDP). §8.1 (LLDP EtherType 0x88CC).
//!   §8.4 (TLV format — 7-bit Type + 9-bit Length packed in
//!   the first 2 bytes). §8.5–8.5.4 (mandatory TLVs: Chassis ID,
//!   Port ID, Time-To-Live; End-of-LLDPDU sentinel). §8.5.5–9
//!   (optional TLVs: System Name, System Description, Port
//!   Description, System Capabilities, Management Address).
//!   <https://standards.ieee.org/ieee/802.3/7071/>
//!
//! No GPL Linux source consulted.
//!
//! ## VLAN tag layout (802.1Q §9.6.2)
//!
//! Inserted after the source MAC of the Ethernet frame:
//!
//! ```text
//!   bytes 0..1  TPID (0x8100 = C-VLAN, 0x88A8 = S-VLAN)
//!   bytes 2..3  TCI:
//!     bits 15..13 PCP (Priority Code Point, 0..7)
//!     bit  12    DEI (Drop Eligible Indicator)
//!     bits 11..0 VID (VLAN Identifier, 0..4095; 0 reserved, 1 default,
//!                       4095 reserved)
//! ```
//!
//! ## LLDP frame (802.1AB §8.1)
//!
//! ```text
//!   bytes 0..5    DA = 01:80:C2:00:00:0E (multicast nearest bridge)
//!   bytes 6..11   SA (sender's MAC)
//!   bytes 12..13  EtherType = 0x88CC
//!   bytes 14..N   TLVs … End-of-LLDPDU
//! ```

extern crate alloc;

use alloc::vec::Vec;

// ── VLAN ──────────────────────────────────────────────────────────

pub const TPID_C_VLAN: u16 = 0x8100;
pub const TPID_S_VLAN: u16 = 0x88A8;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VlanTag {
    pub tpid: u16,
    pub pcp: u8,
    pub dei: bool,
    pub vid: u16,
}

impl VlanTag {
    pub fn encode(self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&self.tpid.to_be_bytes());
        let tci = ((self.pcp as u16 & 0x07) << 13)
            | ((self.dei as u16) << 12)
            | (self.vid & 0x0FFF);
        out[2..4].copy_from_slice(&tci.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let tpid = u16::from_be_bytes([buf[0], buf[1]]);
        let tci = u16::from_be_bytes([buf[2], buf[3]]);
        Some(Self {
            tpid,
            pcp: ((tci >> 13) & 0x07) as u8,
            dei: ((tci >> 12) & 0x01) != 0,
            vid: tci & 0x0FFF,
        })
    }
}

// ── LLDP ──────────────────────────────────────────────────────────

pub const ETHERTYPE_LLDP: u16 = 0x88CC;
pub const LLDP_DEST_MAC_NEAREST_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

// Mandatory + commonly-used TLV types (802.1AB §8.5).
pub const TLV_END_OF_LLDPDU: u8 = 0;
pub const TLV_CHASSIS_ID: u8 = 1;
pub const TLV_PORT_ID: u8 = 2;
pub const TLV_TTL: u8 = 3;
pub const TLV_PORT_DESCRIPTION: u8 = 4;
pub const TLV_SYSTEM_NAME: u8 = 5;
pub const TLV_SYSTEM_DESCRIPTION: u8 = 6;
pub const TLV_SYSTEM_CAPABILITIES: u8 = 7;
pub const TLV_MANAGEMENT_ADDRESS: u8 = 8;

// Chassis ID subtypes (802.1AB §8.5.2.2).
pub const CHASSIS_ID_CHASSIS_COMPONENT: u8 = 1;
pub const CHASSIS_ID_INTERFACE_ALIAS: u8 = 2;
pub const CHASSIS_ID_PORT_COMPONENT: u8 = 3;
pub const CHASSIS_ID_MAC_ADDRESS: u8 = 4;
pub const CHASSIS_ID_NETWORK_ADDRESS: u8 = 5;
pub const CHASSIS_ID_INTERFACE_NAME: u8 = 6;
pub const CHASSIS_ID_LOCALLY_ASSIGNED: u8 = 7;

// Port ID subtypes (802.1AB §8.5.3.2).
pub const PORT_ID_INTERFACE_ALIAS: u8 = 1;
pub const PORT_ID_PORT_COMPONENT: u8 = 2;
pub const PORT_ID_MAC_ADDRESS: u8 = 3;
pub const PORT_ID_NETWORK_ADDRESS: u8 = 4;
pub const PORT_ID_INTERFACE_NAME: u8 = 5;
pub const PORT_ID_AGENT_CIRCUIT_ID: u8 = 6;
pub const PORT_ID_LOCALLY_ASSIGNED: u8 = 7;

// System Capabilities bits (802.1AB §8.5.8.2 table 8-4).
pub const CAP_OTHER: u16 = 1 << 0;
pub const CAP_REPEATER: u16 = 1 << 1;
pub const CAP_MAC_BRIDGE: u16 = 1 << 2;
pub const CAP_WLAN_AP: u16 = 1 << 3;
pub const CAP_ROUTER: u16 = 1 << 4;
pub const CAP_TELEPHONE: u16 = 1 << 5;
pub const CAP_DOCSIS_CABLE: u16 = 1 << 6;
pub const CAP_STATION_ONLY: u16 = 1 << 7;
pub const CAP_CVLAN_COMPONENT: u16 = 1 << 8;
pub const CAP_SVLAN_COMPONENT: u16 = 1 << 9;
pub const CAP_TWO_PORT_MAC_RELAY: u16 = 1 << 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LldpError {
    Short,
    Truncated,
    /// TTL TLV body wasn't 2 bytes per §8.5.4.
    BadTtl,
}

// ── TLV iterator + builder ────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LldpTlv<'a> {
    pub typ: u8,
    pub data: &'a [u8],
}

/// Walk LLDP TLVs starting at `buf[14..]` (i.e. past the Ethernet
/// header). Stops on End-of-LLDPDU.
pub fn iter_tlvs(mut buf: &[u8]) -> impl Iterator<Item = Result<LldpTlv<'_>, LldpError>> {
    core::iter::from_fn(move || {
        if buf.len() < 2 {
            if buf.is_empty() {
                return None;
            } else {
                buf = &[];
                return Some(Err(LldpError::Short));
            }
        }
        let header = u16::from_be_bytes([buf[0], buf[1]]);
        let typ = (header >> 9) as u8;
        let len = (header & 0x01FF) as usize;
        if 2 + len > buf.len() {
            buf = &[];
            return Some(Err(LldpError::Truncated));
        }
        let data = &buf[2..2 + len];
        let consumed = 2 + len;
        buf = &buf[consumed..];
        if typ == TLV_END_OF_LLDPDU {
            return None;
        }
        Some(Ok(LldpTlv { typ, data }))
    })
}

/// Append a TLV (7-bit Type + 9-bit Length packed BE in 2 bytes,
/// then body) to `out`.
pub fn append_tlv(out: &mut Vec<u8>, typ: u8, data: &[u8]) {
    let header: u16 = ((typ as u16 & 0x7F) << 9) | (data.len() as u16 & 0x01FF);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(data);
}

/// Append the End-of-LLDPDU sentinel.
pub fn append_end_of_lldpdu(out: &mut Vec<u8>) {
    append_tlv(out, TLV_END_OF_LLDPDU, &[]);
}

/// Build the body of a Chassis ID TLV — `subtype` + identifier bytes.
pub fn append_chassis_id(out: &mut Vec<u8>, subtype: u8, id: &[u8]) {
    let mut body = Vec::with_capacity(1 + id.len());
    body.push(subtype);
    body.extend_from_slice(id);
    append_tlv(out, TLV_CHASSIS_ID, &body);
}

/// Build the body of a Port ID TLV.
pub fn append_port_id(out: &mut Vec<u8>, subtype: u8, id: &[u8]) {
    let mut body = Vec::with_capacity(1 + id.len());
    body.push(subtype);
    body.extend_from_slice(id);
    append_tlv(out, TLV_PORT_ID, &body);
}

/// Build a TTL TLV — body is a 2-byte BE u16 (in seconds).
pub fn append_ttl(out: &mut Vec<u8>, ttl_secs: u16) {
    append_tlv(out, TLV_TTL, &ttl_secs.to_be_bytes());
}

/// Build a System Capabilities TLV (4 bytes — capabilities + enabled).
pub fn append_system_capabilities(out: &mut Vec<u8>, capabilities: u16, enabled: u16) {
    let mut body = [0u8; 4];
    body[0..2].copy_from_slice(&capabilities.to_be_bytes());
    body[2..4].copy_from_slice(&enabled.to_be_bytes());
    append_tlv(out, TLV_SYSTEM_CAPABILITIES, &body);
}

/// Decode the body of a TTL TLV into seconds.
pub fn parse_ttl(body: &[u8]) -> Result<u16, LldpError> {
    if body.len() != 2 {
        return Err(LldpError::BadTtl);
    }
    Ok(u16::from_be_bytes([body[0], body[1]]))
}
