//! ICMPv4 error/redirect messages + IGMPv3 — clean-room.
//!
//! References (public-only):
//! - RFC 792 — Internet Control Message Protocol (J. Postel, Sep
//!   1981). Destination Unreachable (type 3), Source Quench (type 4
//!   — deprecated by RFC 6633 but still emitted by some hosts), Time
//!   Exceeded (type 11), Parameter Problem (type 12), Redirect
//!   (type 5).
//!   <https://datatracker.ietf.org/doc/html/rfc792>
//! - RFC 1191 — Path MTU Discovery — surfaces the "next-hop MTU"
//!   that lives in the bottom 16 bits of the unused header field of
//!   a fragmentation-needed Destination Unreachable.
//!   <https://datatracker.ietf.org/doc/html/rfc1191>
//! - RFC 3376 — Internet Group Management Protocol, Version 3
//!   (B. Cain et al, Oct 2002). §4 Membership Query (type 0x11) +
//!   §4.2 Membership Report (type 0x22 with Group Records).
//!   <https://datatracker.ietf.org/doc/html/rfc3376>
//! - RFC 1071 — Internet checksum reused for ICMP/IGMP.
//!   <https://datatracker.ietf.org/doc/html/rfc1071>
//!
//! No GPL Linux source consulted.
//!
//! ## ICMP error message header (RFC 792)
//!
//! All ICMP messages share a 4-byte header:
//!
//! ```text
//!   byte 0     Type
//!   byte 1     Code
//!   bytes 2..3 Checksum (over the entire ICMP message + payload)
//! ```
//!
//! Error messages append a 4-byte field (rest of header — varies by
//! type) followed by the IPv4 header + at least 8 bytes of the
//! original datagram that triggered the error.

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::ip_checksum;

// ── ICMP types (RFC 792 + IANA) ────────────────────────────────────

pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_SOURCE_QUENCH: u8 = 4;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_PARAMETER_PROBLEM: u8 = 12;
pub const ICMP_TIMESTAMP: u8 = 13;
pub const ICMP_TIMESTAMP_REPLY: u8 = 14;

// ── Destination Unreachable codes (RFC 792 + RFC 1812) ────────────

pub const DUR_NET_UNREACHABLE: u8 = 0;
pub const DUR_HOST_UNREACHABLE: u8 = 1;
pub const DUR_PROTOCOL_UNREACHABLE: u8 = 2;
pub const DUR_PORT_UNREACHABLE: u8 = 3;
pub const DUR_FRAGMENTATION_NEEDED: u8 = 4;
pub const DUR_SOURCE_ROUTE_FAILED: u8 = 5;
pub const DUR_NET_UNKNOWN: u8 = 6;
pub const DUR_HOST_UNKNOWN: u8 = 7;
pub const DUR_NET_PROHIBITED: u8 = 9;
pub const DUR_HOST_PROHIBITED: u8 = 10;
pub const DUR_TOS_NET_UNREACHABLE: u8 = 11;
pub const DUR_TOS_HOST_UNREACHABLE: u8 = 12;
pub const DUR_COMMUNICATION_PROHIBITED: u8 = 13;

// ── Time Exceeded codes ───────────────────────────────────────────

pub const TE_TTL_EXCEEDED_IN_TRANSIT: u8 = 0;
pub const TE_FRAGMENT_REASSEMBLY_TIMEOUT: u8 = 1;

// ── Redirect codes ────────────────────────────────────────────────

pub const REDIRECT_NET: u8 = 0;
pub const REDIRECT_HOST: u8 = 1;
pub const REDIRECT_TOS_NET: u8 = 2;
pub const REDIRECT_TOS_HOST: u8 = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IcmpExtraError {
    Short,
    BadChecksum,
}

// ── Generic builder: ICMP error header + original-packet head ─────

/// Build a generic 4-byte-rest-of-header ICMP error message:
/// `[Type Code Checksum(2) RestOfHeader(4) OriginalIpHeader+8Bytes…]`.
/// The checksum is filled in over the full message.
pub fn build_error(typ: u8, code: u8, rest_of_header: u32, original: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + original.len());
    out.push(typ);
    out.push(code);
    out.extend_from_slice(&[0u8; 2]); // checksum placeholder
    out.extend_from_slice(&rest_of_header.to_be_bytes());
    out.extend_from_slice(original);
    let cs = ip_checksum(&out);
    out[2] = (cs >> 8) as u8;
    out[3] = (cs & 0xFF) as u8;
    out
}

/// Build a Fragmentation Needed (Type 3 Code 4) message carrying the
/// next-hop MTU in the low 16 bits of the rest-of-header field
/// (RFC 1191).
pub fn build_fragmentation_needed(next_hop_mtu: u16, original: &[u8]) -> Vec<u8> {
    build_error(
        ICMP_DEST_UNREACHABLE,
        DUR_FRAGMENTATION_NEEDED,
        next_hop_mtu as u32,
        original,
    )
}

/// Build a Time Exceeded message.
pub fn build_time_exceeded(code: u8, original: &[u8]) -> Vec<u8> {
    build_error(ICMP_TIME_EXCEEDED, code, 0, original)
}

/// Build a Redirect message — `gateway` is the address the host
/// should use for the next-hop instead.
pub fn build_redirect(code: u8, gateway: [u8; 4], original: &[u8]) -> Vec<u8> {
    let v = u32::from_be_bytes(gateway);
    build_error(ICMP_REDIRECT, code, v, original)
}

/// Decoded ICMP error message header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IcmpError {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
}

impl IcmpError {
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), IcmpExtraError> {
        if buf.len() < 8 {
            return Err(IcmpExtraError::Short);
        }
        let calc = ip_checksum(buf);
        if calc != 0 {
            return Err(IcmpExtraError::BadChecksum);
        }
        Ok((
            Self {
                typ: buf[0],
                code: buf[1],
                checksum: u16::from_be_bytes([buf[2], buf[3]]),
                rest_of_header: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            },
            &buf[8..],
        ))
    }
}

// ── IGMPv3 (RFC 3376) ─────────────────────────────────────────────

/// IGMP types.
pub const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMP_V1_MEMBERSHIP_REPORT: u8 = 0x12;
pub const IGMP_V2_MEMBERSHIP_REPORT: u8 = 0x16;
pub const IGMP_V3_MEMBERSHIP_REPORT: u8 = 0x22;
pub const IGMP_V2_LEAVE_GROUP: u8 = 0x17;

/// IGMPv3 Group-Record types (RFC 3376 §4.2.12).
pub const IGMP_RECORD_MODE_IS_INCLUDE: u8 = 1;
pub const IGMP_RECORD_MODE_IS_EXCLUDE: u8 = 2;
pub const IGMP_RECORD_CHANGE_TO_INCLUDE: u8 = 3;
pub const IGMP_RECORD_CHANGE_TO_EXCLUDE: u8 = 4;
pub const IGMP_RECORD_ALLOW_NEW_SOURCES: u8 = 5;
pub const IGMP_RECORD_BLOCK_OLD_SOURCES: u8 = 6;

/// Decoded IGMPv3 Membership Query header (RFC 3376 §4.1, fixed 12
/// bytes — variable Source-Address list follows).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IgmpV3Query {
    /// Max Resp Code byte, encoded per §4.1.1 (the floating-point
    /// form when bit 7 is set).
    pub max_resp_code: u8,
    pub group_address: [u8; 4],
    /// Bit field at byte 8 — bits 0..2 = QRV (Querier's Robustness
    /// Variable); bit 3 = S Flag (Suppress Router-Side Processing).
    pub flags: u8,
    pub qqic: u8,
    pub number_of_sources: u16,
}

impl IgmpV3Query {
    pub fn decode(buf: &[u8]) -> Result<Self, IcmpExtraError> {
        if buf.len() < 12 {
            return Err(IcmpExtraError::Short);
        }
        if buf[0] != IGMP_MEMBERSHIP_QUERY {
            return Err(IcmpExtraError::Short);
        }
        let mut group = [0u8; 4];
        group.copy_from_slice(&buf[4..8]);
        Ok(Self {
            max_resp_code: buf[1],
            group_address: group,
            flags: buf[8],
            qqic: buf[9],
            number_of_sources: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

/// One IGMPv3 Group Record (RFC 3376 §4.2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    pub record_type: u8,
    pub multicast_address: [u8; 4],
    pub source_addresses: Vec<[u8; 4]>,
    pub auxiliary_data: Vec<u8>,
}

impl GroupRecord {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.record_type);
        out.push((self.auxiliary_data.len() / 4) as u8);
        out.extend_from_slice(&(self.source_addresses.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.multicast_address);
        for s in &self.source_addresses {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(&self.auxiliary_data);
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), IcmpExtraError> {
        if buf.len() < 8 {
            return Err(IcmpExtraError::Short);
        }
        let record_type = buf[0];
        let aux_len_words = buf[1] as usize;
        let n_src = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let mut multicast = [0u8; 4];
        multicast.copy_from_slice(&buf[4..8]);
        let need = 8 + n_src * 4 + aux_len_words * 4;
        if buf.len() < need {
            return Err(IcmpExtraError::Short);
        }
        let mut sources = Vec::with_capacity(n_src);
        for i in 0..n_src {
            let off = 8 + i * 4;
            let mut s = [0u8; 4];
            s.copy_from_slice(&buf[off..off + 4]);
            sources.push(s);
        }
        let aux = &buf[8 + n_src * 4..need];
        Ok((
            Self {
                record_type,
                multicast_address: multicast,
                source_addresses: sources,
                auxiliary_data: aux.to_vec(),
            },
            need,
        ))
    }
}

/// Build an IGMPv3 Membership Report packet (RFC 3376 §4.2). Fixed
/// 8-byte header + N Group Records.
pub fn build_v3_report(records: &[GroupRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + records.len() * 12);
    out.push(IGMP_V3_MEMBERSHIP_REPORT);
    out.push(0); // reserved
    out.extend_from_slice(&[0u8; 2]); // checksum placeholder
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for r in records {
        r.encode(&mut out);
    }
    let cs = ip_checksum(&out);
    out[2] = (cs >> 8) as u8;
    out[3] = (cs & 0xFF) as u8;
    out
}
