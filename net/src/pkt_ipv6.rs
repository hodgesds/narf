//! IPv6 + ICMPv6 Neighbor Discovery codec — clean-room.
//!
//! References (public-only):
//! - RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification
//!   (S. Deering & R. Hinden, July 2017). §3 IPv6 Header Format.
//!   §4.4 Routing / Hop-by-Hop / Fragment / Destination Options
//!   extension headers (we surface the Next Header chain only).
//! - RFC 4443 — Internet Control Message Protocol (ICMPv6) for the
//!   IPv6 Specification. §2.1 Message General Format. §3 Error
//!   Messages. §4 Informational Messages (Echo Request / Reply).
//! - RFC 4861 — Neighbor Discovery for IP version 6.
//!   §4.1 Router Solicitation, §4.2 Router Advertisement,
//!   §4.3 Neighbor Solicitation, §4.4 Neighbor Advertisement,
//!   §4.5 Redirect. §4.6 Option Formats — Source / Target Link-Layer
//!   Address (types 1 / 2), Prefix Information (3), Redirect Header
//!   (4), MTU (5).
//! - RFC 1071 — Internet checksum mechanism reused for the IPv6
//!   pseudo-header (40 bytes: src 16 + dst 16 + length 4 + zero 3
//!   + next-header 1, see RFC 8200 §8.1).
//!
//! No GPL Linux source consulted.

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::ip_checksum;

/// IPv6 fixed header size.
pub const IPV6_HDR_LEN: usize = 40;

/// IPv6 next-header values (selected; IANA Assigned Numbers).
pub const NEXT_HEADER_HBH: u8 = 0; // Hop-by-Hop options
pub const NEXT_HEADER_TCP: u8 = 6;
pub const NEXT_HEADER_UDP: u8 = 17;
pub const NEXT_HEADER_ROUTING: u8 = 43;
pub const NEXT_HEADER_FRAGMENT: u8 = 44;
pub const NEXT_HEADER_ICMPV6: u8 = 58;
pub const NEXT_HEADER_NO_NEXT: u8 = 59;
pub const NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ipv6Error {
    Short,
    /// IP version field isn't 6.
    BadVersion(u8),
    /// Checksum doesn't match.
    BadChecksum,
}

// ── IPv6 fixed header (RFC 8200 §3) ────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ipv6Header {
    /// 6-bit IP version (must be 6).
    pub version: u8,
    /// 8-bit Traffic Class (DSCP + ECN).
    pub traffic_class: u8,
    /// 20-bit Flow Label.
    pub flow_label: u32,
    /// Length of the payload (extension headers + L4) in bytes.
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
}

impl Ipv6Header {
    pub fn encode(&self) -> [u8; IPV6_HDR_LEN] {
        let mut out = [0u8; IPV6_HDR_LEN];
        let v = (6u32) << 28
            | ((self.traffic_class as u32) << 20)
            | (self.flow_label & 0x000F_FFFF);
        out[0..4].copy_from_slice(&v.to_be_bytes());
        out[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        out[6] = self.next_header;
        out[7] = self.hop_limit;
        out[8..24].copy_from_slice(&self.src_ip);
        out[24..40].copy_from_slice(&self.dst_ip);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Ipv6Error> {
        if buf.len() < IPV6_HDR_LEN {
            return Err(Ipv6Error::Short);
        }
        let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let version = ((v >> 28) & 0x0F) as u8;
        if version != 6 {
            return Err(Ipv6Error::BadVersion(version));
        }
        let traffic_class = ((v >> 20) & 0xFF) as u8;
        let flow_label = v & 0x000F_FFFF;
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&buf[8..24]);
        dst_ip.copy_from_slice(&buf[24..40]);
        Ok(Self {
            version,
            traffic_class,
            flow_label,
            payload_length: u16::from_be_bytes([buf[4], buf[5]]),
            next_header: buf[6],
            hop_limit: buf[7],
            src_ip,
            dst_ip,
        })
    }
}

// ── IPv6 pseudo-header (RFC 8200 §8.1) ─────────────────────────────

/// Build the 40-byte IPv6 pseudo-header used by upper-layer checksums.
fn ipv6_pseudo_header(src: [u8; 16], dst: [u8; 16], length: u32, next_header: u8) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0..16].copy_from_slice(&src);
    out[16..32].copy_from_slice(&dst);
    out[32..36].copy_from_slice(&length.to_be_bytes());
    // 33..35 zero; byte 39 = next header.
    out[39] = next_header;
    out
}

/// Compute the upper-layer checksum (TCP / UDP / ICMPv6) against the
/// IPv6 pseudo-header.
pub fn pseudo_checksum(src: [u8; 16], dst: [u8; 16], next_header: u8, body: &[u8]) -> u16 {
    let pseudo = ipv6_pseudo_header(src, dst, body.len() as u32, next_header);
    let mut buf = Vec::with_capacity(pseudo.len() + body.len());
    buf.extend_from_slice(&pseudo);
    buf.extend_from_slice(body);
    ip_checksum(&buf)
}

// ── ICMPv6 (RFC 4443 §2.1) ────────────────────────────────────────

pub const ICMPV6_HDR_LEN: usize = 4;

// Type values (RFC 4443 §2.1 + RFC 4861 §4).
pub const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const ICMPV6_REDIRECT: u8 = 137;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Icmpv6Header {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
}

impl Icmpv6Header {
    pub fn encode(self) -> [u8; ICMPV6_HDR_LEN] {
        [
            self.typ,
            self.code,
            (self.checksum >> 8) as u8,
            (self.checksum & 0xFF) as u8,
        ]
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < ICMPV6_HDR_LEN {
            return None;
        }
        Some(Self {
            typ: buf[0],
            code: buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }
}

// ── Neighbor Discovery options (RFC 4861 §4.6) ─────────────────────

pub const ND_OPT_SOURCE_LINK_LAYER_ADDR: u8 = 1;
pub const ND_OPT_TARGET_LINK_LAYER_ADDR: u8 = 2;
pub const ND_OPT_PREFIX_INFORMATION: u8 = 3;
pub const ND_OPT_REDIRECTED_HEADER: u8 = 4;
pub const ND_OPT_MTU: u8 = 5;

/// Neighbor Discovery option header. Each option is `Type (1) | Length (1
/// in 8-byte units) | Value (Length*8 - 2 bytes)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NdOption<'a> {
    pub typ: u8,
    pub data: &'a [u8],
}

/// Iterate over Neighbor Discovery options. Each option must be at
/// least 8 bytes; malformed options short-circuit the iterator.
pub fn iter_nd_options(mut buf: &[u8]) -> impl Iterator<Item = NdOption<'_>> {
    core::iter::from_fn(move || {
        if buf.len() < 2 {
            return None;
        }
        let typ = buf[0];
        let length_8b = buf[1] as usize;
        if length_8b == 0 {
            return None;
        }
        let total = length_8b * 8;
        if buf.len() < total {
            return None;
        }
        let data = &buf[2..total];
        buf = &buf[total..];
        Some(NdOption { typ, data })
    })
}

/// Pack a Neighbor Discovery option into `out`.
/// `data` must already be padded so that `2 + data.len()` is a
/// multiple of 8 (the spec's "Length is in 8-byte units" invariant).
pub fn append_nd_option(out: &mut Vec<u8>, typ: u8, data: &[u8]) -> Option<()> {
    let total = 2 + data.len();
    if total % 8 != 0 {
        return None;
    }
    out.push(typ);
    out.push((total / 8) as u8);
    out.extend_from_slice(data);
    Some(())
}

// ── Specific message builders ──────────────────────────────────────

/// Build a Router Solicitation body (header bytes 4..7 are reserved).
pub fn router_solicitation(options: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + options.len());
    out.extend_from_slice(&[ICMPV6_ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(options);
    out
}

/// Build a Neighbor Solicitation body. `target` is the IPv6 address
/// being resolved. `options` already contains the (optional) Source
/// Link-Layer Address option.
pub fn neighbor_solicitation(target: [u8; 16], options: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + options.len());
    out.extend_from_slice(&[ICMPV6_NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&target);
    out.extend_from_slice(options);
    out
}

/// Build a Neighbor Advertisement body.
/// `flags` is the 32-bit field whose top 3 bits are the R/S/O flags
/// (Router / Solicited / Override).
pub const NA_FLAG_ROUTER: u32 = 1 << 31;
pub const NA_FLAG_SOLICITED: u32 = 1 << 30;
pub const NA_FLAG_OVERRIDE: u32 = 1 << 29;

pub fn neighbor_advertisement(flags: u32, target: [u8; 16], options: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + options.len());
    out.push(ICMPV6_NEIGHBOR_ADVERTISEMENT);
    out.push(0);
    out.extend_from_slice(&[0u8; 2]); // checksum placeholder
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&target);
    out.extend_from_slice(options);
    out
}

/// Build a Router Advertisement body. `cur_hop_limit` becomes the
/// CurHopLimit field; `mo_flags` is the 8-bit field whose top 2 bits
/// are M (Managed Address Configuration) and O (Other Stateful
/// Configuration). `router_lifetime` is in seconds.
pub const RA_FLAG_MANAGED: u8 = 1 << 7;
pub const RA_FLAG_OTHER_CONFIG: u8 = 1 << 6;

pub fn router_advertisement(
    cur_hop_limit: u8,
    mo_flags: u8,
    router_lifetime_s: u16,
    reachable_time_ms: u32,
    retrans_timer_ms: u32,
    options: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + options.len());
    out.push(ICMPV6_ROUTER_ADVERTISEMENT);
    out.push(0);
    out.extend_from_slice(&[0u8; 2]); // checksum placeholder
    out.push(cur_hop_limit);
    out.push(mo_flags);
    out.extend_from_slice(&router_lifetime_s.to_be_bytes());
    out.extend_from_slice(&reachable_time_ms.to_be_bytes());
    out.extend_from_slice(&retrans_timer_ms.to_be_bytes());
    out.extend_from_slice(options);
    out
}
