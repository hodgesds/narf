//! Multicast DNS + DNS-Based Service Discovery — clean-room.
//!
//! References (public-only):
//! - RFC 6762 — Multicast DNS (S. Cheshire & M. Krochmal, Feb 2013).
//!   §5 (transport: UDP port 5353 + IPv4 224.0.0.251 / IPv6 FF02::FB).
//!   §10.2 (cache-flush bit — top bit of CLASS in answers / authorities
//!   / additionals). §18.12 (Unicast Response — top bit of QCLASS in
//!   questions). §6 (Probing + Conflict Resolution PROBE/announcing).
//!   <https://datatracker.ietf.org/doc/html/rfc6762>
//! - RFC 6763 — DNS-Based Service Discovery (S. Cheshire & M.
//!   Krochmal, Feb 2013). §4 (service-type browsing via PTR queries
//!   for `_service._proto.local`). §6 (TXT records: key=value pairs
//!   each prefixed by 1-byte length, packed inside one or more
//!   character-strings inside the RDATA).
//!   <https://datatracker.ietf.org/doc/html/rfc6763>
//! - RFC 1035 — referenced for the underlying header / question / RR
//!   format (the `pkt_dns` module already covers this).
//!   <https://datatracker.ietf.org/doc/html/rfc1035>
//!
//! No GPL Linux source consulted.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::pkt_dns::{decode_name, DnsError, DnsHeader, FLAG_AA, FLAG_QR};

/// Standard mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;

/// IPv4 multicast address `224.0.0.251` for mDNS.
pub const MDNS_IPV4_GROUP: [u8; 4] = [224, 0, 0, 251];

/// IPv6 multicast address `FF02::FB` for mDNS.
pub const MDNS_IPV6_GROUP: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB];

/// Top bit of QCLASS — request unicast response (RFC 6762 §18.12).
pub const QCLASS_UNICAST_RESPONSE_BIT: u16 = 1 << 15;
/// Top bit of CLASS in answers — cache-flush (RFC 6762 §10.2).
pub const CLASS_CACHE_FLUSH_BIT: u16 = 1 << 15;

/// DNS class mask after stripping the cache-flush / unicast-response
/// bit (top bit). Standard CLASS_IN value lives in the low 15 bits.
pub const CLASS_MASK: u16 = 0x7FFF;

/// Build the standard `_services._dns-sd._udp.local` browsing name
/// (RFC 6763 §9 — the meta-query that asks "what service types exist
/// on this link?").
pub fn services_meta_name() -> &'static str {
    "_services._dns-sd._udp.local"
}

/// Build a DNS-SD service-instance browsing name like
/// `_http._tcp.local` from `service` ("_http") and `proto` ("_tcp").
pub fn service_browse_name(service: &str, proto: &str) -> String {
    let mut s = String::with_capacity(service.len() + proto.len() + 8);
    s.push_str(service);
    s.push('.');
    s.push_str(proto);
    s.push_str(".local");
    s
}

// ── Header builders that pin the mDNS conventions ─────────────────

/// Build an mDNS query header with a single question. Per RFC 6762
/// §18.5 the transaction ID is conventionally 0; the QR bit is 0
/// (query).
pub fn query_header(qdcount: u16) -> DnsHeader {
    DnsHeader {
        id: 0,
        flags: 0, // QR=0, opcode=0, no flags
        qdcount,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    }
}

/// Build an mDNS response header. Per RFC 6762 the AA bit is set on
/// authoritative responses and the response is also broadcast (no
/// transaction matching).
pub fn response_header(ancount: u16, arcount: u16) -> DnsHeader {
    DnsHeader {
        id: 0,
        flags: FLAG_QR | FLAG_AA,
        qdcount: 0,
        ancount,
        nscount: 0,
        arcount,
    }
}

// ── TXT record codec (RFC 6763 §6) ─────────────────────────────────

/// Build the RDATA for a DNS TXT record from a list of `key=value`
/// strings. Each string is prefixed with its 1-byte length per
/// §6.1; an empty list emits a single zero-length character-string.
/// `key=value` strings longer than 255 bytes are truncated.
pub fn build_txt_rdata(entries: &[&str]) -> Vec<u8> {
    if entries.is_empty() {
        return alloc::vec![0];
    }
    let mut out = Vec::new();
    for e in entries {
        let bytes = e.as_bytes();
        let take = bytes.len().min(255);
        out.push(take as u8);
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

/// Decode a TXT-record RDATA into the list of `key=value` strings.
/// Stops at end-of-buffer; tolerates the single zero-length string
/// that represents "no TXT data" per §6.1.
pub fn parse_txt_rdata(rdata: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < rdata.len() {
        let len = rdata[p] as usize;
        p += 1;
        if p + len > rdata.len() {
            break;
        }
        if len > 0 {
            let s = core::str::from_utf8(&rdata[p..p + len])
                .unwrap_or("")
                .to_string();
            out.push(s);
        }
        p += len;
    }
    out
}

// ── SRV record codec (RFC 6763 §5 + RFC 2782) ──────────────────────

/// Decoded SRV record (RFC 2782). RDATA layout: priority (BE u16),
/// weight (BE u16), port (BE u16), then a target name (DNS-format,
/// possibly compressed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl SrvRecord {
    /// Encode an uncompressed SRV record into RDATA bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.target.len() + 2);
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.weight.to_be_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        // Names in SRV RDATA must be encoded in DNS wire format, but
        // they cannot use compression *unless* the message context
        // makes the offset addressable (RFC 2782 §1). For simplicity
        // we emit the uncompressed form here.
        for label in self.target.split('.') {
            if label.is_empty() {
                continue;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Decode an SRV record. `msg` is the entire DNS message (used to
    /// resolve compressed names); `pos` is where the SRV RDATA starts.
    pub fn decode(msg: &[u8], pos: usize, rdlen: usize) -> Result<Self, DnsError> {
        if pos + 6 > msg.len() || rdlen < 6 {
            return Err(DnsError::Short);
        }
        let priority = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let weight = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let port = u16::from_be_bytes([msg[pos + 4], msg[pos + 5]]);
        let (target, _) = decode_name(msg, pos + 6)?;
        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }
}

// ── Class helpers for question/answer encoding ─────────────────────

/// Set the unicast-response bit in a question's QCLASS.
pub fn qclass_with_unicast_response(class: u16) -> u16 {
    class | QCLASS_UNICAST_RESPONSE_BIT
}

/// Strip the unicast-response bit when comparing a question's QCLASS.
pub fn qclass_without_unicast_bit(qclass: u16) -> u16 {
    qclass & CLASS_MASK
}

/// Set the cache-flush bit in an answer's CLASS.
pub fn class_with_cache_flush(class: u16) -> u16 {
    class | CLASS_CACHE_FLUSH_BIT
}

/// Strip the cache-flush bit when looking up the spec class value.
pub fn class_without_cache_flush(class: u16) -> u16 {
    class & CLASS_MASK
}
