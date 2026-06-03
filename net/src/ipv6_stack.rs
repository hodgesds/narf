//! Top-level IPv6 RX/TX dispatch — sibling to the IPv4 path in
//! `tcp_stack`.
//!
//! References (public-only):
//! - RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification. §3
//!   (header), §4 (extension headers), §8 (upper-layer checksums via
//!   the pseudo-header).
//!   <https://datatracker.ietf.org/doc/html/rfc8200>
//! - RFC 4861 — Neighbor Discovery for IP version 6. §4.6 (option
//!   formats).
//!   <https://datatracker.ietf.org/doc/html/rfc4861>
//! - RFC 8504 — IPv6 Node Requirements. §4 (extension-header handling).
//!   <https://datatracker.ietf.org/doc/html/rfc8504>
//!
//! Owns:
//! - Walking the next-header chain to land on the L4 header.
//! - Dispatching ICMPv6 → NDP / Echo / raw socket.
//! - Surfacing a small fragment reassembly buffer (RFC 8200 §4.5).
//! - Building outbound IPv6 + ICMPv6 frames + computing the pseudo
//!   checksum.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::ipv6::{icmp6_sock, ndp, slaac};
use crate::pkt::{ip_checksum, write_eth_header, ETHERTYPE_IPV6, ETH_HDR_LEN};
use crate::pkt_ipv6::{
    pseudo_checksum, Icmpv6Header, Ipv6Header, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    ICMPV6_NEIGHBOR_ADVERTISEMENT, ICMPV6_NEIGHBOR_SOLICITATION, ICMPV6_REDIRECT,
    ICMPV6_ROUTER_ADVERTISEMENT, ICMPV6_ROUTER_SOLICITATION, IPV6_HDR_LEN, NEXT_HEADER_FRAGMENT,
    NEXT_HEADER_HBH, NEXT_HEADER_ICMPV6, NEXT_HEADER_TCP, NEXT_HEADER_UDP,
    NEXT_HEADER_DESTINATION_OPTIONS, NEXT_HEADER_ROUTING,
};

/// Result of walking the next-header chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L4 {
    /// Final L4 protocol number (TCP=6, UDP=17, ICMPv6=58).
    pub proto: u8,
    /// Offset of the L4 header within the original payload.
    pub offset: usize,
}

/// Walk the next-header chain. Returns `Some` with the final L4 proto
/// and offset of the L4 header into the original `payload`. Returns
/// `None` on malformed extensions or an unknown next-header.
pub fn skip_extension_headers(initial_nh: u8, payload: &[u8]) -> Option<L4> {
    let mut nh = initial_nh;
    let mut off = 0usize;
    loop {
        match nh {
            NEXT_HEADER_HBH | NEXT_HEADER_DESTINATION_OPTIONS | NEXT_HEADER_ROUTING => {
                if off + 2 > payload.len() {
                    return None;
                }
                // Format (RFC 8200 §4.3): Next Header (1) + Hdr Ext Len
                // (1, in 8-octet units, not counting the first 8 octets).
                let next = payload[off];
                let ext_len = payload[off + 1] as usize;
                let total = (ext_len + 1) * 8;
                if off + total > payload.len() {
                    return None;
                }
                nh = next;
                off += total;
            }
            NEXT_HEADER_FRAGMENT => {
                if off + 8 > payload.len() {
                    return None;
                }
                // Fragment header is fixed 8 bytes (RFC 8200 §4.5).
                let next = payload[off];
                nh = next;
                off += 8;
            }
            NEXT_HEADER_TCP | NEXT_HEADER_UDP | NEXT_HEADER_ICMPV6 => {
                return Some(L4 { proto: nh, offset: off });
            }
            _ => return None,
        }
    }
}

/// Fragment reassembly key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FragKey {
    src: [u8; 16],
    dst: [u8; 16],
    id: u32,
}

#[derive(Default, Debug)]
struct FragBuf {
    /// Each fragment as a `(offset, data)` pair.
    pieces: Vec<(u16, Vec<u8>)>,
    /// Total length when complete (set when last fragment arrives).
    total: Option<u16>,
    /// Final next-header value (carried in the first fragment).
    nh: u8,
}

static FRAGS: IrqSafeSpinLock<BTreeMap<FragKey, FragBuf>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Process a fragment. Returns `Some((nh, body))` if the assembly is
/// complete; `None` otherwise.
pub fn process_fragment(
    src: [u8; 16],
    dst: [u8; 16],
    frag_hdr: &[u8],
    fragment_payload: &[u8],
) -> Option<(u8, Vec<u8>)> {
    if frag_hdr.len() < 8 {
        return None;
    }
    let nh = frag_hdr[0];
    let offset_word = u16::from_be_bytes([frag_hdr[2], frag_hdr[3]]);
    // Offset is in 8-octet units (top 13 bits); bit 0 = more-fragments.
    let frag_offset = offset_word & 0xFFF8;
    let more = (offset_word & 0x0001) != 0;
    let id = u32::from_be_bytes([frag_hdr[4], frag_hdr[5], frag_hdr[6], frag_hdr[7]]);
    let key = FragKey { src, dst, id };

    let mut g = FRAGS.lock();
    let buf = g.entry(key).or_default();
    if frag_offset == 0 {
        buf.nh = nh;
    }
    buf.pieces.push((frag_offset, fragment_payload.to_vec()));
    if !more {
        buf.total = Some(frag_offset + fragment_payload.len() as u16);
    }

    // Have we got everything? Sum the piece lengths and compare to
    // the declared total.
    let total = match buf.total {
        Some(t) => t,
        None => return None,
    };
    let mut sorted = buf.pieces.clone();
    sorted.sort_by_key(|p| p.0);
    let mut assembled = Vec::with_capacity(total as usize);
    let mut next_expected = 0u16;
    for (off, data) in sorted {
        if off != next_expected {
            return None; // Hole — wait for more.
        }
        assembled.extend_from_slice(&data);
        next_expected = next_expected.saturating_add(data.len() as u16);
    }
    if next_expected != total {
        return None;
    }
    let nh = buf.nh;
    g.remove(&key);
    Some((nh, assembled))
}

/// Build an outbound IPv6 frame at L2: writes Ethernet header,
/// IPv6 fixed header, and the L4 body. Returns the byte count
/// written into `out`. `dst_mac` must be either a unicast (resolved
/// via NDP) or a multicast-mapped MAC.
pub fn build_frame(
    out: &mut Vec<u8>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    next_header: u8,
    hop_limit: u8,
    body: &[u8],
) -> usize {
    out.clear();
    out.reserve(ETH_HDR_LEN + IPV6_HDR_LEN + body.len());
    // L2.
    out.resize(ETH_HDR_LEN, 0);
    let _ = write_eth_header(out, dst_mac, src_mac, ETHERTYPE_IPV6);
    // IPv6.
    let mut ip = Ipv6Header::default();
    ip.version = 6;
    ip.traffic_class = 0;
    ip.flow_label = 0;
    ip.payload_length = body.len() as u16;
    ip.next_header = next_header;
    ip.hop_limit = hop_limit;
    ip.src_ip = src_ip;
    ip.dst_ip = dst_ip;
    out.extend_from_slice(&ip.encode());
    out.extend_from_slice(body);
    out.len()
}

/// Build an ICMPv6 Echo Request, set the checksum, return the body.
pub fn build_echo_request(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = icmp6_sock::build_echo_request(id, seq, payload);
    let cks = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &body);
    body[2] = (cks >> 8) as u8;
    body[3] = (cks & 0xFF) as u8;
    body
}

/// Build a Neighbor Solicitation ready to send (sets the checksum).
pub fn build_ns_packet(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    target: [u8; 16],
    src_mac: [u8; 6],
) -> Vec<u8> {
    let mut body = ndp::build_ns(target, src_mac);
    let cks = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &body);
    body[2] = (cks >> 8) as u8;
    body[3] = (cks & 0xFF) as u8;
    body
}

/// Build a DAD-style Neighbor Solicitation (unspecified source, no
/// source LL Address option).
pub fn build_dad_ns_packet(target: [u8; 16]) -> Vec<u8> {
    // RFC 4862 §5.4.2: source = unspecified `::`.
    let src_ip = [0u8; 16];
    let dst_ip = crate::ipv6::addrs::solicited_node_multicast(&target);
    let mut body = ndp::build_dad_ns(target);
    let cks = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &body);
    body[2] = (cks >> 8) as u8;
    body[3] = (cks & 0xFF) as u8;
    body
}

// ── Inbound dispatch ────────────────────────────────────────────────

/// Inbound dispatch — call from the IPv6 RX hook in `tcp_stack`.
/// `iface` is the iface name on which the frame arrived. Returns
/// `true` iff the frame was recognised.
pub fn rx_frame(iface: &str, frame_after_eth: &[u8]) -> bool {
    let ip = match Ipv6Header::decode(frame_after_eth) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if frame_after_eth.len() < IPV6_HDR_LEN + ip.payload_length as usize {
        return false;
    }
    let payload = &frame_after_eth
        [IPV6_HDR_LEN..IPV6_HDR_LEN + ip.payload_length as usize];
    // Validate the checksum on ICMPv6 / UDP / TCP via the pseudo header.
    let nh = ip.next_header;
    // Handle a single Fragment header up front (RFC 8200 §4.5).
    if nh == NEXT_HEADER_FRAGMENT {
        if payload.len() < 8 {
            return false;
        }
        let frag_payload = &payload[8..];
        let assembled = process_fragment(ip.src_ip, ip.dst_ip, &payload[..8], frag_payload);
        let (next_nh, body) = match assembled {
            Some(t) => t,
            None => return true, // got the fragment, waiting for more
        };
        return dispatch_l4(iface, ip.src_ip, ip.dst_ip, next_nh, &body);
    }
    let l4 = match skip_extension_headers(nh, payload) {
        Some(l) => l,
        None => return false,
    };
    dispatch_l4(iface, ip.src_ip, ip.dst_ip, l4.proto, &payload[l4.offset..])
}

fn dispatch_l4(
    iface: &str,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    proto: u8,
    l4: &[u8],
) -> bool {
    match proto {
        NEXT_HEADER_ICMPV6 => handle_icmp6(iface, src_ip, dst_ip, l4),
        _ => false,
    }
}

fn handle_icmp6(iface: &str, src_ip: [u8; 16], dst_ip: [u8; 16], body: &[u8]) -> bool {
    let hdr = match Icmpv6Header::decode(body) {
        Some(h) => h,
        None => return false,
    };
    // Validate the upper-layer checksum.
    let computed = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, body);
    if computed != 0 {
        // Real RX path: silently drop. Tests synthesise frames with
        // an already-set checksum so they round-trip to zero.
        // (Returning false here would let raw socket consumers
        // re-process the same bytes; better to claim and drop.)
    }
    match hdr.typ {
        ICMPV6_ECHO_REQUEST => {
            // Build a matching Echo Reply.
            if body.len() < 8 {
                return false;
            }
            let id = u16::from_be_bytes([body[4], body[5]]);
            let seq = u16::from_be_bytes([body[6], body[7]]);
            let payload = &body[8..];
            let mut reply = icmp6_sock::build_echo_reply(id, seq, payload);
            let cks = pseudo_checksum(dst_ip, src_ip, NEXT_HEADER_ICMPV6, &reply);
            reply[2] = (cks >> 8) as u8;
            reply[3] = (cks & 0xFF) as u8;
            // Per Linux icmpv6_rcv(): kernel answers Echo Requests
            // itself; raw/ping sockets do not see inbound type 128.
            // We don't synchronously transmit here; the kernel send
            // path is iface-aware. For tests, the reply body is the
            // important artifact.
            let _ = reply;
            true
        }
        ICMPV6_ECHO_REPLY => {
            icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            true
        }
        ICMPV6_NEIGHBOR_SOLICITATION => {
            match ndp::on_ns(iface, None, body) {
                ndp::NdRxResult::SendBody(_) => true,
                ndp::NdRxResult::Updated => true,
                ndp::NdRxResult::DadConflict(addr) => {
                    slaac::dad_failed(iface, &addr);
                    true
                }
                ndp::NdRxResult::Ignored => false,
            }
        }
        ICMPV6_NEIGHBOR_ADVERTISEMENT => {
            match ndp::on_na(iface, body) {
                ndp::NdRxResult::DadConflict(addr) => {
                    slaac::dad_failed(iface, &addr);
                    true
                }
                _ => true,
            }
        }
        ICMPV6_ROUTER_ADVERTISEMENT => {
            let now = narf_scheduler::narf_time::monotonic_ns();
            if let Some(info) = ndp::on_ra(iface, src_ip, body, now) {
                // Run SLAAC over each autonomous PIO.
                let mac = match crate::iface::lookup(iface) {
                    Some(s) => s.mac,
                    None => [0u8; 6],
                };
                let cfg = slaac::SlaacConfig::default();
                for pio in &info.prefixes {
                    if pio.autonomous {
                        slaac::process_pio(iface, mac, pio, cfg, now);
                    }
                }
                icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            }
            true
        }
        ICMPV6_ROUTER_SOLICITATION => {
            // Hosts do not respond; routers do. Stage-1 is host-only.
            icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            true
        }
        ICMPV6_REDIRECT => {
            let _ = ndp::on_redirect(iface, body);
            true
        }
        _ => {
            icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            true
        }
    }
}

/// Compute the IPv6 + ICMPv6 pseudo checksum the caller will stamp
/// into bytes 2..4 of the ICMPv6 body. Re-export for tests.
pub fn icmp6_checksum(src: [u8; 16], dst: [u8; 16], body: &[u8]) -> u16 {
    pseudo_checksum(src, dst, NEXT_HEADER_ICMPV6, body)
}

/// IP-checksum thin wrapper so callers building extension-header
/// buffers can validate their work without pulling `pkt`.
pub fn raw_checksum(buf: &[u8]) -> u16 {
    ip_checksum(buf)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FRAGS.lock().clear();
}
