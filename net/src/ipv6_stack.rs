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
//! - Originating ICMPv6 messages on an interface (Echo Request/Reply,
//!   solicited + unsolicited Neighbor Advertisement, RFC 4443 error
//!   messages) — the transmit surface; see [`send_icmp6_in`].

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::ipv6::{icmp6_sock, ndp, slaac};
use crate::pkt::{ip_checksum, write_eth_header, ETHERTYPE_IPV6, ETH_HDR_LEN};
use crate::pkt_ipv6::{
    pseudo_checksum, Icmpv6Header, Ipv6Header, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    ICMPV6_HDR_LEN, ICMPV6_NEIGHBOR_ADVERTISEMENT, ICMPV6_NEIGHBOR_SOLICITATION,
    ICMPV6_PACKET_TOO_BIG, ICMPV6_REDIRECT, ICMPV6_ROUTER_ADVERTISEMENT,
    ICMPV6_ROUTER_SOLICITATION, IPV6_HDR_LEN, NEXT_HEADER_DESTINATION_OPTIONS,
    NEXT_HEADER_FRAGMENT, NEXT_HEADER_HBH, NEXT_HEADER_ICMPV6, NEXT_HEADER_ROUTING,
    NEXT_HEADER_TCP, NEXT_HEADER_UDP,
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
                return Some(L4 {
                    proto: nh,
                    offset: off,
                });
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
    /// Monotonic time the first-arriving fragment was received.
    first_ns: u64,
    /// Whether the offset-0 (first) fragment arrived (Linux
    /// `INET_FRAG_FIRST_IN`). Only reassemblies with this set get a
    /// Time Exceeded on timeout.
    first_in: bool,
    /// The offset-0 fragment's full IPv6 packet as received (header +
    /// Fragment header + payload), capped at the minimum IPv6 MTU:
    /// the §2.4(c) quote bound (1232 bytes) never needs more. This is
    /// the invoking packet quoted by the Time Exceeded error when
    /// this reassembly times out.
    invoking: Vec<u8>,
}

/// A reassembly abandoned by the 60 s timeout whose sender is owed a
/// Time Exceeded (code 1) error (RFC 4443 §3.3, Linux
/// `ip6_expire_frag_queue`). Only reassemblies whose first (offset-0)
/// fragment arrived are reported — Linux sends no error if the first
/// segment did not arrive.
#[derive(Debug)]
pub struct ExpiredReassembly {
    /// Source of the timed-out datagram (the error's destination).
    pub src: [u8; 16],
    /// Destination of the timed-out datagram (the error's source).
    pub dst: [u8; 16],
    /// The first fragment's full IPv6 packet, quoted by the error.
    pub invoking: Vec<u8>,
}

static FRAGS: IrqSafeSpinLock<BTreeMap<FragKey, FragBuf>> = IrqSafeSpinLock::new(BTreeMap::new());
static PMTU: IrqSafeSpinLock<BTreeMap<(u64, [u8; 16]), u32>> =
    IrqSafeSpinLock::new(BTreeMap::new());
static NEXT_FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);

/// RFC 8200 §4.5: reassembly not complete within 60 seconds of the
/// first-arriving fragment must be abandoned.
pub const FRAG_REASSEMBLY_TIMEOUT_NS: u64 = 60_000_000_000;

/// Process a fragment. Returns the completed reassembly, if any,
/// plus the reassemblies abandoned by the 60 s timeout while
/// processing it (see [`ExpiredReassembly`]).
///
/// `invoking_packet` is this fragment's full IPv6 packet as received
/// (header + Fragment header + payload); the offset-0 fragment's copy
/// is retained (capped at the minimum IPv6 MTU) as the invoking
/// packet for a later Time Exceeded. Callers that do not have the
/// packet (unit tests) pass `&[]` and get no timeout error for it.
pub fn process_fragment(
    src: [u8; 16],
    dst: [u8; 16],
    frag_hdr: &[u8],
    fragment_payload: &[u8],
    invoking_packet: &[u8],
) -> (Option<(u8, Vec<u8>)>, Vec<ExpiredReassembly>) {
    let now = narf_scheduler::narf_time::monotonic_ns();
    process_fragment_at(now, src, dst, frag_hdr, fragment_payload, invoking_packet)
}

/// [`process_fragment`] with an explicit clock, so the reassembly timeout
/// can be exercised deterministically.
#[doc(hidden)]
pub fn process_fragment_at(
    now_ns: u64,
    src: [u8; 16],
    dst: [u8; 16],
    frag_hdr: &[u8],
    fragment_payload: &[u8],
    invoking_packet: &[u8],
) -> (Option<(u8, Vec<u8>)>, Vec<ExpiredReassembly>) {
    if frag_hdr.len() < 8 {
        return (None, Vec::new());
    }
    let nh = frag_hdr[0];
    let offset_word = u16::from_be_bytes([frag_hdr[2], frag_hdr[3]]);
    // Offset is in 8-octet units (top 13 bits); bit 0 = more-fragments.
    let frag_offset = offset_word & 0xFFF8;
    let more = (offset_word & 0x0001) != 0;
    let id = u32::from_be_bytes([frag_hdr[4], frag_hdr[5], frag_hdr[6], frag_hdr[7]]);
    let key = FragKey { src, dst, id };

    // RFC 8200 §4.5: a fragment whose offset + length exceeds 65535 is
    // discarded, and so is a non-final fragment whose length is not a
    // multiple of 8 octets. The first check also keeps `offset + len` from
    // overflowing the u16 arithmetic below.
    let end = frag_offset as usize + fragment_payload.len();
    if end > u16::MAX as usize || (more && fragment_payload.len() % 8 != 0) {
        return (None, Vec::new());
    }
    let end = end as u16;

    let mut g = FRAGS.lock();
    // Abandon reassemblies that outlived the 60 s window. Without this, a
    // datagram that never completes pins its fragments forever.
    // Reassemblies whose first (offset-0) fragment arrived are reported
    // so the caller can originate Time Exceeded (code 1) for them —
    // Linux `ip6_expire_frag_queue` sends no error if the first
    // segment did not arrive. The rest are dropped silently.
    // Deviation, stated plainly: Linux expires on a timer; NARF has no
    // reassembly timer, so expiry — and its error — happen lazily when
    // the next fragment for any key arrives.
    let mut expired = Vec::new();
    g.retain(|key, b| {
        if now_ns.saturating_sub(b.first_ns) < FRAG_REASSEMBLY_TIMEOUT_NS {
            return true;
        }
        if b.first_in && !b.invoking.is_empty() {
            expired.push(ExpiredReassembly {
                src: key.src,
                dst: key.dst,
                invoking: core::mem::take(&mut b.invoking),
            });
        }
        false
    });
    let buf = g.entry(key).or_insert_with(|| FragBuf {
        first_ns: now_ns,
        ..FragBuf::default()
    });
    // RFC 5722 / RFC 8200 §4.5: overlapping fragments abandon the whole
    // reassembly. An exact duplicate may instead simply be dropped.
    let mut duplicate = false;
    for (off, data) in &buf.pieces {
        let o_end = *off as usize + data.len();
        if *off == frag_offset && data.as_slice() == fragment_payload {
            duplicate = true;
            break;
        }
        if (frag_offset as usize) < o_end && (*off as usize) < end as usize {
            g.remove(&key);
            return (None, expired);
        }
    }
    if duplicate {
        return (None, expired);
    }
    // A last fragment that disagrees with an earlier one about where the
    // datagram ends, or a piece reaching past a known end, cannot belong to
    // one consistent datagram.
    let max_end = buf
        .pieces
        .iter()
        .map(|(off, data)| *off as usize + data.len())
        .max()
        .unwrap_or(0);
    let inconsistent = match buf.total {
        Some(total) => end > total || (!more && end != total),
        None => !more && max_end > end as usize,
    };
    if inconsistent {
        g.remove(&key);
        return (None, expired);
    }
    if frag_offset == 0 {
        buf.nh = nh;
        // First fragment arrived: retain its full packet (capped at
        // the minimum IPv6 MTU — the §2.4(c) quote bound never needs
        // more) as the invoking packet for a later Time Exceeded.
        buf.first_in = true;
        if buf.invoking.is_empty() {
            let cap = invoking_packet.len().min(crate::pkt_ipv6::ICMPV6_MIN_MTU);
            buf.invoking = invoking_packet[..cap].to_vec();
        }
    }
    buf.pieces.push((frag_offset, fragment_payload.to_vec()));
    if !more {
        buf.total = Some(end);
    }

    // Have we got everything? Sum the piece lengths and compare to
    // the declared total.
    let total = match buf.total {
        Some(t) => t,
        None => return (None, expired),
    };
    let mut sorted = buf.pieces.clone();
    sorted.sort_by_key(|p| p.0);
    let mut assembled = Vec::with_capacity(total as usize);
    let mut next_expected = 0u16;
    for (off, data) in sorted {
        if off != next_expected {
            return (None, expired); // Hole — wait for more.
        }
        assembled.extend_from_slice(&data);
        next_expected = next_expected.saturating_add(data.len() as u16);
    }
    if next_expected != total {
        return (None, expired);
    }
    let nh = buf.nh;
    g.remove(&key);
    (Some((nh, assembled)), expired)
}

/// Addressing and L4 payload for an outbound IPv6 frame.
#[derive(Debug)]
pub struct Ipv6FrameSpec<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub next_header: u8,
    pub hop_limit: u8,
    pub body: &'a [u8],
}

/// Build an outbound IPv6 frame at L2: writes Ethernet header,
/// IPv6 fixed header, and the L4 body. Returns the byte count
/// written into `out`. `dst_mac` must be either a unicast (resolved
/// via NDP) or a multicast-mapped MAC.
pub fn build_frame(out: &mut Vec<u8>, spec: Ipv6FrameSpec<'_>) -> usize {
    let Ipv6FrameSpec {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        next_header,
        hop_limit,
        body,
    } = spec;
    out.clear();
    out.reserve(ETH_HDR_LEN + IPV6_HDR_LEN + body.len());
    // L2.
    out.resize(ETH_HDR_LEN, 0);
    let _ = write_eth_header(out, dst_mac, src_mac, ETHERTYPE_IPV6);
    // IPv6.
    let ip = Ipv6Header {
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: body.len() as u16,
        next_header,
        hop_limit,
        src_ip,
        dst_ip,
    };
    out.extend_from_slice(&ip.encode());
    out.extend_from_slice(body);
    out.len()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Udp6SendError {
    MessageTooLong,
    NetworkUnreachable,
    NeighborPending,
    NoSourceAddress,
    DeviceFailure,
    QueueFull,
    /// `udp_v6_send_skb`'s -EINVAL for a GSO send: more than
    /// `UDP_MAX_SEGMENTS` segments, or `UDP_NO_CHECK6_TX` set.
    GsoInvalid,
}

/// Per-send UDP transmit options for [`send_udp`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Udp6TxOpts {
    /// UDP GSO segment size (`UDP_SEGMENT`); 0 sends one datagram.
    pub gso_size: u16,
    /// `UDP_NO_CHECK6_TX`: send a zero UDP checksum (RFC 6935), which
    /// `udp_v6_send_skb` permits only without GSO.
    pub no_check6_tx: bool,
}

#[derive(Debug)]
struct PendingUdp6 {
    net_ns_id: u64,
    iface: String,
    neighbor: [u8; 16],
    source: [u8; 16],
    destination: [u8; 16],
    hop_limit: u8,
    traffic_class: u8,
    udp: Vec<u8>,
    mtu: u32,
    may_fragment: bool,
}

const MAX_PENDING_UDP6_PACKETS: usize = 256;
const MAX_PENDING_UDP6_BYTES: usize = 1024 * 1024;
static PENDING_UDP6: IrqSafeSpinLock<VecDeque<PendingUdp6>> = IrqSafeSpinLock::new(VecDeque::new());

fn queue_udp6(packet: PendingUdp6) -> Result<(), Udp6SendError> {
    let mut queue = PENDING_UDP6.lock();
    let bytes: usize = queue.iter().map(|entry| entry.udp.len()).sum();
    if queue.len() >= MAX_PENDING_UDP6_PACKETS
        || bytes.saturating_add(packet.udp.len()) > MAX_PENDING_UDP6_BYTES
    {
        return Err(Udp6SendError::QueueFull);
    }
    queue.push_back(packet);
    Ok(())
}

pub fn neighbor_resolved(net_ns_id: u64, iface_name: &str, neighbor: [u8; 16], mac: [u8; 6]) {
    let mut ready = Vec::new();
    {
        let mut queue = PENDING_UDP6.lock();
        let mut retained = VecDeque::new();
        while let Some(packet) = queue.pop_front() {
            if packet.net_ns_id == net_ns_id
                && packet.iface == iface_name
                && packet.neighbor == neighbor
            {
                ready.push(packet);
            } else {
                retained.push_back(packet);
            }
        }
        *queue = retained;
    }
    let mut ready_icmp6 = Vec::new();
    {
        let mut queue = PENDING_ICMP6.lock();
        let mut retained = VecDeque::new();
        while let Some(packet) = queue.pop_front() {
            if packet.net_ns_id == net_ns_id
                && packet.iface == iface_name
                && packet.neighbor == neighbor
            {
                ready_icmp6.push(packet);
            } else {
                retained.push_back(packet);
            }
        }
        *queue = retained;
    }
    let Some(iface) = crate::iface::lookup_in(net_ns_id, iface_name) else {
        return;
    };
    for packet in ready {
        let _ = emit_udp6(
            &iface,
            mac,
            packet.source,
            packet.destination,
            packet.hop_limit,
            packet.traffic_class,
            &packet.udp,
            packet.mtu,
            packet.may_fragment,
        );
    }
    for packet in ready_icmp6 {
        let _ = emit_icmp6_frame(
            &iface,
            mac,
            packet.source,
            packet.destination,
            packet.hop_limit,
            &packet.body,
        );
    }
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    PENDING_UDP6
        .lock()
        .retain(|packet| packet.net_ns_id != net_ns_id);
    PENDING_ICMP6
        .lock()
        .retain(|packet| packet.net_ns_id != net_ns_id);
    PMTU.lock().retain(|(ns, _), _| *ns != net_ns_id);
}

#[doc(hidden)]
pub fn __pending_udp6_test_insert(net_ns_id: u64, iface: &str, neighbor: [u8; 16]) -> bool {
    queue_udp6(PendingUdp6 {
        net_ns_id,
        iface: String::from(iface),
        neighbor,
        source: [0; 16],
        destination: neighbor,
        hop_limit: 64,
        traffic_class: 0,
        udp: alloc::vec![0; 8],
        mtu: 1280,
        may_fragment: false,
    })
    .is_ok()
}

#[doc(hidden)]
pub fn __pending_udp6_test_count(net_ns_id: u64) -> usize {
    PENDING_UDP6
        .lock()
        .iter()
        .filter(|packet| packet.net_ns_id == net_ns_id)
        .count()
}

/// A complete ICMPv6 message awaiting neighbor resolution — the
/// ICMPv6 half of the UDP pending queue above (`send_icmp6_in`
/// queues here; `neighbor_resolved` flushes). ICMPv6 messages are
/// never fragmented, so there is no MTU/fragment state to carry.
#[derive(Debug)]
struct PendingIcmp6 {
    net_ns_id: u64,
    iface: String,
    neighbor: [u8; 16],
    source: [u8; 16],
    destination: [u8; 16],
    hop_limit: u8,
    body: Vec<u8>,
}

const MAX_PENDING_ICMP6_PACKETS: usize = 256;
const MAX_PENDING_ICMP6_BYTES: usize = 1024 * 1024;
static PENDING_ICMP6: IrqSafeSpinLock<VecDeque<PendingIcmp6>> =
    IrqSafeSpinLock::new(VecDeque::new());

fn queue_icmp6(packet: PendingIcmp6) -> Result<(), Icmp6SendError> {
    let mut queue = PENDING_ICMP6.lock();
    let bytes: usize = queue.iter().map(|entry| entry.body.len()).sum();
    if queue.len() >= MAX_PENDING_ICMP6_PACKETS
        || bytes.saturating_add(packet.body.len()) > MAX_PENDING_ICMP6_BYTES
    {
        return Err(Icmp6SendError::QueueFull);
    }
    queue.push_back(packet);
    Ok(())
}

#[doc(hidden)]
pub fn __pending_icmp6_test_count(net_ns_id: u64) -> usize {
    PENDING_ICMP6
        .lock()
        .iter()
        .filter(|packet| packet.net_ns_id == net_ns_id)
        .count()
}

/// Build an IPv6 UDP segment, including its mandatory pseudo-header checksum.
pub fn build_udp_segment(
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Udp6SendError> {
    const UDP_HDR_LEN: usize = 8;
    if payload.len() > u16::MAX as usize - UDP_HDR_LEN {
        return Err(Udp6SendError::MessageTooLong);
    }
    let udp_len = UDP_HDR_LEN + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let checksum = pseudo_checksum(source, destination, NEXT_HEADER_UDP, &udp);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    Ok(udp)
}

/// Route and emit one IPv6 UDP datagram. A missing NDP entry queues the
/// complete UDP segment until a Neighbor Advertisement supplies the MAC.
#[allow(clippy::too_many_arguments)]
pub fn send_udp(
    net_ns_id: u64,
    source: Option<[u8; 16]>,
    source_port: u16,
    destination: [u8; 16],
    destination_port: u16,
    payload: &[u8],
    bound_ifindex: u32,
    hop_limit: u8,
    traffic_class: u8,
    socket_mtu: Option<u32>,
    mtu_discover: u32,
    dontfrag: bool,
    tx: Udp6TxOpts,
) -> Result<usize, Udp6SendError> {
    let scoped_iface = if bound_ifindex == 0 {
        None
    } else {
        crate::iface::snapshot_all_in(net_ns_id)
            .into_iter()
            .find(|entry| crate::iface::ifindex_of(&entry.name) == Some(bound_ifindex))
            .map(|entry| entry.name)
    };
    if bound_ifindex != 0 && scoped_iface.is_none() {
        return Err(Udp6SendError::NetworkUnreachable);
    }
    let next_hop = crate::ipv6::route::lookup_in(net_ns_id, &destination, scoped_iface.as_deref());
    let (iface_name, neighbor_ip) = match next_hop {
        crate::ipv6::route::NextHop::Direct(iface) => (iface, destination),
        crate::ipv6::route::NextHop::Gateway { iface, gateway } => (iface, gateway),
        crate::ipv6::route::NextHop::Unreachable => return Err(Udp6SendError::NetworkUnreachable),
    };
    let iface =
        crate::iface::lookup_in(net_ns_id, &iface_name).ok_or(Udp6SendError::NetworkUnreachable)?;
    let source = match source {
        Some(addr) if addr != [0; 16] => addr,
        _ => crate::ipv6::addrs::list_iface_in(net_ns_id, &iface_name)
            .into_iter()
            .find(|entry| {
                matches!(
                    entry.state,
                    crate::ipv6::addrs::AddrState::Preferred
                        | crate::ipv6::addrs::AddrState::Deprecated
                )
            })
            .map(|entry| entry.addr)
            .ok_or(Udp6SendError::NoSourceAddress)?,
    };
    if payload.len() > u16::MAX as usize - 8 {
        return Err(Udp6SendError::MessageTooLong);
    }
    let path_mtu = PMTU
        .lock()
        .get(&(net_ns_id, destination))
        .copied()
        .unwrap_or(iface.mtu)
        .min(iface.mtu)
        .min(socket_mtu.unwrap_or(u32::MAX).max(1280));
    let may_fragment = !dontfrag && (mtu_discover < 2 || mtu_discover == 5);
    // A GSO send is appended against IP6_MAX_MTU (`__ip6_append_data`), then
    // `udp_v6_send_skb` checks each segment against the cork's fragsize.
    let segment = if tx.gso_size != 0 {
        match crate::udp_gso::gso_check(
            IPV6_HDR_LEN,
            payload.len(),
            tx.gso_size,
            path_mtu,
            tx.no_check6_tx,
        ) {
            Ok(split) => split,
            Err(crate::udp_gso::GsoError::MsgSize) => return Err(Udp6SendError::MessageTooLong),
            Err(crate::udp_gso::GsoError::Invalid) => return Err(Udp6SendError::GsoInvalid),
        }
    } else {
        if IPV6_HDR_LEN + 8 + payload.len() > path_mtu as usize && !may_fragment {
            return Err(Udp6SendError::MessageTooLong);
        }
        false
    };
    // `__udp_gso_segment`: every segment is a datagram with its own UDP
    // header and full checksum.
    let mut udps = Vec::new();
    if segment {
        for chunk in crate::udp_gso::segment_payload(payload, usize::from(tx.gso_size)) {
            udps.push(build_udp_segment(
                source,
                destination,
                source_port,
                destination_port,
                chunk,
            )?);
        }
    } else {
        let mut udp =
            build_udp_segment(source, destination, source_port, destination_port, payload)?;
        if tx.no_check6_tx {
            // `udp_v6_send_skb`: CHECKSUM_NONE leaves `uh->check` zero.
            udp[6..8].copy_from_slice(&[0, 0]);
        }
        udps.push(udp);
    }
    let hop_limit = if hop_limit == 0 { 64 } else { hop_limit };
    let destination_mac = if destination[0] == 0xff {
        [
            0x33,
            0x33,
            destination[12],
            destination[13],
            destination[14],
            destination[15],
        ]
    } else if let Some(mac) =
        crate::ipv6::ndp::neigh_lookup_in(net_ns_id, &iface_name, &neighbor_ip)
    {
        mac
    } else {
        for udp in udps {
            queue_udp6(PendingUdp6 {
                net_ns_id,
                iface: iface_name.clone(),
                neighbor: neighbor_ip,
                source,
                destination,
                hop_limit,
                traffic_class,
                udp,
                mtu: path_mtu,
                may_fragment,
            })?;
        }
        start_neighbor_resolution(net_ns_id, &iface_name, source, neighbor_ip);
        return Ok(payload.len());
    };

    for udp in &udps {
        emit_udp6(
            &iface,
            destination_mac,
            source,
            destination,
            hop_limit,
            traffic_class,
            udp,
            path_mtu,
            may_fragment,
        )?;
    }
    Ok(payload.len())
}

#[allow(clippy::too_many_arguments)]
/// Patch the IPv6 Traffic Class field (for ECN / DSCP from `IPV6_TCLASS`) into
/// a frame `build_frame` just wrote with TC 0. The first 4 header bytes are
/// version(4) | traffic_class(8) | flow_label(20); `build_frame` writes
/// version 6 + flow_label 0, so only the TC bits (low nibble of byte 0, high
/// nibble of byte 1) need setting, preserving version and the flow label.
fn apply_tclass(frame: &mut [u8], tc: u8) {
    let base = ETH_HDR_LEN;
    frame[base] = 0x60 | (tc >> 4);
    frame[base + 1] = (frame[base + 1] & 0x0f) | ((tc & 0x0f) << 4);
}

#[allow(clippy::too_many_arguments)]
fn emit_udp6(
    iface: &crate::iface::NetIfaceSnapshot,
    destination_mac: [u8; 6],
    source: [u8; 16],
    destination: [u8; 16],
    hop_limit: u8,
    traffic_class: u8,
    udp: &[u8],
    mtu: u32,
    may_fragment: bool,
) -> Result<(), Udp6SendError> {
    if IPV6_HDR_LEN + udp.len() <= mtu as usize {
        let mut frame = Vec::new();
        build_frame(
            &mut frame,
            Ipv6FrameSpec {
                src_mac: iface.mac,
                dst_mac: destination_mac,
                src_ip: source,
                dst_ip: destination,
                next_header: NEXT_HEADER_UDP,
                hop_limit,
                body: udp,
            },
        );
        apply_tclass(&mut frame, traffic_class);
        return iface.xmit(&frame).map_err(|_| Udp6SendError::DeviceFailure);
    }
    if !may_fragment || mtu as usize <= IPV6_HDR_LEN + 8 {
        return Err(Udp6SendError::MessageTooLong);
    }
    let id = NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
    for fragment in fragment_udp6(udp, mtu, id)? {
        let mut frame = Vec::new();
        build_frame(
            &mut frame,
            Ipv6FrameSpec {
                src_mac: iface.mac,
                dst_mac: destination_mac,
                src_ip: source,
                dst_ip: destination,
                next_header: NEXT_HEADER_FRAGMENT,
                hop_limit,
                body: &fragment,
            },
        );
        apply_tclass(&mut frame, traffic_class);
        iface
            .xmit(&frame)
            .map_err(|_| Udp6SendError::DeviceFailure)?;
    }
    Ok(())
}

fn fragment_udp6(udp: &[u8], mtu: u32, id: u32) -> Result<Vec<Vec<u8>>, Udp6SendError> {
    let chunk_len = ((mtu as usize - IPV6_HDR_LEN - 8) / 8) * 8;
    if chunk_len == 0 {
        return Err(Udp6SendError::MessageTooLong);
    }
    let mut fragments = Vec::new();
    let mut offset = 0usize;
    while offset < udp.len() {
        let end = (offset + chunk_len).min(udp.len());
        let more = end < udp.len();
        let mut fragment = Vec::with_capacity(8 + end - offset);
        fragment.push(NEXT_HEADER_UDP);
        fragment.push(0);
        let offset_flags = ((offset / 8) as u16) << 3 | u16::from(more);
        fragment.extend_from_slice(&offset_flags.to_be_bytes());
        fragment.extend_from_slice(&id.to_be_bytes());
        fragment.extend_from_slice(&udp[offset..end]);
        fragments.push(fragment);
        offset = end;
    }
    Ok(fragments)
}

#[doc(hidden)]
pub fn __fragment_udp6_for_test(udp: &[u8], mtu: u32, id: u32) -> Option<Vec<Vec<u8>>> {
    fragment_udp6(udp, mtu, id).ok()
}

fn start_neighbor_resolution(net_ns_id: u64, iface_name: &str, source: [u8; 16], target: [u8; 16]) {
    let now = narf_scheduler::narf_time::monotonic_ns();
    if let Some(existing) = crate::ipv6::ndp::neigh_list_in(net_ns_id)
        .into_iter()
        .find(|entry| entry.iface == iface_name && entry.ip == target)
    {
        if existing.mac.is_some() || existing.deadline_ns == 0 || now < existing.deadline_ns {
            return;
        }
        crate::ipv6::ndp::neigh_remove_in(net_ns_id, iface_name, &target);
    }
    crate::ipv6::ndp::neigh_upsert_in(
        net_ns_id,
        crate::ipv6::ndp::Neigh {
            iface: alloc::string::String::from(iface_name),
            ip: target,
            mac: None,
            state: crate::ipv6::ndp::NeighState::Incomplete,
            is_router: false,
            deadline_ns: now.saturating_add(1_000_000_000),
        },
    );
    // The solicitation itself goes out through the ICMPv6 transmit
    // surface (same frame as before: solicited-node multicast dst,
    // hop limit 255, Source LL Address option).
    let _ = send_ns_in(net_ns_id, iface_name, source, target);
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

// ── ICMPv6 transmit surface (#1536) ─────────────────────────────────
//
// The stack side of the virtio-net gap-13 remainder: until this lane,
// nothing could originate an ICMPv6 packet on an interface — the
// solicited NS→NA reply body and the Echo Reply body were both built
// and dropped in `handle_icmp6`. The entry point is `send_icmp6_in`;
// the typed wrappers below cover the messages the stack originates
// itself (Echo Request, Neighbor Solicitation, solicited +
// unsolicited Neighbor Advertisement, RFC 4443 errors).
//
// References (public-only):
// - RFC 4443 — ICMPv6. §2.2 (reply source determination), §2.3
//   (pseudo-header checksum), §2.4(c) (error truncation to the
//   minimum IPv6 MTU) + (e) (when an error must NOT be originated)
//   + (f) (error rate limiting — the token bucket in
//   `icmp6_error_rate_limiter`, applied by `send_icmp6_error_in`),
//   §3 (error formats), §4 (echo).
//   <https://datatracker.ietf.org/doc/html/rfc4443>
// - RFC 4861 — Neighbor Discovery. §7.2.2 (sending NS), §7.2.4
//   (solicited NA), §7.2.6 (unsolicited NA).
//   <https://datatracker.ietf.org/doc/html/rfc4861>
// - RFC 8200 — IPv6. §3 (header), §8.1 (pseudo-header checksum).
//   <https://datatracker.ietf.org/doc/html/rfc8200>

/// Hop limit for originated ICMPv6 echo / error messages (Linux
/// `ip6_dst_hoplimit` default). ND messages use 255 instead — a
/// receiver discards them with any other value (RFC 4861 §7.1.1,
/// §7.1.2) — so the ND wrappers pass [`ICMPV6_ND_HOP_LIMIT`].
pub const ICMPV6_ORIGIN_HOP_LIMIT: u8 = 64;

/// Hop limit for originated ND messages (NS / NA). RFC 4861 §7.1.1,
/// §7.1.2: receivers MUST discard ND messages with hop limit != 255.
pub const ICMPV6_ND_HOP_LIMIT: u8 = 255;

/// Errors from the ICMPv6 transmit path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Icmp6SendError {
    /// No usable source address on the interface.
    NoSourceAddress,
    /// Unicast destination has no neighbor-cache entry: the packet was
    /// queued and resolution started (RFC 4861 §7.2.2); it is not on
    /// the wire yet. It is emitted when the NA arrives
    /// ([`neighbor_resolved`]).
    NeighborPending,
    /// Interface (or its namespace) does not exist.
    NetworkUnreachable,
    /// Frame exceeds the interface MTU, or the body is shorter than
    /// the 4-byte ICMPv6 header. ICMPv6 messages are never fragmented
    /// by this path.
    MessageTooLong,
    /// The device refused the frame.
    DeviceFailure,
    /// The pending-resolution queue is full; the packet was dropped.
    QueueFull,
    /// RFC 4443 §2.4(e): an error message must not be originated for
    /// this invoking packet. Nothing was queued or sent.
    ErrorSuppressed,
    /// RFC 4443 §2.4(f): the originated-error rate limit was
    /// exhausted. Nothing was queued or sent; the caller may retry
    /// after the bucket refills.
    RateLimited,
}

/// Emit one ICMPv6 message on an already-resolved interface: stamp
/// the pseudo-header checksum (bytes 2..4 are zeroed first, so a body
/// whose checksum a builder already filled is re-stamped, not
/// double-counted), build the Ethernet + IPv6 frame, and hand it to
/// the device.
fn emit_icmp6_frame(
    iface: &crate::iface::NetIfaceSnapshot,
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    hop_limit: u8,
    body: &[u8],
) -> Result<(), Icmp6SendError> {
    if body.len() < ICMPV6_HDR_LEN || ETH_HDR_LEN + IPV6_HDR_LEN + body.len() > iface.mtu as usize {
        return Err(Icmp6SendError::MessageTooLong);
    }
    let mut body = body.to_vec();
    // RFC 4443 §2.3 / RFC 8200 §8.1: the checksum covers the ICMPv6
    // message plus the IPv6 pseudo-header (next header 58), with the
    // checksum field zeroed while computing.
    body[2] = 0;
    body[3] = 0;
    let cks = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &body);
    body[2] = (cks >> 8) as u8;
    body[3] = (cks & 0xFF) as u8;
    let mut frame = Vec::new();
    build_frame(
        &mut frame,
        Ipv6FrameSpec {
            src_mac: iface.mac,
            dst_mac,
            src_ip,
            dst_ip,
            next_header: NEXT_HEADER_ICMPV6,
            hop_limit,
            body: &body,
        },
    );
    iface
        .xmit(&frame)
        .map_err(|_| Icmp6SendError::DeviceFailure)
}

/// Originate one ICMPv6 message on `iface_name`: resolve the
/// link-layer destination (RFC 2464 §7 multicast mapping for
/// ff00::/8, neighbor-cache lookup otherwise), build the frame, and
/// transmit it through the interface's device path. A unicast
/// destination with no cache entry queues the complete message and
/// starts neighbor resolution (RFC 4861 §7.2.2); the caller gets
/// `NeighborPending` and the message is emitted when the NA arrives.
/// `body` carries a zero checksum field — it is stamped here.
pub fn send_icmp6(
    iface_name: &str,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    body: &[u8],
    hop_limit: u8,
) -> Result<(), Icmp6SendError> {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_icmp6_in(net_ns_id, iface_name, src_ip, dst_ip, body, hop_limit)
}

pub fn send_icmp6_in(
    net_ns_id: u64,
    iface_name: &str,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    body: &[u8],
    hop_limit: u8,
) -> Result<(), Icmp6SendError> {
    let iface =
        crate::iface::lookup_in(net_ns_id, iface_name).ok_or(Icmp6SendError::NetworkUnreachable)?;
    if ETH_HDR_LEN + IPV6_HDR_LEN + body.len() > iface.mtu as usize {
        return Err(Icmp6SendError::MessageTooLong);
    }
    let dst_mac = if dst_ip[0] == 0xff {
        // RFC 2464 §7: multicast IPv6 → 33:33:<low 32 bits>.
        [0x33, 0x33, dst_ip[12], dst_ip[13], dst_ip[14], dst_ip[15]]
    } else if let Some(mac) = crate::ipv6::ndp::neigh_lookup_in(net_ns_id, iface_name, &dst_ip) {
        mac
    } else {
        // No cache entry: queue the message and solicit the neighbor
        // (same pattern as the UDP pending queue in `send_udp`).
        queue_icmp6(PendingIcmp6 {
            net_ns_id,
            iface: String::from(iface_name),
            neighbor: dst_ip,
            source: src_ip,
            destination: dst_ip,
            hop_limit,
            body: body.to_vec(),
        })?;
        start_neighbor_resolution(net_ns_id, iface_name, src_ip, dst_ip);
        return Err(Icmp6SendError::NeighborPending);
    };
    emit_icmp6_frame(&iface, dst_mac, src_ip, dst_ip, hop_limit, body)
}

/// Originate an ICMPv6 Echo Request (RFC 4443 §4.1) to `dst` from the
/// interface's scope-matched source address. Returns the payload
/// length on success, mirroring `send_udp`. A cold neighbor cache
/// queues the request and returns `NeighborPending`.
pub fn send_echo_request(
    iface_name: &str,
    dst: [u8; 16],
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Result<usize, Icmp6SendError> {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_echo_request_in(net_ns_id, iface_name, dst, id, seq, payload)
}

pub fn send_echo_request_in(
    net_ns_id: u64,
    iface_name: &str,
    dst: [u8; 16],
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Result<usize, Icmp6SendError> {
    let source = crate::ipv6::addrs::pick_source_in(net_ns_id, iface_name, &dst)
        .ok_or(Icmp6SendError::NoSourceAddress)?;
    let body = icmp6_sock::build_echo_request(id, seq, payload);
    send_icmp6_in(
        net_ns_id,
        iface_name,
        source,
        dst,
        &body,
        ICMPV6_ORIGIN_HOP_LIMIT,
    )?;
    Ok(payload.len())
}

/// Originate a Neighbor Solicitation for `target` from `src_ip`
/// (RFC 4861 §7.2.2): destination is the target's solicited-node
/// multicast, hop limit 255, Source LL Address option = iface MAC.
pub fn send_ns(iface_name: &str, src_ip: [u8; 16], target: [u8; 16]) -> Result<(), Icmp6SendError> {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_ns_in(net_ns_id, iface_name, src_ip, target)
}

pub fn send_ns_in(
    net_ns_id: u64,
    iface_name: &str,
    src_ip: [u8; 16],
    target: [u8; 16],
) -> Result<(), Icmp6SendError> {
    let iface =
        crate::iface::lookup_in(net_ns_id, iface_name).ok_or(Icmp6SendError::NetworkUnreachable)?;
    let dst_ip = crate::ipv6::addrs::solicited_node_multicast(&target);
    let body = build_ns_packet(src_ip, dst_ip, target, iface.mac);
    send_icmp6_in(
        net_ns_id,
        iface_name,
        src_ip,
        dst_ip,
        &body,
        ICMPV6_ND_HOP_LIMIT,
    )
}

/// Originate one unsolicited Neighbor Advertisement for `target` on
/// `iface_name` (RFC 4861 §7.2.6): Solicited clear, Override set,
/// Target LL Address option = iface MAC, IPv6 source = `target`,
/// destination ff02::1 (all-nodes), hop limit 255. This is the emit
/// surface the virtio-net gap-13 remainder (#1536) was missing: the
/// driver announce path calls [`send_unsolicited_na`] (below)
/// alongside the existing IPv4 gratuitous ARP.
pub fn send_unsolicited_na_for(iface_name: &str, target: [u8; 16]) -> Result<(), Icmp6SendError> {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_unsolicited_na_for_in(net_ns_id, iface_name, target)
}

pub fn send_unsolicited_na_for_in(
    net_ns_id: u64,
    iface_name: &str,
    target: [u8; 16],
) -> Result<(), Icmp6SendError> {
    let iface =
        crate::iface::lookup_in(net_ns_id, iface_name).ok_or(Icmp6SendError::NetworkUnreachable)?;
    let body = ndp::build_unsolicited_na(target, iface.mac);
    send_icmp6_in(
        net_ns_id,
        iface_name,
        target,
        crate::ipv6::addrs::ALL_NODES_MULTICAST,
        &body,
        ICMPV6_ND_HOP_LIMIT,
    )
}

/// Originate one unsolicited Neighbor Advertisement per usable address
/// on `iface_name` (Linux analog: `netdev_notify_peers` →
/// `ndisc_notify`). Returns the number of advertisements emitted.
/// Only Preferred/Deprecated addresses are announced — a Tentative
/// address is still owned by DAD and must not be advertised.
///
/// NOTE (RFC 4861 §7.2.6 SHOULD): a node with several addresses
/// SHOULD introduce a small delay between the advertisements to
/// reduce the probability of loss from congestion. This call emits
/// synchronously, one per address, with no pacing — callers that
/// need pacing should drive [`send_unsolicited_na_for`] per address
/// from a timer instead.
pub fn send_unsolicited_na(iface_name: &str) -> usize {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_unsolicited_na_in(net_ns_id, iface_name)
}

pub fn send_unsolicited_na_in(net_ns_id: u64, iface_name: &str) -> usize {
    use crate::ipv6::addrs::AddrState;
    let mut sent = 0usize;
    for entry in crate::ipv6::addrs::list_iface_in(net_ns_id, iface_name) {
        if !matches!(entry.state, AddrState::Preferred | AddrState::Deprecated) {
            continue;
        }
        if send_unsolicited_na_for_in(net_ns_id, iface_name, entry.addr).is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Which ICMPv6 error message to originate (RFC 4443 §3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Icmp6ErrorKind {
    /// Type 1. Code: 0 no route, 1 administratively prohibited,
    /// 2 beyond scope of source, 3 address unreachable, 4 port
    /// unreachable, 5 source failed ingress/egress policy, 6 reject
    /// route. (RFC 4443 §3.1; there is no code 7.)
    DestinationUnreachable(u8),
    /// Type 2, code 0. Carries the MTU of the next-hop link
    /// (RFC 4443 §3.2).
    PacketTooBig(u32),
    /// Type 3. Code: 0 hop limit exceeded in transit, 1 fragment
    /// reassembly time exceeded (RFC 4443 §3.3).
    TimeExceeded(u8),
    /// Type 4. (Code, Pointer): 0 erroneous header field,
    /// 1 unrecognized Next Header, 2 unrecognized IPv6 option;
    /// Pointer is the octet offset of the problem within the
    /// invoking packet (RFC 4443 §3.4).
    ParameterProblem(u8, u32),
}

impl Icmp6ErrorKind {
    fn body(self, invoking: &[u8]) -> Vec<u8> {
        match self {
            Icmp6ErrorKind::DestinationUnreachable(code) => {
                crate::pkt_ipv6::destination_unreachable(code, invoking)
            }
            Icmp6ErrorKind::PacketTooBig(mtu) => crate::pkt_ipv6::packet_too_big(mtu, invoking),
            Icmp6ErrorKind::TimeExceeded(code) => crate::pkt_ipv6::time_exceeded(code, invoking),
            Icmp6ErrorKind::ParameterProblem(code, pointer) => {
                crate::pkt_ipv6::parameter_problem(code, pointer, invoking)
            }
        }
    }

    /// The two §2.4(e.3) exceptions that MAY answer a
    /// multicast-destined packet: Packet Too Big, and Parameter
    /// Problem code 2.
    fn allows_multicast_dst(self) -> bool {
        matches!(
            self,
            Icmp6ErrorKind::PacketTooBig(_) | Icmp6ErrorKind::ParameterProblem(2, _)
        )
    }
}

/// Whether an error message of `kind` may be originated for
/// `invoking` (RFC 4443 §2.4(e)). `invoking` is the offending packet
/// starting at its IPv6 header; shorter than a header, or with a
/// non-identifying source, fails closed (no error is sent).
fn error_may_originate(kind: Icmp6ErrorKind, invoking: &[u8]) -> bool {
    if invoking.len() < IPV6_HDR_LEN {
        return false;
    }
    let src: [u8; 16] = invoking[8..24].try_into().unwrap();
    let dst: [u8; 16] = invoking[24..40].try_into().unwrap();
    // (e.6) The source must uniquely identify a single node: not
    // the Unspecified Address, not a multicast address.
    if src == [0; 16] || src[0] == 0xff {
        return false;
    }
    // (e.3) No error for a multicast-destined packet, except Packet
    // Too Big and Parameter Problem code 2.
    if dst[0] == 0xff && !kind.allows_multicast_dst() {
        return false;
    }
    // (e.1)/(e.2) No error in response to an ICMPv6 error message or
    // a Redirect. Walk the extension chain to the L4 header; an
    // unidentifiable L4 is not provably either, so it does not
    // suppress on this ground.
    let nh = invoking[6];
    if let Some(l4) = skip_extension_headers(nh, &invoking[IPV6_HDR_LEN..]) {
        if l4.proto == NEXT_HEADER_ICMPV6 {
            let off = IPV6_HDR_LEN + l4.offset;
            if off < invoking.len() {
                let typ = invoking[off];
                if typ < 128 || typ == ICMPV6_REDIRECT {
                    return false;
                }
            }
        }
    }
    true
}

// ── ICMPv6 originated-error rate limiting (RFC 4443 §2.4(f)) ────────
//
// §2.4(f) REQUIRES an IPv6 node to limit the rate of ICMPv6 error
// messages it originates, "in order to limit the bandwidth and
// forwarding costs incurred by originating ICMPv6 error messages",
// and the §2.4(e)/(f) restrictions take precedence over any
// requirement elsewhere to originate an error. The recommended method
// is a token bucket: up to B error messages in a burst, refilling at
// an average rate of N per second. The parameters SHOULD be
// configurable; for a small/mid-size device the RFC's example
// defaults are B=10, N=10/s, and those are the defaults here — NARF
// is a host, not a high-end router, so no deviation from the RFC
// examples is warranted.
//
// Scope decision: ONE bucket per node (global), not per-interface or
// per-destination. The RFC frames the limit per node ("an IPv6 node
// MUST limit the rate of ICMPv6 error messages it originates"), and
// a single bucket is the smallest mechanism that satisfies the MUST
// without unbounded per-destination state (which would need bounded
// eviction). Trade-off, stated plainly: one destination flooding the
// stack with erroneous packets can exhaust the shared bucket and
// suppress errors to other destinations until it refills. A
// per-destination limiter is a possible follow-up if that starvation
// matters; it is not required by §2.4(f).
//
// The algorithm mirrors `crate::netfilter::IcmpRateLimit` (the IPv4
// ICMP bucket): lock-free atomics, refill from the monotonic clock,
// `try_acquire(now_ns)` takes an explicit clock so tests can inject
// time deterministically. The bucket is consulted by
// `send_icmp6_error_in`, so every originator is covered; the
// `#1727` RX-triggered error generators consume the same entry point
// (`icmp6_error_rate_limiter`) instead of growing a second limiter.

/// Token-bucket burst for originated ICMPv6 errors (RFC 4443
/// §2.4(f) example default for a small/mid-size device).
pub const ICMPV6_ERROR_RATE_LIMIT_BURST: u64 = 10;

/// Token-bucket refill rate, errors per second, for originated
/// ICMPv6 errors (RFC 4443 §2.4(f) example default for a
/// small/mid-size device).
pub const ICMPV6_ERROR_RATE_LIMIT_PER_SEC: u64 = 10;

/// Token-bucket limiter for originated ICMPv6 errors (RFC 4443
/// §2.4(f)). Lock-free: atomics only, no spinlock, so it is safe on
/// the RX-driven error paths that call `send_icmp6_error_in`.
#[derive(Debug)]
pub struct Icmp6ErrorRateLimiter {
    /// Tokens currently available.
    tokens: AtomicU64,
    /// Last refill time in nanoseconds (monotonic).
    last_refill_ns: AtomicU64,
    /// Maximum tokens / bucket capacity (B).
    capacity: AtomicU64,
    /// Refill rate in tokens per second (N).
    rate_per_sec: AtomicU64,
}

impl Icmp6ErrorRateLimiter {
    pub const fn new(burst: u64, rate_per_sec: u64) -> Self {
        Self {
            tokens: AtomicU64::new(burst),
            last_refill_ns: AtomicU64::new(0),
            capacity: AtomicU64::new(burst),
            rate_per_sec: AtomicU64::new(rate_per_sec),
        }
    }

    /// Try to consume one token. Returns `true` on success (caller
    /// may originate the ICMPv6 error), `false` on rate-limit (drop
    /// instead, returning [`Icmp6SendError::RateLimited`]).
    ///
    /// `now_ns` is the current monotonic time in nanoseconds. Tests
    /// inject this directly; production callers use
    /// [`Icmp6ErrorRateLimiter::try_acquire_now`].
    pub fn try_acquire(&self, now_ns: u64) -> bool {
        self.refill(now_ns);
        // Optimistic decrement.
        loop {
            let cur = self.tokens.load(Ordering::Acquire);
            if cur == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// [`Icmp6ErrorRateLimiter::try_acquire`] at the current
    /// monotonic time. This is the entry point originators call:
    /// `icmp6_error_rate_limiter().try_acquire_now()`.
    pub fn try_acquire_now(&self) -> bool {
        self.try_acquire(narf_scheduler::narf_time::monotonic_ns())
    }

    /// Refill based on elapsed time since the last refill.
    /// Idempotent — callers don't need to lock around it.
    fn refill(&self, now_ns: u64) {
        let last = self.last_refill_ns.load(Ordering::Acquire);
        if now_ns <= last {
            return;
        }
        let elapsed = now_ns - last;
        // Tokens-to-add = (elapsed_ns * rate) / 1e9.
        let rate = self.rate_per_sec.load(Ordering::Acquire);
        let to_add = elapsed.saturating_mul(rate) / 1_000_000_000;
        if to_add == 0 {
            return;
        }
        // CAS last_refill_ns so concurrent callers don't double-count.
        if self
            .last_refill_ns
            .compare_exchange(last, now_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Cap tokens at capacity.
        let capacity = self.capacity.load(Ordering::Acquire);
        let mut cur = self.tokens.load(Ordering::Acquire);
        loop {
            let new = core::cmp::min(capacity, cur.saturating_add(to_add));
            match self
                .tokens
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Reconfigure the bucket (RFC 4443 §2.4(f): "The rate-limiting
    /// parameters SHOULD be configurable"). `burst` is B, the maximum
    /// burst size; `rate_per_sec` is N, the long-term average rate.
    /// A burst of 0 disables originated errors entirely; a rate of 0
    /// never refills. Tokens above a shrunk capacity are clamped
    /// away at once, so the new burst bound applies immediately.
    pub fn configure(&self, burst: u64, rate_per_sec: u64) {
        self.capacity.store(burst, Ordering::Release);
        self.rate_per_sec.store(rate_per_sec, Ordering::Release);
        // Clamp any surplus tokens to the new capacity.
        let mut cur = self.tokens.load(Ordering::Acquire);
        loop {
            let new = core::cmp::min(burst, cur);
            match self
                .tokens
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Current burst bound (B).
    pub fn burst(&self) -> u64 {
        self.capacity.load(Ordering::Acquire)
    }

    /// Current refill rate (N, errors per second).
    pub fn rate_per_sec(&self) -> u64 {
        self.rate_per_sec.load(Ordering::Acquire)
    }

    /// Currently available tokens (smoke instrumentation).
    pub fn tokens_available(&self) -> u64 {
        self.tokens.load(Ordering::Acquire)
    }

    /// Restore the RFC 4443 §2.4(f) example defaults (B=10, N=10/s)
    /// with a full bucket. Test-only; also called from
    /// [`__reset_for_test`] so every smoke starts un-limited.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.capacity
            .store(ICMPV6_ERROR_RATE_LIMIT_BURST, Ordering::Release);
        self.rate_per_sec
            .store(ICMPV6_ERROR_RATE_LIMIT_PER_SEC, Ordering::Release);
        self.tokens
            .store(ICMPV6_ERROR_RATE_LIMIT_BURST, Ordering::Release);
        self.last_refill_ns.store(0, Ordering::Release);
    }
}

/// The node's single originated-ICMPv6-error token bucket
/// (RFC 4443 §2.4(f), defaults B=10, N=10/s).
static ICMP6_ERROR_RATE_LIMIT: Icmp6ErrorRateLimiter = Icmp6ErrorRateLimiter::new(
    ICMPV6_ERROR_RATE_LIMIT_BURST,
    ICMPV6_ERROR_RATE_LIMIT_PER_SEC,
);

/// The global originated-ICMPv6-error rate limiter. This is the
/// small entry point every error originator consumes — including the
/// #1727 RX-triggered error generators, which are specified as
/// subject to this limit: call `try_acquire_now()` before
/// originating, and drop (returning [`Icmp6SendError::RateLimited`])
/// when it returns `false`. `send_icmp6_error_in` already does this
/// for the send path itself, so generators that go through it are
/// covered without a second check.
pub fn icmp6_error_rate_limiter() -> &'static Icmp6ErrorRateLimiter {
    &ICMP6_ERROR_RATE_LIMIT
}

/// Originate an ICMPv6 error message for `invoking` (RFC 4443 §3).
/// `src_ip` is this node's address the error is sent from (the
/// address the invoking packet was destined to); the error's
/// destination is copied from the invoking packet's source (RFC 4443
/// §3, "Destination Address"). The invoking packet is quoted up to
/// the minimum-IPv6-MTU bound (RFC 4443 §2.4(c)) and the §2.4(e)
/// suppression rules are applied — a suppressed error returns
/// `ErrorSuppressed` and sends nothing. The §2.4(f) token bucket
/// ([`icmp6_error_rate_limiter`]) is then consulted: an exhausted
/// bucket returns `RateLimited` and sends nothing, so the §2.4(e)/(f)
/// restrictions take precedence over any requirement to originate an
/// error, as §2.4 requires. Callers no longer need to self-throttle
/// per-packet on a fast path — the limiter bounds the originated
/// rate — but they must still only originate errors for packets the
/// stack itself drops for a specific reason.
///
/// The (e.4)/(e.5) link-layer multicast/broadcast checks still need
/// the RX path to forward the L2 destination: [`rx_frame_l2`] threads
/// it through as [`L2Dst`], and the #1727 RX-triggered generators
/// suppress themselves on a link-layer multicast/broadcast frame.
/// Callers of this entry point that cannot see the L2 destination
/// (notably the test-only [`rx_frame`]) pass [`L2Dst::Unknown`], which
/// fails open — the checks cannot be evaluated without the address.
pub fn send_icmp6_error(
    iface_name: &str,
    src_ip: [u8; 16],
    kind: Icmp6ErrorKind,
    invoking: &[u8],
) -> Result<(), Icmp6SendError> {
    let net_ns_id = crate::iface::lookup(iface_name)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    send_icmp6_error_in(net_ns_id, iface_name, src_ip, kind, invoking)
}

pub fn send_icmp6_error_in(
    net_ns_id: u64,
    iface_name: &str,
    src_ip: [u8; 16],
    kind: Icmp6ErrorKind,
    invoking: &[u8],
) -> Result<(), Icmp6SendError> {
    if !error_may_originate(kind, invoking) {
        return Err(Icmp6SendError::ErrorSuppressed);
    }
    // RFC 4443 §2.4(f): limit the rate of originated errors. The
    // bucket is checked after the §2.4(e) suppression rules so a
    // suppressed error never burns a token, and before any frame is
    // built or queued so a limited error costs nothing.
    if !ICMP6_ERROR_RATE_LIMIT.try_acquire_now() {
        return Err(Icmp6SendError::RateLimited);
    }
    // §3: the error's destination is the invoking packet's source.
    let dst_ip: [u8; 16] = invoking[8..24].try_into().unwrap();
    let body = kind.body(invoking);
    send_icmp6_in(
        net_ns_id,
        iface_name,
        src_ip,
        dst_ip,
        &body,
        ICMPV6_ORIGIN_HOP_LIMIT,
    )
}

// ── Inbound dispatch ────────────────────────────────────────────────
//
// #1727 RX-triggered ICMPv6 error generation points (each goes through
// `send_icmp6_error_in`, so the §2.4(e) suppression + §2.4(f) rate
// limit apply to every one):
//   (a) UDP RX with no listener → Destination Unreachable code 4,
//       in `handle_udp6` (Linux `__udp6_lib_rcv`). LIVE.
//   (b) Packet Too Big for forwarded packets exceeding the next-hop
//       MTU → NOT APPLICABLE: there is no IPv6 forwarding path in
//       this tree (`ip_forward::try_forward` is IPv4-only and
//       `tcp_stack::dispatch_l3` has no IPv6 arm), and a host that
//       does not forward has nothing to generate (Linux `ip6_forward`
//       is only reached when forwarding is enabled). The PTB builder
//       stays available for the forwarding lane that owns this.
//   (c) Time Exceeded code 1 on fragment reassembly timeout, in the
//       fragment branch below (Linux `ip6_expire_frag_queue`). LIVE.
//   (d) RFC 4443 §2.4(e.4)/(e.5) link-layer suppression: the L2
//       destination is threaded through as `L2Dst`. LIVE for the
//       generators below; `send_icmp6_error_in` itself cannot see it.

/// Class of the link-layer destination a frame arrived on, for the
/// RFC 4443 §2.4(e.4)/(e.5) suppression checks: no error may be
/// originated for a packet received as a link-layer multicast or
/// broadcast. The broadcast address has the I/G bit set, so one
/// class covers both rules.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum L2Dst {
    /// The L2 destination is not known (legacy/test entry point):
    /// the (e.4)/(e.5) checks cannot be evaluated and fail open.
    Unknown,
    /// Unicast L2 destination: errors may be originated.
    Unicast,
    /// Link-layer multicast or broadcast destination: the #1727
    /// generators suppress themselves.
    Multicast,
}

impl L2Dst {
    /// Classify an Ethernet destination MAC by the I/G bit (LSB of
    /// the first octet).
    pub fn from_mac(dst_mac: [u8; 6]) -> Self {
        if dst_mac[0] & 1 != 0 {
            L2Dst::Multicast
        } else {
            L2Dst::Unicast
        }
    }
}

/// Inbound dispatch — call from the IPv6 RX hook in `tcp_stack`.
/// `iface` is the iface name on which the frame arrived. Returns
/// `true` iff the frame was recognised.
///
/// The L2 destination is unknown through this entry point, so the
/// §2.4(e.4)/(e.5) checks fail open; production callers that have
/// the Ethernet header use [`rx_frame_l2`].
pub fn rx_frame(iface: &str, frame_after_eth: &[u8]) -> bool {
    rx_frame_l2(iface, frame_after_eth, L2Dst::Unknown)
}

/// [`rx_frame`] with the link-layer destination class, for the
/// RFC 4443 §2.4(e.4)/(e.5) suppression checks. Production callers
/// classify the Ethernet destination MAC with [`L2Dst::from_mac`].
pub fn rx_frame_l2(iface: &str, frame_after_eth: &[u8], l2_dst: L2Dst) -> bool {
    rx_frame_l2_at(
        iface,
        frame_after_eth,
        l2_dst,
        narf_scheduler::narf_time::monotonic_ns(),
    )
}

/// [`rx_frame_l2`] with an explicit clock, so the fragment
/// reassembly timeout (and its Time Exceeded) can be exercised
/// deterministically.
#[doc(hidden)]
pub fn rx_frame_l2_at(iface: &str, frame_after_eth: &[u8], l2_dst: L2Dst, now_ns: u64) -> bool {
    let ip = match Ipv6Header::decode(frame_after_eth) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if frame_after_eth.len() < IPV6_HDR_LEN + ip.payload_length as usize {
        return false;
    }
    let payload = &frame_after_eth[IPV6_HDR_LEN..IPV6_HDR_LEN + ip.payload_length as usize];
    // Validate the checksum on ICMPv6 / UDP / TCP via the pseudo header.
    let nh = ip.next_header;
    // Handle a single Fragment header up front (RFC 8200 §4.5).
    if nh == NEXT_HEADER_FRAGMENT {
        if payload.len() < 8 {
            return false;
        }
        let frag_payload = &payload[8..];
        let (assembled, expired) = process_fragment_at(
            now_ns,
            ip.src_ip,
            ip.dst_ip,
            &payload[..8],
            frag_payload,
            frame_after_eth,
        );
        // #1727(c): Time Exceeded code 1 for each reassembly that
        // timed out (Linux `ip6_expire_frag_queue`). Each goes
        // through `send_icmp6_error_in` (§2.4(e)/(f) apply); a
        // link-layer multicast/broadcast frame suppresses, per
        // §2.4(e.4)/(e.5). Failures drop silently — the fragments
        // are already gone.
        if l2_dst != L2Dst::Multicast {
            let net_ns_id = crate::iface::lookup(iface)
                .map(|entry| entry.net_ns_id)
                .unwrap_or(0);
            for e in &expired {
                let _ = send_icmp6_error_in(
                    net_ns_id,
                    iface,
                    e.dst,
                    Icmp6ErrorKind::TimeExceeded(1),
                    &e.invoking,
                );
            }
        }
        let (next_nh, body) = match assembled {
            Some(t) => t,
            None => return true, // got the fragment, waiting for more
        };
        // Reconstruct the invoking (reassembled) packet for the L4
        // handlers: the decoded header with the reassembled length
        // and next-header, plus the reassembled body.
        let mut hdr = ip;
        hdr.payload_length = body.len() as u16;
        hdr.next_header = next_nh;
        let mut invoking = hdr.encode().to_vec();
        invoking.extend_from_slice(&body);
        return dispatch_l4(
            iface,
            ip.src_ip,
            ip.dst_ip,
            crate::udp_sock::RxIpMeta {
                ttl: ip.hop_limit,
                tos: ip.traffic_class,
            },
            next_nh,
            &body,
            Icmp6ErrorCtx {
                invoking: &invoking,
                l2_dst,
            },
        );
    }
    let l4 = match skip_extension_headers(nh, payload) {
        Some(l) => l,
        None => return false,
    };
    let invoking = &frame_after_eth[..IPV6_HDR_LEN + ip.payload_length as usize];
    dispatch_l4(
        iface,
        ip.src_ip,
        ip.dst_ip,
        crate::udp_sock::RxIpMeta {
            ttl: ip.hop_limit,
            tos: ip.traffic_class,
        },
        l4.proto,
        &payload[l4.offset..],
        Icmp6ErrorCtx { invoking, l2_dst },
    )
}

/// The context an L4 handler needs to originate an ICMPv6 error in
/// reply to the packet being dispatched (RFC 4443 §2.4(e)): the
/// invoking packet, quoted in the error body (§3), and the class of
/// the link-layer destination it arrived on, which gates whether an
/// error may be originated at all (§2.4(e.4)/(e.5)). The two travel
/// together — bundled so `dispatch_l4` stays under clippy's
/// argument-count limit without an `#[allow]`.
struct Icmp6ErrorCtx<'a> {
    invoking: &'a [u8],
    l2_dst: L2Dst,
}

fn dispatch_l4(
    iface: &str,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    meta: crate::udp_sock::RxIpMeta,
    proto: u8,
    l4: &[u8],
    err_ctx: Icmp6ErrorCtx<'_>,
) -> bool {
    match proto {
        NEXT_HEADER_ICMPV6 => handle_icmp6(iface, src_ip, dst_ip, l4),
        NEXT_HEADER_UDP => handle_udp6(iface, src_ip, dst_ip, meta, l4, err_ctx),
        NEXT_HEADER_TCP => handle_tcp6(iface, src_ip, dst_ip, l4),
        _ => false,
    }
}

fn handle_tcp6(iface: &str, src_ip: [u8; 16], dst_ip: [u8; 16], segment: &[u8]) -> bool {
    if segment.len() < crate::pkt_tcp::TCP_HDR_MIN {
        return true;
    }
    if pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_TCP, segment) != 0 {
        return true;
    }
    let net_ns_id = crate::iface::lookup(iface)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0);
    crate::tcp::core::handle_segment6_in(net_ns_id, src_ip, dst_ip, segment);
    true
}

fn handle_udp6(
    iface: &str,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    meta: crate::udp_sock::RxIpMeta,
    datagram: &[u8],
    err_ctx: Icmp6ErrorCtx<'_>,
) -> bool {
    const UDP_HDR_LEN: usize = 8;
    if datagram.len() < UDP_HDR_LEN {
        return true;
    }
    let length = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    // IPv6 UDP jumbograms use a zero length and require a Jumbo Payload
    // option. That extension is not accepted by this stack yet, so zero and
    // ordinary malformed lengths are silently discarded.
    if length < UDP_HDR_LEN || length > datagram.len() {
        return true;
    }
    let datagram = &datagram[..length];
    // Unlike IPv4, a zero UDP checksum is forbidden for IPv6 (RFC 8200 §8.1).
    if datagram[6..8] == [0, 0] || pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_UDP, datagram) != 0 {
        return true;
    }
    let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let (net_ns_id, ifindex) = crate::iface::lookup(iface)
        .map(|entry| {
            (
                entry.net_ns_id,
                crate::iface::ifindex_of(iface).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0));
    let delivered = crate::udp_sock::user_deliver(
        net_ns_id,
        &src_ip,
        src_port,
        &dst_ip,
        dst_port,
        &datagram[UDP_HDR_LEN..],
        ifindex,
        meta,
    );
    // #1727(a): no listener consumed the datagram. Linux
    // `__udp6_lib_rcv` answers that with Destination Unreachable
    // code 4 (port unreachable) — after the checksum validation
    // above, as here. The in-kernel socket table has no IPv6 demux
    // (`deliver_in` is IPv4-only), so the userspace delivery hook IS
    // the listener check for IPv6: `false` means no socket, in-kernel
    // or userspace, owns the port. The error goes through
    // `send_icmp6_error_in`, so the §2.4(e) suppression (including
    // (e.3) multicast destination) and the §2.4(f) rate limit apply;
    // a link-layer multicast/broadcast frame suppresses per
    // §2.4(e.4)/(e.5). Every failure drops silently.
    if !delivered && err_ctx.l2_dst != L2Dst::Multicast {
        let _ = send_icmp6_error_in(
            net_ns_id,
            iface,
            dst_ip,
            Icmp6ErrorKind::DestinationUnreachable(4),
            err_ctx.invoking,
        );
    }
    true
}

fn handle_icmp6(iface: &str, src_ip: [u8; 16], dst_ip: [u8; 16], body: &[u8]) -> bool {
    let hdr = match Icmpv6Header::decode(body) {
        Some(h) => h,
        None => return false,
    };
    // Validate the upper-layer checksum.
    let computed = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, body);
    if computed != 0 {
        // RFC 4443 §2.4 / RFC 4861 §6.1, §7.1: a message whose checksum
        // does not verify is silently discarded — before it can touch the
        // neighbour cache, the router list or SLAAC state. Claim it
        // (return true) so raw-socket consumers don't re-process the bytes.
        return true;
    }
    match hdr.typ {
        ICMPV6_PACKET_TOO_BIG => {
            // ICMPv6 error body: type/code/checksum, 32-bit MTU, then the
            // invoking packet. The quoted IPv6 destination identifies the
            // route cache entry whose PMTU is reduced.
            if body.len() < 48 || body[8] >> 4 != 6 {
                return true;
            }
            let advertised = u32::from_be_bytes(body[4..8].try_into().unwrap()).max(1280);
            let destination: [u8; 16] = body[32..48].try_into().unwrap();
            if let Some(net_ns_id) = crate::iface::lookup(iface).map(|entry| entry.net_ns_id) {
                let mut cache = PMTU.lock();
                cache
                    .entry((net_ns_id, destination))
                    .and_modify(|mtu| *mtu = (*mtu).min(advertised))
                    .or_insert(advertised);
            }
            icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            true
        }
        ICMPV6_ECHO_REQUEST => {
            // Build a matching Echo Reply and transmit it (RFC 4443
            // §4.2: id, sequence and data are echoed unmodified).
            // Per Linux icmpv6_rcv(): the kernel answers Echo Requests
            // itself; raw/ping sockets do not see inbound type 128.
            if body.len() < 8 {
                return false;
            }
            // No reply is addressable to the Unspecified Address or
            // to a multicast source.
            if src_ip == [0; 16] || src_ip[0] == 0xff {
                return true;
            }
            let id = u16::from_be_bytes([body[4], body[5]]);
            let seq = u16::from_be_bytes([body[6], body[7]]);
            let payload = &body[8..];
            let reply = icmp6_sock::build_echo_reply(id, seq, payload);
            let net_ns_id = crate::iface::lookup(iface)
                .map(|entry| entry.net_ns_id)
                .unwrap_or(0);
            // RFC 4443 §2.2(a)/(b) + §4.2: a unicast request is
            // answered from the address it was sent to; a
            // multicast/anycast request from a unicast address of
            // the receiving interface.
            let src = if dst_ip[0] == 0xff {
                match crate::ipv6::addrs::pick_source_in(net_ns_id, iface, &src_ip) {
                    Some(addr) => addr,
                    None => return true,
                }
            } else {
                dst_ip
            };
            // A cold neighbor cache queues the reply (NeighborPending)
            // and solicits; any other send failure drops it silently
            // — the request itself was already consumed.
            let _ = send_icmp6_in(
                net_ns_id,
                iface,
                src,
                src_ip,
                &reply,
                ICMPV6_ORIGIN_HOP_LIMIT,
            );
            true
        }
        ICMPV6_ECHO_REPLY => {
            icmp6_sock::on_rx(src_ip, dst_ip, hdr.typ, hdr.code, body);
            true
        }
        ICMPV6_NEIGHBOR_SOLICITATION => match ndp::on_ns(iface, src_ip, None, body) {
            ndp::NdRxResult::SendBody {
                body: na_body,
                src_ip: na_src,
                dst_ip: na_dst,
                dst_mac,
            } => {
                // Transmit the solicited NA (RFC 4861 §7.2.4). When the
                // solicitation carried a Source LL Address option the
                // link-layer destination is known and the NA goes
                // straight to it; otherwise the transmit path resolves
                // it via the neighbor cache (queueing + soliciting on
                // a miss) or maps it for a multicast destination
                // (the DAD-probe reply to ff02::1).
                let net_ns_id = crate::iface::lookup(iface)
                    .map(|entry| entry.net_ns_id)
                    .unwrap_or(0);
                match dst_mac {
                    Some(mac) => {
                        if let Some(snap) = crate::iface::lookup_in(net_ns_id, iface) {
                            let _ = emit_icmp6_frame(
                                &snap,
                                mac,
                                na_src,
                                na_dst,
                                ICMPV6_ND_HOP_LIMIT,
                                &na_body,
                            );
                        }
                    }
                    None => {
                        let _ = send_icmp6_in(
                            net_ns_id,
                            iface,
                            na_src,
                            na_dst,
                            &na_body,
                            ICMPV6_ND_HOP_LIMIT,
                        );
                    }
                }
                true
            }
            ndp::NdRxResult::Updated => true,
            ndp::NdRxResult::DadConflict(addr) => {
                slaac::dad_failed(iface, &addr);
                true
            }
            ndp::NdRxResult::Ignored => false,
        },
        ICMPV6_NEIGHBOR_ADVERTISEMENT => match ndp::on_na(iface, body) {
            ndp::NdRxResult::DadConflict(addr) => {
                slaac::dad_failed(iface, &addr);
                true
            }
            _ => true,
        },
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
    PMTU.lock().clear();
    PENDING_ICMP6.lock().clear();
    ICMP6_ERROR_RATE_LIMIT.__reset_for_test();
}
