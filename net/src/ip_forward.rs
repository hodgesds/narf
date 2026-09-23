//! IPv4 forwarding — the router path, gated on `net.ipv4.ip_forward`.
//!
//! Linux ref: `ip_forward()` and `ip_forward_finish()` in
//! `net/ipv4/ip_forward.c`, reached from `ip_route_input_noref()` when the
//! destination resolves to `RTN_UNICAST` rather than `RTN_LOCAL`.
//!
//! [`crate::ip_local::deliver_locally_in`] makes that classification; this
//! module is the branch it cannot take on its own. Before this existed the
//! branch did not exist either: the netfilter FORWARD chain was registered
//! but never traversed, nothing ever decremented a TTL, no received packet
//! was ever retransmitted, and `net.ipv4.ip_forward` was stored where the
//! network stack could not even read it. Writing the knob changed nothing.
//!
//! ## What this does, in Linux's order
//!
//! 1. Refuse unless `ip_forward` is set. Default 0, as in Linux.
//! 2. TTL: a packet arriving with TTL <= 1 dies here, and the sender is told
//!    with ICMP Time Exceeded / TTL exceeded in transit. This is what makes
//!    `traceroute` through the box work, and it is the loop bound — every
//!    other check may pass and a routing loop still terminates.
//! 3. Route the destination. No route is ICMP Destination Unreachable /
//!    net unreachable, not a silent drop, so the sender learns immediately.
//! 4. Run the FORWARD chain, then POST_ROUTING, matching
//!    `NF_INET_FORWARD` → `NF_INET_POST_ROUTING`.
//! 5. Decrement the TTL and repair the header checksum, then emit on the
//!    egress interface with the next hop's MAC.
//!
//! ## What it deliberately does not do
//!
//! Broadcast and multicast never arrive here — `deliver_locally_in` claims
//! them as local first, which matches Linux dropping anything that is not
//! `PACKET_HOST` in `ip_forward()`. There is no ICMP Redirect generation
//! (Linux sends one when a packet leaves by the interface it arrived on),
//! no per-interface `conf/<dev>/forwarding`, and no fragmentation: a packet
//! larger than the egress MTU is answered with Fragmentation Needed rather
//! than split, which is correct for the DF case and conservative otherwise.

use alloc::vec::Vec;

use narf_lib::sysctl::ipv4 as sysctl;

use crate::iface;
use crate::ipv4::Ipv4Addr;
use crate::pkt::{ip_checksum, write_eth_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IP_PROTO_ICMP};
use crate::pkt_icmp_extra::{
    build_error, build_fragmentation_needed, build_time_exceeded, DUR_NET_UNREACHABLE,
    ICMP_DEST_UNREACHABLE, TE_TTL_EXCEEDED_IN_TRANSIT,
};
use crate::route;
use crate::tcp_stack::arp_resolve_in;

/// How long to wait for the next hop's MAC. Matches the ICMP reply path.
const ARP_TIMEOUT_MS: u64 = 1000;

/// Offsets into the IPv4 header.
const TTL_OFF: usize = 8;
const CHECKSUM_OFF: usize = 10;
const MIN_HDR: usize = 20;

/// Try to forward `packet` (an IPv4 packet, no Ethernet header) that arrived
/// on `iface_in` and is not addressed to us.
///
/// Returns `true` if the packet was handled — forwarded, or answered with an
/// ICMP error. `false` means the caller should drop it, which is also what
/// happens whenever forwarding is disabled.
pub fn try_forward(net_ns_id: u64, iface_in: &str, packet: &[u8]) -> bool {
    if !sysctl::ip_forward() {
        return false;
    }
    if packet.len() < MIN_HDR {
        return false;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_HDR || packet.len() < ihl {
        return false;
    }
    let src = Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]);
    let dst = Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]);

    // ── TTL ──
    //
    // Linux tests `ip_hdr(skb)->ttl <= 1` before the route lookup, so a
    // packet that has run out of hops is reported even when it was going
    // nowhere reachable. The ICMP reply carries the original header plus 8
    // bytes, which is what identifies the probe to traceroute.
    if packet[TTL_OFF] <= 1 {
        send_icmp_error(
            net_ns_id,
            src,
            build_time_exceeded(TE_TTL_EXCEEDED_IN_TRANSIT, packet),
        );
        return true;
    }

    // ── Route ──
    let route = match route::route_lookup_in(net_ns_id, dst) {
        Some(r) => r,
        None => {
            send_icmp_error(
                net_ns_id,
                src,
                build_error(ICMP_DEST_UNREACHABLE, DUR_NET_UNREACHABLE, 0, packet),
            );
            return true;
        }
    };
    let egress = match iface::lookup_in(net_ns_id, &route.iface) {
        Some(e) => e,
        None => return false,
    };
    if !egress.link_up {
        return false;
    }

    // A packet that will not fit cannot be split here — NARF has no IPv4
    // fragmentation on output — so the sender is told the next-hop MTU,
    // which is what path-MTU discovery needs to hear anyway.
    if packet.len() > egress.mtu as usize {
        send_icmp_error(
            net_ns_id,
            src,
            build_fragmentation_needed(egress.mtu as u16, packet),
        );
        return true;
    }

    // ── FORWARD, then POST_ROUTING ──
    //
    // Both hooks may rewrite (a NAT rule is the point of POST_ROUTING), so
    // they get an owned copy which is also the buffer the TTL is decremented
    // in below.
    let mut owned: Vec<u8> = packet.to_vec();
    {
        let mut ctx = crate::netfilter::PktCtx::new_ipv4(
            crate::netfilter::HookPoint::Forward,
            iface_in,
            &egress.name,
            &mut owned,
        )
        .with_net_ns(net_ns_id);
        if crate::netfilter::nf_dispatch(&mut ctx) != crate::netfilter::Verdict::Accept {
            return true;
        }
    }
    {
        let mut ctx = crate::netfilter::PktCtx::new_ipv4(
            crate::netfilter::HookPoint::PostRouting,
            iface_in,
            &egress.name,
            &mut owned,
        )
        .with_net_ns(net_ns_id);
        if crate::netfilter::nf_dispatch(&mut ctx) != crate::netfilter::Verdict::Accept {
            return true;
        }
    }
    if owned.len() < MIN_HDR {
        return false;
    }

    // ── Decrement TTL, repair the checksum ──
    //
    // Recomputed over the whole header rather than patched incrementally:
    // a POST_ROUTING NAT rewrite may already have changed the addresses,
    // so the incremental update RFC 1624 describes has no valid starting
    // checksum to adjust.
    owned[TTL_OFF] -= 1;
    let hdr_len = (((owned[0] & 0x0F) as usize) * 4).min(owned.len());
    if hdr_len < MIN_HDR {
        return false;
    }
    owned[CHECKSUM_OFF..CHECKSUM_OFF + 2].copy_from_slice(&[0, 0]);
    let cs = ip_checksum(&owned[..hdr_len]);
    owned[CHECKSUM_OFF..CHECKSUM_OFF + 2].copy_from_slice(&cs.to_be_bytes());

    // ── Emit ──
    let dst_mac = match arp_resolve_in(net_ns_id, route.nexthop.0, ARP_TIMEOUT_MS) {
        Ok(m) => m,
        // Linux answers an unresolvable neighbour with Host Unreachable.
        Err(_) => return true,
    };
    let mut frame = alloc::vec![0u8; ETH_HDR_LEN + owned.len()];
    write_eth_header(&mut frame, dst_mac, egress.mac, ETHERTYPE_IPV4);
    frame[ETH_HDR_LEN..].copy_from_slice(&owned);
    let _ = (egress.send)(&frame);
    true
}

/// Send an ICMP error built by `pkt_icmp_extra` back to `dst`.
///
/// The reply is sourced from the interface the route to `dst` picks, which is
/// how the sender learns which hop dropped the packet. ARP resolves the
/// route's NEXT HOP, not `dst` itself — the sender of a forwarded packet is
/// by definition somewhere else, and for an off-link one its own address has
/// no MAC on this segment to find.
fn send_icmp_error(net_ns_id: u64, dst: Ipv4Addr, icmp_body: Vec<u8>) {
    let (egress, nexthop, src) = match route::route_lookup_in(net_ns_id, dst) {
        Some(r) => match iface::lookup_in(net_ns_id, &r.iface) {
            Some(e) => {
                let src = if r.src.is_unspecified() {
                    e.ipv4
                } else {
                    r.src.0
                };
                (e, r.nexthop, src)
            }
            None => return,
        },
        // No route to the sender either. Fall back to the interface that
        // would carry traffic toward it, treating the destination as on-link.
        None => match iface::for_dst_in(net_ns_id, dst.0) {
            Some(e) => {
                let src = e.ipv4;
                (e, dst, src)
            }
            None => return,
        },
    };
    let dst_mac = match arp_resolve_in(net_ns_id, nexthop.0, ARP_TIMEOUT_MS) {
        Ok(m) => m,
        Err(_) => return,
    };
    let ip_total = MIN_HDR + icmp_body.len();
    let mut frame = alloc::vec![0u8; ETH_HDR_LEN + ip_total];
    write_eth_header(&mut frame, dst_mac, egress.mac, ETHERTYPE_IPV4);
    crate::pkt::write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total as u16,
        IP_PROTO_ICMP,
        src,
        dst.0,
    );
    crate::pkt::set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + MIN_HDR]);
    frame[ETH_HDR_LEN + MIN_HDR..].copy_from_slice(&icmp_body);
    let _ = (egress.send)(&frame);
}
