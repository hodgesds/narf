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
//! Forwarding is decided per ingress interface, so one interface can route
//! while another does not — the usual shape for a box with an untrusted
//! side.
//!
//! ## What this does, in Linux's order
//!
//! 1. Refuse unless the INGRESS interface forwards. Linux's
//!    `IN_DEV_FORWARD` reads `conf.<dev>.forwarding` alone; writing
//!    `net.ipv4.ip_forward` reaches the datapath by propagating into every
//!    interface. Default 0, as in Linux.
//! 2. TTL: a packet arriving with TTL <= 1 dies here, and the sender is told
//!    with ICMP Time Exceeded / TTL exceeded in transit. This is what makes
//!    `traceroute` through the box work, and it is the loop bound — every
//!    other check may pass and a routing loop still terminates.
//! 3. Route the destination. No route is ICMP Destination Unreachable /
//!    net unreachable, not a silent drop, so the sender learns immediately.
//! 4. Run the FORWARD chain, then POST_ROUTING, matching
//!    `NF_INET_FORWARD` → `NF_INET_POST_ROUTING`.
//! 5. Decrement the TTL, run the hooks, repair the header checksum, then
//!    emit on the egress interface with the next hop's MAC, fragmenting if
//!    the packet does not fit.
//!
//! ## What it deliberately does not do
//!
//! Broadcast and multicast never arrive here — `deliver_locally_in` claims
//! them as local first, which matches Linux dropping anything that is not
//! `PACKET_HOST` in `ip_forward()`. There is no ICMP Redirect generation
//! (Linux sends one when a packet leaves by the interface it arrived on),
//! no per-interface `conf/<dev>/forwarding`.

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_lib::sysctl::ipv4 as sysctl;
use narf_scheduler::narf_time;

use crate::iface;
use crate::ifaddr;
use crate::ipv4::Ipv4Addr;
use crate::pkt::{ip_checksum, write_eth_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IP_PROTO_ICMP};
use crate::pkt_icmp_extra::{
    build_error, build_fragmentation_needed, build_redirect, build_time_exceeded,
    DUR_NET_UNREACHABLE, ICMP_DEST_UNREACHABLE, TE_TTL_EXCEEDED_IN_TRANSIT,
};
use crate::route;
use crate::tcp_stack::arp_resolve_in;

/// How long to wait for the next hop's MAC. Matches the ICMP reply path.
const ARP_TIMEOUT_MS: u64 = 1000;

/// IPv4 fragment-control bits, in the flags/offset word at byte 6.
const IP_DF: u16 = 0x4000;
const IP_MF: u16 = 0x2000;
const FRAG_OFF_MASK: u16 = 0x1FFF;

/// Offsets into the IPv4 header.
const TTL_OFF: usize = 8;
const FRAG_OFF: usize = 6;
const CHECKSUM_OFF: usize = 10;
const MIN_HDR: usize = 20;

/// Try to forward `packet` (an IPv4 packet, no Ethernet header) that arrived
/// on `iface_in` and is not addressed to us.
///
/// Returns `true` if the packet was handled — forwarded, or answered with an
/// ICMP error. `false` means the caller should drop it, which is also what
/// happens whenever forwarding is disabled.
pub fn try_forward(net_ns_id: u64, iface_in: &str, packet: &[u8]) -> bool {
    // `IN_DEV_FORWARD(in_dev)` — the INGRESS interface's own setting, not
    // the global knob. `net.ipv4.ip_forward` reaches this only by having
    // been propagated into every interface when it was written.
    if !sysctl::device_forwarding(iface_in) {
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

    // Too big for the egress link. With DF set the packet must not be split,
    // so the sender is told the next-hop MTU — `ip_exceeds_mtu` gates on
    // exactly that bit, and this is the reply path-MTU discovery depends on.
    // Without DF the packet is fragmented at send time instead.
    let df = u16::from_be_bytes([packet[FRAG_OFF], packet[FRAG_OFF + 1]]) & IP_DF != 0;
    if packet.len() > egress.mtu as usize && df {
        send_icmp_error(
            net_ns_id,
            src,
            build_fragmentation_needed(egress.mtu as u16, packet),
        );
        return true;
    }

    // ── Decrement the TTL ──
    //
    // Before the hooks, as `ip_forward()` does: a FORWARD rule matching on
    // TTL must see the value this hop is passing on, not the one that
    // arrived. The header checksum is repaired after the hooks instead,
    // since they may rewrite the addresses too.
    //
    // Both hooks may rewrite (a NAT rule is the point of POST_ROUTING), so
    // they work on an owned copy.
    let mut owned: Vec<u8> = packet.to_vec();
    owned[TTL_OFF] -= 1;

    // A packet leaving by the interface it arrived on means the sender chose
    // the wrong first hop. Tell it — after the decrement and before the
    // FORWARD hook, where `ip_forward()` does it — and forward the packet
    // anyway, as Linux does.
    maybe_send_redirect(net_ns_id, iface_in, &egress, src, route.nexthop, &owned);

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

    // ── Repair the checksum ──
    //
    // Recomputed over the whole header rather than patched incrementally:
    // the TTL changed above and a POST_ROUTING NAT rewrite may have changed
    // the addresses since, so the incremental update RFC 1624 describes has
    // no valid starting checksum to adjust.
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
    send_ipv4(&egress, dst_mac, &owned);
    true
}

/// Emit one IPv4 packet on `egress`, splitting it into fragments if it
/// exceeds the link MTU.
///
/// Linux ref: `ip_fragment()` / `ip_do_fragment()` in net/ipv4/ip_output.c,
/// reached from `ip_finish_output` after the FORWARD hook. A packet with DF
/// set never arrives here oversized — `try_forward` has already answered it
/// with Fragmentation Needed.
///
/// Fragments of an already-fragmented packet are handled: the incoming
/// offset is the base that each piece's offset is added to, and an incoming
/// More Fragments bit forces MF on every piece, since this packet is not the
/// tail of the original datagram either.
fn send_ipv4(egress: &iface::NetIfaceSnapshot, dst_mac: [u8; 6], packet: &[u8]) {
    let mtu = egress.mtu as usize;
    if packet.len() <= mtu {
        emit(egress, dst_mac, packet);
        return;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_HDR || packet.len() < ihl {
        return;
    }
    // Every fragment but the last carries a payload that is a multiple of 8
    // bytes, because the offset field counts 8-byte units.
    let max_data = (mtu.saturating_sub(ihl)) & !7usize;
    if max_data == 0 {
        // The MTU cannot even hold a header plus one unit; nothing to send.
        return;
    }

    let frag_word = u16::from_be_bytes([packet[FRAG_OFF], packet[FRAG_OFF + 1]]);
    let base_units = (frag_word & FRAG_OFF_MASK) as usize;
    let inbound_mf = frag_word & IP_MF != 0;
    let payload = &packet[ihl..];

    let mut consumed = 0usize;
    while consumed < payload.len() {
        let chunk = max_data.min(payload.len() - consumed);
        let more = consumed + chunk < payload.len() || inbound_mf;
        let units = base_units + consumed / 8;
        if units > FRAG_OFF_MASK as usize {
            return;
        }

        let mut frag = alloc::vec![0u8; ihl + chunk];
        frag[..ihl].copy_from_slice(&packet[..ihl]);
        frag[2..4].copy_from_slice(&((ihl + chunk) as u16).to_be_bytes());
        // DF is necessarily clear here, and must stay clear in a fragment.
        let word = if more {
            IP_MF | units as u16
        } else {
            units as u16
        };
        frag[FRAG_OFF..FRAG_OFF + 2].copy_from_slice(&word.to_be_bytes());
        frag[CHECKSUM_OFF..CHECKSUM_OFF + 2].copy_from_slice(&[0, 0]);
        let cs = ip_checksum(&frag[..ihl]);
        frag[CHECKSUM_OFF..CHECKSUM_OFF + 2].copy_from_slice(&cs.to_be_bytes());
        frag[ihl..].copy_from_slice(&payload[consumed..consumed + chunk]);

        emit(egress, dst_mac, &frag);
        consumed += chunk;
    }
}

/// Wrap one IPv4 packet in an Ethernet header and hand it to the driver.
fn emit(egress: &iface::NetIfaceSnapshot, dst_mac: [u8; 6], packet: &[u8]) {
    let mut frame = alloc::vec![0u8; ETH_HDR_LEN + packet.len()];
    write_eth_header(&mut frame, dst_mac, egress.mac, ETHERTYPE_IPV4);
    frame[ETH_HDR_LEN..].copy_from_slice(packet);
    let _ = (egress.send)(&frame);
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

// ── ICMP Redirect ───────────────────────────────────────────────────────────

/// ICMP Redirect code 1 — redirect datagrams for the host.
const ICMP_REDIR_HOST: u8 = 1;

/// Linux's `ip_rt_redirect_number`: how many redirects one destination is
/// told before we stop repeating ourselves.
const REDIRECT_MAX: u32 = 9;

/// Roughly Linux's `ip_rt_redirect_silence` — quiet for this long and the
/// count resets, so a host that stops provoking redirects can be told again
/// later.
const REDIRECT_SILENCE_NS: u64 = 20_000_000_000;

/// Per-destination redirect budget. Linux keeps this on the `inet_peer`
/// entry; NARF has no peer table, so a small fixed ring stands in. Overflow
/// evicts the oldest, which at worst costs a host a redirect it would have
/// been sent — never a wrong one.
const REDIRECT_PEERS: usize = 16;

#[derive(Clone, Copy)]
struct RedirectPeer {
    addr: [u8; 4],
    count: u32,
    last_ns: u64,
}

static REDIRECT_LOG: IrqSafeSpinLock<[RedirectPeer; REDIRECT_PEERS]> = IrqSafeSpinLock::new(
    [RedirectPeer {
        addr: [0, 0, 0, 0],
        count: 0,
        last_ns: 0,
    }; REDIRECT_PEERS],
);

/// Claim a redirect for `dst`, or refuse because it has had enough.
fn redirect_budget(dst: [u8; 4]) -> bool {
    let now = narf_time::monotonic_ns();
    let mut g = REDIRECT_LOG.lock();

    if let Some(p) = g.iter_mut().find(|p| p.addr == dst) {
        if now.saturating_sub(p.last_ns) > REDIRECT_SILENCE_NS {
            p.count = 0;
        }
        if p.count >= REDIRECT_MAX {
            // Linux still stamps the time here, so the silence window is
            // measured from the last provoking packet, not the last redirect.
            p.last_ns = now;
            return false;
        }
        p.count += 1;
        p.last_ns = now;
        return true;
    }

    // Take a free slot, or evict the least recently used one.
    let idx = match g.iter().position(|p| p.addr == [0, 0, 0, 0]) {
        Some(i) => i,
        None => {
            let mut oldest = 0;
            for (i, p) in g.iter().enumerate() {
                if p.last_ns < g[oldest].last_ns {
                    oldest = i;
                }
            }
            oldest
        }
    };
    g[idx] = RedirectPeer {
        addr: dst,
        count: 1,
        last_ns: now,
    };
    true
}

/// True iff `a` and `b` share a subnet configured on `iface`.
///
/// Linux's `inet_addr_onlink(out_dev, saddr, gw)`: find the address whose
/// subnet holds the gateway, then ask whether it also holds the sender. If it
/// does, the sender could have reached the next hop directly and this hop is
/// a detour worth reporting.
fn same_link(iface: &str, a: [u8; 4], b: [u8; 4]) -> bool {
    let a_raw = u32::from_be_bytes(a);
    let b_raw = u32::from_be_bytes(b);
    ifaddr::iface_addrs(iface).iter().any(|ia| {
        let mask = ifaddr::prefix_to_mask(ia.prefix_len);
        let net = ia.addr.to_u32() & mask;
        (a_raw & mask) == net && (b_raw & mask) == net
    })
}

/// Tell `src` that `nexthop` is the better first hop for `dst`.
///
/// Linux ref: `ip_rt_send_redirect()` (net/ipv4/route.c), reached from
/// `ip_forward()` when `__mkroute_input` flagged IPSKB_DOREDIRECT.
///
/// The conditions there are: the packet leaves by the interface it arrived
/// on, `send_redirects` allows it, and the sender is on the same link as the
/// next hop. NARF does not model `conf.<dev>.shared_media`, which in Linux
/// defaults to 1 and short-circuits that last test, so NARF sends strictly
/// fewer redirects than a stock Linux would — never a redirect Linux would
/// not have sent.
fn maybe_send_redirect(
    net_ns_id: u64,
    iface_in: &str,
    egress: &iface::NetIfaceSnapshot,
    src: Ipv4Addr,
    nexthop: Ipv4Addr,
    packet: &[u8],
) {
    if egress.name != iface_in {
        return;
    }
    if !sysctl::device_send_redirects(&egress.name) {
        return;
    }
    if !same_link(&egress.name, src.0, nexthop.0) {
        return;
    }
    if !redirect_budget(src.0) {
        return;
    }
    send_icmp_error(
        net_ns_id,
        src,
        build_redirect(ICMP_REDIR_HOST, nexthop.0, packet),
    );
}
