//! IPv4 input routing decision — is this packet for us?
//!
//! Linux makes this call in `ip_rcv_finish()` → `ip_route_input_noref()`
//! (`net/ipv4/route.c`), between PRE_ROUTING and LOCAL_IN. The route lookup
//! classifies the destination as `RTN_LOCAL` (deliver up the stack),
//! `RTN_BROADCAST` / `RTN_MULTICAST` (also delivered locally), or something
//! reachable elsewhere — which is forwarded when `ip_forward` allows it and
//! dropped otherwise. A destination on no local subnet at all is a martian.
//!
//! NARF had no such step: `handle_ipv4` ran PRE_ROUTING and then LOCAL_IN
//! unconditionally, so **every** IPv4 packet that reached the stack was
//! treated as locally addressed regardless of its destination. The socket
//! layer does not recover the check — UDP matches on port, namespace and
//! `SO_BINDTODEVICE` only, never comparing a socket's bound address against
//! the datagram's destination, and a wildcard TCP listener matches any
//! destination by design. So a frame delivered to our MAC carrying someone
//! else's destination address reached local sockets, and ICMP answered echo
//! requests for addresses NARF does not own.
//!
//! NARF has no forwarding plane at all (the netfilter FORWARD chain is
//! registered but never traversed, and nothing decrements TTL or
//! retransmits a received packet), so the forward branch of that decision
//! does not exist here: non-local is simply dropped. That is the correct
//! behaviour for `ip_forward = 0`, which is both the Linux default and the
//! only thing NARF can currently honour.
//!
//! ## Three address sources
//!
//! An address can be recorded in any of three places, and a destination is
//! local if *any* of them claims it:
//!
//! - `iface::NetIfaceEntry.ipv4` — the legacy single address per interface,
//!   set by `set_default_ipv4`.
//! - `ifaddr::iface_addrs()` — the `(addr, prefix_len)` table, which is what
//!   carries secondary addresses and the prefix used for directed broadcast.
//! - `ipv4::lookup_binding()` — the `(addr, netmask, gateway, dns)` binding.
//!
//! Consulting fewer than all three would drop traffic for a genuinely
//! configured address depending on which API configured it.

use crate::iface;
use crate::ifaddr;
use crate::ipv4;

/// 224.0.0.0/4.
#[inline]
pub fn is_multicast(dst: [u8; 4]) -> bool {
    (224..=239).contains(&dst[0])
}

/// 255.255.255.255 — the limited broadcast.
#[inline]
pub fn is_limited_broadcast(dst: [u8; 4]) -> bool {
    dst == [255, 255, 255, 255]
}

/// 127.0.0.0/8.
#[inline]
pub fn is_loopback(dst: [u8; 4]) -> bool {
    dst[0] == 127
}

/// True iff `dst` is the directed broadcast of `(addr, mask)` — same network,
/// all host bits set. A /31 or /32 has no host bits and so no directed
/// broadcast (RFC 3021).
#[inline]
fn is_directed_broadcast_of(addr: u32, mask: u32, dst: u32) -> bool {
    if mask == u32::MAX || mask == 0xFFFF_FFFE {
        return false;
    }
    (addr & mask) == (dst & mask) && (dst & !mask) == !mask
}

/// True iff `dst` is a directed broadcast of any subnet configured on
/// `iface_name`.
pub fn is_directed_broadcast_on(iface_name: &str, dst: [u8; 4]) -> bool {
    let dst_raw = u32::from_be_bytes(dst);
    if ifaddr::iface_addrs(iface_name).iter().any(|a| {
        is_directed_broadcast_of(
            a.addr.to_u32(),
            ifaddr::prefix_to_mask(a.prefix_len),
            dst_raw,
        )
    }) {
        return true;
    }
    match ipv4::lookup_binding(iface_name) {
        Some(b) => is_directed_broadcast_of(b.addr.to_u32(), b.netmask.to_u32(), dst_raw),
        None => false,
    }
}

/// True iff `dst` is a broadcast or multicast destination as seen by
/// `iface_name` — the reconstruction of Linux's `RTCF_BROADCAST |
/// RTCF_MULTICAST` route flags, which NARF's receive path has no route
/// object to carry.
pub fn is_broadcast_or_multicast_on(iface_name: &str, dst: [u8; 4]) -> bool {
    is_limited_broadcast(dst) || is_multicast(dst) || is_directed_broadcast_on(iface_name, dst)
}

/// The input routing decision: may this destination be delivered locally?
///
/// Mirrors the `RTN_LOCAL` / `RTN_BROADCAST` / `RTN_MULTICAST` outcomes of
/// `ip_route_input_noref()`. Everything else would be forwarded or dropped;
/// with no forwarding plane, NARF drops.
pub fn deliver_locally_in(net_ns_id: u64, dst: [u8; 4]) -> bool {
    // Broadcast and multicast are delivered locally in Linux too —
    // `ip_route_input_slow` returns RTN_BROADCAST/RTN_MULTICAST and
    // `ip_local_deliver` still runs. NARF keeps no IPv4 multicast
    // membership table, so it cannot apply `ip_check_mc_rcv`'s group
    // filter and accepts every group, as a host in all-groups promiscuous
    // mode would. Narrowing that needs IGMP membership state first.
    if is_limited_broadcast(dst) || is_multicast(dst) || is_loopback(dst) {
        return true;
    }
    // 0.0.0.0 is not a routable destination; it appears on the bring-up
    // paths (notably DHCP) that run before an address exists.
    if dst == [0, 0, 0, 0] {
        return true;
    }

    let dst_raw = u32::from_be_bytes(dst);
    let mut configured = false;

    for e in iface::snapshot_all_in(net_ns_id) {
        if e.ipv4 != [0, 0, 0, 0] {
            configured = true;
            if e.ipv4 == dst {
                return true;
            }
        }
        for a in ifaddr::iface_addrs(&e.name) {
            configured = true;
            let mask = ifaddr::prefix_to_mask(a.prefix_len);
            if a.addr.to_u32() == dst_raw
                || is_directed_broadcast_of(a.addr.to_u32(), mask, dst_raw)
            {
                return true;
            }
        }
        if let Some(b) = ipv4::lookup_binding(&e.name) {
            if !b.addr.is_unspecified() {
                configured = true;
                if b.addr.to_u32() == dst_raw
                    || is_directed_broadcast_of(b.addr.to_u32(), b.netmask.to_u32(), dst_raw)
                {
                    return true;
                }
            }
        }
    }

    // Nothing in this namespace has an address yet. There is no local/foreign
    // judgement to make, and dropping here would break every path that runs
    // before address assignment. Linux reaches the same outcome from the
    // other side: its DHCP clients sit on AF_PACKET, below the routing
    // decision, so bring-up traffic never depends on this call.
    !configured
}
