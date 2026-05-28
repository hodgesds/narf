//! Per-interface IPv4 address binding + `ipv4_send` egress path.
//!
//! Spec references:
//! - RFC 791 — Internet Protocol (J. Postel, Sep 1981).
//!   §3.1 (header format), §3.2 (protocol behaviour).
//!   <https://datatracker.ietf.org/doc/html/rfc791>
//! - RFC 1071 — Computing the Internet Checksum (Braden et al., 1988).
//!   <https://datatracker.ietf.org/doc/html/rfc1071>
//!
//! ## What this module provides
//!
//! - `Ipv4Addr` — 4-byte address newtype with display helpers.
//! - `IpProto` — protocol number enum (ICMP=1, TCP=6, UDP=17, Raw).
//! - `Binding` — per-interface `(addr, netmask, gateway, dns[])`.
//! - `bind_address` — install a binding on a named interface.
//! - `ipv4_send` — look up the binding + ARP-resolve the next-hop,
//!   then push an Ethernet+IPv4 frame through `iface::send`.
//!
//! ## No-alloc header path
//!
//! `ipv4_send` builds the frame on a fixed 1600-byte stack buffer and
//! calls the `iface::send` function-pointer. No heap is touched in the
//! fast path. Bindings are stored in a global `IrqSafeSpinLock<Vec<_>>`
//! (rare writes, rare reads — no contention concern in the kernel).
//!
//! ## Relationship to `pkt.rs`
//!
//! This module re-uses `crate::pkt::{write_ipv4_header, set_ipv4_checksum,
//! write_eth_header, ETH_HDR_LEN, IPV4_HDR_LEN, ETHERTYPE_IPV4}` for the
//! actual byte layout. `ipv4.rs` owns the *routing* policy (default-gateway
//! selection, next-hop resolution) while `pkt.rs` owns the *wire format*.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

use crate::arp;
use crate::iface;
use crate::pkt::{
    set_ipv4_checksum, write_eth_header, write_ipv4_header, ETH_HDR_LEN, ETHERTYPE_IPV4,
    IPV4_HDR_LEN,
};

// ── Ipv4Addr ────────────────────────────────────────────────────────

/// 4-byte IPv4 address (host-byte order stored in network order, i.e.
/// `[a, b, c, d]` represents `a.b.c.d`). RFC 791 §3.1.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    /// 0.0.0.0 — unspecified.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    /// 255.255.255.255 — limited broadcast.
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    /// Build from a u32 in host byte order. `0x0A00020F` → `10.0.2.15`.
    #[inline]
    pub fn from_u32(v: u32) -> Self {
        Self(v.to_be_bytes())
    }

    #[inline]
    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// True iff the address is in 169.254.0.0/16 (link-local, RFC 3927).
    #[inline]
    pub fn is_link_local(self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// True iff all bytes are 0 (UNSPECIFIED).
    #[inline]
    pub fn is_unspecified(self) -> bool {
        self == Self::UNSPECIFIED
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(b: [u8; 4]) -> Self {
        Self(b)
    }
}

impl From<Ipv4Addr> for [u8; 4] {
    fn from(a: Ipv4Addr) -> [u8; 4] {
        a.0
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

// ── IpProto ────────────────────────────────────────────────────────

/// IP protocol number. RFC 791 §3.1 (Protocol field, one byte).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpProto {
    Icmp,
    Tcp,
    Udp,
    /// Escape hatch for any other protocol number.
    Raw(u8),
}

impl IpProto {
    pub fn to_u8(self) -> u8 {
        match self {
            IpProto::Icmp  => 1,
            IpProto::Tcp   => 6,
            IpProto::Udp   => 17,
            IpProto::Raw(n) => n,
        }
    }
}

// ── Per-interface binding ───────────────────────────────────────────

/// Per-interface IPv4 configuration. Installed by `bind_address` (e.g.
/// after a DHCP ACK) or a static boot-time call. See RFC 791 §2.3.
#[derive(Clone, Debug)]
pub struct Binding {
    /// Interface name (matches `iface::register` / `iface::lookup` key).
    pub iface_name: alloc::string::String,
    /// Assigned address.
    pub addr: Ipv4Addr,
    /// Network mask.
    pub netmask: Ipv4Addr,
    /// Default gateway. `None` when on a directly-connected segment
    /// with no router.
    pub gateway: Option<Ipv4Addr>,
    /// DNS resolver addresses (up to 3). RFC 2132 §3.8 (option 6).
    pub dns: Vec<Ipv4Addr>,
}

/// Error conditions returned by `ipv4_send`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// No binding registered for the named interface.
    NoBinding,
    /// Interface not found in the `iface` registry.
    NoIface,
    /// ARP resolution for the next-hop timed out.
    ArpTimeout,
    /// The payload is too large to fit in a single MTU frame.
    TooLarge,
    /// The `iface::send` function pointer reported failure.
    DriverError,
}

static BINDINGS: IrqSafeSpinLock<Vec<Binding>> = IrqSafeSpinLock::new(Vec::new());

/// Install or replace the IPv4 binding on `iface_name`. Called by the
/// DHCP client after a successful ACK, or by the static-config path.
///
/// Silently replaces an existing binding for the same interface name
/// (hard cutover — no compat alias). Stores up to 3 DNS addresses from
/// the supplied slice.
pub fn bind_address(
    iface_name: &str,
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    dns: &[Ipv4Addr],
) {
    let dns_vec: Vec<Ipv4Addr> = dns.iter().take(3).copied().collect();
    let binding = Binding {
        iface_name: alloc::string::String::from(iface_name),
        addr,
        netmask,
        gateway,
        dns: dns_vec,
    };
    let mut g = BINDINGS.lock();
    g.retain(|b| b.iface_name != iface_name);
    g.push(binding);
}

/// Look up the binding for `iface_name`. Returns a clone so the lock
/// is not held during slow operations (ARP resolution).
pub fn lookup_binding(iface_name: &str) -> Option<Binding> {
    BINDINGS.lock().iter().find(|b| b.iface_name == iface_name).cloned()
}

// ── ipv4_send ──────────────────────────────────────────────────────

/// Maximum frame we'll ever write (Ethernet + IPv4 + full MTU payload).
/// 1514 = 14 (Eth) + 20 (IPv4) + 1480 — keeps us inside standard MTU.
const FRAME_BUF: usize = 1514;

/// Send an IPv4 datagram on the named interface. The caller supplies
/// a pre-built `payload` (e.g. a UDP datagram including UDP header);
/// this function prepends the Ethernet + IPv4 headers and calls the
/// driver's `send` function-pointer.
///
/// Next-hop selection follows RFC 791 §3.2:
/// - If `dst` is on the local subnet (dst & netmask == addr & netmask)
///   the frame is sent directly to `dst`.
/// - Otherwise the frame is sent to the configured default gateway.
/// - Broadcast destinations are sent to the Ethernet broadcast MAC.
///
/// ARP resolution uses `arp::resolve_blocking` with a 1 s timeout
/// (same budget as `tcp_stack::arp_resolve`). If resolution fails the
/// function returns `Err(SendError::ArpTimeout)`.
pub fn ipv4_send(
    iface_name: &str,
    dst: Ipv4Addr,
    proto: IpProto,
    payload: &[u8],
) -> Result<(), SendError> {
    let binding = lookup_binding(iface_name).ok_or(SendError::NoBinding)?;
    let snap = iface::lookup(iface_name).ok_or(SendError::NoIface)?;

    let total = ETH_HDR_LEN + IPV4_HDR_LEN + payload.len();
    if total > FRAME_BUF {
        return Err(SendError::TooLarge);
    }

    // Determine the next-hop IP for ARP resolution.
    let dst_raw = dst.to_u32();
    let mask_raw = binding.netmask.to_u32();
    let addr_raw = binding.addr.to_u32();
    let nexthop_ip = if dst == Ipv4Addr::BROADCAST
        || (dst_raw & mask_raw) == (addr_raw & mask_raw)
    {
        dst
    } else {
        binding.gateway.ok_or(SendError::ArpTimeout)?
    };

    // Resolve next-hop to MAC. Broadcast maps directly.
    let dst_mac: [u8; 6] = if dst == Ipv4Addr::BROADCAST
        || nexthop_ip == Ipv4Addr::BROADCAST
    {
        [0xFF; 6]
    } else {
        arp::resolve_blocking(iface_name, nexthop_ip.0, 1000)
            .map_err(|_| SendError::ArpTimeout)?
    };

    // Build the frame on the stack.
    let mut frame = [0u8; FRAME_BUF];
    write_eth_header(&mut frame, dst_mac, snap.mac, ETHERTYPE_IPV4);
    {
        let ip_buf = &mut frame[ETH_HDR_LEN..];
        write_ipv4_header(
            ip_buf,
            (IPV4_HDR_LEN + payload.len()) as u16,
            proto.to_u8(),
            binding.addr.0,
            dst.0,
        );
    }
    frame[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + payload.len()]
        .copy_from_slice(payload);
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);

    (snap.send)(&frame[..total]).map_err(|_| SendError::DriverError)
}

/// Clear all bindings. For testing and interface reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    BINDINGS.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_detection() {
        assert!(Ipv4Addr([169, 254, 1, 1]).is_link_local());
        assert!(!Ipv4Addr([10, 0, 2, 15]).is_link_local());
    }
}
