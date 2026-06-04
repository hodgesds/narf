//! Per-interface IPv4 address table.
//!
//! Each network interface can hold multiple IPv4 addresses (uncommon but
//! valid — e.g. multi-homed servers). This module stores them as
//! `Vec<(Ipv4Addr, u8)>` (address + prefix length) and provides the CRUD
//! API that higher layers (DHCP, static config, `route.rs`) call.
//!
//! When an address is added, a connected (link-scope) route is
//! automatically installed in the global routing table via
//! `route::route_add`. When an address is removed the corresponding
//! connected route is deleted.
//!
//! ## Linux reference
//!
//! `net/ipv4/fib_frontend.c` `inet_rtm_newaddr()` (around line 600) — the
//! kernel calls `fib_add_ifaddr` immediately after setting the address,
//! which inserts the connected route. We mirror that behaviour here.
//! `net/ipv4/fib_semantics.c` `fib_check_nh_addr()` — validates that each
//! nexthop address is reachable via an on-link connected route; our
//! `route_add` call satisfies that contract for locally-owned prefixes.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::ipv4::Ipv4Addr;

// ── IfaceAddr ──────────────────────────────────────────────────────────

/// A single IPv4 address assigned to an interface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IfaceAddr {
    pub addr: Ipv4Addr,
    /// CIDR prefix length (0–32). e.g. 24 for a /24 netmask.
    pub prefix_len: u8,
}

impl IfaceAddr {
    /// Compute the network address for this binding (addr & mask).
    #[inline]
    pub fn network(self) -> Ipv4Addr {
        let mask = prefix_to_mask(self.prefix_len);
        Ipv4Addr::from_u32(self.addr.to_u32() & mask)
    }

    /// True iff `other` is within the subnet described by this address.
    #[inline]
    pub fn covers(self, other: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix_len);
        (self.addr.to_u32() & mask) == (other.to_u32() & mask)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Convert a CIDR prefix length to a 32-bit network mask.
/// prefix 24 → 0xFFFFFF00.
#[inline]
pub fn prefix_to_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    }
}

// ── Global table ───────────────────────────────────────────────────────

struct IfaceAddrs {
    iface_name: String,
    addrs: Vec<IfaceAddr>,
}

static IFACE_ADDRS: IrqSafeSpinLock<Vec<IfaceAddrs>> = IrqSafeSpinLock::new(Vec::new());

// ── Public API ─────────────────────────────────────────────────────────

/// Add an IPv4 address to the named interface. If the same (addr,
/// prefix_len) pair already exists it is silently ignored (idempotent).
///
/// After inserting, a connected route (`Scope::Link`) for the subnet is
/// automatically registered. Ref: Linux `fib_frontend.c:fib_add_ifaddr`.
pub fn iface_add_addr(iface_name: &str, addr: Ipv4Addr, prefix_len: u8) {
    let entry = IfaceAddr { addr, prefix_len };
    {
        let mut g = IFACE_ADDRS.lock();
        if let Some(ia) = g.iter_mut().find(|ia| ia.iface_name == iface_name) {
            if !ia.addrs.contains(&entry) {
                ia.addrs.push(entry);
            }
        } else {
            g.push(IfaceAddrs {
                iface_name: String::from(iface_name),
                addrs: alloc::vec![entry],
            });
        }
    }
    // Auto-install the connected route for the subnet.
    crate::route::install_connected_route(iface_name, addr, prefix_len);
}

/// Remove an IPv4 address from the named interface. No-op if not found.
/// The corresponding connected route is also deleted.
pub fn iface_del_addr(iface_name: &str, addr: Ipv4Addr, prefix_len: u8) {
    let entry = IfaceAddr { addr, prefix_len };
    let mut g = IFACE_ADDRS.lock();
    if let Some(ia) = g.iter_mut().find(|ia| ia.iface_name == iface_name) {
        ia.addrs.retain(|a| a != &entry);
    }
    drop(g);
    crate::route::remove_connected_route(iface_name, addr, prefix_len);
}

/// Return a snapshot of all IPv4 addresses on the named interface.
pub fn iface_addrs(iface_name: &str) -> Vec<IfaceAddr> {
    let g = IFACE_ADDRS.lock();
    g.iter()
        .find(|ia| ia.iface_name == iface_name)
        .map(|ia| ia.addrs.clone())
        .unwrap_or_default()
}

/// Return the first address on the named interface, or `None`.
pub fn iface_primary_addr(iface_name: &str) -> Option<IfaceAddr> {
    let g = IFACE_ADDRS.lock();
    g.iter()
        .find(|ia| ia.iface_name == iface_name)
        .and_then(|ia| ia.addrs.first().copied())
}

/// Test helper: flush all per-interface address state.
#[doc(hidden)]
pub fn __reset_for_test() {
    IFACE_ADDRS.lock().clear();
}
