//! Per-interface IPv6 address registry + lifetimes.
//!
//! References (public-only):
//! - RFC 4862 — IPv6 Stateless Address Autoconfiguration (S. Thomson,
//!   T. Narten, T. Jinmei, Sep 2007). §5.4 (DAD) and §5.5 (lifetime
//!   handling for valid/preferred timers).
//!   <https://datatracker.ietf.org/doc/html/rfc4862>
//! - RFC 4291 — IP Version 6 Addressing Architecture (R. Hinden, S.
//!   Deering, Feb 2006). §2.5.1 (interface identifiers) and §2.5.6
//!   (link-local).
//!   <https://datatracker.ietf.org/doc/html/rfc4291>
//! - RFC 7217 — Stable Privacy-Enhanced IIDs (F. Gont, Apr 2014).
//!   <https://datatracker.ietf.org/doc/html/rfc7217>
//! - RFC 8981 — Temporary IPv6 Addresses (F. Gont et al, Feb 2021).
//!   <https://datatracker.ietf.org/doc/html/rfc8981>
//!
//! Per-system lifetime fields are stored as monotonic-ns deadlines so
//! the scheduler's `narf_time::monotonic_ns()` clock is the only time
//! source. The registry is held under a single `IrqSafeSpinLock`;
//! per-iface manipulation is rare (RA arrives), per-iface lookup is
//! also rare (only when emitting outbound packets), so a single global
//! lock is fine for now.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// IPv6 address state (RFC 4862 §5.5.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddrState {
    /// Tentative: DAD is running. Outbound traffic from this source
    /// is suppressed.
    Tentative,
    /// Preferred: address is fully usable as a source.
    Preferred,
    /// Deprecated: still valid for receiving but no longer preferred
    /// as a source.
    Deprecated,
    /// Invalid: address has expired or DAD found a conflict.
    Invalid,
}

/// IPv6 address scope (RFC 4291 §2.7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddrScope {
    /// This node only (`::1`).
    Host,
    LinkLocal,
    UniqueLocal,
    Global,
}

/// An IPv6 address bound to an interface.
#[derive(Clone, Debug)]
pub struct Ipv6IfAddr {
    pub iface: String,
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub state: AddrState,
    pub scope: AddrScope,
    /// Deadline (monotonic-ns) past which the address is `Deprecated`.
    /// `u64::MAX` for infinite.
    pub preferred_deadline_ns: u64,
    /// Deadline (monotonic-ns) past which the address is `Invalid`.
    /// `u64::MAX` for infinite.
    pub valid_deadline_ns: u64,
    /// Was this generated from RFC 8981 privacy extensions?
    pub temporary: bool,
}

#[derive(Clone, Debug)]
struct NamespacedAddr {
    net_ns_id: u64,
    addr: Ipv6IfAddr,
}

static ADDRS: IrqSafeSpinLock<Vec<NamespacedAddr>> = IrqSafeSpinLock::new(Vec::new());

fn iface_namespace(iface: &str) -> u64 {
    crate::iface::lookup(iface)
        .map(|entry| entry.net_ns_id)
        .unwrap_or(0)
}

/// Add an IPv6 address binding (RFC 4862 §5.5.3).
pub fn add(addr: Ipv6IfAddr) {
    add_in(iface_namespace(&addr.iface), addr);
}

pub fn add_in(net_ns_id: u64, addr: Ipv6IfAddr) {
    let mut g = ADDRS.lock();
    g.retain(|e| {
        !(e.net_ns_id == net_ns_id && e.addr.iface == addr.iface && e.addr.addr == addr.addr)
    });
    g.push(NamespacedAddr { net_ns_id, addr });
}

/// Remove an address by `(iface, addr)`.
pub fn remove(iface: &str, addr: &[u8; 16]) -> bool {
    remove_in(iface_namespace(iface), iface, addr)
}

pub fn remove_in(net_ns_id: u64, iface: &str, addr: &[u8; 16]) -> bool {
    let mut g = ADDRS.lock();
    let before = g.len();
    g.retain(|e| !(e.net_ns_id == net_ns_id && e.addr.iface == iface && &e.addr.addr == addr));
    g.len() != before
}

/// Transition an address to a new state (e.g. Tentative → Preferred
/// after DAD passes, or Tentative → Invalid on DAD conflict).
pub fn set_state(iface: &str, addr: &[u8; 16], state: AddrState) -> bool {
    set_state_in(iface_namespace(iface), iface, addr, state)
}

pub fn set_state_in(net_ns_id: u64, iface: &str, addr: &[u8; 16], state: AddrState) -> bool {
    let mut g = ADDRS.lock();
    if let Some(e) = g
        .iter_mut()
        .find(|e| e.net_ns_id == net_ns_id && e.addr.iface == iface && &e.addr.addr == addr)
    {
        e.addr.state = state;
        true
    } else {
        false
    }
}

/// List addresses on an interface. Returns a clone to avoid holding
/// the lock during render.
pub fn list_iface(iface: &str) -> Vec<Ipv6IfAddr> {
    list_iface_in(iface_namespace(iface), iface)
}

pub fn list_iface_in(net_ns_id: u64, iface: &str) -> Vec<Ipv6IfAddr> {
    let g = ADDRS.lock();
    g.iter()
        .filter(|e| e.net_ns_id == net_ns_id && e.addr.iface == iface)
        .map(|e| e.addr.clone())
        .collect()
}

/// List every address in every interface. Boot-time / diagnostic.
pub fn list_all() -> Vec<Ipv6IfAddr> {
    list_all_in(0)
}

pub fn list_all_in(net_ns_id: u64) -> Vec<Ipv6IfAddr> {
    ADDRS
        .lock()
        .iter()
        .filter(|entry| entry.net_ns_id == net_ns_id)
        .map(|entry| entry.addr.clone())
        .collect()
}

/// Snapshot for `/proc/net/if_inet6`. The Linux format is one
/// line per address with fields `<32-hex-addr> <ifindex-hex>
/// <prefix-hex> <scope-hex> <flags-hex> <iface>`.
#[derive(Clone, Debug)]
pub struct Ipv6IfAddrSnapshot {
    pub iface: String,
    pub addr: [u8; 16],
    /// The device's ifindex (`ifp->idev->dev->ifindex`).
    pub ifindex: u32,
    pub prefix_len: u8,
    /// `ifp->scope`: Linux's [`ipv6_addr_scope`] bits (0 global, 0x10
    /// loopback, 0x20 link-local, 0x40 site-local).
    pub scope: u8,
    /// `(u8)ifp->flags`, the low byte of [`ifa_flags`].
    pub flags: u8,
}

/// The loopback address `::1`.
pub const LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// `IPV6_ADDR_LOOPBACK` / `IFA_HOST`.
pub const IFA_HOST: u8 = 0x10;
/// `IPV6_ADDR_LINKLOCAL` / `IFA_LINK`.
pub const IFA_LINK: u8 = 0x20;
/// `IPV6_ADDR_SITELOCAL` / `IFA_SITE`.
pub const IFA_SITE: u8 = 0x40;

/// Linux `ipv6_addr_scope()` (`include/net/ipv6.h`) for a unicast address:
/// `__ipv6_addr_type(addr) & IPV6_ADDR_SCOPE_MASK`. `::1` is
/// IPV6_ADDR_LOOPBACK, fe80::/10 IPV6_ADDR_LINKLOCAL, fec0::/10
/// IPV6_ADDR_SITELOCAL; every other unicast address, a ULA (fc00::/7)
/// included, is global scope and has no scope bit. This is the value
/// `inet6_ifaddr.scope` holds and `/proc/net/if_inet6` prints.
pub fn ipv6_addr_scope(addr: &[u8; 16]) -> u8 {
    if *addr == LOOPBACK {
        IFA_HOST
    } else if addr[0] == 0xfe && addr[1] & 0xc0 == 0x80 {
        IFA_LINK
    } else if addr[0] == 0xfe && addr[1] & 0xc0 == 0xc0 {
        IFA_SITE
    } else {
        0
    }
}

/// Linux `rt_scope()` (`include/net/addrconf.h`): the `RT_SCOPE_*` value
/// `inet6_fill_ifaddr` puts in `ifa_scope` for an [`ipv6_addr_scope`].
pub fn rt_scope(ifa_scope: u8) -> u8 {
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_SITE: u8 = 200;
    const RT_SCOPE_LINK: u8 = 253;
    const RT_SCOPE_HOST: u8 = 254;
    if ifa_scope & IFA_HOST != 0 {
        RT_SCOPE_HOST
    } else if ifa_scope & IFA_LINK != 0 {
        RT_SCOPE_LINK
    } else if ifa_scope & IFA_SITE != 0 {
        RT_SCOPE_SITE
    } else {
        RT_SCOPE_UNIVERSE
    }
}

/// The 32-bit `inet6_ifaddr.flags` (IFA_F_*) of an address: TENTATIVE (0x40)
/// while DAD runs, DEPRECATED (0x20) past its preferred lifetime, TEMPORARY
/// (0x01) for an RFC 8981 address, and PERMANENT (0x80) for an address with
/// no lifetime at all (`inet6_addr_add` sets it when `valid_lft ==
/// INFINITY_LIFE_TIME`). A SLAAC address carries its router-advertised
/// lifetimes and is not permanent (`addrconf_prefix_rcv_add_addr`).
pub fn ifa_flags(addr: &Ipv6IfAddr) -> u32 {
    const IFA_F_TEMPORARY: u32 = 0x01;
    const IFA_F_DEPRECATED: u32 = 0x20;
    const IFA_F_TENTATIVE: u32 = 0x40;
    const IFA_F_PERMANENT: u32 = 0x80;
    let mut flags = match addr.state {
        AddrState::Tentative => IFA_F_TENTATIVE,
        AddrState::Deprecated => IFA_F_DEPRECATED,
        AddrState::Preferred | AddrState::Invalid => 0,
    };
    if addr.temporary {
        flags |= IFA_F_TEMPORARY;
    }
    if addr.valid_deadline_ns == u64::MAX && addr.preferred_deadline_ns == u64::MAX {
        flags |= IFA_F_PERMANENT;
    }
    flags
}

/// The loopback device's `::1/128` (`init_loopback` → `add_addr(idev,
/// &in6addr_loopback, 128, IFA_HOST)`, IFA_F_PERMANENT).
pub fn loopback_ifaddr() -> Ipv6IfAddr {
    Ipv6IfAddr {
        iface: String::from("lo"),
        addr: LOOPBACK,
        prefix_len: 128,
        state: AddrState::Preferred,
        scope: AddrScope::Host,
        preferred_deadline_ns: u64::MAX,
        valid_deadline_ns: u64::MAX,
        temporary: false,
    }
}

/// Snapshot every IPv6 address bound to any interface.
pub fn snapshot() -> Vec<Ipv6IfAddrSnapshot> {
    snapshot_in(0)
}

/// `/proc/net/if_inet6` (`if6_seq_show`) for `net_ns_id`: `::1` on lo, then
/// every configured address, with the device's ifindex, its
/// [`ipv6_addr_scope`] and the low byte of its [`ifa_flags`].
pub fn snapshot_in(net_ns_id: u64) -> Vec<Ipv6IfAddrSnapshot> {
    // A namespace's own `lo` holds `::1` only while it is up
    // (`init_loopback` on NETDEV_UP, `addrconf_ifdown` on NETDEV_DOWN), as
    // the RTM_GETADDR dump reports; the initial namespace's `lo` is up.
    let loopback_up =
        net_ns_id == 0 || crate::iface::namespace_loopback(net_ns_id).is_none_or(|lo| lo.up);
    // Copy the table out before resolving ifindexes: the interface registry
    // has its own lock, which is never taken under ADDRS.
    let entries: Vec<Ipv6IfAddr> = loopback_up
        .then(loopback_ifaddr)
        .into_iter()
        .chain(
            ADDRS
                .lock()
                .iter()
                .filter(|entry| entry.net_ns_id == net_ns_id)
                .map(|entry| entry.addr.clone()),
        )
        .collect();
    entries
        .into_iter()
        .filter(|e| e.state != AddrState::Invalid)
        .map(|e| Ipv6IfAddrSnapshot {
            ifindex: crate::iface::ifindex_of(&e.iface).unwrap_or(0),
            prefix_len: e.prefix_len,
            scope: ipv6_addr_scope(&e.addr),
            flags: ifa_flags(&e) as u8,
            addr: e.addr,
            iface: e.iface,
        })
        .collect()
}

/// True iff `addr` is bound to *any* interface.
pub fn is_local(addr: &[u8; 16]) -> bool {
    is_local_in(0, addr)
}

pub fn is_local_in(net_ns_id: u64, addr: &[u8; 16]) -> bool {
    let g = ADDRS.lock();
    g.iter().any(|e| {
        e.net_ns_id == net_ns_id && &e.addr.addr == addr && e.addr.state != AddrState::Invalid
    })
}

/// True iff `addr` is bound to a specific interface.
pub fn is_local_on(iface: &str, addr: &[u8; 16]) -> bool {
    is_local_on_in(iface_namespace(iface), iface, addr)
}

pub fn is_local_on_in(net_ns_id: u64, iface: &str, addr: &[u8; 16]) -> bool {
    let g = ADDRS.lock();
    g.iter().any(|e| {
        e.net_ns_id == net_ns_id
            && e.addr.iface == iface
            && &e.addr.addr == addr
            && e.addr.state != AddrState::Invalid
    })
}

/// Walk every address and demote/expire per the current time.
pub fn age_tick(now_ns: u64) {
    let mut g = ADDRS.lock();
    for e in g.iter_mut() {
        if e.addr.state == AddrState::Preferred && now_ns >= e.addr.preferred_deadline_ns {
            e.addr.state = AddrState::Deprecated;
        }
        if e.addr.state != AddrState::Invalid && now_ns >= e.addr.valid_deadline_ns {
            e.addr.state = AddrState::Invalid;
        }
    }
    g.retain(|e| e.addr.state != AddrState::Invalid);
}

/// Pick a source address for sending to `dst` on `iface`. Returns the
/// first non-tentative non-invalid address matching the destination
/// scope. RFC 6724 §5 has the full algorithm; this is the minimal
/// "same scope first, then any non-link-local" subset.
pub fn pick_source(iface: &str, dst: &[u8; 16]) -> Option<[u8; 16]> {
    pick_source_in(iface_namespace(iface), iface, dst)
}

pub fn pick_source_in(net_ns_id: u64, iface: &str, dst: &[u8; 16]) -> Option<[u8; 16]> {
    let dst_scope = scope_of(dst);
    let g = ADDRS.lock();
    // First pass: state == Preferred and scopes match.
    if let Some(e) = g.iter().find(|e| {
        e.net_ns_id == net_ns_id
            && e.addr.iface == iface
            && e.addr.state == AddrState::Preferred
            && e.addr.scope == dst_scope
    }) {
        return Some(e.addr.addr);
    }
    // Second pass: any Preferred address.
    if let Some(e) = g.iter().find(|e| {
        e.net_ns_id == net_ns_id && e.addr.iface == iface && e.addr.state == AddrState::Preferred
    }) {
        return Some(e.addr.addr);
    }
    // Third pass: any non-Invalid.
    g.iter()
        .find(|e| {
            e.net_ns_id == net_ns_id && e.addr.iface == iface && e.addr.state != AddrState::Invalid
        })
        .map(|e| e.addr.addr)
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    ADDRS.lock().retain(|entry| entry.net_ns_id != net_ns_id);
}

/// Classify an address by its scope (RFC 4291).
pub fn scope_of(addr: &[u8; 16]) -> AddrScope {
    if *addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        AddrScope::Host // ::1
    } else if addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80 {
        AddrScope::LinkLocal // fe80::/10
    } else if addr[0] == 0xFC || addr[0] == 0xFD {
        AddrScope::UniqueLocal // fc00::/7
    } else {
        AddrScope::Global
    }
}

/// Build an EUI-64 modified interface identifier from a MAC (RFC 4291
/// Appendix A): insert `0xFF 0xFE` in the middle, flip the U/L bit
/// (bit 1 of the first byte).
pub fn eui64_from_mac(mac: [u8; 6]) -> [u8; 8] {
    let mut iid = [0u8; 8];
    iid[0] = mac[0] ^ 0x02; // flip U/L
    iid[1] = mac[1];
    iid[2] = mac[2];
    iid[3] = 0xFF;
    iid[4] = 0xFE;
    iid[5] = mac[3];
    iid[6] = mac[4];
    iid[7] = mac[5];
    iid
}

/// Synthesise a link-local address from a MAC: `fe80::<EUI-64>`.
pub fn link_local_from_mac(mac: [u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xFE;
    a[1] = 0x80;
    a[8..16].copy_from_slice(&eui64_from_mac(mac));
    a
}

/// The all-nodes link-local multicast address ff02::1 (RFC 4291
/// §2.7.1). Unsolicited Neighbor Advertisements go here (RFC 4861
/// §7.2.6); so do DAD-probe replies (RFC 4861 §7.2.4).
pub const ALL_NODES_MULTICAST: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

/// Form the solicited-node multicast address for `target`
/// (RFC 4291 §2.7.1): `ff02::1:ff` || target[13..16].
pub fn solicited_node_multicast(target: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = 0xFF;
    out[1] = 0x02;
    out[11] = 0x01;
    out[12] = 0xFF;
    out[13] = target[13];
    out[14] = target[14];
    out[15] = target[15];
    out
}

/// Generate a per-interface random IID for an RFC 8981 temporary
/// address. The randomness source is a per-call SplitMix-style
/// scramble of `seed`; the caller provides whatever entropy it
/// has (monotonic time XOR MAC bytes is typical).
pub fn random_iid(seed: u64) -> [u8; 8] {
    let mut s = seed;
    // SplitMix64.
    s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    s ^= s >> 30;
    s = s.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    s ^= s >> 27;
    s = s.wrapping_mul(0x94D0_49BB_1331_11EB);
    s ^= s >> 31;
    // Clear the universal (U) bit per RFC 4291 §2.5.1 so the IID is
    // recognisably administratively assigned, not derived from EUI-64.
    let mut iid = s.to_be_bytes();
    iid[0] &= 0xFD;
    iid
}

/// Form a SLAAC address by concatenating `prefix` (high `prefix_len`
/// bits) and `iid` (low 64 bits). The function tolerates any
/// `prefix_len <= 64`; longer prefixes are clamped because the IID
/// must occupy the low 64 bits.
pub fn slaac_compose(prefix: &[u8; 16], prefix_len: u8, iid: &[u8; 8]) -> [u8; 16] {
    let mut out = *prefix;
    let pl = if prefix_len > 64 { 64 } else { prefix_len };
    // Zero everything past the prefix-length boundary up to byte 8.
    let mut byte = (pl / 8) as usize;
    let bit_in_byte = pl % 8;
    if bit_in_byte != 0 && byte < 8 {
        // Mask the partial byte: keep the top `bit_in_byte` bits.
        let mask: u8 = !((1u8 << (8 - bit_in_byte)) - 1);
        out[byte] &= mask;
        byte += 1;
    }
    while byte < 8 {
        out[byte] = 0;
        byte += 1;
    }
    out[8..16].copy_from_slice(iid);
    out
}

/// Reset the registry. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    ADDRS.lock().clear();
}
