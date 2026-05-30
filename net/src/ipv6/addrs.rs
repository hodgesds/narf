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

static ADDRS: IrqSafeSpinLock<Vec<Ipv6IfAddr>> = IrqSafeSpinLock::new(Vec::new());

/// Add an IPv6 address binding (RFC 4862 §5.5.3).
pub fn add(addr: Ipv6IfAddr) {
    let mut g = ADDRS.lock();
    g.retain(|e| !(e.iface == addr.iface && e.addr == addr.addr));
    g.push(addr);
}

/// Remove an address by `(iface, addr)`.
pub fn remove(iface: &str, addr: &[u8; 16]) -> bool {
    let mut g = ADDRS.lock();
    let before = g.len();
    g.retain(|e| !(e.iface == iface && &e.addr == addr));
    g.len() != before
}

/// Transition an address to a new state (e.g. Tentative → Preferred
/// after DAD passes, or Tentative → Invalid on DAD conflict).
pub fn set_state(iface: &str, addr: &[u8; 16], state: AddrState) -> bool {
    let mut g = ADDRS.lock();
    if let Some(e) = g.iter_mut().find(|e| e.iface == iface && &e.addr == addr) {
        e.state = state;
        true
    } else {
        false
    }
}

/// List addresses on an interface. Returns a clone to avoid holding
/// the lock during render.
pub fn list_iface(iface: &str) -> Vec<Ipv6IfAddr> {
    let g = ADDRS.lock();
    g.iter().filter(|e| e.iface == iface).cloned().collect()
}

/// List every address in every interface. Boot-time / diagnostic.
pub fn list_all() -> Vec<Ipv6IfAddr> {
    ADDRS.lock().clone()
}

/// Snapshot for `/proc/net/if_inet6`. The Linux format is one
/// line per address with fields `<32-hex-addr> <ifindex-hex>
/// <prefix-hex> <scope-hex> <flags-hex> <iface>`.
#[derive(Clone, Debug)]
pub struct Ipv6IfAddrSnapshot {
    pub iface: String,
    pub addr: [u8; 16],
    pub ifindex: u32,
    pub prefix_len: u8,
    /// Linux scope byte: 0=Global, 0x10=LinkLocal, 0x20=SiteLocal.
    pub scope: u8,
    /// IFA_F_* bitmap: Tentative=0x40, Permanent=0x80, Deprecated=0x20.
    pub flags: u8,
}

/// Snapshot every IPv6 address bound to any interface.
pub fn snapshot() -> Vec<Ipv6IfAddrSnapshot> {
    let g = ADDRS.lock();
    let mut out = Vec::with_capacity(g.len());
    // Assign a per-iface index starting at 1. Real ifindex
    // allocation needs to live in iface.rs once that surface
    // exists; until then index by iface-name ordinal.
    let mut idx_for_iface: alloc::collections::BTreeMap<&str, u32> =
        alloc::collections::BTreeMap::new();
    let mut next_idx: u32 = 1;
    for e in g.iter() {
        let ifindex = *idx_for_iface
            .entry(e.iface.as_str())
            .or_insert_with(|| {
                let i = next_idx;
                next_idx += 1;
                i
            });
        let scope = match e.scope {
            AddrScope::Global => 0x00,
            AddrScope::LinkLocal => 0x20,
            AddrScope::UniqueLocal => 0x40,
        };
        let mut flags: u8 = 0;
        if e.state == AddrState::Tentative {
            flags |= 0x40;
        }
        if e.state == AddrState::Deprecated {
            flags |= 0x20;
        }
        if e.state == AddrState::Preferred {
            flags |= 0x80;
        }
        out.push(Ipv6IfAddrSnapshot {
            iface: e.iface.clone(),
            addr: e.addr,
            ifindex,
            prefix_len: e.prefix_len,
            scope,
            flags,
        });
    }
    out
}

/// True iff `addr` is bound to *any* interface.
pub fn is_local(addr: &[u8; 16]) -> bool {
    let g = ADDRS.lock();
    g.iter().any(|e| &e.addr == addr && e.state != AddrState::Invalid)
}

/// True iff `addr` is bound to a specific interface.
pub fn is_local_on(iface: &str, addr: &[u8; 16]) -> bool {
    let g = ADDRS.lock();
    g.iter().any(|e| e.iface == iface && &e.addr == addr && e.state != AddrState::Invalid)
}

/// Walk every address and demote/expire per the current time.
pub fn age_tick(now_ns: u64) {
    let mut g = ADDRS.lock();
    for e in g.iter_mut() {
        if e.state == AddrState::Preferred && now_ns >= e.preferred_deadline_ns {
            e.state = AddrState::Deprecated;
        }
        if e.state != AddrState::Invalid && now_ns >= e.valid_deadline_ns {
            e.state = AddrState::Invalid;
        }
    }
    g.retain(|e| e.state != AddrState::Invalid);
}

/// Pick a source address for sending to `dst` on `iface`. Returns the
/// first non-tentative non-invalid address matching the destination
/// scope. RFC 6724 §5 has the full algorithm; this is the minimal
/// "same scope first, then any non-link-local" subset.
pub fn pick_source(iface: &str, dst: &[u8; 16]) -> Option<[u8; 16]> {
    let dst_scope = scope_of(dst);
    let g = ADDRS.lock();
    // First pass: state == Preferred and scopes match.
    if let Some(e) = g.iter().find(|e| {
        e.iface == iface
            && e.state == AddrState::Preferred
            && e.scope == dst_scope
    }) {
        return Some(e.addr);
    }
    // Second pass: any Preferred address.
    if let Some(e) = g.iter().find(|e| e.iface == iface && e.state == AddrState::Preferred) {
        return Some(e.addr);
    }
    // Third pass: any non-Invalid.
    g.iter()
        .find(|e| e.iface == iface && e.state != AddrState::Invalid)
        .map(|e| e.addr)
}

/// Classify an address by its scope (RFC 4291).
pub fn scope_of(addr: &[u8; 16]) -> AddrScope {
    if addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80 {
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
