//! Neighbor Discovery Protocol — RFC 4861.
//!
//! References (public-only):
//! - RFC 4861 — Neighbor Discovery for IP version 6 (T. Narten, E.
//!   Nordmark, W. Simpson, H. Soliman, Sep 2007). §4 (message formats),
//!   §6 (router behaviour & RA processing), §7 (neighbor cache &
//!   resolution), §7.2 (Address Resolution: NS multicast,
//!   NA reply), §7.3 (Neighbor Unreachability Detection — Incomplete,
//!   Reachable, Stale, Delay, Probe).
//!   <https://datatracker.ietf.org/doc/html/rfc4861>
//! - RFC 4862 — IPv6 Stateless Address Autoconfiguration. §5.4
//!   (Duplicate Address Detection).
//!   <https://datatracker.ietf.org/doc/html/rfc4862>
//! - RFC 8106 — IPv6 Router Advertisement Options for DNS Configuration
//!   (J. Jeong, S. Park, L. Beloeil, S. Madanapalli, Mar 2017).
//!   <https://datatracker.ietf.org/doc/html/rfc8106>
//!
//! The codec lives in `crate::pkt_ipv6` (NS / NA / RA / RS builders and
//! the ND-option iterator); this module owns the *state machine*: the
//! neighbor cache, default-router list, prefix list, and DAD timers.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::pkt_ipv6::{
    self, append_nd_option, iter_nd_options, neighbor_advertisement, neighbor_solicitation,
    router_solicitation, ICMPV6_NEIGHBOR_ADVERTISEMENT, ICMPV6_NEIGHBOR_SOLICITATION,
    ICMPV6_REDIRECT, ICMPV6_ROUTER_ADVERTISEMENT, NA_FLAG_OVERRIDE, NA_FLAG_SOLICITED,
    ND_OPT_PREFIX_INFORMATION, ND_OPT_SOURCE_LINK_LAYER_ADDR, ND_OPT_TARGET_LINK_LAYER_ADDR,
};

use super::addrs::{self, solicited_node_multicast};
use super::route::{self, Route};

/// Neighbor cache state (RFC 4861 §7.3.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NeighState {
    /// Address resolution in progress — no LL address yet.
    Incomplete,
    /// LL address known and confirmed bidirectionally recently.
    Reachable,
    /// LL address known but reachability not confirmed recently.
    Stale,
    /// Stale; sending data, deferring NUD probe to allow upper-layer
    /// hint.
    Delay,
    /// Probing: NS sent, waiting for NA.
    Probe,
}

/// Neighbor cache entry.
#[derive(Clone, Debug)]
pub struct Neigh {
    pub iface: String,
    pub ip: [u8; 16],
    pub mac: Option<[u8; 6]>,
    pub state: NeighState,
    pub is_router: bool,
    /// Deadline (monotonic-ns) past which the state ages.
    pub deadline_ns: u64,
}

static NEIGH: IrqSafeSpinLock<Vec<Neigh>> = IrqSafeSpinLock::new(Vec::new());

/// Insert / update a neighbor entry.
pub fn neigh_upsert(entry: Neigh) {
    let mut g = NEIGH.lock();
    if let Some(e) = g
        .iter_mut()
        .find(|e| e.iface == entry.iface && e.ip == entry.ip)
    {
        e.mac = entry.mac;
        e.state = entry.state;
        e.is_router = entry.is_router;
        e.deadline_ns = entry.deadline_ns;
    } else {
        g.push(entry);
    }
}

/// Look up the MAC for `(iface, ip)`. Returns `None` if no entry or
/// the entry is still `Incomplete`.
pub fn neigh_lookup(iface: &str, ip: &[u8; 16]) -> Option<[u8; 6]> {
    let g = NEIGH.lock();
    g.iter()
        .find(|e| e.iface == iface && &e.ip == ip)
        .and_then(|e| e.mac)
}

/// Snapshot the cache.
pub fn neigh_list() -> Vec<Neigh> {
    NEIGH.lock().clone()
}

/// Remove an entry by `(iface, ip)`.
pub fn neigh_remove(iface: &str, ip: &[u8; 16]) -> bool {
    let mut g = NEIGH.lock();
    let before = g.len();
    g.retain(|e| !(e.iface == iface && &e.ip == ip));
    g.len() != before
}

/// Mark an entry `Stale` if it was `Reachable` for longer than its
/// deadline (RFC 4861 §7.3.3 reachable-timer expiry).
pub fn age_tick(now_ns: u64) {
    let mut g = NEIGH.lock();
    for e in g.iter_mut() {
        if e.deadline_ns != 0 && now_ns >= e.deadline_ns {
            e.state = match e.state {
                NeighState::Reachable => NeighState::Stale,
                NeighState::Delay => NeighState::Probe,
                s => s,
            };
        }
    }
}

// ── Default router list (RFC 4861 §6.3.4) ───────────────────────────

#[derive(Clone, Debug)]
pub struct DefaultRouter {
    pub iface: String,
    pub addr: [u8; 16],
    pub deadline_ns: u64,
}

static ROUTERS: IrqSafeSpinLock<Vec<DefaultRouter>> = IrqSafeSpinLock::new(Vec::new());

pub fn routers() -> Vec<DefaultRouter> {
    ROUTERS.lock().clone()
}

fn router_upsert(r: DefaultRouter) {
    let mut g = ROUTERS.lock();
    if let Some(e) = g
        .iter_mut()
        .find(|e| e.iface == r.iface && e.addr == r.addr)
    {
        e.deadline_ns = r.deadline_ns;
    } else {
        g.push(r);
    }
}

// ── Outbound message builders ───────────────────────────────────────

/// Build a Router Solicitation body with a Source LL Address option.
pub fn build_rs(src_mac: [u8; 6]) -> Vec<u8> {
    let mut opts = Vec::new();
    // Source LL Address option: 1 byte type + 1 byte length (1 = 8
    // bytes) + 6-byte MAC. Total = 8 bytes — meets the "length in
    // 8-byte units" invariant.
    let mut data = Vec::with_capacity(6);
    data.extend_from_slice(&src_mac);
    let _ = append_nd_option(&mut opts, ND_OPT_SOURCE_LINK_LAYER_ADDR, &data);
    router_solicitation(&opts)
}

/// Build a Neighbor Solicitation body targeting `target`, including a
/// Source LL Address option.
pub fn build_ns(target: [u8; 16], src_mac: [u8; 6]) -> Vec<u8> {
    let mut opts = Vec::new();
    let mut data = Vec::with_capacity(6);
    data.extend_from_slice(&src_mac);
    let _ = append_nd_option(&mut opts, ND_OPT_SOURCE_LINK_LAYER_ADDR, &data);
    neighbor_solicitation(target, &opts)
}

/// Build a DAD-style Neighbor Solicitation. The source LL Address
/// option is omitted (RFC 4862 §5.4.2) so a receiver knows the sender
/// has no assigned address yet.
pub fn build_dad_ns(target: [u8; 16]) -> Vec<u8> {
    neighbor_solicitation(target, &[])
}

/// Build a Neighbor Advertisement body for `target` with the S/O
/// flags set (Solicited + Override). Includes a Target LL Address
/// option.
pub fn build_na(target: [u8; 16], src_mac: [u8; 6], router: bool) -> Vec<u8> {
    let mut opts = Vec::new();
    let mut data = Vec::with_capacity(6);
    data.extend_from_slice(&src_mac);
    let _ = append_nd_option(&mut opts, ND_OPT_TARGET_LINK_LAYER_ADDR, &data);
    let mut flags = NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE;
    if router {
        flags |= pkt_ipv6::NA_FLAG_ROUTER;
    }
    neighbor_advertisement(flags, target, &opts)
}

// ── Inbound dispatch ────────────────────────────────────────────────

/// Result of dispatching an inbound ICMPv6 ND message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NdRxResult {
    /// Caller should emit this ICMPv6 body in reply (no header bytes).
    SendBody(Vec<u8>),
    /// State updated; no reply needed.
    Updated,
    /// Message ignored.
    Ignored,
    /// DAD-relevant: the address we were tentatively claiming was
    /// already in use. Caller drops the address.
    DadConflict([u8; 16]),
}

/// Process an inbound Neighbor Solicitation. If the `target` matches
/// one of *our* iface addresses, emit a Neighbor Advertisement.
pub fn on_ns(iface: &str, src_mac_opt: Option<[u8; 6]>, body: &[u8]) -> NdRxResult {
    if body.len() < 24 || body[0] != ICMPV6_NEIGHBOR_SOLICITATION {
        return NdRxResult::Ignored;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&body[8..24]);
    // Walk options and record any Source LL Address.
    let mut sll: Option<[u8; 6]> = None;
    for opt in iter_nd_options(&body[24..]) {
        if opt.typ == ND_OPT_SOURCE_LINK_LAYER_ADDR && opt.data.len() >= 6 {
            let mut m = [0u8; 6];
            m.copy_from_slice(&opt.data[..6]);
            sll = Some(m);
        }
    }
    if let Some(m) = sll.or(src_mac_opt) {
        // Sender's IP isn't carried in the NS body itself; the caller
        // (IPv6 stack) provides it via the outer packet, but for
        // address-resolution purposes we cache (iface, target_of_NS,
        // sender_mac). Without the sender IP we cache only the MAC
        // tied to the NS source LL option.
        let _ = m;
    }
    // Is `target` one of our tentative addresses? Then this is a DAD
    // probe from a peer claiming the same address — conflict.
    let addrs = addrs::list_iface(iface);
    if let Some(local) = addrs.iter().find(|a| a.addr == target) {
        use super::addrs::AddrState;
        if local.state == AddrState::Tentative {
            return NdRxResult::DadConflict(target);
        }
        // It's our final address; reply with an NA.
        // (Caller fills in source MAC; we just produce the body.)
        return NdRxResult::SendBody(build_na(target, [0; 6], false));
    }
    NdRxResult::Ignored
}

/// Process an inbound Neighbor Advertisement. Update the neighbor
/// cache; if the target was tentative-DAD, signal `DadConflict`.
pub fn on_na(iface: &str, body: &[u8]) -> NdRxResult {
    if body.len() < 24 || body[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT {
        return NdRxResult::Ignored;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&body[8..24]);
    let flags = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let mut tll: Option<[u8; 6]> = None;
    for opt in iter_nd_options(&body[24..]) {
        if opt.typ == ND_OPT_TARGET_LINK_LAYER_ADDR && opt.data.len() >= 6 {
            let mut m = [0u8; 6];
            m.copy_from_slice(&opt.data[..6]);
            tll = Some(m);
        }
    }
    // DAD: if target is one of our Tentative addresses, the peer
    // already owns it — drop our claim.
    let addrs = addrs::list_iface(iface);
    if let Some(local) = addrs.iter().find(|a| a.addr == target) {
        use super::addrs::AddrState;
        if local.state == AddrState::Tentative {
            return NdRxResult::DadConflict(target);
        }
    }
    if let Some(m) = tll {
        let is_router = (flags & pkt_ipv6::NA_FLAG_ROUTER) != 0;
        neigh_upsert(Neigh {
            iface: String::from(iface),
            ip: target,
            mac: Some(m),
            state: NeighState::Reachable,
            is_router,
            deadline_ns: 0,
        });
        return NdRxResult::Updated;
    }
    NdRxResult::Ignored
}

/// Result of RA dispatch: lifetimes + RDNSS list parsed out of the
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaInfo {
    pub router_lifetime_s: u16,
    pub managed_flag: bool,
    pub other_flag: bool,
    pub prefixes: Vec<RaPrefix>,
    pub rdnss: Vec<[u8; 16]>,
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaPrefix {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime_s: u32,
    pub preferred_lifetime_s: u32,
}

/// Process an inbound Router Advertisement. Updates the default-router
/// list and the prefix list; returns the parsed info so SLAAC can
/// run against it.
pub fn on_ra(iface: &str, src_addr: [u8; 16], body: &[u8], now_ns: u64) -> Option<RaInfo> {
    if body.len() < 16 || body[0] != ICMPV6_ROUTER_ADVERTISEMENT {
        return None;
    }
    let mo_flags = body[5];
    let managed_flag = (mo_flags & pkt_ipv6::RA_FLAG_MANAGED) != 0;
    let other_flag = (mo_flags & pkt_ipv6::RA_FLAG_OTHER_CONFIG) != 0;
    let router_lifetime_s = u16::from_be_bytes([body[6], body[7]]);
    // Default router update.
    if router_lifetime_s > 0 {
        router_upsert(DefaultRouter {
            iface: String::from(iface),
            addr: src_addr,
            deadline_ns: now_ns.saturating_add((router_lifetime_s as u64) * 1_000_000_000),
        });
        // Install a default route via the RA source.
        route::add(Route {
            prefix: [0u8; 16],
            prefix_len: 0,
            gateway: Some(src_addr),
            iface: String::from(iface),
            metric: 1024,
            valid_deadline_ns: now_ns.saturating_add((router_lifetime_s as u64) * 1_000_000_000),
        });
    }
    let mut prefixes = Vec::new();
    let mut rdnss = Vec::new();
    let mut mtu = None;
    for opt in iter_nd_options(&body[16..]) {
        match opt.typ {
            // Prefix Information Option (RFC 4861 §4.6.2): 30-byte
            // body (after the 2-byte option header).
            ND_OPT_PREFIX_INFORMATION => {
                if opt.data.len() >= 30 {
                    let prefix_len = opt.data[0];
                    let lflags = opt.data[1];
                    let on_link = (lflags & 0x80) != 0;
                    let autonomous = (lflags & 0x40) != 0;
                    let valid_lifetime_s =
                        u32::from_be_bytes([opt.data[2], opt.data[3], opt.data[4], opt.data[5]]);
                    let preferred_lifetime_s =
                        u32::from_be_bytes([opt.data[6], opt.data[7], opt.data[8], opt.data[9]]);
                    let mut prefix = [0u8; 16];
                    prefix.copy_from_slice(&opt.data[14..30]);
                    prefixes.push(RaPrefix {
                        prefix,
                        prefix_len,
                        on_link,
                        autonomous,
                        valid_lifetime_s,
                        preferred_lifetime_s,
                    });
                    if on_link && valid_lifetime_s > 0 {
                        route::add(Route {
                            prefix,
                            prefix_len,
                            gateway: None,
                            iface: String::from(iface),
                            metric: 256,
                            valid_deadline_ns: now_ns
                                .saturating_add((valid_lifetime_s as u64) * 1_000_000_000),
                        });
                    }
                }
            }
            // MTU option (RFC 4861 §4.6.4).
            pkt_ipv6::ND_OPT_MTU => {
                if opt.data.len() >= 6 {
                    let v =
                        u32::from_be_bytes([opt.data[2], opt.data[3], opt.data[4], opt.data[5]]);
                    mtu = Some(v);
                }
            }
            // RDNSS option (RFC 8106 §5.1, IANA type 25). Body:
            // 2 bytes reserved, 4 bytes lifetime, then N×16-byte
            // addresses.
            25 => {
                if opt.data.len() >= 6 {
                    let mut p = 6;
                    while p + 16 <= opt.data.len() {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&opt.data[p..p + 16]);
                        rdnss.push(a);
                        p += 16;
                    }
                }
            }
            _ => {}
        }
    }
    Some(RaInfo {
        router_lifetime_s,
        managed_flag,
        other_flag,
        prefixes,
        rdnss,
        mtu,
    })
}

/// Process an inbound Redirect (RFC 4861 §8). The body layout is:
/// 4 bytes reserved + 16 bytes target + 16 bytes destination.
pub fn on_redirect(iface: &str, body: &[u8]) -> NdRxResult {
    if body.len() < 40 || body[0] != ICMPV6_REDIRECT {
        return NdRxResult::Ignored;
    }
    let mut target = [0u8; 16];
    let mut dest = [0u8; 16];
    target.copy_from_slice(&body[8..24]);
    dest.copy_from_slice(&body[24..40]);
    // Install a /128 host route via the new target.
    route::add(Route {
        prefix: dest,
        prefix_len: 128,
        gateway: Some(target),
        iface: String::from(iface),
        metric: 200,
        valid_deadline_ns: 0,
    });
    NdRxResult::Updated
}

/// Compute the solicited-node multicast for `target` (re-export for
/// the caller's convenience).
pub fn snm(target: &[u8; 16]) -> [u8; 16] {
    solicited_node_multicast(target)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    NEIGH.lock().clear();
    ROUTERS.lock().clear();
}
