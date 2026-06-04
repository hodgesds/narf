//! IPv6 routing table — longest-prefix-match over `(prefix, len)` tuples.
//!
//! References (public-only):
//! - RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification.
//!   §3 (header), §4 (extension headers — Hop-by-Hop / Fragment).
//!   <https://datatracker.ietf.org/doc/html/rfc8200>
//! - RFC 4291 — IP Version 6 Addressing Architecture. §2.5.6 (link-local
//!   never routed past the originating link), §2.5.4 (global unicast
//!   format), §2.7 (multicast scoped routing).
//!   <https://datatracker.ietf.org/doc/html/rfc4291>
//! - RFC 4861 — Neighbor Discovery for IP version 6. §6.3.4 (default
//!   router list maintained from RA Router Lifetime), §6.3.5 (Prefix
//!   List from PIO).
//!   <https://datatracker.ietf.org/doc/html/rfc4861>
//!
//! Stage-1 scope: a single ordered `Vec` of entries. Longest-prefix
//! search is O(N), trivially adequate for the dozen-entry tables that
//! arise from a couple of on-link prefixes plus a default route. The
//! search is bounded by `prefix_len` (longer first) so the first
//! match wins.
//!
//! Special cases:
//! - `fe80::/10`: always `Direct(iface)`. Link-local traffic is never
//!   forwarded; the scope-id (= iface name) is mandatory.
//! - `ff00::/8`: multicast; always `Direct(iface)` per the scope rules.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use super::addrs::AddrScope;

/// Next-hop classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextHop {
    /// Destination is on-link — send directly via the iface.
    Direct(String),
    /// Destination is off-link — send to `gateway` via `iface`.
    Gateway { iface: String, gateway: [u8; 16] },
    /// No route — drop and let the upper layer surface ENETUNREACH.
    Unreachable,
}

/// A routing entry.
#[derive(Clone, Debug)]
pub struct Route {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 16]>,
    pub iface: String,
    /// Metric — smaller is preferred when prefix_len ties.
    pub metric: u32,
    /// Deadline (monotonic-ns) past which the route is dropped. 0 =
    /// never expires (e.g. statically configured connected routes).
    pub valid_deadline_ns: u64,
}

static ROUTES: IrqSafeSpinLock<Vec<Route>> = IrqSafeSpinLock::new(Vec::new());

/// Install a route, replacing any existing entry with the same
/// `(prefix, prefix_len, iface)`.
pub fn add(route: Route) {
    let mut g = ROUTES.lock();
    g.retain(|r| {
        !(r.prefix == route.prefix && r.prefix_len == route.prefix_len && r.iface == route.iface)
    });
    g.push(route);
    // Keep the table sorted longest-prefix-first so lookup is a
    // straight forward scan.
    g.sort_by(|a, b| {
        b.prefix_len
            .cmp(&a.prefix_len)
            .then(a.metric.cmp(&b.metric))
    });
}

/// Remove a route by `(prefix, prefix_len, iface)`. Returns true iff a
/// matching entry existed.
pub fn remove(prefix: &[u8; 16], prefix_len: u8, iface: &str) -> bool {
    let mut g = ROUTES.lock();
    let before = g.len();
    g.retain(|r| !(&r.prefix == prefix && r.prefix_len == prefix_len && r.iface == iface));
    g.len() != before
}

/// Snapshot every route. Diagnostic use.
pub fn list_all() -> Vec<Route> {
    ROUTES.lock().clone()
}

/// Snapshot for `/proc/net/ipv6_route`. Linux's format:
/// `<dst> <plen> <src> <splen> <next-hop> <metric> <ref> <use>
///  <flags> <iface>`.
#[derive(Clone, Debug)]
pub struct Ipv6RouteSnapshot {
    pub dst: [u8; 16],
    pub dst_prefix_len: u8,
    pub src: [u8; 16],
    pub src_prefix_len: u8,
    pub gateway: [u8; 16],
    pub metric: u32,
    pub refcnt: u32,
    pub use_count: u32,
    pub flags: u32,
    pub iface: String,
}

/// Snapshot every IPv6 route.
pub fn snapshot() -> Vec<Ipv6RouteSnapshot> {
    let g = ROUTES.lock();
    let mut out = Vec::with_capacity(g.len());
    for r in g.iter() {
        let gateway = r.gateway.unwrap_or([0u8; 16]);
        let mut flags: u32 = 0x0001; // RTF_UP
        if r.gateway.is_some() {
            flags |= 0x0002; // RTF_GATEWAY
        }
        out.push(Ipv6RouteSnapshot {
            dst: r.prefix,
            dst_prefix_len: r.prefix_len,
            src: [0u8; 16],
            src_prefix_len: 0,
            gateway,
            metric: r.metric,
            refcnt: 0,
            use_count: 0,
            flags,
            iface: r.iface.clone(),
        });
    }
    out
}

/// Walk routes and drop any whose deadline has elapsed.
pub fn age_tick(now_ns: u64) {
    let mut g = ROUTES.lock();
    g.retain(|r| r.valid_deadline_ns == 0 || now_ns < r.valid_deadline_ns);
}

/// Test whether the first `prefix_len` bits of `addr` match `prefix`.
pub fn match_prefix(addr: &[u8; 16], prefix: &[u8; 16], prefix_len: u8) -> bool {
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if full > 16 {
        return false;
    }
    if addr[..full] != prefix[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    if full >= 16 {
        return true;
    }
    let mask: u8 = !((1u8 << (8 - rem)) - 1);
    (addr[full] & mask) == (prefix[full] & mask)
}

/// Look up a route for `dst`. `scope_iface` is the caller-supplied
/// scope-id for link-local destinations; `None` means "any iface".
///
/// Returns the most specific match. Link-local routes are honoured
/// even without a matching entry in the table — the iface is taken
/// from `scope_iface`. Multicast is similarly direct.
pub fn lookup(dst: &[u8; 16], scope_iface: Option<&str>) -> NextHop {
    // Link-local — always direct, scope required.
    if super::addrs::scope_of(dst) == AddrScope::LinkLocal {
        return match scope_iface {
            Some(iface) => NextHop::Direct(String::from(iface)),
            None => NextHop::Unreachable,
        };
    }
    // Multicast — always direct on whatever iface the caller named.
    if dst[0] == 0xFF {
        return match scope_iface {
            Some(iface) => NextHop::Direct(String::from(iface)),
            None => {
                // Default: try to pick the first iface from the table.
                let g = ROUTES.lock();
                match g.first() {
                    Some(r) => NextHop::Direct(r.iface.clone()),
                    None => NextHop::Unreachable,
                }
            }
        };
    }
    // Normal LPM lookup.
    let g = ROUTES.lock();
    for r in g.iter() {
        if match_prefix(dst, &r.prefix, r.prefix_len) {
            return match r.gateway {
                None => NextHop::Direct(r.iface.clone()),
                Some(gw) => NextHop::Gateway {
                    iface: r.iface.clone(),
                    gateway: gw,
                },
            };
        }
    }
    NextHop::Unreachable
}

/// Reset the table. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    ROUTES.lock().clear();
}
