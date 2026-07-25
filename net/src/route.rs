//! IPv4 Forwarding Information Base (FIB) — routing table, longest-prefix-
//! match lookup, and source-address selection.
//!
//! ## Design rationale
//!
//! The table is a `Vec<Route>` kept sorted by `prefix_len` descending.
//! Lookup is O(n) linear scan — sufficient for a microkernel with at most a
//! handful of routes (loopback, two or three NICs, a default gateway). A
//! Patricia/CIDR trie (`fib_trie.c`) is the right data structure for a
//! full OS with thousands of routes, but it requires significant allocation
//! and complexity that has no payoff here. Document the choice so the
//! next engineer knows where to look.
//!
//! ## Linux references
//!
//! - `net/ipv4/fib_trie.c` `fib_table_lookup()` — performs LPM over the
//!   level-compressed trie. Our Vec scan replaces the trie.
//! - `net/ipv4/fib_semantics.c` `fib_check_nh()` — validates nexthop
//!   reachability; we do a lighter version (just prefix check).
//! - `net/ipv4/route.c` `ip_route_output_key_hash_rcu()` (around line 2780)
//!   calls `inet_select_addr` for source selection — our `src_for` mirrors
//!   that sequence.
//! - `net/ipv4/fib_semantics.c` `inet_select_addr()` (line 1294–1297) —
//!   picks the first local address in the same scope as the nexthop; we
//!   implement the same precedence: subnet-match first, then any local
//!   address on the egress interface.
//!
//! ## Loopback
//!
//! 127.0.0.0/8 is a special connected route installed at boot on the "lo"
//! interface. `route_lookup` for any 127.x.x.x address hits this route and
//! returns the loopback interface — the frame never goes to a NIC.
//!
//! ## Source-address selection (RFC 1122 §3.3.5)
//!
//! 1. Look up the route for `dst`.
//! 2. If `route.src_hint` is set, use it directly.
//! 3. Otherwise scan the egress interface's addresses for one that is in
//!    the same subnet as the gateway (or as `dst` if there is no gateway).
//! 4. Fall back to the first address on the interface.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::ifaddr::{iface_addrs, prefix_to_mask, IfaceAddr};
use crate::ipv4::Ipv4Addr;

// ── Types ──────────────────────────────────────────────────────────────

/// IPv4 network (address + CIDR prefix length).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Net {
    /// True iff `ip` falls within this network.
    #[inline]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix_len);
        (self.addr.to_u32() & mask) == (ip.to_u32() & mask)
    }
}

/// Route scope — mirrors Linux `RT_SCOPE_*`.
/// Ref: `include/uapi/linux/rtnetlink.h` enum rt_scope_t.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Route to a specific host directly reachable.
    Host = 254,
    /// Link-scope — direct delivery, no gateway.
    Link = 253,
    /// Universe — requires a gateway to reach.
    Universe = 0,
}

/// Route table IDs (subset of Linux RT_TABLE_*).
pub const TABLE_MAIN: u8 = 254;
pub const TABLE_LOCAL: u8 = 255;
pub const TABLE_DEFAULT: u8 = 253;

/// A single routing table entry.
#[derive(Clone, Debug)]
pub struct Route {
    /// Network namespace that owns this FIB entry.
    pub net_ns_id: u64,
    /// Destination network (address + prefix length).
    pub dst: Ipv4Net,
    /// Next-hop router. `None` means the destination is directly connected
    /// (link-local delivery). Ref: Linux `fib_nh.fib_nh_gw4`.
    pub gateway: Option<Ipv4Addr>,
    /// Egress interface name.
    pub iface: String,
    /// Preferred source address hint. When set, `src_for` skips the
    /// address scan and uses this directly.
    pub src_hint: Option<Ipv4Addr>,
    /// Route metric (lower is better). Used for tie-breaking when two
    /// routes have equal prefix length.
    pub metric: u32,
    pub scope: Scope,
    pub table: u8,
}

/// Result of a successful route lookup.
#[derive(Clone, Debug)]
pub struct RouteResult {
    /// Egress interface.
    pub iface: String,
    /// Next-hop IP (gateway, or `dst` itself for direct delivery).
    pub nexthop: Ipv4Addr,
    /// Preferred source address (after `src_for` is run).
    pub src: Ipv4Addr,
    /// The raw gateway (for callers that need to distinguish direct from
    /// routed delivery).
    pub gateway: Option<Ipv4Addr>,
}

// ── Global table ───────────────────────────────────────────────────────

/// The routing table. Maintained sorted by `prefix_len` descending so
/// the first match in a linear scan is always the longest prefix.
static ROUTE_TABLE: IrqSafeSpinLock<Vec<Route>> = IrqSafeSpinLock::new(Vec::new());

// ── Public API ─────────────────────────────────────────────────────────

/// Add a route. If a route with identical (dst, iface, table) already
/// exists it is replaced (hard cutover — no aliasing).
///
/// The table is re-sorted by prefix_len descending after insertion so
/// `route_lookup` always finds the longest match first.
pub fn route_add(route: Route) {
    let mut g = ROUTE_TABLE.lock();
    // Hard cutover: remove any exact-match (dst, iface, table).
    g.retain(|r| {
        !(r.net_ns_id == route.net_ns_id
            && r.dst == route.dst
            && r.iface == route.iface
            && r.table == route.table)
    });
    g.push(route);
    // Sort: longest prefix first; break ties by metric ascending.
    g.sort_by(|a, b| {
        b.dst
            .prefix_len
            .cmp(&a.dst.prefix_len)
            .then(a.metric.cmp(&b.metric))
    });
}

/// Delete the first route whose (dst, iface, table) matches.
pub fn route_delete(dst: Ipv4Net, iface_name: &str, table: u8) {
    route_delete_in(0, dst, iface_name, table);
}

pub fn route_delete_in(net_ns_id: u64, dst: Ipv4Net, iface_name: &str, table: u8) {
    let mut g = ROUTE_TABLE.lock();
    if let Some(pos) = g.iter().position(|r| {
        r.net_ns_id == net_ns_id && r.dst == dst && r.iface == iface_name && r.table == table
    }) {
        g.remove(pos);
    }
}

/// Snapshot of all routes (cheapest debug / test tool).
pub fn route_list() -> Vec<Route> {
    route_list_in(0)
}

pub fn route_list_in(net_ns_id: u64) -> Vec<Route> {
    ROUTE_TABLE
        .lock()
        .iter()
        .filter(|route| route.net_ns_id == net_ns_id)
        .cloned()
        .collect()
}

/// Re-home every route whose egress device is being moved to another network
/// namespace. Called in the same interface-admin transaction as ownership.
pub(crate) fn move_iface_routes(iface_name: &str, net_ns_id: u64) {
    let mut routes = ROUTE_TABLE.lock();
    for route in routes.iter_mut().filter(|route| route.iface == iface_name) {
        route.net_ns_id = net_ns_id;
    }
}

/// Snapshot of one route in the form `/proc/net/route` expects.
/// Mirrors what Linux's `rt_cache_seq_show` emits per row.
#[derive(Clone, Debug)]
pub struct RouteSnapshot {
    pub iface: String,
    pub dst: [u8; 4],
    pub gateway: [u8; 4],
    /// Linux flag bits: 1=UP, 2=GATEWAY, 4=HOST, 0x10=DYNAMIC, ...
    pub flags: u16,
    pub refcnt: u32,
    pub use_count: u32,
    pub metric: u32,
    pub mask: [u8; 4],
    pub mtu: u32,
    pub window: u32,
    pub irtt: u32,
}

/// Snapshot the routing table in `/proc/net/route` row shape.
pub fn snapshot() -> Vec<RouteSnapshot> {
    snapshot_in(0)
}

pub fn snapshot_in(net_ns_id: u64) -> Vec<RouteSnapshot> {
    let g = ROUTE_TABLE.lock();
    let mut out = Vec::new();
    for r in g.iter().filter(|route| route.net_ns_id == net_ns_id) {
        // RTF_UP is always set; RTF_GATEWAY when a gateway exists.
        let mut flags: u16 = 0x0001;
        if r.gateway.is_some() {
            flags |= 0x0002;
        }
        let gateway = r.gateway.map(|g| g.0).unwrap_or([0u8; 4]);
        let mask = u32::to_be_bytes(prefix_to_mask(r.dst.prefix_len));
        out.push(RouteSnapshot {
            iface: r.iface.clone(),
            dst: r.dst.addr.0,
            gateway,
            flags,
            refcnt: 0,
            use_count: 0,
            metric: r.metric,
            mask,
            mtu: 0,
            window: 0,
            irtt: 0,
        });
    }
    out
}

/// Longest-prefix-match lookup for `dst`.
///
/// Returns the first `Route` (highest prefix_len) whose `dst` network
/// contains `ip`. Falls back to the default route (0.0.0.0/0) if
/// present. Returns `None` only if no route matches at all.
///
/// Ref: Linux `fib_table_lookup()` in `net/ipv4/fib_trie.c` — same
/// semantics, much simpler implementation.
pub fn route_lookup_raw(ip: Ipv4Addr) -> Option<Route> {
    route_lookup_raw_in(0, ip)
}

pub fn route_lookup_raw_in(net_ns_id: u64, ip: Ipv4Addr) -> Option<Route> {
    let g = ROUTE_TABLE.lock();
    g.iter()
        .find(|r| r.net_ns_id == net_ns_id && r.dst.contains(ip))
        .cloned()
}

/// Full lookup: returns a `RouteResult` with the egress iface, nexthop
/// IP, and chosen source address. This is what the send paths call.
///
/// Source-address selection steps (RFC 1122 §3.3.5):
/// 1. `route.src_hint` if set.
/// 2. An address on the egress iface that covers the nexthop / dst.
/// 3. The first address on the egress iface.
pub fn route_lookup(dst: Ipv4Addr) -> Option<RouteResult> {
    route_lookup_in(0, dst)
}

pub fn route_lookup_in(net_ns_id: u64, dst: Ipv4Addr) -> Option<RouteResult> {
    let route = route_lookup_raw_in(net_ns_id, dst)?;
    let nexthop = route.gateway.unwrap_or(dst);
    let src = choose_src(&route, nexthop, dst);
    Some(RouteResult {
        iface: route.iface.clone(),
        nexthop,
        src,
        gateway: route.gateway,
    })
}

/// Source-address selection function — exported so `tcp_stack` and
/// `udp_sock` can call it directly without repeating the lookup.
///
/// Returns `(iface_name, src_ip, gateway_ip)` or `None` if no route
/// and no source address exist.
pub fn src_for(dst: Ipv4Addr) -> Option<(String, Ipv4Addr, Option<Ipv4Addr>)> {
    let r = route_lookup(dst)?;
    Some((r.iface, r.src, r.gateway))
}

// ── Connected-route helpers (called from ifaddr) ────────────────────────

/// Install a connected (link-scope) route for `addr/prefix_len` on
/// `iface_name`. Called by `ifaddr::iface_add_addr`.
/// Ref: Linux `fib_frontend.c:fib_add_ifaddr`.
pub fn install_connected_route(iface_name: &str, addr: Ipv4Addr, prefix_len: u8) {
    let mask = prefix_to_mask(prefix_len);
    let net_addr = Ipv4Addr::from_u32(addr.to_u32() & mask);
    let dst = Ipv4Net {
        addr: net_addr,
        prefix_len,
    };
    route_add(Route {
        net_ns_id: crate::iface::lookup(iface_name).map_or(0, |iface| iface.net_ns_id),
        dst,
        gateway: None, // direct delivery
        iface: String::from(iface_name),
        src_hint: Some(addr),
        metric: 0,
        scope: Scope::Link,
        table: TABLE_MAIN,
    });
}

/// Remove the connected route that was auto-installed for `addr/prefix_len`.
/// Called by `ifaddr::iface_del_addr`.
pub fn remove_connected_route(iface_name: &str, addr: Ipv4Addr, prefix_len: u8) {
    let mask = prefix_to_mask(prefix_len);
    let net_addr = Ipv4Addr::from_u32(addr.to_u32() & mask);
    let dst = Ipv4Net {
        addr: net_addr,
        prefix_len,
    };
    route_delete(dst, iface_name, TABLE_MAIN);
}

/// Install the loopback route (127.0.0.0/8 → "lo"). Must be called at
/// network init after the loopback interface is registered. Idempotent.
pub fn install_loopback_route() {
    route_add(Route {
        net_ns_id: 0,
        dst: Ipv4Net {
            addr: Ipv4Addr([127, 0, 0, 0]),
            prefix_len: 8,
        },
        gateway: None,
        iface: String::from("lo"),
        src_hint: Some(Ipv4Addr([127, 0, 0, 1])),
        metric: 0,
        scope: Scope::Host,
        table: TABLE_LOCAL,
    });
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Pick the best source address for the given route + nexthop. Returns
/// `Ipv4Addr::UNSPECIFIED` as a last resort (caller should treat that as
/// "no address configured on the egress interface").
fn choose_src(route: &Route, nexthop: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Addr {
    // Step 1: explicit hint.
    if let Some(h) = route.src_hint {
        return h;
    }

    let addrs: Vec<IfaceAddr> = iface_addrs(&route.iface);

    // Step 2: find an address on the egress iface that covers the nexthop
    // (or dst if direct delivery). Ref: Linux `inet_select_addr()` in
    // `net/ipv4/fib_semantics.c` line ~1294.
    let probe = if route.gateway.is_some() {
        nexthop
    } else {
        dst
    };
    for ia in &addrs {
        if ia.covers(probe) {
            return ia.addr;
        }
    }

    // Step 3: first address on the interface.
    addrs
        .first()
        .map(|ia| ia.addr)
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

// ── Test helpers ───────────────────────────────────────────────────────

/// Flush the routing table. For unit tests only.
#[doc(hidden)]
pub fn __reset_for_test() {
    ROUTE_TABLE.lock().clear();
}
