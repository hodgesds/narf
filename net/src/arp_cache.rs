//! Per-interface ARP cache with state machine and LRU eviction.
//!
//! ## State machine
//!
//! Entries transition through states modelled after Linux's neighbour
//! state machine (`include/net/neighbour.h` NUD_* flags) and RFC 4861
//! (used for IPv6 but the state names are canonical for IPv4 too):
//!
//! ```text
//! (miss) → Incomplete → Reachable → Stale → Probe → Reachable
//!                                         ↘ (no reply) → Failed
//! ```
//!
//! - **Incomplete**: ARP request has been sent; MAC not yet known.
//! - **Reachable**: MAC is confirmed valid. Expires after
//!   `REACHABLE_TIME_NS` (30 s, matching Linux's
//!   `NEIGH_VAR_BASE_REACHABLE_TIME` at `net/ipv4/arp.c:170`).
//! - **Stale**: reachable timer expired; the entry is still usable but
//!   a new ARP request will be sent before the next use.
//! - **Probe**: a re-validation ARP request is in flight.
//!
//! ## Eviction policy
//!
//! The cache is bounded to `MAX_ENTRIES` (1024 per interface). When a
//! new entry would exceed the bound, the entry with the oldest
//! `last_used_ns` timestamp is evicted (LRU). Ref: Linux
//! `neigh_forced_gc()` in `net/core/neighbour.c` performs a similar GC
//! sweep, evicting NUD_FAILED / NUD_STALE entries first.
//!
//! ## Gratuitous ARP
//!
//! `send_gratuitous_arp(iface_name, addr)` broadcasts an ARP "reply"
//! with sender == target == our own address. Used when an interface
//! comes up to flush stale caches on neighbours. Ref: RFC 5227 §2.4(e);
//! Linux `arp_send_dst()` in `net/ipv4/arp.c`.
//!
//! ## Per-interface separation
//!
//! Each interface has its own `BTreeMap<[u8;4], ArpEntry>`. An IP address
//! seen on iface0 is stored only in iface0's map, so a multi-homed host
//! with the same peer on two segments doesn't conflate their MAC
//! addresses.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::iface;
use crate::pkt;

// ── Constants ──────────────────────────────────────────────────────────

/// Reachable entries expire after 30 s. Matches Linux
/// `NEIGH_VAR_BASE_REACHABLE_TIME` at `net/ipv4/arp.c:170`.
pub const REACHABLE_TIME_NS: u64 = 30_000_000_000;

/// Per-interface cache bound. The 1025th insert evicts the LRU.
/// Linux's ARP table defaults to gc_thresh3 = 1024 entries.
pub const MAX_ENTRIES: usize = 1024;

// ── Entry types ────────────────────────────────────────────────────────

/// ARP entry state. Mirrors Linux `NUD_*` flags (neighbour.h).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArpState {
    /// ARP request sent, reply not yet received.
    Incomplete,
    /// MAC confirmed valid; entry expires at `expires_at`.
    Reachable,
    /// Reachable timer expired; entry will be re-probed on next use.
    Stale,
    /// Re-validation probe in flight.
    Probe,
}

/// One entry in the per-interface ARP cache.
#[derive(Copy, Clone, Debug)]
pub struct ArpEntry {
    pub mac: [u8; 6],
    pub state: ArpState,
    /// Monotonic nanosecond timestamp when the entry becomes Stale
    /// (only meaningful in Reachable state).
    pub expires_at: u64,
    /// Monotonic nanosecond timestamp of last use. Used for LRU eviction.
    pub last_used_ns: u64,
    /// Number of ARP requests outstanding for this entry.
    pub requests_outstanding: u8,
}

// ── Per-interface cache ─────────────────────────────────────────────────

struct IfaceArpCache {
    name: String,
    entries: BTreeMap<[u8; 4], ArpEntry>,
}

static CACHES: IrqSafeSpinLock<Vec<IfaceArpCache>> = IrqSafeSpinLock::new(Vec::new());

// ── Internal helpers ───────────────────────────────────────────────────

fn now_ns() -> u64 {
    narf_time::monotonic_ns()
}

/// Evict the LRU entry from `cache` when it's at capacity.
fn maybe_evict(cache: &mut BTreeMap<[u8; 4], ArpEntry>) {
    if cache.len() < MAX_ENTRIES {
        return;
    }
    // Find the key with the smallest `last_used_ns` (LRU).
    let lru_key = cache
        .iter()
        .min_by_key(|(_, e)| e.last_used_ns)
        .map(|(k, _)| *k);
    if let Some(k) = lru_key {
        cache.remove(&k);
    }
}

fn get_or_create_cache<'g>(
    g: &'g mut Vec<IfaceArpCache>,
    iface_name: &str,
) -> &'g mut BTreeMap<[u8; 4], ArpEntry> {
    if let Some(pos) = g.iter().position(|c| c.name == iface_name) {
        return &mut g[pos].entries;
    }
    g.push(IfaceArpCache {
        name: String::from(iface_name),
        entries: BTreeMap::new(),
    });
    let last = g.len() - 1;
    &mut g[last].entries
}

// ── Public API ─────────────────────────────────────────────────────────

/// Look up `ip` in the named interface's ARP cache.
///
/// - Returns `Some(mac)` if the entry is Reachable or Stale.
/// - Returns `None` for Incomplete / missing entries.
/// - Transitions Stale → Probe (the caller should send a new ARP
///   request after a Stale hit).
///
/// `last_used_ns` is updated on every non-None return.
pub fn lookup(iface_name: &str, ip: [u8; 4]) -> Option<[u8; 6]> {
    let now = now_ns();
    let mut g = CACHES.lock();
    let map = get_or_create_cache(&mut g, iface_name);
    let entry = map.get_mut(&ip)?;

    // Age Reachable → Stale if the timer has fired.
    if entry.state == ArpState::Reachable && now >= entry.expires_at {
        entry.state = ArpState::Stale;
    }

    match entry.state {
        ArpState::Reachable | ArpState::Stale | ArpState::Probe => {
            if entry.state == ArpState::Stale {
                entry.state = ArpState::Probe;
            }
            entry.last_used_ns = now;
            Some(entry.mac)
        }
        ArpState::Incomplete => None,
    }
}

/// Insert or refresh an `(ip, mac)` mapping. On a new entry the state
/// is set to `Reachable` with `expires_at = now + REACHABLE_TIME_NS`.
/// On an existing entry the MAC is updated and the state is reset to
/// `Reachable` (this is what happens when an ARP reply arrives).
///
/// LRU eviction is triggered if the cache is full before insertion.
pub fn insert(iface_name: &str, ip: [u8; 4], mac: [u8; 6]) {
    let now = now_ns();
    let mut g = CACHES.lock();
    let map = get_or_create_cache(&mut g, iface_name);

    if let Some(entry) = map.get_mut(&ip) {
        entry.mac = mac;
        entry.state = ArpState::Reachable;
        entry.expires_at = now + REACHABLE_TIME_NS;
        entry.last_used_ns = now;
        entry.requests_outstanding = 0;
        return;
    }

    maybe_evict(map);
    map.insert(
        ip,
        ArpEntry {
            mac,
            state: ArpState::Reachable,
            expires_at: now + REACHABLE_TIME_NS,
            last_used_ns: now,
            requests_outstanding: 0,
        },
    );
}

/// Mark an entry as Incomplete (ARP request sent, no reply yet).
/// Creates the entry if it doesn't exist. Used by the ARP resolver
/// before sending the request.
pub fn mark_incomplete(iface_name: &str, ip: [u8; 4]) {
    let now = now_ns();
    let mut g = CACHES.lock();
    let map = get_or_create_cache(&mut g, iface_name);
    map.entry(ip).or_insert_with(|| ArpEntry {
        mac: [0u8; 6],
        state: ArpState::Incomplete,
        expires_at: 0,
        last_used_ns: now,
        requests_outstanding: 1,
    });
}

/// Return the state of an entry, or `None` if not in the cache.
pub fn entry_state(iface_name: &str, ip: [u8; 4]) -> Option<ArpState> {
    let now = now_ns();
    let mut g = CACHES.lock();
    if let Some(cache) = g.iter_mut().find(|c| c.name == iface_name) {
        if let Some(entry) = cache.entries.get_mut(&ip) {
            if entry.state == ArpState::Reachable && now >= entry.expires_at {
                entry.state = ArpState::Stale;
            }
            return Some(entry.state);
        }
    }
    None
}

/// Directly read an entry (for tests that inspect state without side-effects).
pub fn get_entry(iface_name: &str, ip: [u8; 4]) -> Option<ArpEntry> {
    let g = CACHES.lock();
    g.iter()
        .find(|c| c.name == iface_name)
        .and_then(|c| c.entries.get(&ip).copied())
}

/// Count of entries in the named interface's cache.
pub fn entry_count(iface_name: &str) -> usize {
    let g = CACHES.lock();
    g.iter()
        .find(|c| c.name == iface_name)
        .map(|c| c.entries.len())
        .unwrap_or(0)
}

/// Send a gratuitous ARP for `addr` on `iface_name`. A GARP is an ARP
/// reply with sender == target == the host's own address. Neighbours
/// that receive it update their caches to the new MAC.
///
/// Called when a NIC comes up (RFC 5227 §2.4(e)).
/// Ref: Linux `arp_send_dst()` in `net/ipv4/arp.c`.
pub fn send_gratuitous_arp(iface_name: &str, addr: [u8; 4]) {
    let snap = match iface::lookup(iface_name) {
        Some(s) => s,
        None => return,
    };
    // A GARP is an ARP request with TPA == SPA (sender answers for itself).
    let mut frame = [0u8; 60];
    if let Some(n) = pkt::build_arp_request(&mut frame, snap.mac, addr, addr) {
        let _ = (snap.send)(&frame[..n]);
    }
}

/// RX path: called when an ARP reply arrives on `iface_name`. Updates the
/// per-interface cache and the legacy `tcp_stack` BTreeMap.
pub fn arp_insert_from_rx(iface_name: &str, ip: [u8; 4], mac: [u8; 6]) {
    insert(iface_name, ip, mac);
    // Keep legacy cache in sync for tcp_stack paths that haven't yet
    // been migrated to arp_cache::lookup.
    crate::tcp_stack::__arp_insert_legacy(ip, mac);
}

/// Test helper: flush all ARP caches.
#[doc(hidden)]
pub fn __reset_for_test() {
    CACHES.lock().clear();
}

/// Snapshot of one ARP cache entry. Used by `/proc/net/arp` to
/// produce the per-row text. Mirrors what Linux's `arp_seq_show`
/// extracts.
#[derive(Clone, Debug)]
pub struct ArpSnapshot {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub iface: String,
    /// Linux flag bits from `arp_seq_show`. 0=Incomplete, 2=Complete,
    /// 4=Permanent, 6=Pub.
    pub flags: u8,
}

/// Snapshot every entry across all per-iface caches.
pub fn snapshot() -> Vec<ArpSnapshot> {
    let g = CACHES.lock();
    let mut out = Vec::new();
    for cache in g.iter() {
        for (ip, e) in cache.entries.iter() {
            let flags = match e.state {
                ArpState::Reachable | ArpState::Stale | ArpState::Probe => 0x02,
                ArpState::Incomplete => 0x00,
            };
            out.push(ArpSnapshot {
                ip: *ip,
                mac: e.mac,
                iface: cache.name.clone(),
                flags,
            });
        }
    }
    out
}

// ── Fake-time test hook ────────────────────────────────────────────────

/// Insert an entry and set its `expires_at` to the given value. Test-only.
#[doc(hidden)]
pub fn __insert_with_expiry(iface_name: &str, ip: [u8; 4], mac: [u8; 6], expires_at: u64) {
    let now = now_ns();
    let mut g = CACHES.lock();
    let map = get_or_create_cache(&mut g, iface_name);
    maybe_evict(map);
    map.insert(
        ip,
        ArpEntry {
            mac,
            state: ArpState::Reachable,
            expires_at,
            last_used_ns: now,
            requests_outstanding: 0,
        },
    );
}
