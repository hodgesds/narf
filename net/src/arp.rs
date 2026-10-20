//! ARP cache and packet helpers — clean-room.
//!
//! References (public-only):
//! - RFC 826 — An Ethernet Address Resolution Protocol
//!   (D. Plummer, Nov 1982). §2 definitions, packet format.
//!   <https://datatracker.ietf.org/doc/html/rfc826>
//! - RFC 1122 — Requirements for Internet Hosts — Communication Layers
//!   (Braden, Oct 1989). §2.3.2.1 (ARP cache timeout); §2.3.2.2
//!   (must send ARP request for each cache miss).
//!   <https://datatracker.ietf.org/doc/html/rfc1122>
//!
//! ## ARP cache design
//!
//! A fixed 16-entry per-interface LRU cache. Each `ArpCache` is stored
//! in the global `ARP_CACHES` table keyed by interface name. On every
//! successful lookup the entry is promoted to MRU (head of a logical
//! list). Eviction always removes the LRU entry (tail).
//!
//! The cache is intentionally separate from `tcp_stack::ARP_CACHE` (a
//! BTreeMap with no bound). The TCP stack's cache is the Stage-1 artefact
//! wired before this module existed; it continues to work. This module
//! adds the new LRU cache required by the spec.
//!
//! ## Resolution
//!
//! Nothing here waits for a reply: senders queue on the neighbour through
//! `tcp_stack::neigh_output_in` (Linux `neigh_output`). The RX path in
//! `tcp_stack` calls `arp_insert_from_rx` when it parses an ARP reply,
//! populating this cache as well.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

// ── Cache entry + ring buffer ───────────────────────────────────────

const ARP_CACHE_SIZE: usize = 16;

/// One entry in the ARP cache.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

/// 16-entry LRU ARP cache for a single interface. Entries are stored in
/// a fixed-size ring; `head` is the index of the most-recently-used
/// slot. On promotion we copy the newly-found MAC into `entries[head]`
/// and bump `head`.
#[derive(Debug)]
pub struct ArpCache {
    entries: [Option<ArpEntry>; ARP_CACHE_SIZE],
    /// Next write position (wraps mod `ARP_CACHE_SIZE`).
    head: usize,
    /// Number of valid entries (saturates at `ARP_CACHE_SIZE`).
    count: usize,
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpCache {
    pub const fn new() -> Self {
        Self {
            entries: [None; ARP_CACHE_SIZE],
            head: 0,
            count: 0,
        }
    }

    /// Probe the cache. On a hit the entry is promoted to MRU by
    /// swapping it with `entries[head-1]` (most-recently-written
    /// slot). Returns `None` on a miss.
    pub fn lookup(&mut self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for i in 0..ARP_CACHE_SIZE {
            if let Some(e) = self.entries[i] {
                if e.ip == ip {
                    // Promote: swap with the last-written slot.
                    let mru = if self.head == 0 {
                        ARP_CACHE_SIZE - 1
                    } else {
                        self.head - 1
                    };
                    if i != mru {
                        self.entries.swap(i, mru);
                    }
                    return Some(e.mac);
                }
            }
        }
        None
    }

    /// Insert or refresh an `(ip, mac)` mapping. If `ip` is already
    /// present the MAC is updated in-place and the entry is promoted.
    /// If the cache is full the LRU slot (`head`) is evicted.
    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        // Refresh existing entry.
        for i in 0..ARP_CACHE_SIZE {
            if let Some(ref mut e) = self.entries[i] {
                if e.ip == ip {
                    e.mac = mac;
                    // Promote.
                    let mru = if self.head == 0 {
                        ARP_CACHE_SIZE - 1
                    } else {
                        self.head - 1
                    };
                    if i != mru {
                        self.entries.swap(i, mru);
                    }
                    return;
                }
            }
        }
        // New entry: write at `head`, advance.
        self.entries[self.head] = Some(ArpEntry { ip, mac });
        self.head = (self.head + 1) % ARP_CACHE_SIZE;
        if self.count < ARP_CACHE_SIZE {
            self.count += 1;
        }
    }

    /// Number of valid entries currently in the cache.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── Global per-interface table ──────────────────────────────────────

struct IfaceArp {
    name: String,
    cache: ArpCache,
}

impl fmt::Debug for IfaceArp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IfaceArp")
            .field("name", &self.name)
            .field("count", &self.cache.count)
            .finish()
    }
}

static ARP_CACHES: IrqSafeSpinLock<Vec<IfaceArp>> = IrqSafeSpinLock::new(Vec::new());

/// Look up an IP → MAC mapping in the named interface's ARP cache.
pub fn lookup(iface_name: &str, ip: [u8; 4]) -> Option<[u8; 6]> {
    let mut g = ARP_CACHES.lock();
    if let Some(entry) = g.iter_mut().find(|e| e.name == iface_name) {
        return entry.cache.lookup(ip);
    }
    None
}

/// Insert or refresh a mapping in the named interface's ARP cache.
/// Creates the per-interface entry if it doesn't exist yet.
pub fn insert(iface_name: &str, ip: [u8; 4], mac: [u8; 6]) {
    let mut g = ARP_CACHES.lock();
    if let Some(entry) = g.iter_mut().find(|e| e.name == iface_name) {
        entry.cache.insert(ip, mac);
        return;
    }
    let mut cache = ArpCache::new();
    cache.insert(ip, mac);
    g.push(IfaceArp {
        name: String::from(iface_name),
        cache,
    });
}

/// Snapshot every live IPv4 neighbor entry with its owning interface.
/// Cloning keeps rtnetlink serialization outside the cache lock.
pub fn snapshot() -> Vec<(String, ArpEntry)> {
    let g = ARP_CACHES.lock();
    let mut out = Vec::new();
    for iface in g.iter() {
        for entry in iface.cache.entries.iter().flatten() {
            out.push((iface.name.clone(), *entry));
        }
    }
    out
}

/// Remove one IPv4 neighbor entry from a named interface.
pub fn remove(iface_name: &str, ip: [u8; 4]) -> bool {
    let mut g = ARP_CACHES.lock();
    let Some(iface) = g.iter_mut().find(|iface| iface.name == iface_name) else {
        return false;
    };
    let before = iface.cache.count;
    for slot in &mut iface.cache.entries {
        if slot.is_some_and(|entry| entry.ip == ip) {
            *slot = None;
        }
    }
    iface.cache.count = iface.cache.entries.iter().flatten().count();
    iface.cache.count != before
}

/// Called from the RX path when an ARP reply arrives. Populates both
/// this module's LRU cache and the legacy `tcp_stack` BTreeMap.
pub fn arp_insert_from_rx(iface_name: &str, ip: [u8; 4], mac: [u8; 6]) {
    insert(iface_name, ip, mac);
    // Also update the legacy BTreeMap in tcp_stack so existing code
    // that reads from there continues to work.
    crate::tcp_stack::__arp_insert_legacy(ip, mac);
}

/// Test-only: flush all ARP caches.
#[doc(hidden)]
pub fn __reset_for_test() {
    ARP_CACHES.lock().clear();
}
