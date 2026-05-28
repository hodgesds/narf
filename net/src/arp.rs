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
//! ## Blocking resolver
//!
//! `resolve_blocking(iface, target_ip, timeout_ms)` sends an ARP
//! request via `iface::send` and busy-waits (via
//! `narf_scheduler::responsive_spin_until`) until either a reply lands
//! in the cache or the deadline passes. The RX path in `tcp_stack`
//! calls `arp_insert_from_rx` when it parses an ARP reply, populating
//! this cache as well.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::iface;
use crate::pkt;

// ── Cache entry + ring buffer ───────────────────────────────────────

const ARP_CACHE_SIZE: usize = 16;

/// One entry in the ARP cache.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip:  [u8; 4],
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

/// Called from the RX path when an ARP reply arrives. Populates both
/// this module's LRU cache and the legacy `tcp_stack` BTreeMap.
pub fn arp_insert_from_rx(iface_name: &str, ip: [u8; 4], mac: [u8; 6]) {
    insert(iface_name, ip, mac);
    // Also update the legacy BTreeMap in tcp_stack so existing code
    // that reads from there continues to work.
    crate::tcp_stack::__arp_insert_legacy(ip, mac);
}

// ── Blocking resolver ──────────────────────────────────────────────

/// ARP resolution error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArpError {
    /// No interface with the given name is registered.
    NoIface,
    /// ARP reply not received within the timeout.
    Timeout,
}

/// Resolve `target_ip` to a MAC on `iface_name`. First checks the LRU
/// cache; on a miss, sends an ARP request and busy-waits up to
/// `timeout_ms` milliseconds for a reply to land in the cache (pumped
/// by `iface::drain_pump` on each iteration).
///
/// RFC 826 §2: the sender fills its sender hardware/protocol addresses,
/// sets the target hardware address to zero, and broadcasts on the link.
pub fn resolve_blocking(
    iface_name: &str,
    target_ip: [u8; 4],
    timeout_ms: u64,
) -> Result<[u8; 6], ArpError> {
    // Fast path: cache hit.
    if let Some(mac) = lookup(iface_name, target_ip) {
        return Ok(mac);
    }

    // Build and send an ARP request.
    let snap = iface::lookup(iface_name).ok_or(ArpError::NoIface)?;
    {
        let mut frame = [0u8; 60];
        let n = pkt::build_arp_request(&mut frame, snap.mac, snap.ipv4, target_ip)
            .ok_or(ArpError::NoIface)?;
        let _ = (snap.send)(&frame[..n]);
    }

    // Busy-wait for the reply to land.
    let deadline = narf_time::Deadline::after_ns(timeout_ms.saturating_mul(1_000_000));
    let name = iface_name;
    let mut result = None;
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            if let Some(mac) = lookup(name, target_ip) {
                result = Some(mac);
                return true;
            }
            false
        },
        deadline,
    );
    result.ok_or(ArpError::Timeout)
}

/// Test-only: flush all ARP caches.
#[doc(hidden)]
pub fn __reset_for_test() {
    ARP_CACHES.lock().clear();
}
