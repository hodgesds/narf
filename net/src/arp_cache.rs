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

/// Retransmit interval for an unanswered request —
/// `NEIGH_VAR_RETRANS_TIME` = 1 s (`net/ipv4/arp.c:169`).
pub const RETRANS_TIME_NS: u64 = 1_000_000_000;

// Probe budget, from the same table. `neigh_max_probes`
// (`net/core/neighbour.c:1055`) is
//
//     UCAST_PROBES + APP_PROBES +
//     (nud_state & NUD_PROBE ? MCAST_REPROBES : MCAST_PROBES)
//
// and `arp_tbl` sets UCAST = MCAST = 3 while leaving APP_PROBES and
// MCAST_REPROBES unset (0). So a fresh resolution gets 6 attempts and a
// re-probe of an entry we already knew gets 3 — fewer, because a host that
// answered once and has now gone quiet is not worth the same effort.
const UCAST_PROBES: u8 = 3;
const APP_PROBES: u8 = 0;
const MCAST_PROBES: u8 = 3;
const MCAST_REPROBES: u8 = 0;

/// `neigh_max_probes()` for an entry in `state`.
fn max_probes(state: ArpState) -> u8 {
    UCAST_PROBES
        + APP_PROBES
        + if state == ArpState::Probe {
            MCAST_REPROBES
        } else {
            MCAST_PROBES
        }
}

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
    /// Resolution gave up: the probe budget was exhausted with no reply.
    ///
    /// Linux `NUD_FAILED`, set by `neigh_timer_handler`
    /// (`net/core/neighbour.c:1172`) once `probes >= neigh_max_probes()`.
    /// It is a NEGATIVE cache entry and that is the point: without it every
    /// send to an unreachable address restarts a full probe cycle, so a
    /// host that is simply switched off costs a burst of broadcast traffic
    /// per packet rather than per minute.
    Failed,
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
    /// Probes sent for the resolution currently in flight — Linux
    /// `neigh->probes`. Compared against [`max_probes`] to decide when to
    /// give up. Reset to 0 whenever a reply confirms the entry.
    pub requests_outstanding: u8,
    /// Monotonic deadline for the next retransmit while Incomplete or
    /// Probe. Linux arms a per-entry timer for this; NARF's resolver polls
    /// it, so the deadline is stored rather than scheduled.
    pub retrans_at: u64,
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
    // `neigh_forced_gc` reaps the entries that are worth least first, and
    // ordering matters under pressure: a Failed entry holds no usable
    // address, and a Stale one can be re-resolved, while evicting a
    // Reachable entry throws away a working translation. Ranking by state
    // and only then by LRU is what the module doc has always claimed this
    // does; it used to be pure LRU, so a burst of failures could evict live
    // entries and leave the dead ones resident.
    fn rank(e: &ArpEntry) -> u8 {
        match e.state {
            ArpState::Failed => 0,
            ArpState::Stale => 1,
            ArpState::Incomplete => 2,
            ArpState::Probe => 3,
            ArpState::Reachable => 4,
        }
    }
    let victim = cache
        .iter()
        .min_by_key(|(_, e)| (rank(e), e.last_used_ns))
        .map(|(k, _)| *k);
    if let Some(k) = victim {
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
        // Incomplete has no MAC yet; Failed has one only in the sense that
        // resolution gave up, and handing it out would defeat the negative
        // cache.
        ArpState::Incomplete | ArpState::Failed => None,
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
        // A reply ends the resolution: probes reset and the retransmit
        // deadline is disarmed, exactly as `neigh_update` clears
        // `neigh->probes` on confirmation.
        entry.requests_outstanding = 0;
        entry.retrans_at = 0;
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
            retrans_at: 0,
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
    if let Some(entry) = map.get_mut(&ip) {
        // An existing entry starts a FRESH resolution. This used to be an
        // `or_insert_with`, which silently did nothing for an entry that
        // already existed — so the probe counter stuck at 1 and the
        // retransmit deadline was never armed.
        //
        // A Stale/Reachable entry being re-probed keeps its MAC and becomes
        // Probe (Linux `neigh_event_send` -> NUD_PROBE); anything else
        // restarts as Incomplete.
        entry.state = match entry.state {
            ArpState::Reachable | ArpState::Stale | ArpState::Probe => ArpState::Probe,
            _ => ArpState::Incomplete,
        };
        entry.requests_outstanding = 1;
        entry.retrans_at = now + RETRANS_TIME_NS;
        entry.last_used_ns = now;
        return;
    }
    maybe_evict(map);
    map.insert(
        ip,
        ArpEntry {
            mac: [0u8; 6],
            state: ArpState::Incomplete,
            expires_at: 0,
            last_used_ns: now,
            requests_outstanding: 1,
            retrans_at: now + RETRANS_TIME_NS,
        },
    );
}

/// What the resolver should do next for an in-flight resolution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The retransmit timer has not fired; keep waiting.
    Wait,
    /// Send another request for this address.
    Retransmit,
    /// The probe budget is exhausted; the entry is now `Failed`.
    GaveUp,
}

/// Advance an in-flight resolution's retransmit timer.
///
/// This is `neigh_timer_handler`'s NUD_INCOMPLETE/NUD_PROBE arm
/// (`net/core/neighbour.c:1160-1177`):
///
/// ```c
/// /* NUD_PROBE|NUD_INCOMPLETE */
/// next = now + max(NEIGH_VAR(neigh->parms, RETRANS_TIME), HZ/100);
/// ...
/// if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
///     atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
///         WRITE_ONCE(neigh->nud_state, NUD_FAILED);
///         neigh_invalidate(neigh);
/// }
/// ```
///
/// Linux arms a real timer per entry; NARF's resolver polls, so the
/// deadline lives on the entry and this is called as it spins. The budget
/// is checked BEFORE sending, so `max_probes` requests go out in total
/// rather than one more than that.
pub fn poll_resolution(iface_name: &str, ip: [u8; 4]) -> ResolutionStep {
    let now = now_ns();
    let mut g = CACHES.lock();
    let map = get_or_create_cache(&mut g, iface_name);
    let Some(entry) = map.get_mut(&ip) else {
        return ResolutionStep::Wait;
    };
    if !matches!(entry.state, ArpState::Incomplete | ArpState::Probe) {
        return ResolutionStep::Wait;
    }
    if now < entry.retrans_at {
        return ResolutionStep::Wait;
    }
    if entry.requests_outstanding >= max_probes(entry.state) {
        entry.state = ArpState::Failed;
        // `neigh_invalidate` drops the hardware address: a Failed entry
        // must not keep a MAC that a later lookup could hand out.
        entry.mac = [0u8; 6];
        entry.retrans_at = 0;
        return ResolutionStep::GaveUp;
    }
    entry.requests_outstanding = entry.requests_outstanding.saturating_add(1);
    entry.retrans_at = now + RETRANS_TIME_NS;
    ResolutionStep::Retransmit
}

/// Whether resolution for `ip` has already been given up on.
///
/// The resolver checks this before starting: re-probing an address we just
/// exhausted the budget on is what the negative cache exists to prevent.
/// The entry stays Failed until it is evicted or a gratuitous ARP/reply
/// for it arrives, which `insert` handles by resetting the state.
pub fn resolution_failed(iface_name: &str, ip: [u8; 4]) -> bool {
    let g = CACHES.lock();
    g.iter()
        .find(|c| c.name == iface_name)
        .and_then(|c| c.entries.get(&ip))
        .map(|e| e.state == ArpState::Failed)
        .unwrap_or(false)
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

/// Test helper: make the retransmit timer fire immediately, so a test can
/// walk the probe budget without waiting `RETRANS_TIME_NS` per step.
#[doc(hidden)]
pub fn __force_retrans_due(iface_name: &str, ip: [u8; 4]) {
    let mut g = CACHES.lock();
    if let Some(cache) = g.iter_mut().find(|c| c.name == iface_name) {
        if let Some(entry) = cache.entries.get_mut(&ip) {
            entry.retrans_at = 0;
        }
    }
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
    snapshot_in(0)
}

pub fn snapshot_in(net_ns_id: u64) -> Vec<ArpSnapshot> {
    let interface_names: Vec<String> = crate::iface::snapshot_all_in(net_ns_id)
        .into_iter()
        .map(|interface| interface.name)
        .collect();
    let g = CACHES.lock();
    let mut out = Vec::new();
    for cache in g
        .iter()
        .filter(|cache| interface_names.iter().any(|name| name == &cache.name))
    {
        for (ip, e) in cache.entries.iter() {
            // `ATF_COM` (0x02) means the hardware address is known.
            // `arp_seq_show` derives it from the entry being complete, so
            // Failed reports 0 alongside Incomplete: giving up on a
            // resolution does not produce a usable MAC.
            let flags = match e.state {
                ArpState::Reachable | ArpState::Stale | ArpState::Probe => 0x02,
                ArpState::Incomplete | ArpState::Failed => 0x00,
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
            retrans_at: 0,
        },
    );
}

// ── Tests ──────────────────────────────────────────────────────────────

/// An unanswered resolution retransmits on a budget and then FAILS.
///
/// `neigh_timer_handler` (`net/core/neighbour.c:1165`) gives up once
/// `probes >= neigh_max_probes()`, which for a fresh ARP resolution is
/// UCAST(3) + APP(0) + MCAST(3) = 6. Before this, `requests_outstanding`
/// was only ever reset to zero — never incremented, never read — so an
/// entry that got no reply sat Incomplete forever and the `→ Failed`
/// transition this module's own diagram documents did not exist.
fn smoke_arp_incomplete_exhausts_probe_budget() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    const IFACE: &str = "arptest0";
    const IP: [u8; 4] = [10, 9, 9, 1];
    __reset_for_test();

    mark_incomplete(IFACE, IP);
    match entry_state(IFACE, IP) {
        Some(ArpState::Incomplete) => {}
        _ => return TestResult::Fail("mark_incomplete did not create an Incomplete entry"),
    }
    // Before the timer fires there is nothing to do.
    if poll_resolution(IFACE, IP) != ResolutionStep::Wait {
        return TestResult::Fail("a resolution must not retransmit before RETRANS_TIME");
    }

    // The first probe was the request that created the entry, so five more
    // retransmits are allowed before the budget of six is spent.
    for i in 0..5 {
        __force_retrans_due(IFACE, IP);
        if poll_resolution(IFACE, IP) != ResolutionStep::Retransmit {
            let _ = i;
            return TestResult::Fail("resolution gave up before the probe budget was spent");
        }
    }
    __force_retrans_due(IFACE, IP);
    if poll_resolution(IFACE, IP) != ResolutionStep::GaveUp {
        return TestResult::Fail("resolution did not fail once the probe budget was spent");
    }
    if entry_state(IFACE, IP) != Some(ArpState::Failed) {
        return TestResult::Fail("an exhausted resolution must leave the entry Failed");
    }
    // A Failed entry is a negative cache: no MAC, and it says so.
    if lookup(IFACE, IP).is_some() {
        return TestResult::Fail("a Failed entry must not hand out a MAC");
    }
    if !resolution_failed(IFACE, IP) {
        return TestResult::Fail("resolution_failed must report the give-up");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("net/arp", smoke_arp_incomplete_exhausts_probe_budget);

/// Re-probing a known entry gets a SMALLER budget than a fresh resolution.
///
/// `neigh_max_probes` uses MCAST_REPROBES for NUD_PROBE and MCAST_PROBES
/// otherwise, and `arp_tbl` leaves MCAST_REPROBES unset (0) while setting
/// MCAST_PROBES to 3. So a fresh resolution gets 6 attempts and a re-probe
/// of an address that already answered once gets 3.
fn smoke_arp_probe_budget_smaller_than_incomplete() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    const IFACE: &str = "arptest1";
    const IP: [u8; 4] = [10, 9, 9, 2];
    __reset_for_test();

    // A known entry re-probed becomes Probe, keeping its MAC.
    insert(IFACE, IP, [1, 2, 3, 4, 5, 6]);
    mark_incomplete(IFACE, IP);
    if entry_state(IFACE, IP) != Some(ArpState::Probe) {
        return TestResult::Fail("re-probing a known entry must enter Probe, not Incomplete");
    }
    // Budget 3: two more retransmits after the initial request.
    for _ in 0..2 {
        __force_retrans_due(IFACE, IP);
        if poll_resolution(IFACE, IP) != ResolutionStep::Retransmit {
            return TestResult::Fail("Probe gave up before its 3-probe budget was spent");
        }
    }
    __force_retrans_due(IFACE, IP);
    if poll_resolution(IFACE, IP) != ResolutionStep::GaveUp {
        return TestResult::Fail("Probe must give up after 3 probes, not 6");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("net/arp", smoke_arp_probe_budget_smaller_than_incomplete);

/// A reply revives a Failed entry.
///
/// `neigh_update` clears the probe state on confirmation, so a host that
/// was merely switched off is not condemned permanently — the negative
/// cache has to be undone by the first reply that arrives, or the entry
/// would outlive the outage.
///
/// (The eviction ordering `maybe_evict` now applies is asserted by
/// inspection rather than here: filling 1024 entries to observe it is a
/// poor trade for what it proves.)
fn smoke_arp_failed_entry_revives_on_reply() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    const IFACE: &str = "arptest2";
    const DEAD: [u8; 4] = [10, 9, 9, 3];
    __reset_for_test();

    // Drive one address to Failed.
    mark_incomplete(IFACE, DEAD);
    for _ in 0..6 {
        __force_retrans_due(IFACE, DEAD);
        poll_resolution(IFACE, DEAD);
    }
    if entry_state(IFACE, DEAD) != Some(ArpState::Failed) {
        return TestResult::Fail("setup: entry should be Failed");
    }
    // A reply arriving later revives it — a host that was switched off is
    // not condemned permanently.
    insert(IFACE, DEAD, [9, 9, 9, 9, 9, 9]);
    if entry_state(IFACE, DEAD) != Some(ArpState::Reachable) {
        return TestResult::Fail("an ARP reply must revive a Failed entry");
    }
    if lookup(IFACE, DEAD) != Some([9, 9, 9, 9, 9, 9]) {
        return TestResult::Fail("a revived entry must resolve again");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("net/arp", smoke_arp_failed_entry_revives_on_reply);
