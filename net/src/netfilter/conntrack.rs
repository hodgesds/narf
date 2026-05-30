//! Connection tracking — flow-tuple hash table + state machine.
//!
//! Models Linux's `nf_conn` from `net/netfilter/nf_conntrack_core.c`.
//! Each tracked flow has:
//!
//! - An *original* tuple (the direction of the first packet seen)
//! - A *reply* tuple (what we expect the response to look like; NAT
//!   may rewrite this so it differs from `invert(original)`)
//! - A state machine — `NEW` until a reply is seen, then `ESTABLISHED`.
//!   TCP tracks a richer state derived from header flags.
//! - An expiry deadline; entries idle past it are evicted.
//!
//! Hash table is bounded at `MAX_ENTRIES` (4096 by default) with LRU
//! eviction. The map is keyed by the tuple in *both* directions
//! (original and reply), so lookup from either side finds the same
//! entry — matches `__nf_conntrack_find()` in
//! `net/netfilter/nf_conntrack_core.c:790`.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::{HookPoint, PktCtx, Tuple, Verdict, parse_tuple_ipv4, L4Proto};

/// Maximum tracked entries. LRU evicts beyond this.
pub const MAX_ENTRIES: usize = 4096;

/// Default expiry deadlines per protocol (nanoseconds).
pub const UDP_DEFAULT_EXPIRY_NS: u64       = 30 * 1_000_000_000;
pub const ICMP_DEFAULT_EXPIRY_NS: u64      = 30 * 1_000_000_000;
pub const TCP_SYN_SENT_EXPIRY_NS: u64      = 120 * 1_000_000_000;
pub const TCP_ESTABLISHED_EXPIRY_NS: u64   = 5 * 60 * 1_000_000_000;
pub const TCP_FIN_WAIT_EXPIRY_NS: u64      = 120 * 1_000_000_000;
pub const TCP_TIME_WAIT_EXPIRY_NS: u64     = 120 * 1_000_000_000;
pub const TCP_CLOSE_EXPIRY_NS: u64         = 10 * 1_000_000_000;

/// Generic conntrack state. Mirrors `enum ip_conntrack_status` bits
/// in Linux `include/uapi/linux/netfilter/nf_conntrack_common.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CtState {
    /// First packet of a flow — no reply yet.
    New,
    /// Both directions seen.
    Established,
    /// Related to an existing connection (e.g. ICMP error).
    Related,
    /// Doesn't fit — bad flags, out-of-window.
    Invalid,
}

/// TCP sub-state — `enum tcp_conntrack` in
/// `net/netfilter/nf_conntrack_proto_tcp.c:24`. Subset that's needed
/// for the NAT path; ignore the SACK/window edge-cases.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpCtState {
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
}

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const TCP_FIN: u8 = 0x01;

/// One tracked flow.
#[derive(Debug)]
pub struct ConntrackEntry {
    pub id: u64,
    /// Tuple in the original direction (the SYN sender's view).
    pub original: Tuple,
    /// Tuple in the reply direction. After NAT this differs from
    /// `original.invert()`.
    pub reply: Tuple,
    /// Coarse state.
    pub state: CtState,
    /// TCP sub-state (only meaningful for TCP flows).
    pub tcp_state: Option<TcpCtState>,
    /// Last-touch timestamp in monotonic ns.
    pub last_seen_ns: u64,
    /// Expiry deadline in monotonic ns. `last_seen_ns + per-state-ns`.
    pub expires_at_ns: u64,
}

impl ConntrackEntry {
    fn new(id: u64, original: Tuple, now_ns: u64) -> Self {
        let proto = L4Proto::from_u8(original.proto);
        let (state, tcp_state, expiry) = match proto {
            L4Proto::Tcp  => (CtState::New, Some(TcpCtState::SynSent), TCP_SYN_SENT_EXPIRY_NS),
            L4Proto::Udp  => (CtState::New, None, UDP_DEFAULT_EXPIRY_NS),
            L4Proto::Icmp => (CtState::New, None, ICMP_DEFAULT_EXPIRY_NS),
            L4Proto::Other(_) => (CtState::New, None, UDP_DEFAULT_EXPIRY_NS),
        };
        Self {
            id,
            original,
            reply: original.invert(),
            state,
            tcp_state,
            last_seen_ns: now_ns,
            expires_at_ns: now_ns + expiry,
        }
    }

    /// Rewrite `reply` after NAT has decided what the masqueraded
    /// reply tuple looks like.
    pub fn set_nat_reply(&mut self, reply: Tuple) {
        self.reply = reply;
    }

    fn refresh_expiry(&mut self, now_ns: u64) {
        self.last_seen_ns = now_ns;
        let exp = match L4Proto::from_u8(self.original.proto) {
            L4Proto::Tcp => match self.tcp_state {
                Some(TcpCtState::SynSent | TcpCtState::SynRecv) => TCP_SYN_SENT_EXPIRY_NS,
                Some(TcpCtState::Established) => TCP_ESTABLISHED_EXPIRY_NS,
                Some(TcpCtState::FinWait | TcpCtState::CloseWait | TcpCtState::LastAck)
                    => TCP_FIN_WAIT_EXPIRY_NS,
                Some(TcpCtState::TimeWait) => TCP_TIME_WAIT_EXPIRY_NS,
                Some(TcpCtState::Close) => TCP_CLOSE_EXPIRY_NS,
                None => TCP_ESTABLISHED_EXPIRY_NS,
            },
            L4Proto::Udp  => UDP_DEFAULT_EXPIRY_NS,
            L4Proto::Icmp => ICMP_DEFAULT_EXPIRY_NS,
            L4Proto::Other(_) => UDP_DEFAULT_EXPIRY_NS,
        };
        self.expires_at_ns = now_ns + exp;
    }
}

/// Connection-tracking table.
#[derive(Debug)]
pub struct Conntrack {
    /// Tuple → Entry id. Both `original` and `reply` tuples are keyed
    /// to the same id so a lookup from either side finds the flow.
    by_tuple: IrqSafeSpinLock<BTreeMap<Tuple, u64>>,
    /// Entry storage.
    by_id: IrqSafeSpinLock<BTreeMap<u64, Arc<IrqSafeSpinLock<ConntrackEntry>>>>,
    /// LRU order — pushed on insert / refresh, popped on eviction.
    /// Approximation: a `Vec<u64>` with newest at tail.
    lru: IrqSafeSpinLock<alloc::vec::Vec<u64>>,
    next_id: AtomicU64,
    /// Hard cap on simultaneous entries.
    max_entries: usize,
}

impl Conntrack {
    pub const fn new(max_entries: usize) -> Self {
        Self {
            by_tuple: IrqSafeSpinLock::new(BTreeMap::new()),
            by_id: IrqSafeSpinLock::new(BTreeMap::new()),
            lru: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
            next_id: AtomicU64::new(1),
            max_entries,
        }
    }

    /// Look up an entry by tuple. Honors both original and reply
    /// directions — matches `__nf_conntrack_find()`.
    pub fn lookup(&self, t: &Tuple) -> Option<Arc<IrqSafeSpinLock<ConntrackEntry>>> {
        let id = *self.by_tuple.lock().get(t)?;
        self.by_id.lock().get(&id).cloned()
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.by_id.lock().len()
    }

    /// Touch LRU (move id to tail).
    fn touch_lru(&self, id: u64) {
        let mut lru = self.lru.lock();
        lru.retain(|&x| x != id);
        lru.push(id);
    }

    /// Evict the LRU entry. Called when `len == max_entries`.
    fn evict_lru(&self) {
        let victim_id = {
            let mut lru = self.lru.lock();
            if lru.is_empty() {
                return;
            }
            lru.remove(0)
        };
        let entry = self.by_id.lock().remove(&victim_id);
        if let Some(e) = entry {
            let g = e.lock();
            let orig = g.original;
            let reply = g.reply;
            drop(g);
            let mut by = self.by_tuple.lock();
            by.remove(&orig);
            by.remove(&reply);
        }
    }

    /// Insert a new flow originating from `original`. Returns the new
    /// entry's Arc. If a same-tuple entry already exists, returns the
    /// existing one (no double-insert).
    pub fn insert_new(
        &self,
        original: Tuple,
        now_ns: u64,
    ) -> Arc<IrqSafeSpinLock<ConntrackEntry>> {
        if let Some(e) = self.lookup(&original) {
            self.touch_lru(e.lock().id);
            return e;
        }
        // LRU eviction if at capacity.
        if self.by_id.lock().len() >= self.max_entries {
            self.evict_lru();
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(IrqSafeSpinLock::new(ConntrackEntry::new(id, original, now_ns)));
        {
            let reply = entry.lock().reply;
            let mut by = self.by_tuple.lock();
            by.insert(original, id);
            by.insert(reply, id);
        }
        self.by_id.lock().insert(id, entry.clone());
        self.touch_lru(id);
        entry
    }

    /// Update the per-tuple index after NAT changes the reply tuple.
    /// Removes the old reply key and inserts the new one.
    pub fn update_reply_tuple(
        &self,
        id: u64,
        old_reply: Tuple,
        new_reply: Tuple,
    ) {
        let mut by = self.by_tuple.lock();
        by.remove(&old_reply);
        by.insert(new_reply, id);
    }

    /// Walk every entry's expiry and evict the stale ones. Returns
    /// the number of entries removed.
    pub fn reap_expired(&self, now_ns: u64) -> usize {
        let stale_ids: alloc::vec::Vec<u64> = {
            let by = self.by_id.lock();
            by.iter()
                .filter_map(|(id, e)| {
                    let g = e.lock();
                    if g.expires_at_ns <= now_ns {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect()
        };
        let n = stale_ids.len();
        for id in stale_ids {
            let entry = self.by_id.lock().remove(&id);
            if let Some(e) = entry {
                let g = e.lock();
                let orig = g.original;
                let reply = g.reply;
                drop(g);
                let mut by = self.by_tuple.lock();
                by.remove(&orig);
                by.remove(&reply);
                drop(by);
                let mut lru = self.lru.lock();
                lru.retain(|&x| x != id);
            }
        }
        n
    }

    /// Reset the table — wipe entries, LRU, and id counter.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.by_tuple.lock().clear();
        self.by_id.lock().clear();
        self.lru.lock().clear();
        self.next_id.store(1, Ordering::Relaxed);
    }
}

/// Single global conntrack table.
static CT: Conntrack = Conntrack::new(MAX_ENTRIES);

/// Reference the global conntrack table.
#[inline]
pub fn ct() -> &'static Conntrack {
    &CT
}

/// Reset the global table — test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    CT.__reset_for_test();
}

/// Snapshot of one conntrack entry for `/proc/net/nf_conntrack`.
/// Linux's `ct_seq_show` emits one line per entry; we copy minimal
/// data out of the locked entry so the render loop doesn't hold
/// the global table lock.
#[derive(Clone, Debug)]
pub struct ConntrackSnapshot {
    pub l3proto: &'static str,
    pub l3proto_num: u8,
    pub l4proto: &'static str,
    pub l4proto_num: u8,
    pub timeout: u32,
    pub state: &'static str,
    pub orig_src: [u8; 4],
    pub orig_dst: [u8; 4],
    pub orig_sport: u16,
    pub orig_dport: u16,
    pub reply_src: [u8; 4],
    pub reply_dst: [u8; 4],
    pub reply_sport: u16,
    pub reply_dport: u16,
    pub assured: bool,
    pub use_count: u32,
}

/// Snapshot every tracked flow for `/proc/net/nf_conntrack`.
pub fn snapshot() -> alloc::vec::Vec<ConntrackSnapshot> {
    let by_id = CT.by_id.lock();
    let mut out = alloc::vec::Vec::with_capacity(by_id.len());
    let now = narf_scheduler::narf_time::monotonic_ns();
    for entry in by_id.values() {
        let e = entry.lock();
        let l4_num = e.original.proto;
        let l4_name = match super::L4Proto::from_u8(l4_num) {
            super::L4Proto::Tcp => "tcp",
            super::L4Proto::Udp => "udp",
            super::L4Proto::Icmp => "icmp",
            super::L4Proto::Other(_) => "other",
        };
        let state_str = match (l4_name, e.state, e.tcp_state) {
            ("tcp", _, Some(TcpCtState::SynSent)) => "SYN_SENT",
            ("tcp", _, Some(TcpCtState::SynRecv)) => "SYN_RECV",
            ("tcp", _, Some(TcpCtState::Established)) => "ESTABLISHED",
            ("tcp", _, Some(TcpCtState::FinWait)) => "FIN_WAIT",
            ("tcp", _, Some(TcpCtState::CloseWait)) => "CLOSE_WAIT",
            ("tcp", _, Some(TcpCtState::LastAck)) => "LAST_ACK",
            ("tcp", _, Some(TcpCtState::TimeWait)) => "TIME_WAIT",
            ("tcp", _, Some(TcpCtState::Close)) => "CLOSE",
            (_, CtState::Established, _) => "ESTABLISHED",
            (_, CtState::New, _) => "NEW",
            (_, CtState::Related, _) => "RELATED",
            (_, CtState::Invalid, _) => "INVALID",
        };
        let timeout = (e.expires_at_ns.saturating_sub(now) / 1_000_000_000) as u32;
        out.push(ConntrackSnapshot {
            l3proto: "ipv4",
            l3proto_num: 2,
            l4proto: l4_name,
            l4proto_num: l4_num,
            timeout,
            state: state_str,
            orig_src: e.original.src_ip,
            orig_dst: e.original.dst_ip,
            orig_sport: e.original.src_port,
            orig_dport: e.original.dst_port,
            reply_src: e.reply.src_ip,
            reply_dst: e.reply.dst_ip,
            reply_sport: e.reply.src_port,
            reply_dport: e.reply.dst_port,
            assured: e.state == CtState::Established,
            use_count: 1,
        });
    }
    out
}

/// Advance a TCP entry's sub-state based on inbound flags + direction.
/// `is_reply` is true when the packet matches the reply tuple (or
/// equivalently, originated from the responder).
pub fn tcp_advance(
    entry: &Arc<IrqSafeSpinLock<ConntrackEntry>>,
    flags: u8,
    is_reply: bool,
    now_ns: u64,
) {
    let mut e = entry.lock();
    let cur = e.tcp_state.unwrap_or(TcpCtState::SynSent);
    let new = next_tcp_state(cur, flags, is_reply);
    e.tcp_state = Some(new);
    e.state = match new {
        TcpCtState::Established => CtState::Established,
        TcpCtState::SynSent | TcpCtState::SynRecv => CtState::New,
        TcpCtState::FinWait | TcpCtState::CloseWait
        | TcpCtState::LastAck | TcpCtState::TimeWait
        | TcpCtState::Close => CtState::Established, // still tracked while closing
    };
    e.refresh_expiry(now_ns);
}

/// Tiny TCP state machine. Subset that handles SYN_SENT → ESTABLISHED
/// → FIN-driven teardown. Models the `tcp_conntracks` lookup table in
/// Linux `net/netfilter/nf_conntrack_proto_tcp.c:134`.
fn next_tcp_state(cur: TcpCtState, flags: u8, is_reply: bool) -> TcpCtState {
    let syn = flags & TCP_SYN != 0;
    let ack = flags & TCP_ACK != 0;
    let fin = flags & TCP_FIN != 0;
    let rst = flags & TCP_RST != 0;
    if rst {
        return TcpCtState::Close;
    }
    match cur {
        TcpCtState::SynSent => {
            if is_reply && syn && ack {
                TcpCtState::SynRecv
            } else if syn {
                TcpCtState::SynSent
            } else {
                cur
            }
        }
        TcpCtState::SynRecv => {
            // After SYN+ACK, the originator's ACK promotes to ESTABLISHED.
            if !is_reply && ack && !syn {
                TcpCtState::Established
            } else {
                cur
            }
        }
        TcpCtState::Established => {
            if fin {
                TcpCtState::FinWait
            } else {
                cur
            }
        }
        TcpCtState::FinWait => {
            if fin {
                TcpCtState::TimeWait
            } else {
                cur
            }
        }
        TcpCtState::TimeWait | TcpCtState::CloseWait
        | TcpCtState::LastAck | TcpCtState::Close => cur,
    }
}

/// Apply the conntrack hook at PRE_ROUTING (and again at LOCAL_OUT) —
/// looks the packet up by tuple, creates the entry if missing,
/// advances TCP state, refreshes UDP/ICMP expiry, and tags
/// `ctx.conntrack_id` for downstream hooks.
pub fn conntrack_hook(ctx: &mut PktCtx<'_>) -> Verdict {
    let tuple = match parse_tuple_ipv4(ctx.packet) {
        Some(t) => t,
        None => return Verdict::Accept,
    };
    let now = narf_scheduler::narf_time::monotonic_ns();
    let entry = CT.lookup(&tuple).unwrap_or_else(|| CT.insert_new(tuple, now));
    let id = entry.lock().id;
    ctx.conntrack_id = Some(id);
    CT.touch_lru(id);

    // Direction: matches original if `tuple == entry.original`.
    let original = entry.lock().original;
    let is_reply = tuple != original;

    // Update state.
    match L4Proto::from_u8(tuple.proto) {
        L4Proto::Tcp => {
            // TCP flags live at IPv4 + 13.
            let flags_off = super::IPV4_MIN_HDR_LEN + 13;
            if ctx.packet.len() > flags_off {
                let flags = ctx.packet[flags_off];
                tcp_advance(&entry, flags, is_reply, now);
            }
        }
        L4Proto::Udp => {
            let mut e = entry.lock();
            if is_reply && e.state == CtState::New {
                e.state = CtState::Established;
            }
            e.refresh_expiry(now);
        }
        L4Proto::Icmp => {
            let mut e = entry.lock();
            if is_reply && e.state == CtState::New {
                e.state = CtState::Established;
            }
            e.refresh_expiry(now);
        }
        L4Proto::Other(_) => {
            let mut e = entry.lock();
            e.refresh_expiry(now);
        }
    }
    Verdict::Accept
}

/// Register the conntrack hooks at PRE_ROUTING and LOCAL_OUT with
/// priority -200 (matches `NF_IP_PRI_CONNTRACK` in Linux
/// `include/uapi/linux/netfilter_ipv4.h:51`).
pub fn register_default_hooks() {
    super::nf_register_hook(HookPoint::PreRouting, -200, conntrack_hook);
    super::nf_register_hook(HookPoint::LocalOut,   -200, conntrack_hook);
}
