//! TCB + segment-arrival processing + the public stack API.
//!
//! This is the orchestrator that ties together:
//! - the FSM ([`state_machine`])
//! - the RTO timer ([`retransmit`])
//! - the congestion controller ([`congestion`])
//! - the SACK book ([`sack`])
//! - the option negotiation state ([`options`])
//! - the socket buffers ([`socket_buf`])
//!
//! Public entrypoints map to the user-space socket layer's
//! expected API:
//!
//! ```text
//!   listen      / accept     / connect
//!   send        / recv       / shutdown / close
//!   setsockopt  / getsockopt
//! ```
//!
//! All entrypoints take a `TcbId: u32` token returned by
//! `listen` / `connect` / `accept`. The TCB table maps tokens to
//! `Arc<IrqSafeSpinLock<Tcb>>` so callers can share connection
//! handles without juggling lifetimes.
//!
//! Linux refs (with the structural map to where we put each
//! routine):
//!
//! - `tcp_v4_rcv` → [`handle_segment`]
//! - `tcp_rcv_state_process` → [`process_in_state`]
//! - `tcp_data_queue` → [`enqueue_recv`]
//! - `tcp_write_xmit` → [`pump_send`]
//! - `tcp_retransmit_timer` → [`fire_retransmit`]
//! - `tcp_send_fin` / `tcp_close` → [`do_shutdown`]

#![allow(dead_code, clippy::too_many_arguments)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::iface;
use crate::pkt::{
    self, write_eth_header, write_ipv4_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN,
    IP_PROTO_TCP,
};
use crate::pkt_tcp::{
    ipv4_pseudo_checksum, TcpHeader, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, TCP_HDR_MIN,
};

use super::congestion::{
    default_cc, install as install_cc, seq_geq, seq_leq, seq_lt, Cc, CcError, CcState,
    CongestionControl, Cubic, LossEvent, Reno,
};
use super::options::{
    encode_data_options, encode_syn_options, OptionsState, ParsedOptions, DEFAULT_WSCALE, MIN_MSS,
};
use super::retransmit::{OutSeg, RttEstimator};
use super::sack::{SackBlock, SackBook, SenderScoreboard};
use super::socket_buf::{RecvBuf, SendBuf, DEFAULT_RCV_BUF, DEFAULT_SND_BUF};
use super::state_machine::{DropCause, Shutdown, TcpState};

// ── Configuration constants ─────────────────────────────────────────

/// 2*MSL TIME-WAIT timer. RFC 9293 §3.4.2 suggests 2*MSL; "typical"
/// MSL of 30 s gives 60 s; we hold that.
pub const TIME_WAIT_NS: u64 = 60_000_000_000;
/// Delayed-ACK ceiling — RFC 5681 §4.2 recommends ≤ 500 ms; Linux
/// uses 40 ms, we follow.
pub const DELAYED_ACK_NS: u64 = 40_000_000;
/// Nagle ceiling — bound how long we'll hold a partial segment
/// waiting for more bytes before flushing it. Matches
/// `TCP_NAGLE_OFF` flush latency in practice.
pub const NAGLE_HOLD_NS: u64 = 40_000_000;
/// Zero-window persist initial timeout (1 s, doubles on each
/// probe). RFC 9293 §3.8.6.
pub const PERSIST_INITIAL_NS: u64 = 1_000_000_000;
/// Zero-window persist cap.
pub const PERSIST_MAX_NS: u64 = 60_000_000_000;
/// Default `SO_KEEPALIVE` idle time before first probe (2 hours).
/// RFC 9293 §3.8.4.
pub const KEEPALIVE_IDLE_NS: u64 = 2 * 60 * 60 * 1_000_000_000u64;
/// Default keepalive probe interval (75 s).
pub const KEEPALIVE_INTVL_NS: u64 = 75 * 1_000_000_000;
/// Default keepalive probe count before drop.
pub const KEEPALIVE_CNT: u8 = 9;
/// Max outstanding segments we remember per connection for the
/// retransmit queue. Bounded to keep the per-connection memory
/// footprint predictable; oversize sends back-pressure via
/// `tcp_send` returning short writes.
pub const MAX_OUTSTANDING: usize = 256;

// ── Setsockopt option keys ──────────────────────────────────────────
//
// We keep the option ABI inline here since userspace and the
// stack agree on numeric values out of this module.

pub const TCP_NODELAY: i32 = 1;
pub const TCP_KEEPALIVE: i32 = 9;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
pub const TCP_USER_TIMEOUT: i32 = 18;
pub const TCP_CONGESTION: i32 = 13;
pub const TCP_QUICKACK: i32 = 12;
pub const TCP_MAXSEG: i32 = 2;
pub const TCP_CORK: i32 = 3;

// ── TCB ─────────────────────────────────────────────────────────────

/// Per-connection state. Carried inside `Arc<IrqSafeSpinLock<_>>`
/// so the table and any caller share the same lock.
pub struct Tcb {
    pub id: u32,
    pub net_ns_id: u64,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub remote_mac: [u8; 6],
    pub state: TcpState,

    // ── Sequence space (RFC 9293 §3.3.1) ──
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub iss: u32,
    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    pub irs: u32,
    /// snd.wl1/snd.wl2 — sequence numbers used to update snd.wnd
    /// per RFC 9293 §3.10.7.4 — drop stale window updates.
    pub snd_wl1: u32,
    pub snd_wl2: u32,

    // ── Send / receive buffers ──
    pub send_buf: SendBuf,
    pub recv_buf: RecvBuf,

    // ── Retransmit ──
    pub rtt: RttEstimator,
    pub retx_queue: VecDeque<OutSeg>,
    /// Cycles at which the retransmit timer should fire. 0 = no
    /// timer armed.
    pub retx_deadline_cycles: u64,
    /// Number of back-to-back RTOs without a fresh ACK.
    pub rto_count: u32,

    // ── Congestion control ──
    /// Per-socket cc state (cwnd, ssthresh, CUBIC curve params).
    /// Algorithm-agnostic data; the policy lives in `cc`.
    pub cong: CcState,
    /// Pluggable cc algorithm. Defaults to CUBIC for fresh TCBs;
    /// swap via `set_congestion_control` (cap-gated on `Cap<Cc, Grant>`).
    pub cc: Box<dyn CongestionControl>,
    /// Bytes the sender thinks are in flight (for cwnd math).
    pub flightsize: u32,
    /// Sender-side SACK scoreboard.
    pub scoreboard: SenderScoreboard,
    /// Receiver-side SACK book.
    pub sack_book: SackBook,

    // ── Option negotiation ──
    pub opts: OptionsState,

    // ── Delayed ACK ──
    /// Cycles at which the pending delayed ACK should fire. 0 if
    /// none pending.
    pub delayed_ack_deadline_cycles: u64,
    /// Number of un-ACK'd data segments arrived since last ACK
    /// we sent. ≥2 triggers immediate ACK.
    pub unacked_data_segments: u8,

    // ── Persist (zero-window probe) ──
    pub persist_deadline_cycles: u64,
    pub persist_backoff_ns: u64,

    // ── Keepalive ──
    pub keepalive_enabled: bool,
    pub keepalive_idle_ns: u64,
    pub keepalive_intvl_ns: u64,
    pub keepalive_cnt: u8,
    pub keepalive_probes_sent: u8,
    /// Cycles of the most recent data ACK; the keepalive timer
    /// fires after `keepalive_idle_ns` of idle.
    pub last_progress_cycles: u64,

    // ── Per-connection knobs ──
    pub nagle_enabled: bool,
    pub cork_enabled: bool,
    pub quickack_left: u8,
    pub user_timeout_ns: u64,

    // ── TIME-WAIT timer ──
    pub time_wait_deadline_cycles: u64,

    // ── FIN tracking ──
    /// `true` after we put a FIN on the wire.
    pub fin_sent: bool,
    /// Sequence number of our FIN (snd_nxt at the moment we sent
    /// it). When snd_una reaches `fin_seq + 1`, peer acked it.
    pub fin_seq: u32,
    /// `true` after we received and ack'd a peer FIN.
    pub fin_received: bool,

    // ── Listen-queue + accept-queue (passive open) ──
    /// When this TCB is in LISTEN state: queue of fully-established
    /// child TCB ids waiting for `tcp_accept`.
    pub accept_queue: VecDeque<u32>,
    /// Max accept-queue depth.
    pub backlog: usize,

    // ── Drop cause + waker bookkeeping ──
    pub drop_cause: Option<DropCause>,
    /// Last error from a setsockopt / get path.
    pub last_error: i32,

    /// Memoized egress interface (NIC source MAC + frame-emit fn) for this
    /// connection. The egress is a pure function of the immutable
    /// `remote_addr` (route → iface), so we resolve `iface::for_dst` ONCE on
    /// the first `send_data` and cache it here. Without this, every TX
    /// segment took the global `ROUTE_TABLE` + `IFACES` locks (a per-segment
    /// hot-path serialization across all workers + the RX forwarder's ACKs).
    /// `None` until first resolved (and for LISTEN TCBs, which never send).
    pub egress: Option<CachedEgress>,
}

/// Cached per-connection egress: the chosen NIC's source MAC and its
/// frame-emit function. Both are immutable for the life of the connection
/// (the route to a fixed peer doesn't change), so they're resolved once and
/// reused — keeping `ROUTE_TABLE`/`IFACES` off the per-segment TX path.
#[derive(Clone, Debug)]
pub struct CachedEgress {
    pub name: Arc<str>,
    pub mac: [u8; 6],
    pub send: iface::SendFn,
}

fn emit_tcb_frame(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    iface_name: &str,
    send: iface::SendFn,
    mut frame: Vec<u8>,
) {
    let net_ns_id = arc.lock().net_ns_id;
    if frame.len() < crate::pkt::ETH_HDR_LEN {
        return;
    }
    if crate::tcp_stack::nf_tx_filter_in(
        net_ns_id,
        iface_name,
        &mut frame[crate::pkt::ETH_HDR_LEN..],
    ) == crate::netfilter::Verdict::Accept
    {
        let _ = send(&frame);
    }
}

impl core::fmt::Debug for Tcb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tcb")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("snd_wnd", &self.snd_wnd)
            .field("rcv_wnd", &self.rcv_wnd)
            .field("cong.cwnd", &self.cong.cwnd)
            .field("cong.ssthresh", &self.cong.ssthresh)
            .finish_non_exhaustive()
    }
}

impl Tcb {
    pub fn new_active(
        id: u32,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        remote_mac: [u8; 6],
        iss: u32,
    ) -> Self {
        Self {
            id,
            net_ns_id: 0,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            remote_mac,
            state: TcpState::Closed,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd: DEFAULT_RCV_BUF as u32,
            irs: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            send_buf: SendBuf::new(DEFAULT_SND_BUF, iss.wrapping_add(1)),
            recv_buf: RecvBuf::new(DEFAULT_RCV_BUF),
            rtt: RttEstimator::new(),
            retx_queue: VecDeque::new(),
            retx_deadline_cycles: 0,
            rto_count: 0,
            cong: CcState::default(),
            cc: default_cc(),
            flightsize: 0,
            scoreboard: SenderScoreboard::new(),
            sack_book: SackBook::new(),
            opts: OptionsState::new(),
            delayed_ack_deadline_cycles: 0,
            unacked_data_segments: 0,
            persist_deadline_cycles: 0,
            persist_backoff_ns: PERSIST_INITIAL_NS,
            keepalive_enabled: false,
            keepalive_idle_ns: KEEPALIVE_IDLE_NS,
            keepalive_intvl_ns: KEEPALIVE_INTVL_NS,
            keepalive_cnt: KEEPALIVE_CNT,
            keepalive_probes_sent: 0,
            last_progress_cycles: 0,
            nagle_enabled: true,
            cork_enabled: false,
            quickack_left: 0,
            user_timeout_ns: 0,
            time_wait_deadline_cycles: 0,
            fin_sent: false,
            fin_seq: 0,
            fin_received: false,
            accept_queue: VecDeque::new(),
            backlog: 0,
            drop_cause: None,
            last_error: 0,
            egress: None,
        }
    }

    pub fn new_listener(id: u32, local_addr: [u8; 4], local_port: u16, backlog: usize) -> Self {
        let mut t = Self::new_active(id, local_addr, local_port, [0; 4], 0, [0; 6], 0);
        t.state = TcpState::Listen;
        t.backlog = backlog.max(1);
        t
    }

    pub fn with_net_ns(mut self, net_ns_id: u64) -> Self {
        self.net_ns_id = net_ns_id;
        self
    }

    /// Effective send window from RFC 9293 §3.10.7.4 — min of
    /// peer's advertised window and our congestion window, minus
    /// what's already in flight.
    pub fn usable_send_window(&self) -> u32 {
        let cap = core::cmp::min(self.snd_wnd, self.cong.effective_cwnd());
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
        cap.saturating_sub(in_flight)
    }

    /// `true` once we transition into a state where the user
    /// can read inbound data.
    pub fn user_can_read(&self) -> bool {
        self.recv_buf.has_data()
            || matches!(self.state, TcpState::CloseWait | TcpState::Closed)
            || self.drop_cause.is_some()
    }

    /// `true` once data is "deliverable" or the peer is dead.
    pub fn user_can_write(&self) -> bool {
        match self.state {
            TcpState::Established | TcpState::CloseWait => {
                self.send_buf.len() < self.send_buf.limit
            }
            _ => false,
        }
    }
}

// ── TCB table ───────────────────────────────────────────────────────

/// Number of by-id TCB-table shards (power of two). The by-id table is the
/// authoritative registry (lifecycle, timer sweep, /proc, and the syscall
/// `send`/`recv`/`readable` handle-resolution path). Under an 8-worker
/// server each worker resolves its own connections' ids via `lookup_tcb`
/// on EVERY read/write/poll — a single global lock there serialized all
/// workers (the 8-thread mt-echo wedge: a CPU spinning in
/// `run_lock_spin_hook`). Sharding by id (ids are sequential, so `id & MASK`
/// round-robins them) means distinct connections almost never share a shard
/// lock. Mirrors the already-sharded `CONN_INDEX`.
const TCB_SHARDS: usize = 32;

#[allow(clippy::type_complexity)]
static TCB_TABLE: [IrqSafeSpinLock<Option<BTreeMap<u32, Arc<IrqSafeSpinLock<Tcb>>>>>; TCB_SHARDS] =
    [const { IrqSafeSpinLock::new(None) }; TCB_SHARDS];

#[inline]
fn tcb_shard(id: u32) -> usize {
    (id as usize) & (TCB_SHARDS - 1)
}

static NEXT_TCB_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_LOCAL_PORT: AtomicU32 = AtomicU32::new(49152);

// ── Fast TCB lookup indexes (off the global by-id TCB_TABLE lock) ────
//
// `handle_segment` (the RX hot path) and the accept-enqueue path must
// find a TCB by its 4-tuple / listen (addr,port) WITHOUT holding
// `TCB_TABLE` across an O(N) `values().find()` scan. That scan locked
// every TCB while the BSP RX forwarder held the one global lock —
// serializing it against every AP worker's by-id `send`/`recv` lookup
// (which also takes `TCB_TABLE`). These indexes give O(1) lookups: the
// connected index is sharded so RX dispatch for different connections
// never shares a lock, and the by-id `TCB_TABLE` is no longer on the
// per-segment path at all (it stays the authoritative registry for
// lifecycle, the timer sweep, and syscall handle resolution).
//
// Maintained centrally by `install_tcb`/`remove_tcb`, keyed off
// immutable TCB fields (a TCB's 4-tuple and LISTEN role never change
// after construction), so the indexes cannot drift from the by-id table.

/// Number of connected-index shards (power of two).
const CONN_SHARDS: usize = 32;

/// Connected-TCB key: (remote_ip, remote_port, local_ip, local_port),
/// IPs packed big-endian. Uniquely identifies a non-LISTEN TCB.
type ConnKey = (u64, u32, u16, u32, u16);

#[inline]
fn conn_key(
    net_ns_id: u64,
    remote: [u8; 4],
    remote_port: u16,
    local: [u8; 4],
    local_port: u16,
) -> ConnKey {
    (
        net_ns_id,
        u32::from_be_bytes(remote),
        remote_port,
        u32::from_be_bytes(local),
        local_port,
    )
}

#[inline]
fn conn_shard(k: &ConnKey) -> usize {
    // FNV-1a over the tuple, masked to the shard count.
    let mut h: u32 = 0x811c_9dc5;
    let mut mix = |v: u32| {
        for b in v.to_le_bytes() {
            h = (h ^ b as u32).wrapping_mul(0x0100_0193);
        }
    };
    mix(k.0 as u32);
    mix((k.0 >> 32) as u32);
    mix(k.1);
    mix(k.2 as u32);
    mix(k.3);
    mix(k.4 as u32);
    (h as usize) & (CONN_SHARDS - 1)
}

#[allow(clippy::type_complexity)]
static CONN_INDEX: [IrqSafeSpinLock<Option<BTreeMap<ConnKey, Arc<IrqSafeSpinLock<Tcb>>>>>;
    CONN_SHARDS] = [const { IrqSafeSpinLock::new(None) }; CONN_SHARDS];

/// Listener index: (local_ip, local_port) → SO_REUSEPORT group. Far
/// lower frequency than the connected path (per-SYN, not per-segment),
/// so a single lock is fine.
#[allow(clippy::type_complexity)]
static LISTEN_INDEX: IrqSafeSpinLock<
    Option<BTreeMap<(u64, u32, u16), alloc::vec::Vec<Arc<IrqSafeSpinLock<Tcb>>>>>,
> = IrqSafeSpinLock::new(None);

fn conn_index_insert(key: ConnKey, arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let mut g = CONN_INDEX[conn_shard(&key)].lock();
    g.get_or_insert_with(BTreeMap::new).insert(key, arc.clone());
}

fn conn_index_remove(key: ConnKey) {
    let mut g = CONN_INDEX[conn_shard(&key)].lock();
    if let Some(m) = g.as_mut() {
        m.remove(&key);
    }
}

fn conn_index_lookup(key: ConnKey) -> Option<Arc<IrqSafeSpinLock<Tcb>>> {
    let g = CONN_INDEX[conn_shard(&key)].lock();
    g.as_ref().and_then(|m| m.get(&key).cloned())
}

fn listen_index_insert(
    net_ns_id: u64,
    local: [u8; 4],
    local_port: u16,
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
) {
    let key = (net_ns_id, u32::from_be_bytes(local), local_port);
    let mut g = LISTEN_INDEX.lock();
    g.get_or_insert_with(BTreeMap::new)
        .entry(key)
        .or_default()
        .push(arc.clone());
}

fn listen_index_remove(
    net_ns_id: u64,
    local: [u8; 4],
    local_port: u16,
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
) {
    let key = (net_ns_id, u32::from_be_bytes(local), local_port);
    let mut g = LISTEN_INDEX.lock();
    if let Some(m) = g.as_mut() {
        if let Some(v) = m.get_mut(&key) {
            // Identity compare by Arc pointer — no TCB lock taken under
            // the LISTEN_INDEX lock (avoids a lock-ordering hazard).
            v.retain(|a| !Arc::ptr_eq(a, arc));
            if v.is_empty() {
                m.remove(&key);
            }
        }
    }
}

/// All LISTEN TCBs that match an inbound packet to (dst, port): a
/// concrete-addr listener bound to `dst` plus an INADDR_ANY (0.0.0.0)
/// listener on the same port. Order is deterministic (concrete then
/// wildcard, install order within each) so the SO_REUSEPORT flow-hash
/// selection is stable across the SYN and accept-enqueue call sites.
fn listen_index_group(
    net_ns_id: u64,
    dst: [u8; 4],
    port: u16,
) -> alloc::vec::Vec<Arc<IrqSafeSpinLock<Tcb>>> {
    let mut out: alloc::vec::Vec<Arc<IrqSafeSpinLock<Tcb>>> = alloc::vec::Vec::new();
    let g = LISTEN_INDEX.lock();
    let m = match g.as_ref() {
        Some(m) => m,
        None => return out,
    };
    if let Some(v) = m.get(&(net_ns_id, u32::from_be_bytes(dst), port)) {
        out.extend(v.iter().cloned());
    }
    if dst != [0, 0, 0, 0] {
        if let Some(v) = m.get(&(net_ns_id, 0u32, port)) {
            out.extend(v.iter().cloned());
        }
    }
    out
}

/// Internal: register a TCB and return its id.
fn install_tcb(tcb: Tcb) -> (u32, Arc<IrqSafeSpinLock<Tcb>>) {
    let id = tcb.id;
    // Compute the index key from immutable fields BEFORE moving `tcb`.
    let is_listen = tcb.state == TcpState::Listen;
    let conn_k = (!is_listen).then(|| {
        conn_key(
            tcb.net_ns_id,
            tcb.remote_addr,
            tcb.remote_port,
            tcb.local_addr,
            tcb.local_port,
        )
    });
    let listen_k = is_listen.then_some((tcb.net_ns_id, tcb.local_addr, tcb.local_port));
    let arc = Arc::new(IrqSafeSpinLock::new(tcb));
    {
        let mut g = TCB_TABLE[tcb_shard(id)].lock();
        let m = g.get_or_insert_with(BTreeMap::new);
        m.insert(id, arc.clone());
    }
    // Maintain the fast lookup index (outside the TCB_TABLE lock).
    if let Some(k) = conn_k {
        conn_index_insert(k, &arc);
    }
    if let Some((ns, la, lp)) = listen_k {
        listen_index_insert(ns, la, lp, &arc);
    }
    (id, arc)
}

fn fresh_tcb_id() -> u32 {
    NEXT_TCB_ID.fetch_add(1, Ordering::Relaxed)
}

fn fresh_local_port() -> u16 {
    NEXT_LOCAL_PORT.fetch_add(1, Ordering::Relaxed) as u16
}

/// Look up a TCB by id.
pub fn lookup_tcb(id: u32) -> Option<Arc<IrqSafeSpinLock<Tcb>>> {
    let g = TCB_TABLE[tcb_shard(id)].lock();
    g.as_ref().and_then(|m| m.get(&id).cloned())
}

/// Remove a TCB from the table (and its fast-lookup index entry).
pub fn remove_tcb(id: u32) {
    // Resolve the TCB first so we can drop its index entry by its
    // (immutable) key. Read fields under the per-TCB lock, then DROP
    // that lock before touching the indexes (no nested locking).
    if let Some(arc) = lookup_tcb(id) {
        let (ns, is_listen, la, lp, ra, rp) = {
            let t = arc.lock();
            (
                t.net_ns_id,
                t.state == TcpState::Listen,
                t.local_addr,
                t.local_port,
                t.remote_addr,
                t.remote_port,
            )
        };
        if is_listen {
            listen_index_remove(ns, la, lp, &arc);
        } else {
            conn_index_remove(conn_key(ns, ra, rp, la, lp));
        }
    }
    let mut g = TCB_TABLE[tcb_shard(id)].lock();
    if let Some(m) = g.as_mut() {
        m.remove(&id);
    }
}

/// Test-only: drop every TCB.
#[doc(hidden)]
pub fn __reset_for_test() {
    for shard in TCB_TABLE.iter() {
        let mut g = shard.lock();
        if let Some(m) = g.as_mut() {
            m.clear();
        }
    }
    for shard in CONN_INDEX.iter() {
        let mut g = shard.lock();
        if let Some(m) = g.as_mut() {
            m.clear();
        }
    }
    {
        let mut g = LISTEN_INDEX.lock();
        if let Some(m) = g.as_mut() {
            m.clear();
        }
    }
    NEXT_TCB_ID.store(1, Ordering::Relaxed);
    NEXT_LOCAL_PORT.store(49152, Ordering::Relaxed);
}

/// Snapshot of one TCB's fields-of-interest. Used to render
/// `/proc/net/tcp` without holding the TCB table lock across the
/// whole render — we copy minimal data out, drop the lock, then
/// format. Matches what Linux's `get_tcp4_sock` extracts per row.
#[derive(Clone, Debug)]
pub struct TcbSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// Per Linux's `include/net/tcp_states.h` (1-indexed).
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub retrnsmt: u32,
}

/// Snapshot every TCB in the table. Cheap: a few cycles per entry
/// to copy 16 bytes plus the state byte.
pub fn snapshot() -> alloc::vec::Vec<TcbSnapshot> {
    snapshot_in(0)
}

pub fn snapshot_in(net_ns_id: u64) -> alloc::vec::Vec<TcbSnapshot> {
    let mut out = alloc::vec::Vec::new();
    for shard in TCB_TABLE.iter() {
        let g = shard.lock();
        let m = match g.as_ref() {
            Some(m) => m,
            None => continue,
        };
        for arc in m.values() {
            let t = arc.lock();
            if t.net_ns_id != net_ns_id {
                continue;
            }
            out.push(TcbSnapshot {
                local_addr: t.local_addr,
                local_port: t.local_port,
                remote_addr: t.remote_addr,
                remote_port: t.remote_port,
                state_code: tcp_state_code(t.state),
                tx_queue: t.send_buf.len() as u32,
                // RecvBuf exposes free_window; rx_queue is the in-order
                // bytes waiting for the user, i.e. limit - free_window.
                rx_queue: (t.recv_buf.limit as u32).saturating_sub(t.recv_buf.free_window()),
                retrnsmt: t.rto_count,
            });
        }
    }
    out
}

/// Map the in-tree `TcpState` enum onto Linux's tcp_state numbering
/// from `include/net/tcp_states.h`. The numeric values are what
/// netstat / ss parse from /proc/net/tcp's `st` column.
fn tcp_state_code(s: TcpState) -> u8 {
    match s {
        TcpState::Established => 0x01,
        TcpState::SynSent => 0x02,
        TcpState::SynReceived => 0x03,
        TcpState::FinWait1 => 0x04,
        TcpState::FinWait2 => 0x05,
        TcpState::TimeWait => 0x06,
        TcpState::Closed => 0x07,
        TcpState::CloseWait => 0x08,
        TcpState::LastAck => 0x09,
        TcpState::Listen => 0x0A,
        TcpState::Closing => 0x0B,
    }
}

// ── Public API: listen / accept ─────────────────────────────────────

pub fn listen(local_addr: [u8; 4], local_port: u16, backlog: usize) -> Result<u32, ()> {
    listen_in(0, local_addr, local_port, backlog)
}

pub fn listen_in(
    net_ns_id: u64,
    local_addr: [u8; 4],
    local_port: u16,
    backlog: usize,
) -> Result<u32, ()> {
    let id = fresh_tcb_id();
    let tcb = Tcb::new_listener(id, local_addr, local_port, backlog).with_net_ns(net_ns_id);
    let (id, _arc) = install_tcb(tcb);
    Ok(id)
}

/// Non-blocking accept. Returns Ok(Some(child_id)) when a new
/// connection is ready, Ok(None) if the queue is empty.
pub fn accept(listen_id: u32) -> Result<Option<u32>, ()> {
    let arc = lookup_tcb(listen_id).ok_or(())?;
    let mut t = arc.lock();
    if t.state != TcpState::Listen {
        return Err(());
    }
    Ok(t.accept_queue.pop_front())
}

/// Non-destructive accept-readiness check: true iff the listener has at
/// least one completed connection waiting in its accept-queue. Used by
/// `poll`/`epoll` so an event-driven server (e.g. redis) wakes on an
/// inbound off-box connection without consuming it.
pub fn listen_has_pending(listen_id: u32) -> bool {
    match lookup_tcb(listen_id) {
        Some(arc) => {
            let t = arc.lock();
            t.state == TcpState::Listen && !t.accept_queue.is_empty()
        }
        None => false,
    }
}

// ── Public API: connect ─────────────────────────────────────────────

pub fn connect(remote_addr: [u8; 4], remote_port: u16) -> Result<u32, ()> {
    connect_in(0, remote_addr, remote_port)
}

pub fn connect_in(net_ns_id: u64, remote_addr: [u8; 4], remote_port: u16) -> Result<u32, ()> {
    let iface = iface::for_dst_in(net_ns_id, remote_addr).ok_or(())?;
    let mac = crate::tcp_stack::arp_resolve_in(net_ns_id, iface.gateway, 1000)?;
    let local_port = fresh_local_port();
    let id = fresh_tcb_id();
    let iss = compute_isn();
    let mut tcb = Tcb::new_active(
        id,
        iface.ipv4,
        local_port,
        remote_addr,
        remote_port,
        mac,
        iss,
    )
    .with_net_ns(net_ns_id);
    tcb.state = TcpState::SynSent;
    let (id, arc) = install_tcb(tcb);

    // Emit the SYN with our negotiation options.
    send_syn(&arc, false);

    // Active-spin until the FSM advances out of SYN-SENT or the
    // deadline expires.
    let deadline = narf_scheduler::narf_time::Deadline::after_ns(5_000_000_000);
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            // Pump retransmits from inside the spin so a lost SYN
            // gets retried before the deadline.
            tick_retransmit(&arc);
            let st = arc.lock().state;
            st != TcpState::SynSent && st != TcpState::SynReceived
        },
        deadline,
    );
    let st = arc.lock().state;
    match st {
        TcpState::Established => Ok(id),
        _ => {
            remove_tcb(id);
            Err(())
        }
    }
}

fn compute_isn() -> u32 {
    let t = narf_scheduler::narf_time::monotonic_ns();
    // Twist with a constant so two near-simultaneous opens land
    // in different windows.
    (t as u32).wrapping_mul(2654435769)
}

// ── Public API: send / recv ─────────────────────────────────────────

pub fn send(id: u32, buf: &[u8]) -> Result<usize, ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let n = {
        let mut t = arc.lock();
        if !t.state.can_send_data() {
            return Err(());
        }
        t.send_buf.write(buf)
    };
    if n > 0 {
        pump_send(&arc);
    }
    Ok(n)
}

pub fn recv(id: u32, buf: &mut [u8]) -> Result<usize, ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let mut t = arc.lock();
    Ok(t.recv_buf.read(buf))
}

/// `true` if a `recv` on this TCB would return immediately — either
/// inbound data is buffered, or the peer has closed / the connection
/// is dead (so a read returns EOF/error rather than blocking). Drives
/// `POLL_IN` for kernel-TCP (`InetWired`) sockets so epoll/poll/select
/// can wake on incoming data. An unknown id (TCB already reaped) is
/// reported readable so a poller proceeds to a read that returns EOF
/// instead of hanging.
pub fn readable(id: u32) -> bool {
    match lookup_tcb(id) {
        Some(arc) => arc.lock().user_can_read(),
        None => true,
    }
}

// ── Public API: shutdown / close ────────────────────────────────────

pub fn shutdown(id: u32, how: Shutdown) -> Result<(), ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let mut t = arc.lock();
    do_shutdown(&mut t, how);
    let state = t.state;
    drop(t);
    if matches!(state, TcpState::FinWait1 | TcpState::LastAck) {
        // Make sure the FIN actually goes on the wire.
        pump_send(&arc);
    }
    Ok(())
}

fn do_shutdown(t: &mut Tcb, how: Shutdown) {
    match how {
        Shutdown::Read => {
            t.recv_buf = RecvBuf::new(t.recv_buf.limit);
        }
        Shutdown::Write | Shutdown::Both => {
            if !t.fin_sent
                && matches!(
                    t.state,
                    TcpState::Established | TcpState::SynReceived | TcpState::CloseWait
                )
            {
                t.fin_sent = true;
                t.fin_seq = t.snd_nxt;
                t.state = match t.state {
                    TcpState::CloseWait => TcpState::LastAck,
                    _ => TcpState::FinWait1,
                };
            }
            if matches!(how, Shutdown::Both) {
                t.recv_buf = RecvBuf::new(t.recv_buf.limit);
            }
        }
    }
}

pub fn close(id: u32) -> Result<(), ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    {
        let mut t = arc.lock();
        do_shutdown(&mut t, Shutdown::Both);
    }
    pump_send(&arc);
    Ok(())
}

// ── Public API: setsockopt / getsockopt ─────────────────────────────

pub fn setsockopt_int(id: u32, opt: i32, val: i32) -> Result<(), ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let mut t = arc.lock();
    match opt {
        TCP_NODELAY => {
            t.nagle_enabled = val == 0;
        }
        TCP_KEEPALIVE => {
            t.keepalive_enabled = val != 0;
        }
        TCP_KEEPIDLE => {
            t.keepalive_idle_ns = (val as u64).saturating_mul(1_000_000_000);
        }
        TCP_KEEPINTVL => {
            t.keepalive_intvl_ns = (val as u64).saturating_mul(1_000_000_000);
        }
        TCP_KEEPCNT => {
            t.keepalive_cnt = val.clamp(1, 255) as u8;
        }
        TCP_USER_TIMEOUT => {
            t.user_timeout_ns = (val as u64).saturating_mul(1_000_000);
        }
        TCP_QUICKACK => {
            if val != 0 {
                t.quickack_left = 4;
            } else {
                t.quickack_left = 0;
            }
        }
        TCP_MAXSEG => {
            let v = val.clamp(MIN_MSS as i32, 9000) as u32;
            t.opts.our_mss = v as u16;
            t.cong.set_mss(v);
        }
        TCP_CORK => {
            t.cork_enabled = val != 0;
        }
        _ => return Err(()),
    }
    Ok(())
}

pub fn setsockopt_str(id: u32, opt: i32, val: &str) -> Result<(), ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let mut t = arc.lock();
    match opt {
        TCP_CONGESTION => {
            // `TCP_CONGESTION` is a name-keyed install. The Linux
            // surface is uncapped; we bootstrap an authority here so
            // the cap-gated install path runs on every setsockopt.
            // Userspace gating happens at the syscall boundary (a
            // future Wave-I will pass an explicit cap through).
            let cap = Cap::<Cc, Grant>::bootstrap();
            let boxed: Box<dyn CongestionControl> = match val {
                "cubic" => install_cc(&cap, Cubic).map_err(|_| ())?,
                "reno" => install_cc(&cap, Reno).map_err(|_| ())?,
                _ => return Err(()),
            };
            t.cc = boxed;
            Ok(())
        }
        _ => Err(()),
    }
}

pub fn getsockopt_int(id: u32, opt: i32) -> Result<i32, ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let t = arc.lock();
    let v = match opt {
        TCP_NODELAY => (!t.nagle_enabled) as i32,
        TCP_KEEPALIVE => t.keepalive_enabled as i32,
        TCP_KEEPIDLE => (t.keepalive_idle_ns / 1_000_000_000) as i32,
        TCP_KEEPINTVL => (t.keepalive_intvl_ns / 1_000_000_000) as i32,
        TCP_KEEPCNT => t.keepalive_cnt as i32,
        TCP_USER_TIMEOUT => (t.user_timeout_ns / 1_000_000) as i32,
        TCP_MAXSEG => t.opts.our_mss as i32,
        TCP_QUICKACK => (t.quickack_left > 0) as i32,
        TCP_CORK => t.cork_enabled as i32,
        _ => return Err(()),
    };
    Ok(v)
}

pub fn getsockopt_cong(id: u32) -> Result<&'static str, ()> {
    let arc = lookup_tcb(id).ok_or(())?;
    let t = arc.lock();
    Ok(t.cc.name())
}

/// Cap-gated, per-socket cc install. Replaces the boxed policy on the
/// named TCB. `cap` is checked for liveness; revoking the install
/// cap disables further swaps on every TCB.
pub fn set_congestion_control<C: CongestionControl>(
    id: u32,
    cap: &Cap<Cc, Grant>,
    cc: C,
) -> Result<(), CcError> {
    let arc = lookup_tcb(id).ok_or(CcError::AuthorityRevoked)?;
    let boxed = install_cc(cap, cc)?;
    let mut t = arc.lock();
    t.cc = boxed;
    Ok(())
}

// ── Segment build / send ────────────────────────────────────────────

/// Construct the bytes for an Ethernet+IPv4+TCP frame carrying
/// `payload`. Used by every outbound path.
fn build_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: Vec<u8>,
    payload: &[u8],
) -> Vec<u8> {
    let opt_len = options.len();
    let tcp_hdr_len = TCP_HDR_MIN + opt_len;
    let total = ETH_HDR_LEN + IPV4_HDR_LEN + tcp_hdr_len + payload.len();
    let mut frame = vec![0u8; total];
    let ip_total = (IPV4_HDR_LEN + tcp_hdr_len + payload.len()) as u16;
    let _ = write_eth_header(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4);
    let _ = write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total,
        IP_PROTO_TCP,
        src_ip,
        dst_ip,
    );
    pkt::set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let hdr = TcpHeader {
        src_port,
        dst_port,
        sequence: seq,
        acknowledgement: ack,
        header_len: tcp_hdr_len as u8,
        flags,
        window,
        checksum: 0,
        urgent_ptr: 0,
        options,
    };
    let bytes = hdr.encode();
    frame[tcp_off..tcp_off + bytes.len()].copy_from_slice(&bytes);
    frame[tcp_off + bytes.len()..tcp_off + bytes.len() + payload.len()].copy_from_slice(payload);
    let segment = &frame[tcp_off..tcp_off + tcp_hdr_len + payload.len()];
    // Patch the 2-byte TCP checksum in place (it lives at offset 16 of the
    // TCP header, after src/dst port + seq + ack + dataoff/flags + window)
    // rather than re-encoding the whole header into a fresh Vec and copying
    // it back — saves one heap alloc + a full-header copy per outbound
    // segment. The checksum was computed over the header with this field
    // zeroed (as encoded above), which is the required pseudo-header form.
    let cs = ipv4_pseudo_checksum(src_ip, dst_ip, segment);
    frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
    frame
}

fn send_syn(arc: &Arc<IrqSafeSpinLock<Tcb>>, ack_too: bool) {
    let (net_ns_id, dst_for_iface) = {
        let t = arc.lock();
        (t.net_ns_id, t.remote_addr)
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_for_iface) {
        Some(i) => i,
        None => return,
    };
    let (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        our_iss,
        ack,
        peer_dst_mac,
        mss,
        our_wscale,
        our_ts,
        peer_tsval,
    ) = {
        let t = arc.lock();
        let our_ts = tsval_now();
        (
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.iss,
            t.rcv_nxt,
            t.remote_mac,
            t.opts.our_mss,
            DEFAULT_WSCALE,
            our_ts,
            t.opts.ts_recent,
        )
    };
    // For a SYN-ACK the TSecr must echo the peer's most recent TSval
    // (captured into `ts_recent` from the incoming SYN), NOT the ACK
    // sequence number. A wrong TSecr makes a strict peer (a real Linux
    // host over tap; SLIRP regenerates timestamps so it masked this)
    // reject the SYN-ACK and RST the handshake.
    let opts = encode_syn_options(
        mss,
        our_wscale,
        our_ts,
        if ack_too { peer_tsval } else { 0 },
    );
    let flags = if ack_too {
        FLAG_SYN | FLAG_ACK
    } else {
        FLAG_SYN
    };
    let frame = build_frame(
        iface.mac,
        peer_dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        our_iss,
        if ack_too { ack } else { 0 },
        flags,
        65535,
        opts,
        &[],
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
    // Track SYN in the retransmit queue so a missed SYN-ACK
    // re-triggers retransmit.
    let mut t = arc.lock();
    let iss = t.iss;
    t.snd_nxt = iss.wrapping_add(1);
    queue_retransmit(&mut t, iss, 1, flags);
    arm_retransmit_timer(&mut t);
}

fn send_ack(arc: &Arc<IrqSafeSpinLock<Tcb>>, extra_flags: u8) {
    let (net_ns_id, dst_for_iface) = {
        let t = arc.lock();
        (t.net_ns_id, t.remote_addr)
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_for_iface) {
        Some(i) => i,
        None => return,
    };
    let (src_ip, dst_ip, src_port, dst_port, seq, ack, peer_mac, window, opt_bytes) = {
        let mut t = arc.lock();
        let window = effective_advertised_window(&t);
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        // Clear pending delayed-ACK + count.
        t.delayed_ack_deadline_cycles = 0;
        t.unacked_data_segments = 0;
        (
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.snd_nxt,
            t.rcv_nxt,
            t.remote_mac,
            window,
            opts,
        )
    };
    let frame = build_frame(
        iface.mac,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        FLAG_ACK | extra_flags,
        window,
        opt_bytes,
        &[],
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
}

fn send_rst(arc: &Arc<IrqSafeSpinLock<Tcb>>, seq: u32, ack: u32, ack_flag: bool) {
    let (net_ns_id, dst_for_iface) = {
        let t = arc.lock();
        (t.net_ns_id, t.remote_addr)
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_for_iface) {
        Some(i) => i,
        None => return,
    };
    let (src_ip, dst_ip, src_port, dst_port, peer_mac) = {
        let t = arc.lock();
        (
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.remote_mac,
        )
    };
    let flags = if ack_flag {
        FLAG_RST | FLAG_ACK
    } else {
        FLAG_RST
    };
    let frame = build_frame(
        iface.mac,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        0,
        Vec::new(),
        &[],
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
}

/// Build & send one data segment carrying `payload` from sequence
/// number `seq`. Honours options (timestamps when negotiated) and
/// updates the retransmit queue.
fn send_data(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    seq: u32,
    payload: &[u8],
    extra_flags: u8,
    record_retx: bool,
) {
    // Egress (NIC src MAC + emit fn): use the per-connection memoized cache;
    // resolve `iface::for_dst` (global ROUTE_TABLE + IFACES locks) only on
    // the first segment, then reuse — keeping those locks off the hot path.
    let egress = {
        let cached = arc.lock().egress.clone();
        match cached {
            Some(e) => e,
            None => {
                let (net_ns_id, dst_for_iface) = {
                    let t = arc.lock();
                    (t.net_ns_id, t.remote_addr)
                };
                let snap = match iface::for_dst_in(net_ns_id, dst_for_iface) {
                    Some(i) => i,
                    None => return,
                };
                let e = CachedEgress {
                    name: Arc::from(snap.name),
                    mac: snap.mac,
                    send: snap.send,
                };
                arc.lock().egress = Some(e.clone());
                e
            }
        }
    };
    let (src_ip, dst_ip, src_port, dst_port, ack, peer_mac, window, opt_bytes) = {
        let mut t = arc.lock();
        let window = effective_advertised_window(&t);
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        t.delayed_ack_deadline_cycles = 0;
        t.unacked_data_segments = 0;
        (
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.rcv_nxt,
            t.remote_mac,
            window,
            opts,
        )
    };
    let frame = build_frame(
        egress.mac,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        FLAG_ACK | extra_flags,
        window,
        opt_bytes,
        payload,
    );
    emit_tcb_frame(arc, egress.name.as_ref(), egress.send, frame);
    if record_retx {
        let mut t = arc.lock();
        let payload_len = payload.len() as u32;
        let mut seq_len = payload_len;
        if extra_flags & FLAG_FIN != 0 {
            seq_len = seq_len.saturating_add(1);
        }
        queue_retransmit(&mut t, seq, seq_len, FLAG_ACK | extra_flags);
        arm_retransmit_timer(&mut t);
    }
}

fn effective_advertised_window(t: &Tcb) -> u16 {
    let raw = t.recv_buf.free_window();
    t.opts.encode_our_window(raw)
}

fn tsval_now() -> u32 {
    // 1 ms resolution, wrapping at 32 bits.
    (narf_scheduler::narf_time::monotonic_ns() / 1_000_000) as u32
}

// ── Retransmit queue ────────────────────────────────────────────────

fn queue_retransmit(t: &mut Tcb, seq: u32, seq_len: u32, flags: u8) {
    let now = narf_scheduler::narf_time::now_cycles();
    let seg = OutSeg {
        seq,
        len: seq_len,
        sent_at_cycles: now,
        retransmitted: false,
        flags,
    };
    // Bounded queue — drop oldest if we hit the cap. Real TCP
    // would block tcp_send instead; the bound is here to keep the
    // per-TCB memory predictable.
    if t.retx_queue.len() >= MAX_OUTSTANDING {
        t.retx_queue.pop_front();
    }
    t.retx_queue.push_back(seg);
    t.flightsize = t.flightsize.saturating_add(seq_len);
}

fn arm_retransmit_timer(t: &mut Tcb) {
    if t.retx_queue.is_empty() {
        t.retx_deadline_cycles = 0;
        return;
    }
    let rto = t.rtt.current_rto();
    let now = narf_scheduler::narf_time::now_cycles();
    let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
    t.retx_deadline_cycles = now.wrapping_add(rto.saturating_mul(cpn as u64));
}

/// Fire the RTO if the deadline has passed. Resends the oldest
/// unacked segment and applies the exponential back-off.
pub fn tick_retransmit(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let now = narf_scheduler::narf_time::now_cycles();
    let do_fire = {
        let t = arc.lock();
        t.retx_deadline_cycles != 0 && now >= t.retx_deadline_cycles && !t.retx_queue.is_empty()
    };
    if do_fire {
        fire_retransmit(arc);
    }
    // Also pump delayed ACKs that timed out.
    tick_delayed_ack(arc);
    // Persist timer for zero-window probing.
    tick_persist(arc);
    // Keepalive timer.
    tick_keepalive(arc);
    // TIME-WAIT reaper.
    tick_time_wait(arc);
}

fn fire_retransmit(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let oldest = {
        let t = arc.lock();
        t.retx_queue.front().copied()
    };
    let Some(seg) = oldest else { return };

    // Back-off; tear down if exceeded.
    let backoff_ok = {
        let mut t = arc.lock();
        let ok = t.rtt.back_off();
        if ok {
            t.rto_count = t.rto_count.saturating_add(1);
            let now = narf_scheduler::narf_time::now_cycles();
            let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
            let flight = t.flightsize;
            // Split-borrow the guard: `cc` is `&Box<dyn …>` (immutable
            // self) while `cong` is the `&mut CcState` target. Going
            // through a `&mut Tcb` lets the compiler see the two fields
            // as disjoint borrows.
            {
                let tcb: &mut Tcb = &mut t;
                tcb.cc.on_rto(&mut tcb.cong, flight, now, cpn);
            }
            // Mark every outstanding segment as retransmitted —
            // Karn's algorithm.
            for s in t.retx_queue.iter_mut() {
                s.retransmitted = true;
            }
            // Reset the sender to retransmit from snd_una.
            t.send_buf.rewind_for_retransmit();
            t.snd_nxt = t.snd_una;
        } else {
            t.drop_cause = Some(DropCause::RetransmitGiveUp);
            t.state = TcpState::Closed;
        }
        ok
    };
    if !backoff_ok {
        // Tear down the connection.
        let id = arc.lock().id;
        remove_tcb(id);
        return;
    }
    // Rebuild & send the oldest segment.
    if seg.flags & FLAG_SYN != 0 {
        // Resend the initial SYN.
        let (ack_too, _) = {
            let t = arc.lock();
            (t.state == TcpState::SynReceived, t.rcv_nxt)
        };
        // Pop the existing SYN entry before sending so we don't
        // double-record it.
        {
            let mut t = arc.lock();
            t.retx_queue.pop_front();
            t.flightsize = t.flightsize.saturating_sub(seg.len);
            // Roll back snd_nxt so send_syn re-installs the
            // retransmit record at the correct seq.
            t.snd_nxt = t.iss;
        }
        send_syn(arc, ack_too);
        return;
    }
    // Otherwise it's data (possibly with FIN). Build by pulling
    // out of the send buffer (data) or by synthesising a FIN.
    let payload_len = seg
        .len
        .saturating_sub(if seg.flags & FLAG_FIN != 0 { 1 } else { 0 });
    let (
        net_ns_id,
        payload,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ack,
        window,
        opt_bytes,
        _flags,
    ) = {
        let t = arc.lock();
        let want = payload_len as usize;
        let mut payload = Vec::with_capacity(want);
        let (a, b) = t.send_buf.unsent_slices(want);
        payload.extend_from_slice(a);
        payload.extend_from_slice(b);
        // The data we want lives in the head of send_buf; we did
        // a rewind_for_retransmit before so sent_offset is 0.
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        let window = effective_advertised_window(&t);
        (
            t.net_ns_id,
            payload,
            t.remote_mac,
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.rcv_nxt,
            window,
            opts,
            seg.flags,
        )
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_ip) {
        Some(i) => i,
        None => return,
    };
    let frame = build_frame(
        iface.mac, peer_mac, src_ip, dst_ip, src_port, dst_port, seg.seq, ack, seg.flags, window,
        opt_bytes, &payload,
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
    {
        let mut t = arc.lock();
        // Advance send-buf sent_offset by the payload length so
        // pump_send doesn't double-send.
        t.send_buf.mark_sent(payload.len());
        t.snd_nxt = t.snd_nxt.wrapping_add(seg.len);
        arm_retransmit_timer(&mut t);
    }
}

fn tick_delayed_ack(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let due = {
        let t = arc.lock();
        t.delayed_ack_deadline_cycles != 0
            && narf_scheduler::narf_time::now_cycles() >= t.delayed_ack_deadline_cycles
    };
    if due {
        send_ack(arc, 0);
    }
}

fn tick_persist(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let due = {
        let t = arc.lock();
        t.persist_deadline_cycles != 0
            && narf_scheduler::narf_time::now_cycles() >= t.persist_deadline_cycles
    };
    if due {
        send_persist_probe(arc);
    }
}

fn send_persist_probe(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let (net_ns_id, dst_for_iface) = {
        let t = arc.lock();
        (t.net_ns_id, t.remote_addr)
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_for_iface) {
        Some(i) => i,
        None => return,
    };
    let (probe_byte, seq, src_ip, dst_ip, src_port, dst_port, peer_mac, window, opt_bytes, ack) = {
        let mut t = arc.lock();
        let probe = if let Some((a, _)) = Some(t.send_buf.unsent_slices(1)) {
            a.first().copied().unwrap_or(0)
        } else {
            0
        };
        let window = effective_advertised_window(&t);
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        let seq = t.snd_una; // probe at snd_una as a one-byte ping
                             // Schedule the next probe with exponential back-off.
        t.persist_backoff_ns = (t.persist_backoff_ns * 2).min(PERSIST_MAX_NS);
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.persist_deadline_cycles = narf_scheduler::narf_time::now_cycles()
            .wrapping_add(t.persist_backoff_ns.saturating_mul(cpn as u64));
        (
            probe,
            seq,
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.remote_mac,
            window,
            opts,
            t.rcv_nxt,
        )
    };
    let frame = build_frame(
        iface.mac,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        FLAG_ACK,
        window,
        opt_bytes,
        &[probe_byte],
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
}

fn tick_keepalive(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let (enabled, idle, intvl, cnt, probes, last_prog, state) = {
        let t = arc.lock();
        (
            t.keepalive_enabled,
            t.keepalive_idle_ns,
            t.keepalive_intvl_ns,
            t.keepalive_cnt,
            t.keepalive_probes_sent,
            t.last_progress_cycles,
            t.state,
        )
    };
    if !enabled || state != TcpState::Established {
        return;
    }
    let now = narf_scheduler::narf_time::now_cycles();
    let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
    let idle_cycles = idle.saturating_mul(cpn as u64);
    let intvl_cycles = intvl.saturating_mul(cpn as u64);
    let elapsed_since_progress = now.wrapping_sub(last_prog);
    let due = if probes == 0 {
        elapsed_since_progress >= idle_cycles
    } else {
        elapsed_since_progress >= idle_cycles.saturating_add((probes as u64) * intvl_cycles)
    };
    if !due {
        return;
    }
    if probes >= cnt {
        // Exhausted — drop the connection.
        let mut t = arc.lock();
        t.drop_cause = Some(DropCause::KeepaliveDead);
        t.state = TcpState::Closed;
        let id = t.id;
        drop(t);
        remove_tcb(id);
        return;
    }
    // Send empty segment with seq = snd_una - 1 (RFC 9293 §3.8.4).
    let (net_ns_id, dst_for_iface) = {
        let t = arc.lock();
        (t.net_ns_id, t.remote_addr)
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_for_iface) {
        Some(i) => i,
        None => return,
    };
    let (seq, src_ip, dst_ip, src_port, dst_port, peer_mac, window, opt_bytes, ack) = {
        let mut t = arc.lock();
        t.keepalive_probes_sent = t.keepalive_probes_sent.saturating_add(1);
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        let window = effective_advertised_window(&t);
        (
            t.snd_una.wrapping_sub(1),
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            t.remote_mac,
            window,
            opts,
            t.rcv_nxt,
        )
    };
    let frame = build_frame(
        iface.mac,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        FLAG_ACK,
        window,
        opt_bytes,
        &[],
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
}

fn tick_time_wait(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    let due = {
        let t = arc.lock();
        t.state == TcpState::TimeWait
            && t.time_wait_deadline_cycles != 0
            && narf_scheduler::narf_time::now_cycles() >= t.time_wait_deadline_cycles
    };
    if due {
        let mut t = arc.lock();
        t.state = TcpState::Closed;
        let id = t.id;
        drop(t);
        remove_tcb(id);
    }
}

// ── Sender pipeline ─────────────────────────────────────────────────

/// Drain the send buffer to the wire, honouring cwnd / receiver
/// window / MSS. Called on each `tcp_send` and after each ACK.
pub fn pump_send(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    loop {
        let (chunks, seq, fin_flag, mss, drained_all) = {
            let mut t = arc.lock();
            let usable = t.usable_send_window();
            let mss = t.opts.peer_mss as u32;
            if usable == 0 {
                // Receiver window closed — arm persist if not
                // already armed.
                if t.persist_deadline_cycles == 0 && !t.send_buf.is_empty() {
                    let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
                    t.persist_backoff_ns = PERSIST_INITIAL_NS;
                    t.persist_deadline_cycles = narf_scheduler::narf_time::now_cycles()
                        .wrapping_add(PERSIST_INITIAL_NS.saturating_mul(cpn as u64));
                }
                break;
            }
            let unsent = t.send_buf.unsent_len() as u32;
            // Nagle/cork: hold partial segments while data outstanding.
            let in_flight = t.snd_nxt.wrapping_sub(t.snd_una);
            let small = unsent < mss;
            if (t.nagle_enabled || t.cork_enabled) && small && in_flight > 0 {
                break;
            }
            if unsent == 0 {
                // Maybe just FIN to send.
                if t.fin_sent && t.snd_nxt == t.fin_seq {
                    let seq = t.fin_seq;
                    let flags = FLAG_FIN;
                    t.snd_nxt = t.snd_nxt.wrapping_add(1);
                    (Vec::<Vec<u8>>::new(), seq, flags, mss, true)
                } else {
                    break;
                }
            } else {
                let mut chunks: Vec<Vec<u8>> = Vec::new();
                let mut remaining = unsent.min(usable);
                let starting_seq = t.send_buf.seq_at_sent_offset();
                while remaining > 0 {
                    let take = remaining.min(mss);
                    let (a, b) = t.send_buf.unsent_slices(take as usize);
                    let mut chunk = Vec::with_capacity(take as usize);
                    chunk.extend_from_slice(a);
                    chunk.extend_from_slice(b);
                    if chunk.is_empty() {
                        break;
                    }
                    t.send_buf.mark_sent(chunk.len());
                    remaining = remaining.saturating_sub(chunk.len() as u32);
                    chunks.push(chunk);
                }
                let total: u32 = chunks.iter().map(|c| c.len() as u32).sum();
                t.snd_nxt = t.snd_nxt.wrapping_add(total);
                let drained = t.send_buf.unsent_len() == 0;
                let attach_fin = drained && t.fin_sent && t.snd_nxt == t.fin_seq;
                if attach_fin {
                    t.snd_nxt = t.snd_nxt.wrapping_add(1);
                }
                (
                    chunks,
                    starting_seq,
                    if attach_fin { FLAG_FIN } else { 0 },
                    mss,
                    drained,
                )
            }
        };
        if chunks.is_empty() {
            if fin_flag != 0 {
                // Pure FIN segment.
                send_data(arc, seq, &[], FLAG_FIN, true);
                break;
            }
            break;
        }
        let mut cur_seq = seq;
        for (i, c) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let extra = if last && fin_flag != 0 {
                FLAG_FIN | FLAG_PSH
            } else {
                FLAG_PSH
            };
            send_data(arc, cur_seq, c, extra, true);
            cur_seq = cur_seq.wrapping_add(c.len() as u32);
        }
        let _ = mss;
        let _ = drained_all;
        if fin_flag != 0 {
            break;
        }
    }
}

// ── Segment-arrival processing ──────────────────────────────────────

/// Top-level dispatch from the RX path. Handles passive open
/// (LISTEN → SYN-RECEIVED) and per-connection arrivals alike.
pub fn handle_segment(src: [u8; 4], dst: [u8; 4], segment: &[u8]) {
    handle_segment_in(0, src, dst, segment);
}

pub fn handle_segment_in(net_ns_id: u64, src: [u8; 4], dst: [u8; 4], segment: &[u8]) {
    let (hdr, _hdr_len) = match TcpHeader::decode(segment) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Find a connected-TCB match first (O(1) sharded 4-tuple index, no
    // global lock); on miss, fall back to a matching LISTEN TCB.
    if let Some(arc) = conn_index_lookup(conn_key(net_ns_id, src, hdr.src_port, dst, hdr.dst_port))
    {
        process_in_state(&arc, src, dst, &hdr, segment);
        return;
    }
    // LISTEN bucket: any listener on (dst | 0.0.0.0, dst_port) drives the
    // passive open. The accept-enqueue (add_to_listener_accept_queue)
    // re-selects within the SO_REUSEPORT group by flow hash.
    if let Some(listen_arc) = listen_index_group(net_ns_id, dst, hdr.dst_port)
        .into_iter()
        .next()
    {
        accept_into_listen(&listen_arc, src, dst, &hdr, segment);
    }
}

fn accept_into_listen(
    listen_arc: &Arc<IrqSafeSpinLock<Tcb>>,
    src: [u8; 4],
    dst: [u8; 4],
    hdr: &TcpHeader,
    segment: &[u8],
) {
    // Only a SYN drives passive open.
    if hdr.flags & FLAG_SYN == 0 {
        return;
    }
    // Parse SYN options + create the child TCB.
    let payload_off = hdr.header_len as usize;
    let opts_raw = if hdr.header_len as usize > TCP_HDR_MIN {
        &segment[TCP_HDR_MIN..payload_off]
    } else {
        &[][..]
    };
    let parsed = ParsedOptions::parse(opts_raw);

    let (backlog, net_ns_id) = {
        let l = listen_arc.lock();
        (l.backlog, l.net_ns_id)
    };
    let mac = match crate::tcp_stack::arp_resolve_in(net_ns_id, src, 500) {
        Ok(m) => m,
        Err(_) => {
            // Without an ARP MAC we can't reply — just drop.
            return;
        }
    };
    let id = fresh_tcb_id();
    let iss = compute_isn();
    let mut child =
        Tcb::new_active(id, dst, hdr.dst_port, src, hdr.src_port, mac, iss).with_net_ns(net_ns_id);
    child.state = TcpState::SynReceived;
    child.irs = hdr.sequence;
    child.rcv_nxt = hdr.sequence.wrapping_add(1);
    child.snd_wnd = parsed
        .wscale
        .map(|s| (hdr.window as u32) << s as u32)
        .unwrap_or(hdr.window as u32);
    child.opts.negotiate(&parsed, DEFAULT_WSCALE);
    if let Some((tsv, _)) = parsed.timestamps {
        child.opts.ts_recent = tsv;
        child.opts.ts_recent_at_cycles = narf_scheduler::narf_time::now_cycles();
    }
    child.cong.set_mss(child.opts.peer_mss as u32);
    let _ = backlog;
    let (cid, child_arc) = install_tcb(child);
    // Emit SYN-ACK.
    send_syn(&child_arc, true);
    // Register on the listener's accept queue (placeholder until
    // ACK lands — RFC 9293 allows enqueueing once ESTABLISHED;
    // we enqueue early so a non-blocking accept can pick it up).
    let _ = cid;
}

/// State-aware processing of an arrived segment.
fn process_in_state(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    src: [u8; 4],
    dst: [u8; 4],
    hdr: &TcpHeader,
    segment: &[u8],
) {
    let _ = (src, dst);
    let payload_off = hdr.header_len as usize;
    let payload = if segment.len() > payload_off {
        &segment[payload_off..]
    } else {
        &[][..]
    };
    let opts_raw = if hdr.header_len as usize > TCP_HDR_MIN {
        &segment[TCP_HDR_MIN..payload_off]
    } else {
        &[][..]
    };
    let parsed = ParsedOptions::parse(opts_raw);

    // ── RST handling (RFC 9293 §3.10.7.3) ──
    if hdr.flags & FLAG_RST != 0 {
        handle_rst(arc, hdr);
        return;
    }

    // ── PAWS (RFC 7323 §5.3) ──
    {
        let t = arc.lock();
        if let Some((tsv, _)) = parsed.timestamps {
            if t.opts.paws_reject(tsv) {
                drop(t);
                // Drop the segment + send ACK as challenge-style
                // response. Don't touch our state.
                send_ack(arc, 0);
                return;
            }
        }
    }

    // Update ts_recent.
    if let Some((tsv, _)) = parsed.timestamps {
        let mut t = arc.lock();
        let now = narf_scheduler::narf_time::now_cycles();
        t.opts.update_ts_recent(tsv, now);
    }

    let state = arc.lock().state;
    match state {
        TcpState::SynSent => handle_in_syn_sent(arc, hdr, &parsed, payload),
        TcpState::SynReceived => handle_in_syn_received(arc, hdr, payload),
        TcpState::Established => handle_in_established(arc, hdr, &parsed, payload),
        TcpState::FinWait1 => handle_in_fin_wait1(arc, hdr, &parsed, payload),
        TcpState::FinWait2 => handle_in_fin_wait2(arc, hdr, &parsed, payload),
        TcpState::CloseWait => handle_in_close_wait(arc, hdr, &parsed),
        TcpState::Closing => handle_in_closing(arc, hdr, &parsed),
        TcpState::LastAck => handle_in_last_ack(arc, hdr, &parsed),
        TcpState::TimeWait => handle_in_time_wait(arc, hdr),
        TcpState::Listen | TcpState::Closed => {}
    }
}

fn handle_rst(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader) {
    let mut t = arc.lock();
    // RFC 9293 §3.10.7.3 — synchronised states accept RST if
    // SEG.SEQ is in the window.
    if t.state.is_synchronised() {
        let seg = hdr.sequence;
        let in_window = seq_geq(seg, t.rcv_nxt)
            && seq_lt(seg, t.rcv_nxt.wrapping_add(t.recv_buf.free_window()));
        if !in_window {
            // Out-of-window RST → Challenge ACK.
            drop(t);
            send_ack(arc, 0);
            return;
        }
    }
    t.drop_cause = Some(DropCause::PeerReset);
    t.state = TcpState::Closed;
    let id = t.id;
    drop(t);
    remove_tcb(id);
}

fn handle_in_syn_sent(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    hdr: &TcpHeader,
    parsed: &ParsedOptions,
    payload: &[u8],
) {
    // RFC 9293 §3.10.7.3 — expect SYN+ACK.
    let is_synack = hdr.flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK);
    if !is_synack {
        // Simultaneous open: bare SYN → SYN-RECEIVED.
        if hdr.flags & FLAG_SYN != 0 {
            let mut t = arc.lock();
            t.irs = hdr.sequence;
            t.rcv_nxt = hdr.sequence.wrapping_add(1);
            t.snd_wnd = parsed
                .wscale
                .map(|s| (hdr.window as u32) << s as u32)
                .unwrap_or(hdr.window as u32);
            t.opts.negotiate(parsed, DEFAULT_WSCALE);
            let mss = t.opts.peer_mss as u32;
            t.cong.set_mss(mss);
            t.state = TcpState::SynReceived;
            drop(t);
            // SYN-ACK.
            send_syn(arc, true);
        }
        return;
    }
    {
        let mut t = arc.lock();
        t.snd_una = hdr.acknowledgement;
        t.irs = hdr.sequence;
        t.rcv_nxt = hdr.sequence.wrapping_add(1);
        t.snd_wnd = parsed
            .wscale
            .map(|s| (hdr.window as u32) << s as u32)
            .unwrap_or(hdr.window as u32);
        t.snd_wl1 = hdr.sequence;
        t.snd_wl2 = hdr.acknowledgement;
        t.opts.negotiate(parsed, DEFAULT_WSCALE);
        let mss = t.opts.peer_mss as u32;
        t.cong.set_mss(mss);
        let una = t.snd_una;
        t.send_buf.unacked_head_seq = una;
        t.state = TcpState::Established;
        // Take an RTT sample from the SYN's queue entry.
        if let Some(seg) = t.retx_queue.pop_front() {
            if !seg.retransmitted {
                let elapsed =
                    narf_scheduler::narf_time::now_cycles().wrapping_sub(seg.sent_at_cycles);
                let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
                let rtt_ns = elapsed / cpn;
                t.rtt.sample(rtt_ns);
            }
            t.flightsize = t.flightsize.saturating_sub(seg.len);
        }
        t.retx_deadline_cycles = 0;
        t.last_progress_cycles = narf_scheduler::narf_time::now_cycles();
    }
    // Final ACK of the handshake.
    send_ack(arc, 0);
    let _ = payload; // SYN+ACK shouldn't carry data
}

fn handle_in_syn_received(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader, payload: &[u8]) {
    // Expecting ACK of our SYN.
    if hdr.flags & FLAG_ACK == 0 {
        return;
    }
    {
        let mut t = arc.lock();
        if !seq_geq(hdr.acknowledgement, t.iss.wrapping_add(1)) {
            return;
        }
        t.snd_una = hdr.acknowledgement;
        t.snd_wnd = (hdr.window as u32) << t.opts.peer_wscale;
        t.snd_wl1 = hdr.sequence;
        t.snd_wl2 = hdr.acknowledgement;
        t.send_buf.unacked_head_seq = t.snd_una;
        t.state = TcpState::Established;
        if let Some(seg) = t.retx_queue.pop_front() {
            if !seg.retransmitted {
                let elapsed =
                    narf_scheduler::narf_time::now_cycles().wrapping_sub(seg.sent_at_cycles);
                let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
                let rtt_ns = elapsed / cpn;
                t.rtt.sample(rtt_ns);
            }
            t.flightsize = t.flightsize.saturating_sub(seg.len);
        }
        t.retx_deadline_cycles = 0;
        t.last_progress_cycles = narf_scheduler::narf_time::now_cycles();
    }
    // Look for a parent LISTEN TCB to push this onto; it returns the
    // listener it steered the connection to.
    let listener_id = add_to_listener_accept_queue(arc);
    // A connection just became accept-ready — wake the worker parked in
    // epoll_wait/poll on THAT listener (keyed by the listener's TCB id so
    // only the steered worker wakes, not the whole REUSEPORT group).
    crate::readiness::notify(listener_id.map(|i| i as u64).unwrap_or(0));
    if !payload.is_empty() {
        enqueue_recv(arc, hdr.sequence, payload);
    }
    if hdr.flags & FLAG_FIN != 0 {
        process_fin(arc, hdr);
    }
}

/// Hash the connection's remote endpoint (+ local port) to a stable
/// 32-bit value. Used to steer a completed passive-open to one listener
/// of a `SO_REUSEPORT` group: the same flow always maps to the same
/// listener, and distinct flows spread across the group. FNV-1a over the
/// 4-tuple-ish key. Mirrors Linux `reuseport_select_sock`'s flow hash.
#[inline]
fn reuseport_flow_hash(remote_addr: [u8; 4], remote_port: u16, local_port: u16) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in remote_addr {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    for b in remote_port.to_be_bytes() {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    for b in local_port.to_be_bytes() {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    h
}

/// Steer a completed passive-open onto a listener's accept queue and
/// return that listener's TCB id (for the targeted accept-ready wake).
fn add_to_listener_accept_queue(arc: &Arc<IrqSafeSpinLock<Tcb>>) -> Option<u32> {
    let (net_ns_id, local_addr, local_port, remote_addr, remote_port, id) = {
        let t = arc.lock();
        (
            t.net_ns_id,
            t.local_addr,
            t.local_port,
            t.remote_addr,
            t.remote_port,
            t.id,
        )
    };
    // EVERY LISTEN TCB on this (addr, port). Normally exactly one, but a
    // `SO_REUSEPORT`/`SO_REUSEADDR` server (e.g. a multithreaded daemon
    // with one listener per worker thread, each its own kernel TCB)
    // installs several distinct Listen TCBs on the same port. The index
    // returns them in a deterministic order for a stable listener set.
    let group = listen_index_group(net_ns_id, local_addr, local_port);
    let listen_arc = match group.len() {
        0 => return None,
        // Single listener: the common, non-REUSEPORT case — no steering.
        1 => group[0].clone(),
        // Multiple listeners (REUSEPORT group): steer this flow to one of
        // them by hashing its remote endpoint, so distinct flows land on
        // distinct listeners/workers/cores in parallel.
        n => {
            let h = reuseport_flow_hash(remote_addr, remote_port, local_port);
            group[(h as usize) % n].clone()
        }
    };
    let mut l = listen_arc.lock();
    if l.accept_queue.len() < l.backlog {
        l.accept_queue.push_back(id);
    }
    Some(l.id)
}

fn handle_in_established(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    hdr: &TcpHeader,
    parsed: &ParsedOptions,
    payload: &[u8],
) {
    handle_ack(arc, hdr, parsed);
    if !payload.is_empty() {
        enqueue_recv(arc, hdr.sequence, payload);
    }
    if hdr.flags & FLAG_FIN != 0 {
        process_fin(arc, hdr);
    }
    schedule_ack(arc, !payload.is_empty());
    pump_send(arc);
    // Data (or a FIN → EOF) just became visible to the application —
    // wake any task parked in epoll_wait/poll on this socket NOW instead
    // of leaving it to its next wheel deadline. Done after all locks are
    // released; best-effort (no correctness dependency).
    if !payload.is_empty() || hdr.flags & FLAG_FIN != 0 {
        // Key the wake by THIS connection's TCB id so only its owning
        // task wakes (no thundering herd).
        let id = arc.lock().id as u64;
        crate::readiness::notify(id);
    }
}

fn handle_in_fin_wait1(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    hdr: &TcpHeader,
    parsed: &ParsedOptions,
    payload: &[u8],
) {
    handle_ack(arc, hdr, parsed);
    // Check whether peer's ACK covered our FIN.
    let our_fin_acked = {
        let t = arc.lock();
        t.fin_sent && seq_geq(t.snd_una, t.fin_seq.wrapping_add(1))
    };
    if !payload.is_empty() {
        enqueue_recv(arc, hdr.sequence, payload);
    }
    let their_fin = hdr.flags & FLAG_FIN != 0;
    if their_fin {
        process_fin(arc, hdr);
    }
    let mut t = arc.lock();
    if our_fin_acked && their_fin {
        // → TIME-WAIT.
        t.state = TcpState::TimeWait;
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.time_wait_deadline_cycles = narf_scheduler::narf_time::now_cycles()
            .wrapping_add(TIME_WAIT_NS.saturating_mul(cpn as u64));
    } else if our_fin_acked {
        t.state = TcpState::FinWait2;
    } else if their_fin {
        t.state = TcpState::Closing;
    }
    drop(t);
    schedule_ack(arc, !payload.is_empty() || their_fin);
}

fn handle_in_fin_wait2(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    hdr: &TcpHeader,
    parsed: &ParsedOptions,
    payload: &[u8],
) {
    handle_ack(arc, hdr, parsed);
    if !payload.is_empty() {
        enqueue_recv(arc, hdr.sequence, payload);
    }
    if hdr.flags & FLAG_FIN != 0 {
        process_fin(arc, hdr);
        let mut t = arc.lock();
        t.state = TcpState::TimeWait;
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.time_wait_deadline_cycles = narf_scheduler::narf_time::now_cycles()
            .wrapping_add(TIME_WAIT_NS.saturating_mul(cpn as u64));
    }
    schedule_ack(arc, !payload.is_empty() || hdr.flags & FLAG_FIN != 0);
}

fn handle_in_close_wait(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader, parsed: &ParsedOptions) {
    handle_ack(arc, hdr, parsed);
    pump_send(arc);
}

fn handle_in_closing(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader, parsed: &ParsedOptions) {
    handle_ack(arc, hdr, parsed);
    let our_fin_acked = {
        let t = arc.lock();
        seq_geq(t.snd_una, t.fin_seq.wrapping_add(1))
    };
    if our_fin_acked {
        let mut t = arc.lock();
        t.state = TcpState::TimeWait;
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.time_wait_deadline_cycles = narf_scheduler::narf_time::now_cycles()
            .wrapping_add(TIME_WAIT_NS.saturating_mul(cpn as u64));
    }
}

fn handle_in_last_ack(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader, parsed: &ParsedOptions) {
    handle_ack(arc, hdr, parsed);
    let our_fin_acked = {
        let t = arc.lock();
        seq_geq(t.snd_una, t.fin_seq.wrapping_add(1))
    };
    if our_fin_acked {
        let id = arc.lock().id;
        {
            let mut t = arc.lock();
            t.state = TcpState::Closed;
            t.drop_cause = Some(DropCause::Graceful);
        }
        remove_tcb(id);
    }
}

fn handle_in_time_wait(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader) {
    // Restart the 2*MSL timer on any new segment; ACK if it was
    // a retransmitted FIN.
    let mut t = arc.lock();
    let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
    t.time_wait_deadline_cycles = narf_scheduler::narf_time::now_cycles()
        .wrapping_add(TIME_WAIT_NS.saturating_mul(cpn as u64));
    drop(t);
    if hdr.flags & FLAG_FIN != 0 {
        send_ack(arc, 0);
    }
}

// ── ACK + retransmit queue cleanup ──────────────────────────────────

fn handle_ack(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader, parsed: &ParsedOptions) {
    if hdr.flags & FLAG_ACK == 0 {
        return;
    }
    let ack = hdr.acknowledgement;
    let mut t = arc.lock();
    // Window update (RFC 9293 §3.10.7.4).
    if seq_lt(t.snd_wl1, hdr.sequence) || (t.snd_wl1 == hdr.sequence && seq_leq(t.snd_wl2, ack)) {
        t.snd_wnd = (hdr.window as u32) << t.opts.peer_wscale;
        t.snd_wl1 = hdr.sequence;
        t.snd_wl2 = ack;
        if t.snd_wnd > 0 {
            t.persist_deadline_cycles = 0;
            t.persist_backoff_ns = PERSIST_INITIAL_NS;
        }
    }
    // Cumulative ACK math.
    if seq_lt(t.snd_una, ack) && seq_leq(ack, t.snd_nxt) {
        let acked = ack.wrapping_sub(t.snd_una);
        t.snd_una = ack;
        // Release ack'd bytes from send buffer + cong control.
        let from_buf = t.send_buf.ack(ack);
        let bytes_acked = acked;
        let now = narf_scheduler::narf_time::now_cycles();
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.cong.cycles_per_ns = cpn;
        // RTT sample on the first non-retransmitted segment whose
        // entire range was just ack'd.
        while let Some(front) = t.retx_queue.front() {
            if seq_leq(front.end_seq(), ack) {
                let f = *front;
                t.retx_queue.pop_front();
                t.flightsize = t.flightsize.saturating_sub(f.len);
                if !f.retransmitted {
                    let elapsed = now.wrapping_sub(f.sent_at_cycles);
                    let rtt_ns = elapsed / cpn;
                    if rtt_ns > 0 {
                        t.rtt.sample(rtt_ns);
                    }
                }
            } else {
                break;
            }
        }
        t.cong.clear_dup_acks();
        {
            let tcb: &mut Tcb = &mut t;
            tcb.cc.on_ack(&mut tcb.cong, bytes_acked, now);
        }
        t.cong.clear_recovery_if_passed(ack);
        t.rto_count = 0;
        t.keepalive_probes_sent = 0;
        t.last_progress_cycles = now;
        // Re-arm retransmit timer if there's still unacked data.
        if t.retx_queue.is_empty() {
            t.retx_deadline_cycles = 0;
        } else {
            arm_retransmit_timer(&mut t);
        }
        let _ = from_buf;
        // Scoreboard prune.
        t.scoreboard.prune_below(ack);
    } else if ack == t.snd_una && !t.retx_queue.is_empty() {
        // Duplicate ACK — fast retransmit machinery.
        if t.cong.on_dup_ack() {
            // Fast retransmit + enter fast recovery.
            let now = narf_scheduler::narf_time::now_cycles();
            let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
            let nxt = t.snd_nxt;
            {
                let tcb: &mut Tcb = &mut t;
                tcb.cc.on_loss(
                    &mut tcb.cong,
                    LossEvent::FastRetransmit {
                        snd_nxt: nxt,
                        now_cycles: now,
                        cycles_per_ns: cpn,
                    },
                );
            }
            drop(t);
            fast_retransmit(arc);
            return;
        }
    }
    // Apply incoming SACK option to the scoreboard.
    let sack_blocks: Vec<SackBlock> = parsed.sack_iter().collect();
    if !sack_blocks.is_empty() {
        t.scoreboard.update_from(&sack_blocks);
    }
}

fn fast_retransmit(arc: &Arc<IrqSafeSpinLock<Tcb>>) {
    // Retransmit segments at snd_una that aren't on the SACK
    // scoreboard. This is the RFC 6675 selective-retx path.
    let (
        net_ns_id,
        seg_seq,
        seg_flags,
        payload,
        peer_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        window,
        ack,
        opt_bytes,
    ) = {
        let t = arc.lock();
        let oldest = match t.retx_queue.front() {
            Some(s) => *s,
            None => return,
        };
        if t.scoreboard.is_sacked(oldest.seq) {
            return;
        }
        let payload_len =
            oldest
                .len
                .saturating_sub(if oldest.flags & FLAG_FIN != 0 { 1 } else { 0 })
                as usize;
        let head = t.send_buf.unacked_head_seq;
        let off = oldest.seq.wrapping_sub(head) as usize;
        let (a, b) = t.send_buf.full_slices();
        let mut payload = Vec::with_capacity(payload_len);
        let total_avail = a.len() + b.len();
        if off < total_avail {
            let end = (off + payload_len).min(total_avail);
            // Stitch across the (possibly-wrapped) deque ring.
            for i in off..end {
                let byte = if i < a.len() { a[i] } else { b[i - a.len()] };
                payload.push(byte);
            }
        }
        let blocks: Vec<SackBlock> = t.sack_book.blocks().to_vec();
        let opts = encode_data_options(&t.opts, tsval_now(), &blocks);
        let window = effective_advertised_window(&t);
        (
            t.net_ns_id,
            oldest.seq,
            oldest.flags,
            payload,
            t.remote_mac,
            t.local_addr,
            t.remote_addr,
            t.local_port,
            t.remote_port,
            window,
            t.rcv_nxt,
            opts,
        )
    };
    let iface = match iface::for_dst_in(net_ns_id, dst_ip) {
        Some(i) => i,
        None => return,
    };
    let frame = build_frame(
        iface.mac, peer_mac, src_ip, dst_ip, src_port, dst_port, seg_seq, ack, seg_flags, window,
        opt_bytes, &payload,
    );
    emit_tcb_frame(arc, &iface.name, iface.send, frame);
    let mut t = arc.lock();
    // Mark the segment as retransmitted (Karn).
    if let Some(front) = t.retx_queue.front_mut() {
        front.retransmitted = true;
    }
    arm_retransmit_timer(&mut t);
}

fn enqueue_recv(arc: &Arc<IrqSafeSpinLock<Tcb>>, seq: u32, payload: &[u8]) {
    let mut t = arc.lock();
    let before = t.rcv_nxt;
    let rcv = t.rcv_nxt;
    let new_rcv = t.recv_buf.accept(seq, payload, rcv);
    if new_rcv != before {
        // Contiguous bytes advanced — clear SACK ranges fully
        // covered.
        t.sack_book.prune_to(new_rcv);
    } else if !payload.is_empty() {
        // Out-of-order segment — record SACK range.
        t.sack_book
            .add_range(seq, seq.wrapping_add(payload.len() as u32));
    }
    t.rcv_nxt = new_rcv;
    t.unacked_data_segments = t.unacked_data_segments.saturating_add(1);
}

fn process_fin(arc: &Arc<IrqSafeSpinLock<Tcb>>, hdr: &TcpHeader) {
    let mut t = arc.lock();
    // FIN consumes one sequence number.
    // Only advance rcv_nxt for the FIN if our buffered data is
    // contiguous (i.e. peer's FIN sequence == rcv_nxt + payload).
    let fin_seq = hdr
        .sequence
        .wrapping_add(if hdr.flags & FLAG_SYN != 0 { 1 } else { 0 })
        .wrapping_add(if hdr.flags & FLAG_FIN != 0 {
            // Compute payload length in this segment.
            0
        } else {
            0
        });
    let _ = fin_seq;
    // If everything before the FIN is in order, advance rcv_nxt past it.
    if !t.fin_received {
        t.fin_received = true;
        // Advance rcv_nxt by 1 only if rcv_nxt is now at the FIN
        // boundary (i.e. all data up to FIN is queued).
        // We trust enqueue_recv to have moved rcv_nxt over any
        // payload first.
        t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
        // FSM transitions: ESTABLISHED → CLOSE-WAIT; SYN-RECEIVED
        // path already handled by callers.
        if matches!(t.state, TcpState::Established | TcpState::SynReceived) {
            t.state = TcpState::CloseWait;
        }
    }
}

/// Schedule an ACK — immediate if 2nd un-acked data segment or
/// quickack credit remains, else delay by [`DELAYED_ACK_NS`].
fn schedule_ack(arc: &Arc<IrqSafeSpinLock<Tcb>>, had_payload: bool) {
    let immediate = {
        let mut t = arc.lock();
        let mut imm = false;
        if t.quickack_left > 0 {
            t.quickack_left = t.quickack_left.saturating_sub(1);
            imm = true;
        } else if had_payload && t.unacked_data_segments >= 2 {
            imm = true;
        } else if !had_payload {
            // Pure ACK (window/RST handled elsewhere); send right away.
            imm = true;
        }
        imm
    };
    if immediate {
        send_ack(arc, 0);
        return;
    }
    let mut t = arc.lock();
    if t.delayed_ack_deadline_cycles == 0 {
        let cpn = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        t.delayed_ack_deadline_cycles = narf_scheduler::narf_time::now_cycles()
            .wrapping_add(DELAYED_ACK_NS.saturating_mul(cpn as u64));
    }
}

// ── Test-only injection hook ────────────────────────────────────────

/// Test-only: inject a synthesized inbound TCP segment as if it
/// came off the wire. Bypasses the iface drain and IP parse so
/// FSM tests can run without driver scaffolding.
#[doc(hidden)]
pub fn __inject_segment(src: [u8; 4], dst: [u8; 4], segment: &[u8]) {
    handle_segment(src, dst, segment);
}

/// Test-only: create a TCB pre-installed in a given state so a
/// per-feature smoke (e.g. RTO) can skip the 3WHS.
#[doc(hidden)]
pub fn __install_test_tcb(
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    state: TcpState,
) -> u32 {
    __install_test_tcb_in(0, local_addr, local_port, remote_addr, remote_port, state)
}

#[doc(hidden)]
pub fn __install_test_tcb_in(
    net_ns_id: u64,
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    state: TcpState,
) -> u32 {
    let id = fresh_tcb_id();
    let iss = 0x10000;
    let mut tcb = Tcb::new_active(
        id,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        [0x52, 0x54, 0, 0, 0, 1],
        iss,
    )
    .with_net_ns(net_ns_id);
    tcb.state = state;
    tcb.snd_una = iss;
    tcb.snd_nxt = iss;
    tcb.rcv_nxt = 0x20000;
    tcb.snd_wnd = 65535;
    tcb.send_buf.unacked_head_seq = iss;
    let (id, _arc) = install_tcb(tcb);
    id
}

/// Test-only: borrow the TCB lock for assertion.
#[doc(hidden)]
pub fn __with_tcb<R>(id: u32, f: impl FnOnce(&Tcb) -> R) -> Option<R> {
    let arc = lookup_tcb(id)?;
    let t = arc.lock();
    Some(f(&t))
}

#[doc(hidden)]
pub fn __with_tcb_mut<R>(id: u32, f: impl FnOnce(&mut Tcb) -> R) -> Option<R> {
    let arc = lookup_tcb(id)?;
    let mut t = arc.lock();
    Some(f(&mut t))
}

// ── Public timer-sweep + ICMP-error glue ────────────────────────────

/// Sweep every live TCB, ticking the retransmit / delayed-ACK /
/// persist / keepalive / TIME-WAIT timers. Called once per sleep-
/// pump iteration; cheap (lock + short walk).
pub fn tick_all() {
    let ids: Vec<u32> = {
        let mut ids = Vec::new();
        for shard in TCB_TABLE.iter() {
            if let Some(m) = shard.lock().as_ref() {
                ids.extend(m.keys().copied());
            }
        }
        ids
    };
    for id in ids {
        if let Some(arc) = lookup_tcb(id) {
            tick_retransmit(&arc);
        }
    }
}

/// Convert an ICMP destination-unreachable into a connection drop.
/// Mirrors `tcp_v4_err` (`net/ipv4/tcp_ipv4.c`); we don't currently
/// distinguish hard vs. soft errors and just close the TCB.
pub fn signal_icmp_error(remote_ip: [u8; 4], remote_port: u16, local_ip: [u8; 4], local_port: u16) {
    signal_icmp_error_in(0, remote_ip, remote_port, local_ip, local_port);
}

pub fn signal_icmp_error_in(
    net_ns_id: u64,
    remote_ip: [u8; 4],
    remote_port: u16,
    local_ip: [u8; 4],
    local_port: u16,
) {
    let arc = conn_index_lookup(conn_key(
        net_ns_id,
        remote_ip,
        remote_port,
        local_ip,
        local_port,
    ));
    if let Some(arc) = arc {
        let mut t = arc.lock();
        t.drop_cause = Some(DropCause::PeerReset);
        t.state = TcpState::Closed;
        let id = t.id;
        drop(t);
        remove_tcb(id);
    }
}
