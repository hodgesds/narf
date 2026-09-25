//! Two-endpoint end-to-end smokes for the NARF TCP stack.
//!
//! ## Why this file exists
//!
//! Every other TCP smoke (`e2e_tests.rs`, `tcp_timer_e2e_tests.rs`, the
//! unit smokes in `tests.rs`) plays the *peer* by hand: it synthesises one
//! segment, injects it, and inspects the single reply. That checks each
//! transition in isolation but never lets two real TCBs negotiate with each
//! other — the client side of `smoke_e2e_tcp_loopback_round_trip` does not
//! even exist ("there is no client TCB in the table").
//!
//! Here both ends are the real stack. The active side goes through
//! `connect`, the passive side through `listen`/`accept`, and every segment
//! either side emits travels over a **virtual wire** back into the full RX
//! path (`tcp_stack::rx_handler`: Ethernet → netfilter → IPv4 → TCP). The
//! wire can drop, reorder, or duplicate segments, so the recovery machinery
//! (RTO, fast retransmit, reassembly, persist) is exercised against the
//! stack's own peer rather than a scripted one.
//!
//! ## Harness
//!
//! - **Wire.** The test interface's `SendFn` (`wire_send`) queues each frame
//!   after consulting the active [`Fault`]. `deliver_one` pops a frame and
//!   runs it through `rx_handler`. `wire_drain` is also registered as an RX
//!   drain so the busy-wait inside `connect` pumps the wire itself.
//! - **Virtual clock.** Nothing waits on wall time. When the wire is quiet,
//!   `advance_clock` jumps to the next pending timer class — delayed ACKs
//!   first, then RTO / persist — by expiring that deadline and ticking the
//!   TCB. So a lost segment is recovered at the next "RTO" deterministically,
//!   and a stall (nothing on the wire, no timer pending, work unfinished) is
//!   reported as a failure instead of hanging.
//! - **Addresses.** Client and server sit on distinct IPs of one interface
//!   (`CLIENT_IP` is the primary, `SERVER_IP` a secondary), so the 4-tuples
//!   of the two TCBs are genuinely mirrored rather than equal.
//!
//! ## Linux refs
//!
//! - `tools/testing/selftests/net/tcp_*` and packetdrill's two-stack mode
//!   are the models: real sockets on both ends, faults injected on the link.
//! - `net/ipv4/tcp_ipv4.c::tcp_v4_send_reset` — RST for segments that match
//!   no socket (the refused-connect case below).

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::arp_cache;
use crate::iface;
use crate::pkt::{ETHERTYPE_IPV4, ETH_HDR_LEN, IP_PROTO_TCP};
use crate::pkt_tcp::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::route;
use crate::tcp::core::{
    self as tcp_core, __with_tcb, __with_tcb_mut, accept, close, connect, listen, lookup_tcb, recv,
    send, shutdown, tick_retransmit,
};
use crate::tcp::state_machine::{Shutdown, TcpState};

// ── Topology ────────────────────────────────────────────────────────────────

const IFACE: &str = "tcpe2e0";
const IFACE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x77, 0x01];
const CLIENT_IP: [u8; 4] = [10, 0, 77, 1];
const SERVER_IP: [u8; 4] = [10, 0, 77, 2];
const SERVER_PORT: u16 = 18_080;
/// A port nothing listens on — the refused-connect target.
const CLOSED_PORT: u16 = 18_081;
/// An on-link router that originates ICMP errors.
const ROUTER_IP: [u8; 4] = [10, 0, 77, 254];

/// Upper bound on TCB ids scanned by the virtual clock. `__reset_for_test`
/// restarts ids at 1 and no smoke here creates more than a few dozen.
const MAX_TCB_ID: u32 = 128;

/// Harness-loop iteration budgets. One iteration delivers one frame or
/// fires one timer class, so these are frame counts, not wall time.
const BUDGET_SMALL: u32 = 20_000;
const BUDGET_BULK: u32 = 400_000;

// ── Segment metadata ────────────────────────────────────────────────────────

/// What the wire saw for one frame. Logged for every frame offered to the
/// wire, including the ones a [`Fault`] then dropped.
#[derive(Clone, Copy, Debug)]
struct Seg {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload_len: usize,
    dropped: bool,
}

impl Seg {
    fn has(&self, flags: u8) -> bool {
        self.flags & flags == flags
    }
    fn dir(&self) -> Dir {
        if self.dst_port == SERVER_PORT || self.dst_port == CLOSED_PORT {
            Dir::ToServer
        } else {
            Dir::ToClient
        }
    }
}

/// Parse the TCP header fields out of an Ethernet + IPv4 + TCP frame.
fn parse_seg(frame: &[u8]) -> Option<Seg> {
    if frame.len() < ETH_HDR_LEN + 20 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETH_HDR_LEN..];
    if ip[9] != IP_PROTO_TCP {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total > ip.len() || total < ihl + 20 {
        return None;
    }
    let tcp = &ip[ihl..total];
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > tcp.len() {
        return None;
    }
    Some(Seg {
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
        payload_len: tcp.len() - data_off,
        dropped: false,
    })
}

// ── Fault injection ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
    Any,
}

impl Dir {
    fn matches(self, seg: &Seg) -> bool {
        self == Dir::Any || self == seg.dir()
    }
}

/// Link impairment applied by `wire_send`.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Perfect link.
    None,
    /// Drop the `nth` (0-based) data-bearing segment travelling in `dir`.
    DropNthData { dir: Dir, nth: u32 },
    /// Drop the next `count` segments in `dir` whose flag byte, masked to
    /// SYN|ACK|FIN|RST, equals `flags` *and* that carry no payload.
    DropControl { dir: Dir, flags: u8, count: u32 },
    /// Deliver data segments in `dir` pairwise swapped (n+1 before n).
    SwapData { dir: Dir },
    /// Deliver every data segment in `dir` twice.
    DuplicateData { dir: Dir },
    /// Drop each segment (any kind, either direction) with probability
    /// `per_mille / 1000`, from a deterministic xorshift stream.
    RandomLoss { per_mille: u32 },
    /// Answer the next `count` bare SYNs with an ICMP destination-unreachable
    /// of `code` (from `ROUTER_IP`) instead of delivering them — a router
    /// refusing the path.
    IcmpOnSyn { code: u8, count: u32 },
}

struct Wire {
    queue: VecDeque<Vec<u8>>,
    /// Data segment held back by `Fault::SwapData`, waiting for its successor.
    held: Option<Vec<u8>>,
    log: Vec<Seg>,
    fault: Fault,
    /// Data segments seen so far per direction (index: 0 = to server).
    data_seen: [u32; 2],
    rng: u32,
}

impl Wire {
    const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            held: None,
            log: Vec::new(),
            fault: Fault::None,
            data_seen: [0; 2],
            rng: 0x9e37_79b9,
        }
    }

    fn next_rand(&mut self) -> u32 {
        // xorshift32 — deterministic so a failing seed replays exactly.
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }
}

static WIRE: IrqSafeSpinLock<Wire> = IrqSafeSpinLock::new(Wire::new());
/// When set, a quiet `wire_drain` advances the virtual clock. Lets the
/// busy-wait inside `connect` recover a lost SYN / SYN-ACK without waiting
/// out a real RTO.
static FFWD: AtomicBool = AtomicBool::new(false);
static DRAIN_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Number of RTO / persist firings the virtual clock forced.
static FORCED_RTOS: AtomicU32 = AtomicU32::new(0);

/// `SendFn` of the test interface: log the frame, apply the fault, queue it.
fn wire_send(frame: &[u8]) -> Result<(), ()> {
    let mut w = WIRE.lock();
    let Some(mut seg) = parse_seg(frame) else {
        // Non-TCP (e.g. ARP) — deliver untouched.
        w.queue.push_back(frame.to_vec());
        return Ok(());
    };
    let is_data = seg.payload_len > 0;
    let dir_idx = if seg.dir() == Dir::ToServer { 0 } else { 1 };
    let nth_data = w.data_seen[dir_idx];
    if is_data {
        w.data_seen[dir_idx] += 1;
    }

    let mut drop_it = false;
    let mut dup = false;
    let mut swap = false;
    match w.fault {
        Fault::None => {}
        Fault::DropNthData { dir, nth } => {
            drop_it = is_data && dir.matches(&seg) && nth_data == nth;
        }
        Fault::DropControl { dir, flags, count } => {
            let mask = FLAG_SYN | FLAG_ACK | FLAG_FIN | FLAG_RST;
            if count > 0 && !is_data && dir.matches(&seg) && seg.flags & mask == flags {
                drop_it = true;
                w.fault = Fault::DropControl {
                    dir,
                    flags,
                    count: count - 1,
                };
            }
        }
        Fault::SwapData { dir } => swap = is_data && dir.matches(&seg),
        Fault::DuplicateData { dir } => dup = is_data && dir.matches(&seg),
        Fault::RandomLoss { per_mille } => {
            drop_it = w.next_rand() % 1000 < per_mille;
        }
        Fault::IcmpOnSyn { code, count } => {
            if count > 0 && seg.has(FLAG_SYN) && !seg.has(FLAG_ACK) {
                drop_it = true;
                w.fault = Fault::IcmpOnSyn {
                    code,
                    count: count - 1,
                };
                let icmp = icmp_error_frame(ROUTER_IP, 3, code, &frame[ETH_HDR_LEN..]);
                w.queue.push_back(icmp);
            }
        }
    }

    seg.dropped = drop_it;
    w.log.push(seg);
    if drop_it {
        return Ok(());
    }
    let frame = frame.to_vec();
    if swap {
        match w.held.take() {
            None => w.held = Some(frame),
            Some(prev) => {
                w.queue.push_back(frame);
                w.queue.push_back(prev);
            }
        }
        return Ok(());
    }
    if dup {
        w.queue.push_back(frame.clone());
    }
    w.queue.push_back(frame);
    Ok(())
}

/// Ethernet + IPv4 + ICMP error frame from `from` about `offending`
/// (an IPv4 packet we sent): type/code, then the quoted IPv4 header and the
/// first 8 bytes of its payload (RFC 792), addressed back to its source.
fn icmp_error_frame(from: [u8; 4], icmp_type: u8, code: u8, offending: &[u8]) -> Vec<u8> {
    use crate::pkt::{
        ip_checksum, set_ipv4_checksum, write_eth_header, write_ipv4_header, IPV4_HDR_LEN,
        IP_PROTO_ICMP,
    };
    let ihl = ((offending[0] & 0x0f) as usize) * 4;
    let quoted = &offending[..(ihl + 8).min(offending.len())];
    let dst: [u8; 4] = [offending[12], offending[13], offending[14], offending[15]];
    let mut icmp = vec![0u8; 8 + quoted.len()];
    icmp[0] = icmp_type;
    icmp[1] = code;
    icmp[8..].copy_from_slice(quoted);
    let cs = ip_checksum(&icmp);
    icmp[2..4].copy_from_slice(&cs.to_be_bytes());
    let ip_total = IPV4_HDR_LEN + icmp.len();
    let mut frame = vec![0u8; ETH_HDR_LEN + ip_total];
    write_eth_header(
        &mut frame,
        IFACE_MAC,
        [0x02, 0, 0, 0, 0x77, 0xfe],
        ETHERTYPE_IPV4,
    );
    write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total as u16,
        IP_PROTO_ICMP,
        from,
        dst,
    );
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    frame[ETH_HDR_LEN + IPV4_HDR_LEN..].copy_from_slice(&icmp);
    frame
}

/// Deliver one queued frame through the full RX path. Returns `false` when
/// the wire is empty. A frame held back for swapping is released once
/// nothing else is queued (its successor never came).
fn deliver_one() -> bool {
    let frame = {
        let mut w = WIRE.lock();
        match w.queue.pop_front() {
            Some(f) => Some(f),
            None => w.held.take(),
        }
    };
    match frame {
        Some(mut f) => {
            // The WIRE lock is released: RX may transmit (ACKs, replies),
            // which re-enters `wire_send`.
            crate::tcp_stack::rx_handler(IFACE, &mut f);
            true
        }
        None => false,
    }
}

/// RX drain registered with `iface::install_rx_drain`, so `connect`'s
/// busy-wait moves frames across the wire.
fn wire_drain() -> bool {
    if deliver_one() {
        return true;
    }
    FFWD.load(Ordering::Acquire) && advance_clock()
}

// ── Virtual clock ───────────────────────────────────────────────────────────

fn live_ids() -> Vec<u32> {
    (1..=MAX_TCB_ID)
        .filter(|&id| lookup_tcb(id).is_some())
        .collect()
}

/// Jump to the next timer event. Delayed ACKs are the earliest timers a
/// healthy connection has pending (40 ms vs a ≥200 ms RTO), so fire those
/// first; only if none is pending, fire the retransmit / persist timers.
/// Returns `true` if any timer fired.
fn advance_clock() -> bool {
    let ids = live_ids();
    let mut fired = false;
    for &id in &ids {
        let due = __with_tcb_mut(id, |t| {
            if t.delayed_ack_deadline_cycles != 0 {
                t.delayed_ack_deadline_cycles = 1;
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
        if due {
            if let Some(arc) = lookup_tcb(id) {
                tick_retransmit(&arc);
                fired = true;
            }
        }
    }
    if fired {
        return true;
    }
    for &id in &ids {
        let due = __with_tcb_mut(id, |t| {
            let mut due = false;
            if t.retx_deadline_cycles != 0 && !t.retx_queue.is_empty() {
                t.retx_deadline_cycles = 1;
                due = true;
            }
            if t.persist_deadline_cycles != 0 {
                t.persist_deadline_cycles = 1;
                due = true;
            }
            due
        })
        .unwrap_or(false);
        if due {
            if let Some(arc) = lookup_tcb(id) {
                FORCED_RTOS.fetch_add(1, Ordering::Relaxed);
                tick_retransmit(&arc);
                fired = true;
            }
        }
    }
    fired
}

/// Expire every TIME-WAIT timer (the 2·MSL reaper) and tick.
fn expire_time_wait() {
    for id in live_ids() {
        let tw = __with_tcb_mut(id, |t| {
            if t.state == TcpState::TimeWait {
                t.time_wait_deadline_cycles = 1;
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
        if tw {
            if let Some(arc) = lookup_tcb(id) {
                tick_retransmit(&arc);
            }
        }
    }
}

/// Drive the wire + clock, calling `step` (the "application") every
/// iteration, until `step` reports done. Returns `false` on budget
/// exhaustion or a stall: nothing on the wire, no timer to fire, and the
/// application still not done.
fn run_until(budget: u32, mut step: impl FnMut() -> bool) -> bool {
    let mut idle = 0u32;
    for _ in 0..budget {
        if step() {
            return true;
        }
        if deliver_one() || advance_clock() {
            idle = 0;
            continue;
        }
        idle += 1;
        if idle > 2 {
            return step();
        }
    }
    false
}

/// Deliver everything on the wire and every timer consequence of it until
/// the system is quiescent (bounded).
fn settle() {
    let _ = run_until(BUDGET_SMALL, || false);
}

// ── Setup / teardown ────────────────────────────────────────────────────────

fn reset() {
    FFWD.store(false, Ordering::Release);
    tcp_core::__reset_for_test();
    route::__reset_for_test();
    arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    crate::bypass::__reset_for_test();
    crate::netfilter::__reset_all_for_test();
    narf_lib::sysctl::ipv4::__reset_for_test();
    *WIRE.lock() = Wire::new();
    FORCED_RTOS.store(0, Ordering::Relaxed);

    iface::register(IFACE, IFACE_MAC, wire_send);
    iface::set_iface_ipv4_fields(IFACE, CLIENT_IP, [0, 0, 0, 0]);
    iface::add_addr(IFACE, CLIENT_IP, 24);
    iface::add_addr(IFACE, SERVER_IP, 24);

    // Both addresses live on this one NIC, so both resolve to its MAC.
    for ip in [CLIENT_IP, SERVER_IP] {
        crate::tcp_stack::__arp_insert_legacy(ip, IFACE_MAC);
        arp_cache::insert(IFACE, ip, IFACE_MAC);
    }

    if !DRAIN_INSTALLED.swap(true, Ordering::AcqRel) {
        iface::install_rx_drain(wire_drain);
    }
    FFWD.store(true, Ordering::Release);
}

/// Leave the wire idle and empty so `wire_drain` is inert for other suites.
fn teardown() {
    FFWD.store(false, Ordering::Release);
    *WIRE.lock() = Wire::new();
    tcp_core::__reset_for_test();
}

fn set_fault(f: Fault) {
    let mut w = WIRE.lock();
    w.fault = f;
    w.data_seen = [0; 2];
}

fn wire_log() -> Vec<Seg> {
    WIRE.lock().log.clone()
}

fn clear_log() {
    WIRE.lock().log.clear();
}

/// An established connection: listener, client TCB, accepted server TCB.
#[derive(Clone, Copy, Debug)]
struct Conn {
    listener: u32,
    client: u32,
    server: u32,
}

/// `connect` + `accept` over the wire. The final ACK of the handshake is
/// still on the wire when `connect` returns; `run_until` delivers it.
fn accept_one(listener: u32) -> Result<u32, &'static str> {
    let mut sid = None;
    let ok = run_until(BUDGET_SMALL, || {
        if sid.is_none() {
            sid = accept(listener).ok().flatten();
        }
        sid.is_some()
    });
    match (ok, sid) {
        (true, Some(id)) => Ok(id),
        _ => Err("accept produced no child after the handshake"),
    }
}

fn open() -> Result<Conn, &'static str> {
    let listener = listen(SERVER_IP, SERVER_PORT, 16).map_err(|_| "listen failed")?;
    let client = connect(SERVER_IP, SERVER_PORT).map_err(|_| "connect failed")?;
    let server = accept_one(listener)?;
    Ok(Conn {
        listener,
        client,
        server,
    })
}

fn state_of(id: u32) -> Option<TcpState> {
    __with_tcb(id, |t| t.state)
}

// ── Data helpers ────────────────────────────────────────────────────────────

/// Deterministic, position-dependent bytes: a reordered, duplicated or
/// shifted byte shows up as a mismatch at a precise offset.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// One direction of a transfer driven by `pump_streams`.
struct Stream<'a> {
    from: u32,
    to: u32,
    data: &'a [u8],
    sent: usize,
    got: Vec<u8>,
    send_err: bool,
}

impl<'a> Stream<'a> {
    fn new(from: u32, to: u32, data: &'a [u8]) -> Self {
        Self {
            from,
            to,
            data,
            sent: 0,
            got: Vec::with_capacity(data.len()),
            send_err: false,
        }
    }

    /// One application step: push what the send buffer accepts, drain what
    /// the receive buffer holds. Returns `true` once all bytes arrived.
    fn step(&mut self, buf: &mut [u8]) -> bool {
        if self.sent < self.data.len() && !self.send_err {
            match send(self.from, &self.data[self.sent..]) {
                Ok(n) => self.sent += n,
                Err(()) => self.send_err = true,
            }
        }
        while let Ok(n) = recv(self.to, buf) {
            if n == 0 {
                break;
            }
            self.got.extend_from_slice(&buf[..n]);
        }
        self.got.len() >= self.data.len()
    }

    fn verdict(&self) -> Result<(), &'static str> {
        if self.send_err {
            return Err("send() failed mid-transfer");
        }
        if self.got.len() < self.data.len() {
            return Err("transfer stalled before all bytes arrived");
        }
        if self.got.len() > self.data.len() {
            return Err("receiver got more bytes than were sent (duplicate delivery)");
        }
        if self.got != self.data {
            return Err("received bytes differ from sent bytes (corruption / misordering)");
        }
        Ok(())
    }
}

/// Run any number of concurrent streams to completion.
fn pump_streams(streams: &mut [Stream<'_>], budget: u32) -> Result<(), &'static str> {
    let mut buf = vec![0u8; 16 * 1024];
    let done = run_until(budget, || {
        let mut all = true;
        for s in streams.iter_mut() {
            all &= s.step(&mut buf);
        }
        all
    });
    for s in streams.iter() {
        s.verdict()?;
    }
    if !done {
        return Err("transfer did not complete within budget");
    }
    Ok(())
}

fn transfer(from: u32, to: u32, data: &[u8], budget: u32) -> Result<(), &'static str> {
    let mut streams = [Stream::new(from, to, data)];
    pump_streams(&mut streams, budget)
}

/// Sender side fully drained and acknowledged: nothing unsent, nothing in
/// flight, no retransmit timer armed.
fn sender_quiescent(id: u32) -> Result<(), &'static str> {
    __with_tcb(id, |t| {
        if t.snd_una != t.snd_nxt || !t.retx_queue.is_empty() || !t.send_buf.is_empty() {
            Err("sender not quiescent: unacked or queued data left")
        } else if t.retx_deadline_cycles != 0 {
            Err("sender not quiescent: RTO still armed with nothing in flight")
        } else if t.flightsize != 0 {
            Err("sender not quiescent: flightsize accounting did not return to 0")
        } else {
            Ok(())
        }
    })
    .ok_or("sender TCB vanished")?
}

/// Count data segments that re-sent a sequence number already sent in the
/// same direction.
fn retransmitted_data_segments(log: &[Seg]) -> usize {
    let mut seen = BTreeSet::new();
    let mut n = 0;
    for s in log.iter().filter(|s| s.payload_len > 0) {
        if !seen.insert((s.dir() == Dir::ToServer, s.seq)) {
            n += 1;
        }
    }
    n
}

fn dump_seg(s: &Seg) {
    narf_console::klog!(
        "  {:5}->{:5} seq={:10} ack={:10} flags={:#04x} len={:5}{}",
        s.src_port,
        s.dst_port,
        s.seq,
        s.ack,
        s.flags,
        s.payload_len,
        if s.dropped { " DROPPED" } else { "" }
    );
}

/// On failure, log the wire tail and every live TCB so the serial console
/// shows *why* — only on the failure path, never while the test runs.
fn dump_state() {
    let log = wire_log();
    // The segments leading up to the first retransmission, then the tail.
    let mut seen = BTreeSet::new();
    let first_retx = log
        .iter()
        .position(|s| s.payload_len > 0 && !seen.insert((s.dir() == Dir::ToServer, s.seq)));
    if let Some(i) = first_retx {
        narf_console::klog!("tcp_e2e: first data retransmission at segment #{}:", i);
        for s in &log[i.saturating_sub(24)..(i + 4).min(log.len())] {
            dump_seg(s);
        }
    }
    let start = log.len().saturating_sub(48);
    narf_console::klog!("tcp_e2e: wire log tail ({} segments total):", log.len());
    for s in &log[start..] {
        dump_seg(s);
    }
    for id in live_ids() {
        let _ = __with_tcb(id, |t| {
            narf_console::klog!(
                "  tcb {} {:?} :{}->:{} una={} nxt={} wnd={} rcv_nxt={} rwnd_free={} \
                 retxq={} unsent={} fin_sent={} fin_seq={} rto_count={}",
                id,
                t.state,
                t.local_port,
                t.remote_port,
                t.snd_una,
                t.snd_nxt,
                t.snd_wnd,
                t.rcv_nxt,
                t.recv_buf.free_window(),
                t.retx_queue.len(),
                t.send_buf.unsent_len(),
                t.fin_sent,
                t.fin_seq,
                t.rto_count
            );
        });
    }
}

fn finish(r: Result<(), &'static str>) -> TestResult {
    if r.is_err() {
        dump_state();
    }
    teardown();
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

// ── 1. Handshake ────────────────────────────────────────────────────────────
//
// connect() ↔ listen()/accept(): both TCBs ESTABLISHED, 4-tuples mirrored,
// ISNs cross-acknowledged, and the SYN-option negotiation (MSS, window
// scale, SACK-permitted, timestamps) agreed by both sides.

fn tcp_e2e_handshake() -> Result<(), &'static str> {
    reset();
    let c = open()?;

    let cl = __with_tcb(c.client, |t| {
        (
            t.state,
            t.local_addr,
            t.local_port,
            t.remote_addr,
            t.remote_port,
            t.iss,
            t.irs,
            t.snd_nxt,
            t.rcv_nxt,
            t.opts.sack_active,
            t.opts.timestamps_active,
            t.opts.wscale_active,
            t.opts.peer_wscale,
            t.opts.our_wscale,
            t.opts.peer_mss,
            t.opts.our_mss,
        )
    })
    .ok_or("client TCB missing")?;
    let sv = __with_tcb(c.server, |t| {
        (
            t.state,
            t.local_addr,
            t.local_port,
            t.remote_addr,
            t.remote_port,
            t.iss,
            t.irs,
            t.snd_nxt,
            t.rcv_nxt,
            t.opts.sack_active,
            t.opts.timestamps_active,
            t.opts.wscale_active,
            t.opts.peer_wscale,
            t.opts.our_wscale,
            t.opts.peer_mss,
            t.opts.our_mss,
        )
    })
    .ok_or("server TCB missing")?;

    if cl.0 != TcpState::Established || sv.0 != TcpState::Established {
        return Err("both ends must be ESTABLISHED");
    }
    if cl.1 != CLIENT_IP || cl.3 != SERVER_IP || cl.4 != SERVER_PORT {
        return Err("client 4-tuple wrong");
    }
    if sv.1 != SERVER_IP || sv.2 != SERVER_PORT || sv.3 != CLIENT_IP || sv.4 != cl.2 {
        return Err("server 4-tuple does not mirror the client's");
    }
    if cl.6 != sv.5 || sv.6 != cl.5 {
        return Err("IRS on each side must equal the peer's ISS");
    }
    if cl.7 != sv.8 || sv.7 != cl.8 {
        return Err("snd_nxt on each side must equal the peer's rcv_nxt");
    }
    if !(cl.9 && sv.9) {
        return Err("SACK-permitted not negotiated on both sides");
    }
    if !(cl.10 && sv.10) {
        return Err("timestamps not negotiated on both sides");
    }
    if !(cl.11 && sv.11) {
        return Err("window scaling not negotiated on both sides");
    }
    if cl.12 != sv.13 || sv.12 != cl.13 {
        return Err("each side's peer_wscale must equal the other's our_wscale");
    }
    if cl.14 != sv.15 || sv.14 != cl.15 {
        return Err("each side's peer_mss must equal the other's advertised MSS");
    }

    // Exactly SYN, SYN-ACK, ACK — no retransmits, no RST.
    let log = wire_log();
    let syns = log
        .iter()
        .filter(|s| s.has(FLAG_SYN) && !s.has(FLAG_ACK))
        .count();
    let synacks = log.iter().filter(|s| s.has(FLAG_SYN | FLAG_ACK)).count();
    if syns != 1 || synacks != 1 {
        return Err("expected exactly one SYN and one SYN-ACK on a clean link");
    }
    if log.iter().any(|s| s.has(FLAG_RST)) {
        return Err("RST seen during a clean handshake");
    }

    // Accept queue drained; nothing readable yet on either end.
    if accept(c.listener) != Ok(None) {
        return Err("listener accept queue not empty after accept");
    }
    if tcp_core::readable(c.client) || tcp_core::readable(c.server) {
        return Err("a fresh connection must not be readable");
    }
    if state_of(c.listener) != Some(TcpState::Listen) {
        return Err("listener left LISTEN");
    }
    Ok(())
}

fn smoke_tcp_e2e_handshake() -> TestResult {
    finish(tcp_e2e_handshake())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_handshake);

// ── 2. Request / response ping-pong ─────────────────────────────────────────
//
// 64 rounds of variable-size request → echo. Sizes span sub-MSS writes
// (Nagle + delayed-ACK interplay) and multi-segment writes.

fn tcp_e2e_echo_ping_pong() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    for round in 0..64u32 {
        let len = ((round * 997) % 5000 + 1) as usize;
        let req = pattern(len, round + 1);
        transfer(c.client, c.server, &req, BUDGET_SMALL)?;
        // Echo it back verbatim.
        transfer(c.server, c.client, &req, BUDGET_SMALL)?;
    }
    settle();
    sender_quiescent(c.client)?;
    sender_quiescent(c.server)?;
    if retransmitted_data_segments(&wire_log()) != 0 {
        return Err("clean link produced data retransmissions");
    }
    Ok(())
}

fn smoke_tcp_e2e_echo_ping_pong() -> TestResult {
    finish(tcp_e2e_echo_ping_pong())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_echo_ping_pong);

// ── 3. Bulk transfer, each direction ────────────────────────────────────────
//
// 1 MiB — 4× the send and receive buffers — so the transfer depends on
// window updates, cwnd growth and buffer recycling, not one burst.

fn tcp_e2e_bulk(client_to_server: bool) -> Result<(), &'static str> {
    reset();
    let c = open()?;
    let data = pattern(1024 * 1024, 0xB0_1C);
    let (from, to) = if client_to_server {
        (c.client, c.server)
    } else {
        (c.server, c.client)
    };
    transfer(from, to, &data, BUDGET_BULK)?;
    settle();
    sender_quiescent(from)?;
    let log = wire_log();
    if retransmitted_data_segments(&log) != 0 {
        return Err("clean link produced data retransmissions");
    }
    if log.iter().any(|s| s.has(FLAG_RST)) {
        return Err("RST during bulk transfer");
    }
    // Every data segment must respect the negotiated MSS.
    let mss = __with_tcb(from, |t| t.opts.peer_mss as usize).ok_or("sender gone")?;
    if log.iter().any(|s| s.payload_len > mss) {
        return Err("data segment exceeded the peer's MSS");
    }
    Ok(())
}

fn smoke_tcp_e2e_bulk_client_to_server() -> TestResult {
    finish(tcp_e2e_bulk(true))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_bulk_client_to_server);

fn smoke_tcp_e2e_bulk_server_to_client() -> TestResult {
    finish(tcp_e2e_bulk(false))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_bulk_server_to_client);

// ── 4. Full duplex ──────────────────────────────────────────────────────────
//
// Both directions stream simultaneously, so data segments carry
// piggy-backed ACKs for the reverse stream.

fn tcp_e2e_full_duplex() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    let up = pattern(512 * 1024, 0x0000_5EED);
    let down = pattern(512 * 1024, 0x0000_D0D0);
    let mut streams = [
        Stream::new(c.client, c.server, &up),
        Stream::new(c.server, c.client, &down),
    ];
    pump_streams(&mut streams, BUDGET_BULK)?;
    settle();
    sender_quiescent(c.client)?;
    sender_quiescent(c.server)?;
    if retransmitted_data_segments(&wire_log()) != 0 {
        return Err("clean link produced data retransmissions");
    }
    Ok(())
}

fn smoke_tcp_e2e_full_duplex() -> TestResult {
    finish(tcp_e2e_full_duplex())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_full_duplex);

// ── 5. Graceful close ───────────────────────────────────────────────────────
//
// The active closer calls close() with far more data queued than the
// window admits: every byte must still arrive *before* EOF, and the FIN
// must follow the last byte. Then the full FSM walk:
//   active:  ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → (reaped)
//   passive: ESTABLISHED → CLOSE-WAIT → LAST-ACK → (reaped)

fn tcp_e2e_graceful_close(client_closes_first: bool) -> Result<(), &'static str> {
    reset();
    let c = open()?;
    let (active, passive) = if client_closes_first {
        (c.client, c.server)
    } else {
        (c.server, c.client)
    };
    let data = pattern(200 * 1024, 0xC105E);

    // Queue everything the send buffer takes, then close immediately.
    let queued = send(active, &data).map_err(|_| "send before close failed")?;
    close(active).map_err(|_| "close failed")?;

    let mut got = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let eof = run_until(BUDGET_BULK, || {
        while let Ok(n) = recv(passive, &mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        state_of(passive) == Some(TcpState::CloseWait)
            && __with_tcb(passive, |t| t.recv_buf.is_idle()).unwrap_or(false)
    });
    if got.len() != queued || got[..] != data[..queued] {
        return Err("data queued before close() was not delivered intact before EOF");
    }
    if !eof {
        return Err("passive side never reached CLOSE-WAIT (FIN lost or never sent)");
    }
    // EOF semantics: readable (so a poller wakes) and recv returns 0.
    if !tcp_core::readable(passive) || recv(passive, &mut buf) != Ok(0) {
        return Err("CLOSE-WAIT must be readable with recv() == 0 (EOF)");
    }
    settle();
    if state_of(active) != Some(TcpState::FinWait2) {
        return Err("active closer not in FIN-WAIT-2 after its FIN was ACKed");
    }
    // The FIN is the last thing the active side sent, right after the data.
    let log = wire_log();
    let active_is_client = client_closes_first;
    let fins: Vec<&Seg> = log
        .iter()
        .filter(|s| s.has(FLAG_FIN) && ((s.dir() == Dir::ToServer) == active_is_client))
        .collect();
    let Some(fin) = fins.first() else {
        return Err("no FIN on the wire from the active closer");
    };
    let data_end = log
        .iter()
        .filter(|s| (s.dir() == Dir::ToServer) == active_is_client && s.payload_len > 0)
        .map(|s| s.seq.wrapping_add(s.payload_len as u32))
        .max()
        .ok_or("no data segments seen")?;
    if fin.seq.wrapping_add(fin.payload_len as u32) != data_end {
        return Err("FIN sequence number does not follow the last data byte");
    }

    // Passive side closes → LAST-ACK → reaped once its FIN is ACKed.
    close(passive).map_err(|_| "passive close failed")?;
    settle();
    if lookup_tcb(passive).is_some() {
        return Err("passive closer not reaped after LAST-ACK");
    }
    if state_of(active) != Some(TcpState::TimeWait) {
        return Err("active closer not in TIME-WAIT after the peer's FIN");
    }
    expire_time_wait();
    if lookup_tcb(active).is_some() {
        return Err("TIME-WAIT TCB not reaped after 2*MSL");
    }
    if live_ids() != vec![c.listener] {
        return Err("TCBs leaked after both sides closed");
    }
    if wire_log().iter().any(|s| s.has(FLAG_RST)) {
        return Err("RST during graceful close");
    }
    Ok(())
}

fn smoke_tcp_e2e_close_client_first() -> TestResult {
    finish(tcp_e2e_graceful_close(true))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_close_client_first);

fn smoke_tcp_e2e_close_server_first() -> TestResult {
    finish(tcp_e2e_graceful_close(false))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_close_server_first);

// ── 6. Simultaneous close ───────────────────────────────────────────────────
//
// Both FINs cross on the wire: FIN-WAIT-1 → CLOSING → TIME-WAIT on both
// sides (RFC 9293 §3.6 case 2), then both reaped.

fn tcp_e2e_simultaneous_close() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    close(c.client).map_err(|_| "client close failed")?;
    close(c.server).map_err(|_| "server close failed")?;
    settle();
    if state_of(c.client) != Some(TcpState::TimeWait)
        || state_of(c.server) != Some(TcpState::TimeWait)
    {
        return Err("simultaneous close must leave both ends in TIME-WAIT");
    }
    expire_time_wait();
    if live_ids() != vec![c.listener] {
        return Err("TCBs leaked after simultaneous close");
    }
    Ok(())
}

fn smoke_tcp_e2e_simultaneous_close() -> TestResult {
    finish(tcp_e2e_simultaneous_close())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_simultaneous_close);

// ── 7. Half close ───────────────────────────────────────────────────────────
//
// shutdown(SHUT_WR) on the client: the server sees EOF but can keep
// sending, and the half-closed client keeps receiving.

fn tcp_e2e_half_close() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    shutdown(c.client, Shutdown::Write).map_err(|_| "shutdown(WR) failed")?;
    settle();
    if state_of(c.server) != Some(TcpState::CloseWait) {
        return Err("server must be in CLOSE-WAIT after the client's SHUT_WR");
    }
    if state_of(c.client) != Some(TcpState::FinWait2) {
        return Err("client must be in FIN-WAIT-2 after SHUT_WR is ACKed");
    }
    if send(c.client, b"x").is_ok() {
        return Err("send() after SHUT_WR must fail");
    }
    let data = pattern(128 * 1024, 0x4A1F);
    transfer(c.server, c.client, &data, BUDGET_BULK)?;
    close(c.server).map_err(|_| "server close failed")?;
    settle();
    if state_of(c.client) != Some(TcpState::TimeWait) {
        return Err("client not in TIME-WAIT after the server's FIN");
    }
    if lookup_tcb(c.server).is_some() {
        return Err("server not reaped after LAST-ACK");
    }
    Ok(())
}

fn smoke_tcp_e2e_half_close() -> TestResult {
    finish(tcp_e2e_half_close())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_half_close);

// ── 8. Lost data segment ────────────────────────────────────────────────────
//
// Drop one data segment mid-stream. Enough segments follow it to generate
// three duplicate ACKs, so recovery must come from fast retransmit
// (RFC 5681 §3.2) without waiting for the RTO.

fn tcp_e2e_fast_retransmit(dir: Dir) -> Result<(), &'static str> {
    reset();
    let c = open()?;
    let (from, to) = if dir == Dir::ToServer {
        (c.client, c.server)
    } else {
        (c.server, c.client)
    };
    set_fault(Fault::DropNthData { dir, nth: 2 });
    let data = pattern(256 * 1024, 0xFA57);
    transfer(from, to, &data, BUDGET_BULK)?;
    settle();
    sender_quiescent(from)?;
    let log = wire_log();
    if log.iter().filter(|s| s.dropped).count() != 1 {
        return Err("fault did not drop exactly one segment");
    }
    if retransmitted_data_segments(&log) == 0 {
        return Err("lost segment was never retransmitted");
    }
    if FORCED_RTOS.load(Ordering::Relaxed) != 0 {
        return Err("recovery needed an RTO; fast retransmit should have repaired a single loss");
    }
    Ok(())
}

fn smoke_tcp_e2e_fast_retransmit_client_data() -> TestResult {
    finish(tcp_e2e_fast_retransmit(Dir::ToServer))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_fast_retransmit_client_data);

fn smoke_tcp_e2e_fast_retransmit_server_data() -> TestResult {
    finish(tcp_e2e_fast_retransmit(Dir::ToClient))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_fast_retransmit_server_data);

// ── 9. Lost tail segment → RTO ──────────────────────────────────────────────
//
// A single-segment message whose only segment is lost produces no
// duplicate ACKs; only the retransmission timer can recover it.

fn tcp_e2e_tail_loss_rto() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    set_fault(Fault::DropNthData {
        dir: Dir::ToServer,
        nth: 0,
    });
    transfer(c.client, c.server, b"only-segment", BUDGET_SMALL)?;
    settle();
    sender_quiescent(c.client)?;
    if FORCED_RTOS.load(Ordering::Relaxed) == 0 {
        return Err("tail loss recovered without an RTO firing — loss not injected?");
    }
    let rto_count = __with_tcb(c.client, |t| t.rto_count).ok_or("client gone")?;
    if rto_count != 0 {
        return Err("rto_count must reset once new data is ACKed");
    }
    Ok(())
}

fn smoke_tcp_e2e_tail_loss_rto() -> TestResult {
    finish(tcp_e2e_tail_loss_rto())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_tail_loss_rto);

// ── 10. Reordering ──────────────────────────────────────────────────────────
//
// Every pair of data segments is swapped in flight. The receiver must
// reassemble out-of-order data and never hand the application bytes out
// of order.

fn tcp_e2e_reorder() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    set_fault(Fault::SwapData { dir: Dir::Any });
    let up = pattern(256 * 1024, 0x0E0D);
    let down = pattern(64 * 1024, 0x0E0E);
    let mut streams = [
        Stream::new(c.client, c.server, &up),
        Stream::new(c.server, c.client, &down),
    ];
    pump_streams(&mut streams, BUDGET_BULK)?;
    settle();
    sender_quiescent(c.client)?;
    sender_quiescent(c.server)
}

fn smoke_tcp_e2e_reorder() -> TestResult {
    finish(tcp_e2e_reorder())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_reorder);

// ── 11. Duplication ─────────────────────────────────────────────────────────
//
// Every data segment arrives twice. Duplicates must be discarded: the
// application sees each byte exactly once.

fn tcp_e2e_duplicate() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    set_fault(Fault::DuplicateData { dir: Dir::Any });
    let up = pattern(128 * 1024, 0xD0_0B);
    let down = pattern(128 * 1024, 0xD0_0C);
    let mut streams = [
        Stream::new(c.client, c.server, &up),
        Stream::new(c.server, c.client, &down),
    ];
    pump_streams(&mut streams, BUDGET_BULK)?;
    settle();
    sender_quiescent(c.client)?;
    sender_quiescent(c.server)
}

fn smoke_tcp_e2e_duplicate() -> TestResult {
    finish(tcp_e2e_duplicate())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_duplicate);

// ── 12. Lossy link, whole lifecycle ─────────────────────────────────────────
//
// 3% random loss on every segment kind in both directions — data, pure
// ACKs, FINs — across full-duplex transfer and graceful close. The
// connection must deliver both streams intact and still wind down to
// nothing.

fn tcp_e2e_lossy_lifecycle() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    set_fault(Fault::RandomLoss { per_mille: 30 });
    let up = pattern(256 * 1024, 0x1055_0001);
    let down = pattern(256 * 1024, 0x1055_0002);
    let mut streams = [
        Stream::new(c.client, c.server, &up),
        Stream::new(c.server, c.client, &down),
    ];
    pump_streams(&mut streams, BUDGET_BULK)?;
    if wire_log().iter().filter(|s| s.dropped).count() == 0 {
        return Err("random loss dropped nothing — fault not active");
    }

    close(c.client).map_err(|_| "client close failed")?;
    let mut buf = [0u8; 64];
    let eof = run_until(BUDGET_BULK, || {
        state_of(c.server) == Some(TcpState::CloseWait) && recv(c.server, &mut buf) == Ok(0)
    });
    if !eof {
        return Err("server never saw the client's FIN over the lossy link");
    }
    close(c.server).map_err(|_| "server close failed")?;
    let closed = run_until(BUDGET_BULK, || {
        lookup_tcb(c.server).is_none() && state_of(c.client) == Some(TcpState::TimeWait)
    });
    if !closed {
        return Err("close did not complete over the lossy link");
    }
    expire_time_wait();
    if live_ids() != vec![c.listener] {
        return Err("TCBs leaked after lossy lifecycle");
    }
    Ok(())
}

fn smoke_tcp_e2e_lossy_lifecycle() -> TestResult {
    finish(tcp_e2e_lossy_lifecycle())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_lossy_lifecycle);

// ── 13. Handshake loss ──────────────────────────────────────────────────────
//
// Drop, in turn, the SYN, the SYN-ACK, and the final ACK. connect() and
// accept() must still both succeed — via SYN retransmit, SYN-ACK
// retransmit, and the first data segment's ACK respectively.

fn tcp_e2e_handshake_loss(flags: u8, dir: Dir) -> Result<(), &'static str> {
    reset();
    set_fault(Fault::DropControl {
        dir,
        flags,
        count: 1,
    });
    let c = open_or_late_accept()?;
    let log = wire_log();
    if log.iter().filter(|s| s.dropped).count() != 1 {
        return Err("handshake fault did not drop exactly one segment");
    }
    if state_of(c.client) != Some(TcpState::Established)
        || state_of(c.server) != Some(TcpState::Established)
    {
        return Err("connection not ESTABLISHED on both ends after handshake loss");
    }
    // Prove the recovered connection carries data both ways.
    transfer(c.client, c.server, b"after-handshake-loss", BUDGET_SMALL)?;
    transfer(c.server, c.client, b"reply", BUDGET_SMALL)
}

/// Like `open`, but when the final handshake ACK is the lost segment the
/// server child only reaches ESTABLISHED once the client's first data
/// segment (which carries the ACK) arrives — so send before accepting.
fn open_or_late_accept() -> Result<Conn, &'static str> {
    let listener = listen(SERVER_IP, SERVER_PORT, 16).map_err(|_| "listen failed")?;
    let client = connect(SERVER_IP, SERVER_PORT).map_err(|_| "connect failed")?;
    settle();
    let server = match accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            // Final ACK lost: the first data segment completes the handshake.
            send(client, b"!").map_err(|_| "send on client failed")?;
            let id = accept_one(listener)?;
            let mut b = [0u8; 1];
            if !run_until(BUDGET_SMALL, || recv(id, &mut b) == Ok(1)) || &b != b"!" {
                return Err("data carried by the handshake-completing segment was lost");
            }
            id
        }
    };
    Ok(Conn {
        listener,
        client,
        server,
    })
}

fn smoke_tcp_e2e_lost_syn() -> TestResult {
    finish(tcp_e2e_handshake_loss(FLAG_SYN, Dir::ToServer))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_lost_syn);

fn smoke_tcp_e2e_lost_synack() -> TestResult {
    finish(tcp_e2e_handshake_loss(FLAG_SYN | FLAG_ACK, Dir::ToClient))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_lost_synack);

fn smoke_tcp_e2e_lost_final_ack() -> TestResult {
    finish(tcp_e2e_handshake_loss(FLAG_ACK, Dir::ToServer))
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_lost_final_ack);

// ── 14. Connection refused ──────────────────────────────────────────────────
//
// A SYN to a port with no listener must be answered with RST|ACK
// (RFC 9293 §3.10.7.1), so connect() fails on the first round trip rather
// than retransmitting its SYN until it gives up.

fn tcp_e2e_connect_refused() -> Result<(), &'static str> {
    reset();
    if connect(SERVER_IP, CLOSED_PORT).is_ok() {
        return Err("connect to a closed port succeeded");
    }
    let log = wire_log();
    let syns: Vec<&Seg> = log
        .iter()
        .filter(|s| s.has(FLAG_SYN) && s.dst_port == CLOSED_PORT)
        .collect();
    let Some(syn) = syns.first() else {
        return Err("no SYN sent");
    };
    let rst = log
        .iter()
        .find(|s| s.src_port == CLOSED_PORT && s.has(FLAG_RST))
        .ok_or("closed port did not answer the SYN with RST")?;
    if !rst.has(FLAG_ACK) || rst.ack != syn.seq.wrapping_add(1) {
        return Err("RST to a SYN must be RST|ACK acknowledging SYN.seq + 1");
    }
    if syns.len() != 1 {
        return Err("client retransmitted its SYN despite receiving RST");
    }
    if !live_ids().is_empty() {
        return Err("refused connect leaked a TCB");
    }
    Ok(())
}

fn smoke_tcp_e2e_connect_refused() -> TestResult {
    finish(tcp_e2e_connect_refused())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_connect_refused);

// ── 15. Segment for a vanished connection ───────────────────────────────────
//
// Once the server's TCB is gone, further data from the client must draw
// an RST that tears the client down (drop cause PeerReset), not silence.

fn tcp_e2e_rst_on_stale_connection() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    // Tear down the server side without a FIN (as a crash / reboot would).
    tcp_core::remove_tcb(c.server);
    send(c.client, b"anyone there?").map_err(|_| "client send failed")?;
    let ok = run_until(BUDGET_SMALL, || lookup_tcb(c.client).is_none());
    if !ok {
        return Err("client not torn down by RST from the peer's closed port");
    }
    if !wire_log()
        .iter()
        .any(|s| s.src_port == SERVER_PORT && s.has(FLAG_RST))
    {
        return Err("no RST emitted for a segment matching no connection");
    }
    Ok(())
}

fn smoke_tcp_e2e_rst_on_stale_connection() -> TestResult {
    finish(tcp_e2e_rst_on_stale_connection())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_rst_on_stale_connection);

// ── 16. Many concurrent connections ─────────────────────────────────────────
//
// Eight clients on one listener, each streaming its own payload
// concurrently. Demultiplexing must keep every byte on its own
// connection.

fn tcp_e2e_many_connections() -> Result<(), &'static str> {
    const N: usize = 8;
    reset();
    let listener = listen(SERVER_IP, SERVER_PORT, 16).map_err(|_| "listen failed")?;
    let mut clients = Vec::new();
    for _ in 0..N {
        clients.push(connect(SERVER_IP, SERVER_PORT).map_err(|_| "connect failed")?);
    }
    settle();
    // Pair each accepted child with its client by port.
    let mut pairs = Vec::new();
    while let Ok(Some(sid)) = accept(listener) {
        let rport = __with_tcb(sid, |t| t.remote_port).ok_or("child gone")?;
        let cid = *clients
            .iter()
            .find(|&&cid| __with_tcb(cid, |t| t.local_port) == Some(rport))
            .ok_or("accepted child matches no client port")?;
        pairs.push((cid, sid));
    }
    if pairs.len() != N {
        return Err("accept did not return one child per client");
    }
    let payloads: Vec<Vec<u8>> = (0..N)
        .map(|i| pattern(32 * 1024 + i * 1111, 0xC0_0000 + i as u32))
        .collect();
    let mut streams: Vec<Stream<'_>> = pairs
        .iter()
        .zip(payloads.iter())
        .map(|(&(cid, sid), p)| Stream::new(cid, sid, p))
        .collect();
    pump_streams(&mut streams, BUDGET_BULK)?;
    Ok(())
}

fn smoke_tcp_e2e_many_connections() -> TestResult {
    finish(tcp_e2e_many_connections())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_many_connections);

// ── 17. Zero window ─────────────────────────────────────────────────────────
//
// The server application stops reading. The client fills the server's
// receive buffer, sees a zero window, and must hold (persist) rather than
// overrun it; once the application drains the buffer, the transfer
// resumes and completes intact.

fn tcp_e2e_zero_window() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    let data = pattern(768 * 1024, 0x2E_2011);
    let mut sent = 0usize;

    // Phase 1: write, never read, until the peer advertises a zero window.
    let stalled = run_until(BUDGET_BULK, || {
        if sent < data.len() {
            if let Ok(n) = send(c.client, &data[sent..]) {
                sent += n;
            }
        }
        __with_tcb(c.client, |t| {
            t.snd_wnd == 0 && t.persist_deadline_cycles != 0
        })
        .unwrap_or(false)
    });
    if !stalled {
        return Err("sender never saw a zero window with persist armed");
    }
    let (room, limit, wscale) = __with_tcb(c.server, |t| {
        (t.recv_buf.window(), t.recv_buf.limit, t.opts.our_wscale)
    })
    .ok_or("server gone")?;
    // A window below one scaling unit legitimately advertises as zero.
    if room >= 1 << wscale {
        return Err("zero window advertised while receive buffer had room");
    }
    // Probe a few times while still closed: nothing may be accepted beyond
    // the buffer limit.
    for _ in 0..4 {
        advance_clock();
        while deliver_one() {}
    }
    let used = __with_tcb(c.server, |t| {
        t.recv_buf.limit - t.recv_buf.free_window() as usize
    })
    .ok_or("server gone")?;
    if used > limit {
        return Err("receiver accepted data beyond its buffer");
    }

    // Phase 2: application drains; transfer finishes.
    let mut got = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let done = run_until(BUDGET_BULK, || {
        if sent < data.len() {
            if let Ok(n) = send(c.client, &data[sent..]) {
                sent += n;
            }
        }
        while let Ok(n) = recv(c.server, &mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got.len() >= data.len()
    });
    if !done {
        return Err("transfer did not resume after the window reopened");
    }
    if got != data {
        return Err("bytes corrupted across the zero-window stall");
    }
    Ok(())
}

fn smoke_tcp_e2e_zero_window() -> TestResult {
    finish(tcp_e2e_zero_window())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_zero_window);

// ── errno contract ──────────────────────────────────────────────────────────
//
// What `send` / `recv` / `shutdown` / `connect` / `SO_ERROR` report, pinned
// to the Linux source that decides it for the same condition:
//
// - `tcp_recvmsg_locked` (net/ipv4/tcp.c): queued data first; then
//   SOCK_DONE → 0, `sock_error` (once) → errno, RCV_SHUTDOWN → 0,
//   TCP_CLOSE → ENOTCONN, else EAGAIN.
// - `tcp_sendmsg_locked` + `sk_stream_error` (net/core/stream.c): pending
//   error once, then EPIPE; EAGAIN when the send buffer is full.
// - `tcp_reset` (net/ipv4/tcp_input.c): SYN-SENT → ECONNREFUSED,
//   CLOSE-WAIT → EPIPE, else ECONNRESET.
// - `tcp_write_err` (net/ipv4/tcp_timer.c): `sk_err_soft ?: ETIMEDOUT`.
// - `tcp_v4_err` (net/ipv4/tcp_ipv4.c) + `icmp_err_convert`
//   (net/ipv4/icmp.c): fatal in SYN-SENT, soft once established.
// - `inet_shutdown` (net/ipv4/af_inet.c): TCP_CLOSE → ENOTCONN.
// - `sk_getsockopt(SO_ERROR)` (net/core/sock.c): `sock_error`, else the
//   soft error, each cleared by the read.

use narf_lib::errno;

use crate::tcp::core::{connect_errno_in, recv_errno, send_errno, shutdown_errno, take_sock_error};

const EAGAIN: i32 = errno::EAGAIN as i32;
const EPIPE: i32 = errno::EPIPE as i32;
const ENOTCONN: i32 = errno::ENOTCONN as i32;
const ECONNRESET: i32 = errno::ECONNRESET as i32;
const ECONNREFUSED: i32 = errno::ECONNREFUSED as i32;
const ETIMEDOUT: i32 = errno::ETIMEDOUT as i32;
const EHOSTUNREACH: i32 = errno::EHOSTUNREACH as i32;
const ENETUNREACH: i32 = errno::ENETUNREACH as i32;
const EHOSTDOWN: i32 = errno::EHOSTDOWN as i32;

fn expect(
    got: Result<usize, i32>,
    want: Result<usize, i32>,
    msg: &'static str,
) -> Result<(), &'static str> {
    if got == want {
        Ok(())
    } else {
        narf_console::klog!("tcp_e2e errno: got {:?}, want {:?}", got, want);
        Err(msg)
    }
}

// Orderly shutdown: EAGAIN while live, 0 at EOF, EPIPE after SHUT_WR, and
// ENOTCONN / EPIPE / 0 once the connection is gone.
fn tcp_e2e_errno_orderly_shutdown() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    let mut b = [0u8; 16];
    expect(
        recv_errno(c.server, &mut b),
        Err(EAGAIN),
        "live, empty: recv must be EAGAIN",
    )?;
    if tcp_core::readable(c.server) {
        return Err("live, empty socket must not poll readable");
    }
    shutdown_errno(c.client, Shutdown::Write).map_err(|_| "shutdown(SHUT_WR) failed")?;
    expect(
        send_errno(c.client, b"x"),
        Err(EPIPE),
        "send after SHUT_WR must be EPIPE",
    )?;
    settle();
    expect(
        recv_errno(c.server, &mut b),
        Ok(0),
        "peer FIN: recv must be 0 (EOF)",
    )?;
    expect(recv_errno(c.server, &mut b), Ok(0), "EOF must be sticky")?;
    if !tcp_core::readable(c.server) {
        return Err("EOF must poll readable");
    }
    // The half-closed client still reads: nothing yet → EAGAIN.
    expect(
        recv_errno(c.client, &mut b),
        Err(EAGAIN),
        "FIN-WAIT-2, empty: recv must be EAGAIN",
    )?;
    expect(
        send_errno(c.server, b"late"),
        Ok(4),
        "CLOSE-WAIT may still send",
    )?;
    settle();
    expect(
        recv_errno(c.client, &mut b),
        Ok(4),
        "half-closed side must receive",
    )?;
    shutdown_errno(c.server, Shutdown::Write).map_err(|_| "server SHUT_WR failed")?;
    settle();
    expect(
        recv_errno(c.client, &mut b),
        Ok(0),
        "EOF after the server's FIN",
    )?;
    if !tcp_core::readable(c.client) {
        return Err("TIME-WAIT socket at EOF must poll readable");
    }
    // Client in TIME-WAIT — its user socket is closed (`tcp_time_wait`).
    if shutdown_errno(c.client, Shutdown::Write) != Err(ENOTCONN) {
        return Err("shutdown in TIME-WAIT must be ENOTCONN");
    }
    expire_time_wait();
    expect(
        recv_errno(c.client, &mut b),
        Ok(0),
        "closed connection: recv must be 0",
    )?;
    expect(
        send_errno(c.client, b"x"),
        Err(EPIPE),
        "closed connection: send must be EPIPE",
    )?;
    if shutdown_errno(c.client, Shutdown::Both) != Err(ENOTCONN) {
        return Err("shutdown on a closed connection must be ENOTCONN");
    }
    if take_sock_error(c.client) != 0 {
        return Err("orderly close must leave no SO_ERROR");
    }
    Ok(())
}

fn smoke_tcp_e2e_errno_orderly_shutdown() -> TestResult {
    finish(tcp_e2e_errno_orderly_shutdown())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_orderly_shutdown);

// A full send buffer is EAGAIN, never a silent 0.
fn tcp_e2e_errno_send_buffer_full() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    let chunk = pattern(64 * 1024, 7);
    // Nothing is delivered (the wire is not run), so the buffer fills.
    for _ in 0..64 {
        match send_errno(c.client, &chunk) {
            Ok(n) if n > 0 => continue,
            Ok(_) => return Err("full send buffer returned Ok(0) instead of EAGAIN"),
            Err(e) if e == EAGAIN => return Ok(()),
            Err(_) => return Err("full send buffer returned an errno other than EAGAIN"),
        }
    }
    Err("send buffer never filled")
}

fn smoke_tcp_e2e_errno_send_buffer_full() -> TestResult {
    finish(tcp_e2e_errno_send_buffer_full())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_send_buffer_full);

/// Establish, then make the server vanish without a FIN (crash / reboot)
/// and have the client send, drawing an RST. Returns the client id.
fn reset_client_by_peer(listener: u32) -> Result<u32, &'static str> {
    let client = connect(SERVER_IP, SERVER_PORT).map_err(|_| "connect failed")?;
    let server = accept_one(listener)?;
    settle();
    tcp_core::remove_tcb(server);
    expect(
        send_errno(client, b"hello?"),
        Ok(6),
        "send before the RST must succeed",
    )?;
    if !run_until(BUDGET_SMALL, || lookup_tcb(client).is_none()) {
        return Err("client not torn down by the RST");
    }
    Ok(client)
}

// RST in ESTABLISHED: ECONNRESET exactly once (whichever call sees it),
// then recv → 0 and send → EPIPE.
fn tcp_e2e_errno_reset_established() -> Result<(), &'static str> {
    reset();
    let mut b = [0u8; 8];
    let listener = listen(SERVER_IP, SERVER_PORT, 16).map_err(|_| "listen failed")?;
    let id = reset_client_by_peer(listener)?;
    if !tcp_core::readable(id) {
        return Err("reset socket must poll readable");
    }
    expect(
        recv_errno(id, &mut b),
        Err(ECONNRESET),
        "first recv after RST must be ECONNRESET",
    )?;
    expect(
        recv_errno(id, &mut b),
        Ok(0),
        "ECONNRESET is reported once; then EOF",
    )?;
    expect(
        send_errno(id, b"x"),
        Err(EPIPE),
        "send after the reported reset must be EPIPE",
    )?;

    // Same again, but the first call is a send.
    let id = reset_client_by_peer(listener)?;
    expect(
        send_errno(id, b"x"),
        Err(ECONNRESET),
        "first send after RST must be ECONNRESET",
    )?;
    expect(send_errno(id, b"x"), Err(EPIPE), "then EPIPE")?;
    expect(recv_errno(id, &mut b), Ok(0), "then recv is EOF")?;

    // And via SO_ERROR.
    let id = reset_client_by_peer(listener)?;
    if take_sock_error(id) != ECONNRESET {
        return Err("SO_ERROR after RST must be ECONNRESET");
    }
    if take_sock_error(id) != 0 {
        return Err("SO_ERROR must clear once read");
    }
    tcp_core::release(id);
    Ok(())
}

fn smoke_tcp_e2e_errno_reset_established() -> TestResult {
    finish(tcp_e2e_errno_reset_established())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_reset_established);

// RST in CLOSE-WAIT is EPIPE (tcp_reset), and since the peer's FIN was
// received (SOCK_DONE), recv still reports EOF rather than the error.
fn tcp_e2e_errno_reset_close_wait() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    shutdown_errno(c.client, Shutdown::Write).map_err(|_| "client SHUT_WR failed")?;
    settle();
    if state_of(c.server) != Some(TcpState::CloseWait) {
        return Err("server not in CLOSE-WAIT");
    }
    tcp_core::remove_tcb(c.client);
    expect(
        send_errno(c.server, b"data"),
        Ok(4),
        "CLOSE-WAIT send must succeed",
    )?;
    if !run_until(BUDGET_SMALL, || lookup_tcb(c.server).is_none()) {
        return Err("server not torn down by the RST");
    }
    let mut b = [0u8; 8];
    expect(
        recv_errno(c.server, &mut b),
        Ok(0),
        "SOCK_DONE precedes sk_err: recv must be 0",
    )?;
    if take_sock_error(c.server) != EPIPE {
        return Err("RST in CLOSE-WAIT must report EPIPE");
    }
    Ok(())
}

fn smoke_tcp_e2e_errno_reset_close_wait() -> TestResult {
    finish(tcp_e2e_errno_reset_close_wait())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_reset_close_wait);

// connect(): RST → ECONNREFUSED; silence → ETIMEDOUT; unresolvable next
// hop → EHOSTUNREACH; no interface → ENETUNREACH.
fn tcp_e2e_errno_connect_failures() -> Result<(), &'static str> {
    reset();
    if connect_errno_in(0, SERVER_IP, CLOSED_PORT) != Err(ECONNREFUSED) {
        return Err("RST to SYN must fail connect with ECONNREFUSED");
    }
    set_fault(Fault::DropControl {
        dir: Dir::ToServer,
        flags: FLAG_SYN,
        count: u32::MAX,
    });
    let _ = listen(SERVER_IP, SERVER_PORT, 4).map_err(|_| "listen failed")?;
    if connect_errno_in(0, SERVER_IP, SERVER_PORT) != Err(ETIMEDOUT) {
        return Err("unanswered SYNs must fail connect with ETIMEDOUT");
    }
    set_fault(Fault::None);
    // On-link, but nothing answers ARP.
    if connect_errno_in(0, [10, 0, 77, 99], SERVER_PORT) != Err(EHOSTUNREACH) {
        return Err("unresolvable next hop must fail connect with EHOSTUNREACH");
    }
    if live_ids().len() != 1 {
        return Err("failed connects leaked TCBs");
    }
    Ok(())
}

fn smoke_tcp_e2e_errno_connect_failures() -> TestResult {
    finish(tcp_e2e_errno_connect_failures())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_connect_failures);

// ICMP destination-unreachable in SYN-SENT is fatal, with the errno from
// `icmp_err_convert[code]`. FRAG_NEEDED is PMTU, not an error.
fn tcp_e2e_errno_connect_icmp() -> Result<(), &'static str> {
    const CASES: [(u8, i32); 4] = [
        (0, ENETUNREACH),  // ICMP_NET_UNREACH
        (1, EHOSTUNREACH), // ICMP_HOST_UNREACH
        (3, ECONNREFUSED), // ICMP_PORT_UNREACH
        (7, EHOSTDOWN),    // ICMP_HOST_UNKNOWN
    ];
    reset();
    for_each_icmp_case(&CASES)?;
    // FRAG_NEEDED on the first SYN: not an error; the retransmitted SYN
    // gets through and connect succeeds.
    reset();
    let _ = listen(SERVER_IP, SERVER_PORT, 4).map_err(|_| "listen failed")?;
    set_fault(Fault::IcmpOnSyn { code: 4, count: 1 });
    if connect_errno_in(0, SERVER_IP, SERVER_PORT).is_err() {
        return Err("ICMP FRAG_NEEDED must not abort the connect");
    }
    Ok(())
}

fn for_each_icmp_case(cases: &[(u8, i32)]) -> Result<(), &'static str> {
    for &(code, want) in cases {
        set_fault(Fault::IcmpOnSyn { code, count: 1 });
        let got = connect_errno_in(0, SERVER_IP, SERVER_PORT);
        if got != Err(want) {
            narf_console::klog!(
                "tcp_e2e errno: ICMP code {} → {:?}, want {}",
                code,
                got,
                want
            );
            return Err("ICMP error in SYN-SENT did not map per icmp_err_convert");
        }
    }
    Ok(())
}

fn smoke_tcp_e2e_errno_connect_icmp() -> TestResult {
    finish(tcp_e2e_errno_connect_icmp())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_connect_icmp);

/// An ICMP error from `ROUTER_IP` about a client→server segment with
/// sequence number `seq`, delivered through the full RX path.
fn inject_icmp_about_client_segment(client_port: u16, seq: u32, code: u8) {
    use crate::pkt::{set_ipv4_checksum, write_ipv4_header, IPV4_HDR_LEN};
    let mut quoted = vec![0u8; IPV4_HDR_LEN + 8];
    write_ipv4_header(
        &mut quoted,
        (IPV4_HDR_LEN + 20) as u16,
        IP_PROTO_TCP,
        CLIENT_IP,
        SERVER_IP,
    );
    set_ipv4_checksum(&mut quoted);
    quoted[IPV4_HDR_LEN..IPV4_HDR_LEN + 2].copy_from_slice(&client_port.to_be_bytes());
    quoted[IPV4_HDR_LEN + 2..IPV4_HDR_LEN + 4].copy_from_slice(&SERVER_PORT.to_be_bytes());
    quoted[IPV4_HDR_LEN + 4..IPV4_HDR_LEN + 8].copy_from_slice(&seq.to_be_bytes());
    let mut frame = icmp_error_frame(ROUTER_IP, 3, code, &quoted);
    crate::tcp_stack::rx_handler(IFACE, &mut frame);
}

// Once established, ICMP errors are soft (RFC 1122 §4.2.3.9): the
// connection survives, SO_ERROR reports the soft error once, a quoted
// sequence number outside [snd_una, snd_nxt] is ignored, and a later
// timeout reports the soft error instead of ETIMEDOUT.
fn tcp_e2e_errno_icmp_soft_established() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    let (port, una) = __with_tcb(c.client, |t| (t.local_port, t.snd_una)).ok_or("client gone")?;

    inject_icmp_about_client_segment(port, una.wrapping_add(100_000), 1);
    if take_sock_error(c.client) != 0 {
        return Err("ICMP quoting an out-of-window sequence number must be ignored");
    }
    inject_icmp_about_client_segment(port, una, 1);
    if state_of(c.client) != Some(TcpState::Established) {
        return Err("ICMP error must not abort an established connection");
    }
    if take_sock_error(c.client) != EHOSTUNREACH || take_sock_error(c.client) != 0 {
        return Err("SO_ERROR must report the soft ICMP error exactly once");
    }
    transfer(c.client, c.server, b"still-alive", BUDGET_SMALL)?;

    // Soft error, then the path goes dark until the retransmit give-up.
    let una = __with_tcb(c.client, |t| t.snd_una).ok_or("client gone")?;
    inject_icmp_about_client_segment(port, una, 1);
    set_fault(Fault::RandomLoss { per_mille: 1000 });
    expect(
        send_errno(c.client, b"into the void"),
        Ok(13),
        "send must queue",
    )?;
    if !run_until(BUDGET_BULK, || lookup_tcb(c.client).is_none()) {
        return Err("connection never timed out on a dead path");
    }
    expect(
        send_errno(c.client, b"x"),
        Err(EHOSTUNREACH),
        "timeout after a soft ICMP error must report it (sk_err_soft ?: ETIMEDOUT)",
    )?;
    Ok(())
}

fn smoke_tcp_e2e_errno_icmp_soft_established() -> TestResult {
    finish(tcp_e2e_errno_icmp_soft_established())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_icmp_soft_established);

// A plain retransmit give-up with no ICMP history is ETIMEDOUT.
fn tcp_e2e_errno_retransmit_timeout() -> Result<(), &'static str> {
    reset();
    let c = open()?;
    settle();
    set_fault(Fault::RandomLoss { per_mille: 1000 });
    expect(send_errno(c.client, b"lost"), Ok(4), "send must queue")?;
    if !run_until(BUDGET_BULK, || lookup_tcb(c.client).is_none()) {
        return Err("connection never timed out on a dead path");
    }
    let mut b = [0u8; 4];
    expect(
        recv_errno(c.client, &mut b),
        Err(ETIMEDOUT),
        "retransmit give-up must be ETIMEDOUT",
    )?;
    expect(
        recv_errno(c.client, &mut b),
        Ok(0),
        "reported once; then EOF",
    )?;
    Ok(())
}

fn smoke_tcp_e2e_errno_retransmit_timeout() -> TestResult {
    finish(tcp_e2e_errno_retransmit_timeout())
}
kernel_test_in!("net/tcp_e2e", smoke_tcp_e2e_errno_retransmit_timeout);
