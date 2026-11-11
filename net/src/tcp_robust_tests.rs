//! Kernel tests for the TCP behaviours long, large, paced and lossy streams
//! depend on. Each one pins a bug the net-smoke robustness phases found
//! (`verification/data/musl-demo/netserve_smoke_x86_64.c` §8) to the stack
//! itself, against Linux's behaviour for the same input.
//!
//! The harness is `tcp_timer_e2e_tests`'s: a capture interface, TCBs
//! installed directly in a state, and segments injected through
//! `handle_segment`.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::arp_cache;
use crate::iface;
use crate::pkt::{ETH_HDR_LEN, IPV4_HDR_LEN};
use crate::pkt_tcp::{ipv4_pseudo_checksum, TcpHeader, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::route;
use crate::tcp::core::{
    self, __install_test_tcb, __with_tcb, __with_tcb_mut, close, handle_segment, listen,
    lookup_tcb, queue_ioctl, recv_errno, recv_peek_errno, send, tick_retransmit, TcpQueueIoctl,
};
use crate::tcp::options::{encode_data_options, OptionsState, MAX_TCP_OPTION_SPACE};
use crate::tcp::sack::SackBlock;
use crate::tcp::state_machine::TcpState;

static CAPTURE: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn capture_send(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    CAPTURE.lock().push(frame.to_vec());
    Ok(())
}

fn drain() -> Vec<Vec<u8>> {
    ::core::mem::take(&mut *CAPTURE.lock())
}

/// Fresh stack with one capture interface `name` at `local`/24; the peer is
/// `local` with last octet 2.
fn reset(name: &'static str, local: [u8; 4]) -> [u8; 4] {
    core::__reset_for_test();
    route::__reset_for_test();
    arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    CAPTURE.lock().clear();
    iface::register(name, [0x02, 0, 0, 0, 0, 0x31], capture_send);
    iface::set_default_ipv4(local, local);
    iface::add_addr(name, local, 24);
    let peer = [local[0], local[1], local[2], 2];
    let peer_mac = [0x52, 0x54, 0, 0, 0, 1];
    crate::tcp_stack::__arp_insert_legacy(peer, peer_mac);
    arp_cache::insert(name, peer, peer_mac);
    peer
}

/// Install an ESTABLISHED TCB `local:lport <-> peer:pport` (snd_una 0x10000,
/// rcv_nxt 0x20000, peer window 65535).
fn established(local: [u8; 4], lport: u16, peer: [u8; 4], pport: u16) -> u32 {
    __install_test_tcb(local, lport, peer, pport, TcpState::Established)
}

struct Seg<'a> {
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: Vec<u8>,
    payload: &'a [u8],
}

/// The TCP segment (header + payload) for `handle_segment`.
fn tcp_bytes(s: Seg<'_>) -> Vec<u8> {
    let hdr_len = 20 + s.options.len();
    let mut hdr = TcpHeader {
        src_port: s.sport,
        dst_port: s.dport,
        sequence: s.seq,
        acknowledgement: s.ack,
        header_len: hdr_len as u8,
        flags: s.flags,
        window: s.window,
        checksum: 0,
        urgent_ptr: 0,
        options: s.options.clone(),
    };
    let mut seg = hdr.encode();
    seg.extend_from_slice(s.payload);
    hdr.checksum = ipv4_pseudo_checksum(s.src, s.dst, &seg);
    let mut out = hdr.encode();
    out.extend_from_slice(s.payload);
    out
}

fn inject(s: Seg<'_>) {
    let (src, dst) = (s.src, s.dst);
    handle_segment(src, dst, &tcp_bytes(s));
}

/// NOP NOP TS(tsval, tsecr).
fn ts_option(tsval: u32, tsecr: u32) -> Vec<u8> {
    let mut o = vec![1, 1, 8, 10];
    o.extend_from_slice(&tsval.to_be_bytes());
    o.extend_from_slice(&tsecr.to_be_bytes());
    o
}

const TCP_OFF: usize = ETH_HDR_LEN + IPV4_HDR_LEN;

fn frame_flags(f: &[u8]) -> u8 {
    f.get(TCP_OFF + 13).copied().unwrap_or(0)
}

fn frame_payload_len(f: &[u8]) -> usize {
    if f.len() < TCP_OFF + 20 {
        return 0;
    }
    let ip_total = u16::from_be_bytes([f[ETH_HDR_LEN + 2], f[ETH_HDR_LEN + 3]]) as usize;
    let tcp_hdr = ((f[TCP_OFF + 12] >> 4) as usize) * 4;
    ip_total.saturating_sub(IPV4_HDR_LEN + tcp_hdr)
}

fn frame_ip_len(f: &[u8]) -> usize {
    u16::from_be_bytes([f[ETH_HDR_LEN + 2], f[ETH_HDR_LEN + 3]]) as usize
}

// ── Ephemeral ports ─────────────────────────────────────────────────────

/// Active-open ports come from `ip_local_port_range` (32768–60999), never
/// repeat a tuple still in use (TIME-WAIT included), and run out with
/// EADDRNOTAVAIL instead of wrapping. The old counter started at 49152 and
/// was cast to u16, so connect #16385 got port 0 and later ones reused
/// tuples held by TIME-WAIT connections.
fn smoke_connect_ports_stay_in_range_and_unique() -> TestResult {
    let local = [10, 0, 91, 1];
    let peer = reset("tcp-rob-ports", local);
    // The allocator walks the whole range once, never leaves it, never
    // repeats a port still in use, and then reports exhaustion.
    let mut used = BTreeSet::new();
    loop {
        let Some(p) = core::__pick_local_port_with_for_test(|p| used.contains(&p)) else {
            break;
        };
        if !(core::LOCAL_PORT_LOW..=core::LOCAL_PORT_HIGH).contains(&p) {
            return TestResult::Fail("connect port outside ip_local_port_range");
        }
        if !used.insert(p) {
            return TestResult::Fail("connect handed out a port that is still in use");
        }
        if used.len() > 70_000 {
            return TestResult::Fail("the allocator never reported exhaustion");
        }
    }
    let span = (core::LOCAL_PORT_HIGH - core::LOCAL_PORT_LOW) as usize + 1;
    if used.len() != span {
        return TestResult::Fail("connect did not use the whole range before EADDRNOTAVAIL");
    }
    // A TIME-WAIT connection holds its tuple: after a reset the first
    // candidate is the range's low end, which TIME-WAIT now occupies.
    core::__reset_for_test();
    let _tw = __install_test_tcb(local, core::LOCAL_PORT_LOW, peer, 80, TcpState::TimeWait);
    match core::__pick_local_port4_for_test(0, local, peer, 80) {
        Some(p) if p == core::LOCAL_PORT_LOW => {
            TestResult::Fail("connect reused the tuple of a TIME-WAIT connection")
        }
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("no port for a destination with one tuple in use"),
    }
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_connect_ports_stay_in_range_and_unique
);

// ── MSS and options ─────────────────────────────────────────────────────

/// With timestamps negotiated every data segment carries 12 option bytes,
/// so the payload is the peer's MSS minus 12 (Linux `tcp_current_mss`):
/// 1448 for a 1460 MSS. Sending 1460 bytes built 1512-byte IP packets.
fn smoke_send_mss_leaves_room_for_timestamps() -> TestResult {
    let local = [10, 0, 92, 1];
    let peer = reset("tcp-rob-mss", local);
    let id = established(local, 40_001, peer, 80);
    __with_tcb_mut(id, |t| {
        t.opts.timestamps_active = true;
        t.opts.peer_mss = 1460;
        t.cong.cwnd = 1 << 20;
        t.snd_wnd = 1 << 20;
        t.nagle_enabled = false;
    });
    let _ = drain();
    if send(id, &[0x5a; 6000]).is_err() {
        return TestResult::Fail("send failed");
    }
    let frames = drain();
    let data: Vec<&Vec<u8>> = frames.iter().filter(|f| frame_payload_len(f) > 0).collect();
    if data.is_empty() {
        return TestResult::Fail("no data segment sent");
    }
    for f in data {
        if frame_ip_len(f) > 1500 {
            return TestResult::Fail("data segment exceeds the 1500-byte MTU with timestamps");
        }
        if frame_payload_len(f) > 1448 {
            return TestResult::Fail("payload above MSS - 12 with timestamps negotiated");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_send_mss_leaves_room_for_timestamps);

/// Timestamps (12) + SACK must fit the 40-byte option space: at most three
/// SACK blocks beside timestamps (`tcp_established_options`).
fn smoke_sack_blocks_fit_beside_timestamps() -> TestResult {
    let mut st = OptionsState::new();
    st.timestamps_active = true;
    st.sack_active = true;
    let blocks = [
        SackBlock {
            left: 100,
            right: 200,
        },
        SackBlock {
            left: 300,
            right: 400,
        },
        SackBlock {
            left: 500,
            right: 600,
        },
        SackBlock {
            left: 700,
            right: 800,
        },
    ];
    let with_ts = encode_data_options(&st, 1, &blocks);
    if with_ts.len() > MAX_TCP_OPTION_SPACE {
        return TestResult::Fail("timestamps + SACK exceed the 40-byte option space");
    }
    st.timestamps_active = false;
    let without = encode_data_options(&st, 1, &blocks);
    if without.len() > MAX_TCP_OPTION_SPACE || without.len() < 4 + 4 * 8 {
        return TestResult::Fail("four SACK blocks without timestamps");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_sack_blocks_fit_beside_timestamps);

// ── Initial sequence numbers (RFC 6528) ─────────────────────────────────

/// Spin until the 64 ns ISN clock has moved on.
fn isn_clock_tick() {
    let t0 = narf_scheduler::narf_time::monotonic_ns();
    while narf_scheduler::narf_time::monotonic_ns() < t0 + 1_000 {
        ::core::hint::spin_loop();
    }
}

/// `secure_tcp_seq`: one 4-tuple's ISNs increase with time, so a reused
/// tuple's new SYN is past the old connection's sequence space and a peer's
/// TIME-WAIT takes it as a new connection. The old ISN was a multiplicative
/// hash of the clock, below the previous incarnation's about half the time,
/// and such a SYN is dropped as an old duplicate. Distinct tuples (and
/// namespaces) get unrelated offsets.
fn smoke_isn_monotonic_per_tuple() -> TestResult {
    let (a, b) = ([10, 0, 2, 15], [10, 0, 2, 2]);
    let mut prev = core::__secure_tcp_seq_for_test(0, a, b, 32_819, 17_782);
    for _ in 0..64 {
        isn_clock_tick();
        let next = core::__secure_tcp_seq_for_test(0, a, b, 32_819, 17_782);
        if (next.wrapping_sub(prev) as i32) <= 0 {
            return TestResult::Fail("an ISN for the same 4-tuple did not increase");
        }
        prev = next;
    }
    let base = core::__secure_tcp_seq_for_test(0, a, b, 32_819, 17_782);
    let others = [
        core::__secure_tcp_seq_for_test(0, a, b, 32_820, 17_782),
        core::__secure_tcp_seq_for_test(0, a, b, 32_819, 17_783),
        core::__secure_tcp_seq_for_test(0, b, a, 32_819, 17_782),
        core::__secure_tcp_seq_for_test(1, a, b, 32_819, 17_782),
    ];
    // The clock advances them all alike, so tuples apart by only a few ticks
    // would mean the hash ignored the tuple.
    if others
        .iter()
        .any(|&o| o.wrapping_sub(base).wrapping_add(1 << 20) < 1 << 21)
    {
        return TestResult::Fail("distinct 4-tuples got nearly the same ISN offset");
    }
    let (a6, b6) = (
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    );
    let first = core::__secure_tcpv6_seq_for_test(a6, b6, 40_000, 443);
    isn_clock_tick();
    let second = core::__secure_tcpv6_seq_for_test(a6, b6, 40_000, 443);
    if (second.wrapping_sub(first) as i32) <= 0 {
        return TestResult::Fail("an IPv6 ISN for the same 4-tuple did not increase");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_isn_monotonic_per_tuple);

// ── Neighbour resolution never waits (`neigh_output`) ──────────────────

const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x31];

fn ethertype(f: &[u8]) -> u16 {
    u16::from_be_bytes([f[12], f[13]])
}

fn arp_requests_for(frames: &[Vec<u8>], ip: [u8; 4]) -> usize {
    frames
        .iter()
        .filter(|f| ethertype(f) == 0x0806 && f.get(38..42) == Some(&ip[..]))
        .count()
}

fn tcp_frames(frames: &[Vec<u8>]) -> Vec<&Vec<u8>> {
    frames
        .iter()
        .filter(|f| ethertype(f) == 0x0800 && f.get(ETH_HDR_LEN + 9) == Some(&6))
        .collect()
}

/// `peer` (at `peer_mac`) answers our ARP request on `iface`.
fn arp_reply(iface: &str, local: [u8; 4], peer: [u8; 4], peer_mac: [u8; 6]) {
    let request = crate::pkt::ArpPacket {
        op: crate::pkt::ARP_OP_REQUEST,
        sha: OUR_MAC,
        spa: local,
        tha: [0; 6],
        tpa: peer,
    };
    let mut frame = [0u8; 64];
    let n = crate::pkt::build_arp_reply(&mut frame, peer_mac, peer, &request).unwrap_or(0);
    crate::tcp_stack::handle_arp_on_in(&frame[ETH_HDR_LEN..n], 0, Some(iface));
}

/// An active open to an on-link peer whose MAC is unknown returns at once:
/// the ARP request goes out and the SYN waits on the neighbour (Linux
/// `__neigh_event_send`) — no busy-wait in connect. The ARP reply sends the
/// SYN, addressed to the MAC it taught, and the TCB keeps that MAC.
fn smoke_connect_queues_syn_on_unresolved_neighbour() -> TestResult {
    let local = [10, 0, 99, 1];
    let _ = reset("tcp-rob-neigh", local);
    let peer = [10, 0, 99, 7];
    let peer_mac = [0x52, 0x54, 0, 0, 0, 7];
    let t0 = narf_scheduler::narf_time::monotonic_ns();
    let Ok(id) = core::connect_start_in(0, peer, 80, core::ConnectOptions::default()) else {
        return TestResult::Fail("connect_start_in failed for an on-link peer");
    };
    if narf_scheduler::narf_time::monotonic_ns() - t0 > 200_000_000 {
        return TestResult::Fail("connect_start_in waited on ARP");
    }
    let frames = drain();
    if arp_requests_for(&frames, peer) != 1 || !tcp_frames(&frames).is_empty() {
        return TestResult::Fail("want exactly one ARP request and no SYN before resolution");
    }
    if crate::arp_cache::__pending_count("tcp-rob-neigh", peer) != 1 {
        return TestResult::Fail("the SYN is not queued on the neighbour");
    }
    arp_reply("tcp-rob-neigh", local, peer, peer_mac);
    let frames = drain();
    let syns = tcp_frames(&frames);
    if syns.len() != 1 || frame_flags(syns[0]) & FLAG_SYN == 0 || syns[0][..6] != peer_mac {
        return TestResult::Fail("the ARP reply did not send the SYN to the taught MAC");
    }
    if __with_tcb(id, |t| t.remote_mac) != Some(peer_mac) {
        return TestResult::Fail("the TCB did not keep the resolved MAC");
    }
    if crate::arp_cache::__pending_count("tcp-rob-neigh", peer) != 0 {
        return TestResult::Fail("the neighbour queue was not drained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_connect_queues_syn_on_unresolved_neighbour
);

/// Resolution giving up fails the queued SYN back to its socket as an ICMP
/// host unreachable (`arp_error_report` → `tcp_v4_err`): the connect ends
/// with EHOSTUNREACH once the probes are spent, and every probe was sent.
fn smoke_connect_fails_ehostunreach_when_arp_gives_up() -> TestResult {
    let local = [10, 0, 99, 1];
    let _ = reset("tcp-rob-neigh-fail", local);
    let peer = [10, 0, 99, 8];
    let Ok(id) = core::connect_start_in(0, peer, 80, core::ConnectOptions::default()) else {
        return TestResult::Fail("connect_start_in failed");
    };
    let mut requests = arp_requests_for(&drain(), peer);
    // `connect_status` takes the error (`sock_error`), so keep what it said.
    let mut status = core::connect_status(id);
    for _ in 0..16 {
        if status != core::ConnectStatus::InProgress {
            break;
        }
        crate::arp_cache::__force_retrans_due("tcp-rob-neigh-fail", peer);
        crate::tcp_stack::neigh_tick();
        requests += arp_requests_for(&drain(), peer);
        status = core::connect_status(id);
    }
    if requests != 6 {
        return TestResult::Fail("want the full probe budget (6 requests) before giving up");
    }
    if status != core::ConnectStatus::Failed(narf_lib::errno::EHOSTUNREACH as i32) {
        return TestResult::Fail("a connect whose neighbour failed must be EHOSTUNREACH");
    }
    if crate::arp_cache::__pending_count("tcp-rob-neigh-fail", peer) != 0 {
        return TestResult::Fail("the failed neighbour kept its queue");
    }
    core::release(id);
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_connect_fails_ehostunreach_when_arp_gives_up
);

/// A SYN from a peer whose MAC we do not know is answered without waiting in
/// the RX path: the SYN-ACK queues on the neighbour and goes out with the ARP
/// reply. (This used to spin up to 500 ms inside the receive handler.)
fn smoke_passive_synack_queues_on_unresolved_neighbour() -> TestResult {
    let local = [10, 0, 99, 1];
    let _ = reset("tcp-rob-neigh-rx", local);
    let peer = [10, 0, 99, 9];
    let peer_mac = [0x52, 0x54, 0, 0, 0, 9];
    if listen(local, 8080, 16).is_err() {
        return TestResult::Fail("setup: listen failed");
    }
    let t0 = narf_scheduler::narf_time::monotonic_ns();
    inject(Seg {
        src: peer,
        dst: local,
        sport: 40_300,
        dport: 8080,
        seq: 0x1000,
        ack: 0,
        flags: FLAG_SYN,
        window: 65535,
        options: Vec::new(),
        payload: &[],
    });
    if narf_scheduler::narf_time::monotonic_ns() - t0 > 200_000_000 {
        return TestResult::Fail("the RX path waited on ARP for a SYN-ACK");
    }
    let frames = drain();
    if arp_requests_for(&frames, peer) != 1 || !tcp_frames(&frames).is_empty() {
        return TestResult::Fail("want an ARP request and the SYN-ACK held back");
    }
    arp_reply("tcp-rob-neigh-rx", local, peer, peer_mac);
    let frames = drain();
    let out = tcp_frames(&frames);
    if out.len() != 1
        || frame_flags(out[0]) & (FLAG_SYN | FLAG_ACK) != FLAG_SYN | FLAG_ACK
        || out[0][..6] != peer_mac
    {
        return TestResult::Fail("the ARP reply did not send the SYN-ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_passive_synack_queues_on_unresolved_neighbour
);

/// `unres_qlen_bytes`: a neighbour holds at most `UNRES_QLEN_BYTES` of queued
/// transmits; past it the oldest are dropped (never called), and the rest
/// run in order when the neighbour resolves.
fn smoke_neigh_queue_drops_oldest_past_unres_qlen_bytes() -> TestResult {
    use ::core::sync::atomic::{AtomicU32, Ordering};
    static SENT: AtomicU32 = AtomicU32::new(0);
    static ORDER_OK: AtomicU32 = AtomicU32::new(1);
    static LAST: AtomicU32 = AtomicU32::new(0);
    let local = [10, 0, 99, 1];
    let _ = reset("tcp-rob-neigh-q", local);
    SENT.store(0, Ordering::SeqCst);
    LAST.store(0, Ordering::SeqCst);
    ORDER_OK.store(1, Ordering::SeqCst);
    let peer = [10, 0, 99, 10];
    let chunk = crate::arp_cache::UNRES_QLEN_BYTES / 4;
    for i in 1..=6u32 {
        crate::tcp_stack::neigh_output_in(
            0,
            peer,
            chunk,
            alloc::boxed::Box::new(move |mac| {
                if mac.is_some() {
                    SENT.fetch_add(1, Ordering::SeqCst);
                    if LAST.swap(i, Ordering::SeqCst) >= i {
                        ORDER_OK.store(0, Ordering::SeqCst);
                    }
                }
            }),
        );
    }
    if crate::arp_cache::__pending_count("tcp-rob-neigh-q", peer) != 4 {
        return TestResult::Fail("the queue did not cap at unres_qlen_bytes");
    }
    arp_reply("tcp-rob-neigh-q", local, peer, [0x52, 0x54, 0, 0, 0, 10]);
    if SENT.load(Ordering::SeqCst) != 4 || ORDER_OK.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("the four newest transmits must run, in order");
    }
    if LAST.load(Ordering::SeqCst) != 6 {
        return TestResult::Fail("the oldest transmits were not the ones dropped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_neigh_queue_drops_oldest_past_unres_qlen_bytes
);

// ── TIME-WAIT reuse ─────────────────────────────────────────────────────

/// A bare SYN from `peer:pport` to `local:lport` at `seq`.
fn syn(local: [u8; 4], lport: u16, peer: [u8; 4], pport: u16, seq: u32) -> Seg<'static> {
    Seg {
        src: peer,
        dst: local,
        sport: pport,
        dport: lport,
        seq,
        ack: 0,
        flags: FLAG_SYN,
        window: 65535,
        options: Vec::new(),
        payload: &[],
    }
}

fn syn_acks(frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter(|f| frame_flags(f) & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK)
        .count()
}

/// A new SYN for a 4-tuple in TIME-WAIT reopens it when its sequence number
/// is past RCV.NXT (Linux `tcp_timewait_state_process` → `TCP_TW_SYN`, then
/// `tcp_v4_rcv` hands it to the listener). Under connection churn through a
/// NAT the peer reuses a port while our side still holds it in TIME-WAIT;
/// dropping that SYN hung the new connection.
fn smoke_time_wait_new_syn_reopens() -> TestResult {
    let local = [10, 0, 96, 1];
    let peer = reset("tcp-rob-twsyn", local);
    if listen(local, 7_795, 16).is_err() {
        return TestResult::Fail("setup: listen failed");
    }
    let tw = __install_test_tcb(local, 7_795, peer, 40_100, TcpState::TimeWait);
    let rcv_nxt = __with_tcb(tw, |t| t.rcv_nxt).unwrap_or(0);
    let _ = drain();
    inject(syn(
        local,
        7_795,
        peer,
        40_100,
        rcv_nxt.wrapping_add(100_000),
    ));
    if lookup_tcb(tw).is_some() {
        return TestResult::Fail("a new SYN did not end TIME-WAIT");
    }
    if syn_acks(&drain()) != 1 {
        return TestResult::Fail("the listener did not answer the new SYN with a SYN-ACK");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_time_wait_new_syn_reopens);

/// An old duplicate SYN (sequence at or before RCV.NXT, no newer timestamp)
/// leaves TIME-WAIT alone and is only ACKed; so is any SYN when nothing
/// listens on the port.
fn smoke_time_wait_old_syn_ignored() -> TestResult {
    let local = [10, 0, 97, 1];
    let peer = reset("tcp-rob-twold", local);
    if listen(local, 7_796, 16).is_err() {
        return TestResult::Fail("setup: listen failed");
    }
    let tw = __install_test_tcb(local, 7_796, peer, 40_101, TcpState::TimeWait);
    let rcv_nxt = __with_tcb(tw, |t| t.rcv_nxt).unwrap_or(0);
    let _ = drain();
    inject(syn(local, 7_796, peer, 40_101, rcv_nxt.wrapping_sub(1_000)));
    if __with_tcb(tw, |t| t.state) != Some(TcpState::TimeWait) {
        return TestResult::Fail("an old duplicate SYN ended TIME-WAIT");
    }
    if syn_acks(&drain()) != 0 {
        return TestResult::Fail("an old duplicate SYN opened a connection");
    }
    // No listener: the TIME-WAIT connection stays, whatever the sequence.
    let tw2 = __install_test_tcb(local, 7_797, peer, 40_102, TcpState::TimeWait);
    let rcv_nxt = __with_tcb(tw2, |t| t.rcv_nxt).unwrap_or(0);
    inject(syn(
        local,
        7_797,
        peer,
        40_102,
        rcv_nxt.wrapping_add(100_000),
    ));
    if __with_tcb(tw2, |t| t.state) != Some(TcpState::TimeWait) {
        return TestResult::Fail("a SYN with no listener ended TIME-WAIT");
    }
    if syn_acks(&drain()) != 0 {
        return TestResult::Fail("a SYN with no listener opened a connection");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_time_wait_old_syn_ignored);

// ── Keepalive ───────────────────────────────────────────────────────────

/// Arm keepalive (1 s idle / 1 s interval / 3 probes) on `id` and make it
/// look idle for the full window, so the next tick is due.
fn keepalive_idle(id: u32) {
    let _ = __with_tcb_mut(id, |t| {
        t.keepalive_enabled = true;
        t.keepalive_idle_ns = 1_000_000_000;
        t.keepalive_intvl_ns = 1_000_000_000;
        t.keepalive_cnt = 3;
        let window = narf_scheduler::narf_time::ns_to_cycles(10_000_000_000);
        // Timer elapsed time uses wrapping subtraction. Match it even when
        // this split-suite boot has not yet been up for the idle window.
        t.last_progress_cycles = narf_scheduler::narf_time::now_cycles().wrapping_sub(window);
    });
}

fn tick(id: u32) {
    if let Some(arc) = lookup_tcb(id) {
        tick_retransmit(&arc);
    }
}

/// A keepalive probe the peer answers keeps the connection alive: the bare
/// ACK at SND.UNA clears the probe count and restarts the idle clock (Linux
/// `tcp_ack`: `icsk_probes_out = 0`, `rcv_tstamp`). Only ACKs that advanced
/// SND.UNA used to count, so an idle connection died after `keepcnt`
/// answered probes. Unanswered, it still dies with ETIMEDOUT.
fn smoke_keepalive_answered_probe_keeps_connection() -> TestResult {
    let local = [10, 0, 98, 1];
    let peer = reset("tcp-rob-ka", local);
    let id = established(local, 40_200, peer, 80);
    let (snd_una, rcv_nxt) = __with_tcb(id, |t| (t.snd_una, t.rcv_nxt)).unwrap_or((0, 0));
    for _ in 0..6 {
        keepalive_idle(id);
        let _ = drain();
        tick(id);
        if drain().is_empty() {
            return TestResult::Fail("an idle connection sent no keepalive probe");
        }
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 40_200,
            seq: rcv_nxt,
            ack: snd_una,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[],
        });
        if __with_tcb(id, |t| t.keepalive_probes_sent) != Some(0) {
            return TestResult::Fail(
                "the answer to a keepalive probe did not reset the probe count",
            );
        }
    }
    // Unanswered: three probes, then the connection is dropped.
    for _ in 0..4 {
        let _ = __with_tcb_mut(id, |t| {
            let window = narf_scheduler::narf_time::ns_to_cycles(10_000_000_000);
            t.last_progress_cycles = narf_scheduler::narf_time::now_cycles().wrapping_sub(window);
        });
        tick(id);
    }
    if lookup_tcb(id).is_some() {
        return TestResult::Fail("unanswered keepalive probes never dropped the connection");
    }
    if recv_errno(id, &mut [0u8; 4]) != Err(narf_lib::errno::ETIMEDOUT as i32) {
        return TestResult::Fail("a keepalive timeout must report ETIMEDOUT");
    }
    core::release(id);
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_keepalive_answered_probe_keeps_connection
);

// ── Resets (RFC 5961) ───────────────────────────────────────────────────

/// Fill the receive buffer so the advertised window is 0.
fn fill_receive_window(id: u32, local: [u8; 4], lport: u16, peer: [u8; 4], pport: u16) {
    let (mut seq, limit) = __with_tcb(id, |t| (t.rcv_nxt, t.recv_buf.limit)).unwrap_or((0, 0));
    let chunk = [0x11u8; 1400];
    let mut left = limit;
    while left > 0 {
        let n = left.min(chunk.len());
        inject(Seg {
            src: peer,
            dst: local,
            sport: pport,
            dport: lport,
            seq,
            ack: 0x10000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &chunk[..n],
        });
        seq = seq.wrapping_add(n as u32);
        left -= n;
    }
}

/// A peer's abort at exactly RCV.NXT resets the connection even while our
/// receive window is closed. The old check demanded SEG.SEQ < RCV.NXT +
/// RCV.WND, which no sequence number satisfies when RCV.WND is 0, so a
/// paused reader (a video player between bursts) never saw the reset.
fn smoke_exact_rst_accepted_with_zero_window() -> TestResult {
    let local = [10, 0, 93, 1];
    let peer = reset("tcp-rob-rst0", local);
    let id = established(local, 40_002, peer, 80);
    fill_receive_window(id, local, 40_002, peer, 80);
    if __with_tcb(id, |t| t.recv_buf.window()).unwrap_or(1) != 0 {
        return TestResult::Fail("setup: the receive window did not close");
    }
    let (rcv_nxt, queued) =
        __with_tcb(id, |t| (t.rcv_nxt, t.recv_buf.in_order_len())).unwrap_or((0, 0));
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_002,
        seq: rcv_nxt,
        ack: 0,
        flags: FLAG_RST,
        window: 0,
        options: Vec::new(),
        payload: &[],
    });
    if lookup_tcb(id).is_some() {
        return TestResult::Fail("an exact-sequence RST was ignored with a zero window");
    }
    // `tcp_done` keeps the receive queue: the full window is read first.
    let (mut got, mut buf) = (0usize, [0u8; 4096]);
    let end = loop {
        match recv_errno(id, &mut buf) {
            Ok(n) if n > 0 => {
                if buf[..n].iter().any(|&b| b != 0x11) {
                    return TestResult::Fail("unread bytes corrupted by the reset");
                }
                got += n;
            }
            other => break other,
        }
    };
    if queued == 0 || got != queued {
        return TestResult::Fail("the unread window was not readable after the reset");
    }
    if end != Err(narf_lib::errno::ECONNRESET as i32) {
        return TestResult::Fail("the reset was not reported as ECONNRESET");
    }
    core::release(id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_exact_rst_accepted_with_zero_window);

/// An RST in the window but not at RCV.NXT draws a challenge ACK and leaves
/// the connection alone (RFC 5961 §3.2); an RST outside the window is
/// dropped without an answer.
fn smoke_inexact_rst_challenged_not_reset() -> TestResult {
    let local = [10, 0, 94, 1];
    let peer = reset("tcp-rob-rst1", local);
    let id = established(local, 40_003, peer, 80);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    let _ = drain();
    let rst = |seq: u32| {
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 40_003,
            seq,
            ack: 0,
            flags: FLAG_RST,
            window: 0,
            options: Vec::new(),
            payload: &[],
        })
    };
    rst(rcv_nxt.wrapping_add(1000));
    if lookup_tcb(id).is_none() {
        return TestResult::Fail("an in-window but inexact RST reset the connection");
    }
    let sent = drain();
    if !sent
        .iter()
        .any(|f| frame_flags(f) & FLAG_ACK != 0 && frame_flags(f) & FLAG_RST == 0)
    {
        return TestResult::Fail("no challenge ACK for an inexact RST");
    }
    rst(rcv_nxt.wrapping_add(0x4000_0000));
    if lookup_tcb(id).is_none() {
        return TestResult::Fail("an out-of-window RST reset the connection");
    }
    if !drain().is_empty() {
        return TestResult::Fail("an out-of-window RST was answered");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_inexact_rst_challenged_not_reset);

// ── PAWS under reordering ───────────────────────────────────────────────

/// ts_recent moves only on a segment at or left of RCV.WUP (Linux
/// `tcp_replace_ts_recent`). Taking it from an out-of-order segment made
/// PAWS drop the earlier, reordered segment — older TSval — as a stale
/// duplicate.
fn smoke_reordered_segment_survives_paws() -> TestResult {
    let local = [10, 0, 95, 1];
    let peer = reset("tcp-rob-paws", local);
    let id = established(local, 40_004, peer, 80);
    __with_tcb_mut(id, |t| {
        t.opts.timestamps_active = true;
        t.opts.ts_recent = 1000;
        t.rcv_wup = t.rcv_nxt;
    });
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    let data = [0x22u8; 1000];
    // Second segment first, sent later by the peer (higher TSval).
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_004,
        seq: rcv_nxt.wrapping_add(1000),
        ack: 0x10000,
        flags: FLAG_ACK,
        window: 65535,
        options: ts_option(1050, 0),
        payload: &data,
    });
    // Then the first one, TSval 1010.
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_004,
        seq: rcv_nxt,
        ack: 0x10000,
        flags: FLAG_ACK,
        window: 65535,
        options: ts_option(1010, 0),
        payload: &data,
    });
    let now = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    if now != rcv_nxt.wrapping_add(2000) {
        return TestResult::Fail("PAWS dropped a reordered in-window segment");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_reordered_segment_survives_paws);

// ── Close, TIME-WAIT and orphans ────────────────────────────────────────

/// Walk an established connection through our close to FIN-WAIT-2 (the
/// peer ACKs our FIN). Returns the FIN's sequence number.
fn close_to_fin_wait2(id: u32, local: [u8; 4], lport: u16, peer: [u8; 4], pport: u16) -> u32 {
    let _ = close(id);
    let (fin_seq, rcv_nxt) = __with_tcb(id, |t| (t.fin_seq, t.rcv_nxt)).unwrap_or((0, 0));
    inject(Seg {
        src: peer,
        dst: local,
        sport: pport,
        dport: lport,
        seq: rcv_nxt,
        ack: fin_seq.wrapping_add(1),
        flags: FLAG_ACK,
        window: 65535,
        options: Vec::new(),
        payload: &[],
    });
    fin_seq
}

/// A TIME-WAIT connection keeps no send/receive buffer capacity or
/// retransmit state (Linux swaps in a small `tcp_timewait_sock`).
fn smoke_time_wait_holds_no_buffers() -> TestResult {
    let local = [10, 0, 96, 1];
    let peer = reset("tcp-rob-tw", local);
    let id = established(local, 40_005, peer, 80);
    __with_tcb_mut(id, |t| {
        t.cong.cwnd = 1 << 20;
        t.snd_wnd = 1 << 20;
    });
    // Data both ways, all of it acknowledged and read.
    let _ = send(id, &[0x33; 32 * 1024]);
    let snd_nxt = __with_tcb(id, |t| t.snd_nxt).unwrap_or(0);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_005,
        seq: rcv_nxt,
        ack: snd_nxt,
        flags: FLAG_ACK,
        window: 65535,
        options: Vec::new(),
        payload: &[0x44; 1000],
    });
    let mut sink = [0u8; 2000];
    let _ = recv_errno(id, &mut sink);
    close_to_fin_wait2(id, local, 40_005, peer, 80);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    let snd_nxt = __with_tcb(id, |t| t.snd_nxt).unwrap_or(0);
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_005,
        seq: rcv_nxt,
        ack: snd_nxt,
        flags: FLAG_ACK | FLAG_FIN,
        window: 65535,
        options: Vec::new(),
        payload: &[],
    });
    let held = __with_tcb(id, |t| {
        (
            t.state,
            t.send_buf.capacity() + t.recv_buf.capacity(),
            t.retx_queue.capacity(),
        )
    });
    match held {
        Some((TcpState::TimeWait, 0, 0)) => TestResult::Pass,
        Some((TcpState::TimeWait, _, _)) => {
            TestResult::Fail("a TIME-WAIT connection still holds buffer capacity")
        }
        _ => TestResult::Fail("setup: did not reach TIME-WAIT"),
    }
}
kernel_test_in!("net/tcp/robust", smoke_time_wait_holds_no_buffers);

/// An orphaned connection in FIN-WAIT-2 is torn down after `tcp_fin_timeout`
/// if the peer never sends its FIN; before, it lived forever.
fn smoke_orphan_fin_wait2_times_out() -> TestResult {
    let local = [10, 0, 97, 1];
    let peer = reset("tcp-rob-fw2", local);
    let id = established(local, 40_006, peer, 80);
    close_to_fin_wait2(id, local, 40_006, peer, 80);
    let armed = __with_tcb(id, |t| (t.state, t.time_wait_deadline_cycles != 0));
    if armed != Some((TcpState::FinWait2, true)) {
        return TestResult::Fail("an orphaned FIN-WAIT-2 connection has no fin timeout");
    }
    __with_tcb_mut(id, |t| t.time_wait_deadline_cycles = 1);
    if let Some(arc) = lookup_tcb(id) {
        tick_retransmit(&arc);
    }
    if lookup_tcb(id).is_some() {
        return TestResult::Fail("the orphaned FIN-WAIT-2 connection outlived tcp_fin_timeout");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_orphan_fin_wait2_times_out);

/// close() with received data still unread resets the connection (Linux
/// `tcp_close`: `data_was_unread` → `tcp_send_active_reset`) instead of
/// sending a FIN the peer would take for a clean end.
fn smoke_close_with_unread_data_resets() -> TestResult {
    let local = [10, 0, 98, 1];
    let peer = reset("tcp-rob-unread", local);
    let id = established(local, 40_007, peer, 80);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_007,
        seq: rcv_nxt,
        ack: 0x10000,
        flags: FLAG_ACK,
        window: 65535,
        options: Vec::new(),
        payload: &[0x55; 500],
    });
    let _ = drain();
    let _ = close(id);
    let sent = drain();
    if sent.iter().any(|f| frame_flags(f) & FLAG_FIN != 0) {
        return TestResult::Fail("close() with unread data sent a FIN");
    }
    if !sent.iter().any(|f| frame_flags(f) & FLAG_RST != 0) {
        return TestResult::Fail("close() with unread data sent no RST");
    }
    if lookup_tcb(id).is_some() {
        return TestResult::Fail("the reset connection is still in the table");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_close_with_unread_data_resets);

/// SO_LINGER {1, 0}: close aborts with an RST, never a FIN.
fn smoke_zero_linger_close_resets() -> TestResult {
    let local = [10, 0, 99, 1];
    let peer = reset("tcp-rob-linger", local);
    let id = established(local, 40_008, peer, 80);
    let _ = drain();
    let _ = core::close_linger(id, true);
    let sent = drain();
    if sent.iter().any(|f| frame_flags(f) & FLAG_FIN != 0)
        || !sent.iter().any(|f| frame_flags(f) & FLAG_RST != 0)
    {
        return TestResult::Fail("a zero-linger close did not abort with an RST");
    }
    if lookup_tcb(id).is_some() {
        return TestResult::Fail("the aborted connection is still in the table");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_zero_linger_close_resets);

// ── Queue ioctls and MSG_PEEK ───────────────────────────────────────────

/// SIOCINQ is the readable byte count, SIOCOUTQ the unacknowledged bytes
/// (`write_seq - snd_una`), SIOCOUTQNSD the unsent ones; a listener is
/// EINVAL (Linux `tcp_ioctl`). NARF used to answer 0 for every TCP socket.
fn smoke_queue_ioctls_count_bytes() -> TestResult {
    let local = [10, 0, 100, 1];
    let peer = reset("tcp-rob-ioctl", local);
    let id = established(local, 40_009, peer, 80);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_009,
        seq: rcv_nxt,
        ack: 0x10000,
        flags: FLAG_ACK,
        window: 65535,
        options: Vec::new(),
        payload: &[0x66; 700],
    });
    if queue_ioctl(id, TcpQueueIoctl::Inq) != Ok(700) {
        return TestResult::Fail("SIOCINQ does not count the queued bytes");
    }
    // The peer's window holds the queue back: nothing goes out.
    __with_tcb_mut(id, |t| t.snd_wnd = 0);
    let _ = send(id, &[0x77; 3000]);
    if queue_ioctl(id, TcpQueueIoctl::Outq) != Ok(3000) {
        return TestResult::Fail("SIOCOUTQ does not count the unacknowledged bytes");
    }
    if queue_ioctl(id, TcpQueueIoctl::OutqNsd) != Ok(3000) {
        return TestResult::Fail("SIOCOUTQNSD does not count the unsent bytes");
    }
    let listener = match core::listen(local, 40_010, 4) {
        Ok(l) => l,
        Err(()) => return TestResult::Fail("listen failed"),
    };
    if queue_ioctl(listener, TcpQueueIoctl::Inq) != Err(narf_lib::errno::EINVAL as i32) {
        return TestResult::Fail("SIOCINQ on a listener is not EINVAL");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_queue_ioctls_count_bytes);

/// MSG_PEEK copies queued bytes without consuming them.
fn smoke_peek_leaves_data_queued() -> TestResult {
    let local = [10, 0, 101, 1];
    let peer = reset("tcp-rob-peek", local);
    let id = established(local, 40_011, peer, 80);
    let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
    let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    inject(Seg {
        src: peer,
        dst: local,
        sport: 80,
        dport: 40_011,
        seq: rcv_nxt,
        ack: 0x10000,
        flags: FLAG_ACK,
        window: 65535,
        options: Vec::new(),
        payload: &data,
    });
    let mut a = [0u8; 100];
    if recv_peek_errno(id, &mut a) != Ok(100) || a[..] != data[..100] {
        return TestResult::Fail("MSG_PEEK did not copy the head of the queue");
    }
    let mut b = [0u8; 300];
    if recv_errno(id, &mut b) != Ok(300) || b[..] != data[..] {
        return TestResult::Fail("MSG_PEEK consumed the bytes it copied");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_peek_leaves_data_queued);

// ── Wakeups in the half-closed states ───────────────────────────────────

/// Data or a FIN arriving after our own FIN (FIN-WAIT-1 / FIN-WAIT-2) must
/// wake the reader. Only ESTABLISHED used to notify, so a client that shut
/// down its write side and then read the response hung with a full receive
/// queue.
fn smoke_half_closed_receive_wakes_reader() -> TestResult {
    let local = [10, 0, 102, 1];
    let peer = reset("tcp-rob-hc", local);
    for (state, port) in [
        (TcpState::FinWait1, 40_012u16),
        (TcpState::FinWait2, 40_013),
    ] {
        let id = __install_test_tcb(local, port, peer, 80, state);
        let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
        let gen = crate::readiness::generation();
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: port,
            seq: rcv_nxt,
            ack: 0x10000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[0x88; 100],
        });
        if crate::readiness::generation() == gen {
            return TestResult::Fail("data in a half-closed state did not wake the reader");
        }
        let gen = crate::readiness::generation();
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: port,
            seq: rcv_nxt.wrapping_add(100),
            ack: 0x10000,
            flags: FLAG_ACK | FLAG_FIN,
            window: 65535,
            options: Vec::new(),
            payload: &[],
        });
        if crate::readiness::generation() == gen {
            return TestResult::Fail(
                "the peer's FIN in a half-closed state did not wake the reader",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_half_closed_receive_wakes_reader);

/// Deliver `segments` in-order 1400-byte data segments and read them all.
fn stream_and_read(id: u32, local: [u8; 4], peer: [u8; 4], port: u16, segments: usize) -> usize {
    let payload = [0x5a; 1400];
    for _ in 0..segments {
        let seq = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: port,
            seq,
            ack: 0x10000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &payload,
        });
    }
    let mut buf = vec![0u8; segments * payload.len()];
    recv_errno(id, &mut buf).unwrap_or(0)
}

/// Physical I225, browser download at a third of line rate: every
/// connection advertised the fixed 256 KiB receive buffer for its whole
/// life, which bounds a sender at 256 KiB per round trip. Linux
/// `tcp_rcv_space_adjust` grows the buffer while the reader keeps pace, and
/// leaves a buffer the application sized with `SO_RCVBUF` alone.
fn smoke_receive_buffer_autotunes_past_default() -> TestResult {
    use crate::tcp::socket_buf::DEFAULT_RCV_BUF;
    let local = [10, 91, 0, 1];
    let peer = reset("rcvtune0", local);
    let id = established(local, 7_901, peer, 80);
    let _ = __with_tcb_mut(id, |t| {
        t.opts.wscale_active = true;
        t.opts.our_wscale = 7;
    });
    // Less than one advertised window: no receiver RTT sample yet, so the
    // buffer must not move however much was read.
    if stream_and_read(id, local, peer, 7_901, 100) != 140_000 {
        return TestResult::Fail("in-order data was not readable");
    }
    if __with_tcb(id, |t| t.recv_buf.limit) != Some(DEFAULT_RCV_BUF) {
        return TestResult::Fail("receive buffer changed before any RTT sample");
    }
    // A full advertised window has now arrived: that is the RTT sample, and
    // the reader took all of it within the round.
    let _ = drain();
    if stream_and_read(id, local, peer, 7_901, 100) != 140_000 {
        return TestResult::Fail("in-order data was not readable");
    }
    let (limit, sampled) =
        __with_tcb(id, |t| (t.recv_buf.limit, t.rcv_space.rtt_us8 != 0)).unwrap_or((0, false));
    if !sampled {
        return TestResult::Fail("a full window of data produced no receiver RTT sample");
    }
    if limit <= DEFAULT_RCV_BUF {
        return TestResult::Fail("receive buffer did not grow for a reader that kept pace");
    }
    if limit > 6_291_456 / 2 {
        return TestResult::Fail("receive buffer grew past tcp_rmem[2]");
    }
    // The larger window must reach the peer: the read's window update
    // advertises it (scaled by 2^7).
    let advertised = drain()
        .iter()
        .filter(|f| ethertype(f) == 0x0800 && f.len() >= TCP_OFF + 20)
        .map(|f| u32::from(u16::from_be_bytes([f[TCP_OFF + 14], f[TCP_OFF + 15]])) << 7)
        .max()
        .unwrap_or(0);
    if advertised <= DEFAULT_RCV_BUF as u32 {
        return TestResult::Fail("the grown receive window was never advertised");
    }

    // SO_RCVBUF (SOCK_RCVBUF_LOCK) pins the buffer through the same traffic.
    let locked = established(local, 7_902, peer, 80);
    if core::set_buffer_limits(locked, None, Some(2 * DEFAULT_RCV_BUF as u32)).is_err() {
        return TestResult::Fail("SO_RCVBUF was rejected");
    }
    for _ in 0..2 {
        let _ = stream_and_read(locked, local, peer, 7_902, 100);
    }
    let (limit, measured) =
        __with_tcb(locked, |t| (t.recv_buf.limit, t.rcv_space.space)).unwrap_or((0, 0));
    if limit != DEFAULT_RCV_BUF {
        return TestResult::Fail("autotuning resized a buffer the application locked");
    }
    if measured == 0 {
        return TestResult::Fail("a locked buffer stopped the consumption measurement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_receive_buffer_autotunes_past_default
);

/// The upload half of the same defect: the 256 KiB send buffer bounds the
/// flight whatever the congestion window. Linux `tcp_sndbuf_expand` gives a
/// writer that filled its buffer room for twice the window, up to
/// `tcp_wmem[2]`, unless `SO_SNDBUF` fixed the size.
fn smoke_send_buffer_expands_with_congestion_window() -> TestResult {
    use crate::tcp::socket_buf::DEFAULT_SND_BUF;
    let local = [10, 92, 0, 1];
    let peer = reset("sndtune0", local);
    let data = vec![0x33u8; DEFAULT_SND_BUF + 4096];
    for (port, lock) in [(7_911u16, false), (7_912, true)] {
        let id = established(local, port, peer, 80);
        if lock && core::set_buffer_limits(id, Some(DEFAULT_SND_BUF as u32), None).is_err() {
            return TestResult::Fail("SO_SNDBUF was rejected");
        }
        let _ = __with_tcb_mut(id, |t| {
            t.opts.peer_wscale = 7;
            t.snd_wnd = 65_535 << 7;
            t.cong.cwnd = 1 << 20;
        });
        if send(id, &data) != Ok(DEFAULT_SND_BUF) {
            return TestResult::Fail("the writer did not fill the default send buffer");
        }
        let _ = drain();
        // The peer acknowledges part of the flight with its window open.
        let rcv_nxt = __with_tcb(id, |t| t.rcv_nxt).unwrap_or(0);
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: port,
            seq: rcv_nxt,
            ack: 0x10000 + 100_000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[],
        });
        let limit = __with_tcb(id, |t| t.send_buf.limit).unwrap_or(0);
        if lock {
            if limit != DEFAULT_SND_BUF {
                return TestResult::Fail("autotuning resized a send buffer the application locked");
            }
        } else if !(2 << 20..=4_194_304).contains(&limit) {
            return TestResult::Fail(
                "a full send buffer did not expand to twice the congestion window",
            );
        }
        let _ = drain();
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_send_buffer_expands_with_congestion_window
);

// ── Transmit backpressure (`crate::txq`) ────────────────────────────────

use crate::txq::{TxBackpressure, TxQueue, TxQueueGeometry, TxRefusal};
use alloc::collections::VecDeque;
use alloc::sync::Arc;

/// Makes the ordinary transmit hook refuse, as a device with no descriptor
/// left does.
static CAPTURE_REFUSES: ::core::sync::atomic::AtomicBool =
    ::core::sync::atomic::AtomicBool::new(false);

/// A connection to resume from inside the ordinary transmit hook: a sender
/// running between an RTO's rewind and the end of `fire_retransmit`.
static PLAIN_REENTER: ::core::sync::atomic::AtomicU32 = ::core::sync::atomic::AtomicU32::new(0);

fn refusable_send(frame: &[u8], meta: crate::TxMeta) -> Result<(), ()> {
    if CAPTURE_REFUSES.load(::core::sync::atomic::Ordering::SeqCst) {
        return Err(());
    }
    let id = PLAIN_REENTER.swap(0, ::core::sync::atomic::Ordering::SeqCst);
    if id != 0 {
        core::tx_resume(id);
    }
    capture_send(frame, meta)
}

#[derive(Debug, Default)]
struct FakeRing {
    /// Posted, not yet transmitted.
    held: VecDeque<Vec<u8>>,
    /// The charge that came with each held frame, released with it.
    charges: VecDeque<Option<crate::txq::TxCharge>>,
    /// Transmitted, in order.
    wire: Vec<Vec<u8>>,
}

const FAKE_RING_LEN: u32 = 16;

/// A TCP segment and the addresses it travels between: `(src, dst, bytes)`.
type PeerSegment = ([u8; 4], [u8; 4], Vec<u8>);

/// A one-queue device with a 16-descriptor ring that speaks the transmit
/// driver contract: one descriptor per frame, stop below 2 free, wake at 4.
#[derive(Debug)]
struct FakeNic {
    queue: Arc<TxQueue>,
    ring: IrqSafeSpinLock<FakeRing>,
    /// A connection to resume from inside the next transmit, the way an
    /// acknowledgement processed during the send re-enters the sender.
    reenter: ::core::sync::atomic::AtomicU32,
    /// The queue object after a resize; `queue` is then the stale one.
    replacement: IrqSafeSpinLock<Option<Arc<TxQueue>>>,
    /// Frames offered, accepted or not.
    offers: ::core::sync::atomic::AtomicU32,
    /// Answer `Busy` without stopping the queue: a driver breaking the
    /// contract, which must still not make the sender spin.
    busy_unstopped: ::core::sync::atomic::AtomicBool,
    /// A segment the peer delivers right after the next accepted frame:
    /// its ACK overtakes the sender's own bookkeeping for that frame.
    on_accept: IrqSafeSpinLock<Option<PeerSegment>>,
    /// Refuse, once, the frame that starts at this sequence number.
    refuse_seq: ::core::sync::atomic::AtomicU32,
    /// A segment `(src, dst, bytes)` the peer delivers during that refusal:
    /// after the device said no, before the sender takes its lock again.
    on_refuse: IrqSafeSpinLock<Option<PeerSegment>>,
}

impl FakeNic {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: TxQueue::new(TxQueueGeometry {
                ring_len: FAKE_RING_LEN,
                max_frame_descs: 2,
            }),
            ring: IrqSafeSpinLock::new(FakeRing::default()),
            reenter: ::core::sync::atomic::AtomicU32::new(0),
            replacement: IrqSafeSpinLock::new(None),
            offers: ::core::sync::atomic::AtomicU32::new(0),
            busy_unstopped: ::core::sync::atomic::AtomicBool::new(false),
            on_accept: IrqSafeSpinLock::new(None),
            refuse_seq: ::core::sync::atomic::AtomicU32::new(0),
            on_refuse: IrqSafeSpinLock::new(None),
        })
    }
    fn free(ring: &FakeRing) -> u32 {
        FAKE_RING_LEN - 1 - ring.held.len() as u32
    }
    /// The queue object the driver currently uses.
    fn current(&self) -> Arc<TxQueue> {
        self.replacement
            .lock()
            .clone()
            .unwrap_or_else(|| self.queue.clone())
    }
    /// `ethtool -G`: a new queue object for the same ring.
    fn replace_queue(&self) -> Arc<TxQueue> {
        let queue = TxQueue::new(TxQueueGeometry {
            ring_len: FAKE_RING_LEN,
            max_frame_descs: 2,
        });
        *self.replacement.lock() = Some(queue.clone());
        queue
    }
    fn post(&self, frame: &[u8], charge: Option<crate::txq::TxCharge>) -> Result<(), TxRefusal> {
        self.offers
            .fetch_add(1, ::core::sync::atomic::Ordering::SeqCst);
        if self
            .busy_unstopped
            .load(::core::sync::atomic::Ordering::SeqCst)
        {
            return Err(TxRefusal::Busy);
        }
        let seq = tcp_parts(frame).0;
        if self
            .refuse_seq
            .compare_exchange(
                seq,
                0,
                ::core::sync::atomic::Ordering::SeqCst,
                ::core::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            self.current().refused();
            let delivered = self.on_refuse.lock().take();
            if let Some((src, dst, segment)) = delivered {
                handle_segment(src, dst, &segment);
            }
            return Err(TxRefusal::Busy);
        }
        {
            let queue = self.current();
            let mut ring = self.ring.lock();
            if queue.is_stopped() || Self::free(&ring) == 0 {
                queue.refused();
                return Err(TxRefusal::Busy);
            }
            ring.held.push_back(frame.to_vec());
            ring.charges.push_back(charge);
            let free = Self::free(&ring);
            queue.sent(frame.len() as u32, || free);
        }
        let delivered = self.on_accept.lock().take();
        if let Some((src, dst, segment)) = delivered {
            handle_segment(src, dst, &segment);
        }
        let id = self.reenter.swap(0, ::core::sync::atomic::Ordering::SeqCst);
        if id != 0 {
            core::tx_resume(id);
        }
        Ok(())
    }
    /// The device transmitted up to `n` frames: one reclaim batch.
    fn complete(&self, n: usize) {
        let mut ring = self.ring.lock();
        let mut bytes = 0u64;
        let mut done = 0u32;
        while (done as usize) < n {
            let Some(frame) = ring.held.pop_front() else {
                break;
            };
            bytes += frame.len() as u64;
            ring.wire.push(frame);
            ring.charges.pop_front();
            done += 1;
        }
        let free = Self::free(&ring);
        self.current().completed(done, bytes, free);
    }
    /// A watchdog reset: whatever the ring held is discarded.
    fn reset(&self) -> usize {
        let mut ring = self.ring.lock();
        let lost = ring.held.len();
        ring.held.clear();
        ring.charges.clear();
        self.queue.reset();
        lost
    }
    fn held(&self) -> Vec<Vec<u8>> {
        self.ring.lock().held.iter().cloned().collect()
    }
    fn wire(&self) -> Vec<Vec<u8>> {
        self.ring.lock().wire.clone()
    }
}

impl TxBackpressure for FakeNic {
    fn tx_queue_count(&self) -> u16 {
        1
    }
    fn tx_queue(&self, q: u16) -> Option<Arc<TxQueue>> {
        (q == 0).then(|| self.current())
    }
    fn tx_select_queue(&self, _frame: &[u8]) -> u16 {
        0
    }
    fn tx_link_speed_mbps(&self) -> u32 {
        0
    }
    fn try_xmit(
        &self,
        _q: u16,
        frame: crate::Frame,
        _meta: crate::TxMeta,
    ) -> Result<(), TxRefusal> {
        self.post(frame.payload(), None)
    }
    fn try_xmit_copy(
        &self,
        _q: u16,
        frame: &[u8],
        _meta: crate::TxMeta,
        charge: Option<crate::txq::TxCharge>,
    ) -> Result<(), TxRefusal> {
        self.post(frame, charge)
    }
}

/// An established connection whose egress is a [`FakeNic`], with windows
/// wide enough that only the device limits it.
fn backpressure_conn(
    name: &'static str,
    local: [u8; 4],
    port: u16,
) -> (Arc<FakeNic>, u32, [u8; 4]) {
    CAPTURE_REFUSES.store(false, ::core::sync::atomic::Ordering::SeqCst);
    core::__reset_for_test();
    route::__reset_for_test();
    arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    CAPTURE.lock().clear();
    iface::register(name, [0x02, 0, 0, 0, 0, 0x32], refusable_send);
    iface::set_default_ipv4(local, local);
    iface::add_addr(name, local, 24);
    let peer = [local[0], local[1], local[2], 2];
    let peer_mac = [0x52, 0x54, 0, 0, 0, 1];
    crate::tcp_stack::__arp_insert_legacy(peer, peer_mac);
    arp_cache::insert(name, peer, peer_mac);
    let nic = FakeNic::new();
    let _ = iface::set_tx_backpressure(name, nic.clone());
    let id = established(local, port, peer, 80);
    let _ = __with_tcb_mut(id, |t| {
        t.opts.peer_wscale = 7;
        t.snd_wnd = 65_535 << 7;
        t.cong.cwnd = 1 << 20;
        t.nagle_enabled = false;
    });
    (nic, id, peer)
}

/// `(sequence, flags, payload)` of a TCP frame.
fn tcp_parts(f: &[u8]) -> (u32, u8, &[u8]) {
    let seq = u32::from_be_bytes([
        f[TCP_OFF + 4],
        f[TCP_OFF + 5],
        f[TCP_OFF + 6],
        f[TCP_OFF + 7],
    ]);
    let hdr = ((f[TCP_OFF + 12] >> 4) as usize) * 4;
    let len = frame_payload_len(f);
    (seq, frame_flags(f), &f[TCP_OFF + hdr..TCP_OFF + hdr + len])
}

/// The byte stream `frames` carry from `first_seq`, or `None` if a byte is
/// missing, repeated or out of order.
fn stream_of(frames: &[Vec<u8>], first_seq: u32) -> Option<Vec<u8>> {
    let mut next = first_seq;
    let mut out = Vec::new();
    for f in frames {
        let (seq, _, payload) = tcp_parts(f);
        if payload.is_empty() {
            continue;
        }
        if seq != next {
            return None;
        }
        out.extend_from_slice(payload);
        next = next.wrapping_add(payload.len() as u32);
    }
    Some(out)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Complete five frames and run the wake pass until `want` payload bytes are
/// on the wire. False if the connection stalls.
fn drive_to_wire(nic: &FakeNic, want: usize) -> bool {
    for _ in 0..2000 {
        let on_wire: usize = nic.wire().iter().map(|f| frame_payload_len(f)).sum();
        if on_wire >= want {
            return true;
        }
        nic.complete(5);
        nic.queue.run_wakeups();
    }
    false
}

/// The defect: a burst larger than the ring. Every segment the device
/// refuses must stay unsent — not in `snd_nxt`, not in the retransmit queue
/// — and go out, in order, once completions wake the queue.
fn smoke_tx_burst_larger_than_ring_waits_and_arrives_in_order() -> TestResult {
    let (nic, id, _) = backpressure_conn("txbp0", [10, 94, 0, 1], 7_921);
    let data = pattern(120_000);
    if send(id, &data) != Ok(data.len()) {
        return TestResult::Fail("the send buffer did not take the burst");
    }
    let held = nic.held();
    // Stop threshold 2 of 15 usable descriptors: 14 frames, one kept free.
    if held.len() != 14 || !nic.queue.is_stopped() {
        return TestResult::Fail("the ring did not stop one worst-case frame short of full");
    }
    let taken: usize = held.iter().map(|f| frame_payload_len(f)).sum();
    let Some((snd_nxt, retx, waiting)) = __with_tcb(id, |t| {
        (t.snd_nxt, t.retx_queue.len(), t.tx_wait_since_cycles != 0)
    }) else {
        return TestResult::Fail("connection vanished");
    };
    if snd_nxt != 0x10000u32.wrapping_add(taken as u32) {
        return TestResult::Fail("a segment the device refused was accounted as sent");
    }
    if retx != held.len() {
        return TestResult::Fail("a refused segment was put in the retransmit queue");
    }
    if !waiting {
        return TestResult::Fail("the connection is not marked as waiting for its queue");
    }
    // A wake pass with nothing completed resumes nobody.
    nic.queue.run_wakeups();
    if nic.held().len() != held.len() {
        return TestResult::Fail("sent into a stopped queue");
    }
    if !drive_to_wire(&nic, data.len()) {
        return TestResult::Fail("the connection did not resume after completions");
    }
    if stream_of(&nic.wire(), 0x10000).as_deref() != Some(data.as_slice()) {
        return TestResult::Fail("bytes were lost, repeated or reordered across the wait");
    }
    if drain().iter().any(|f| frame_payload_len(f) != 0) {
        return TestResult::Fail("data bypassed the queue through the dropping hook");
    }
    if nic.queue.busy() == 0 || nic.queue.restarts() == 0 {
        return TestResult::Fail("the ring never pushed back");
    }
    if __with_tcb(id, |t| t.tx_wait_since_cycles) != Some(0) {
        return TestResult::Fail("still marked waiting after everything was sent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_burst_larger_than_ring_waits_and_arrives_in_order
);

/// The wake pass never runs (a lost wake): the probe timer must resume the
/// connection on its own.
fn smoke_tx_wait_probe_recovers_a_lost_wake() -> TestResult {
    let (nic, id, _) = backpressure_conn("txbp1", [10, 95, 0, 1], 7_922);
    let data = pattern(120_000);
    if send(id, &data) != Ok(data.len()) {
        return TestResult::Fail("the send buffer did not take the burst");
    }
    let stopped_with = nic.held().len();
    // Room again, but nobody runs the wake pass.
    nic.complete(stopped_with);
    if !nic.held().is_empty() {
        return TestResult::Fail("completion alone transmitted");
    }
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    // The wait began longer ago than the probe interval.
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if nic.held().is_empty() {
        return TestResult::Fail("a lost wake stalled the connection for good");
    }
    if !drive_to_wire(&nic, data.len()) || stream_of(&nic.wire(), 0x10000) != Some(data) {
        return TestResult::Fail("the stream was not completed in order after the probe");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/robust", smoke_tx_wait_probe_recovers_a_lost_wake);

/// The review's interleaving. After an RTO the sender is in go-back-N and
/// `H` is the highest byte ever sent. It marks a segment `[s, e)` with
/// `s < H < e`, the device refuses it, and before the sender takes its lock
/// again the peer's ACK for `H` is processed: the retransmit queue empties
/// and its timer stops. `[H, e)` is then marked sent, was never
/// transmitted, and nothing covers it. Un-sending must hand it back.
fn smoke_tx_refusal_with_ack_inside_segment_unsends_the_rest() -> TestResult {
    let local = [10, 100, 0, 1];
    let (nic, id, peer) = backpressure_conn("txbp6", local, 7_927);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    let mss = __with_tcb(id, core::send_mss).unwrap_or(0) as usize;
    if mss < 200 {
        return TestResult::Fail("unexpected MSS");
    }
    let iss = 0x10000u32;
    // Two and a half segments go out: H is not on a segment boundary.
    let first = 2 * mss + mss / 2;
    let data = pattern(first + 3 * mss);
    if send(id, &data[..first]) != Ok(first) || nic.held().len() != 3 {
        return TestResult::Fail("the first two and a half segments were not sent");
    }
    let high = iss.wrapping_add(first as u32);
    // RTO: rewind to snd_una and resend the head; snd_nxt = iss + mss < H.
    let _ = __with_tcb_mut(id, |t| t.retx_deadline_cycles = 1);
    tick_retransmit(&arc);
    if __with_tcb(id, |t| (t.snd_nxt, t.snd_high)) != Some((iss.wrapping_add(mss as u32), high)) {
        return TestResult::Fail("the RTO did not leave the sender in go-back-N below H");
    }
    // The RTO collapsed cwnd to one segment, all of it in flight. Recovery
    // reopens it as ACKs arrive; start from that point, with room to send.
    let _ = __with_tcb_mut(id, |t| t.cong.cwnd = 1 << 20);
    // The device will refuse the segment that straddles H, and the peer's
    // ACK for H arrives during that refusal.
    nic.refuse_seq.store(
        iss.wrapping_add(2 * mss as u32),
        ::core::sync::atomic::Ordering::SeqCst,
    );
    *nic.on_refuse.lock() = Some((
        peer,
        local,
        tcp_bytes(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 7_927,
            seq: 0x20000,
            ack: high,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[],
        }),
    ));
    if send(id, &data[first..]) != Ok(3 * mss) {
        return TestResult::Fail("the send buffer did not take the rest");
    }
    if nic.refuse_seq.load(::core::sync::atomic::Ordering::SeqCst) != 0 {
        return TestResult::Fail("the straddling segment was never offered");
    }
    let Some((snd_una, snd_nxt, snd_high, unsent)) = __with_tcb(id, |t| {
        (t.snd_una, t.snd_nxt, t.snd_high, t.send_buf.unsent_len())
    }) else {
        return TestResult::Fail("connection vanished");
    };
    if snd_una != high {
        return TestResult::Fail("the ACK for H was not processed during the refusal");
    }
    if snd_nxt != high || unsent != 3 * mss {
        return TestResult::Fail("bytes past H stayed marked sent though the device refused them");
    }
    if snd_high != high {
        return TestResult::Fail("snd_high still covers bytes that were never transmitted");
    }
    // The wake sends them, in order from H, with a timer behind them.
    nic.complete(FAKE_RING_LEN as usize);
    nic.queue.run_wakeups();
    nic.complete(FAKE_RING_LEN as usize);
    let mut covered = vec![false; data.len()];
    for f in nic.wire() {
        let (seq, _, payload) = tcp_parts(&f);
        let at = seq.wrapping_sub(iss) as usize;
        for (i, byte) in payload.iter().enumerate() {
            if data.get(at + i) != Some(byte) {
                return TestResult::Fail("a transmitted byte does not match the stream");
            }
            covered[at + i] = true;
        }
    }
    if covered.iter().any(|sent| !sent) {
        return TestResult::Fail("part of the stream was never transmitted");
    }
    if __with_tcb(id, |t| {
        t.retx_queue.is_empty() || t.retx_deadline_cycles == 0
    }) != Some(false)
    {
        return TestResult::Fail("the re-sent bytes are covered by no retransmit timer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_refusal_with_ack_inside_segment_unsends_the_rest
);

/// A watchdog reset empties the ring while a connection waits on it. The
/// waiter must be released, and the discarded frames must still be owed:
/// they were sent, so they stay in the retransmit queue for loss recovery.
fn smoke_tx_reset_releases_waiter_and_keeps_lost_frames_owed() -> TestResult {
    let (nic, id, _) = backpressure_conn("txbp2", [10, 96, 0, 1], 7_923);
    if send(id, &pattern(120_000)) != Ok(120_000) {
        return TestResult::Fail("the send buffer did not take the burst");
    }
    let snd_nxt = __with_tcb(id, |t| t.snd_nxt).unwrap_or(0);
    let lost = nic.reset();
    if lost == 0 || nic.queue.is_stopped() {
        return TestResult::Fail("reset left the queue stopped");
    }
    if nic.queue.run_wakeups() != 1 {
        return TestResult::Fail("reset did not release the waiting connection");
    }
    let resumed = nic.held();
    if resumed.is_empty() {
        return TestResult::Fail("the connection did not resume after the reset");
    }
    if tcp_parts(&resumed[0]).0 != snd_nxt {
        return TestResult::Fail("transmission did not resume at the first unsent byte");
    }
    if __with_tcb(id, |t| t.retx_queue.len()) != Some(lost + resumed.len()) {
        return TestResult::Fail("frames lost in the reset are no longer owed for retransmission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_reset_releases_waiter_and_keeps_lost_frames_owed
);

/// A connection torn down while it waits: the wake pass finds no connection
/// and sends nothing.
fn smoke_tx_wake_skips_a_connection_closed_while_waiting() -> TestResult {
    let (nic, id, _) = backpressure_conn("txbp3", [10, 97, 0, 1], 7_924);
    if send(id, &pattern(120_000)) != Ok(120_000) {
        return TestResult::Fail("the send buffer did not take the burst");
    }
    core::remove_tcb(id);
    nic.complete(nic.held().len());
    if nic.queue.run_wakeups() != 1 {
        return TestResult::Fail("the closed connection was not on the wake list");
    }
    if !nic.held().is_empty() {
        return TestResult::Fail("a closed connection transmitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_wake_skips_a_connection_closed_while_waiting
);

/// Three things at once: the sender is re-entered from inside the device's
/// transmit (one pumper at a time, or the stream reorders), a pure ACK is
/// owed while the data queue is stopped (it must not wait behind the data),
/// and the FIN attaches to a final segment that is refused and re-offered.
fn smoke_tx_backpressure_keeps_order_acks_flowing_and_one_fin() -> TestResult {
    let local = [10, 98, 0, 1];
    let (nic, id, peer) = backpressure_conn("txbp4", local, 7_925);
    let data = pattern(60_000);
    nic.reenter
        .store(id, ::core::sync::atomic::Ordering::SeqCst);
    if send(id, &data) != Ok(data.len()) {
        return TestResult::Fail("the send buffer did not take the burst");
    }
    if !nic.queue.is_stopped() {
        return TestResult::Fail("the ring did not stop");
    }
    // Two full segments from the peer call for an immediate ACK.
    let _ = drain();
    for i in 0..2u32 {
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 7_925,
            seq: 0x20000 + i * 1000,
            ack: 0x10000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[0x41; 1000],
        });
    }
    if !drain()
        .iter()
        .any(|f| frame_payload_len(f) == 0 && frame_flags(f) & FLAG_ACK != 0)
    {
        return TestResult::Fail("a pure ACK waited behind the stopped data queue");
    }
    // Unread data would turn the close into a reset.
    let mut sink = vec![0u8; 4096];
    let _ = recv_errno(id, &mut sink);
    if close(id).is_err() {
        return TestResult::Fail("close failed");
    }
    if !drive_to_wire(&nic, data.len()) {
        return TestResult::Fail("the connection did not finish sending");
    }
    nic.complete(FAKE_RING_LEN as usize);
    let wire = nic.wire();
    if stream_of(&wire, 0x10000) != Some(data) {
        return TestResult::Fail("re-entrant or re-offered segments broke the stream");
    }
    let fins = wire
        .iter()
        .filter(|f| frame_flags(f) & FLAG_FIN != 0)
        .count();
    let last_has_fin = wire.last().is_some_and(|f| frame_flags(f) & FLAG_FIN != 0);
    if fins != 1 || !last_has_fin {
        return TestResult::Fail("the FIN was not sent exactly once, after the data");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_backpressure_keeps_order_acks_flowing_and_one_fin
);

/// A pure ACK the device has no descriptor for is not forgotten: it stays
/// owed and the delayed-ACK timer sends it (`__tcp_send_ack`'s fallback).
fn smoke_tx_refused_ack_is_retried_from_delayed_ack_timer() -> TestResult {
    let local = [10, 99, 0, 1];
    let (_nic, id, peer) = backpressure_conn("txbp5", local, 7_926);
    CAPTURE_REFUSES.store(true, ::core::sync::atomic::Ordering::SeqCst);
    for i in 0..2u32 {
        inject(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 7_926,
            seq: 0x20000 + i * 1000,
            ack: 0x10000,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[0x42; 1000],
        });
    }
    CAPTURE_REFUSES.store(false, ::core::sync::atomic::Ordering::SeqCst);
    if __with_tcb(id, |t| t.delayed_ack_deadline_cycles) == Some(0) {
        return TestResult::Fail("a refused ACK was dropped with no retry armed");
    }
    let _ = drain();
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    let _ = __with_tcb_mut(id, |t| t.delayed_ack_deadline_cycles = 1);
    tick_retransmit(&arc);
    let acked = drain().iter().any(|f| {
        frame_payload_len(f) == 0
            && frame_flags(f) & FLAG_ACK != 0
            && f[TCP_OFF + 8..TCP_OFF + 12] == (0x20000u32 + 2000).to_be_bytes()
    });
    if !acked {
        return TestResult::Fail("the owed ACK was not sent by the delayed-ACK timer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_refused_ack_is_retried_from_delayed_ack_timer
);

/// A device that takes nothing — stalled, link down, being reset — refuses
/// every RTO retransmission. Linux retries those every
/// TCP_RESOURCE_PROBE_INTERVAL without counting them (`tcp_retransmit_timer`
/// leaves before `icsk_backoff++`). Counting them reset the connection after
/// eight probes, 3.5 s into the stall.
fn smoke_tx_refused_rto_retransmission_is_not_an_attempt() -> TestResult {
    let (_nic, id, _) = backpressure_conn("txbp7", [10, 101, 0, 1], 7_928);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    if send(id, &pattern(1000)) != Ok(1000) {
        return TestResult::Fail("the segment was not sent");
    }
    let before = __with_tcb(id, |t| (t.rtt.rto_ns, t.rtt.backoff_count)).unwrap_or((0, 9));
    CAPTURE_REFUSES.store(true, ::core::sync::atomic::Ordering::SeqCst);
    for _ in 0..20 {
        let _ = __with_tcb_mut(id, |t| t.retx_deadline_cycles = 1);
        tick_retransmit(&arc);
    }
    CAPTURE_REFUSES.store(false, ::core::sync::atomic::Ordering::SeqCst);
    let now = narf_scheduler::narf_time::now_cycles();
    let Some((state, estimator, deadline)) = __with_tcb(id, |t| {
        (
            t.state,
            (t.rtt.rto_ns, t.rtt.backoff_count),
            t.retx_deadline_cycles,
        )
    }) else {
        return TestResult::Fail("refused retransmissions reset the connection");
    };
    if state != TcpState::Established {
        return TestResult::Fail("refused retransmissions closed the connection");
    }
    if estimator != before {
        return TestResult::Fail("a refused retransmission backed the RTO off or was counted");
    }
    let probe = narf_scheduler::narf_time::ns_to_cycles(500_000_000);
    if deadline == 0 || deadline.saturating_sub(now) > probe {
        return TestResult::Fail("the next probe is not within TCP_RESOURCE_PROBE_INTERVAL");
    }
    // Once the device takes it, the retransmission goes out and is counted.
    let _ = drain();
    let _ = __with_tcb_mut(id, |t| t.retx_deadline_cycles = 1);
    tick_retransmit(&arc);
    if !drain().iter().any(|f| frame_payload_len(f) == 1000) {
        return TestResult::Fail("the retransmission was not sent once the device took it");
    }
    if __with_tcb(id, |t| t.rtt.backoff_count) != Some(before.1 + 1) {
        return TestResult::Fail("an accepted retransmission was not counted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_refused_rto_retransmission_is_not_an_attempt
);

/// The hang this guards against: `ethtool -G/-L` gives the driver new queue
/// objects while a connection stays bound to the old one. If the old flag
/// reads "running" and the new queue refuses, the sender must not re-offer
/// in a loop: it drops the binding, parks, and binds to the new queue when
/// the probe timer resumes it.
fn smoke_tx_sender_parks_and_rebinds_when_its_queue_is_replaced() -> TestResult {
    use ::core::sync::atomic::Ordering;
    let (nic, id, _) = backpressure_conn("txbp8", [10, 102, 0, 1], 7_929);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    let data = pattern(40_000);
    if send(id, &data[..2000]) != Ok(2000) || nic.held().is_empty() {
        return TestResult::Fail("the first segments were not sent");
    }
    // The resize: a new queue object, stopped, while the old flag is clear.
    let new_queue = nic.replace_queue();
    new_queue.refused();
    nic.offers.store(0, Ordering::SeqCst);
    if send(id, &data[2000..]) != Ok(38_000) {
        return TestResult::Fail("the send buffer did not take the rest");
    }
    if nic.offers.load(Ordering::SeqCst) > 2 {
        return TestResult::Fail("the sender kept re-offering to a queue that refuses");
    }
    let Some((parked, bound)) =
        __with_tcb(id, |t| (t.tx_wait_since_cycles != 0, t.tx_bind.is_some()))
    else {
        return TestResult::Fail("connection vanished");
    };
    if !parked || bound {
        return TestResult::Fail("the sender did not park and drop its stale binding");
    }
    // Room on the new queue; nobody is on its waiter list, so the probe
    // timer is what resumes the connection.
    nic.complete(FAKE_RING_LEN as usize);
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    let rebound = __with_tcb(id, |t| {
        t.tx_bind
            .as_ref()
            .is_some_and(|bind| Arc::ptr_eq(bind.account.queue(), &new_queue))
    });
    if rebound != Some(true) || nic.held().is_empty() {
        return TestResult::Fail("the connection did not bind to the new queue and resume");
    }
    for _ in 0..200 {
        nic.complete(5);
        new_queue.run_wakeups();
    }
    if stream_of(&nic.wire(), 0x10000) != Some(data) {
        return TestResult::Fail("the stream did not complete in order on the new queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_sender_parks_and_rebinds_when_its_queue_is_replaced
);

/// The other half: the connection is waiting on the old queue, whose flag
/// stays "stopped" for ever once the driver has moved to a new object.
fn smoke_tx_waiter_on_a_replaced_queue_is_released_by_the_probe() -> TestResult {
    let (nic, id, _) = backpressure_conn("txbp9", [10, 103, 0, 1], 7_930);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    let data = pattern(60_000);
    if send(id, &data) != Ok(data.len()) || !nic.queue.is_stopped() {
        return TestResult::Fail("the ring did not stop");
    }
    let new_queue = nic.replace_queue();
    nic.complete(FAKE_RING_LEN as usize);
    if !nic.queue.is_stopped() || !nic.held().is_empty() {
        return TestResult::Fail("test setup: the old queue should stay stopped");
    }
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if nic.held().is_empty() {
        return TestResult::Fail("a waiter on a replaced queue was never released");
    }
    for _ in 0..200 {
        nic.complete(5);
        new_queue.run_wakeups();
    }
    if stream_of(&nic.wire(), 0x10000) != Some(data) {
        return TestResult::Fail("the stream did not complete in order after the rebind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_waiter_on_a_replaced_queue_is_released_by_the_probe
);

/// The hard bound, whatever the driver does: a device that answers `Busy`
/// without stopping its queue gets two offers per call, then the sender
/// parks for the probe timer.
fn smoke_tx_sender_never_spins_on_a_busy_queue_that_is_not_stopped() -> TestResult {
    use ::core::sync::atomic::Ordering;
    let (nic, id, _) = backpressure_conn("txbp10", [10, 104, 0, 1], 7_931);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    if send(id, &pattern(1000)) != Ok(1000) {
        return TestResult::Fail("the first segment was not sent");
    }
    nic.busy_unstopped.store(true, Ordering::SeqCst);
    nic.offers.store(0, Ordering::SeqCst);
    if send(id, &pattern(30_000)) != Ok(30_000) {
        return TestResult::Fail("the send buffer did not take the data");
    }
    if nic.offers.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("the sender did not stop after one re-offer");
    }
    if __with_tcb(id, |t| t.tx_wait_since_cycles != 0) != Some(true) {
        return TestResult::Fail("the sender is not parked for the probe timer");
    }
    // Each probe is again bounded.
    nic.offers.store(0, Ordering::SeqCst);
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if nic.offers.load(Ordering::SeqCst) > 2 {
        return TestResult::Fail("a probe re-offered without bound");
    }
    nic.busy_unstopped.store(false, Ordering::SeqCst);
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if nic.held().len() < 2 {
        return TestResult::Fail("the sender did not resume once the device took frames");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_sender_never_spins_on_a_busy_queue_that_is_not_stopped
);

/// Frames the driver copies are charged like owned ones, so the
/// per-connection limit holds for them: the connection stops at the limit
/// with ring to spare, and its own completions resume it.
fn smoke_tx_copied_frames_are_charged_and_throttled() -> TestResult {
    use ::core::sync::atomic::Ordering;
    let (nic, id, _) = backpressure_conn("txbp11", [10, 105, 0, 1], 7_932);
    narf_lib::sysctl::ipv4::TCP_LIMIT_OUTPUT_BYTES.store(4000, Ordering::Relaxed);
    let sent = send(id, &pattern(60_000));
    narf_lib::sysctl::ipv4::TCP_LIMIT_OUTPUT_BYTES.store(4 << 20, Ordering::Relaxed);
    if sent != Ok(60_000) {
        return TestResult::Fail("the send buffer did not take the data");
    }
    let held = nic.held();
    let in_device: usize = held.iter().map(Vec::len).sum();
    let Some((queued, parked)) = __with_tcb(id, |t| {
        (
            t.tx_bind.as_ref().map_or(0, |bind| bind.account.queued()),
            t.tx_wait_since_cycles != 0,
        )
    }) else {
        return TestResult::Fail("connection vanished");
    };
    if queued as usize != in_device || in_device == 0 {
        return TestResult::Fail("copied frames are not charged to their connection");
    }
    if nic.queue.is_stopped() || held.len() >= 14 || in_device <= 4000 || !parked {
        return TestResult::Fail("the per-connection limit did not stop the sender first");
    }
    // Its own completions return the charge and schedule the resume.
    nic.complete(held.len());
    if __with_tcb(id, |t| {
        t.tx_bind.as_ref().map_or(1, |bind| bind.account.queued())
    }) != Some(0)
    {
        return TestResult::Fail("completion did not return the charges");
    }
    if nic.queue.run_wakeups() != 1 || nic.held().is_empty() {
        return TestResult::Fail("completions did not resume the throttled connection");
    }
    // A reset returns what the ring held as well.
    let _ = nic.reset();
    if __with_tcb(id, |t| {
        t.tx_bind.as_ref().map_or(1, |bind| bind.account.queued())
    }) != Some(0)
    {
        return TestResult::Fail("a reset kept the charges of the frames it discarded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_copied_frames_are_charged_and_throttled
);

/// The ACK for a segment can be processed before the sender records the
/// segment for retransmission (the record is made after the device took the
/// frame). That record was then never released: on an idle connection its
/// timer fired with nothing to resend, did not re-arm, fired again on every
/// tick, and the eighth firing reset the connection.
fn smoke_tx_ack_before_record_leaves_no_stale_retransmit_timer() -> TestResult {
    let local = [10, 106, 0, 1];
    let (nic, id, peer) = backpressure_conn("txbp12", local, 7_933);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    *nic.on_accept.lock() = Some((
        peer,
        local,
        tcp_bytes(Seg {
            src: peer,
            dst: local,
            sport: 80,
            dport: 7_933,
            seq: 0x20000,
            ack: 0x10000 + 300,
            flags: FLAG_ACK,
            window: 65535,
            options: Vec::new(),
            payload: &[],
        }),
    ));
    if send(id, &pattern(300)) != Ok(300) {
        return TestResult::Fail("the segment was not sent");
    }
    if __with_tcb(id, |t| {
        (t.snd_una, t.retx_queue.len(), t.retx_deadline_cycles)
    }) != Some((0x10000 + 300, 0, 0))
    {
        return TestResult::Fail("a segment already acknowledged was recorded for retransmission");
    }
    // A stale record that exists anyway must be discarded, not counted.
    let before = __with_tcb(id, |t| t.rtt.backoff_count).unwrap_or(9);
    let _ = __with_tcb_mut(id, |t| {
        t.retx_queue.push_back(crate::tcp::retransmit::OutSeg {
            seq: 0x10000,
            len: 300,
            sent_at_cycles: 1,
            retransmitted: false,
            flags: FLAG_ACK,
        });
    });
    for _ in 0..20 {
        let _ = __with_tcb_mut(id, |t| {
            if !t.retx_queue.is_empty() {
                t.retx_deadline_cycles = 1;
            }
        });
        tick_retransmit(&arc);
    }
    if __with_tcb(id, |t| {
        (
            t.state,
            t.retx_queue.len(),
            t.retx_deadline_cycles,
            t.rtt.backoff_count,
        )
    }) != Some((TcpState::Established, 0, 0, before))
    {
        return TestResult::Fail("a stale retransmit record kept firing or reset the connection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_ack_before_record_leaves_no_stale_retransmit_timer
);

/// `fire_retransmit` releases the lock between rewinding to `snd_una` and
/// advancing past the head it resent. A sender that runs in between has
/// already advanced; advancing again left the send-buffer offset ahead of
/// `snd_nxt`, a range marked sent that nothing ever transmits.
fn smoke_tx_rto_does_not_advance_over_a_sender_that_ran_meanwhile() -> TestResult {
    let (_nic, id, _) = backpressure_conn("txbp13", [10, 107, 0, 1], 7_934);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    if send(id, &pattern(6000)) != Ok(6000) {
        return TestResult::Fail("the data was not sent");
    }
    // The sender runs from inside the RTO's own retransmission.
    PLAIN_REENTER.store(id, ::core::sync::atomic::Ordering::SeqCst);
    let _ = __with_tcb_mut(id, |t| t.retx_deadline_cycles = 1);
    tick_retransmit(&arc);
    if PLAIN_REENTER.load(::core::sync::atomic::Ordering::SeqCst) != 0 {
        return TestResult::Fail("the RTO did not retransmit through the ordinary hook");
    }
    let Some((marked, in_flight)) = __with_tcb(id, |t| {
        (
            t.send_buf.inflight_bytes() as u32,
            t.snd_nxt.wrapping_sub(t.snd_una),
        )
    }) else {
        return TestResult::Fail("connection vanished");
    };
    if marked != in_flight || in_flight == 0 {
        return TestResult::Fail("the send-buffer offset and snd_nxt disagree after the RTO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_rto_does_not_advance_over_a_sender_that_ran_meanwhile
);

/// A connection that cannot get its data into the device is counted: every
/// 64 refusals in a row, and every second spent waiting. Sending again
/// clears both.
fn smoke_tx_stuck_sender_is_counted_and_cleared() -> TestResult {
    use crate::txq::stats::{LONG_WAITS, REOFFER_STORMS};
    use ::core::sync::atomic::Ordering;
    let (nic, id, _) = backpressure_conn("txbp14", [10, 108, 0, 1], 7_935);
    let Some(arc) = lookup_tcb(id) else {
        return TestResult::Fail("connection vanished");
    };
    if send(id, &pattern(1000)) != Ok(1000) {
        return TestResult::Fail("the first segment was not sent");
    }
    nic.busy_unstopped.store(true, Ordering::SeqCst);
    let storms = REOFFER_STORMS.load(Ordering::Relaxed);
    if send(id, &pattern(30_000)) != Ok(30_000) {
        return TestResult::Fail("the send buffer did not take the data");
    }
    for _ in 0..40 {
        let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
        tick_retransmit(&arc);
    }
    if REOFFER_STORMS.load(Ordering::Relaxed) == storms {
        return TestResult::Fail("82 refusals in a row were not counted as a storm");
    }
    // The wait began more than a second ago: counted once, then the second
    // starts over.
    let waits = LONG_WAITS.load(Ordering::Relaxed);
    let _ = __with_tcb_mut(id, |t| {
        t.tx_wait_start_cycles = 1;
        t.tx_wait_since_cycles = 1;
    });
    tick_retransmit(&arc);
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if LONG_WAITS.load(Ordering::Relaxed) != waits + 1 {
        return TestResult::Fail("a second of waiting was not counted exactly once");
    }
    nic.busy_unstopped.store(false, Ordering::SeqCst);
    let _ = __with_tcb_mut(id, |t| t.tx_wait_since_cycles = 1);
    tick_retransmit(&arc);
    if __with_tcb(id, |t| (t.tx_refused_in_row, t.tx_wait_start_cycles)) != Some((0, 0)) {
        return TestResult::Fail("sending again did not clear the stuck-sender state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_tx_stuck_sender_is_counted_and_cleared
);

// ── Receive batches (`iface::rx_batch`) ─────────────────────────────────

/// An Ethernet ARP request from `peer` for `target`.
fn arp_request(peer: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mac = [0x52, 0x54, 0, 0, 0, 1];
    let mut f = vec![0u8; 60];
    f[..6].fill(0xff);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&peer);
    f[38..42].copy_from_slice(&target);
    f
}

/// A receive poll resolves its interface once: every frame of the batch
/// reaches the stack with the right device, with one registry lookup, and
/// the interface counters are folded in when the batch ends.
fn smoke_rx_batch_resolves_device_once_per_poll() -> TestResult {
    use ::core::sync::atomic::Ordering;
    const FRAMES: u64 = 32;
    let local = [10, 93, 0, 1];
    let peer = reset("rxbatch0", local);
    iface::install_native_rx_handler(crate::tcp_stack::rx_handler_native);
    iface::install_native_rx_resolved_handler(crate::tcp_stack::rx_handler_native_resolved);
    let counters = || {
        iface::lookup("rxbatch0").map_or((0, 0), |dev| (dev.stats.rx_packets, dev.stats.rx_bytes))
    };
    let before = counters();
    let lookups = iface::RX_BATCH_LOOKUPS.load(Ordering::Relaxed);
    {
        let mut batch = iface::rx_batch("rxbatch0");
        for _ in 0..FRAMES {
            batch.receive(&mut arp_request(peer, local), None);
        }
        if counters() != before {
            return TestResult::Fail("interface counters were taken under the lock per frame");
        }
    }
    if iface::RX_BATCH_LOOKUPS.load(Ordering::Relaxed) != lookups + 1 {
        return TestResult::Fail("the batch looked its interface up more than once");
    }
    if counters() != (before.0 + FRAMES, before.1 + FRAMES * 60) {
        return TestResult::Fail("the batch's frames and bytes were not counted when it ended");
    }
    // Each request was answered from this interface: the stack saw the
    // frames with their ingress device.
    let replies = drain()
        .iter()
        .filter(|f| ethertype(f) == 0x0806 && f[20..22] == [0, 2] && f[28..32] == local)
        .count();
    if replies as u64 != FRAMES {
        return TestResult::Fail("a frame of the batch did not reach the stack with its device");
    }
    // An unregistered name still takes the by-name path and counts nothing.
    let mut unknown = iface::rx_batch("rxbatch-missing");
    unknown.receive(&mut arp_request(peer, local), None);
    drop(unknown);
    TestResult::Pass
}
kernel_test_in!(
    "net/tcp/robust",
    smoke_rx_batch_resolves_device_once_per_poll
);
