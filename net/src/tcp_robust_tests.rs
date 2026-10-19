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
        t.last_progress_cycles = narf_scheduler::narf_time::now_cycles().saturating_sub(window);
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
            t.last_progress_cycles = narf_scheduler::narf_time::now_cycles().saturating_sub(window);
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
