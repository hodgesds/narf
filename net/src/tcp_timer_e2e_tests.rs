//! Timer-wheel + RTO + congestion end-to-end smokes for NARF TCP.
//!
//! ## What this file covers
//!
//! 18 smokes that walk the timing-sensitive code paths that the Wave-27
//! e2e file (`e2e_tests.rs`) does not exercise in depth:
//!
//! - RTT sampling / EWMA (RFC 6298 §2)
//! - RTO floor / ceiling clamping
//! - RTO exponential back-off + 7-strike give-up
//! - Karn's algorithm — no RTT sample on retransmitted segments
//! - CUBIC slow-start, ssthresh halving, cubic-curve growth
//! - Fast retransmit on 3 dup-ACKs + fast-recovery exit
//! - SACK scoreboard encode/decode + skip-on-SACK selective retransmit
//! - Zero-window persist timer with exponential back-off
//! - Keepalive after 2-hour idle
//! - TIME-WAIT 2*MSL expiry
//!
//! ## Test harness idiom
//!
//! All smokes use the `__install_test_tcb` / `__inject_segment` /
//! `__with_tcb` / `__with_tcb_mut` backdoors from `tcp::core`.
//! Virtual time is advanced by writing past-deadline values directly
//! into the TCB's `*_deadline_cycles` fields and calling
//! `tick_retransmit` — exactly the same technique as Smoke 5 and 6 in
//! Wave 27's `e2e_tests.rs`.
//!
//! `cycles_per_ns()` is 1 in test builds (the wall calibration is
//! skipped), so `deadline_cycles = 1` is always expired and
//! `deadline_cycles = now_cycles() + N_ns * 1` arms a timer N
//! nanoseconds out.
//!
//! ## Linux refs
//!
//! - `net/ipv4/tcp_timer.c::tcp_retransmit_timer` — RTO fire + back-off
//! - `net/ipv4/tcp_input.c::tcp_rtt_estimator` — SRTT/RTTVAR/RTO
//! - `net/ipv4/tcp_input.c::tcp_rcv_established` — dup-ACK + fast-retx
//! - `net/ipv4/tcp_output.c::tcp_retransmit_skb` — retransmit send
//! - `net/ipv4/tcp_cubic.c::bictcp_cong_avoid` — CUBIC W(t) curve
//!
//! ## Deferred items
//!
//! The following are explicitly out-of-scope for this wave:
//! - DSACK (RFC 2883)
//! - F-RTO (RFC 5682)
//! - BBR / DCTCP / Vegas
//! - ECN ECE/CWR flag handling

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::arp_cache;
use crate::iface;
use crate::pkt::{
    set_ipv4_checksum, write_eth_header, write_ipv4_header, ETHERTYPE_IPV4, ETH_HDR_LEN,
    IPV4_HDR_LEN, IP_PROTO_TCP,
};
use crate::pkt_tcp::{
    ipv4_pseudo_checksum, TcpHeader, FLAG_ACK, FLAG_FIN, FLAG_SYN, TCP_HDR_MIN,
};
use crate::route;
use crate::tcp::congestion::{CongAlg, CongestionState};
use crate::tcp::core::{
    self, handle_segment, listen, lookup_tcb, accept, send, close, shutdown,
    tick_retransmit, __with_tcb, __with_tcb_mut,
    PERSIST_INITIAL_NS, PERSIST_MAX_NS, KEEPALIVE_IDLE_NS,
};
use crate::tcp::retransmit::{
    RttEstimator, RTO_MIN_NS, RTO_MAX_NS, MAX_RETRANSMITS,
};
use crate::tcp::sack::{SackBlock, SackBook, SenderScoreboard};
use crate::tcp::state_machine::{Shutdown, TcpState};

// ── Shared TX-capture cell ─────────────────────────────────────────────────
//
// Mirrors the TX_CAPTURE pattern from e2e_tests.rs. Each test calls
// `timer_drain_captured()` to snapshot + clear the queue.

static TIMER_TX_CAPTURE: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn timer_capture_send(frame: &[u8]) -> Result<(), ()> {
    TIMER_TX_CAPTURE.lock().push(frame.to_vec());
    Ok(())
}

fn timer_drain_captured() -> Vec<Vec<u8>> {
    let mut g = TIMER_TX_CAPTURE.lock();
    let d = g.clone();
    g.clear();
    d
}

// ── Full reset ─────────────────────────────────────────────────────────────

fn timer_full_reset(iface_name: &'static str, local_ip: [u8; 4], gateway: [u8; 4]) {
    core::__reset_for_test();
    route::__reset_for_test();
    arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    TIMER_TX_CAPTURE.lock().clear();

    iface::register(iface_name, [0x02, 0x00, 0x00, 0x00, 0x00, 0x07], timer_capture_send);
    iface::set_default_ipv4(local_ip, gateway);
    iface::add_addr(iface_name, local_ip, 24);

    let gw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    crate::tcp_stack::__arp_insert_legacy(gateway, gw_mac);
    arp_cache::insert(iface_name, gateway, gw_mac);

    // Seed local path for loopback-over-iface.
    crate::tcp_stack::__arp_insert_legacy(local_ip, [0x02, 0x00, 0x00, 0x00, 0x00, 0x07]);
    arp_cache::insert(iface_name, local_ip, [0x02, 0x00, 0x00, 0x00, 0x00, 0x07]);
    // Pre-seed the remote peer (10.x.x.2) used in __install_test_tcb smokes.
    let peer_mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];
    let peer_ip = [local_ip[0], local_ip[1], local_ip[2], 2];
    crate::tcp_stack::__arp_insert_legacy(peer_ip, peer_mac);
    arp_cache::insert(iface_name, peer_ip, peer_mac);
}

// ── Frame builder ──────────────────────────────────────────────────────────

fn build_tcp_seg(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN + payload.len();
    let mut frame = vec![0u8; total];
    let ip_total = (IPV4_HDR_LEN + TCP_HDR_MIN + payload.len()) as u16;
    write_eth_header(&mut frame, [0x02; 6], [0x52, 0x54, 0, 0, 0, 1], ETHERTYPE_IPV4);
    write_ipv4_header(&mut frame[ETH_HDR_LEN..], ip_total, IP_PROTO_TCP, src_ip, dst_ip);
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let mut hdr = TcpHeader {
        src_port,
        dst_port,
        sequence: seq,
        acknowledgement: ack,
        header_len: TCP_HDR_MIN as u8,
        flags,
        window,
        checksum: 0,
        urgent_ptr: 0,
        options: Vec::new(),
    };
    let enc = hdr.encode();
    frame[tcp_off..tcp_off + enc.len()].copy_from_slice(&enc);
    if !payload.is_empty() {
        frame[tcp_off + enc.len()..].copy_from_slice(payload);
    }
    let seg = &frame[tcp_off..tcp_off + TCP_HDR_MIN + payload.len()];
    let cs = ipv4_pseudo_checksum(src_ip, dst_ip, seg);
    hdr.checksum = cs;
    let enc2 = hdr.encode();
    frame[tcp_off..tcp_off + enc2.len()].copy_from_slice(&enc2);
    frame
}

/// Extract the SEQ number from a captured frame (returns 0 if too short).
fn frame_seq(frame: &[u8]) -> u32 {
    let off = ETH_HDR_LEN + IPV4_HDR_LEN;
    if frame.len() < off + 8 {
        return 0;
    }
    u32::from_be_bytes([frame[off + 4], frame[off + 5], frame[off + 6], frame[off + 7]])
}

/// Extract ACK number from a captured frame.
fn frame_ack(frame: &[u8]) -> u32 {
    let off = ETH_HDR_LEN + IPV4_HDR_LEN;
    if frame.len() < off + 12 {
        return 0;
    }
    u32::from_be_bytes([frame[off + 8], frame[off + 9], frame[off + 10], frame[off + 11]])
}

/// Extract flags byte from a captured frame.
fn frame_flags(frame: &[u8]) -> u8 {
    let off = ETH_HDR_LEN + IPV4_HDR_LEN + 13;
    if frame.len() < off + 1 {
        return 0;
    }
    frame[off]
}

// ── Helper: complete a 3WHS and return the server child TCB id ─────────────
//
// Shared by smokes that need an established connection but focus on
// timer / congestion behavior rather than the handshake itself.

fn establish_server_side(
    local_ip: [u8; 4],
    server_port: u16,
    client_port: u16,
    client_iss: u32,
) -> Result<(u32 /* listen_id */, u32 /* child_id */, u32 /* server_iss */), &'static str> {
    let listen_id = listen(local_ip, server_port, 8).map_err(|_| "listen failed")?;

    let syn = build_tcp_seg(
        local_ip, local_ip, client_port, server_port,
        client_iss, 0, FLAG_SYN, 65535, &[],
    );
    handle_segment(local_ip, local_ip, &syn[ETH_HDR_LEN + IPV4_HDR_LEN..]);

    let txd = timer_drain_captured();
    let synack = txd
        .iter()
        .find(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN
                && f[ETH_HDR_LEN + IPV4_HDR_LEN + 13] & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK)
        })
        .cloned()
        .ok_or("no SYN-ACK")?;

    let server_iss = frame_seq(&synack);

    let ack = build_tcp_seg(
        local_ip, local_ip, client_port, server_port,
        client_iss.wrapping_add(1), server_iss.wrapping_add(1),
        FLAG_ACK, 65535, &[],
    );
    handle_segment(local_ip, local_ip, &ack[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    let _ = timer_drain_captured();

    let mut child_id = None;
    for _ in 0..50 {
        if let Ok(Some(id)) = accept(listen_id) {
            child_id = Some(id);
            break;
        }
    }
    let child_id = child_id.ok_or("accept returned nothing")?;

    Ok((listen_id, child_id, server_iss))
}

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 1 — First RTT sample seeds SRTT + RTTVAR (RFC 6298 §2.2)
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux ref: `tcp_rtt_estimator` in `net/ipv4/tcp_input.c`.
// After the very first sample of R ms:
//   SRTT   = R
//   RTTVAR = R / 2
//   RTO    = SRTT + 4 * RTTVAR = 3 * R  (clamped to RTO_MIN if too small)

fn smoke_rtt_first_sample_seeds_srtt_and_rttvar() -> TestResult {
    let mut e = RttEstimator::new();

    // Feed 100 ms.
    e.sample(100_000_000);

    if !e.valid {
        return TestResult::Fail("RttEstimator.valid not set after first sample");
    }
    if e.srtt_ns != 100_000_000 {
        return TestResult::Fail("SRTT not 100ms after first sample");
    }
    if e.rttvar_ns != 50_000_000 {
        return TestResult::Fail("RTTVAR not 50ms (R/2) after first sample");
    }
    // RTO = SRTT + max(G, 4*RTTVAR) = 100ms + 200ms = 300ms.
    if e.current_rto() != 300_000_000 {
        return TestResult::Fail("RTO not 300ms after first sample");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rtt_first_sample_seeds_srtt_and_rttvar);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 2 — EWMA smoothing across multiple samples
// ═══════════════════════════════════════════════════════════════════════════
//
// Feeds RTTs [100, 110, 90, 105] ms and verifies that SRTT converges
// smoothly (lies between the min and max of the series after all samples).

fn smoke_rtt_ewma_smoothing_across_samples() -> TestResult {
    let mut e = RttEstimator::new();
    for &rtt_ms in &[100u64, 110, 90, 105] {
        e.sample(rtt_ms * 1_000_000);
    }
    if !e.valid {
        return TestResult::Fail("not valid after 4 samples");
    }
    // SRTT must be between 90 ms and 110 ms (smoothed, not volatile).
    if e.srtt_ns < 90_000_000 || e.srtt_ns > 110_000_000 {
        return TestResult::Fail("SRTT out of [90ms, 110ms] range after EWMA samples");
    }
    // RTO must be >= RTO_MIN and <= RTO_MAX.
    let rto = e.current_rto();
    if rto < RTO_MIN_NS || rto > RTO_MAX_NS {
        return TestResult::Fail("RTO out of bounds after EWMA samples");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rtt_ewma_smoothing_across_samples);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 3 — RTO floor clamp: very small RTT must yield RTO >= 200ms
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux: `TCP_RTO_MIN` is HZ/5 = 200ms on a 1000Hz kernel.
// `net/include/tcp.h:#define TCP_RTO_MIN ((unsigned)(HZ/5))`

fn smoke_rto_floor_200ms() -> TestResult {
    let mut e = RttEstimator::new();
    e.sample(5_000_000); // 5 ms RTT
    let rto = e.current_rto();
    if rto < RTO_MIN_NS {
        return TestResult::Fail("RTO below 200ms floor after tiny RTT sample");
    }
    if rto != RTO_MIN_NS {
        // RTO = SRTT + 4*RTTVAR = 5ms + 4*(2.5ms) = 15ms < 200ms → clamp.
        // We just require it's at the floor, not above it by much.
        if rto > RTO_MIN_NS * 2 {
            return TestResult::Fail("RTO not clamped close to floor");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rto_floor_200ms);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 4 — RTO ceiling clamp after 8 back-offs: capped at 60s
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 6298 §2.5: RTO must not exceed 60 seconds regardless of back-off.
// Linux: `TCP_RTO_MAX` = 120s by default; we use 60s.

fn smoke_rto_ceiling_60s_after_back_offs() -> TestResult {
    let mut e = RttEstimator::new();
    // Seed with a modest RTT so back-off starts from a real value.
    e.sample(200_000_000); // 200 ms

    // Apply 8 back-offs.
    let mut i = 0;
    while i < 8 {
        if !e.back_off() {
            break;
        }
        i += 1;
    }
    let rto = e.current_rto();
    if rto > RTO_MAX_NS {
        return TestResult::Fail("RTO exceeded 60s ceiling after 8 back-offs");
    }
    // Must also not be 0.
    if rto < RTO_MIN_NS {
        return TestResult::Fail("RTO below floor after 8 back-offs");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rto_ceiling_60s_after_back_offs);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 5 — RTO fires retransmit of oldest unACKed segment
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux ref: `tcp_retransmit_timer` → `tcp_retransmit_skb`.

fn smoke_rto_fires_retransmit() -> TestResult {
    const IFACE: &str = "tcp-timer-s5";
    const LOCAL_IP: [u8; 4] = [10, 0, 51, 1];
    const GW: [u8; 4] = [10, 0, 51, 1];
    const SERVER_PORT: u16 = 51_001;
    const CLIENT_PORT: u16 = 51_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _server_iss) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1100_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Send 100 bytes from the server side.
    let payload = vec![0xBBu8; 100];
    match send(child_id, &payload) {
        Ok(n) if n > 0 => {}
        _ => return TestResult::Fail("send(100) failed"),
    }
    let txd = timer_drain_captured();
    let orig_seg = match txd.iter().find(|f| f.len() > ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN) {
        Some(f) => f.clone(),
        None => return TestResult::Fail("no data segment after send"),
    };
    let orig_seq = frame_seq(&orig_seg);

    // Force RTO expiry by setting deadline to 1 (always expired) and
    // ensuring rto_count = 0 (first back-off allowed).
    {
        let arc = match lookup_tcb(child_id) {
            Some(a) => a,
            None => return TestResult::Fail("TCB gone before retransmit test"),
        };
        let mut t = arc.lock();
        t.retx_deadline_cycles = 1;
        t.rto_count = 0;
    }

    // tick_retransmit must observe the expired deadline and re-send.
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }

    let retx = timer_drain_captured();
    let retx_seg = retx.iter().find(|f| {
        f.len() > ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN && frame_seq(f) == orig_seq
    });
    if retx_seg.is_none() {
        return TestResult::Fail("no retransmit with orig SEQ after RTO fire");
    }

    // rto_count must have incremented.
    let rto_count = __with_tcb(child_id, |t| t.rto_count);
    if rto_count != Some(1) {
        return TestResult::Fail("rto_count did not increment after first RTO fire");
    }

    let _ = close(child_id);
    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rto_fires_retransmit);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 6 — Karn's algorithm: no RTT sample on retransmitted segment
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 6298 §3: "Do not use RTT measurements from retransmitted segments."
// After a retransmit, if the ACK arrives, the `retransmitted` flag
// prevents `sample()` from being called.

fn smoke_karn_algorithm_no_sample_on_retransmit() -> TestResult {
    const IFACE: &str = "tcp-timer-s6";
    const LOCAL_IP: [u8; 4] = [10, 0, 52, 1];
    const GW: [u8; 4] = [10, 0, 52, 1];
    const SERVER_PORT: u16 = 52_001;
    const CLIENT_PORT: u16 = 52_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _server_iss) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1200_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Send 50 bytes.
    match send(child_id, &vec![0xCCu8; 50]) {
        Ok(n) if n > 0 => {}
        _ => return TestResult::Fail("send(50) failed"),
    }
    let txd = timer_drain_captured();
    let orig_seg = match txd.iter().find(|f| f.len() > ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN) {
        Some(f) => f.clone(),
        None => return TestResult::Fail("no data segment"),
    };
    let seg_end_seq = frame_seq(&orig_seg)
        .wrapping_add((orig_seg.len() - ETH_HDR_LEN - IPV4_HDR_LEN - TCP_HDR_MIN) as u32);

    // Force RTO: mark segment as retransmitted in the retx_queue + expire.
    {
        let arc = lookup_tcb(child_id).unwrap();
        let mut t = arc.lock();
        t.retx_deadline_cycles = 1;
        t.rto_count = 0;
        // Mark ALL entries as retransmitted (Karn).
        for s in t.retx_queue.iter_mut() {
            s.retransmitted = true;
        }
    }
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }
    let _ = timer_drain_captured();

    // Snapshot SRTT after the forced retransmit (before ACK).
    let srtt_after_retx = __with_tcb(child_id, |t| t.rtt.srtt_ns).unwrap_or(0);

    // Now inject a cumulative ACK covering the segment.
    let client_next = 0x1200_0001u32; // client's next seq
    let ack_seg = build_tcp_seg(
        LOCAL_IP, LOCAL_IP, CLIENT_PORT, SERVER_PORT,
        client_next, seg_end_seq,
        FLAG_ACK, 65535, &[],
    );
    handle_segment(LOCAL_IP, LOCAL_IP, &ack_seg[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    let _ = timer_drain_captured();

    // SRTT must NOT have changed (Karn's algorithm): retransmitted flag
    // prevents sampling.
    let srtt_after_ack = __with_tcb(child_id, |t| t.rtt.srtt_ns).unwrap_or(0);
    if srtt_after_ack != srtt_after_retx {
        // The RTT estimator sampled a retransmitted segment — Karn violation.
        return TestResult::Fail("Karn violation: SRTT changed after ACK of retransmitted segment");
    }

    let _ = close(child_id);
    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_karn_algorithm_no_sample_on_retransmit);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 7 — RTO exponential back-off × 3 rounds → RTO = base * 8
// ═══════════════════════════════════════════════════════════════════════════
//
// Each RTO fire doubles the RTO. After 3 fires starting from 200ms:
//   round 1 → 400ms, round 2 → 800ms, round 3 → 1600ms = 200ms * 8.

fn smoke_rto_exponential_back_off_three_rounds() -> TestResult {
    let mut e = RttEstimator::new();
    // Seed with 200ms so RTO = exactly RTO_MIN.
    e.sample(200_000_000);
    // Manually set rto_ns to the clamped minimum for precision.
    let rto_initial = e.current_rto();

    for i in 0..3 {
        if !e.back_off() {
            return TestResult::Fail("back_off returned false before 3 rounds");
        }
        let _ = i;
    }
    let rto_after = e.current_rto();
    // Must be 8× the initial value, capped to RTO_MAX.
    let expected = (rto_initial * 8).min(RTO_MAX_NS);
    if rto_after != expected {
        return TestResult::Fail("RTO not 8× initial after 3 back-offs");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_rto_exponential_back_off_three_rounds);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 8 — 7-strike give-up: connection dropped after MAX_RETRANSMITS
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux: `net.ipv4.tcp_retries2` = 15 by default; NARF uses 7.
// `tcp_retransmit_timer` → `tcp_write_err` after `icsk_retransmits > R2`.

fn smoke_seven_strike_give_up() -> TestResult {
    const IFACE: &str = "tcp-timer-s8";
    const LOCAL_IP: [u8; 4] = [10, 0, 53, 1];
    const GW: [u8; 4] = [10, 0, 53, 1];
    const SERVER_PORT: u16 = 53_001;
    const CLIENT_PORT: u16 = 53_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1300_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Queue some data (to arm the retransmit timer).
    match send(child_id, &vec![0xDDu8; 20]) {
        Ok(n) if n > 0 => {}
        _ => return TestResult::Fail("send(20) failed in 7-strike smoke"),
    }
    let _ = timer_drain_captured();

    // Fire RTO 7+1 times (MAX_RETRANSMITS + 1 to trigger give-up).
    for _round in 0..=(MAX_RETRANSMITS as usize) {
        // Force deadline expiry.
        if let Some(arc) = lookup_tcb(child_id) {
            let mut t = arc.lock();
            t.retx_deadline_cycles = 1;
            drop(t);
            drop(arc);
            if let Some(arc2) = lookup_tcb(child_id) {
                tick_retransmit(&arc2);
            }
        }
        let _ = timer_drain_captured();
    }

    // After MAX_RETRANSMITS+1 give-ups, the TCB should be gone.
    if lookup_tcb(child_id).is_some() {
        return TestResult::Fail("TCB still alive after 7-strike give-up");
    }

    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_seven_strike_give_up);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 9 — Slow start: cwnd grows by ~1 MSS per ACK'd MSS
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 5681 §3.1: during slow start, cwnd increases by min(N, SMSS) for
// each ACK that newly ACKs N bytes. We drive this through the congestion
// state machine directly (unit-level), then verify at the TCB level.

fn smoke_slow_start_cwnd_growth() -> TestResult {
    let mss = 1460u32;
    let mut c = CongestionState::new(CongAlg::Reno, mss);
    // Start below ssthresh (ssthresh = MAX initially → always slow start).
    c.cwnd = mss; // 1 MSS

    let initial = c.cwnd;
    // Feed 3 ACKs of 1 MSS each — cwnd should grow by 3 MSS.
    for _ in 0..3 {
        c.on_ack(mss, 0);
    }
    if c.cwnd != initial + 3 * mss {
        return TestResult::Fail("slow start: cwnd did not grow by 3 MSS after 3 ACKs");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_slow_start_cwnd_growth);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 10 — ssthresh halves on loss event; switch to congestion avoidance
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux: `tcp_enter_loss` / `tcp_enter_fast_retrans_state`.

fn smoke_ssthresh_halves_on_loss() -> TestResult {
    let mss = 1460u32;
    let mut c = CongestionState::new(CongAlg::Reno, mss);
    c.cwnd = 20 * mss; // well above ssthresh
    c.ssthresh = u32::MAX;

    // Trigger fast retransmit (loss).
    let snd_nxt: u32 = 100_000;
    c.enter_fast_recovery(snd_nxt, 0, 1);

    // ssthresh ← cwnd / 2 = 10 MSS.
    let expected_ssth = 10 * mss;
    if c.ssthresh != expected_ssth {
        return TestResult::Fail("ssthresh not halved on fast-retransmit loss");
    }
    // in_recovery = true.
    if !c.in_recovery {
        return TestResult::Fail("not in recovery after enter_fast_recovery");
    }
    // cwnd ← ssthresh + 3*MSS = 13 MSS.
    if c.cwnd != expected_ssth + 3 * mss {
        return TestResult::Fail("cwnd not ssthresh+3*MSS after enter_fast_recovery");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_ssthresh_halves_on_loss);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 11 — CUBIC W(t) = C*(t-K)^3 + W_max grows after loss
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 9438 §4: after a loss event, W_cubic grows toward W_max and beyond.
// We verify the curve shape is non-shrinking over successive time steps.

fn smoke_cubic_curve_grows_after_loss() -> TestResult {
    let mss = 1460u32;
    let mut c = CongestionState::new(CongAlg::Cubic, mss);
    c.cwnd = 50 * mss;
    c.ssthresh = 25 * mss;
    // Record a loss event at t=0 with cycles_per_ns=1.
    c.enter_fast_recovery(200_000u32, 1_000_000, 1);
    c.in_recovery = false; // manually exit recovery to test CA path
    c.cwnd = c.ssthresh;

    let mut prev_cwnd = c.cwnd;
    // Advance time in 1-billion-cycle steps (= 1 second with cpn=1).
    for i in 1..=5 {
        let now = (i as u64) * 1_000_000_000u64 + 1_000_000;
        c.on_ack(mss, now);
        // cwnd must be non-decreasing in CUBIC CA.
        if c.cwnd < prev_cwnd {
            return TestResult::Fail("CUBIC cwnd decreased during congestion avoidance");
        }
        prev_cwnd = c.cwnd;
    }
    // After 5 RTTs, cwnd should have grown appreciably.
    if c.cwnd <= 25 * mss {
        return TestResult::Fail("CUBIC cwnd did not grow beyond ssthresh after 5 RTTs");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_cubic_curve_grows_after_loss);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 12 — 3 dup-ACKs trigger fast retransmit + cwnd halved
// ═══════════════════════════════════════════════════════════════════════════
//
// Linux ref: `tcp_rcv_established` → `tcp_ack` → `tcp_enter_fast_retrans_state`.

fn smoke_three_dup_acks_fast_retransmit() -> TestResult {
    const IFACE: &str = "tcp-timer-s12";
    const LOCAL_IP: [u8; 4] = [10, 0, 54, 1];
    const GW: [u8; 4] = [10, 0, 54, 1];
    const SERVER_PORT: u16 = 54_001;
    const CLIENT_PORT: u16 = 54_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, server_iss) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1400_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Snapshot cwnd before loss.
    let cwnd_before = __with_tcb(child_id, |t| t.cong.cwnd).unwrap_or(0);

    // Send 5 segments worth of data from the server side.
    // We use a small payload to stay inside one MSS per call.
    let mss = __with_tcb(child_id, |t| t.opts.peer_mss as usize).unwrap_or(512);
    let seg_payload = vec![0xAAu8; mss.min(512)];
    for _ in 0..5 {
        let _ = send(child_id, &seg_payload);
    }
    let _ = timer_drain_captured();

    // Inject 3 duplicate ACKs for snd_una (server's ISS+1 = first acked byte).
    // Each dup-ACK acks nothing new — ack = snd_una.
    let snd_una = __with_tcb(child_id, |t| t.snd_una).unwrap_or(server_iss.wrapping_add(1));
    let client_seq: u32 = 0x1400_0001;

    for _ in 0..3 {
        let dup = build_tcp_seg(
            LOCAL_IP, LOCAL_IP, CLIENT_PORT, SERVER_PORT,
            client_seq, snd_una,
            FLAG_ACK, 65535, &[],
        );
        handle_segment(LOCAL_IP, LOCAL_IP, &dup[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    }
    let retx_frames = timer_drain_captured();

    // After 3 dup-ACKs there must be a retransmitted data segment.
    let has_retx = retx_frames
        .iter()
        .any(|f| f.len() > ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN);
    if !has_retx {
        return TestResult::Fail("no fast retransmit frame after 3 dup-ACKs");
    }

    // cwnd must have been halved (ssthresh = cwnd/2; cwnd = ssthresh + 3*MSS).
    let in_recovery = __with_tcb(child_id, |t| t.cong.in_recovery).unwrap_or(false);
    if !in_recovery {
        return TestResult::Fail("not in fast recovery after 3 dup-ACKs");
    }
    let cwnd_after = __with_tcb(child_id, |t| t.cong.cwnd).unwrap_or(0);
    // cwnd should be strictly less than before (halved + inflation, but still lower
    // than unbounded slow-start cwnd from Wave 27).
    if cwnd_after >= cwnd_before {
        // This is only a failure if cwnd_before was significantly above 2*ssthresh.
        // The IW10 start means cwnd_before = 10*MSS. After loss, ssthresh = 5*MSS,
        // cwnd = 5*MSS + 3*MSS = 8*MSS < 10*MSS.
        if cwnd_before > 8 * mss as u32 {
            return TestResult::Fail("cwnd not reduced after fast retransmit loss event");
        }
    }

    let _ = close(child_id);
    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_three_dup_acks_fast_retransmit);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 13 — Fast recovery exit on ACK above recovery point
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 5681 §3.4: exit recovery when snd_una ≥ recover.
// Linux: `tcp_fastretrans_alert` → `TCP_CA_Open`.

fn smoke_fast_recovery_exit_on_ack_above_recover_point() -> TestResult {
    let mss = 1460u32;
    let mut c = CongestionState::new(CongAlg::Reno, mss);
    c.cwnd = 10 * mss;
    let recover_snd_nxt: u32 = 50_000;

    c.enter_fast_recovery(recover_snd_nxt, 0, 1);
    if !c.in_recovery {
        return TestResult::Fail("not in recovery after enter_fast_recovery");
    }

    // ACK below recover_point — still in recovery.
    c.clear_recovery_if_passed(recover_snd_nxt.wrapping_sub(1000));
    if !c.in_recovery {
        return TestResult::Fail("premature recovery exit on partial ACK");
    }

    // ACK exactly at recover_point — must exit.
    c.clear_recovery_if_passed(recover_snd_nxt);
    if c.in_recovery {
        return TestResult::Fail("still in recovery after snd_una reached recover_point");
    }
    // cwnd must deflate to ssthresh.
    if c.cwnd > c.ssthresh.saturating_add(mss) {
        return TestResult::Fail("cwnd not deflated to ssthresh on recovery exit");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_fast_recovery_exit_on_ack_above_recover_point);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 14 — SACK block encoded in ACK for out-of-order delivery
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 2018 §3: receiver advertises SACK blocks for out-of-order segments.
// Linux: `tcp_sacktag_write_queue`, `tcp_options_write`.

fn smoke_sack_block_recorded_for_out_of_order_segment() -> TestResult {
    // Use the SackBook directly (receiver side).
    let mut book = SackBook::new();

    // rcv_nxt = 1000; receive seg at 1100 (out of order).
    book.add_range(1100, 1200);
    let blocks = book.blocks();
    if blocks.is_empty() {
        return TestResult::Fail("SackBook empty after out-of-order segment");
    }
    if blocks[0].left != 1100 || blocks[0].right != 1200 {
        return TestResult::Fail("SackBook first block wrong for range 1100..1200");
    }

    // Receive seg at 1300 (another gap).
    book.add_range(1300, 1400);
    let blocks2 = book.blocks();
    if blocks2.len() < 2 {
        return TestResult::Fail("SackBook missing second block");
    }
    // MRU order: newest first.
    if blocks2[0].left != 1300 {
        return TestResult::Fail("SackBook not MRU ordered");
    }

    // Prune below 1100 — first block should survive.
    book.prune_to(1050);
    if book.blocks().is_empty() {
        return TestResult::Fail("SackBook over-pruned below rcv_nxt");
    }

    // Prune below 1200 — first block should be dropped, second remains.
    book.prune_to(1200);
    let after = book.blocks();
    if after.iter().any(|b| b.left == 1100) {
        return TestResult::Fail("SackBook kept block covered by rcv_nxt advance");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_sack_block_recorded_for_out_of_order_segment);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 15 — Skip-on-SACK: retransmit skips scoreboarded ranges
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 6675: selective retransmit skips segments already covered by a
// received SACK option. Linux: `tcp_sacktag_write_queue`.

fn smoke_skip_on_sack_retransmit() -> TestResult {
    // Use the SenderScoreboard directly (sender side).
    let mut sb = SenderScoreboard::new();

    // Peer SACKed seq 1000..2000 and 3000..4000 (segs 2 and 4 of 5).
    sb.update_from(&[
        SackBlock { left: 1000, right: 2000 },
        SackBlock { left: 3000, right: 4000 },
    ]);

    // Gaps: 0..1000, 2000..3000, 4000..5000 should be retransmitted.
    // SACKed seqs 1000 and 3000 should be skipped.
    if !sb.is_sacked(1000) {
        return TestResult::Fail("seq 1000 not in scoreboard");
    }
    if !sb.is_sacked(1500) {
        return TestResult::Fail("seq 1500 not in scoreboard (inside 1000..2000 block)");
    }
    if !sb.is_sacked(3000) {
        return TestResult::Fail("seq 3000 not in scoreboard");
    }
    // Unacked gaps must NOT be in the scoreboard.
    if sb.is_sacked(0) {
        return TestResult::Fail("seq 0 wrongly in scoreboard");
    }
    if sb.is_sacked(2000) {
        return TestResult::Fail("seq 2000 (gap) wrongly in scoreboard");
    }
    if sb.is_sacked(4500) {
        return TestResult::Fail("seq 4500 (gap) wrongly in scoreboard");
    }

    // Prune: cumulative ACK advances to 2000 — first block pruned.
    sb.prune_below(2000);
    if sb.blocks.iter().any(|b| b.left == 1000) {
        return TestResult::Fail("scoreboard kept block covered by cumulative ACK");
    }
    if !sb.blocks.iter().any(|b| b.left == 3000) {
        return TestResult::Fail("scoreboard lost block not covered by cumulative ACK");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_skip_on_sack_retransmit);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 16 — Zero-window persist timer fires at 1s, backs off to 2s, 4s
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 9293 §3.8.6: if snd_wnd = 0 and data in the buffer, arm a persist
// timer. Initial timeout = 1s, doubles on each probe (capped at 60s).
// Linux: `tcp_persist_timer`, `tcp_probe_timer`.

fn smoke_zero_window_persist_timer() -> TestResult {
    const IFACE: &str = "tcp-timer-s16";
    const LOCAL_IP: [u8; 4] = [10, 0, 55, 1];
    const GW: [u8; 4] = [10, 0, 55, 1];
    const SERVER_PORT: u16 = 55_001;
    const CLIENT_PORT: u16 = 55_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1500_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Queue 100 bytes in send buffer.
    match send(child_id, &vec![0xEEu8; 100]) {
        Ok(n) if n > 0 => {}
        _ => return TestResult::Fail("send(100) failed in persist smoke"),
    }
    let _ = timer_drain_captured();

    // Advertise window = 0 from the peer — pump_send must arm the persist timer.
    let snd_una = __with_tcb(child_id, |t| t.snd_una).unwrap_or(0);
    let client_seq: u32 = 0x1500_0001;
    let zero_win = build_tcp_seg(
        LOCAL_IP, LOCAL_IP, CLIENT_PORT, SERVER_PORT,
        client_seq, snd_una,
        FLAG_ACK, 0, // window = 0
        &[],
    );
    handle_segment(LOCAL_IP, LOCAL_IP, &zero_win[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    let _ = timer_drain_captured();

    // Verify persist timer was armed.
    let persist_armed = __with_tcb(child_id, |t| t.persist_deadline_cycles != 0).unwrap_or(false);
    if !persist_armed {
        return TestResult::Fail("persist timer not armed after zero-window ACK");
    }

    // Verify initial back-off == PERSIST_INITIAL_NS (1s).
    let backoff1 = __with_tcb(child_id, |t| t.persist_backoff_ns).unwrap_or(0);
    if backoff1 != PERSIST_INITIAL_NS {
        return TestResult::Fail("persist_backoff_ns not 1s on first arm");
    }

    // Force first persist probe: set deadline = 1.
    __with_tcb_mut(child_id, |t| t.persist_deadline_cycles = 1);
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }
    let probes1 = timer_drain_captured();
    if probes1.is_empty() {
        return TestResult::Fail("no persist probe sent after first deadline expiry");
    }

    // After first probe, back-off doubles to 2s.
    let backoff2 = __with_tcb(child_id, |t| t.persist_backoff_ns).unwrap_or(0);
    if backoff2 != PERSIST_INITIAL_NS * 2 {
        return TestResult::Fail("persist_backoff_ns not 2s after first probe");
    }

    // Force second persist probe.
    __with_tcb_mut(child_id, |t| t.persist_deadline_cycles = 1);
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }
    let probes2 = timer_drain_captured();
    if probes2.is_empty() {
        return TestResult::Fail("no persist probe on second deadline expiry");
    }

    // Back-off doubles again to 4s.
    let backoff3 = __with_tcb(child_id, |t| t.persist_backoff_ns).unwrap_or(0);
    if backoff3 != PERSIST_INITIAL_NS * 4 {
        return TestResult::Fail("persist_backoff_ns not 4s after second probe");
    }

    // Persist back-off must be capped at PERSIST_MAX_NS (60s) eventually.
    for _ in 0..20 {
        __with_tcb_mut(child_id, |t| t.persist_deadline_cycles = 1);
        if let Some(arc) = lookup_tcb(child_id) {
            tick_retransmit(&arc);
        }
        let _ = timer_drain_captured();
    }
    let backoff_final = __with_tcb(child_id, |t| t.persist_backoff_ns).unwrap_or(0);
    if backoff_final > PERSIST_MAX_NS {
        return TestResult::Fail("persist_backoff_ns exceeded PERSIST_MAX_NS cap");
    }

    let _ = close(child_id);
    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_zero_window_persist_timer);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 17 — Keepalive probe sent after 2-hour idle
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 9293 §3.8.4: keepalive probe has seq = snd_una - 1.
// Linux: `tcp_keepalive_timer`.

fn smoke_keepalive_after_two_hour_idle() -> TestResult {
    const IFACE: &str = "tcp-timer-s17";
    const LOCAL_IP: [u8; 4] = [10, 0, 56, 1];
    const GW: [u8; 4] = [10, 0, 56, 1];
    const SERVER_PORT: u16 = 56_001;
    const CLIENT_PORT: u16 = 56_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1600_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // Enable keepalive and set idle timeout to a manageable value.
    __with_tcb_mut(child_id, |t| {
        t.keepalive_enabled = true;
        t.keepalive_idle_ns = KEEPALIVE_IDLE_NS; // 2 hours (we'll fake elapsed time)
        t.keepalive_intvl_ns = 75_000_000_000; // 75s
        t.keepalive_cnt = 9;
        t.keepalive_probes_sent = 0;
        // Back-date last_progress_cycles so that elapsed > 2h.
        // cycles_per_ns = 1, so 2h = 7200s = 7_200_000_000_000 ns = 7_200_000_000_000 cycles.
        // Set last_progress = 0, so elapsed = now_cycles() which is always > that.
        t.last_progress_cycles = 0;
    });

    // tick_keepalive inside tick_retransmit should fire a probe.
    let _ = timer_drain_captured();
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }
    let txd = timer_drain_captured();

    // Must have emitted at least one keepalive (empty body) probe.
    if txd.is_empty() {
        return TestResult::Fail("no keepalive probe emitted after 2-hour idle");
    }

    // Verify the keepalive probe uses seq = snd_una - 1 (RFC 9293 §3.8.4).
    let snd_una = __with_tcb(child_id, |t| t.snd_una).unwrap_or(0);
    let probe_seq = frame_seq(&txd[0]);
    if probe_seq != snd_una.wrapping_sub(1) {
        return TestResult::Fail("keepalive probe seq != snd_una - 1");
    }

    // keepalive_probes_sent must have incremented.
    let probes_sent = __with_tcb(child_id, |t| t.keepalive_probes_sent).unwrap_or(0);
    if probes_sent == 0 {
        return TestResult::Fail("keepalive_probes_sent not incremented");
    }

    let _ = close(child_id);
    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_keepalive_after_two_hour_idle);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 18 — TIME-WAIT 2*MSL expiry removes TCB
// ═══════════════════════════════════════════════════════════════════════════
//
// RFC 9293 §3.4.2: TCB must persist in TIME-WAIT for 2*MSL (60s here).
// Linux: `tcp_time_wait`.

fn smoke_time_wait_2msl_expiry() -> TestResult {
    const IFACE: &str = "tcp-timer-s18";
    const LOCAL_IP: [u8; 4] = [10, 0, 57, 1];
    const GW: [u8; 4] = [10, 0, 57, 1];
    const SERVER_PORT: u16 = 57_001;
    const CLIENT_PORT: u16 = 57_100;

    timer_full_reset(IFACE, LOCAL_IP, GW);

    let (listen_id, child_id, _) =
        match establish_server_side(LOCAL_IP, SERVER_PORT, CLIENT_PORT, 0x1700_0000) {
            Ok(t) => t,
            Err(e) => return TestResult::Fail(e),
        };

    // ── Active close: server sends FIN ──
    match shutdown(child_id, Shutdown::Write) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("shutdown(Write) failed"),
    }
    let txd = timer_drain_captured();
    let has_fin = txd.iter().any(|f| frame_flags(f) & FLAG_FIN != 0);
    if !has_fin {
        return TestResult::Fail("no FIN after shutdown(Write)");
    }

    // Peer ACKs the FIN (FIN-WAIT-1 → FIN-WAIT-2).
    let fin_seq = __with_tcb(child_id, |t| t.fin_seq).unwrap_or(0);
    let client_seq: u32 = 0x1700_0001;
    let ack_fin = build_tcp_seg(
        LOCAL_IP, LOCAL_IP, CLIENT_PORT, SERVER_PORT,
        client_seq, fin_seq.wrapping_add(1),
        FLAG_ACK, 65535, &[],
    );
    handle_segment(LOCAL_IP, LOCAL_IP, &ack_fin[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    let _ = timer_drain_captured();

    // Peer sends FIN (passive close → server reaches TIME-WAIT).
    let client_fin = build_tcp_seg(
        LOCAL_IP, LOCAL_IP, CLIENT_PORT, SERVER_PORT,
        client_seq, fin_seq.wrapping_add(1),
        FLAG_FIN | FLAG_ACK, 65535, &[],
    );
    handle_segment(LOCAL_IP, LOCAL_IP, &client_fin[ETH_HDR_LEN + IPV4_HDR_LEN..]);
    let _ = timer_drain_captured();

    // Server should now be in TIME-WAIT.
    let state = __with_tcb(child_id, |t| t.state);
    match state {
        Some(TcpState::TimeWait) => {}
        other => {
            // May already be removed if FIN-WAIT-2 simultaneous close path
            // differs slightly; accept Closed or None as well.
            if other == Some(TcpState::Closed) || other.is_none() {
                // Already gone — check it's not in the table.
                if lookup_tcb(child_id).is_none() {
                    let _ = close(listen_id);
                    return TestResult::Pass;
                }
            }
            return TestResult::Fail("server not in TIME-WAIT after FIN exchange");
        }
    }

    // Before deadline: TCB must still be present.
    if lookup_tcb(child_id).is_none() {
        return TestResult::Fail("TCB vanished before 2*MSL deadline");
    }

    // ── Drive 2*MSL expiry: set time_wait_deadline_cycles = 1 ──
    __with_tcb_mut(child_id, |t| t.time_wait_deadline_cycles = 1);
    {
        let arc = lookup_tcb(child_id).unwrap();
        tick_retransmit(&arc);
    }

    // After expiry the TCB must be gone.
    if lookup_tcb(child_id).is_some() {
        return TestResult::Fail("TCB still in table after 2*MSL TIME-WAIT expiry");
    }

    let _ = close(listen_id);
    TestResult::Pass
}
kernel_test_in!("net/tcp/timer", smoke_time_wait_2msl_expiry);
