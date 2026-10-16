//! IPv4 fragment reassembly smokes.
//!
//! Every case injects real IPv4 fragments as Ethernet frames through
//! `tcp_stack::rx_handler` — the driver RX entry point that reaches
//! `handle_ipv4` — and observes the result where a user would: a bound UDP
//! socket's queue, a TCP listener's SYN-ACK, or an ICMP error on the wire.
//!
//! Linux ref: `net/ipv4/ip_fragment.c`, `net/ipv4/inet_fragment.c`,
//! `ip_local_deliver` in `net/ipv4/ip_input.c`.
//!
//! State isolation: each smoke resets the interface registry, FIB, ARP,
//! netfilter, TCB table and reassembly queues, and uses the `frag0`
//! interface, 10.0.91.0/24 and ports 3910x that no other smoke uses.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::ip_fragment::{
    self, __reset_for_test, __set_high_thresh_for_test, __usage_in, expire_at, stats_in,
    ReasmStats, IPFRAG_HIGH_THRESH, IPFRAG_LOW_THRESH, IPFRAG_TIME_NS,
};
use crate::pkt::{
    ip_checksum, write_eth_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_ICMP,
    IP_PROTO_TCP, IP_PROTO_UDP,
};
use crate::udp_sock::SocketAddrV4;
use crate::udp_sock::{udp_bind, udp_close, udp_recv, UdpOptions};

const IFACE: &str = "frag0";
const LOCAL: [u8; 4] = [10, 0, 91, 15];
const GW: [u8; 4] = [10, 0, 91, 1];
const PEER: [u8; 4] = [10, 0, 91, 7];
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x91, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x91, 0x07];

const MF: u16 = 0x2000;
const DF: u16 = 0x4000;

static TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn capture(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    TX.lock().push(frame.to_vec());
    Ok(())
}

/// IPv4 packets (Ethernet stripped) transmitted since the last drain.
fn drain_ipv4() -> Vec<Vec<u8>> {
    core::mem::take(&mut *TX.lock())
        .into_iter()
        .filter(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN
                && u16::from_be_bytes([f[12], f[13]]) == ETHERTYPE_IPV4
        })
        .map(|f| f[ETH_HDR_LEN..].to_vec())
        .collect()
}

fn reset() {
    crate::tcp::core::__reset_for_test();
    crate::route::__reset_for_test();
    crate::arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    crate::bypass::__reset_for_test();
    crate::netfilter::__reset_all_for_test();
    narf_lib::sysctl::ipv4::__reset_for_test();
    __reset_for_test();
    TX.lock().clear();

    crate::iface::register(IFACE, MAC, capture);
    crate::iface::set_link_state(IFACE, true);
    crate::iface::set_iface_ipv4_fields(IFACE, LOCAL, GW);
    crate::iface::add_addr(IFACE, LOCAL, 24);
    crate::tcp_stack::__arp_insert_legacy(PEER, PEER_MAC);
    crate::arp_cache::insert(IFACE, PEER, PEER_MAC);
    crate::tcp_stack::__arp_insert_legacy(LOCAL, MAC);
    crate::arp_cache::insert(IFACE, LOCAL, MAC);
}

/// One IPv4 packet with a valid header checksum.
fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, frag_word: u16, payload: &[u8]) -> Vec<u8> {
    let total = IPV4_HDR_LEN + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&frag_word.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[IPV4_HDR_LEN..].copy_from_slice(payload);
    let cs = ip_checksum(&p[..IPV4_HDR_LEN]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    p
}

/// Hand `packet` to the stack as a frame received on `frag0`.
fn rx(packet: &[u8]) {
    let mut f = vec![0u8; ETH_HDR_LEN + packet.len()];
    write_eth_header(&mut f, MAC, PEER_MAC, ETHERTYPE_IPV4);
    f[ETH_HDR_LEN..].copy_from_slice(packet);
    crate::tcp_stack::rx_handler(IFACE, &mut f);
}

/// A fragment of `l4` covering `[off, off + len)` (bytes), MF unless it
/// reaches the end.
fn piece(proto: u8, id: u16, l4: &[u8], off: usize, len: usize) -> Vec<u8> {
    let end = (off + len).min(l4.len());
    let mf = if end < l4.len() { MF } else { 0 };
    ipv4(PEER, LOCAL, proto, id, mf | (off / 8) as u16, &l4[off..end])
}

/// A UDP datagram PEER:sport → LOCAL:dport with a correct checksum.
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 8 + payload.len()];
    let n = crate::pkt_udp::build_ipv4(&mut d, PEER, LOCAL, sport, dport, payload).unwrap_or(0);
    d.truncate(n);
    d
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 3) as u8).collect()
}

/// Bind 0.0.0.0:`port`, inject `frags` in order, and return every datagram
/// payload the socket received.
fn udp_roundtrip(port: u16, frags: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, &'static str> {
    let sock = udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default())
        .map_err(|_| "bind failed")?;
    for f in frags {
        rx(f);
    }
    let mut got = Vec::new();
    let mut buf = vec![0u8; 70_000];
    while let Ok((n, _)) = udp_recv(&sock, &mut buf) {
        got.push(buf[..n].to_vec());
    }
    udp_close(&sock);
    Ok(got)
}

fn expect_one(got: &[Vec<u8>], want: &[u8]) -> TestResult {
    match got {
        [one] if one.as_slice() == want => TestResult::Pass,
        [] => TestResult::Fail("fragmented datagram was not delivered"),
        [one] if one.len() != want.len() => TestResult::Fail("reassembled payload length wrong"),
        [_] => TestResult::Fail("reassembled payload bytes wrong"),
        _ => TestResult::Fail("datagram delivered more than once"),
    }
}

fn run(r: Result<TestResult, &'static str>) -> TestResult {
    match r {
        Ok(t) => t,
        Err(e) => TestResult::Fail(e),
    }
}

// ── Delivery ────────────────────────────────────────────────────────────────

fn smoke_ipfrag_udp_two_fragments_in_order() -> TestResult {
    reset();
    let payload = pattern(1000);
    let dg = udp(5000, 39101, &payload);
    let frags = [
        piece(IP_PROTO_UDP, 0x1001, &dg, 0, 504),
        piece(IP_PROTO_UDP, 0x1001, &dg, 504, 504),
    ];
    let got = match udp_roundtrip(39101, &frags) {
        Ok(g) => g,
        Err(e) => return TestResult::Fail(e),
    };
    let st = stats_in(0);
    if st.reqds != 2 || st.oks != 1 || st.fails != 0 {
        return TestResult::Fail("ReasmReqds/ReasmOKs/ReasmFails not 2/1/0");
    }
    if __usage_in(0) != (0, 0) {
        return TestResult::Fail("completed queue still holds memory");
    }
    expect_one(&got, &payload)
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_udp_two_fragments_in_order);

fn smoke_ipfrag_udp_two_fragments_out_of_order() -> TestResult {
    reset();
    let payload = pattern(1000);
    let dg = udp(5000, 39102, &payload);
    let frags = [
        piece(IP_PROTO_UDP, 0x1002, &dg, 504, 504),
        piece(IP_PROTO_UDP, 0x1002, &dg, 0, 504),
    ];
    run(udp_roundtrip(39102, &frags).map(|g| expect_one(&g, &payload)))
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_udp_two_fragments_out_of_order
);

fn smoke_ipfrag_udp_three_fragments_all_orders() -> TestResult {
    let payload = pattern(3000);
    let dg = udp(5000, 39103, &payload);
    let cuts = [(0usize, 1480usize), (1480, 1480), (2960, 48)];
    for (n, order) in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1], [0, 2, 1]]
        .iter()
        .enumerate()
    {
        reset();
        let id = 0x1100 + n as u16;
        let frags: Vec<Vec<u8>> = order
            .iter()
            .map(|&i| piece(IP_PROTO_UDP, id, &dg, cuts[i].0, cuts[i].1))
            .collect();
        match udp_roundtrip(39103, &frags) {
            Ok(g) => {
                if let TestResult::Fail(e) = expect_one(&g, &payload) {
                    return TestResult::Fail(e);
                }
            }
            Err(e) => return TestResult::Fail(e),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_udp_three_fragments_all_orders
);

/// A SYN whose TCP header is split across two fragments must still reach
/// the listener and draw a SYN-ACK.
fn smoke_ipfrag_tcp_syn_split_header_accepted() -> TestResult {
    use crate::pkt_tcp::{TcpHeader, FLAG_ACK, FLAG_SYN};
    reset();
    const PORT: u16 = 39104;
    const SPORT: u16 = 40404;
    if crate::tcp::core::listen(LOCAL, PORT, 4).is_err() {
        return TestResult::Fail("listen failed");
    }
    let mut hdr = TcpHeader {
        src_port: SPORT,
        dst_port: PORT,
        sequence: 0x0BAD_F00D,
        acknowledgement: 0,
        header_len: 20,
        flags: FLAG_SYN,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
        options: Vec::new(),
    };
    let mut seg = hdr.encode();
    hdr.checksum = crate::pkt_tcp::ipv4_pseudo_checksum(PEER, LOCAL, &seg);
    seg[16..18].copy_from_slice(&hdr.checksum.to_be_bytes());
    let _ = drain_ipv4();
    rx(&piece(IP_PROTO_TCP, 0x1004, &seg, 16, 4));
    rx(&piece(IP_PROTO_TCP, 0x1004, &seg, 0, 16));
    let synack = drain_ipv4().into_iter().any(|p| {
        p.len() >= IPV4_HDR_LEN + 20
            && p[9] == IP_PROTO_TCP
            && p[16..20] == PEER
            && u16::from_be_bytes([p[22], p[23]]) == SPORT
            && p[IPV4_HDR_LEN + 13] & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK
            && u32::from_be_bytes([p[28], p[29], p[30], p[31]]) == 0x0BAD_F00E
    });
    if !synack {
        return TestResult::Fail("fragmented SYN drew no SYN-ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_tcp_syn_split_header_accepted
);

/// The reassembled header: total length fixed, MF/offset cleared, DF kept
/// only when the largest fragment had it, ECN CE folded in, checksum valid.
/// Checked on `ip_defrag` directly — LOCAL_IN and the transport see the same
/// bytes.
fn smoke_ipfrag_reassembled_header_fixed_up() -> TestResult {
    reset();
    let dg = udp(5000, 39105, &pattern(1000));
    let mut a = piece(IP_PROTO_UDP, 0x1005, &dg, 0, 504);
    let mut b = piece(IP_PROTO_UDP, 0x1005, &dg, 504, 504);
    // ECT(0) on one, CE on the other → CE; DF on both (largest has DF).
    for (p, tos) in [(&mut a, 0x02u8), (&mut b, 0x03u8)] {
        p[1] = tos;
        let w = u16::from_be_bytes([p[6], p[7]]) | DF;
        p[6..8].copy_from_slice(&w.to_be_bytes());
        p[10..12].copy_from_slice(&[0, 0]);
        let cs = ip_checksum(&p[..IPV4_HDR_LEN]);
        p[10..12].copy_from_slice(&cs.to_be_bytes());
    }
    if ip_fragment::ip_defrag_at(1, 0, IFACE, &a).is_some() {
        return TestResult::Fail("first fragment alone completed a datagram");
    }
    let Some(whole) = ip_fragment::ip_defrag_at(2, 0, IFACE, &b) else {
        return TestResult::Fail("datagram did not complete");
    };
    if whole.len() != IPV4_HDR_LEN + dg.len() || whole[IPV4_HDR_LEN..] != dg[..] {
        return TestResult::Fail("reassembled payload wrong");
    }
    if u16::from_be_bytes([whole[2], whole[3]]) as usize != whole.len() {
        return TestResult::Fail("total length not fixed up");
    }
    if u16::from_be_bytes([whole[6], whole[7]]) != DF {
        return TestResult::Fail("frag_off must be DF with MF and offset cleared");
    }
    if whole[1] & 0x03 != 0x03 {
        return TestResult::Fail("CE from one fragment not folded into the header");
    }
    if ip_checksum(&whole[..IPV4_HDR_LEN]) != 0 {
        return TestResult::Fail("reassembled header checksum invalid");
    }
    // Not-ECT mixed with ECT is an invalid combination: dropped.
    let mut c = piece(IP_PROTO_UDP, 0x1006, &dg, 0, 504);
    c[1] = 0x02;
    c[10..12].copy_from_slice(&[0, 0]);
    let cs = ip_checksum(&c[..IPV4_HDR_LEN]);
    c[10..12].copy_from_slice(&cs.to_be_bytes());
    let d = piece(IP_PROTO_UDP, 0x1006, &dg, 504, 504);
    let _ = ip_fragment::ip_defrag_at(3, 0, IFACE, &c);
    if ip_fragment::ip_defrag_at(4, 0, IFACE, &d).is_some() {
        return TestResult::Fail("Not-ECT + ECT(0) fragments reassembled");
    }
    TestResult::Pass
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_reassembled_header_fixed_up);

/// Reassembled data gets no checksum offload: a corrupted byte in any
/// fragment must fail the UDP checksum over the whole datagram.
fn smoke_ipfrag_reassembled_bad_udp_checksum_dropped() -> TestResult {
    reset();
    let payload = pattern(1000);
    let mut dg = udp(5000, 39106, &payload);
    dg[700] ^= 0x5A;
    let frags = [
        piece(IP_PROTO_UDP, 0x1007, &dg, 0, 504),
        piece(IP_PROTO_UDP, 0x1007, &dg, 504, 504),
    ];
    match udp_roundtrip(39106, &frags) {
        Ok(g) if g.is_empty() => {}
        Ok(_) => return TestResult::Fail("datagram with a bad UDP checksum delivered"),
        Err(e) => return TestResult::Fail(e),
    }
    if stats_in(0).oks != 1 {
        return TestResult::Fail("IP reassembly itself should have succeeded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_reassembled_bad_udp_checksum_dropped
);

// ── Malformed fragment sets ─────────────────────────────────────────────────

/// `IPFRAG_OVERLAP` discards the whole queue (RFC 5722 / CVE-2018-5391).
fn smoke_ipfrag_overlap_discards_datagram() -> TestResult {
    reset();
    let payload = pattern(1000);
    let dg = udp(5000, 39107, &payload);
    let frags = [
        piece(IP_PROTO_UDP, 0x1008, &dg, 0, 504),
        // Starts 8 bytes inside the first fragment.
        piece(IP_PROTO_UDP, 0x1008, &dg, 496, 512),
        // The correct remainder no longer completes anything.
        piece(IP_PROTO_UDP, 0x1008, &dg, 504, 504),
    ];
    match udp_roundtrip(39107, &frags) {
        Ok(g) if g.is_empty() => {}
        Ok(_) => return TestResult::Fail("overlapping fragments were reassembled"),
        Err(e) => return TestResult::Fail(e),
    }
    let st = stats_in(0);
    if st.fails != 1 || st.oks != 0 {
        return TestResult::Fail("overlap must count exactly one ReasmFails");
    }
    // The discarded queue is gone; the trailing fragment opened a new one.
    if __usage_in(0).0 != 1 {
        return TestResult::Fail("overlap did not discard the original queue");
    }
    // A clean retransmission of the whole datagram still gets through.
    let again = [
        piece(IP_PROTO_UDP, 0x1009, &dg, 0, 504),
        piece(IP_PROTO_UDP, 0x1009, &dg, 504, 504),
    ];
    run(udp_roundtrip(39107, &again).map(|g| expect_one(&g, &payload)))
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_overlap_discards_datagram);

/// An overlap that lands BELOW the tail (the rb-tree path) discards too.
fn smoke_ipfrag_overlap_below_tail_discards_datagram() -> TestResult {
    reset();
    let payload = pattern(3000);
    let dg = udp(5000, 39108, &payload);
    let frags = [
        piece(IP_PROTO_UDP, 0x100A, &dg, 1480, 1480),
        piece(IP_PROTO_UDP, 0x100A, &dg, 2960, 1480),
        // Straddles the start of the first run.
        piece(IP_PROTO_UDP, 0x100A, &dg, 1472, 16),
        piece(IP_PROTO_UDP, 0x100A, &dg, 0, 1480),
    ];
    match udp_roundtrip(39108, &frags) {
        Ok(g) if g.is_empty() => {}
        Ok(_) => return TestResult::Fail("overlap below the tail was reassembled"),
        Err(e) => return TestResult::Fail(e),
    }
    if stats_in(0).fails != 1 {
        return TestResult::Fail("overlap below the tail must count one ReasmFails");
    }
    // The same pieces without the straddler reassemble.
    let clean = [
        piece(IP_PROTO_UDP, 0x1015, &dg, 1480, 1480),
        piece(IP_PROTO_UDP, 0x1015, &dg, 2960, 1480),
        piece(IP_PROTO_UDP, 0x1015, &dg, 0, 1480),
    ];
    run(udp_roundtrip(39108, &clean).map(|g| expect_one(&g, &payload)))
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_overlap_below_tail_discards_datagram
);

/// `IPFRAG_DUP`: an exact duplicate is dropped and the queue survives.
fn smoke_ipfrag_exact_duplicate_tolerated() -> TestResult {
    reset();
    let payload = pattern(3000);
    let dg = udp(5000, 39109, &payload);
    let frags = [
        piece(IP_PROTO_UDP, 0x100B, &dg, 0, 1480),
        piece(IP_PROTO_UDP, 0x100B, &dg, 0, 1480),
        piece(IP_PROTO_UDP, 0x100B, &dg, 2960, 1480),
        piece(IP_PROTO_UDP, 0x100B, &dg, 2960, 1480),
        piece(IP_PROTO_UDP, 0x100B, &dg, 1480, 1480),
    ];
    let got = match udp_roundtrip(39109, &frags) {
        Ok(g) => g,
        Err(e) => return TestResult::Fail(e),
    };
    if stats_in(0).fails != 0 {
        return TestResult::Fail("a duplicate must not count ReasmFails");
    }
    expect_one(&got, &payload)
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_exact_duplicate_tolerated);

/// A non-final fragment whose length is not a multiple of 8. Linux does
/// not drop it: `ip_frag_queue` truncates `end &= ~7`, so the excess bytes
/// never enter the datagram. Junk past the 8-byte boundary is discarded and
/// the datagram completes; a fragment left empty by the truncation
/// (`end == offset`) discards the whole queue.
fn smoke_ipfrag_non_multiple_of_8_middle_truncated() -> TestResult {
    reset();
    let payload = pattern(1000);
    let dg = udp(5000, 39110, &payload);
    // Middle fragment: 496 real bytes + 5 bytes of junk, MF set.
    let mut middle_data = dg[504..1000].to_vec();
    middle_data.extend_from_slice(&[0xEE; 5]);
    let middle = ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x100C, MF | 63, &middle_data);
    let frags = [
        piece(IP_PROTO_UDP, 0x100C, &dg, 0, 504),
        middle,
        piece(IP_PROTO_UDP, 0x100C, &dg, 1000, 8),
    ];
    match udp_roundtrip(39110, &frags) {
        Ok(g) => {
            if let TestResult::Fail(e) = expect_one(&g, &payload) {
                return TestResult::Fail(e);
            }
        }
        Err(e) => return TestResult::Fail(e),
    }
    // A 5-byte MF fragment truncates to nothing: the queue is discarded.
    reset();
    let frags = [
        piece(IP_PROTO_UDP, 0x100D, &dg, 0, 504),
        ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x100D, MF | 63, &dg[504..509]),
        piece(IP_PROTO_UDP, 0x100D, &dg, 504, 504),
    ];
    match udp_roundtrip(39110, &frags) {
        Ok(g) if g.is_empty() => {}
        Ok(_) => return TestResult::Fail("datagram completed after an empty MF fragment"),
        Err(e) => return TestResult::Fail(e),
    }
    if stats_in(0).fails != 1 {
        return TestResult::Fail("empty MF fragment must discard the queue (ReasmFails)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_non_multiple_of_8_middle_truncated
);

/// A last fragment ending before data already queued, or two different
/// last fragments, discard the queue.
fn smoke_ipfrag_inconsistent_end_discards_queue() -> TestResult {
    let dg = udp(5000, 39111, &pattern(1000));
    let cases: [(&str, [Vec<u8>; 2]); 2] = [
        (
            // Bytes up to 1008 are queued, then a final fragment ends at 504.
            "final fragment ending below queued data accepted",
            [
                ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x100E, MF | 63, &dg[504..1008]),
                ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x100E, 1, &dg[8..504]),
            ],
        ),
        (
            // Two final fragments that disagree on where the datagram ends.
            "second final fragment with a different end accepted",
            [
                ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x1016, 125, &dg[1000..1008]),
                ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x1016, 126, &[0u8; 8]),
            ],
        ),
    ];
    for (why, frags) in cases {
        reset();
        match udp_roundtrip(39111, &frags) {
            Ok(g) if g.is_empty() => {}
            _ => return TestResult::Fail(why),
        }
        if stats_in(0).fails != 1 || __usage_in(0).0 != 0 {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_inconsistent_end_discards_queue
);

/// A datagram reassembling to more than 65535 bytes is rejected
/// (`ip_frag_reasm`: `-E2BIG`).
fn smoke_ipfrag_oversize_rejected() -> TestResult {
    reset();
    // 44 × 1480 + 500 = 65620 bytes of payload, 65640 with the header.
    let data = pattern(44 * 1480 + 500);
    let sock = match udp_bind(
        SocketAddrV4::new([0, 0, 0, 0], 39112),
        UdpOptions::default(),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let mut l4 = data.clone();
    l4[0..2].copy_from_slice(&5000u16.to_be_bytes());
    l4[2..4].copy_from_slice(&39112u16.to_be_bytes());
    l4[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    l4[6..8].copy_from_slice(&[0, 0]);
    let mut off = 0;
    while off < l4.len() {
        rx(&piece(IP_PROTO_UDP, 0x100F, &l4, off, 1480));
        off += 1480;
    }
    let mut buf = vec![0u8; 70_000];
    let delivered = udp_recv(&sock, &mut buf).is_ok();
    udp_close(&sock);
    if delivered {
        return TestResult::Fail("datagram larger than 65535 bytes delivered");
    }
    let st = stats_in(0);
    if st.fails != 1 || st.oks != 0 || st.reqds != 45 {
        return TestResult::Fail("oversize must count 45 ReasmReqds, 1 ReasmFails, 0 ReasmOKs");
    }
    if __usage_in(0) != (0, 0) {
        return TestResult::Fail("oversize queue not freed");
    }
    TestResult::Pass
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_oversize_rejected);

// ── Timeout ─────────────────────────────────────────────────────────────────

fn time_exceeded_frames() -> Vec<Vec<u8>> {
    drain_ipv4()
        .into_iter()
        .filter(|p| p.len() >= IPV4_HDR_LEN + 8 && p[9] == IP_PROTO_ICMP)
        .collect()
}

/// `ip_expire`: after `ipfrag_time` the queue is freed, ReasmTimeout and
/// ReasmFails count, and — only because offset 0 arrived — ICMP Time
/// Exceeded code 1 goes back to the sender quoting the first fragment.
fn smoke_ipfrag_timeout_sends_time_exceeded_with_first_fragment() -> TestResult {
    reset();
    let dg = udp(5000, 39113, &pattern(1000));
    let first = piece(IP_PROTO_UDP, 0x1010, &dg, 0, 504);
    let start = narf_scheduler::narf_time::monotonic_ns();
    rx(&first);
    let _ = drain_ipv4();
    if expire_at(start + IPFRAG_TIME_NS - 1_000_000_000) != 0 {
        return TestResult::Fail("queue expired before ipfrag_time");
    }
    let now = narf_scheduler::narf_time::monotonic_ns();
    if expire_at(now + IPFRAG_TIME_NS) != 1 {
        return TestResult::Fail("queue did not expire after ipfrag_time");
    }
    let icmp = time_exceeded_frames();
    let [p] = icmp.as_slice() else {
        return TestResult::Fail("expected exactly one ICMP error");
    };
    let icmp_hdr = &p[IPV4_HDR_LEN..];
    if icmp_hdr[0] != 11 || icmp_hdr[1] != 1 {
        return TestResult::Fail("ICMP error is not Time Exceeded / reassembly (11/1)");
    }
    if p[12..16] != LOCAL || p[16..20] != PEER {
        return TestResult::Fail("ICMP error must go LOCAL → PEER");
    }
    if ip_checksum(icmp_hdr) != 0 {
        return TestResult::Fail("ICMP checksum invalid");
    }
    // The quote is the first fragment's header (id 0x1010, MF) + its data.
    let quoted = &icmp_hdr[8..];
    if quoted.len() < IPV4_HDR_LEN + 8 || quoted[..IPV4_HDR_LEN + 8] != first[..IPV4_HDR_LEN + 8] {
        return TestResult::Fail("ICMP error does not quote the first fragment");
    }
    let st = stats_in(0);
    if st.timeout != 1 || st.fails != 1 {
        return TestResult::Fail("expiry must count ReasmTimeout and ReasmFails");
    }
    if __usage_in(0) != (0, 0) {
        return TestResult::Fail("expired queue not freed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_timeout_sends_time_exceeded_with_first_fragment
);

fn smoke_ipfrag_timeout_without_first_fragment_is_silent() -> TestResult {
    reset();
    let dg = udp(5000, 39114, &pattern(1000));
    rx(&piece(IP_PROTO_UDP, 0x1011, &dg, 504, 504));
    let _ = drain_ipv4();
    let now = narf_scheduler::narf_time::monotonic_ns();
    if expire_at(now + IPFRAG_TIME_NS) != 1 {
        return TestResult::Fail("queue did not expire after ipfrag_time");
    }
    if !time_exceeded_frames().is_empty() {
        return TestResult::Fail("ICMP sent although offset 0 never arrived");
    }
    if stats_in(0).timeout != 1 {
        return TestResult::Fail("expiry must count ReasmTimeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_timeout_without_first_fragment_is_silent
);

// ── Memory bound ────────────────────────────────────────────────────────────

/// `inet_frag_find` refuses every fragment once the namespace's fragment
/// memory is above `ipfrag_high_thresh` — even the one that would complete
/// an existing queue — and counts ReasmFails. Expiry frees the memory.
fn smoke_ipfrag_high_thresh_drops_new_fragments() -> TestResult {
    if IPFRAG_HIGH_THRESH != 4 * 1024 * 1024 || IPFRAG_LOW_THRESH != 3 * 1024 * 1024 {
        return TestResult::Fail("ipfrag thresholds differ from Linux's 4 MiB / 3 MiB");
    }
    reset();
    __set_high_thresh_for_test(0, 16 * 1024);
    let payload = pattern(1000);
    let dg = udp(5000, 39115, &payload);
    let mut id = 0x2000u16;
    // First halves of distinct datagrams until the threshold is crossed.
    while __usage_in(0).1 <= 16 * 1024 {
        rx(&piece(IP_PROTO_UDP, id, &dg, 0, 504));
        id += 1;
        if id > 0x2100 {
            return TestResult::Fail("fragment memory never crossed the threshold");
        }
    }
    let queued = __usage_in(0);
    let before: ReasmStats = stats_in(0);
    // Completing the first datagram is refused: memory is over the limit.
    match udp_roundtrip(39115, &[piece(IP_PROTO_UDP, 0x2000, &dg, 504, 504)]) {
        Ok(g) if g.is_empty() => {}
        Ok(_) => return TestResult::Fail("fragment accepted above ipfrag_high_thresh"),
        Err(e) => return TestResult::Fail(e),
    }
    // So is a brand-new datagram.
    rx(&piece(IP_PROTO_UDP, 0x3000, &dg, 0, 504));
    let after = stats_in(0);
    if after.fails != before.fails + 2 || after.reqds != before.reqds + 2 {
        return TestResult::Fail("refused fragments must count ReasmReqds and ReasmFails");
    }
    if __usage_in(0) != queued {
        return TestResult::Fail("refused fragments changed the queue set");
    }
    // Expiry drains the memory and reassembly works again.
    let now = narf_scheduler::narf_time::monotonic_ns();
    let _ = expire_at(now + IPFRAG_TIME_NS);
    if __usage_in(0) != (0, 0) {
        return TestResult::Fail("expiry did not release fragment memory");
    }
    let frags = [
        piece(IP_PROTO_UDP, 0x3001, &dg, 0, 504),
        piece(IP_PROTO_UDP, 0x3001, &dg, 504, 504),
    ];
    run(udp_roundtrip(39115, &frags).map(|g| expect_one(&g, &payload)))
}
kernel_test_in!(
    "net/ip_fragment",
    smoke_ipfrag_high_thresh_drops_new_fragments
);

// ── Not reassembled ─────────────────────────────────────────────────────────

/// Whole datagrams — DF set or not — never touch the reassembler.
fn smoke_ipfrag_non_fragment_unaffected() -> TestResult {
    reset();
    let payload = pattern(300);
    let dg = udp(5000, 39116, &payload);
    let plain = ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x1012, 0, &dg);
    let df = ipv4(PEER, LOCAL, IP_PROTO_UDP, 0x1013, DF, &dg);
    let got = match udp_roundtrip(39116, &[plain, df]) {
        Ok(g) => g,
        Err(e) => return TestResult::Fail(e),
    };
    if got.len() != 2 || got.iter().any(|g| g.as_slice() != payload.as_slice()) {
        return TestResult::Fail("whole datagrams not delivered intact");
    }
    if stats_in(0) != ReasmStats::default() || __usage_in(0) != (0, 0) {
        return TestResult::Fail("a whole datagram went through reassembly");
    }
    TestResult::Pass
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_non_fragment_unaffected);

/// Fragments not addressed to this host are forwarded (or dropped) as they
/// are: reassembly is `ip_local_deliver`'s, never the router's.
fn smoke_ipfrag_not_for_us_not_reassembled() -> TestResult {
    reset();
    let dg = udp(5000, 39117, &pattern(1000));
    let mut p = piece(IP_PROTO_UDP, 0x1014, &dg, 0, 504);
    // Other kernel smokes register interfaces globally. Pick a TEST-NET
    // destination which is not any registered interface's primary address,
    // so this remains a non-local fragment regardless of suite order.
    let foreign = (1..=u8::MAX)
        .map(|last| [192, 0, 2, last])
        .find(|candidate| {
            !crate::iface::snapshot_all_in(0)
                .iter()
                .any(|iface| iface.ipv4 == *candidate)
        })
        .unwrap_or([198, 51, 100, 1]);
    p[16..20].copy_from_slice(&foreign);
    p[10..12].copy_from_slice(&[0, 0]);
    let cs = ip_checksum(&p[..IPV4_HDR_LEN]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    rx(&p);
    if stats_in(0).reqds != 0 || __usage_in(0) != (0, 0) {
        return TestResult::Fail("a fragment for another host entered reassembly");
    }
    TestResult::Pass
}
kernel_test_in!("net/ip_fragment", smoke_ipfrag_not_for_us_not_reassembled);
